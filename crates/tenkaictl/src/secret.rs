//! Sealed secrets from the client, and their recipient pins (ADR 0045).

use std::io::Read as _;

use anyhow::{Context as _, Result, bail};
use tenkai::recipient_pins::{
    OfferedRecipient, PinCheck, RecipientPinStore, offered_from_public_key, refuse_unpinned,
};
use tenkai::sealing_key::normalize_fingerprint;

use crate::token_cache::config_dir_from_env;

pub(crate) fn pin_store() -> Result<RecipientPinStore> {
    Ok(RecipientPinStore::new(config_dir_from_env()?))
}

pub(crate) fn server_key(server_url: Option<&str>) -> Result<String> {
    let url = server_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("--server-url or TENKAI_SERVER_URL is required"))?;
    Ok(url.trim_end_matches('/').to_owned())
}

pub(crate) fn trust(server_url: Option<&str>, env: &str, fingerprint: &str) -> Result<()> {
    let server = server_key(server_url)?;
    let fingerprint = pin_store()?.trust(&server, env, fingerprint)?;
    println!("trusted {fingerprint} for {env}");
    Ok(())
}

pub(crate) fn show_recipients(
    server_url: Option<&str>,
    env: &str,
    offered: Vec<tenkai::management_operations::EnvironmentRecipient>,
) -> Result<()> {
    let server = server_key(server_url)?;
    let store = pin_store()?;
    let offered: Vec<OfferedRecipient> = offered
        .into_iter()
        .map(|recipient| offered_from_public_key(&recipient.runtime_id, &recipient.public_key))
        .collect::<Result<_>>()?;
    if offered.is_empty() {
        println!("{env} has no recipient keys");
        return Ok(());
    }
    for recipient in &offered {
        let holder = if recipient.runtime_id.is_empty() {
            "recovery"
        } else {
            &recipient.runtime_id
        };
        println!("{} {} {}", recipient.fingerprint, holder, env);
    }
    let check = store.check(&server, env, &offered)?;
    match check {
        PinCheck::Trusted => Ok(()),
        PinCheck::FirstUse { .. } if stdin_is_tty() => {
            eprint!("Accept these recipient keys for {env}? [y/N] ");
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
                bail!(
                    "unpinned recipient keys were not accepted; accept with tenkaictl secret trust"
                );
            }
            for recipient in &offered {
                store.trust(&server, env, &recipient.fingerprint)?;
            }
            eprintln!("pinned {} recipient key(s) for {env}", offered.len());
            Ok(())
        }
        other => refuse_unpinned(&other),
    }
}

/// `secret set`: seal the value on standard input to every recipient the
/// server offers, all of which must already be pinned, and submit only the
/// sealed form. `target` is environment, instance and `<secret>/<key>`.
pub(crate) async fn set(
    client: &tenkai_http::RemoteClient,
    server_url: Option<&str>,
    (env, instance, secret): (&str, &str, &str),
    remote: &crate::env_args::RemoteChange,
) -> Result<()> {
    use tenkai::sealed_secret::{SealedTarget, SecretRef};
    let target = SealedTarget::new(env, instance, SecretRef::parse(secret)?)?;
    let (generation, reason) = crate::remote_env_config::require(remote)?;
    let offered = client.list_environment_recipients(env).await?.recipients;
    let recipients = pinned_recipients(server_url, env, &offered)?;
    let value = read_value(std::io::stdin().lock(), stdin_is_tty())?;
    let sealed = tenkai::sealed_secret::seal(&target, &value, &recipients)?;
    drop(value);
    let change = tenkai::environment_config::EnvironmentConfigChange::SetSealedSecret {
        instance: target.instance,
        secret: target.secret.secret,
        key: target.secret.key,
        sealed,
    };
    let result = client
        .configure_environment(env, change, reason, generation)
        .await?;
    println!("{}", result.message);
    Ok(())
}

/// The offered recipient keys, once every one is pinned. First use and an
/// unpinned key are refused: pinning asks on a terminal, and `secret set`
/// reads the value from standard input.
fn pinned_recipients(
    server_url: Option<&str>,
    env: &str,
    offered: &[tenkai::management_operations::EnvironmentRecipient],
) -> Result<Vec<tenkai::sealing_key::SealingPublicKey>> {
    if offered.is_empty() {
        bail!("{env} offers no recipient keys; enroll a runtime first");
    }
    let server = server_key(server_url)?;
    let offered: Vec<OfferedRecipient> = offered
        .iter()
        .map(|recipient| offered_from_public_key(&recipient.runtime_id, &recipient.public_key))
        .collect::<Result<_>>()?;
    match pin_store()?.check(&server, env, &offered)? {
        PinCheck::Trusted => {}
        PinCheck::FirstUse { .. } => bail!(
            "no recipient keys are pinned for {env}; compare fingerprints with \
             tenkaictl secret recipients {env} first"
        ),
        unpinned => refuse_unpinned(&unpinned)?,
    }
    offered
        .iter()
        .map(|recipient| tenkai::sealing_key::SealingPublicKey::from_wire(&recipient.public_key))
        .collect()
}

/// The exact bytes of standard input, never echoed: a terminal is refused.
fn read_value(
    mut input: impl std::io::Read,
    terminal: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if terminal {
        bail!("pipe the secret value on standard input; it is not read from a terminal");
    }
    let limit = tenkai::sealed_secret::MAX_VALUE_BYTES;
    let mut value = zeroize::Zeroizing::new(Vec::new());
    (&mut input)
        .take(limit as u64 + 1)
        .read_to_end(&mut value)
        .context("reading the secret value from standard input")?;
    if value.is_empty() || value.len() > limit {
        bail!("the secret value on standard input must be 1..={limit} bytes");
    }
    Ok(value)
}

/// `secret list`: one line per sealed key, then a warning when losing every
/// runtime would lose any of them (ADR 0045 §7). Never a value.
pub(crate) fn print_list(list: &tenkai::sealed_secret::SealedSecretList) {
    if list.secrets.is_empty() {
        println!("{} has no sealed secrets", list.environment);
        return;
    }
    for entry in &list.secrets {
        let recoverable = list
            .recovery_key
            .as_ref()
            .is_some_and(|fingerprint| entry.recipients.contains(fingerprint));
        println!(
            "{} {}/{} {} set_by={} set_at={} recipients={} recovery={}",
            entry.instance,
            entry.secret,
            entry.key,
            entry.digest,
            entry.set_by,
            entry.set_at,
            entry.recipients.len(),
            if recoverable { "yes" } else { "no" }
        );
    }
    if let Some(warning) = list.recovery_warning() {
        eprintln!("warning: {warning}");
    }
}

/// The plan a re-wrap or recovery request created.
pub(crate) fn print_plan(result: &tenkai::management_lifecycle::ManagementLifecycleResult) {
    println!("{}", result.message);
    if let Some(plan_id) = &result.resource {
        println!("plan id: {plan_id}");
    }
    if let Some(digest) = &result.digest {
        println!("plan digest: {digest}");
    }
}

/// `secret recovery-key generate`: write the private key owner-only to
/// `path`, never over an existing file, and print the public half.
pub(crate) fn generate_recovery_key(path: &std::path::Path) -> Result<()> {
    let public = tenkai::sealing_key::generate_recovery_key(path)?;
    println!("public key: {}", public.to_wire());
    println!("fingerprint: {}", public.fingerprint());
    eprintln!(
        "keep {} offline; record the public key with tenkaictl secret recovery-key set",
        path.display()
    );
    Ok(())
}

/// `secret recover`: open each value's recovery wrap with the private key
/// at `key_path`, wrap its data key for the pinned runtime key `recipient`,
/// and ask for the re-wrap plan that carries those wraps (ADR 0045 §7).
/// Values only leave this process sealed. A value with neither a recovery
/// wrap nor a wrap for `recipient` refuses the whole request: the re-wrap
/// step could not open it.
pub(crate) async fn recover(
    client: &tenkai_http::RemoteClient,
    server_url: Option<&str>,
    env: &str,
    key_path: &std::path::Path,
    recipient: &str,
    generation: u64,
) -> Result<()> {
    let recipient = normalize_fingerprint(recipient)?;
    let opener = tenkai::sealed_secret::SealedOpener::from_pem_file(key_path)?;
    let offered = client.list_environment_recipients(env).await?.recipients;
    let keys = pinned_recipients(server_url, env, &offered)?;
    let runtime = offered
        .iter()
        .zip(keys)
        .find(|(offered, _)| !offered.recovery && offered.fingerprint == recipient)
        .map(|(_, key)| key)
        .with_context(|| format!("{recipient} is not a runtime recipient key {env} offers"))?;
    let list = client.list_sealed_secrets(env, true).await?;
    if list.recovery_key.as_deref() != Some(opener.fingerprint()) {
        bail!("{} is not the recovery key of {env}", opener.fingerprint());
    }
    let recovered = recovered_wraps(&list, &opener, &runtime)?;
    if recovered.is_empty() {
        println!("every sealed value of {env} already opens with {recipient}");
        return Ok(());
    }
    let result = client
        .rewrap_sealed_secrets(env, &recipient, generation, recovered)
        .await?;
    print_plan(&result);
    Ok(())
}

/// Wraps for `runtime` of every value it cannot open yet, by instance,
/// made through `opener`'s recovery wrap. Opening authenticates the value
/// under its target, so a value moved to another slot is refused.
fn recovered_wraps(
    list: &tenkai::sealed_secret::SealedSecretList,
    opener: &tenkai::sealed_secret::SealedOpener,
    runtime: &tenkai::sealing_key::SealingPublicKey,
) -> Result<std::collections::BTreeMap<String, Vec<tenkai::sealed_secret::RecipientWrap>>> {
    use tenkai::sealed_secret::{SealedTarget, SecretRef};
    let mut recovered: std::collections::BTreeMap<String, Vec<_>> = Default::default();
    let mut lost = Vec::new();
    for entry in &list.secrets {
        let sealed = entry
            .sealed
            .as_ref()
            .context("the server returned a sealed key without its sealed value")?;
        let has = |fingerprint: &str| {
            sealed
                .wraps
                .iter()
                .any(|wrap| wrap.fingerprint == fingerprint)
        };
        if has(&runtime.fingerprint()) {
            continue;
        }
        if !has(opener.fingerprint()) {
            lost.push(format!("{} {}/{}", entry.instance, entry.secret, entry.key));
            continue;
        }
        let target = SealedTarget::new(
            &list.environment,
            &entry.instance,
            SecretRef::new(&entry.secret, &entry.key)?,
        )?;
        recovered.entry(entry.instance.clone()).or_default().push(
            tenkai::sealed_secret::RecipientWrap {
                secret: entry.secret.clone(),
                key: entry.key.clone(),
                digest: tenkai::sealed_secret::digest(&target, sealed)?,
                wrap: opener.rewrap(&target, sealed, runtime)?,
            },
        );
    }
    if !lost.is_empty() {
        bail!(
            "these sealed values have no recovery wrap and cannot be recovered; set them again with tenkaictl secret set first:\n  {}",
            lost.join("\n  ")
        );
    }
    Ok(recovered)
}

pub(crate) fn require_fingerprint(value: &str) -> Result<String> {
    normalize_fingerprint(value)
}

fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_is_the_exact_piped_bytes_and_never_a_terminal() {
        assert_eq!(
            read_value(&b"s3cret\n"[..], false).unwrap().as_slice(),
            b"s3cret\n"
        );
        assert!(read_value(&b"s3cret"[..], true).is_err());
        assert!(read_value(&b""[..], false).is_err());
        let oversized = vec![b'x'; tenkai::sealed_secret::MAX_VALUE_BYTES + 1];
        assert!(read_value(oversized.as_slice(), false).is_err());
    }

    /// Recovery opens only values sealed with a recovery wrap; one sealed
    /// before the key was set refuses the request by name, and every wrap
    /// made opens the value for the new runtime.
    #[test]
    fn recovery_wraps_open_for_the_new_runtime_and_older_values_are_named() {
        use tenkai::sealed_secret::{
            SealedOpener, SealedSecretEntry, SealedSecretList, SealedTarget, SecretRef,
        };
        let root = std::env::temp_dir().join(format!(
            "tenkaictl-recover-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let recovery_path = root.join("recovery.pem");
        let recovery_key = tenkai::sealing_key::generate_recovery_key(&recovery_path).unwrap();
        assert!(tenkai::sealing_key::generate_recovery_key(&recovery_path).is_err());
        let recovery = SealedOpener::from_pem_file(&recovery_path).unwrap();
        let lost_runtime = tenkai::sealing_key::SealingKey::open_or_generate(&root.join("old"))
            .unwrap()
            .public()
            .clone();
        let new_dir = root.join("new");
        let new_runtime = tenkai::sealing_key::SealingKey::open_or_generate(&new_dir)
            .unwrap()
            .public()
            .clone();
        let entry = |key: &str, recipients: &[tenkai::sealing_key::SealingPublicKey]| {
            let target =
                SealedTarget::new("prod", "api", SecretRef::new("db", key).unwrap()).unwrap();
            let sealed = tenkai::sealed_secret::seal(&target, key.as_bytes(), recipients).unwrap();
            SealedSecretEntry {
                instance: "api".into(),
                secret: "db".into(),
                key: key.into(),
                digest: tenkai::sealed_secret::digest(&target, &sealed).unwrap(),
                set_by: "operator".into(),
                set_at: 1,
                recipients: sealed
                    .wraps
                    .iter()
                    .map(|wrap| wrap.fingerprint.clone())
                    .collect(),
                sealed: Some(sealed),
            }
        };
        let mut list = SealedSecretList {
            environment: "prod".into(),
            secrets: vec![
                entry("password", &[lost_runtime.clone(), recovery_key.clone()]),
                entry("older", std::slice::from_ref(&lost_runtime)),
            ],
            recovery_key: Some(recovery_key.fingerprint()),
        };
        assert_eq!(list.without_recovery(), ["api db/older"]);
        let warning = list.recovery_warning().unwrap();
        assert!(warning.contains("1 sealed value"), "{warning}");

        let error = format!(
            "{:#}",
            recovered_wraps(&list, &recovery, &new_runtime).unwrap_err()
        );
        assert!(error.contains("api db/older"), "{error}");
        assert!(!error.contains("password"), "{error}");

        list.secrets.pop();
        let recovered = recovered_wraps(&list, &recovery, &new_runtime).unwrap();
        let [wrap] = recovered["api"].as_slice() else {
            panic!("one wrap for the one value");
        };
        assert_eq!(wrap.digest, list.secrets[0].digest);
        let target =
            SealedTarget::new("prod", "api", SecretRef::new("db", "password").unwrap()).unwrap();
        let mut sealed = list.secrets[0].sealed.clone().unwrap();
        sealed.wraps.push(wrap.wrap.clone());
        let opened = SealedOpener::load(&new_dir)
            .unwrap()
            .open(&target, &sealed)
            .unwrap();
        assert_eq!(opened.as_slice(), b"password");
        let _ = std::fs::remove_dir_all(root);
    }
}
