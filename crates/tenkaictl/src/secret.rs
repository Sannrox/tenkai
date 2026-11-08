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
        println!("{} {} {}", recipient.fingerprint, recipient.runtime_id, env);
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

/// `secret list`: one line per sealed key. Never a value.
pub(crate) fn print_list(list: &tenkai::sealed_secret::SealedSecretList) {
    if list.secrets.is_empty() {
        println!("{} has no sealed secrets", list.environment);
        return;
    }
    for entry in &list.secrets {
        println!(
            "{} {}/{} {} set_by={} set_at={} recipients={}",
            entry.instance,
            entry.secret,
            entry.key,
            entry.digest,
            entry.set_by,
            entry.set_at,
            entry.recipients.len()
        );
    }
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
}
