//! Client recipient pins for sealed secrets (ADR 0045).

use anyhow::{Result, bail};
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

pub(crate) fn require_fingerprint(value: &str) -> Result<String> {
    normalize_fingerprint(value)
}

fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}
