use anyhow::{Context as _, Result, bail};
use tenkai::key_revocation::{self, RevocationList, RevocationStatement, RevokedKey};

use crate::args::RevocationsCommand;

/// Revocation lists need no Tenkai state: they live at the configured path.
pub(crate) fn run(command: &RevocationsCommand) -> Result<()> {
    match command {
        RevocationsCommand::Sign {
            signing_key,
            sequence,
            revoke,
            out,
        } => {
            let revoked = revoke
                .iter()
                .map(|spec| {
                    let (key_id, reason) = spec
                        .split_once('=')
                        .with_context(|| format!("--revoke {spec} must be <key_id>=<reason>"))?;
                    Ok(RevokedKey {
                        key_id: key_id.into(),
                        reason: reason.into(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let list = key_revocation::sign(
                RevocationStatement {
                    sequence: *sequence,
                    issued_at: tenkai::now_millis(),
                    revoked,
                },
                signing_key,
            )?;
            std::fs::write(out, serde_json::to_vec_pretty(&list)?)
                .with_context(|| format!("writing {}", out.display()))?;
            println!(
                "signed key revocations sequence {sequence} ({} keys) by {}",
                list.statement.revoked.len(),
                list.key_id
            );
        }
        RevocationsCommand::Import { list } => {
            let Some((installed, authorities)) = key_revocation::configured()? else {
                bail!(
                    "set {} and {} to import key revocations",
                    key_revocation::REVOCATIONS_ENV,
                    key_revocation::REVOCATION_TRUST_ROOTS_ENV
                );
            };
            let list = RevocationList::load(list)?;
            key_revocation::install(&list, &authorities, &installed)?;
            println!(
                "installed key revocations sequence {} ({} keys)",
                list.statement.sequence,
                list.statement.revoked.len()
            );
        }
        RevocationsCommand::Show => {
            let Some((installed, _)) = key_revocation::configured()? else {
                println!("no key revocations configured");
                return Ok(());
            };
            if !installed.exists() {
                println!("no key revocations installed");
                return Ok(());
            }
            let list = RevocationList::load(&installed)?;
            println!(
                "sequence {} signed by {}",
                list.statement.sequence, list.key_id
            );
            for revoked in &list.statement.revoked {
                println!("revoked {}: {}", revoked.key_id, revoked.reason);
            }
        }
    }
    Ok(())
}
