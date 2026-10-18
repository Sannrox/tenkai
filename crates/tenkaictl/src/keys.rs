use anyhow::Result;
use tenkai::key_provider::{self, CeremonyRequest, DeployProfile};

use crate::args::KeysCommand;

/// Key ceremony needs no Tenkai operational store: evidence is a signed file.
pub(crate) fn run(command: &KeysCommand) -> Result<()> {
    match command {
        KeysCommand::Ceremony {
            profile,
            signing_key,
            custodian,
            tenant,
            provider_dir,
            out,
        } => {
            let profile = DeployProfile::load(profile)?;
            key_provider::refuse_evidence_path(out, provider_dir, signing_key)?;
            let reservation = key_provider::reserve_evidence(out)?;
            let evidence = match key_provider::run_ceremony(CeremonyRequest {
                profile: &profile,
                signing_key,
                custodians: custodian,
                tenants: tenant,
                provider_dir,
                issued_at: tenkai::now_millis(),
            }) {
                Ok(evidence) => evidence,
                Err(error) => {
                    reservation.discard();
                    return Err(error);
                }
            };
            if let Err(error) = evidence.verify() {
                reservation.discard();
                return Err(error);
            }
            key_provider::write_evidence(reservation, &evidence)?;
            println!(
                "signed key ceremony for {} tenants by {} (root {})",
                evidence.statement.data_keys.len(),
                evidence.key_id,
                evidence.statement.root_key_id
            );
        }
    }
    Ok(())
}
