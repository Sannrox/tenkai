use anyhow::{Result, bail};

use crate::args::Command;
use crate::catalog_args::{ApprovalCommand, ReleaseCommand};
use crate::env_args::EnvCommand;

pub(crate) async fn run(client: &tenkai::server::RemoteClient, command: Command) -> Result<()> {
    match command {
        Command::Publish {
            manifest,
            signature,
            trust_roots,
            allow_unsigned_development,
            provenance,
            provenance_trust_roots,
            change_set_evidence,
        } => {
            if allow_unsigned_development
                || !provenance.is_empty()
                || provenance_trust_roots.is_some()
                || change_set_evidence.is_some()
            {
                bail!(
                    "the local-development publish bypass and extra publication evidence are available only with --target embedded"
                );
            }
            let signature = signature
                .ok_or_else(|| anyhow::anyhow!("--signature is required with --target remote"))?;
            let trust_roots = trust_roots
                .ok_or_else(|| anyhow::anyhow!("--trust-roots is required with --target remote"))?;
            let request = tenkai::management_lifecycle::load_publish_request(
                &manifest,
                &signature,
                &trust_roots,
            )?;
            let result = client.publish_release(&request).await?;
            println!("{}", result.message);
            Ok(())
        }
        Command::Promote { spec, channel } => {
            let result = client.promote_release(&spec, &channel).await?;
            println!("{}", result.message);
            Ok(())
        }
        Command::Release {
            command: ReleaseCommand::Recall { spec },
        } => {
            let result = client.recall_release(&spec).await?;
            println!("{}", result.message);
            Ok(())
        }
        Command::Env {
            command:
                EnvCommand::Subscribe {
                    env,
                    spec,
                    generation,
                },
        } => {
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let result = client
                .subscribe_environment(&env, &spec, generation)
                .await?;
            println!("{}", result.message);
            Ok(())
        }
        Command::Plan { env, generation } => {
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let result = client.plan_environment(&env, generation).await?;
            println!("{}", result.message);
            if let Some(plan_id) = &result.resource {
                println!("plan id: {plan_id}");
            }
            if let Some(digest) = &result.digest {
                println!("plan digest: {digest}");
            }
            Ok(())
        }
        Command::Approval {
            command:
                ApprovalCommand::Submit {
                    plan_id,
                    env,
                    approval,
                    approval_trust_roots,
                    generation,
                },
        } => {
            let generation = generation
                .ok_or_else(|| anyhow::anyhow!("--generation is required with --target remote"))?;
            let request = tenkai::management_lifecycle::load_approve_request(
                &env,
                generation,
                &approval,
                &approval_trust_roots,
            )?;
            let result = client.approve_plan(&plan_id, &request).await?;
            println!("{}", result.message);
            Ok(())
        }
        other => crate::remote_delivery::run(client, other).await,
    }
}
