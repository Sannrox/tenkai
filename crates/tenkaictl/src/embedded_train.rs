use anyhow::Result;
use tenkai::{client, release_train};

use crate::authorization::embedded_management_actor;
use crate::train_args::TrainCommand;

pub(crate) async fn run(ctx: &mut client::Ctx, command: TrainCommand) -> Result<()> {
    let train = match command {
        TrainCommand::Admit {
            profile,
            signature,
            trust_roots,
        } => {
            let actor = embedded_management_actor()?;
            release_train::admit(
                ctx,
                &actor,
                &release_train::Evidence {
                    profile: &profile,
                    signature: &signature,
                    trust_roots: &trust_roots,
                },
            )
            .await?
        }
        TrainCommand::Promote {
            name,
            approve_gates,
        } => {
            let actor = embedded_management_actor()?;
            release_train::promote_stable(ctx, &actor, &name, approve_gates).await?
        }
        TrainCommand::Show { name } => release_train::show(ctx, &name).await?,
    };
    println!("train {} ({:?})", train.name, train.channel);
    if !train.gate_flags.is_empty() {
        println!("  gate flags: {:?}", train.gate_flags);
    }
    for (component, (version, digest)) in &train.components {
        println!("  {component}@{version} {digest}");
    }
    Ok(())
}
