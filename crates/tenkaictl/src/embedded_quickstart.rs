use anyhow::{Result, bail};
use tenkai::{client, maintenance, ontology, plan};

use crate::args::{Cli, Command};

const LAB_ENV_DESCRIPTION: &str = "lab-only governed deploy (not production)";

/// Prepare a lab-only governed environment: keys, trust roots, policy, env.
///
/// Does not publish, plan, or apply. The documented path in README.md does that.
pub(crate) async fn run(cli: &Cli) -> Result<()> {
    let Command::Quickstart { dir, env } = &cli.command else {
        unreachable!("quickstart dispatcher received a non-quickstart command");
    };
    if env == "local" {
        bail!(
            "quickstart refuses the built-in local environment; pass --env lab (or another name that is not local)"
        );
    }
    tenkai::ontology::validate_identifier("environment", env)?;
    tenkai::storage::refuse_postgres_on_embedded()?;

    std::fs::create_dir_all(dir)?;
    let keys = dir.join("keys");
    let release_trust = dir.join("release-trust.toml");
    let approval_trust = dir.join("approval-trust.toml");
    let policy = dir.join("approval-policy.toml");

    tenkai::dev_sign::init_dev_keys(&keys)?;
    tenkai::dev_sign::write_dev_trust_roots(&keys, &release_trust, &approval_trust)?;
    if !policy.exists() {
        tenkai::dev_sign::write_lab_approval_policy(&policy)?;
    }

    let mut ctx = client::Ctx::embedded(&cli.database)?;
    let registered = ontology::register(&mut ctx).await?;
    if registered.is_empty() {
        println!("schema already registered");
    } else {
        println!("registered schema types ({})", registered.len());
    }
    println!(
        "{}",
        plan::env_add(&mut ctx, "local", "this machine").await?
    );
    let migrated = maintenance::migrate_all(&mut ctx).await?;
    println!("maintenance configuration ready for {migrated} environment(s)");
    let existing = plan::list_environments(&mut ctx)
        .await?
        .into_iter()
        .find(|entry| entry.name == *env);
    println!(
        "{}",
        plan::env_add(&mut ctx, env, LAB_ENV_DESCRIPTION).await?
    );
    let expected = policy.canonicalize()?;
    match plan::plan_approval_policy(&mut ctx, env).await? {
        Some(path) if path == expected => {}
        Some(path) => bail!(
            "quickstart refuses to replace {env} plan_approval_policy {} with {}",
            path.display(),
            expected.display()
        ),
        None if existing.is_none()
            || existing
                .as_ref()
                .is_some_and(|entry| entry.description == LAB_ENV_DESCRIPTION) =>
        {
            println!(
                "{}",
                plan::set_plan_approval_policy(&mut ctx, env, &policy).await?
            );
        }
        None => {
            bail!("quickstart refuses to bind an existing environment {env}; pass a new --env")
        }
    }

    println!("{}", tenkai::dev_sign::warning_line());
    println!("lab-only: environment {env} requires signed releases and signed plan approvals.");
    println!("initialized lab in {}", dir.display());
    println!("keys               {}", keys.display());
    println!("release trust      {}", release_trust.display());
    println!("approval trust     {}", approval_trust.display());
    println!("approval policy    {}", policy.display());
    println!();
    println!("Next (lab-only):");
    println!("  export TENKAI_MANAGEMENT_TOKEN=tenkai-local-management");
    println!(
        "  tenkaictl dev sign-release examples/hello-local/tenkai.toml --keys {} --signature {} --trust-roots {}",
        keys.display(),
        dir.join("hello-local-0.1.0.sig.json").display(),
        release_trust.display()
    );
    println!(
        "  tenkaictl publish examples/hello-local/tenkai.toml --signature {} --trust-roots {}",
        dir.join("hello-local-0.1.0.sig.json").display(),
        release_trust.display()
    );
    println!("  tenkaictl promote hello-local@0.1.0 stable");
    println!("  tenkaictl env subscribe {env} hello-local=stable");
    println!("  PLAN=$(tenkaictl plan --env {env} | awk '/^plan id:/ {{print $3}}')");
    println!(
        "  tenkaictl dev sign-approval \"$PLAN\" --keys {} --approval {} --trust-roots {}",
        keys.display(),
        dir.join("plan.approval.json").display(),
        approval_trust.display()
    );
    println!(
        "  tenkaictl apply \"$PLAN\" --approval {} --approval-trust-roots {}",
        dir.join("plan.approval.json").display(),
        approval_trust.display()
    );
    Ok(())
}
