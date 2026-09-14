//! Fifty-spoke offline upgrade and rollback drill (#378).
//!
//! One signed release payload is exported per isolated environment, applied
//! without treating the hub as reachable, then half the spokes roll back on
//! injected health failure. Reconnect is receipt import plus fleet status.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, bail};
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use crate::apply::ExecutionAuthorization;
use crate::auth_context::AuthenticatedRequestContext;
use crate::catalog::PublishOptions;
use crate::client::Ctx;
use crate::connectivity::{self, ConnectivityClass, UpgradeEnvironmentStatus, UpgradeSpec};
use crate::offline_bundle::BundleEnvelope;
use crate::plan;
use crate::release_signing::{TRUST_ROOT_VERSION, TrustRoots, TrustedSigner};

pub const SPOKE_COUNT: usize = 50;
pub const ROLLBACK_COUNT: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrillReport {
    pub upgraded: Vec<String>,
    pub rolled_back: Vec<String>,
    pub spoke_deployed: BTreeMap<String, String>,
    pub hub_deployed: BTreeMap<String, String>,
}

pub fn spoke_name(index: usize) -> String {
    format!("spoke-{index:02}")
}

pub async fn rehearse(
    ctx: &mut Ctx,
    root: &Path,
    actor: &AuthenticatedRequestContext,
) -> Result<DrillReport> {
    publish_signed(ctx, root, "1.0.0").await?;
    publish_signed(ctx, root, "1.1.0").await?;
    crate::catalog::promote(ctx, actor, "edge-app@1.0.0", "stable").await?;
    crate::catalog::promote(ctx, actor, "edge-app@1.1.0", "stable").await?;

    let spokes = (0..SPOKE_COUNT).map(spoke_name).collect::<Vec<_>>();
    for name in &spokes {
        plan::env_add(ctx, name, "offline drill spoke").await?;
        connectivity::set_connectivity_class(ctx, name, ConnectivityClass::Isolated).await?;
        plan::subscribe(ctx, name, "edge-app", "stable").await?;
        plan::reconcile_deployment(ctx, name, "edge-app", Some("1.0.0")).await?;
    }

    let spec = UpgradeSpec {
        name: "offline-fifty".into(),
        product: "edge-app".into(),
        version: "1.1.0".into(),
        channel: "stable".into(),
        environments: spokes.clone(),
    };
    let started = connectivity::start_or_resume(ctx, &spec).await?;
    let keys = root.join("keys");
    let approval_dir = root.join("approvals");
    let trust = root.join("1.1.0").join("release-trust.toml");
    std::fs::create_dir_all(&approval_dir)?;
    for environment in &started.environments {
        let Some(plan_id) = &environment.plan_id else {
            continue;
        };
        let envelope = approval_dir.join(format!("{}.json", plan_id.replace(':', "_")));
        crate::dev_sign::sign_plan_approval(
            &keys,
            &root.join("tenkai.db"),
            plan_id,
            &envelope,
            &trust,
            3600,
        )
        .await?;
    }

    let exporter = SigningKey::from_bytes(&[7; 32]);
    let runtime = SigningKey::from_bytes(&[9; 32]);
    let roots = isolated_trust_roots(&exporter, &runtime);
    let mut first_bundle: Option<(String, BundleEnvelope)> = None;
    for _ in 0..SPOKE_COUNT {
        let interrupted = connectivity::advance(
            ctx,
            "offline-fifty",
            ExecutionAuthorization::LocalDevelopment {
                reason: "offline drill waiting for bundle",
            },
        )
        .await?;
        let target = interrupted
            .environments
            .iter()
            .find(|candidate| candidate.status == UpgradeEnvironmentStatus::Interrupted)
            .ok_or_else(|| anyhow::anyhow!("upgrade did not interrupt an isolated spoke"))?;
        let plan_id = target
            .plan_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("isolated spoke {} has no plan", target.name))?;
        let approval = approval_dir.join(format!("{}.json", plan_id.replace(':', "_")));
        let bundle = connectivity::export_isolated_bundle(
            &target.name,
            plan_id,
            &started.release_id,
            b"offline-fifty-release",
            &exporter,
            crate::now_millis(),
        )?;
        connectivity::bind_isolated_bundle(ctx, "offline-fifty", &target.name, &bundle, &roots)
            .await?;
        connectivity::bind_isolated_bundle(ctx, "offline-fifty", &target.name, &bundle, &roots)
            .await?;
        let verified = bundle.verify(
            &roots,
            crate::ontology::NS,
            &target.name,
            crate::now_millis(),
        )?;
        let receipt = connectivity::export_isolated_receipt(
            &verified,
            &runtime,
            "runtime-1",
            "step-1",
            b"installed",
            crate::now_millis(),
        )?;
        connectivity::import_isolated_receipt(
            ctx,
            "offline-fifty",
            &target.name,
            &receipt,
            &bundle,
            &roots,
        )
        .await?;
        connectivity::advance(
            ctx,
            "offline-fifty",
            ExecutionAuthorization::Signed {
                approval: &approval,
                trust_roots: &trust,
            },
        )
        .await?;
        if first_bundle.is_none() {
            first_bundle = Some((target.name.clone(), bundle));
        }
    }

    let upgraded = connectivity::load_upgrade(ctx, "offline-fifty").await?;
    if upgraded
        .environments
        .iter()
        .any(|environment| environment.status != UpgradeEnvironmentStatus::Applied)
    {
        bail!(
            "expected every spoke to apply from the bundle, got {}",
            connectivity::format_upgrade(&upgraded)
        );
    }

    let rolled_back = spokes[..ROLLBACK_COUNT].to_vec();
    for name in &rolled_back {
        crate::environment::record_observed_health(
            ctx,
            name,
            "edge-app",
            false,
            "injected health failure",
        )
        .await?;
        let step = plan::rollback_step(ctx, name, "edge-app").await?;
        let rollback = plan::create_from_steps(ctx, name, vec![step]).await?;
        let approval = approval_dir.join(format!("rollback-{}.json", name));
        crate::dev_sign::sign_plan_approval(
            &keys,
            &root.join("tenkai.db"),
            &rollback.id,
            &approval,
            &trust,
            3600,
        )
        .await?;
        crate::apply::execute_with_options(
            ctx,
            &rollback.id,
            crate::apply::ExecutionOptions {
                skip_gates: false,
                emergency_reason: None,
                authorization: ExecutionAuthorization::Signed {
                    approval: &approval,
                    trust_roots: &trust,
                },
                software_executor: Some(std::sync::Arc::new(
                    crate::software_executor::FakeSoftwareExecutor::new(),
                )),
                worker_lifecycle: None,
                artifact_registry: None,
                delivery_adapter: None,
                delivery_fence: None,
            },
        )
        .await?;
        crate::environment::record_observed_health(ctx, name, "edge-app", true, "").await?;
    }

    if let Some((name, bundle)) = first_bundle {
        let again =
            connectivity::bind_isolated_bundle(ctx, "offline-fifty", &name, &bundle, &roots)
                .await?;
        let spoke = again
            .environments
            .iter()
            .find(|candidate| candidate.name == name)
            .ok_or_else(|| anyhow::anyhow!("missing spoke {name} after replay"))?;
        if spoke.isolated.is_none() {
            bail!("re-importing the same bundle dropped isolated evidence");
        }
    }

    let spoke_deployed = spoke_versions(ctx, &spokes).await?;
    let mut hub_deployed = BTreeMap::new();
    for name in &spokes {
        let inspect = plan::inspect_environment(ctx, name).await?;
        let deployed = inspect
            .subscriptions
            .iter()
            .find(|subscription| subscription.product == "edge-app")
            .and_then(|subscription| subscription.deployed.clone())
            .ok_or_else(|| anyhow::anyhow!("hub inspect for {name} has no deployed edge-app"))?;
        hub_deployed.insert(name.clone(), deployed);
    }
    let fleet = plan::fleet_status(ctx).await?;
    if fleet.environments_behind != ROLLBACK_COUNT
        || fleet.environments_current != SPOKE_COUNT - ROLLBACK_COUNT
    {
        bail!(
            "hub fleet posture current={} behind={} expected current={} behind={}",
            fleet.environments_current,
            fleet.environments_behind,
            SPOKE_COUNT - ROLLBACK_COUNT,
            ROLLBACK_COUNT
        );
    }
    if spoke_deployed != hub_deployed {
        bail!(
            "hub fleet status does not match spoke evidence: spoke={spoke_deployed:?} hub={hub_deployed:?}"
        );
    }
    for name in &spokes[ROLLBACK_COUNT..] {
        if spoke_deployed.get(name).map(String::as_str) != Some("1.1.0") {
            bail!("upgraded spoke {name} should remain on 1.1.0, got {spoke_deployed:?}");
        }
    }
    for name in &rolled_back {
        if spoke_deployed.get(name).map(String::as_str) != Some("1.0.0") {
            bail!("rolled-back spoke {name} should return to 1.0.0, got {spoke_deployed:?}");
        }
    }
    Ok(DrillReport {
        upgraded: spokes[ROLLBACK_COUNT..].to_vec(),
        rolled_back,
        spoke_deployed,
        hub_deployed,
    })
}

async fn publish_signed(ctx: &mut Ctx, root: &Path, version: &str) -> Result<()> {
    let dir = root.join(version);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("tenkai.toml"),
        format!(
            r#"
[product]
name = "edge-app"
version = "{version}"

[deploy]
install = "true"
"#
        ),
    )?;
    let keys = root.join("keys");
    let signature = dir.join("release.sig.json");
    let trust = dir.join("release-trust.toml");
    crate::dev_sign::sign_release(&keys, &dir.join("tenkai.toml"), &signature, &trust)?;
    crate::catalog::publish(
        ctx,
        &dir.join("tenkai.toml"),
        &PublishOptions {
            signature: Some(signature),
            trust_roots: Some(trust),
            allow_unsigned_development: false,
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

async fn spoke_versions(ctx: &mut Ctx, spokes: &[String]) -> Result<BTreeMap<String, String>> {
    let mut versions = BTreeMap::new();
    for name in spokes {
        let env = crate::environment::environment(ctx, name).await?;
        let Some(version) = env.properties.get("deployed.edge-app").cloned() else {
            bail!("spoke {name} has no local deployed.edge-app evidence");
        };
        versions.insert(name.clone(), version);
    }
    Ok(versions)
}

fn isolated_trust_roots(exporter: &SigningKey, runtime: &SigningKey) -> TrustRoots {
    TrustRoots {
        version: TRUST_ROOT_VERSION,
        signers: vec![
            TrustedSigner {
                key_id: crate::signature_verification::key_id(&exporter.verifying_key().to_bytes()),
                identity: "exporter".into(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(exporter.verifying_key().to_bytes()),
            },
            TrustedSigner {
                key_id: crate::signature_verification::key_id(&runtime.verifying_key().to_bytes()),
                identity: "airgap-runtime".into(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(runtime.verifying_key().to_bytes()),
            },
        ],
    }
}
