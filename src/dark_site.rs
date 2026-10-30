//! Local-only dark-site deploy profile (#683).
//!
//! One profile pins a `model_runtime` digest beside a site-agent worker image,
//! binds those pins to an offline stack index, refuses cloud model routes while
//! active, and rolls back through existing worker-pool drain. The wider
//! commercial platform is not required; the only identity input is a local JWKS.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::atomic_state;
use crate::offline_bundle::OfflineStackManifest;
use crate::routing::RoutingConfig;
use crate::worker_pool::{
    MAX_REPLICAS, WorkerLifecycleSnapshot, WorkerPoolDecision, WorkerPoolSpec, pool_is_converged,
    reconcile,
};

pub const PROFILE_VERSION: u32 = 1;
pub const ACTIVATION_SCHEMA: &str = "tenkai.dark-site.activation.v1";
pub const ACTIVATION_FILE: &str = "dark-site.json";
pub const SITE_AGENT_PROFILE: &str = "site-agent";
pub const LOCAL_PROVIDER: &str = "local";
pub const LOCAL_AUDIENCE: &str = "local";

/// Version 1 dark-site deploy profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DarkSiteProfile {
    pub version: u32,
    pub model_runtime: ModelRuntimePin,
    pub site_agent: SiteAgentPin,
    pub routing: LocalRouting,
    pub verifier: LocalVerifier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRuntimePin {
    pub product: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteAgentPin {
    pub product: String,
    pub version: String,
    /// Shikigami serve profile name; must be `site-agent`.
    pub profile: String,
    pub image_digest: String,
    pub replicas: u32,
    pub drain_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRouting {
    pub audience: String,
    pub model: String,
    pub allowed_providers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVerifier {
    /// Relative path to a local JWKS file. No parent segments.
    pub jwks: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DarkSitePins {
    pub model_digest: String,
    pub worker_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudRouteRefusal {
    pub at_ms: i64,
    pub route: String,
    pub model: String,
    pub provider: String,
    pub reason: String,
}

/// Durable activation written beside environment runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DarkSiteActivation {
    pub schema: String,
    pub profile_digest: String,
    pub profile: DarkSiteProfile,
    pub previous: Option<DarkSitePins>,
    pub activated_at_ms: i64,
    #[serde(default)]
    pub cloud_route_refusals: Vec<CloudRouteRefusal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyReport {
    pub ready: bool,
    pub model_healthy: bool,
    pub workers_ready: u32,
    pub workers_desired: u32,
    pub detail: String,
}

impl DarkSiteProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading dark-site profile {}", path.display()))?;
        let profile: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing dark-site profile {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PROFILE_VERSION {
            bail!("dark-site profile version must be {PROFILE_VERSION}");
        }
        crate::ontology::validate_identifier("model_runtime.product", &self.model_runtime.product)?;
        crate::ontology::validate_identifier("model_runtime.version", &self.model_runtime.version)?;
        validate_digest("model_runtime.digest", &self.model_runtime.digest)?;
        crate::ontology::validate_identifier("site_agent.product", &self.site_agent.product)?;
        crate::ontology::validate_identifier("site_agent.version", &self.site_agent.version)?;
        if self.site_agent.profile != SITE_AGENT_PROFILE {
            bail!(
                "site_agent.profile must be {SITE_AGENT_PROFILE}, got {}",
                self.site_agent.profile
            );
        }
        validate_digest("site_agent.image_digest", &self.site_agent.image_digest)?;
        if self.site_agent.replicas == 0 || self.site_agent.replicas > MAX_REPLICAS {
            bail!("site_agent.replicas must be 1..={MAX_REPLICAS}");
        }
        if self.site_agent.drain_timeout_ms == 0 || self.site_agent.drain_timeout_ms > 3_600_000 {
            bail!("site_agent.drain_timeout_ms is missing or unbounded");
        }
        crate::ontology::validate_identifier("routing.model", &self.routing.model)?;
        if self.routing.audience != LOCAL_AUDIENCE {
            bail!(
                "routing.audience must be {LOCAL_AUDIENCE}, got {}",
                self.routing.audience
            );
        }
        if self.routing.allowed_providers.is_empty()
            || self
                .routing
                .allowed_providers
                .iter()
                .any(|provider| provider != LOCAL_PROVIDER)
        {
            bail!("dark-site routing admits only the {LOCAL_PROVIDER} provider");
        }
        validate_relative_path("verifier.jwks", &self.verifier.jwks)?;
        Ok(())
    }

    pub fn pins(&self) -> DarkSitePins {
        DarkSitePins {
            model_digest: self.model_runtime.digest.clone(),
            worker_digest: self.site_agent.image_digest.clone(),
        }
    }

    pub fn digest(&self) -> Result<String> {
        let encoded = serde_json::to_vec(self).context("encode dark-site profile")?;
        Ok(format!("sha256:{:x}", Sha256::digest(encoded)))
    }

    pub fn worker_spec(&self) -> Result<WorkerPoolSpec> {
        crate::worker_pool::spec_from_section(
            self.site_agent.product.clone(),
            self.site_agent.version.clone(),
            &crate::manifest::WorkerPoolSection {
                intake: crate::worker_pool::INTAKE_PLANE.into(),
                replicas: self.site_agent.replicas,
                drain_timeout_ms: self.site_agent.drain_timeout_ms,
            },
        )
    }
}

/// Bind profile pins to a signed offline stack index. No origin pull.
pub fn bind_stack(profile: &DarkSiteProfile, stack: &OfflineStackManifest) -> Result<()> {
    profile.validate()?;
    if stack.schema != crate::offline_bundle::STACK_MANIFEST_SCHEMA {
        bail!("unsupported offline stack schema {}", stack.schema);
    }
    if !stack
        .weights
        .iter()
        .any(|digest| digest == &profile.model_runtime.digest)
    {
        bail!(
            "offline stack does not carry model_runtime digest {}",
            profile.model_runtime.digest
        );
    }
    if !stack
        .images
        .iter()
        .any(|digest| digest == &profile.site_agent.image_digest)
    {
        bail!(
            "offline stack does not carry site-agent image digest {}",
            profile.site_agent.image_digest
        );
    }
    Ok(())
}

pub fn activation_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(ACTIVATION_FILE)
}

pub fn load_activation(runtime_dir: &Path) -> Result<Option<DarkSiteActivation>> {
    match atomic_state::read_json_optional::<DarkSiteActivation>(&activation_path(runtime_dir))? {
        Some(activation) => {
            if activation.schema != ACTIVATION_SCHEMA {
                bail!(
                    "unsupported dark-site activation schema {}",
                    activation.schema
                );
            }
            activation.profile.validate()?;
            Ok(Some(activation))
        }
        None => Ok(None),
    }
}

pub fn store_activation(runtime_dir: &Path, activation: &DarkSiteActivation) -> Result<()> {
    if activation.schema != ACTIVATION_SCHEMA {
        bail!(
            "unsupported dark-site activation schema {}",
            activation.schema
        );
    }
    activation.profile.validate()?;
    atomic_state::write_json_verified::<_, DarkSiteActivation, _>(
        &activation_path(runtime_dir),
        activation,
        |observed| {
            if observed != activation {
                bail!("dark-site activation post-mutation verification failed");
            }
            Ok(())
        },
    )
}

/// Activate after the bundle stack is bound. `jwks_root` is the profile file's parent.
pub fn activate(
    profile: &DarkSiteProfile,
    stack: &OfflineStackManifest,
    runtime_dir: &Path,
    jwks_root: &Path,
    now_ms: i64,
) -> Result<DarkSiteActivation> {
    profile.validate()?;
    bind_stack(profile, stack)?;
    let jwks = jwks_root.join(&profile.verifier.jwks);
    if !jwks.is_file() {
        bail!("local JWKS {} is missing", jwks.display());
    }
    let previous = load_activation(runtime_dir)?
        .map(|prior| prior.profile.pins())
        .filter(|pins| pins != &profile.pins());
    let activation = DarkSiteActivation {
        schema: ACTIVATION_SCHEMA.into(),
        profile_digest: profile.digest()?,
        profile: profile.clone(),
        previous,
        activated_at_ms: now_ms,
        cloud_route_refusals: Vec::new(),
    };
    store_activation(runtime_dir, &activation)?;
    Ok(activation)
}

pub fn admit_applied_routing(runtime_dir: &Path, config: &RoutingConfig) -> Result<()> {
    admit_applied_routing_at(runtime_dir, config, crate::now_millis())
}

/// Refuse cloud model routes while a dark-site profile is active, and audit each refusal.
pub fn admit_applied_routing_at(
    runtime_dir: &Path,
    config: &RoutingConfig,
    now_ms: i64,
) -> Result<()> {
    let Some(mut activation) = load_activation(runtime_dir)? else {
        return Ok(());
    };
    let mut refused = Vec::new();
    let mut wrong_model = None;
    for route in &config.routes {
        if route.provider != LOCAL_PROVIDER {
            refused.push(CloudRouteRefusal {
                at_ms: now_ms,
                route: route.name.clone(),
                model: route.model.clone(),
                provider: route.provider.clone(),
                reason: "cloud_route_refused".into(),
            });
        }
        if route.model != activation.profile.routing.model && wrong_model.is_none() {
            wrong_model = Some(route.model.clone());
        }
    }
    if !refused.is_empty() {
        activation.cloud_route_refusals.extend(refused);
        store_activation(runtime_dir, &activation)?;
        bail!("dark-site profile refuses cloud model routes while active");
    }
    if let Some(model) = wrong_model {
        bail!(
            "dark-site profile pins routing to local model {}, got {model}",
            activation.profile.routing.model
        );
    }
    Ok(())
}

pub fn ready(
    profile: &DarkSiteProfile,
    model_healthy: bool,
    workers: &[WorkerLifecycleSnapshot],
) -> Result<ReadyReport> {
    profile.validate()?;
    let spec = profile.worker_spec()?;
    let workers_ready = workers
        .iter()
        .filter(|snapshot| {
            snapshot.product == spec.product
                && snapshot.version == spec.version
                && matches!(snapshot.state.as_str(), "ready" | "active")
        })
        .count() as u32;
    let converged = model_healthy && pool_is_converged(&spec, workers);
    Ok(ReadyReport {
        ready: converged,
        model_healthy,
        workers_ready,
        workers_desired: spec.replicas,
        detail: if converged {
            "dark-site ready".into()
        } else if !model_healthy {
            "model_runtime is not healthy".into()
        } else {
            format!(
                "site-agent workers not ready (ready {workers_ready}, desired {})",
                spec.replicas
            )
        },
    })
}

/// Digest-pinned rollback uses existing worker-pool drain when claims remain.
pub fn rollback_decision(
    activation: &DarkSiteActivation,
    workers: &[WorkerLifecycleSnapshot],
    drain_started_at_ms: Option<i64>,
    now_ms: i64,
) -> Result<WorkerPoolDecision> {
    let Some(previous) = activation.previous.as_ref() else {
        bail!("dark-site rollback requires a digest-pinned predecessor");
    };
    let mut spec = activation.profile.worker_spec()?;
    spec.version = previous.worker_digest.clone();
    reconcile(
        &spec,
        workers,
        activation.profile.site_agent.replicas,
        drain_started_at_ms,
        now_ms,
    )
}

fn validate_digest(field: &str, value: &str) -> Result<()> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if !valid {
        bail!("{field} must be a canonical sha256 digest");
    }
    Ok(())
}

fn validate_relative_path(field: &str, value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::Prefix(_) | Component::ParentDir))
    {
        bail!("{field} must be a relative path without parent segments");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_bundle::STACK_MANIFEST_SCHEMA;
    use crate::routing::Route;
    use crate::worker_pool::{LIFECYCLE_PROTOCOL, LIFECYCLE_SCHEMA_VERSION};

    const MODEL: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const WORKER: &str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const PREV_WORKER: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn profile() -> DarkSiteProfile {
        DarkSiteProfile {
            version: 1,
            model_runtime: ModelRuntimePin {
                product: "qwen-coder".into(),
                version: "0.1.0".into(),
                digest: MODEL.into(),
            },
            site_agent: SiteAgentPin {
                product: "site-agent-workers".into(),
                version: "1.0.0".into(),
                profile: SITE_AGENT_PROFILE.into(),
                image_digest: WORKER.into(),
                replicas: 2,
                drain_timeout_ms: 5_000,
            },
            routing: LocalRouting {
                audience: LOCAL_AUDIENCE.into(),
                model: "qwen-coder".into(),
                allowed_providers: vec![LOCAL_PROVIDER.into()],
            },
            verifier: LocalVerifier {
                jwks: "jwks.json".into(),
            },
        }
    }

    fn stack() -> OfflineStackManifest {
        OfflineStackManifest {
            schema: STACK_MANIFEST_SCHEMA.into(),
            images: vec![WORKER.into()],
            weights: vec![MODEL.into()],
            schemas: Vec::new(),
            hub: Vec::new(),
        }
    }

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "tenkai-dark-site-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    fn snapshot(version: &str, state: &str, claims: u32) -> WorkerLifecycleSnapshot {
        WorkerLifecycleSnapshot {
            schema_version: LIFECYCLE_SCHEMA_VERSION,
            protocol: LIFECYCLE_PROTOCOL.into(),
            product: "site-agent-workers".into(),
            version: version.into(),
            worker_id: "w1".into(),
            namespace: "ns".into(),
            runtime_id: "rt".into(),
            intake: crate::worker_pool::INTAKE_PLANE.into(),
            state: state.into(),
            accepting_claims: state == "ready",
            active_claims: claims,
            active_runs: claims,
            configured_concurrency: 1,
            governance_ok: true,
            fencing_ok: true,
        }
    }

    fn write_profile(dir: &Path, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("profile.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn load_rejects_cloud_providers_and_missing_worker_pin() {
        let dir = tmp();
        let err = DarkSiteProfile::load(&write_profile(
            &dir,
            r#"
version = 1
[model_runtime]
product = "qwen-coder"
version = "0.1.0"
digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
[site_agent]
product = "site-agent-workers"
version = "1.0.0"
profile = "site-agent"
image_digest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
replicas = 2
drain_timeout_ms = 5000
[routing]
audience = "local"
model = "qwen-coder"
allowed_providers = ["openai"]
[verifier]
jwks = "jwks.json"
"#,
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("admits only the local provider"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bind_stack_is_local_only_and_requires_both_digests() {
        let profile = profile();
        bind_stack(&profile, &stack()).unwrap();
        let mut missing_weight = stack();
        missing_weight.weights.clear();
        let err = bind_stack(&profile, &missing_weight)
            .unwrap_err()
            .to_string();
        assert!(err.contains("model_runtime digest"), "{err}");
        let mut missing_image = stack();
        missing_image.images.clear();
        let err = bind_stack(&profile, &missing_image)
            .unwrap_err()
            .to_string();
        assert!(err.contains("site-agent image digest"), "{err}");
    }

    #[test]
    fn activate_ready_and_cloud_routes_are_refused_and_audited() {
        let root = tmp();
        let runtime = root.join("runtime");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("jwks.json"), "{\"keys\":[]}").unwrap();
        let profile = profile();
        activate(&profile, &stack(), &runtime, &root, 1_000).unwrap();

        let local = RoutingConfig {
            version: 1,
            routes: vec![Route {
                name: "chat".into(),
                model: "qwen-coder".into(),
                provider: LOCAL_PROVIDER.into(),
                weight: 100,
            }],
        };
        admit_applied_routing_at(&runtime, &local, 1_100).unwrap();

        let cloud = RoutingConfig {
            version: 1,
            routes: vec![Route {
                name: "chat".into(),
                model: "qwen-coder".into(),
                provider: "openai".into(),
                weight: 100,
            }],
        };
        let err = admit_applied_routing_at(&runtime, &cloud, 1_200)
            .unwrap_err()
            .to_string();
        assert!(err.contains("refuses cloud model routes"), "{err}");
        let activation = load_activation(&runtime).unwrap().unwrap();
        assert_eq!(activation.cloud_route_refusals.len(), 1);
        assert_eq!(activation.cloud_route_refusals[0].provider, "openai");
        assert_eq!(
            activation.cloud_route_refusals[0].reason,
            "cloud_route_refused"
        );

        let workers = vec![
            snapshot("1.0.0", "ready", 0),
            WorkerLifecycleSnapshot {
                worker_id: "w2".into(),
                ..snapshot("1.0.0", "ready", 0)
            },
        ];
        let report = ready(&profile, true, &workers).unwrap();
        assert!(report.ready, "{}", report.detail);
        let not_ready = ready(&profile, false, &workers).unwrap();
        assert!(!not_ready.ready);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn digest_pinned_rollback_waits_for_worker_drain() {
        let root = tmp();
        let runtime = root.join("runtime");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("jwks.json"), "{\"keys\":[]}").unwrap();
        let mut first = profile();
        first.site_agent.image_digest = PREV_WORKER.into();
        let mut first_stack = stack();
        first_stack.images = vec![PREV_WORKER.into()];
        activate(&first, &first_stack, &runtime, &root, 1_000).unwrap();
        let second = profile();
        let activation = activate(&second, &stack(), &runtime, &root, 2_000).unwrap();
        assert_eq!(
            activation.previous.as_ref().unwrap().worker_digest,
            PREV_WORKER
        );

        let busy = vec![
            snapshot(WORKER, "active", 1),
            WorkerLifecycleSnapshot {
                worker_id: "w2".into(),
                ..snapshot(WORKER, "ready", 0)
            },
        ];
        let decision = rollback_decision(&activation, &busy, Some(2_000), 2_100).unwrap();
        assert_eq!(decision, WorkerPoolDecision::WaitDrain);

        let drained = vec![
            snapshot(PREV_WORKER, "ready", 0),
            WorkerLifecycleSnapshot {
                worker_id: "w2".into(),
                ..snapshot(PREV_WORKER, "ready", 0)
            },
        ];
        let decision = rollback_decision(&activation, &drained, Some(2_000), 2_100).unwrap();
        assert_eq!(decision, WorkerPoolDecision::Apply { replicas: 2 });
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn activate_fails_closed_without_local_jwks() {
        let root = tmp();
        std::fs::create_dir_all(&root).unwrap();
        let err = activate(&profile(), &stack(), &root.join("runtime"), &root, 1_000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("JWKS"), "{err}");
        assert!(!activation_path(&root.join("runtime")).exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
