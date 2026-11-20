//! Plan-time artifact availability (#1062).
//!
//! Planning resolves each step's digest-bound artifacts through the
//! environment's mirrors, as apply does, and asks the configured store whether
//! each digest is there. The answer is advice, recorded on the plan outside its
//! content address: apply keeps its own check. Only a definite absence refuses
//! the plan; a store error or an environment the planner cannot reach records
//! `unverifiable`, so a flaky registry never refuses plans. The check reads and
//! never stores or pulls.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::client::Ctx;
use crate::connectivity::{CONNECTIVITY_CLASS_PROPERTY, ConnectivityClass};
use crate::oci_artifact::{ArtifactRegistry, OciArtifactRef};
use crate::plan::Step;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    Available,
    Missing,
    Unverifiable,
}

/// What planning found for one artifact digest in the registry the
/// environment pulls from (the mirror when one is configured).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactAvailability {
    pub digest: String,
    pub registry: String,
    pub state: ArtifactState,
}

/// Classify every artifact the plan's steps (and their restore pins) name.
/// Refuses the plan when a probed digest is missing, or when a probed
/// registry has no mirror, which apply would refuse as an origin pull.
pub(super) async fn check(
    ctx: &mut Ctx,
    env_properties: &HashMap<String, String>,
    steps: &[Step],
    registry: Option<&dyn ArtifactRegistry>,
) -> Result<Vec<ArtifactAvailability>> {
    let mut artifacts = Vec::new();
    let mut seen = BTreeSet::new();
    for step in steps.iter().filter(|step| step.deploys_release()) {
        let restore = step.restore.as_ref().map(|pin| pin.release_id.as_str());
        for release_id in std::iter::once(step.release_id.as_str()).chain(restore) {
            if !seen.insert(release_id.to_string()) {
                continue;
            }
            let Some(raw) = ctx
                .get(release_id)
                .await?
                .and_then(|release| release.properties.get("manifest").cloned())
                .filter(|raw| !raw.is_empty())
            else {
                // Apply refuses a release without a stored manifest; planning
                // has nothing to resolve for it.
                continue;
            };
            artifacts.extend(crate::manifest::parse_raw(&raw)?.artifacts);
        }
    }
    let reachable = env_properties
        .get(CONNECTIVITY_CLASS_PROPERTY)
        .and_then(|class| ConnectivityClass::parse(class).ok())
        != Some(ConnectivityClass::Isolated);
    let results = classify(
        &artifacts,
        &crate::oci_artifact::mirrors_from_properties(env_properties),
        registry.filter(|_| reachable),
    )?;
    if let Some(missing) = results
        .iter()
        .find(|result| result.state == ArtifactState::Missing)
    {
        bail!(
            "artifact digest {} is missing from registry {}; publish it there before planning",
            missing.digest,
            missing.registry
        );
    }
    Ok(results)
}

/// One result per distinct digest and registry. `registry` is `None` when the
/// planner has no store or cannot reach the environment's registry: every
/// digest is then `unverifiable`, nothing is asked, and a missing mirror is
/// left for apply to refuse.
fn classify(
    artifacts: &[OciArtifactRef],
    mirrors: &BTreeMap<String, String>,
    registry: Option<&dyn ArtifactRegistry>,
) -> Result<Vec<ArtifactAvailability>> {
    let mut results: Vec<ArtifactAvailability> = Vec::new();
    for artifact in artifacts {
        let (registry_name, state) = match registry {
            None => (
                mirrors
                    .get(&artifact.registry)
                    .unwrap_or(&artifact.registry)
                    .clone(),
                ArtifactState::Unverifiable,
            ),
            Some(registry) => {
                let pull = crate::oci_artifact::pull_reference(artifact, mirrors)?;
                let state = match registry.stored(&pull) {
                    Ok(Some(true)) => ArtifactState::Available,
                    // Absent, or stored with bytes that do not match the digest.
                    Ok(None | Some(false)) => ArtifactState::Missing,
                    Err(_) => ArtifactState::Unverifiable,
                };
                (pull.registry, state)
            }
        };
        if !results
            .iter()
            .any(|seen| seen.digest == artifact.digest && seen.registry == registry_name)
        {
            results.push(ArtifactAvailability {
                digest: artifact.digest.clone(),
                registry: registry_name,
                state,
            });
        }
    }
    Ok(results)
}

/// One operator line per artifact that planning could not confirm.
pub fn render(results: &[ArtifactAvailability]) -> Vec<String> {
    results
        .iter()
        .filter(|result| result.state == ArtifactState::Unverifiable)
        .map(|result| {
            format!(
                "artifact {} unverifiable at planning (registry {}); apply checks it",
                result.digest, result.registry
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_artifact::MemoryArtifactRegistry;

    fn artifact(payload: &[u8]) -> OciArtifactRef {
        use sha2::Digest as _;
        OciArtifactRef {
            registry: "ghcr.io".into(),
            repository: "edge/app".into(),
            digest: format!("sha256:{:x}", sha2::Sha256::digest(payload)),
            media_type: "application/vnd.oci.image.layer.v1.tar".into(),
            sbom: None,
        }
    }

    fn mirrors() -> BTreeMap<String, String> {
        BTreeMap::from([("ghcr.io".into(), "mirror.internal".into())])
    }

    /// A store that fails every read, standing in for an unreachable registry.
    struct Failing;
    impl ArtifactRegistry for Failing {
        fn stored(&self, _: &OciArtifactRef) -> Result<Option<bool>> {
            bail!("connection refused")
        }
        fn verify(&self, _: &OciArtifactRef) -> Result<OciArtifactRef> {
            bail!("connection refused")
        }
        fn fetch(&self, _: &OciArtifactRef) -> Result<Vec<u8>> {
            bail!("connection refused")
        }
        fn store(&self, _: &OciArtifactRef, _: Vec<u8>) -> Result<()> {
            bail!("must not store")
        }
    }

    /// A store error is never `missing`, so a flaky registry cannot refuse a
    /// plan; no store at all records the same.
    #[test]
    fn a_registry_error_or_no_registry_is_unverifiable() {
        let reference = artifact(b"payload");
        for registry in [Some(&Failing as &dyn ArtifactRegistry), None] {
            let results = classify(std::slice::from_ref(&reference), &mirrors(), registry).unwrap();
            assert_eq!(results[0].state, ArtifactState::Unverifiable);
        }
    }

    /// Apply refuses origin pull, so a probe refuses a registry with no mirror.
    #[test]
    fn a_probed_registry_without_a_mirror_refuses() {
        let store = MemoryArtifactRegistry::new();
        let error = classify(&[artifact(b"payload")], &BTreeMap::new(), Some(&store))
            .unwrap_err()
            .to_string();
        assert!(error.contains("origin pull is refused"), "{error}");
    }
}
