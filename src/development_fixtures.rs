//! Disabled-by-default, non-executable fixture projections for local integration demos.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::{
    ChannelRecord, EnvironmentRecord, PlanRecord, PlanStatus, ReleaseRecord, StoreError,
};

pub const DEVELOPMENT_FIXTURE_CONTRACT_VERSION: u32 = 1;
const MAX_OBJECTS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentFixture {
    pub contract_version: u32,
    pub fixture_id: String,
    #[serde(default)]
    pub releases: Vec<FixtureRelease>,
    #[serde(default)]
    pub channels: Vec<FixtureChannel>,
    #[serde(default)]
    pub environments: Vec<FixtureEnvironment>,
    #[serde(default)]
    pub plans: Vec<FixturePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRelease {
    pub name: String,
    pub product: String,
    pub version: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureChannel {
    pub name: String,
    pub product: String,
    pub release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEnvironment {
    pub name: String,
    pub posture: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixturePlan {
    pub name: String,
    pub environment: String,
    pub blocked_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureMap {
    pub contract_version: u32,
    pub fixture_id: String,
    pub fixture_digest: String,
    pub releases: Vec<String>,
    pub channels: Vec<String>,
    pub environments: Vec<String>,
    pub plans: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PreparedDevelopmentFixture {
    pub map: FixtureMap,
    pub releases: Vec<ReleaseRecord>,
    pub channels: Vec<ChannelRecord>,
    pub environments: Vec<EnvironmentRecord>,
    pub plans: Vec<PlanRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureResetResult {
    pub contract_version: u32,
    pub fixture_id: String,
    pub removed: usize,
}

impl DevelopmentFixture {
    pub fn prepare(&self) -> Result<PreparedDevelopmentFixture, StoreError> {
        if self.contract_version != DEVELOPMENT_FIXTURE_CONTRACT_VERSION {
            return invalid(format!(
                "unsupported contract_version {}; expected {DEVELOPMENT_FIXTURE_CONTRACT_VERSION}",
                self.contract_version
            ));
        }
        validate_name("fixture_id", &self.fixture_id)?;
        let total =
            self.releases.len() + self.channels.len() + self.environments.len() + self.plans.len();
        if total == 0 || total > MAX_OBJECTS {
            return invalid(format!(
                "fixture must contain between 1 and {MAX_OBJECTS} objects"
            ));
        }
        let canonical = serde_json::to_vec(self).map_err(|error| StoreError::InvalidData {
            kind: "development_fixture",
            detail: error.to_string(),
        })?;
        let fixture_digest = format!("{:x}", Sha256::digest(canonical));
        let prefix = fixture_prefix(&self.fixture_id)?;

        let mut names = BTreeSet::new();
        let mut releases_by_name = BTreeMap::new();
        let mut releases = Vec::new();
        for release in &self.releases {
            validate_unique("release", &release.name, &mut names)?;
            validate_name("product", &release.product)?;
            validate_version(&release.version)?;
            validate_digest(&release.content_digest)?;
            let id = format!("{prefix}release-{}", release.name);
            releases_by_name.insert(release.name.clone(), (id.clone(), release.product.clone()));
            releases.push(ReleaseRecord {
                id,
                product: release.product.clone(),
                version: format!("fixture-{}-{}", self.fixture_id, release.version),
                content_digest: release.content_digest.clone(),
                descriptor_json: serde_json::json!({
                    "fixture_only": true,
                    "fixture_id": self.fixture_id,
                    "executable": false
                })
                .to_string(),
            });
        }

        names.clear();
        let mut channels = Vec::new();
        for channel in &self.channels {
            validate_unique("channel", &channel.name, &mut names)?;
            validate_name("product", &channel.product)?;
            let Some((release_id, release_product)) = releases_by_name.get(&channel.release) else {
                return invalid(format!(
                    "channel {} references unknown fixture release {}",
                    channel.name, channel.release
                ));
            };
            if release_product != &channel.product {
                return invalid(format!(
                    "channel {} product does not match release {}",
                    channel.name, channel.release
                ));
            }
            channels.push(ChannelRecord {
                id: format!("{prefix}channel-{}", channel.name),
                product: channel.product.clone(),
                name: format!("fixture-{}-{}", self.fixture_id, channel.name),
                release_id: release_id.clone(),
                revision: 1,
            });
        }

        names.clear();
        let mut environments_by_name = BTreeMap::new();
        let mut environments = Vec::new();
        for environment in &self.environments {
            validate_unique("environment", &environment.name, &mut names)?;
            if !matches!(
                environment.posture.as_str(),
                "current" | "behind" | "unhealthy" | "awaiting_approval" | "drifted"
            ) {
                return invalid(format!(
                    "environment {} has unsupported posture",
                    environment.name
                ));
            }
            if environment.description.len() > 256 {
                return invalid(format!(
                    "environment {} description is too long",
                    environment.name
                ));
            }
            let id = format!("{prefix}environment-{}", environment.name);
            environments_by_name.insert(environment.name.clone(), id.clone());
            environments.push(EnvironmentRecord {
                id,
                revision: 1,
                configuration_json: serde_json::json!({
                    "fixture_only": true,
                    "fixture_id": self.fixture_id,
                    "posture": environment.posture,
                    "description": environment.description
                })
                .to_string(),
            });
        }

        names.clear();
        let mut plans = Vec::new();
        for plan in &self.plans {
            validate_unique("plan", &plan.name, &mut names)?;
            let Some(environment_id) = environments_by_name.get(&plan.environment) else {
                return invalid(format!(
                    "plan {} references unknown fixture environment {}",
                    plan.name, plan.environment
                ));
            };
            if plan.blocked_reason.trim().is_empty() || plan.blocked_reason.len() > 256 {
                return invalid(format!(
                    "plan {} blocked_reason must contain 1..256 characters",
                    plan.name
                ));
            }
            let plan_json = serde_json::json!({
                "format_version": 1,
                "fixture_only": true,
                "executable": false,
                "steps": []
            })
            .to_string();
            plans.push(PlanRecord {
                id: format!("{prefix}plan-{}", plan.name),
                environment_id: environment_id.clone(),
                format_version: 1,
                content_digest: format!("{:x}", Sha256::digest(plan_json.as_bytes())),
                plan_json,
                status: PlanStatus::Blocked,
                status_detail: plan.blocked_reason.clone(),
            });
        }

        Ok(PreparedDevelopmentFixture {
            map: FixtureMap {
                contract_version: DEVELOPMENT_FIXTURE_CONTRACT_VERSION,
                fixture_id: self.fixture_id.clone(),
                fixture_digest,
                releases: releases.iter().map(|record| record.id.clone()).collect(),
                channels: channels.iter().map(|record| record.id.clone()).collect(),
                environments: environments
                    .iter()
                    .map(|record| record.id.clone())
                    .collect(),
                plans: plans.iter().map(|record| record.id.clone()).collect(),
            },
            releases,
            channels,
            environments,
            plans,
        })
    }
}

pub fn fixture_prefix(fixture_id: &str) -> Result<String, StoreError> {
    validate_name("fixture_id", fixture_id)?;
    let encoded = fixture_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("fx-{encoded}-"))
}

fn validate_unique(
    kind: &'static str,
    name: &str,
    names: &mut BTreeSet<String>,
) -> Result<(), StoreError> {
    validate_name(kind, name)?;
    if !names.insert(name.to_string()) {
        return invalid(format!("duplicate {kind} name {name}"));
    }
    Ok(())
}

fn validate_name(kind: &'static str, value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 48
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return invalid(format!(
            "{kind} must be 1..48 ASCII alphanumeric, '-' or '_' characters"
        ));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return invalid("release version is invalid".into());
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), StoreError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid("release content_digest must be 64 hexadecimal characters".into());
    }
    Ok(())
}

fn invalid<T>(detail: String) -> Result<T, StoreError> {
    Err(StoreError::InvalidData {
        kind: "development_fixture",
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{OperationalStore, SqliteStore};

    fn fixture() -> DevelopmentFixture {
        DevelopmentFixture {
            contract_version: 1,
            fixture_id: "buyer-demo".into(),
            releases: vec![FixtureRelease {
                name: "app".into(),
                product: "app".into(),
                version: "1.0.0".into(),
                content_digest: "a".repeat(64),
            }],
            channels: vec![FixtureChannel {
                name: "stable".into(),
                product: "app".into(),
                release: "app".into(),
            }],
            environments: vec![FixtureEnvironment {
                name: "prod-eu".into(),
                posture: "awaiting_approval".into(),
                description: "sanitized demo".into(),
            }],
            plans: vec![FixturePlan {
                name: "approval".into(),
                environment: "prod-eu".into(),
                blocked_reason: "awaiting approval".into(),
            }],
        }
    }

    #[test]
    fn prepares_only_namespaced_non_executable_records() {
        let prepared = fixture().prepare().unwrap();
        assert!(prepared.map.releases[0].starts_with("fx-62757965722d64656d6f-"));
        assert_eq!(prepared.plans[0].status, PlanStatus::Blocked);
        assert!(prepared.plans[0].plan_json.contains("\"steps\":[]"));
        assert!(
            prepared.releases[0]
                .descriptor_json
                .contains("\"executable\":false")
        );
    }

    #[test]
    fn rejects_unknown_reference_and_executable_posture() {
        let mut fixture = fixture();
        fixture.plans[0].environment = "foreign".into();
        assert!(fixture.prepare().is_err());
        fixture.plans.clear();
        fixture.environments[0].posture = "running".into();
        assert!(fixture.prepare().is_err());
    }

    #[test]
    fn sqlite_import_is_atomic_idempotent_conflict_safe_and_resettable() {
        let store = SqliteStore::open_in_memory().unwrap();
        let prepared = fixture().prepare().unwrap();
        let first = store
            .import_development_fixture(&prepared, "seed-service", "request-1")
            .unwrap();
        let repeated = store
            .import_development_fixture(&prepared, "seed-service", "request-2")
            .unwrap();
        assert_eq!(first, repeated);
        assert!(store.get_release(&first.releases[0]).unwrap().is_some());
        assert_eq!(
            store.get_plan(&first.plans[0]).unwrap().unwrap().status,
            PlanStatus::Blocked
        );
        let mut changed = fixture();
        changed.plans[0].blocked_reason = "changed".into();
        assert!(
            store
                .import_development_fixture(
                    &changed.prepare().unwrap(),
                    "seed-service",
                    "request-3"
                )
                .is_err()
        );
        let reset = store
            .reset_development_fixture("buyer-demo", "seed-service", "request-4")
            .unwrap();
        assert_eq!(reset.removed, 4);
        assert!(store.get_release(&first.releases[0]).unwrap().is_none());
        assert!(store.get_plan(&first.plans[0]).unwrap().is_none());
    }

    #[test]
    fn sqlite_fixture_plans_cannot_transition_or_be_claimed() {
        let store = SqliteStore::open_in_memory().unwrap();
        let map = store
            .import_development_fixture(&fixture().prepare().unwrap(), "seed-service", "request-1")
            .unwrap();
        assert!(
            store
                .acquire_lease(
                    &map.environments[0],
                    "runtime",
                    crate::now_millis() + 60_000
                )
                .is_err()
        );
        assert!(
            store
                .transition_plan(
                    &map.plans[0],
                    "runtime",
                    1,
                    PlanStatus::Running,
                    "must remain blocked"
                )
                .is_err()
        );
        assert!(
            store
                .claim_runtime_plan(
                    &map.environments[0],
                    &map.plans[0],
                    "runtime",
                    crate::now_millis() + 60_000
                )
                .is_err()
        );
        let ordinary_plan = PlanRecord {
            id: "ordinary-plan".into(),
            environment_id: map.environments[0].clone(),
            format_version: 1,
            content_digest: "c".repeat(64),
            plan_json: r#"{"steps":[]}"#.into(),
            status: PlanStatus::Computed,
            status_detail: String::new(),
        };
        assert!(store.create_plan(&ordinary_plan).is_err());
        let ordinary_channel = ChannelRecord {
            id: "ordinary-channel".into(),
            product: "app".into(),
            name: "stable".into(),
            release_id: map.releases[0].clone(),
            revision: 1,
        };
        assert!(store.promote_channel(&ordinary_channel).is_err());
    }

    #[test]
    fn sqlite_reset_does_not_cross_prefix_or_wildcard_fixture_ids() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut buyer = fixture();
        buyer.fixture_id = "buyer".into();
        let buyer = buyer.prepare().unwrap();
        let buyer_map = store
            .import_development_fixture(&buyer, "seed-service", "request-buyer")
            .unwrap();

        let buyer_demo = fixture().prepare().unwrap();
        let buyer_demo_map = store
            .import_development_fixture(&buyer_demo, "seed-service", "request-buyer-demo")
            .unwrap();

        let mut wildcard = fixture();
        wildcard.fixture_id = "buyer_demo".into();
        let wildcard = wildcard.prepare().unwrap();
        let wildcard_map = store
            .import_development_fixture(&wildcard, "seed-service", "request-wildcard")
            .unwrap();
        let ordinary_release = ReleaseRecord {
            id: format!("{}release-ordinary", fixture_prefix("buyer").unwrap()),
            product: "ordinary".into(),
            version: "1.0.0".into(),
            content_digest: "b".repeat(64),
            descriptor_json: "{}".into(),
        };
        store.publish_release(&ordinary_release).unwrap();

        let reset = store
            .reset_development_fixture("buyer", "seed-service", "request-reset")
            .unwrap();
        assert_eq!(reset.removed, 4);
        assert!(store.get_release(&buyer_map.releases[0]).unwrap().is_none());
        assert!(
            store
                .get_release(&buyer_demo_map.releases[0])
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get_release(&wildcard_map.releases[0])
                .unwrap()
                .is_some()
        );
        assert!(store.get_release(&ordinary_release.id).unwrap().is_some());
    }
}
