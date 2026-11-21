use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub id: String,
    pub product: String,
    pub version: String,
    pub content_digest: String,
    pub descriptor_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRecord {
    pub id: String,
    pub product: String,
    pub name: String,
    pub release_id: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    pub id: String,
    pub revision: u64,
    pub configuration_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Computed,
    Running,
    Blocked,
    Succeeded,
    Failed,
}

impl PlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Computed => "computed",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "computed" => Ok(Self::Computed),
            "running" => Ok(Self::Running),
            "blocked" => Ok(Self::Blocked),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::InvalidData {
                kind: "plan",
                detail: format!("unknown status {other:?}"),
            }),
        }
    }

    pub fn allows(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Computed, Self::Running)
                    | (Self::Computed, Self::Blocked)
                    | (Self::Blocked, Self::Running)
                    | (Self::Running, Self::Blocked)
                    | (Self::Running, Self::Succeeded)
                    | (Self::Running, Self::Failed)
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRecord {
    pub id: String,
    pub environment_id: String,
    pub format_version: u32,
    pub content_digest: String,
    pub plan_json: String,
    pub status: PlanStatus,
    pub status_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub environment_id: String,
    pub owner: String,
    pub generation: u64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub id: String,
    pub environment_id: String,
    pub plan_id: String,
    pub step_id: String,
    pub lease_generation: u64,
    pub payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineImportRecord {
    pub bundle_digest: String,
    pub environment_id: String,
    pub plan_id: String,
    pub receipt_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineStepImportRecord {
    pub receipt_id: String,
    pub environment_id: String,
    pub plan_id: String,
    pub step_id: String,
    pub attempt: u32,
    pub result_digest: String,
    pub succeeded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

impl RollbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::InvalidData {
                kind: "rollback",
                detail: format!("unknown status {other:?}"),
            }),
        }
    }

    pub fn allows(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Pending, Self::Running)
                    | (Self::Pending, Self::Failed)
                    | (Self::Running, Self::Succeeded)
                    | (Self::Running, Self::Failed)
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    pub id: String,
    pub environment_id: String,
    pub plan_id: String,
    pub lease_generation: u64,
    pub checkpoint_json: String,
    pub status: RollbackStatus,
    pub status_detail: String,
}

pub fn rollback_intent_digest(rollback: &RollbackRecord) -> String {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    for value in [
        rollback.environment_id.as_bytes(),
        rollback.plan_id.as_bytes(),
        &rollback.lease_generation.to_le_bytes(),
        rollback.checkpoint_json.as_bytes(),
        rollback.status_detail.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    format!("{:x}", digest.finalize())
}

/// A first-delivery collection timestamp is the only field allowed to be
/// added to a durable provider envelope after enqueue. Preserve enqueue
/// idempotency when the same event is submitted again after that binding.
pub fn provider_event_payloads_match(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let Ok(mut left) = serde_json::from_str::<serde_json::Value>(left) else {
        return false;
    };
    let Ok(mut right) = serde_json::from_str::<serde_json::Value>(right) else {
        return false;
    };
    let (Some(left), Some(right)) = (left.as_object_mut(), right.as_object_mut()) else {
        return false;
    };
    let metadata = |object: &serde_json::Map<String, serde_json::Value>| {
        ["collected_at_ms", "source_sequence"]
            .map(|key| object.get(key).filter(|value| !value.is_null()).cloned())
    };
    let left_metadata = metadata(left);
    let right_metadata = metadata(right);
    if left_metadata == right_metadata
        || !((left_metadata.iter().all(Option::is_none)
            && right_metadata.iter().all(Option::is_some))
            || (right_metadata.iter().all(Option::is_none)
                && left_metadata.iter().all(Option::is_some)))
    {
        return false;
    }
    left.remove("collected_at_ms");
    left.remove("source_sequence");
    right.remove("collected_at_ms");
    right.remove("source_sequence");
    left == right
}

pub fn provider_event_environment_id(payload_json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(payload_json).ok()?;
    value
        .get("binding")?
        .get("environment_id")?
        .as_str()
        .filter(|environment| !environment.trim().is_empty())
        .map(str::to_owned)
}

pub fn provider_event_observed_at(payload_json: &str, fallback: i64) -> i64 {
    let observed_at = serde_json::from_str::<serde_json::Value>(payload_json)
        .ok()
        .and_then(|value| {
            let payload = value.get("payload_json")?.as_str()?;
            let payload = serde_json::from_str::<serde_json::Value>(payload).ok()?;
            payload.get("observed_at")?.as_i64()
        })
        .filter(|observed_at| *observed_at > 0);
    observed_at.unwrap_or(fallback)
}

/// Position of a provider event in newest-first inspection order:
/// `observed_at`, then `provider_kind`, then `id` (text bytewise), all
/// descending. Stores must compare in this order. Unique
/// across the outbox because `(provider_kind, id)` is its key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderEventPosition {
    pub observed_at: i64,
    pub provider_kind: String,
    pub id: String,
}

/// Durable delivery record for optional provider side effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEventRecord {
    pub id: String,
    pub provider_kind: String,
    pub binding_digest: String,
    pub payload_json: String,
    pub attempts: u32,
    pub next_attempt_at: i64,
    pub delivered_at: Option<i64>,
    pub last_error: String,
    pub claim_token: Option<String>,
    pub claim_until: Option<i64>,
}

pub fn validate_new_provider_event(event: &ProviderEventRecord) -> Result<()> {
    if event.id.trim().is_empty()
        || event.provider_kind.trim().is_empty()
        || event.binding_digest.trim().is_empty()
        || event.payload_json.is_empty()
        || event.attempts != 0
        || event.delivered_at.is_some()
        || !event.last_error.is_empty()
        || event.claim_token.is_some()
        || event.claim_until.is_some()
    {
        return Err(StoreError::InvalidData {
            kind: "provider event",
            detail: "new events require identities, content, and pristine delivery state".into(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    pub occurred_at: i64,
    pub principal: String,
    pub operation: String,
    pub resource: String,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeClaim {
    pub plan_id: String,
    pub environment_id: String,
    pub owner: String,
    pub generation: u64,
    pub expires_at: i64,
    pub completion_json: Option<String>,
    /// A `RuntimeProgress` the claim's runner recorded before a step that
    /// loses the runtime, such as an OS image `reboot` (ADR 0051 §3). The
    /// server fills it in for the runner that recorded it; omitted otherwise,
    /// so a runtime that predates it decodes every other claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_json: Option<String>,
}

/// A single-use enrollment for a runtime agent (#630). Only the digest of
/// the token is stored; the token itself is shown once, to the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEnrollmentRecord {
    pub token_digest: String,
    pub environment_id: String,
    pub expires_at: i64,
    pub created_by: String,
}

/// The credential a runtime agent got for its enrollment. Only its digest
/// is stored, and it doubles as the id an operator revokes it by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCredentialRecord {
    pub credential_digest: String,
    pub environment_id: String,
    pub enrollment_digest: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

/// Why and by whom a runtime credential was revoked (#673). The first
/// revocation's reason is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRevocation {
    pub reason: String,
    pub revoked_by: String,
}

/// An enrolled runtime credential as the runner registry lists it (#673).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRunnerRecord {
    pub credential: RuntimeCredentialRecord,
    /// Who issued the enrollment it was redeemed from.
    pub created_by: String,
    /// Present once revoked through the registry; credentials revoked
    /// before it existed have a `revoked_at` but no reason.
    pub revocation: Option<RuntimeRevocation>,
}

/// What one instance of a runner last did (#673). `runner_id` is the
/// digest of the credential or static token the instance presents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeActivityRecord {
    pub runner_id: String,
    pub instance_id: String,
    pub environment_id: String,
    /// The lease owner this instance claims runtime plans as.
    pub owner: String,
    pub runtime_version: Option<String>,
    pub last_work_at: Option<i64>,
    pub last_heartbeat_at: Option<i64>,
    pub last_inventory_at: Option<i64>,
    /// Installed executor kinds, comma-separated canonical names, from the
    /// runtime's last work pull that sent them (ADR 0057). `None` until a
    /// runtime that reports them pulls; a report without them keeps these.
    #[serde(default)]
    pub executors: Option<String>,
    /// Configured model engines, comma-separated canonical names, from the
    /// runtime's last work pull that sent them. `None` until a runtime that
    /// reports them pulls; a report without them keeps these.
    #[serde(default)]
    pub engines: Option<String>,
}

/// A runner's HPKE sealing public key (ADR 0045). Bound to one enrolled
/// runtime instance; renewal replaces only that instance's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSealingKeyRecord {
    pub runner_id: String,
    pub environment_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub recorded_at: i64,
}

/// A runner's latest bound attestation and latest attestation refusal
/// (#675). A write with `evidence_digest` binds and clears the refusal; a
/// write without it records only the refusal and keeps the binding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAttestationRecord {
    pub runner_id: String,
    pub environment_id: String,
    pub evidence_digest: Option<String>,
    pub key_fingerprint: Option<String>,
    pub checked_at: Option<i64>,
    pub bound_at: Option<i64>,
    pub refusal_reason: Option<String>,
    pub refused_at: Option<i64>,
}
