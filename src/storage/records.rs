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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Computed => "computed",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
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

    pub(crate) fn allows(self, next: Self) -> bool {
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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
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

    pub(crate) fn allows(self, next: Self) -> bool {
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
}
