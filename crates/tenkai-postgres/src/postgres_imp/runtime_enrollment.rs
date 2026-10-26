//! Runtime agent enrollments and credentials (#630). Redemption is one
//! conditional update, so of two servers redeeming one token, one wins.

use super::*;
use super::{Inner, pg};

fn refused(detail: &str) -> StoreError {
    StoreError::InvalidData {
        kind: "runtime enrollment",
        detail: detail.into(),
    }
}

impl Inner {
    pub fn create_runtime_enrollment(
        &self,
        schema: &str,
        enrollment: &RuntimeEnrollmentRecord,
    ) -> Result<()> {
        let enrollment = enrollment.clone();
        self.with_schema(schema, move |tx| {
            let inserted = tx
                .execute(
                    "INSERT INTO runtime_enrollments(token_digest,environment_id,expires_at,created_by)
                     VALUES($1,$2,$3,$4) ON CONFLICT(token_digest) DO NOTHING",
                    &[
                        &enrollment.token_digest,
                        &enrollment.environment_id,
                        &enrollment.expires_at,
                        &enrollment.created_by,
                    ],
                )
                .map_err(pg)?;
            if inserted == 0 {
                return Err(StoreError::AlreadyExists {
                    kind: "runtime enrollment",
                    id: enrollment.token_digest.clone(),
                });
            }
            Ok(())
        })
    }

    pub fn redeem_runtime_enrollment(
        &self,
        schema: &str,
        environment: &str,
        token_digest: &str,
        credential_digest: &str,
        now: i64,
    ) -> Result<RuntimeCredentialRecord> {
        let environment_id = environment.to_owned();
        let token_digest = token_digest.to_owned();
        let credential_digest = credential_digest.to_owned();
        self.with_schema(schema, move |tx| {
            let spent = tx
                .execute(
                    "UPDATE runtime_enrollments SET redeemed_at=$3
                     WHERE token_digest=$1 AND environment_id=$2
                       AND redeemed_at IS NULL AND expires_at>$3",
                    &[&token_digest, &environment_id, &now],
                )
                .map_err(pg)?;
            if spent == 0 {
                return Err(refused("unknown, spent or expired"));
            }
            tx.execute(
                "INSERT INTO runtime_credentials(credential_digest,environment_id,enrollment_digest,created_at)
                 VALUES($1,$2,$3,$4)",
                &[&credential_digest, &environment_id, &token_digest, &now],
            )
            .map_err(pg)?;
            Ok(RuntimeCredentialRecord {
                credential_digest,
                environment_id,
                enrollment_digest: token_digest,
                created_at: now,
                revoked_at: None,
            })
        })
    }

    pub fn lapsed_runtime_completion(
        &self,
        schema: &str,
        environment: &str,
        plan_id: &str,
        now: i64,
    ) -> Result<Option<String>> {
        let environment = environment.to_owned();
        let plan_id = plan_id.to_owned();
        self.with_schema(schema, move |tx| {
            Ok(tx
                .query_opt(
                    "SELECT completion_json FROM runtime_claims
                     WHERE plan_id=$1 AND environment_id=$2
                       AND completion_json IS NOT NULL AND expires_at<=$3",
                    &[&plan_id, &environment, &now],
                )
                .map_err(pg)?
                .map(|row| row.get(0)))
        })
    }

    pub fn runtime_credential(
        &self,
        schema: &str,
        credential_digest: &str,
    ) -> Result<Option<RuntimeCredentialRecord>> {
        let credential_digest = credential_digest.to_owned();
        self.with_schema(schema, move |tx| {
            let row = tx
                .query_opt(
                    "SELECT credential_digest,environment_id,enrollment_digest,created_at,revoked_at
                     FROM runtime_credentials WHERE credential_digest=$1",
                    &[&credential_digest],
                )
                .map_err(pg)?;
            Ok(row.map(|row| RuntimeCredentialRecord {
                credential_digest: row.get(0),
                environment_id: row.get(1),
                enrollment_digest: row.get(2),
                created_at: row.get(3),
                revoked_at: row.get(4),
            }))
        })
    }

    pub fn revoke_runtime_credential(
        &self,
        schema: &str,
        credential_digest: &str,
        now: i64,
    ) -> Result<()> {
        let credential_digest = credential_digest.to_owned();
        self.with_schema(schema, move |tx| {
            let known = tx
                .execute(
                    "UPDATE runtime_credentials SET revoked_at=COALESCE(revoked_at, $2)
                     WHERE credential_digest=$1",
                    &[&credential_digest, &now],
                )
                .map_err(pg)?;
            if known == 0 {
                return Err(StoreError::NotFound {
                    kind: "runtime credential",
                    id: credential_digest.clone(),
                });
            }
            Ok(())
        })
    }
}
