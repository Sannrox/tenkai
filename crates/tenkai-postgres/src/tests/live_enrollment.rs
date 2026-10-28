use super::super::*;

/// Runtime enrollment on two replicas (#630): a token is spent once, only in
/// its environment and before it expires, and a credential is revoked.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_runtime_enrollment_is_single_use_across_replicas() {
    use std::sync::{Arc, Barrier};
    use tenkai::auth_context::{
        AuthenticatedRequestContextBuilder, PrincipalIdentity, PrincipalKind,
        TenantDerivationAuthority,
    };
    use tenkai::storage::{
        OperationalStore as _, RuntimeActivityRecord, RuntimeAttestationRecord,
        RuntimeEnrollmentRecord, RuntimeRevocation, StoreError,
    };

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let replica_a = config.open().expect("connect replica a");
    let replica_b = config.open().expect("connect replica b");
    let authority = TenantDerivationAuthority::new("test");
    let context = AuthenticatedRequestContextBuilder::new(
        format!("enrollment-{suffix}"),
        PrincipalIdentity {
            id: "enrollment-conformance".into(),
            kind: PrincipalKind::Service,
        },
        "test",
    )
    .with_tenant(format!("enroll-{suffix}"), &authority)
    .unwrap()
    .build()
    .unwrap();
    let a = replica_a.partition_for(&context).unwrap();
    let b = replica_b.partition_for(&context).unwrap();
    let enrollment = |token: &str, expires_at: i64| RuntimeEnrollmentRecord {
        token_digest: format!("{token}-{suffix}"),
        environment_id: "prod".into(),
        expires_at,
        created_by: "operator".into(),
    };
    let refused =
        |result: tenkai::storage::Result<_>| matches!(result, Err(StoreError::InvalidData { .. }));

    let token = enrollment("race", i64::MAX);
    a.create_runtime_enrollment(&token).unwrap();
    assert!(matches!(
        b.create_runtime_enrollment(&token),
        Err(StoreError::AlreadyExists { .. })
    ));
    assert!(refused(b.redeem_runtime_enrollment(
        "stage",
        &token.token_digest,
        "c0",
        10,
        None
    )));
    let barrier = Arc::new(Barrier::new(2));
    let digest = token.token_digest.clone();
    let (credential_a, credential_b) = (format!("ca-{suffix}"), format!("cb-{suffix}"));
    let results = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            a.redeem_runtime_enrollment("prod", &digest, &credential_a, 10, None)
        });
        let right = scope.spawn(|| {
            barrier.wait();
            b.redeem_runtime_enrollment("prod", &digest, &credential_b, 10, None)
        });
        [left.join().unwrap(), right.join().unwrap()]
    });
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "{results:?}"
    );
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(
        b.runtime_credential(&winner.credential_digest).unwrap(),
        Some(winner.clone())
    );

    let expired = enrollment("expired", 100);
    a.create_runtime_enrollment(&expired).unwrap();
    assert!(refused(b.redeem_runtime_enrollment(
        "prod",
        &expired.token_digest,
        "cx",
        100,
        None
    )));
    // Runner attestation (#675): a usable-token check spends nothing, and
    // a redemption commits its binding with the credential.
    let attested = enrollment("attested", i64::MAX);
    a.create_runtime_enrollment(&attested).unwrap();
    assert!(
        b.runtime_enrollment_usable("prod", &attested.token_digest, 10)
            .unwrap()
    );
    assert!(
        !b.runtime_enrollment_usable("stage", &attested.token_digest, 10)
            .unwrap()
    );
    let bound_runner = format!("bound-{suffix}");
    b.redeem_runtime_enrollment(
        "prod",
        &attested.token_digest,
        &bound_runner,
        10,
        Some(&RuntimeAttestationRecord {
            runner_id: bound_runner.clone(),
            environment_id: "prod".into(),
            evidence_digest: Some("sha256:e0".into()),
            key_fingerprint: Some("sha256:key".into()),
            checked_at: Some(5),
            bound_at: Some(10),
            ..Default::default()
        }),
    )
    .unwrap();
    assert!(
        !a.runtime_enrollment_usable("prod", &attested.token_digest, 10)
            .unwrap()
    );
    assert!(
        a.runtime_attestations()
            .unwrap()
            .iter()
            .any(|record| record.runner_id == bound_runner
                && record.evidence_digest.as_deref() == Some("sha256:e0"))
    );

    let first = RuntimeRevocation {
        reason: "host retired".into(),
        revoked_by: "operator-a".into(),
    };
    let second = RuntimeRevocation {
        reason: "again".into(),
        revoked_by: "operator-b".into(),
    };
    b.revoke_runtime_credential(&winner.credential_digest, 50, &first)
        .unwrap();
    a.revoke_runtime_credential(&winner.credential_digest, 60, &second)
        .unwrap();
    assert_eq!(
        a.runtime_credential(&winner.credential_digest)
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(50)
    );
    assert!(matches!(
        a.revoke_runtime_credential("unknown", 60, &first),
        Err(StoreError::NotFound { .. })
    ));
    // The runner registry (#673): the first reason is kept, and activity
    // from either replica merges per instance.
    let runner = b
        .runtime_runners()
        .unwrap()
        .into_iter()
        .find(|runner| runner.credential.credential_digest == winner.credential_digest)
        .unwrap();
    assert_eq!(runner.revocation, Some(first));
    let activity =
        |work: Option<i64>, beat: Option<i64>, version: Option<&str>| RuntimeActivityRecord {
            runner_id: winner.credential_digest.clone(),
            instance_id: "rt-1".into(),
            environment_id: runner.credential.environment_id.clone(),
            owner: "runtime:rt-1".into(),
            runtime_version: version.map(str::to_string),
            last_work_at: work,
            last_heartbeat_at: beat,
            last_inventory_at: None,
        };
    a.record_runtime_activity(&activity(Some(100), None, Some("0.5.0")))
        .unwrap();
    b.record_runtime_activity(&activity(Some(90), Some(120), None))
        .unwrap();
    let recorded = a
        .runtime_activity()
        .unwrap()
        .into_iter()
        .find(|record| record.runner_id == winner.credential_digest)
        .unwrap();
    assert_eq!(recorded.last_work_at, Some(100));
    assert_eq!(recorded.last_heartbeat_at, Some(120));
    assert_eq!(recorded.runtime_version.as_deref(), Some("0.5.0"));
    // Runner attestation (#675): a refusal from one replica keeps the
    // binding another wrote; a later binding clears the refusal.
    let attestation = |digest: Option<&str>, refusal: Option<&str>| RuntimeAttestationRecord {
        runner_id: winner.credential_digest.clone(),
        environment_id: runner.credential.environment_id.clone(),
        evidence_digest: digest.map(str::to_string),
        key_fingerprint: digest.map(|_| "sha256:key".to_string()),
        checked_at: digest.map(|_| 10),
        bound_at: digest.map(|_| 11),
        refusal_reason: refusal.map(str::to_string),
        refused_at: refusal.map(|_| 12),
    };
    let bound = || {
        a.runtime_attestations()
            .unwrap()
            .into_iter()
            .find(|record| record.runner_id == winner.credential_digest)
            .unwrap()
    };
    a.record_runtime_attestation(&attestation(Some("sha256:e1"), None))
        .unwrap();
    b.record_runtime_attestation(&attestation(None, Some("fact_mismatch")))
        .unwrap();
    assert_eq!(bound().evidence_digest.as_deref(), Some("sha256:e1"));
    assert_eq!(bound().key_fingerprint.as_deref(), Some("sha256:key"));
    assert_eq!(bound().refusal_reason.as_deref(), Some("fact_mismatch"));
    b.record_runtime_attestation(&attestation(Some("sha256:e2"), None))
        .unwrap();
    assert_eq!(bound().evidence_digest.as_deref(), Some("sha256:e2"));
    assert_eq!(bound().refusal_reason, None);
}
