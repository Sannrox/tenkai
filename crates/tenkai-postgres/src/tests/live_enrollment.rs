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
    use tenkai::storage::{OperationalStore as _, RuntimeEnrollmentRecord, StoreError};

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
        10
    )));
    let barrier = Arc::new(Barrier::new(2));
    let digest = token.token_digest.clone();
    let (credential_a, credential_b) = (format!("ca-{suffix}"), format!("cb-{suffix}"));
    let results = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            a.redeem_runtime_enrollment("prod", &digest, &credential_a, 10)
        });
        let right = scope.spawn(|| {
            barrier.wait();
            b.redeem_runtime_enrollment("prod", &digest, &credential_b, 10)
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
        100
    )));

    b.revoke_runtime_credential(&winner.credential_digest, 50)
        .unwrap();
    a.revoke_runtime_credential(&winner.credential_digest, 60)
        .unwrap();
    assert_eq!(
        a.runtime_credential(&winner.credential_digest)
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(50)
    );
    assert!(matches!(
        a.revoke_runtime_credential("unknown", 60),
        Err(StoreError::NotFound { .. })
    ));
}
