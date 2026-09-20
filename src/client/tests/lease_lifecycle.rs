use crate::client::Ctx;

use super::mock_router::remote_ctx;
use super::mock_state::MockSekaiState;

async fn assert_lease_lifecycle(mut ctx: Ctx) {
    let namespace = "tenkai";
    let key = "environment/conformance";
    assert_eq!(ctx.get_lease(namespace, key).await.unwrap(), None);

    let acquired = ctx
        .acquire_lease(namespace, key, "owner-a", 5_000)
        .await
        .unwrap();
    assert_eq!(acquired.namespace, namespace);
    assert_eq!(acquired.key, key);
    assert_eq!(acquired.owner, "owner-a");
    assert_eq!(acquired.status, "active");
    assert!(!acquired.fencing_token.is_empty());
    assert_eq!(
        ctx.get_lease(namespace, key).await.unwrap(),
        Some(acquired.clone())
    );

    let conflict = ctx
        .acquire_lease(namespace, key, "owner-b", 5_000)
        .await
        .unwrap_err();
    let status = conflict
        .downcast_ref::<tonic::Status>()
        .expect("lease conflict should surface as tonic Status");
    assert_eq!(status.code(), tonic::Code::AlreadyExists);

    let refreshed = ctx
        .refresh_lease(namespace, key, &acquired.fencing_token, 8_000)
        .await
        .unwrap();
    assert_eq!(refreshed.fencing_token, acquired.fencing_token);
    assert!(refreshed.expires_at_ms >= acquired.expires_at_ms);
    assert_eq!(refreshed.status, "active");

    let released = ctx
        .release_lease(namespace, key, &acquired.fencing_token)
        .await
        .unwrap();
    assert_eq!(released.status, "released");
    assert!(released.released_at_ms > 0);

    let reacquired = ctx
        .acquire_lease(namespace, key, "owner-c", 1)
        .await
        .unwrap();
    assert_eq!(reacquired.owner, "owner-c");
    assert_eq!(reacquired.status, "active");
    assert_ne!(reacquired.fencing_token, acquired.fencing_token);
    assert!(reacquired.generation > acquired.generation);

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let takeover = ctx
        .takeover_expired_lease(
            namespace,
            key,
            "owner-d",
            &reacquired.fencing_token,
            reacquired.expires_at_ms,
            5_000,
        )
        .await
        .unwrap();
    assert_eq!(takeover.owner, "owner-d");
    assert_eq!(takeover.status, "active");
    assert_ne!(takeover.fencing_token, reacquired.fencing_token);
    assert!(takeover.generation > reacquired.generation);
}

#[tokio::test]
async fn embedded_ctx_conforms_to_lease_lifecycle() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-ctx-lease-conformance-{}.db",
        uuid::Uuid::new_v4()
    ));
    let ctx = Ctx::embedded(&path).unwrap();
    assert_lease_lifecycle(ctx).await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn remote_ctx_conforms_to_lease_lifecycle() {
    let (ctx, server) = remote_ctx(MockSekaiState::default()).await;
    assert_lease_lifecycle(ctx).await;
    server.abort();
}
