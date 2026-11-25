//! Debug session records on the hub (#1556): a session written through one
//! store connection is read back, by id and by environment, through a new
//! one, as after a restart or from another replica.

use super::super::*;
use std::sync::Arc;
use tenkai::debug_session::{DebugSession, DebugSessionMode, DebugSessionState};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Postgres: cargo test --features postgres --lib -- --ignored tests::live_debug_session"]
async fn live_debug_session_outlives_its_store_connection() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let tenants = super::LiveTenants::new(&config);
    let tenant = tenants.tenant("debug");
    let now = tenkai::now_millis();
    let session = DebugSession {
        id: uuid::Uuid::new_v4().to_string(),
        environment: "stage".into(),
        instance: "api".into(),
        subject: "user-1".into(),
        opened_by: "user-1".into(),
        mode: DebugSessionMode::Read,
        reason: "pod restarts".into(),
        opened_at: now,
        not_after: now + 60_000,
        state: DebugSessionState::Open,
        closed_at: None,
        closed_by: None,
        close_reason: None,
        runtime: None,
    };
    {
        let mut ctx =
            tenkai::client::Ctx::tenant_hub_catalog(Arc::new(config.open().expect("connect")))
                .with_catalog_tenant(&tenant);
        tenkai::debug_session::create(&mut ctx, &session)
            .await
            .unwrap();
        assert!(
            tenkai::debug_session::create(&mut ctx, &session)
                .await
                .is_err(),
            "a session id is created once"
        );
    }
    let mut ctx =
        tenkai::client::Ctx::tenant_hub_catalog(Arc::new(config.open().expect("connect")))
            .with_catalog_tenant(&tenant);
    let loaded = tenkai::debug_session::load(&mut ctx, &session.id)
        .await
        .unwrap();
    assert_eq!(loaded.as_ref(), Some(&session));
    let mut closed = session.clone();
    closed.state = DebugSessionState::Closed;
    closed.closed_at = Some(now + 1);
    tenkai::debug_session::save(&mut ctx, &closed)
        .await
        .unwrap();
    let listed = tenkai::debug_session::list(&mut ctx, Some("stage"))
        .await
        .unwrap();
    assert_eq!(listed, vec![closed]);
}
