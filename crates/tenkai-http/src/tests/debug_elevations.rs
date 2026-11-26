//! `/v1/debug-sessions/{session}/elevations` (#1560): write access in a debug
//! session after a signed `debug_elevate` quorum, bounded and revocable.

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use sha2::Digest as _;

use super::debug_sessions::{Fixture, ISSUER, WORK, audited, call, fixture, open, runtime};
use super::*;
use tenkai::debug_elevation::{
    APPROVAL_PURPOSE, APPROVAL_SCHEMA, DebugElevationEnvelope, DebugElevationStatement,
};
use tenkai::plan_approval::SignedApproval as _;

/// One plan-approval key: its seed and the identity the trust roots pin.
struct Approver {
    seed: u8,
    identity: String,
}

impl Approver {
    fn key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[self.seed; 32])
    }

    fn key_id(&self) -> String {
        let public = self.key().verifying_key().to_bytes();
        format!("sha256:{:x}", sha2::Sha256::digest(public))
    }

    /// A signed approval of `elevation`, valid for a minute.
    fn approve(&self, elevation: &serde_json::Value) -> serde_json::Value {
        let now = tenkai::now_millis();
        let statement = DebugElevationStatement {
            session: elevation["session"].as_str().unwrap().into(),
            elevation: elevation["id"].as_str().unwrap().into(),
            environment: elevation["environment"].as_str().unwrap().into(),
            purpose: APPROVAL_PURPOSE.into(),
            issued_at: now - 1_000,
            expires_at: now + 60_000,
        };
        let signature = self.key().sign(&statement.canonical_bytes().unwrap());
        let envelope = DebugElevationEnvelope {
            schema: APPROVAL_SCHEMA.into(),
            key_id: self.key_id(),
            statement,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };
        serde_json::json!({ "approval": envelope })
    }
}

/// Alice and bob, and a key pinned to the requester's own identity.
fn approvers() -> [Approver; 3] {
    [
        Approver {
            seed: 11,
            identity: "alice@example.test".into(),
        },
        Approver {
            seed: 12,
            identity: "bob@example.test".into(),
        },
        Approver {
            seed: 13,
            identity: format!("user-1@{ISSUER}"),
        },
    ]
}

/// Pin every approver as a plan-approval signer of the server.
fn write_roots(fixture: &Fixture) {
    let mut roots = String::from("version = 1\n");
    for approver in approvers() {
        let public = approver.key().verifying_key().to_bytes();
        roots.push_str(&format!(
            "\n[[signers]]\nkey_id = \"{}\"\nidentity = \"{}\"\npublic_key = \"{}\"\n",
            approver.key_id(),
            approver.identity,
            base64::engine::general_purpose::STANDARD.encode(public),
        ));
    }
    std::fs::write(fixture.root.join("approval-roots.toml"), roots).unwrap();
}

/// Set stage's policy to `debug_sessions`, with a two-approver elevation
/// quorum.
async fn stage_policy(fixture: &Fixture, debug_sessions: &str) {
    let policy = fixture.root.join("stage-policy.toml");
    std::fs::write(
        &policy,
        format!(
            "version = 1\nmode = \"manual\"\nttl_ms = 60000\ndebug_sessions = \"{debug_sessions}\"\n\n[[quorum]]\npurpose = \"debug_elevate\"\nn = 2\n"
        ),
    )
    .unwrap();
    let mut ctx = tenkai_sqlite::embedded_ctx(fixture.root.join("tenkai.db")).unwrap();
    tenkai::plan::set_plan_approval_policy(&mut ctx, "stage", &policy)
        .await
        .unwrap();
}

/// The session's `elevated_until` as the owning runtime is handed it.
async fn handed_out(app: &Router) -> serde_json::Value {
    let (code, work) = runtime(app, "GET", WORK, "first", true, None).await;
    assert_eq!(code, StatusCode::OK, "{work}");
    work["debug_sessions"][0]["elevated_until"].clone()
}

/// The requester's own approval never counts; two others activate the
/// elevation, the runtime is handed it and a write starts and is audited;
/// after a revoke the next write is refused.
#[tokio::test]
async fn writes_start_only_between_quorum_and_the_end_of_the_elevation() {
    let fixture = fixture("elevation").await;
    stage_policy(&fixture, "elevate").await;
    write_roots(&fixture);
    let (app, store) = fixture.server().await;
    let human = fixture.token(&["debuggers"], None);
    let (code, session) = call(
        &app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("stage", None)),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{session}");
    let id = session["id"].as_str().unwrap();
    assert!(handed_out(&app).await.is_null());

    let elevations = format!("/v1/debug-sessions/{id}/elevations");
    let request = serde_json::json!({"reason": "restart the stuck pods"});
    let (code, elevation) = call(&app, "POST", &elevations, &human, Some(request)).await;
    assert_eq!(code, StatusCode::CREATED, "{elevation}");
    assert_eq!(elevation["state"], "pending");
    let elevation_id = elevation["id"].as_str().unwrap();
    let approvals = format!("{elevations}/{elevation_id}/approvals");
    let commands = format!("/v1/runtime/environments/stage/debug-sessions/{id}/commands");
    let write = serde_json::json!({"argv": ["restart"], "access": "write", "outcome": "started"});

    let [alice, bob, own] = approvers();
    for approver in [&own, &alice] {
        let (code, answer) = call(
            &app,
            "POST",
            &approvals,
            &human,
            Some(approver.approve(&elevation)),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{answer}");
        assert_eq!(answer["state"], "pending", "{answer}");
    }
    assert!(handed_out(&app).await.is_null());
    let (code, _) = runtime(&app, "POST", &commands, "first", true, Some(write.clone())).await;
    assert_eq!(code, StatusCode::CONFLICT, "no write starts before quorum");

    let (code, active) = call(
        &app,
        "POST",
        &approvals,
        &human,
        Some(bob.approve(&elevation)),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{active}");
    assert_eq!(active["state"], "active", "{active}");
    let until = active["not_after"].as_i64().unwrap();
    assert!(until <= session["not_after"].as_i64().unwrap());
    assert_eq!(handed_out(&app).await, until);
    let (code, answer) = runtime(&app, "POST", &commands, "first", true, Some(write.clone())).await;
    assert_eq!(code, StatusCode::NO_CONTENT, "{answer}");
    assert_eq!(audited(&store, "debug_session.elevate.completed"), 1);
    assert_eq!(audited(&store, "debug_session.command.started"), 1);

    let revoke = format!("{elevations}/{elevation_id}/revoke");
    let reason = serde_json::json!({"reason": "done"});
    let (code, ended) = call(&app, "POST", &revoke, &human, Some(reason)).await;
    assert_eq!(code, StatusCode::OK, "{ended}");
    assert_eq!(ended["state"], "ended", "{ended}");
    assert!(handed_out(&app).await.is_null());
    let (code, _) = runtime(&app, "POST", &commands, "first", true, Some(write)).await;
    assert_eq!(code, StatusCode::CONFLICT, "no write starts after the end");
    let (code, listed) = call(&app, "GET", &elevations, &human, None).await;
    assert_eq!(code, StatusCode::OK, "{listed}");
    assert_eq!(listed["elevations"][0]["state"], "ended");
    assert_eq!(audited(&store, "debug_session.elevate.revoked"), 1);
}

/// A `read` policy, an agent, missing trust roots and an approval bound to
/// another elevation are each refused and audited once; nothing elevates.
#[tokio::test]
async fn refused_elevations_name_their_reason() {
    let fixture = fixture("elevation-refusals").await;
    stage_policy(&fixture, "read").await;
    let (app, store) = fixture.server().await;
    let human = fixture.token(&["debuggers"], None);
    let (_, session) = call(
        &app,
        "POST",
        "/v1/debug-sessions",
        &human,
        Some(open("stage", None)),
    )
    .await;
    let elevations = format!(
        "/v1/debug-sessions/{}/elevations",
        session["id"].as_str().unwrap()
    );
    let request = serde_json::json!({"reason": "restart"});

    let (code, answer) = call(&app, "POST", &elevations, &human, Some(request.clone())).await;
    assert_eq!(
        code,
        StatusCode::FORBIDDEN,
        "a read policy never elevates: {answer}"
    );
    drop(app);

    stage_policy(&fixture, "elevate").await;
    let (app, _) = fixture.server().await;
    let (code, answer) = call(&app, "POST", &elevations, &human, Some(request.clone())).await;
    assert_eq!(
        code,
        StatusCode::SERVICE_UNAVAILABLE,
        "no trust roots: {answer}"
    );
    drop(app);

    write_roots(&fixture);
    let (app, _) = fixture.server().await;
    let agent = fixture.token(&["debuggers"], Some("agent-1"));
    let (code, answer) = call(&app, "POST", &elevations, &agent, Some(request.clone())).await;
    assert_eq!(
        code,
        StatusCode::FORBIDDEN,
        "an agent never elevates: {answer}"
    );

    let (_, first) = call(&app, "POST", &elevations, &human, Some(request.clone())).await;
    let (_, second) = call(&app, "POST", &elevations, &human, Some(request)).await;
    let [alice, ..] = approvers();
    let approvals = format!("{elevations}/{}/approvals", second["id"].as_str().unwrap());
    let (code, answer) = call(
        &app,
        "POST",
        &approvals,
        &human,
        Some(alice.approve(&first)),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST, "bound elsewhere: {answer}");
    assert_eq!(audited(&store, "debug_session.elevate.refused"), 4);
    assert_eq!(audited(&store, "debug_session.elevate.completed"), 0);
}
