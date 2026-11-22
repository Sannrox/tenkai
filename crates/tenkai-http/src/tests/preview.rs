use super::lifecycle_support::lifecycle_router;
use super::support::current_generation;
use super::*;

fn temp_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "tenkai-preview-http-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn sample_pin() -> tenkai::preview::BranchPin {
    tenkai::preview::BranchPin {
        contract: tenkai::preview::PIN_CONTRACT.into(),
        namespace: "acme".into(),
        branch_id: "types".into(),
        head_revision: "rev-1".into(),
        pin_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn other_pin() -> tenkai::preview::BranchPin {
    let mut pin = sample_pin();
    pin.branch_id = "policies".into();
    pin.pin_digest = format!("sha256:{}", "b".repeat(64));
    pin
}

const EXPIRES: &str = "2099-01-01T00:00:00Z";

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> StatusCode {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

fn provision_body(
    environment: &str,
    pin: &tenkai::preview::BranchPin,
    expires_at: &str,
) -> Vec<u8> {
    serde_json::to_vec(&tenkai::environment_config::ProvisionPreviewRequest {
        version: 1,
        operation: "preview".into(),
        environment: environment.into(),
        pin: pin.clone(),
        expires_at: expires_at.into(),
        description: String::new(),
        reason: "review branch".into(),
    })
    .unwrap()
}

/// HTTP v1 create/close of a branch-pin preview: same provision/close_branch
/// rules as embedded `env preview` / `env close-preview`.
#[tokio::test]
async fn http_v1_creates_and_closes_preview_environments() {
    let root = temp_root("create-close");
    let (app, _config, _) = lifecycle_router(&root).await;
    let create = provision_body("review", &sample_pin(), EXPIRES);
    let close = serde_json::to_vec(&tenkai::environment_config::ClosePreviewRequest {
        version: 1,
        operation: "close_preview".into(),
    })
    .unwrap();

    assert_eq!(
        send(
            &app,
            "POST",
            "/v1/environments/preview",
            None,
            create.clone()
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &app,
            "POST",
            "/v1/environments/preview",
            Some("runtime-secret"),
            create.clone()
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &app,
            "POST",
            "/v1/environments/preview",
            Some("stage-secret"),
            create.clone()
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &app,
            "POST",
            "/v1/environments/prod/close-preview",
            Some("stage-secret"),
            close.clone()
        )
        .await,
        StatusCode::FORBIDDEN
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();

    let created = client
        .provision_preview("review", sample_pin(), EXPIRES, "", "review branch")
        .await
        .unwrap();
    assert!(
        created.message.contains("registered"),
        "{}",
        created.message
    );
    let replay = client
        .provision_preview("review", sample_pin(), EXPIRES, "", "review branch")
        .await
        .unwrap();
    assert!(
        replay.message.contains("already registered"),
        "{}",
        replay.message
    );

    let inspect = client.inspect_environment("review").await.unwrap();
    let preview = inspect.preview.expect("preview inspect");
    assert_eq!(preview.status, tenkai::preview::STATUS_ACTIVE);
    assert_eq!(preview.pin_digest, sample_pin().pin_digest);

    let pin_conflict = client
        .provision_preview("review", other_pin(), EXPIRES, "", "review branch")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        pin_conflict.contains("different branch pin"),
        "{pin_conflict}"
    );
    let expiry_conflict = client
        .provision_preview(
            "review",
            sample_pin(),
            "2099-06-01T00:00:00Z",
            "",
            "review branch",
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        expiry_conflict.contains("different expiry"),
        "{expiry_conflict}"
    );
    let past = client
        .provision_preview(
            "review-past",
            sample_pin(),
            "2000-01-01T00:00:00Z",
            "",
            "review branch",
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(past.contains("expiry must be in the future"), "{past}");

    let generation = current_generation(&client, "review").await;
    let subscribe = client
        .subscribe_environment("review", "api=stable", generation, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        subscribe.contains("cannot be promoted to a channel"),
        "{subscribe}"
    );

    let closed = client.close_preview("review").await.unwrap();
    assert!(closed.message.contains("torn down"), "{}", closed.message);
    let after = client.inspect_environment("review").await.unwrap();
    assert_eq!(
        after
            .preview
            .as_ref()
            .map(|preview| preview.status.as_str()),
        Some(tenkai::preview::STATUS_TORN_DOWN)
    );
    let reuse = client
        .provision_preview("review", sample_pin(), EXPIRES, "", "review branch")
        .await
        .unwrap_err()
        .to_string();
    assert!(reuse.contains("was torn down"), "{reuse}");

    let ordinary = client.close_preview("prod").await.unwrap_err().to_string();
    assert!(ordinary.contains("not a preview environment"), "{ordinary}");
    let prod = client.inspect_environment("prod").await.unwrap();
    assert!(prod.preview.is_none(), "{prod:?}");
    assert_eq!(prod.description, "other");

    let _ = std::fs::remove_dir_all(root);
}
