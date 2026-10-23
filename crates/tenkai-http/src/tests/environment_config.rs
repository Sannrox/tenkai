use super::lifecycle_support::lifecycle_router;
use super::*;
use tenkai::environment_config::EnvironmentConfigChange as Change;

fn temp_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "tenkai-env-config-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

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

fn fact_body(environment: &str, kind: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "operation": "configure",
        "environment": environment,
        "expected_generation": 0,
        "reason": "inventory",
        "change": {"kind": kind, "key": "architecture", "value": "arm64"}
    }))
    .unwrap()
}

#[tokio::test]
async fn configuration_routes_require_management_and_stay_in_scope() {
    let root = temp_root("auth");
    let (app, _config, _) = lifecycle_router(&root).await;
    let register = serde_json::to_vec(&serde_json::json!({
        "version": 1, "operation": "register", "environment": "edge", "reason": "new site"
    }))
    .unwrap();
    let facts = "/v1/environments/stage/facts";

    assert_eq!(
        send(&app, "PUT", facts, None, fact_body("stage", "set_fact")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &app,
            "PUT",
            facts,
            Some("runtime-secret"),
            fact_body("stage", "set_fact")
        )
        .await,
        StatusCode::FORBIDDEN
    );
    // An environment-scoped token cannot create environments or edit another one.
    assert_eq!(
        send(
            &app,
            "POST",
            "/v1/environments",
            Some("stage-secret"),
            register.clone()
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &app,
            "PUT",
            "/v1/environments/prod/facts",
            Some("stage-secret"),
            fact_body("prod", "set_fact")
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &app,
            "PUT",
            facts,
            Some("stage-secret"),
            fact_body("stage", "set_fact")
        )
        .await,
        StatusCode::OK
    );
    // The method and the change kind must agree.
    assert_eq!(
        send(
            &app,
            "DELETE",
            facts,
            Some("stage-secret"),
            fact_body("stage", "set_fact")
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(
            &app,
            "POST",
            "/v1/environments",
            Some("management-secret"),
            register
        )
        .await,
        StatusCode::OK
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Every configuration a remote operator can make, made once through HTTP on
/// `edge` and once through the embedded functions on `edge-emb`.
#[tokio::test]
async fn remote_configuration_matches_embedded_and_refuses_like_the_cli() {
    let root = temp_root("parity");
    let (app, _config, store) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();
    let isolated = Some(tenkai::connectivity::ConnectivityClass::Isolated);
    let changes = [
        Change::SetFact {
            key: "architecture".into(),
            value: "arm64".into(),
        },
        Change::SetFact {
            key: "memory_gib".into(),
            value: "64".into(),
        },
        Change::ClearFact {
            key: "memory_gib".into(),
        },
        Change::SetConstraint {
            constraint: "version_pin".into(),
            name: "api".into(),
            value: "1.2.3".into(),
        },
        Change::SetMaintenanceWindow {
            name: "nightly".into(),
            timezone: "Europe/Berlin".into(),
            weekdays: vec![1, 2, 3, 4, 5],
            start: "02:00".into(),
            duration_minutes: 120,
        },
        Change::SetWebhook {
            url: "https://hooks.example/deploy".into(),
            secret_env: "DEPLOY_HOOK_SECRET".into(),
            events: vec![tenkai::deploy_webhook::WebhookEvent::ApplyFailed],
        },
    ];

    client
        .register_environment("edge", "edge site", isolated, "new site")
        .await
        .unwrap();
    for change in changes.clone() {
        let generation = generation(&store, "edge");
        client
            .configure_environment("edge", change, "site setup", generation)
            .await
            .unwrap();
    }

    let mut ctx = tenkai::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    tenkai::environment_config::register(
        &mut ctx,
        &tenkai::environment_config::RegisterEnvironmentRequest {
            version: 1,
            operation: "register".into(),
            environment: "edge-emb".into(),
            description: "edge site".into(),
            connectivity_class: isolated,
            reason: "new site".into(),
        },
        "operator",
    )
    .await
    .unwrap();
    for change in &changes {
        tenkai::environment_config::apply(
            &mut ctx,
            "edge-emb",
            change,
            "site setup",
            "operator",
            || Ok(()),
        )
        .await
        .unwrap();
    }

    let configured = |report: tenkai::environment::EnvironmentInspectReport| {
        let windows = report.maintenance.map(|maintenance| {
            maintenance
                .windows
                .into_iter()
                .map(|window| {
                    (
                        window.identity,
                        window.timezone,
                        window.weekdays,
                        window.start,
                    )
                })
                .collect::<Vec<_>>()
        });
        (
            report.description,
            report.facts,
            report.constraints,
            windows,
        )
    };
    let remote = configured(client.inspect_environment("edge").await.unwrap());
    let embedded = configured(client.inspect_environment("edge-emb").await.unwrap());
    assert_eq!(remote, embedded);
    assert_eq!(
        remote.1.get("architecture").map(String::as_str),
        Some("arm64")
    );
    assert_eq!(
        tenkai::deploy_webhook::list_environment_webhooks(&mut ctx, "edge")
            .await
            .unwrap(),
        tenkai::deploy_webhook::list_environment_webhooks(&mut ctx, "edge-emb")
            .await
            .unwrap()
    );
    let audit = tenkai::environment_config::audit(&mut ctx, "edge")
        .await
        .unwrap();
    // A registration retry may not change an existing connectivity class.
    let retry = client
        .register_environment(
            "edge",
            "edge site",
            Some(tenkai::connectivity::ConnectivityClass::Connected),
            "retry",
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        retry.contains("already registered with connectivity class isolated"),
        "{retry}"
    );
    client
        .register_environment("edge", "edge site", isolated, "retry")
        .await
        .unwrap();

    // Each change is audited before it is written, then with its outcome.
    assert_eq!(audit.len(), 2 * (1 + changes.len()));
    assert_eq!(
        (audit[0].action.as_str(), audit[0].outcome.as_str()),
        ("register", "requested")
    );
    for pair in audit.chunks(2).skip(1) {
        assert_eq!(pair[0].action, pair[1].action);
        assert_eq!(
            (pair[0].outcome.as_str(), pair[1].outcome.as_str()),
            ("requested", "completed")
        );
        assert_eq!(pair[0].reason, "site setup");
    }
    assert!(audit.iter().all(|event| event.actor.contains("management")));

    // Invalid input is refused with the CLI's own messages, before any write.
    for (change, message) in [
        (
            Change::SetFact {
                key: "favourite_colour".into(),
                value: "blue".into(),
            },
            tenkai::plan::set_environment_fact(&mut ctx, "edge", "favourite_colour", "blue")
                .await
                .unwrap_err()
                .to_string(),
        ),
        (
            Change::SetMaintenanceWindow {
                name: "nightly".into(),
                timezone: "Mars/Olympus".into(),
                weekdays: vec![1],
                start: "02:00".into(),
                duration_minutes: 60,
            },
            "unknown IANA timezone".into(),
        ),
        (
            Change::SetWebhook {
                url: "http://hooks.example/deploy".into(),
                secret_env: "DEPLOY_HOOK_SECRET".into(),
                events: Vec::new(),
            },
            "webhook URL must use HTTPS".into(),
        ),
    ] {
        let error = client
            .configure_environment("edge", change, "bad input", generation(&store, "edge"))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("400"), "{error}");
        // The error body is JSON, so the CLI message appears with escaped quotes.
        let message = message.replace('"', "\\\"");
        assert!(error.contains(&message), "{error} lacks {message}");
    }

    // A file that is not a policy never echoes its contents back.
    let not_a_policy = root.join("credentials.toml");
    std::fs::write(&not_a_policy, "token = \"hunter2\" [[[\n").unwrap();
    let refused = client
        .configure_environment(
            "edge",
            Change::SetApprovalPolicy {
                path: not_a_policy.display().to_string(),
            },
            "policy",
            generation(&store, "edge"),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("not a readable, valid policy file"),
        "{refused}"
    );
    assert!(!refused.contains("hunter2"), "{refused}");

    // The operational-store record is fixture state, as for stage and prod.
    store
        .put_environment(&tenkai::storage::EnvironmentRecord {
            id: "edge".into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .unwrap();
    store
        .acquire_lease("edge", "config-fence", tenkai::now_millis() + 60_000)
        .unwrap();
    let stale = client
        .configure_environment("edge", Change::ClearWebhooks { url: None }, "cleanup", 0)
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("stale fencing generation"), "{stale}");
    let _ = std::fs::remove_dir_all(root);
}

fn generation(store: &tenkai::storage::SqliteStore, environment: &str) -> u64 {
    tenkai::management_lifecycle::environment_fence_generation(
        store
            .current_lease(environment)
            .unwrap()
            .map(|lease| lease.generation),
    )
}
