use super::lifecycle_support::lifecycle_router;
use super::support::{current_generation, router_generation};
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

fn fact_body(environment: &str, kind: &str, generation: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "operation": "configure",
        "environment": environment,
        "expected_generation": generation,
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
    let stage = router_generation(&app, "stage").await;

    assert_eq!(
        send(
            &app,
            "PUT",
            facts,
            None,
            fact_body("stage", "set_fact", stage)
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &app,
            "PUT",
            facts,
            Some("runtime-secret"),
            fact_body("stage", "set_fact", stage)
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
            fact_body("prod", "set_fact", stage)
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
            fact_body("stage", "set_fact", stage)
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
            fact_body("stage", "set_fact", stage)
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
    let (app, _config, _store) = lifecycle_router(&root).await;
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
            operational: Vec::new(),
        },
    ];

    client
        .register_environment("edge", "edge site", isolated, "new site")
        .await
        .unwrap();
    for change in changes.clone() {
        let generation = current_generation(&client, "edge").await;
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
            |_| Ok(()),
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
                operational: Vec::new(),
            },
            "webhook URL must use HTTPS".into(),
        ),
    ] {
        let error = client
            .configure_environment(
                "edge",
                change,
                "bad input",
                current_generation(&client, "edge").await,
            )
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
            current_generation(&client, "edge").await,
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("not a readable, valid policy file"),
        "{refused}"
    );
    assert!(!refused.contains("hunter2"), "{refused}");

    // A generation read from inspect is admitted once; the change advances
    // it, so the same value is then stale (#703).
    let read = current_generation(&client, "edge").await;
    client
        .configure_environment(
            "edge",
            Change::SetFact {
                key: "zone".into(),
                value: "zone-b".into(),
            },
            "inventory",
            read,
        )
        .await
        .unwrap();
    assert_ne!(current_generation(&client, "edge").await, read);
    let stale = client
        .configure_environment("edge", Change::ClearWebhooks { url: None }, "cleanup", read)
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("stale fencing generation"), "{stale}");
    let _ = std::fs::remove_dir_all(root);
}

/// #820: inspect reports the configured webhooks (never a secret value) and
/// the approval-policy path, as `tenkaictl env inspect` prints the same
/// report; an edit with the reported generation applies, a stale one is
/// refused.
#[tokio::test]
async fn inspect_reports_webhooks_and_the_policy_path_for_conditional_edits() {
    let root = temp_root("inspect-config");
    let (app, _config, _store) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();
    let policy = root.join("policy.toml");
    std::fs::write(
        &policy,
        "version = 1\nmode = \"manual\"\nttl_ms = 3600000\n",
    )
    .unwrap();
    client
        .register_environment("edge", "edge site", None, "new site")
        .await
        .unwrap();
    for change in [
        Change::SetWebhook {
            url: "https://hooks.example/deploy".into(),
            secret_env: "EDGE_HOOK_SECRET_820".into(),
            events: vec![tenkai::deploy_webhook::WebhookEvent::ApplyFailed],
            operational: Vec::new(),
        },
        Change::SetWebhook {
            url: "https://hooks.example/audit".into(),
            secret_env: "AUDIT_HOOK_SECRET".into(),
            events: Vec::new(),
            operational: vec![tenkai::deploy_webhook::OperationalEvent::PlanHeld],
        },
        Change::SetApprovalPolicy {
            path: policy.to_string_lossy().into_owned(),
        },
    ] {
        let generation = current_generation(&client, "edge").await;
        client
            .configure_environment("edge", change, "site setup", generation)
            .await
            .unwrap();
    }

    let report = client.inspect_environment("edge").await.unwrap();
    let webhooks: Vec<_> = report
        .webhooks
        .iter()
        .map(|hook| (hook.url.as_str(), hook.secret_env.as_str()))
        .collect();
    assert_eq!(
        webhooks,
        [
            ("https://hooks.example/deploy", "EDGE_HOOK_SECRET_820"),
            ("https://hooks.example/audit", "AUDIT_HOOK_SECRET"),
        ]
    );
    assert_eq!(
        report.webhooks[0].events,
        [tenkai::deploy_webhook::WebhookEvent::ApplyFailed]
    );
    assert_eq!(
        report.webhooks[1].operational,
        [tenkai::deploy_webhook::OperationalEvent::PlanHeld]
    );
    let canonical = policy.canonicalize().unwrap();
    assert_eq!(
        report.approval_policy.as_deref(),
        Some(canonical.to_str().unwrap())
    );
    // Only the variable name travels: no field could carry a secret value.
    let body = serde_json::to_value(&report).unwrap();
    for hook in body["webhooks"].as_array().unwrap() {
        let mut keys: Vec<_> = hook.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert!(
            keys.iter()
                .all(|key| ["events", "operational", "secret_env", "url"].contains(&key.as_str())),
            "{keys:?}"
        );
    }

    // The embedded report `tenkaictl env inspect` prints is the same.
    let mut ctx = tenkai::client::Ctx::embedded(root.join("tenkai.db")).unwrap();
    let embedded = tenkai::plan::inspect_environment_with_outcomes(&mut ctx, "edge")
        .await
        .unwrap();
    assert_eq!(embedded.webhooks, report.webhooks);
    assert_eq!(embedded.approval_policy, report.approval_policy);

    // An edit with the generation inspect reports applies; reusing it after
    // that edit advanced the generation is refused.
    let generation = report.lease.generation.unwrap_or(0);
    client
        .configure_environment(
            "edge",
            Change::ClearWebhooks {
                url: Some("https://hooks.example/audit".into()),
            },
            "retire audit hook",
            generation,
        )
        .await
        .unwrap();
    let stale = client
        .configure_environment("edge", Change::ClearApprovalPolicy, "late edit", generation)
        .await
        .unwrap_err()
        .to_string();
    assert!(stale.contains("generation"), "{stale}");
    let after = client.inspect_environment("edge").await.unwrap();
    assert_eq!(after.webhooks.len(), 1);
    assert!(
        after.approval_policy.is_some(),
        "the stale edit wrote nothing"
    );
    let _ = std::fs::remove_dir_all(root);
}
