use super::lifecycle_support::lifecycle_router;
use super::support::current_generation;
use super::*;
use tenkai::canary::CanaryDesignationRequest;
use tenkai::environment_config::EnvironmentConfigChange as Change;

async fn label(client: &RemoteClient, environment: &str, value: &str) {
    let generation = current_generation(client, environment).await;
    client
        .configure_environment(
            environment,
            Change::SetLabel {
                key: "tier".into(),
                value: value.into(),
            },
            "group canaries",
            generation,
        )
        .await
        .unwrap();
}

/// A selector designation records the selector and the set it resolved to
/// at write time; a later label change does not alter the record (#1334).
#[tokio::test]
async fn designating_by_selector_records_the_resolved_set() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-canary-designation-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (app, _config, _store) = lifecycle_router(&root).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");
    let client = RemoteClient::new(&base, "management-secret").unwrap();
    label(&client, "stage", "edge").await;
    label(&client, "prod", "core").await;

    let refused = reqwest::Client::new()
        .post(format!("{base}/v1/canaries"))
        .bearer_auth("management-secret")
        .json(&serde_json::json!({ "selector": "tier=edge,=prod", "designated": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(body["reason"]["code"], "invalid_selector");
    assert_eq!(body["clause"], "=prod");
    assert!(client.canary_designations().await.unwrap().is_empty());

    let result = client
        .designate_canaries(&CanaryDesignationRequest {
            selector: Some("tier=edge".into()),
            environments: Vec::new(),
            designated: true,
        })
        .await
        .unwrap();
    assert_eq!(result.environments, ["stage"]);
    let recorded = tenkai::delivery_hold::HoldSelector {
        selector: "tier=edge".into(),
        environments: vec!["stage".into()],
    };

    // Relabeling prod into the selector leaves the recorded set unchanged.
    label(&client, "prod", "edge").await;
    let designations = client.canary_designations().await.unwrap();
    assert_eq!(designations.len(), 1);
    assert_eq!(designations[0].environment, "stage");
    assert_eq!(designations[0].selector.as_ref(), Some(&recorded));
    assert!(designations[0].set_by.is_some());
    assert!(designations[0].set_at.is_some());

    // By name, then undesignated by selector: both match now.
    client
        .designate_canaries(&CanaryDesignationRequest {
            selector: None,
            environments: vec!["prod".into()],
            designated: true,
        })
        .await
        .unwrap();
    let prod = client.canary_designations().await.unwrap();
    assert_eq!(prod[0].environment, "prod");
    assert_eq!(prod[0].selector, None);
    let cleared = client
        .designate_canaries(&CanaryDesignationRequest {
            selector: Some("tier=edge".into()),
            environments: Vec::new(),
            designated: false,
        })
        .await
        .unwrap();
    assert_eq!(cleared.environments, ["prod", "stage"]);
    assert!(client.canary_designations().await.unwrap().is_empty());

    // Both, neither, and an unknown name are refused before any write.
    for request in [
        serde_json::json!({ "selector": "tier=edge", "environments": ["stage"], "designated": true }),
        serde_json::json!({ "designated": true }),
        serde_json::json!({ "environments": ["stage", "missing"], "designated": true }),
    ] {
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/canaries"))
            .bearer_auth("management-secret")
            .json(&request)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_client_error(), "{request}");
    }
    assert!(client.canary_designations().await.unwrap().is_empty());
    // Designation is catalog-wide: an environment-scoped token is refused.
    let scoped = RemoteClient::new(&base, "stage-secret").unwrap();
    assert!(
        scoped
            .designate_canaries(&CanaryDesignationRequest {
                selector: None,
                environments: vec!["stage".into()],
                designated: true,
            })
            .await
            .is_err()
    );
    let _ = std::fs::remove_dir_all(root);
}
