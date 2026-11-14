use super::lifecycle_support::lifecycle_router;
use super::support::current_generation;
use super::*;

#[tokio::test]
async fn selector_lists_refuses_bad_clauses_and_records_holds() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-selector-http-{}-{}",
        std::process::id(),
        tenkai::now_millis()
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
    for name in ["stage", "prod"] {
        let generation = current_generation(&client, name).await;
        client
            .configure_environment(
                name,
                tenkai::environment_config::EnvironmentConfigChange::SetLabel {
                    key: "tier".into(),
                    value: "web".into(),
                },
                "group the web tier",
                generation,
            )
            .await
            .unwrap();
    }

    let none = client
        .list_environments_matching("tier=batch")
        .await
        .unwrap();
    assert!(none.is_empty());

    let refused = reqwest::Client::new()
        .get(format!("{base}/v1/environments"))
        .query(&[("selector", "tier=web,=prod")])
        .bearer_auth("management-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(body["reason"]["code"], "invalid_selector");
    assert_eq!(body["clause"], "=prod");

    let generation = current_generation(&client, "stage").await;
    client
        .set_environment_hold("stage", "web freeze", generation, Some("tier=web"))
        .await
        .unwrap();
    let view = client.environment_hold("stage").await.unwrap();
    let expected = tenkai::delivery_hold::HoldSelector {
        selector: "tier=web".into(),
        environments: vec!["prod".into(), "stage".into()],
    };
    assert_eq!(view.hold.unwrap().selector.as_ref(), Some(&expected));
    assert_eq!(view.audit[0].selector.as_ref(), Some(&expected));

    let mismatch = client
        .set_environment_hold("stage", "web freeze", generation, Some("tier=batch"))
        .await
        .unwrap_err()
        .to_string();
    assert!(mismatch.contains("does not match selector"), "{mismatch}");
    let _ = std::fs::remove_dir_all(root);
}
