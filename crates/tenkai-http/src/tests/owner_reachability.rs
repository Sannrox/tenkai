use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;
use tenkai::deploy_webhook::{WebhookEndpoint, WebhookEvent};
use tenkai::environment_config::EnvironmentConfigChange as Change;
use tenkai::owner::ReachabilityVerdict;

fn hook(url: &str) -> WebhookEndpoint {
    WebhookEndpoint {
        url: url.into(),
        secret_env: "HOOK_SECRET".into(),
        events: vec![WebhookEvent::ApplyFailed],
        operational: Vec::new(),
        feedback: Vec::new(),
    }
}

#[tokio::test]
async fn owner_reachability_and_product_webhook_delete_by_url() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-owner-reach-{}-{}",
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
    let client = RemoteClient::new(format!("http://{addr}"), "management-secret").unwrap();
    let release = signed_catalog_fixture(&root, "1.0.0");
    client.publish_release(&release).await.unwrap();

    // Deleting one product endpoint by url keeps the others.
    for url in ["https://hooks.example/a", "https://hooks.example/b"] {
        client.set_product_webhook("api", &hook(url)).await.unwrap();
    }
    client
        .clear_product_webhooks("api", Some("https://hooks.example/a"))
        .await
        .unwrap();
    let left = client.list_product_webhooks("api").await.unwrap();
    assert_eq!(
        left.iter()
            .map(|hook| hook.url.as_str())
            .collect::<Vec<_>>(),
        ["https://hooks.example/b"]
    );

    // An owner without endpoints is typed unconfigured on inspect.
    let generation = current_generation(&client, "stage").await;
    client
        .configure_environment(
            "stage",
            Change::SetOwner {
                contact: "oncall@example".into(),
            },
            "owner",
            generation,
        )
        .await
        .unwrap();
    let owner = client
        .inspect_environment("stage")
        .await
        .unwrap()
        .owner
        .unwrap();
    let reachability = owner.reachability.unwrap();
    assert_eq!(reachability.verdict, ReachabilityVerdict::Unconfigured);
    assert!(reachability.endpoints.is_empty());
    let _ = std::fs::remove_dir_all(root);
}
