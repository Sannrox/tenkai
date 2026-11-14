use super::lifecycle_support::{lifecycle_router, signed_catalog_fixture};
use super::support::current_generation;
use super::*;
use tenkai::deploy_webhook::{DeliverySource, OperationalEvent, WebhookEndpoint, WebhookEvent};
use tenkai::environment_config::EnvironmentConfigChange as Change;

const SHARED: &str = "https://hooks.example/shared";
const PRODUCT_ONLY: &str = "https://hooks.example/product";
/// The product subscribes this URL to apply failures only; `stage` to recalls.
const APPLY_ONLY: &str = "https://hooks.example/apply";

fn recall_hook(url: &str) -> WebhookEndpoint {
    WebhookEndpoint {
        url: url.into(),
        secret_env: "HOOK_SECRET".into(),
        events: Vec::new(),
        operational: vec![OperationalEvent::ReleaseRecalled],
        feedback: Vec::new(),
        sources: Vec::new(),
    }
}

#[tokio::test]
async fn deliveries_name_their_sources_and_list_per_product() {
    let root = std::env::temp_dir().join(format!(
        "tenkai-webhook-sources-{}-{}",
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
    client.promote_release("api@1.0.0", "stable").await.unwrap();
    let generation = current_generation(&client, "stage").await;
    client
        .subscribe_environment("stage", "api=stable", generation, None)
        .await
        .unwrap();
    for url in [SHARED, PRODUCT_ONLY] {
        client
            .set_product_webhook("api", &recall_hook(url))
            .await
            .unwrap();
    }
    client
        .set_product_webhook(
            "api",
            &WebhookEndpoint {
                events: vec![WebhookEvent::ApplyFailed],
                operational: Vec::new(),
                ..recall_hook(APPLY_ONLY)
            },
        )
        .await
        .unwrap();
    for url in [SHARED, APPLY_ONLY] {
        let generation = current_generation(&client, "stage").await;
        client
            .configure_environment(
                "stage",
                Change::SetWebhook {
                    url: url.into(),
                    secret_env: "HOOK_SECRET".into(),
                    events: Vec::new(),
                    operational: vec![OperationalEvent::ReleaseRecalled],
                    feedback: Vec::new(),
                },
                "route recalls",
                generation,
            )
            .await
            .unwrap();
    }
    client
        .set_product_owner(
            "api",
            &tenkai::owner::SetOwnerRequest {
                contact: "api-oncall@example".into(),
            },
        )
        .await
        .unwrap();

    client.recall_release("api@1.0.0").await.unwrap();

    let deliveries = client.product_webhook_deliveries("api").await.unwrap();
    let shared = deliveries
        .iter()
        .find(|delivery| delivery.url == SHARED)
        .expect("shared URL delivered once");
    let mut sources = shared.sources.clone();
    sources.sort();
    assert_eq!(
        sources,
        [
            DeliverySource::Environment("stage".into()),
            DeliverySource::Product("api".into()),
        ]
    );
    assert!(
        deliveries
            .iter()
            .any(|delivery| delivery.url == PRODUCT_ONLY)
    );
    assert_eq!(
        deliveries
            .iter()
            .filter(|delivery| delivery.url == SHARED)
            .count(),
        1
    );

    // The product does not subscribe APPLY_ONLY to recalls, so it is no source.
    assert!(!deliveries.iter().any(|delivery| delivery.url == APPLY_ONLY));
    // Recalls are host-wide; an environment-scoped credential reads none.
    let scoped = RemoteClient::new(format!("http://{addr}"), "stage-secret").unwrap();
    assert!(
        scoped
            .product_webhook_deliveries("api")
            .await
            .unwrap()
            .is_empty()
    );

    let owner = client.inspect_product_owner("api").await.unwrap().unwrap();
    let reachability = owner.reachability.expect("product owner reachability");
    assert_eq!(reachability.endpoints.len(), 3);

    let fleet = client.fleet_status().await.unwrap();
    let unrouted = |name: &str| {
        fleet
            .environments
            .iter()
            .find(|row| row.id == format!("tenkai:env:{name}"))
            .unwrap()
            .unrouted
    };
    assert!(!unrouted("stage"));
    assert!(unrouted("prod"));
    let _ = std::fs::remove_dir_all(root);
}
