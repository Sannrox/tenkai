use super::super::*;
use tenkai::deploy_webhook::{OperationalEvent, WebhookEndpoint};
use tenkai::operational_events::{
    HOST_SCOPE, OPERATIONAL_WEBHOOK_KIND, Transition, announce, delivery_page,
    parse_delivery_cursor,
};
use tenkai::storage::OperationalStore;

/// Following the delivery cursor in a tenant partition reads every row of
/// every scope once, newest first, through equal timestamps (#1327).
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_delivery_pages_follow_the_cursor() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let suffix = format!(
        "{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let partition = store.partition_by_id(&format!("dp{suffix}")).unwrap();
    let partition: &dyn OperationalStore = &partition;
    let endpoint = WebhookEndpoint {
        url: "https://hooks.example/ops".into(),
        secret_env: "OPS_HOOK_SECRET".into(),
        events: Vec::new(),
        operational: vec![OperationalEvent::PlanHeld],
        feedback: Vec::new(),
        sources: Vec::new(),
    };
    let scopes = ["stage".to_string(), HOST_SCOPE.to_string()];
    for (index, tick) in [1, 1, 1, 2, 2, 3, 3].into_iter().enumerate() {
        let key = format!("k{index}");
        let held = Transition {
            event: OperationalEvent::PlanHeld,
            scope: &scopes[index % 2],
            resource: "plan-1",
            code: "environment",
            key: &key,
        };
        assert!(announce(
            partition,
            std::slice::from_ref(&endpoint),
            &held,
            tick
        ));
    }
    let mut expected: Vec<_> = scopes
        .iter()
        .flat_map(|scope| {
            partition
                .list_provider_events_after(OPERATIONAL_WEBHOOK_KIND, scope, None, 128)
                .unwrap()
        })
        .collect();
    expected.sort_by(|left, right| right.0.cmp(&left.0));
    let expected: Vec<_> = expected.into_iter().map(|(_, record)| record.id).collect();
    assert_eq!(expected.len(), 7);

    let mut ids = Vec::new();
    let mut after = None;
    loop {
        let page = delivery_page(partition, &scopes, after, 2, |_| true).unwrap();
        ids.extend(page.items.into_iter().map(|delivery| delivery.id));
        match page.next_cursor {
            Some(cursor) => after = Some(parse_delivery_cursor(&cursor).unwrap()),
            None => break,
        }
    }
    assert_eq!(ids, expected);
}
