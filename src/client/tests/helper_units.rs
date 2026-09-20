use crate::client::{
    action_actor_from_changes, apply_remote_property_index, canonical_create_request,
    canonical_update_request, lease_precondition, token_transport_is_safe,
};
use crate::pb::sekai::{Object, ObjectChange};
use sekai_client::ClientConfig;

fn indexed_plan_object(id: &str, created_at: i64) -> Object {
    Object {
        id: id.into(),
        kind: crate::ontology::KIND_PLAN.into(),
        properties: std::collections::HashMap::from([
            ("environment".into(), "stage".into()),
            ("status".into(), "computed".into()),
            ("created_at".into(), created_at.to_string()),
            ("has_steps".into(), "true".into()),
        ]),
        ..Default::default()
    }
}

#[test]
fn remote_property_index_pages_one_transferred_set() {
    let objects = (1..=16)
        .map(|created_at| indexed_plan_object(&format!("plan-{created_at}"), created_at))
        .collect::<Vec<_>>();
    let matching = ["computed"];
    let page0 = apply_remote_property_index(
        objects.clone(),
        &crate::embedded::PropertyIndexQuery {
            matching_key: Some("status"),
            matching_values: &matching,
            equals_key: Some("has_steps"),
            equals_value: Some("true"),
            order_key: Some("created_at"),
            descending: false,
            limit: Some(8),
            offset: Some(0),
            ..crate::embedded::PropertyIndexQuery::new(
                crate::ontology::KIND_PLAN,
                "environment",
                "stage",
            )
        },
    )
    .unwrap();
    let page1 = apply_remote_property_index(
        objects,
        &crate::embedded::PropertyIndexQuery {
            matching_key: Some("status"),
            matching_values: &matching,
            equals_key: Some("has_steps"),
            equals_value: Some("true"),
            order_key: Some("created_at"),
            descending: false,
            limit: Some(8),
            offset: Some(8),
            ..crate::embedded::PropertyIndexQuery::new(
                crate::ontology::KIND_PLAN,
                "environment",
                "stage",
            )
        },
    )
    .unwrap();
    let ids = |page: &[Object]| {
        page.iter()
            .map(|object| object.id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(&page0),
        (1..=8).map(|n| format!("plan-{n}")).collect::<Vec<_>>()
    );
    assert_eq!(
        ids(&page1),
        (9..=16).map(|n| format!("plan-{n}")).collect::<Vec<_>>()
    );
}

#[test]
fn bearer_tokens_require_tls_or_loopback() {
    assert!(token_transport_is_safe("https://sekai.example.com"));
    assert!(token_transport_is_safe("http://127.0.0.1:50051"));
    assert!(token_transport_is_safe("http://[::1]:50051"));
    assert!(!token_transport_is_safe("http://sekai.example.com"));
    assert!(!token_transport_is_safe("http://127.0.0.1.evil.test"));
    assert!(!token_transport_is_safe(
        "http://localhost:80@attacker.example:50051"
    ));
}

#[test]
fn remote_client_config_redacts_credentials_and_preserves_principal() {
    let config = ClientConfig::new("http://127.0.0.1:50051", "tenkai.operator")
        .with_token("provider-token")
        .unwrap();

    assert_eq!(config.principal, "tenkai.operator");
    assert_eq!(
        format!("{:?}", config.credential.as_ref().unwrap()),
        "Credential(REDACTED)"
    );
}

#[test]
fn canonical_fenced_requests_preserve_lease_identity_and_request_id() {
    let precondition = lease_precondition("tenkai", "environment/prod", "fence-7");
    let create = canonical_create_request(
        Object {
            id: "object-1".into(),
            ..Default::default()
        },
        Some(precondition.clone()),
    );
    let update = canonical_update_request(
        Object {
            id: "object-1".into(),
            ..Default::default()
        },
        Some(precondition),
    );

    let create_lease = create.lease_precondition.as_ref().unwrap();
    let update_lease = update.lease_precondition.as_ref().unwrap();
    assert_eq!(create_lease.namespace, "tenkai");
    assert_eq!(create_lease.key, "environment/prod");
    assert_eq!(create_lease.fencing_token, "fence-7");
    assert!(!create_lease.request_id.is_empty());
    assert_eq!(create_lease, update_lease);
}

#[test]
fn emergency_override_actor_uses_property_change_field() {
    let changes = vec![ObjectChange {
        field: "properties.last_emergency_override_correlation".into(),
        new_value: "correlation-1".into(),
        changed_by: "authenticated-operator".into(),
        ..Default::default()
    }];

    assert_eq!(
        action_actor_from_changes(
            &changes,
            "properties.last_emergency_override_correlation",
            "correlation-1"
        )
        .as_deref(),
        Some("authenticated-operator")
    );
    assert_eq!(
        action_actor_from_changes(
            &changes,
            "properties.last_emergency_override_correlation",
            "correlation-2"
        ),
        None
    );
}
