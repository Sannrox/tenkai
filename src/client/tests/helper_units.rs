use crate::client::{action_actor_from_changes, apply_property_index};
use crate::pb::record::{Object, ObjectChange};

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
fn property_index_pages_one_transferred_set() {
    let objects = (1..=16)
        .map(|created_at| indexed_plan_object(&format!("plan-{created_at}"), created_at))
        .collect::<Vec<_>>();
    let matching = ["computed"];
    let page0 = apply_property_index(
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
    let page1 = apply_property_index(
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
