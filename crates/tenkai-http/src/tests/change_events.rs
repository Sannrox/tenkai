use super::support::{FixedReconciler, app};
use super::*;
use tenkai::change_stream::{ChangeEventKind, ChangeEventPage};

#[tokio::test]
async fn change_events_require_read_capability() {
    let (app, _) = app();
    let denied = app
        .clone()
        .oneshot(Request::get("/v1/events").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let runtime = app
        .clone()
        .oneshot(
            Request::get("/v1/events")
                .header("authorization", "Bearer runtime-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(runtime.status(), StatusCode::FORBIDDEN);

    let allowed = app
        .oneshot(
            Request::get("/v1/events")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let page: ChangeEventPage = serde_json::from_slice(
        &axum::body::to_bytes(allowed.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(page.events.is_empty());
    assert_eq!(page.next_cursor, "0");
}

#[tokio::test]
async fn change_events_resume_from_cursor_without_gaps_or_duplicates() {
    let (app, store) = app();
    let mut written = Vec::new();
    for (index, kind) in ChangeEventKind::ALL.iter().enumerate() {
        written.push(
            store
                .append_change_event(
                    1_700_000_000_000 + index as i64,
                    kind.as_str(),
                    &format!("resource-{index}"),
                    if index % 2 == 0 { "prod" } else { "" },
                )
                .unwrap(),
        );
    }

    let first = app
        .clone()
        .oneshot(
            Request::get("/v1/events?limit=5")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_page: ChangeEventPage = serde_json::from_slice(
        &axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first_page.events, written[..5]);
    assert_eq!(first_page.next_cursor, written[4].cursor);

    let second = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/events?cursor={}&limit=20",
                first_page.next_cursor
            ))
            .header("authorization", "Bearer management-secret")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_page: ChangeEventPage = serde_json::from_slice(
        &axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(second_page.events, written[5..]);

    let mut seen = std::collections::BTreeSet::new();
    for event in first_page.events.iter().chain(second_page.events.iter()) {
        assert!(
            seen.insert(event.cursor.clone()),
            "duplicate cursor {}",
            event.cursor
        );
    }
    assert_eq!(seen.len(), written.len());
    assert_eq!(
        first_page
            .events
            .iter()
            .chain(second_page.events.iter())
            .cloned()
            .collect::<Vec<_>>(),
        written
    );

    let invalid = app
        .oneshot(
            Request::get("/v1/events?cursor=nope")
                .header("authorization", "Bearer management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn environment_scoped_events_resume_past_other_environments() {
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.environment_management_assignments =
        HashMap::from([("prod-secret".into(), "prod".into())]);
    let app = router(config, Arc::new(FixedReconciler::default()), store.clone()).unwrap();
    for (index, environment) in ["staging", "staging", "prod", "staging", "prod"]
        .into_iter()
        .enumerate()
    {
        store
            .append_change_event(
                1_700_000_000_000 + index as i64,
                "plan_created",
                &format!("resource-{index}"),
                environment,
            )
            .unwrap();
    }

    let mut cursor = String::from("0");
    let mut seen = Vec::new();
    for _ in 0..8 {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/events?cursor={cursor}&limit=2"))
                    .header("authorization", "Bearer prod-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page: ChangeEventPage = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        if page.events.is_empty() && page.next_cursor == cursor {
            break;
        }
        for event in page.events {
            seen.push(event.resource.clone());
            assert_eq!(event.environment.as_deref(), Some("prod"));
        }
        cursor = page.next_cursor;
    }
    assert_eq!(seen, vec!["resource-2", "resource-4"]);
}
