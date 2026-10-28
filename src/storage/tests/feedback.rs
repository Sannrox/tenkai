//! Feedback observations ride in the operation's transaction (#802).

use super::*;
use crate::feedback_observation::{Capture, FeedbackObservation, Operation, Reason};
use crate::pb::sekai::Object;

fn note(id: &str, value: &str) -> Object {
    Object {
        id: id.into(),
        kind: "note".into(),
        name: id.into(),
        namespace: "test".into(),
        external_id: String::new(),
        properties: std::collections::HashMap::from([("value".into(), value.into())]),
        created: 1,
        updated: 1,
    }
}

fn observation(id: &str, status: &str) -> FeedbackObservation {
    FeedbackObservation::capture(Capture {
        id,
        operation: Operation::ApplyStep,
        environment: "prod",
        product: "api",
        plan_id: "plan-1",
        step_id: "step-1",
        action: Some(crate::plan::Action::Upgrade),
        release_id: "release:api:1.1.0",
        status,
        reason: Reason::None,
        started_at_ms: Some(1_000),
        lease_generation: 1,
        observed_at_ms: 2_000,
    })
}

/// An observation is stored with its operation, survives a reopen, cannot
/// be changed afterwards, and an identical replay is a no-op. A conflicting
/// replay keeps the stored observation and the operation still commits.
#[test]
fn observations_commit_with_their_operation_and_never_change() {
    let dir = std::env::temp_dir().join(format!("tenkai-feedback-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tenkai.db");
    let first = observation("deployment:prod:api:2000", "succeeded");
    {
        let store = SqliteStore::open(&path).unwrap();
        store.put(note("note-1", "a")).unwrap();
        store
            .put_with_provider_events(note("note-1", "b"), &[], std::slice::from_ref(&first))
            .unwrap();
        store
            .put_with_provider_events(note("note-1", "c"), &[], std::slice::from_ref(&first))
            .unwrap();
        let conflicting = observation("deployment:prod:api:2000", "failed");
        store
            .put_with_provider_events(note("note-1", "d"), &[], &[conflicting])
            .unwrap();
        assert_eq!(
            store.get_object("note-1").unwrap().unwrap().properties["value"],
            "d"
        );
        let error = store
            .connection()
            .unwrap()
            .execute("UPDATE feedback_observations SET body_json='{}'", [])
            .unwrap_err();
        assert!(error.to_string().contains("immutable"), "{error}");
    }
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(reopened.feedback_observations("prod").unwrap(), vec![first]);
    drop(reopened);
    let _ = std::fs::remove_dir_all(dir);
}

/// A capture that cannot be stored never interrupts its operation.
#[test]
fn a_failed_capture_does_not_interrupt_the_operation() {
    let store = SqliteStore::open_in_memory().unwrap();
    store.put(note("note-1", "a")).unwrap();
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TABLE feedback_observations")
        .unwrap();
    store
        .put_with_provider_events(
            note("note-1", "b"),
            &[],
            &[observation("deployment:prod:api:2000", "succeeded")],
        )
        .unwrap();
    assert_eq!(
        store.get_object("note-1").unwrap().unwrap().properties["value"],
        "b"
    );
}
