use super::super::*;
use std::sync::mpsc;
use std::time::Duration;
use tenkai::storage::{OperationalStore as _, ProviderEventRecord};

/// #1295: two claimers on separate connections never share a row. Claimer A
/// (a raw connection) holds an uncommitted claim on half the due events while
/// the store claims on its own connection. The store skips A's rows without
/// waiting for A, and A's commit leaves each row with exactly one token.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_postgres_concurrent_claimers_take_disjoint_events() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let tenant = format!(
        "pc{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let partition = store.partition_by_id(&tenant).unwrap();
    for n in 0..10 {
        partition
            .enqueue_provider_event(&ProviderEventRecord {
                id: format!("event-{n}"),
                provider_kind: "feedback".into(),
                binding_digest: "sha256:binding".into(),
                payload_json: "{}".into(),
                attempts: 0,
                next_attempt_at: 1_000 + n,
                delivered_at: None,
                last_error: String::new(),
                claim_token: None,
                claim_until: None,
            })
            .unwrap();
    }
    let schema = partition.schema.clone();
    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    let mut a = raw.transaction().unwrap();
    let held: Vec<String> = a
        .query(
            &format!(
                "UPDATE {schema}.provider_events SET claim_token='worker-a',claim_until=9000
                 WHERE id IN (SELECT id FROM {schema}.provider_events
                              ORDER BY next_attempt_at LIMIT 5)
                 RETURNING id"
            ),
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(held.len(), 5);

    let (done, claimed) = mpsc::channel();
    let claimer = std::thread::spawn(move || {
        let rows = partition
            .claim_provider_events(1_100, 10, "worker-b", 9_000)
            .unwrap();
        done.send(rows).unwrap();
    });
    // A claimer that waits on A's row locks is the bug: it would overwrite
    // A's token once A commits.
    let b = claimed
        .recv_timeout(Duration::from_secs(10))
        .expect("the store claim waited on another claimer's rows");
    a.commit().unwrap();
    claimer.join().unwrap();

    let b_ids: Vec<&str> = b.iter().map(|event| event.id.as_str()).collect();
    assert_eq!(b_ids.len(), 5, "{b_ids:?}");
    assert!(
        b_ids.iter().all(|id| !held.iter().any(|h| h == id)),
        "{b_ids:?}"
    );
    assert!(
        b.iter()
            .all(|e| e.claim_token.as_deref() == Some("worker-b"))
    );
    let tokens: Vec<(String, String)> = raw
        .query(
            &format!("SELECT id,claim_token FROM {schema}.provider_events ORDER BY id"),
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    for (id, token) in &tokens {
        let expected = if held.contains(id) {
            "worker-a"
        } else {
            "worker-b"
        };
        assert_eq!(token, expected, "{id}");
    }
}
