use super::super::*;
use std::sync::mpsc;
use std::time::Duration;
use tenkai::storage::{OperationalStore as _, ProviderEventRecord};

/// #1310: an enqueue racing another enqueue of the same event is idempotent.
/// A raw connection inserts the event and holds its transaction open while
/// the store enqueues the same event, which therefore reads no row and then
/// waits on the key. After A commits, the store's enqueue succeeds instead of
/// failing with a unique violation, and one row remains.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_provider_enqueue_racing_a_duplicate_is_idempotent() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let store = config.open().expect("connect");
    let tenant = format!(
        "pe{}{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let partition = store.partition_by_id(&tenant).unwrap();
    let event = |id: &str| ProviderEventRecord {
        id: id.into(),
        provider_kind: "feedback".into(),
        binding_digest: "sha256:binding".into(),
        payload_json: "{}".into(),
        attempts: 0,
        next_attempt_at: 1_000,
        delivered_at: None,
        last_error: String::new(),
        claim_token: None,
        claim_until: None,
    };
    // Creates the tenant schema.
    partition.enqueue_provider_event(&event("warm-up")).unwrap();
    let schema = partition.schema.clone();

    let mut raw = postgres::Client::connect(&config.url, postgres::NoTls).expect("raw connect");
    let mut a = raw.transaction().unwrap();
    a.execute(
        &format!(
            "INSERT INTO {schema}.provider_events(id,provider_kind,binding_digest,payload_json,attempts,next_attempt_at,last_error)
             VALUES('raced','feedback','sha256:binding','{{}}',0,1000,'')"
        ),
        &[],
    )
    .unwrap();

    let (done, enqueued) = mpsc::channel();
    let racer = std::thread::spawn(move || {
        done.send(partition.enqueue_provider_event(&event("raced")))
            .unwrap();
    });
    assert!(
        enqueued.recv_timeout(Duration::from_millis(500)).is_err(),
        "the store enqueue must wait on the uncommitted key"
    );
    a.commit().unwrap();
    enqueued
        .recv_timeout(Duration::from_secs(30))
        .expect("enqueue finished")
        .expect("a duplicate enqueue is idempotent");
    racer.join().unwrap();
    let rows: i64 = raw
        .query_one(
            &format!("SELECT count(*) FROM {schema}.provider_events WHERE id='raced'"),
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(rows, 1);
}
