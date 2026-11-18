use super::*;

/// #1303: two handles on one WAL file (the CLI next to a server) run
/// read-then-write operations at the same time. Each one waits its turn on
/// the busy timeout instead of failing the read-to-write lock upgrade with
/// `SQLITE_BUSY`, and the results stay correct: the lease keeps its
/// generation, every plan transition lands, and sequences never repeat.
#[test]
fn two_handles_on_one_file_serialize_read_then_write_operations() {
    let path = std::env::temp_dir().join(format!(
        "tenkai-contention-{}-{}.db",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let first = SqliteStore::open(&path).unwrap();
    environment(&first);
    plan(&first);
    let far = crate::now_millis() + 600_000;
    let generation = OperationalStore::acquire_lease(&first, "prod", "worker", far)
        .unwrap()
        .generation;
    first
        .enqueue_provider_event(&ProviderEventRecord {
            id: "event-1".into(),
            provider_kind: "feedback".into(),
            binding_digest: "sha256:binding".into(),
            payload_json: "{}".into(),
            attempts: 0,
            next_attempt_at: 0,
            delivered_at: None,
            last_error: String::new(),
            claim_token: None,
            claim_until: None,
        })
        .unwrap();
    assert_eq!(
        first
            .claim_provider_events(0, 1, "claimer", far)
            .unwrap()
            .len(),
        1
    );
    let second = SqliteStore::open(&path).unwrap();

    const ROUNDS: usize = 50;
    let barrier = std::sync::Barrier::new(2);
    let run = |store: &SqliteStore| -> Vec<i64> {
        barrier.wait();
        (0..ROUNDS)
            .map(|round| {
                let renewed = OperationalStore::acquire_lease(store, "prod", "worker", far)
                    .expect("lease renewal");
                assert_eq!(renewed.generation, generation);
                let status = if round % 2 == 0 {
                    PlanStatus::Blocked
                } else {
                    PlanStatus::Running
                };
                store
                    .transition_plan("plan-1", "worker", generation, status, "")
                    .expect("plan transition");
                store
                    .reserve_provider_event_sequence("feedback", "event-1", "claimer")
                    .expect("sequence reservation")
            })
            .collect()
    };
    let (mut sequences, other) = std::thread::scope(|scope| {
        let a = scope.spawn(|| run(&first));
        let b = scope.spawn(|| run(&second));
        (a.join().unwrap(), b.join().unwrap())
    });
    sequences.extend(other);
    sequences.sort_unstable();
    let expected: Vec<i64> = (1..=(2 * ROUNDS) as i64).collect();
    assert_eq!(sequences, expected, "every reservation is unique");
    drop((first, second));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
