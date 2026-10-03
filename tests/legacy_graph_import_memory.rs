//! Opening a large pre-0.3 graph store must not load it into memory (#498).
//!
//! The legacy import used to read every `embedded_*` row into memory before
//! `tenkai-server` bound its listener, so a multi-GiB store exhausted memory
//! and the server never became ready. This binary runs alone, so the process
//! peak RSS (`VmHWM`) isolates the cost of the import.

#[cfg(target_os = "linux")]
#[test]
fn opening_a_large_legacy_graph_store_keeps_memory_flat() {
    use tenkai::embedded::EmbeddedStore;
    use tenkai::ontology::{KIND_ENVIRONMENT, NS, env_id};
    use tenkai::storage::SqliteStore;

    const OBJECTS: usize = 640;
    const PAYLOAD: usize = 256 * 1024;
    const BUDGET_MIB: u64 = 96;

    fn peak_rss_mib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
            .expect("VmHWM")
            / 1024
    }

    let path = std::env::temp_dir().join(format!("tenkai-498-legacy-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let graph = EmbeddedStore::open(&path, "tenkai".into()).unwrap();
        for index in 0..OBJECTS {
            let name = format!("env-{index}");
            graph
                .put(tenkai::pb::sekai::Object {
                    id: env_id(&name),
                    kind: KIND_ENVIRONMENT.into(),
                    namespace: NS.into(),
                    properties: [("facts.inventory".into(), "x".repeat(PAYLOAD))]
                        .into_iter()
                        .collect(),
                    name,
                    created: 1,
                    updated: 1,
                    ..Default::default()
                })
                .unwrap();
        }
    }
    let legacy_mib = std::fs::metadata(&path).unwrap().len() / (1024 * 1024);

    let before = peak_rss_mib();
    let store = SqliteStore::open(&path).unwrap();
    let growth = peak_rss_mib().saturating_sub(before);
    drop(store);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }

    assert!(
        legacy_mib > 3 * BUDGET_MIB,
        "fixture too small to tell streaming from loading: {legacy_mib} MiB"
    );
    assert!(
        growth < BUDGET_MIB,
        "opening a {legacy_mib} MiB legacy store raised peak RSS by {growth} MiB (budget {BUDGET_MIB} MiB)"
    );
}
