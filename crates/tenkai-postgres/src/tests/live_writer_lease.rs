use std::sync::Arc;

use tenkai::storage::{AuditRecord, OperationalStore, StoreError};
use tenkai::writer_fence::{WriterFence, WriterRole};

use super::super::*;

fn audit(id: &str) -> AuditRecord {
    AuditRecord {
        id: id.into(),
        occurred_at: 1,
        principal: "writer-lease-test".into(),
        operation: "test.write".into(),
        resource: "*".into(),
        outcome: "completed".into(),
    }
}

/// A database of its own for one run, dropped afterwards. The writer lease
/// is one hub-wide row, so two runs sharing a database would contend for it.
pub(super) struct ScratchDatabase {
    admin_url: String,
    name: String,
    pub(super) url: String,
}

impl ScratchDatabase {
    /// Created beside the database `TENKAI_POSTGRES_URL` names; needs
    /// `CREATEDB` there.
    pub(super) fn create() -> Self {
        let admin_url = PostgresTenantConfig::from_env()
            .expect("TENKAI_POSTGRES_URL")
            .url;
        let name = format!(
            "tenkai_lease_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let (base, query) = admin_url
            .split_once('?')
            .unwrap_or((admin_url.as_str(), ""));
        let prefix = &base[..base.rfind('/').expect("a database in the URL") + 1];
        let url = if query.is_empty() {
            format!("{prefix}{name}")
        } else {
            format!("{prefix}{name}?{query}")
        };
        postgres::Client::connect(&admin_url, postgres::NoTls)
            .expect("admin connection")
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .expect("create scratch database");
        Self {
            admin_url,
            name,
            url,
        }
    }
}

impl Drop for ScratchDatabase {
    fn drop(&mut self) {
        if let Ok(mut client) = postgres::Client::connect(&self.admin_url, postgres::NoTls) {
            let _ = client.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        }
    }
}

/// A replica: its own store connection, fenced on its own lease.
struct Replica {
    hub: PostgresTenantPartition,
    lease: PostgresHubWriterLease,
    fence: Arc<WriterFence>,
}

fn replica(config: &PostgresTenantConfig, holder: &str, ttl_ms: i64) -> Replica {
    let fence = Arc::new(WriterFence::default());
    let store = config.open().expect("connect");
    store.fence_writes(fence.clone()).expect("fence");
    Replica {
        hub: store.hub_partition().expect("hub"),
        lease: PostgresHubWriterLease::open(config, holder, ttl_ms, fence.clone()).expect("lease"),
        fence,
    }
}

/// Two hubs (#748): exactly one leads and writes; the standby cannot. After
/// the leader's lease lapses the standby takes over at the next generation,
/// and the old leader's write under the old generation is refused: first by
/// its own lapsed deadline, and inside the transaction when a stale view
/// still says leader. Each run gets a database of its own.
#[cfg(feature = "postgres")]
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_one_hub_leads_and_a_stale_generation_cannot_write_after_takeover() {
    let scratch = ScratchDatabase::create();
    let config = PostgresTenantConfig::new(scratch.url.clone()).expect("scratch config");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let holder_a = format!("hub-a-{suffix}");
    let a = replica(&config, &holder_a, 1_500);
    let b = replica(&config, &format!("hub-b-{suffix}"), 1_500);

    let WriterRole::Leader {
        generation: first, ..
    } = a.lease.renew().expect("a")
    else {
        panic!("the first replica to ask leads");
    };
    assert_eq!(b.lease.renew().expect("b"), WriterRole::Standby);
    a.hub
        .append_audit(&audit(&format!("a1-{suffix}")))
        .expect("the leader writes");
    assert!(matches!(
        b.hub.append_audit(&audit(&format!("b1-{suffix}"))),
        Err(StoreError::NotActiveWriter(_))
    ));
    // Renewing keeps the generation.
    assert_eq!(
        a.lease.renew().expect("renew"),
        WriterRole::Leader {
            holder: holder_a.clone(),
            generation: first
        }
    );

    // The leader stops renewing; once its lease lapses the standby leads.
    std::thread::sleep(std::time::Duration::from_millis(1_600));
    let WriterRole::Leader {
        generation: second, ..
    } = b.lease.renew().expect("takeover")
    else {
        panic!("the standby takes over a lapsed lease");
    };
    assert_eq!(second, first + 1);
    b.hub
        .append_audit(&audit(&format!("b2-{suffix}")))
        .expect("the new leader writes");
    // The old leader's local deadline has lapsed: refused before the database.
    assert!(!a.fence.is_leader());
    assert!(matches!(
        a.hub.append_audit(&audit(&format!("a2-{suffix}"))),
        Err(StoreError::NotActiveWriter(_))
    ));
    // A stale view that still says leader is refused inside the transaction.
    a.fence.set(WriterRole::Leader {
        holder: holder_a.clone(),
        generation: first,
    });
    let refused = a.hub.append_audit(&audit(&format!("a3-{suffix}")));
    assert!(
        matches!(&refused, Err(StoreError::NotActiveWriter(detail)) if detail.contains("superseded")),
        "{refused:?}"
    );
    assert_eq!(a.lease.renew().expect("a again"), WriterRole::Standby);

    // Stepping down hands over without waiting out the lease.
    b.lease.release().expect("release");
    assert!(matches!(
        a.lease.renew().expect("a leads"),
        WriterRole::Leader { generation, .. } if generation == second + 1
    ));
    // Dropped connections cost leadership only until they reconnect.
    postgres::Client::connect(&scratch.url, postgres::NoTls)
        .expect("admin connection")
        .batch_execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
             WHERE datname = current_database() AND pid <> pg_backend_pid()",
        )
        .expect("terminate");
    if a.lease.renew().is_err() {
        assert!(!a.fence.is_leader(), "a failed renewal is standby");
    }
    assert!(
        matches!(
            a.lease.renew().expect("reconnects"),
            WriterRole::Leader { .. }
        ),
        "the lease reconnects on the next renewal"
    );
    // So does the store: the write that finds its connection closed may
    // fail, and the next one runs on a fresh connection.
    let _ = a.hub.append_audit(&audit(&format!("a4-{suffix}")));
    a.hub
        .append_audit(&audit(&format!("a5-{suffix}")))
        .expect("the store reconnects");
    a.lease.release().expect("release");
    drop((a, b));
    drop(scratch);
}
