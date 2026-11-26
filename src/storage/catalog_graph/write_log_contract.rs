//! Store write-log contract (#1569), shared by the memory, SQLite, and
//! Postgres catalog tests: every create, put, delete, link, and unlink leaves
//! rows the reconciler can map to environments, and sequences keep rising
//! across a prune.

use std::collections::BTreeSet;

use crate::pb::record::{Link, Object};
use crate::storage::CatalogGraph;

const KIND: &str = "tenkai.conformance";

/// `(object_id, kind)` pairs logged after `after`, and the highest sequence.
fn logged(
    graph: &dyn CatalogGraph,
    tenant: Option<&str>,
    after: i64,
) -> (BTreeSet<(String, String)>, i64) {
    let rows = graph.writes_after(tenant, after, 1_000).unwrap();
    let high = rows.last().map_or(after, |row| row.seq);
    assert!(
        rows.windows(2).all(|pair| pair[0].seq < pair[1].seq),
        "rows come back in sequence order"
    );
    let pairs = rows
        .into_iter()
        .map(|row| (row.object_id, row.kind))
        .collect();
    (pairs, high)
}

fn pairs(rows: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    rows.iter()
        .map(|(id, kind)| ((*id).into(), (*kind).into()))
        .collect()
}

/// Assert the write-log contract on `graph` for `tenant`, starting from any state.
pub fn assert_write_log(graph: &dyn CatalogGraph, tenant: Option<&str>) {
    let id = "tenkai:conformance:logged";
    let other = "tenkai:conformance:logged-other";
    let object = Object {
        id: id.into(),
        kind: KIND.into(),
        name: "logged".into(),
        properties: [("environment".into(), "lab".into())].into_iter().collect(),
        ..Object::default()
    };
    let start = graph.latest_write(tenant).unwrap();

    graph.create(tenant, object.clone()).unwrap();
    let (rows, high) = logged(graph, tenant, start);
    assert_eq!(rows, pairs(&[(id, KIND)]), "create");
    assert_eq!(graph.latest_write(tenant).unwrap(), high);

    let mut changed = object.clone();
    changed.properties.insert("status".into(), "ready".into());
    graph.put(tenant, changed).unwrap();
    let (rows, high) = logged(graph, tenant, high);
    assert_eq!(rows, pairs(&[(id, KIND)]), "put");

    let link = Link {
        id: format!("{id}--uses--{other}"),
        from_id: id.into(),
        to_id: other.into(),
        relation: "uses".into(),
        created: 1,
    };
    graph.create_link(tenant, link.clone(), true).unwrap();
    let (rows, high) = logged(graph, tenant, high);
    // An endpoint the store does not hold is logged without a kind.
    assert_eq!(rows, pairs(&[(id, KIND), (other, "")]), "link");

    graph.unlink(tenant, &link.id).unwrap();
    let (rows, high) = logged(graph, tenant, high);
    assert_eq!(rows, pairs(&[(id, KIND), (other, "")]), "unlink");

    graph.delete(tenant, id).unwrap();
    let (rows, high) = logged(graph, tenant, high);
    assert_eq!(rows, pairs(&[(id, KIND)]), "delete logs the kind it had");

    // Pruning everything keeps sequences rising, so a cursor never rereads
    // or skips.
    graph
        .prune_writes(tenant, crate::now_millis().saturating_add(1))
        .unwrap();
    assert!(logged(graph, tenant, start).0.is_empty(), "pruned");
    graph.create(tenant, object).unwrap();
    let rows = graph.writes_after(tenant, high, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].seq > high, "sequence rises across a prune");
    graph.delete(tenant, id).unwrap();
}
