//! Stored-record compatibility for the Tenkai-owned record proto (#1582).
//!
//! Each golden payload was encoded by the previous release's generated types,
//! with every field set. Decoding it here must yield the same record, and
//! re-encoding that record must reproduce the bytes, so a store written by
//! either release reads back unchanged in the other.

use prost::Message;
use tenkai_wire::record::{
    Decision, Lease, Link, Object, ObjectChange, ObjectType, PropertyDef, StructFieldDef,
};

const OBJECT: &str = "0a1874656e6b61693a72656c656173653a6170693a312e322e33120752656c656173651a03617069220674656e6b61692a056578742d3732100a0776657273696f6e1205312e322e3338fbd095ffbc3140fbffffffffffffffff01";
const LINK: &str = "0a0d612d2d6465706c6f79732d2d621201611a016222076465706c6f7973282a";
const LEASE: &str = "0a0674656e6b61691210656e7669726f6e6d656e742f70726f6418ffffffffffffffffff01220766656e63652d372a08776f726b65722d31320661637469766538014002480350045a056c6f63616c";
const OBJECT_CHANGE: &str = "0a02633112026f311a1170726f706572746965732e7374617475732208636f6d70757465642a0772756e6e696e6732086f70657261746f723863";
const OBJECT_TYPE: &str = "0a0752656c65617365120772656c656173651a3e0a0473706563120673747275637418012201642a01783203456e763a01654208696e7465726e616c4a140a01661206737472696e671801220266642a017920012a084172746966616374";
const DECISION: &str = "0a02643110071a086f70657261746f722207617070726f76652a026f6b32110a04706c616e12097368613235363a61623a0274314207616c6c6f776564";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

/// Decode the previous release's bytes, compare, and re-encode to the same bytes.
fn assert_round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(
    golden: &str,
    expected: M,
) {
    let stored = bytes(golden);
    let decoded = M::decode(stored.as_slice()).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(decoded.encode_to_vec(), stored);
}

#[test]
fn records_written_by_the_previous_release_round_trip_unchanged() {
    assert_round_trip(
        OBJECT,
        Object {
            id: "tenkai:release:api:1.2.3".into(),
            kind: "Release".into(),
            name: "api".into(),
            namespace: "tenkai".into(),
            external_id: "ext-7".into(),
            properties: [("version".to_string(), "1.2.3".to_string())].into(),
            created: 1_700_000_000_123,
            updated: -5,
        },
    );
    assert_round_trip(
        LINK,
        Link {
            id: "a--deploys--b".into(),
            from_id: "a".into(),
            to_id: "b".into(),
            relation: "deploys".into(),
            created: 42,
        },
    );
    assert_round_trip(
        LEASE,
        Lease {
            namespace: "tenkai".into(),
            key: "environment/prod".into(),
            generation: u64::MAX,
            fencing_token: "fence-7".into(),
            owner: "worker-1".into(),
            status: "active".into(),
            acquired_at_ms: 1,
            refreshed_at_ms: 2,
            expires_at_ms: 3,
            released_at_ms: 4,
            site_id: "local".into(),
        },
    );
    assert_round_trip(
        OBJECT_CHANGE,
        ObjectChange {
            id: "c1".into(),
            object_id: "o1".into(),
            field: "properties.status".into(),
            old_value: "computed".into(),
            new_value: "running".into(),
            changed_by: "operator".into(),
            timestamp: 99,
        },
    );
    assert_round_trip(
        OBJECT_TYPE,
        ObjectType {
            kind: "Release".into(),
            description: "release".into(),
            is_builtin: true,
            implements: vec!["Artifact".into()],
            properties: vec![PropertyDef {
                name: "spec".into(),
                r#type: "struct".into(),
                required: true,
                description: "d".into(),
                enum_values: vec!["x".into()],
                link_kind: "Env".into(),
                compute_expr: "e".into(),
                classification: "internal".into(),
                struct_fields: vec![StructFieldDef {
                    name: "f".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "fd".into(),
                    enum_values: vec!["y".into()],
                }],
            }],
        },
    );
    assert_round_trip(
        DECISION,
        Decision {
            id: "d1".into(),
            timestamp: 7,
            actor: "operator".into(),
            action: "approve".into(),
            reason: "ok".into(),
            evidence: [("plan".to_string(), "sha256:ab".to_string())].into(),
            target_id: "t1".into(),
            outcome: "allowed".into(),
        },
    );
}
