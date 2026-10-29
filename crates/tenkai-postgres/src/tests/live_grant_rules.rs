use std::sync::Arc;

use super::super::*;
use super::live_writer_lease::ScratchDatabase;

/// Stored grant rules (#836) on the hub-wide tables: two replicas'
/// connections share one generation and one rule per claim value. Each run
/// gets a database of its own, since the generation is hub-wide.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_grant_rules_follow_the_contract() {
    let scratch = ScratchDatabase::create();
    let config = PostgresTenantConfig::new(scratch.url.clone()).expect("scratch config");
    let a = Arc::new(config.open().expect("replica a"));
    let b = Arc::new(config.open().expect("replica b"));
    tenkai::grant_rules::assert_grant_rule_store_contract(a, b, "postgres");
}
