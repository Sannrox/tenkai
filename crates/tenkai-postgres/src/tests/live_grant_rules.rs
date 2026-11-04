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
    let raw = std::sync::Mutex::new(
        postgres::Client::connect(&scratch.url, postgres::NoTls).expect("raw connection"),
    );
    let put_row = |value: &str, row: &str| {
        let mut raw = raw.lock().unwrap();
        let mut tx = raw.transaction().unwrap();
        tx.execute(
            "INSERT INTO public.tenkai_grant_rules(value, rule_json) VALUES ($1, $2)",
            &[&value, &row],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO public.tenkai_grant_rule_generation(id, generation) VALUES (1, 1)
             ON CONFLICT (id) DO UPDATE
             SET generation = tenkai_grant_rule_generation.generation + 1",
            &[],
        )
        .unwrap();
        tx.commit().unwrap();
    };
    tenkai::grant_rules::assert_grant_rule_store_contract(a, b, "postgres", &put_row);
}
