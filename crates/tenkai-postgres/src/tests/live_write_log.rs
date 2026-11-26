use super::super::*;
use tenkai::storage::write_log_contract::assert_write_log;

/// #1569: the Postgres catalog logs every write for change-driven ticks.
/// Requires feature `postgres` and `TENKAI_POSTGRES_URL`.
#[test]
#[ignore = "requires Postgres; set TENKAI_POSTGRES_URL and cargo test --features postgres -- --ignored"]
fn live_write_log_records_every_write() {
    let config = PostgresTenantConfig::from_env().expect("TENKAI_POSTGRES_URL");
    let tenants = super::LiveTenants::new(&config);
    let store = config.open().expect("connect");
    let tenant = tenants.tenant("writelog");
    assert_write_log(&store, Some(tenant.as_str()));
}
