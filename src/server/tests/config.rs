use super::*;

#[test]
fn rejects_credential_reuse_across_trust_scopes() {
    let config = ServerConfig::community("same", HashMap::from([("same".into(), "prod".into())]));
    assert!(config.validate().is_err());
}

#[test]
fn rejects_tenant_mode_without_tenant_isolation_capability() {
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.requirements.tenant_mode = true;
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("runtime capability negotiation failed"));
    assert!(error.contains("tenant_isolation"));
}

#[test]
fn rejects_tenant_mode_without_tenant_store_adapter() {
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.requirements.tenant_mode = true;
    config.capabilities = crate::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-tenant-memory",
        [
            crate::tenant_store::tenant_memory_store_capabilities(),
            community_auth_capabilities(),
        ],
    );
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("tenant-isolating operational store"),
        "{error}"
    );
}

#[test]
fn http_exposed_tenant_rpcs_are_subset_of_registry() {
    use crate::tenant_isolation::{http_exposed_tenant_rpc_ids, tenant_visible_rpcs};
    let registered: std::collections::BTreeSet<_> =
        tenant_visible_rpcs().iter().map(|rpc| rpc.id).collect();
    for id in http_exposed_tenant_rpc_ids() {
        assert!(
            registered.contains(id),
            "http-exposed rpc {id} must appear in tenant_visible_rpcs()"
        );
    }
    // Catalog/plan/aggregate registry entries stay non-HTTP until routes exist.
    assert!(!http_exposed_tenant_rpc_ids().contains(&"catalog.list_products"));
    assert!(!http_exposed_tenant_rpc_ids().contains(&"plan.list"));
    assert!(!http_exposed_tenant_rpc_ids().contains(&"aggregate.audit_list"));
    assert!(http_exposed_tenant_rpc_ids().contains(&"runtime.inventory"));
}

#[test]
fn rejects_multi_replica_without_shared_replica_capability() {
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.requirements.replica_count = 2;
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("shared_replica_state"));
}

#[test]
fn enterprise_auth_required_fails_closed_without_extension() {
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.requirements.require_enterprise_authentication = true;
    config.capabilities =
        community_sqlite_profile(crate::runtime_capabilities::enterprise_auth_capabilities());
    config.auth_host.required_extension_id = Some("auth.enterprise".into());
    // Capability claim is present, but no extension is wired — AuthStack
    // composition must still fail before accepting traffic.
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("auth stack composition failed")
            || error.contains("required auth extension"),
        "{error}"
    );
    assert!(!error.contains("management-secret"));
}

#[test]
fn remote_client_requires_tls_except_on_loopback() {
    assert!(RemoteClient::new("https://tenkai.example.test", "secret").is_ok());
    assert!(RemoteClient::new("http://127.0.0.1:8080", "secret").is_ok());
    assert!(RemoteClient::new("http://[::1]:8080", "secret").is_ok());
    assert!(RemoteClient::new("http://tenkai.example.test", "secret").is_err());
}
