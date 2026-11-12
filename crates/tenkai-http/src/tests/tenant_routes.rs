//! Tenant-mode guard over every published HTTP route (#1224).
//!
//! Walks [`crate::contract::http_contract`] against a tenant-mode hub where
//! tenant A owns an environment, a release, and a channel. Tenant B calls
//! every route twice: once with its own identifiers and once with tenant A's.
//!
//! - No response may carry tenant A's identifiers to tenant B, other than
//!   one tenant B itself put in the request path.
//! - A route that succeeds for tenant B, with either set of identifiers,
//!   must be registered in
//!   [`tenkai::tenant_isolation::tenant_visible_rpcs`] or listed in
//!   [`TENANT_FREE_ROUTES`].
//!
//! A new route that serves tenant mode therefore fails here until someone
//! registers it and gives it isolation tests. Mutating routes are sent an
//! empty JSON object, so one that rejects the body before its tenant check
//! passes; the leak check still applies to its error text.

use super::auth_support::TenantAssertionExtension;
use super::support::FixedReconciler;
use super::*;

/// Routes that succeed in tenant mode and return only host or caller data:
/// health, OIDC discovery, the caller's own session, and host trust posture.
const TENANT_FREE_ROUTES: &[&str] = &[
    "GET /healthz",
    "GET /readyz",
    "GET /v1/auth/oidc",
    "GET /v1/auth/me",
    "GET /v1/trust",
];

/// Tenant A identifiers that must never appear in a response to tenant B.
const TENANT_A_MARKERS: &[&str] = &["env-a", "api-a", "api-a@1.0.0", "stable-a"];

const TENANT_B: &str =
    r#"{"tenant":"tenant-b","principal":"user-b","capabilities":["read","management","publish"]}"#;

#[tokio::test]
async fn tenant_mode_routes_are_registered_and_do_not_leak_across_tenants() {
    let app = tenant_hub();
    let registered: Vec<&str> = tenkai::tenant_isolation::tenant_visible_rpcs()
        .iter()
        .map(|rpc| rpc.path_template)
        .collect();
    let contract = crate::contract::http_contract();
    let routes = contract["routes"].as_array().expect("contract routes");

    let mut violations = Vec::new();
    for route in routes {
        let method = route["method"].as_str().unwrap();
        let template = route["path"].as_str().unwrap();
        let key = format!("{method} {template}");
        for (owner, ids) in [("own", OWN_IDS), ("cross", CROSS_IDS)] {
            let path = fill(template, ids);
            let (status, body) = call(&app, method, &path).await;
            let leaked = TENANT_A_MARKERS
                .iter()
                .find(|marker| body.contains(*marker) && !path.contains(*marker));
            if let Some(marker) = leaked {
                violations.push(format!("{key} ({owner}) leaks {marker}: {status} {body}"));
            }
            if status.is_success()
                && !registered.contains(&key.as_str())
                && !TENANT_FREE_ROUTES.contains(&key.as_str())
            {
                violations.push(format!(
                    "{key} ({owner}) serves tenant mode ({status}) but is not in tenant_visible_rpcs"
                ));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// Every registered HTTP template names a live route, so the registry cannot
/// keep entries for routes that were renamed or removed.
#[test]
fn registered_management_routes_exist_in_the_contract() {
    let contract = crate::contract::http_contract();
    let published: Vec<String> = contract["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| {
            format!(
                "{} {}",
                route["method"].as_str().unwrap(),
                route["path"].as_str().unwrap()
            )
        })
        .collect();
    for rpc in tenkai::tenant_isolation::tenant_visible_rpcs() {
        let Some((_, path)) = rpc.path_template.split_once(' ') else {
            continue;
        };
        // The pull runtime and development fixtures are outside the
        // published contract (see `contract.rs`); in-process surfaces have no
        // HTTP path at all.
        if !path.starts_with("/v1/")
            || path.starts_with("/v1/runtime/")
            || path.starts_with("/v1/development/")
        {
            continue;
        }
        assert!(
            published.iter().any(|route| route == rpc.path_template),
            "{} is registered for {} but is not a published route",
            rpc.id,
            rpc.path_template
        );
    }
}

/// Path parameters for tenant B's own resources.
const OWN_IDS: &[(&str, &str)] = &[
    ("environment", "env-b"),
    ("product", "api-b"),
    ("release", "api-b@1.0.0"),
    ("channel", "stable-b"),
];

/// Path parameters naming tenant A's resources.
const CROSS_IDS: &[(&str, &str)] = &[
    ("environment", "env-a"),
    ("product", "api-a"),
    ("release", "api-a@1.0.0"),
    ("channel", "stable-a"),
];

/// Replace `{param}` segments; parameters without a tenant owner get a
/// placeholder that names no resource.
fn fill(template: &str, ids: &[(&str, &str)]) -> String {
    template
        .split('/')
        .map(|segment| {
            let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
                return segment.to_string();
            };
            ids.iter()
                .find(|(param, _)| *param == name)
                .map_or_else(|| "none".to_string(), |(_, id)| (*id).to_string())
        })
        .collect::<Vec<_>>()
        .join("/")
}

async fn call(app: &Router, method: &str, path: &str) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-tenkai-assertion", TENANT_B);
    let body = if method == "GET" {
        Body::empty()
    } else {
        request = request.header("content-type", "application/json");
        Body::from("{}")
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A tenant-mode hub: tenant A owns `env-a` and the `api-a` release on
/// channel `stable-a`; tenant B owns only `env-b`.
fn tenant_hub() -> Router {
    use tenkai::ontology::{KIND_CHANNEL, KIND_RELEASE};
    use tenkai::pb::sekai::Object;
    use tenkai::runtime_capabilities::enterprise_auth_capabilities;
    use tenkai::storage::{CatalogGraph, EnvironmentRecord, MemoryCatalogGraph};
    use tenkai::tenant_store::tenant_memory_store_capabilities;

    let graph = Arc::new(MemoryCatalogGraph::new());
    let object = |id: &str, kind: &str, name: &str, properties: &[(&str, &str)]| Object {
        id: id.into(),
        kind: kind.into(),
        name: name.into(),
        properties: properties
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect(),
        ..Object::default()
    };
    graph
        .create(
            Some("tenant-a"),
            object(
                "tenkai:release:api-a@1.0.0",
                KIND_RELEASE,
                "api-a@1.0.0",
                &[
                    ("product", "api-a"),
                    ("version", "1.0.0"),
                    ("digest", "sha256:test"),
                ],
            ),
        )
        .unwrap();
    graph
        .create(
            Some("tenant-a"),
            object(
                "tenkai:channel:api-a/stable-a",
                KIND_CHANNEL,
                "stable-a",
                &[
                    ("product", "api-a"),
                    ("name", "stable-a"),
                    ("current_release", "tenkai:release:api-a@1.0.0"),
                ],
            ),
        )
        .unwrap();

    let tenant_store = Arc::new(tenkai::tenant_store::InMemoryTenantOperationalStore::new());
    for (tenant, environment) in [("tenant-a", "env-a"), ("tenant-b", "env-b")] {
        let context = TenantAssertionExtension
            .authenticate(
                &CredentialMaterial {
                    request_id: format!("seed-{tenant}"),
                    bearer_token: None,
                    assertion: Some(
                        format!(
                            r#"{{"tenant":"{tenant}","principal":"seed","capabilities":["read","management"]}}"#
                        )
                        .into_bytes(),
                    ),
                    peer_credentials: None,
                },
                &tenkai::auth_context::TenantDerivationAuthority::new("auth.enterprise"),
            )
            .unwrap();
        tenant_store
            .put_environment_for(
                &context,
                &EnvironmentRecord {
                    id: environment.into(),
                    revision: 0,
                    configuration_json: "{}".into(),
                },
            )
            .unwrap();
    }

    let mut config = ServerConfig::community("management-secret", HashMap::new());
    config.requirements.tenant_mode = true;
    config.requirements.require_enterprise_authentication = true;
    config.capabilities = tenkai::runtime_capabilities::ProvidedCapabilities::assemble(
        "enterprise-tenant-memory",
        [
            tenant_memory_store_capabilities(),
            enterprise_auth_capabilities(),
        ],
    );
    config.auth_host = AuthHostConfig {
        required_extension_id: Some("auth.enterprise".into()),
        expected_contract_version: tenkai::auth_context::AUTH_CONTEXT_CONTRACT_VERSION,
        expected_audience: Some("tenkai-server".into()),
    };
    config.enterprise_auth = Some(Arc::new(TenantAssertionExtension));
    config.tenant_store = Some(tenant_store);
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    router(
        config,
        Arc::new(FixedReconciler::with_ctx(
            tenkai::client::Ctx::tenant_hub_catalog(graph),
        )),
        store,
    )
    .unwrap()
}
