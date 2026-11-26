//! Tenant-mode guard over every published HTTP route (#1224).
//!
//! Walks [`crate::contract::http_contract`] against a tenant-mode hub where
//! tenant A owns an environment, a release, and a channel. Tenant B calls
//! every route twice: once with its own identifiers and once with tenant A's.
//! Registered routes that name a tenant resource get a third call with
//! identifiers no tenant owns.
//!
//! - No response may carry tenant A's identifiers to tenant B, other than
//!   one tenant B itself put in the request path.
//! - A route that succeeds for tenant B, with either set of identifiers,
//!   must be registered in
//!   [`tenkai::tenant_isolation::tenant_visible_rpcs`] or listed in
//!   [`TENANT_FREE_ROUTES`].
//! - A registered route that names a tenant A resource must answer tenant B
//!   exactly as it answers for a resource that exists nowhere ([`ABSENT_IDS`]),
//!   so tenant A's records are indistinguishable from missing ones. Registered
//!   mutating routes get a valid body from [`SAMPLE_BODIES`] in both passes, so
//!   the tenant check, not body validation, decides the answer.
//! - Tenant A reads the same state before and after the walk.
//!
//! A new route that serves tenant mode therefore fails here until someone
//! registers it and gives it isolation tests.

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

const TENANT_A: &str =
    r#"{"tenant":"tenant-a","principal":"user-a","capabilities":["read","management"]}"#;

const TENANT_B: &str =
    r#"{"tenant":"tenant-b","principal":"user-b","capabilities":["read","management","publish"]}"#;

/// Valid request bodies for registered mutating routes that name a tenant
/// resource. Every such route needs an entry; the walk fails without one.
const SAMPLE_BODIES: &[(&str, &str)] = &[(
    "POST /v1/environments/{environment}/retire",
    r#"{"version":1,"operation":"retire","reason":"tenant route guard"}"#,
)];

/// Tenant A's own view, compared before and after the walk.
const TENANT_A_READS: &[&str] = &[
    "/v1/environments",
    "/v1/environments/env-a",
    "/v1/releases",
    "/v1/channels",
];

#[tokio::test]
async fn tenant_mode_routes_are_registered_and_do_not_leak_across_tenants() {
    let app = tenant_hub();
    let registered: Vec<&str> = tenkai::tenant_isolation::tenant_visible_rpcs()
        .iter()
        .map(|rpc| rpc.path_template)
        .collect();
    let contract = crate::contract::http_contract();
    let routes = contract["routes"].as_array().expect("contract routes");

    let tenant_a_before = tenant_a_view(&app).await;
    let mut violations = Vec::new();
    for route in routes {
        let method = route["method"].as_str().unwrap();
        let template = route["path"].as_str().unwrap();
        let key = format!("{method} {template}");
        let is_registered = registered.contains(&key.as_str());
        let names_tenant_a = CROSS_IDS
            .iter()
            .any(|(param, _)| template.contains(&format!("{{{param}}}")));
        let must_hide =
            is_registered && names_tenant_a && !TENANT_FREE_ROUTES.contains(&key.as_str());
        let mut responses = Vec::new();
        for (owner, ids) in [
            ("own", OWN_IDS),
            ("cross", CROSS_IDS),
            ("absent", ABSENT_IDS),
        ] {
            if owner == "absent" && !must_hide {
                continue;
            }
            let path = fill(template, ids);
            // The own pass keeps the empty body: a valid one would change
            // tenant B's state under the routes walked after it.
            let body = match (method, owner) {
                ("GET", _) => None,
                (_, "cross" | "absent") if must_hide => {
                    let Some((_, sample)) = SAMPLE_BODIES.iter().find(|(route, _)| *route == key)
                    else {
                        violations.push(format!("{key} has no valid body in SAMPLE_BODIES"));
                        continue;
                    };
                    Some(*sample)
                }
                _ => Some("{}"),
            };
            let (status, body) = call(&app, TENANT_B, method, &path, body).await;
            let leaked = TENANT_A_MARKERS
                .iter()
                .find(|marker| body.contains(*marker) && !path.contains(*marker));
            if let Some(marker) = leaked {
                violations.push(format!("{key} ({owner}) leaks {marker}: {status} {body}"));
            }
            if status.is_success() && !is_registered && !TENANT_FREE_ROUTES.contains(&key.as_str())
            {
                violations.push(format!(
                    "{key} ({owner}) serves tenant mode ({status}) but is not in tenant_visible_rpcs"
                ));
            }
            responses.push((status, body));
        }
        // A path echo is not a leak, so compare the cross answer with the
        // absent one after swapping tenant A's identifiers for absent ones.
        if let [_, (cross_status, cross_body), absent] = responses.as_slice() {
            let cross_body = CROSS_IDS
                .iter()
                .zip(ABSENT_IDS)
                .fold(cross_body.clone(), |body, ((_, cross), (_, absent))| {
                    body.replace(cross, absent)
                });
            if (*cross_status, cross_body.clone()) != *absent {
                violations.push(format!(
                    "{key} tells tenant A's resource from a missing one: \
                     {cross_status} {cross_body} vs {} {}",
                    absent.0, absent.1
                ));
            }
        }
    }
    if tenant_a_view(&app).await != tenant_a_before {
        violations.push("tenant A state changed during the walk".into());
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// What tenant A reads on [`TENANT_A_READS`], each entry as status and body.
async fn tenant_a_view(app: &Router) -> Vec<(StatusCode, String)> {
    let mut view = Vec::new();
    for path in TENANT_A_READS {
        let response = call(app, TENANT_A, "GET", path, None).await;
        assert!(
            response.0.is_success(),
            "tenant A read {path}: {response:?}"
        );
        view.push(response);
    }
    view
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

/// Path parameters naming resources no tenant owns.
const ABSENT_IDS: &[(&str, &str)] = &[
    ("environment", "env-z"),
    ("product", "api-z"),
    ("release", "api-z@1.0.0"),
    ("channel", "stable-z"),
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

/// Call `path` as `assertion`, with `body` as JSON when one is given.
async fn call(
    app: &Router,
    assertion: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-tenkai-assertion", assertion);
    let body = match body {
        None => Body::empty(),
        Some(json) => {
            request = request.header("content-type", "application/json");
            Body::from(json.to_owned())
        }
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
    use tenkai::pb::record::Object;
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
    let store = Arc::new(tenkai_sqlite::SqliteStore::open_in_memory().unwrap());
    router(
        config,
        Arc::new(FixedReconciler::with_ctx(
            tenkai::client::Ctx::tenant_hub_catalog(graph),
        )),
        store,
    )
    .unwrap()
}
