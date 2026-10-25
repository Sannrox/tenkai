//! Isolated-network directory bridge (#637).
//!
//! Tenkai never binds to a customer directory or handles directory passwords.
//! A site-local OIDC issuer maps directory groups through `[grants]`. Login
//! and JWKS load use a static file or loopback; a directory or issuer outage
//! fails closed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::auth_context::EnterpriseAuthExtension;

use super::{
    CredentialMaterial, DeliveryCapability, ISSUER, JwksCache, OIDC_AUTH_EXTENSION_ID,
    OidcAuthExtension, Signer, TenantDerivationAuthority, authenticate, config, far_future, jwks,
    key_source,
};

struct SiteDirectory {
    groups_by_user: BTreeMap<String, Vec<String>>,
    available: bool,
}

impl SiteDirectory {
    fn login(&self, signer: &Signer, user: &str) -> Result<Vec<u8>, &'static str> {
        if !self.available {
            return Err("directory unavailable");
        }
        let groups = self
            .groups_by_user
            .get(user)
            .ok_or("unknown directory user")?;
        let mut claims = far_future(serde_json::json!(groups));
        claims["sub"] = serde_json::json!(user);
        Ok(signer.sign(&claims))
    }
}

fn unique_temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tenkai-oidc-bridge-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn jwks_file_extension(signer: &Signer, dir: &Path) -> OidcAuthExtension {
    let jwks_path = dir.join("jwks.json");
    std::fs::write(&jwks_path, jwks(&[signer])).unwrap();
    let mut cfg = config("");
    cfg.jwks_file = Some(jwks_path);
    let source = key_source(&cfg).unwrap();
    let cache = JwksCache::load(source).unwrap();
    OidcAuthExtension::new(cfg, Arc::new(cache), None, false).unwrap()
}

#[test]
fn jwks_file_login_maps_directory_groups_without_network() {
    let dir = unique_temp_dir();
    let signer = Signer::new("k1");
    let ext = jwks_file_extension(&signer, &dir);
    let directory = SiteDirectory {
        groups_by_user: BTreeMap::from([(
            "alice".into(),
            vec!["tenkai-admins".into(), "ops".into()],
        )]),
        available: true,
    };

    let token = directory.login(&signer, "alice").expect("directory login");
    let context = authenticate(&ext, token).unwrap();
    assert_eq!(context.principal_id(), format!("alice@{ISSUER}"));
    assert!(context.has_delivery_capability(DeliveryCapability::Management));
    assert!(context.has_delivery_capability(DeliveryCapability::Read));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_outage_refuses_login_and_unauthenticated_calls() {
    let dir = unique_temp_dir();
    let signer = Signer::new("k1");
    let ext = jwks_file_extension(&signer, &dir);
    let mut directory = SiteDirectory {
        groups_by_user: BTreeMap::from([("alice".into(), vec!["tenkai-admins".into()])]),
        available: true,
    };
    let token = directory.login(&signer, "alice").unwrap();
    assert!(
        authenticate(&ext, token)
            .unwrap()
            .has_delivery_capability(DeliveryCapability::Management)
    );

    directory.available = false;
    assert_eq!(
        directory.login(&signer, "alice").unwrap_err(),
        "directory unavailable"
    );
    let error = ext
        .authenticate(
            &CredentialMaterial {
                request_id: "req-1".into(),
                bearer_token: None,
                assertion: None,
            },
            &TenantDerivationAuthority::new(OIDC_AUTH_EXTENSION_ID),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("bearer token or assertion"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn loopback_idp_and_missing_jwks_file_fail_closed() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut discovery = config("");
    discovery.issuer = format!("http://127.0.0.1:{port}/realms/ops");
    match key_source(&discovery) {
        Err(error) => assert!(
            error.to_string().contains("fetching"),
            "directory issuer outage must fail closed: {error}"
        ),
        Ok(_) => panic!("loopback issuer outage must fail closed"),
    }

    let dir = unique_temp_dir();
    let mut missing = config("");
    missing.jwks_file = Some(dir.join("missing.json"));
    let source = key_source(&missing).expect("file key source is constructed before read");
    match JwksCache::load(source) {
        Err(error) => assert!(
            error.to_string().contains("failed to read JWKS file"),
            "{error}"
        ),
        Ok(_) => panic!("missing JWKS file must fail closed"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}
