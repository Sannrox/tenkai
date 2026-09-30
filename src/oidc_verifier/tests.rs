use super::test_support::{Signer, b64, jwks};
use super::*;

const ISSUER: &str = "https://idp.example.test/realms/ops";
const AUDIENCE: &str = "tenkai";
const NOW: i64 = 1_800_000_000;

// RFC 7515 Appendix A.2: RS256 JWS and its public key (published test vector).
const RFC7515_A2_JWS: &str = concat!(
    "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODA",
    "sDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Ee",
    "tdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Q",
    "c_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--",
    "f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN",
    "9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6I",
    "eYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypG",
    "lUPQGe77Rw",
);
const RFC7515_A2_N: &str = concat!(
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp",
    "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW",
    "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs",
    "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k",
    "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2",
    "PAcDTW9gb54h4FRWyuXpoQ",
);

fn claims(groups: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER, "sub": "user-1", "aud": [AUDIENCE, "account"],
        "exp": NOW + 300, "nbf": NOW - 10, "groups": groups,
    })
}

fn config(extra: &str) -> OidcConfig {
    toml::from_str(&format!(
        r#"
issuer = "{ISSUER}"
audience = "{AUDIENCE}"
{extra}
[grants]
claim = "groups"
tenant_claim = "tenant"
[[grants.rules]]
value = "tenkai-admins"
capabilities = ["read", "management"]
[[grants.rules]]
value = "tenkai-viewers"
capabilities = ["read"]
[[grants.rules]]
value = "prod-operators"
capabilities = ["management"]
environment = "prod"
[[grants.rules]]
value = "stage-operators"
capabilities = ["management"]
environment = "stage"
"#
    ))
    .unwrap()
}

fn static_source(raw: String) -> Arc<dyn KeySource> {
    Arc::new(move || Ok(raw.clone()))
}

fn extension(signers: &[&Signer], require_tenant: bool) -> OidcAuthExtension {
    let cache = JwksCache::with_min_interval(static_source(jwks(signers)), Duration::ZERO).unwrap();
    OidcAuthExtension::new(config(""), Arc::new(cache), None, require_tenant).unwrap()
}

fn authenticate(
    ext: &OidcAuthExtension,
    token: Vec<u8>,
) -> Result<AuthenticatedRequestContext, AuthError> {
    ext.authenticate(
        &CredentialMaterial {
            request_id: "req-1".into(),
            bearer_token: None,
            assertion: Some(token),
        },
        &TenantDerivationAuthority::new(OIDC_AUTH_EXTENSION_ID),
    )
}

fn far_future(groups: serde_json::Value) -> serde_json::Value {
    let mut claims = claims(groups);
    claims["exp"] = serde_json::json!(now_unix_secs() + 300);
    claims["nbf"] = serde_json::json!(now_unix_secs() - 10);
    claims
}

#[test]
fn rfc7515_rs256_vector_verifies_and_rejects_tampering() {
    let key = PublicKey::Rsa {
        n: b64url_decode(RFC7515_A2_N).unwrap(),
        e: b64url_decode("AQAB").unwrap(),
    };
    let (input, signature) = RFC7515_A2_JWS.rsplit_once('.').unwrap();
    let signature = b64url_decode(signature).unwrap();
    key.verify(input.as_bytes(), &signature).unwrap();
    let mut tampered = input.as_bytes().to_vec();
    tampered[0] ^= 1;
    assert!(key.verify(&tampered, &signature).is_err());
}

#[test]
fn groups_map_to_fleet_grants() {
    let signer = Signer::new("k1");
    let ext = extension(&[&signer], false);
    let context = authenticate(
        &ext,
        signer.sign(&far_future(serde_json::json!(["tenkai-admins"]))),
    )
    .unwrap();
    assert_eq!(context.principal_id(), format!("user-1@{ISSUER}"));
    assert!(context.has_delivery_capability(DeliveryCapability::Management));
    assert_eq!(context.environment_binding(), None);

    let viewer = authenticate(
        &ext,
        signer.sign(&far_future(serde_json::json!("tenkai-viewers"))),
    )
    .unwrap();
    assert!(viewer.has_delivery_capability(DeliveryCapability::Read));
    assert!(!viewer.has_delivery_capability(DeliveryCapability::Management));
}

#[test]
fn unmapped_groups_grant_nothing() {
    let signer = Signer::new("k1");
    let ext = extension(&[&signer], false);
    for groups in [
        serde_json::json!(["unknown"]),
        serde_json::json!(42),
        serde_json::Value::Null,
    ] {
        let context = authenticate(&ext, signer.sign(&far_future(groups))).unwrap();
        assert!(context.delivery_capabilities().is_empty());
    }
}

#[test]
fn environment_rules_bind_management_to_one_environment() {
    let signer = Signer::new("k1");
    let ext = extension(&[&signer], false);
    let scoped = authenticate(
        &ext,
        signer.sign(&far_future(serde_json::json!([
            "prod-operators",
            "tenkai-viewers"
        ]))),
    )
    .unwrap();
    assert_eq!(scoped.environment_binding(), Some("prod"));
    assert!(scoped.has_delivery_capability(DeliveryCapability::Management));

    let admin = authenticate(
        &ext,
        signer.sign(&far_future(serde_json::json!([
            "prod-operators",
            "tenkai-admins"
        ]))),
    )
    .unwrap();
    assert_eq!(
        admin.environment_binding(),
        None,
        "fleet management is not narrowed"
    );

    let error = authenticate(
        &ext,
        signer.sign(&far_future(serde_json::json!([
            "prod-operators",
            "stage-operators"
        ]))),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("more than one environment"),
        "{error}"
    );
}

#[test]
fn claim_checks_fail_closed() {
    let signer = Signer::new("k1");
    let ext = extension(&[&signer], false);
    let groups = serde_json::json!(["tenkai-admins"]);
    assert!(
        ext.verify(&signer.sign(&claims(groups.clone())), NOW)
            .is_ok()
    );
    let cases: [(&str, serde_json::Value); 6] = [
        ("iss", serde_json::json!("https://other.example.test")),
        ("aud", serde_json::json!("someone-else")),
        ("aud", serde_json::json!(["account"])),
        ("exp", serde_json::json!(NOW - 3600)),
        ("nbf", serde_json::json!(NOW + 3600)),
        ("sub", serde_json::json!(" ")),
    ];
    for (claim, value) in cases {
        let mut claims = claims(groups.clone());
        claims[claim] = value;
        assert!(
            ext.verify(&signer.sign(&claims), NOW).is_err(),
            "{claim} must fail"
        );
    }
    let mut single_audience = claims(groups);
    single_audience["aud"] = serde_json::json!(AUDIENCE);
    assert!(ext.verify(&signer.sign(&single_audience), NOW).is_ok());
}

#[test]
fn only_configured_asymmetric_algorithms_are_accepted() {
    let signer = Signer::new("k1");
    let ext = extension(&[&signer], false);
    let body = claims(serde_json::json!(["tenkai-admins"]));
    for alg in ["none", "HS256", "RS256", "EdDSA"] {
        let token = signer.sign_with_header(serde_json::json!({"alg": alg, "kid": "k1"}), &body);
        assert!(ext.verify(&token, NOW).is_err(), "{alg} must fail");
    }
    let unsigned = format!(
        "{}.{}.",
        b64(br#"{"alg":"none","kid":"k1"}"#),
        b64(body.to_string().as_bytes())
    );
    assert!(ext.verify(unsigned.as_bytes(), NOW).is_err());
    let no_kid = signer.sign_with_header(serde_json::json!({"alg": "ES256"}), &body);
    assert!(ext.verify(&no_kid, NOW).is_err());
}

#[test]
fn tampered_payload_and_foreign_keys_are_refused() {
    let signer = Signer::new("k1");
    let impostor = Signer::new("k1");
    let ext = extension(&[&signer], false);
    let body = claims(serde_json::json!(["tenkai-viewers"]));
    assert!(ext.verify(&impostor.sign(&body), NOW).is_err());
    let token = String::from_utf8(signer.sign(&body)).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let mut escalated = body;
    escalated["groups"] = serde_json::json!(["tenkai-admins"]);
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        b64(escalated.to_string().as_bytes()),
        parts[2]
    );
    assert!(ext.verify(forged.as_bytes(), NOW).is_err());
}

#[test]
fn unknown_kid_signals_refresh_and_rotation_succeeds_after_it() {
    let old = Signer::new("old");
    let new = Signer::new("new");
    let current = Arc::new(Mutex::new(jwks(&[&old])));
    let source_state = current.clone();
    let source: Arc<dyn KeySource> = Arc::new(move || Ok(source_state.lock().unwrap().clone()));
    let cache = Arc::new(JwksCache::with_min_interval(source, Duration::ZERO).unwrap());
    let (refresh, signals) = mpsc::sync_channel(1);
    let ext = OidcAuthExtension::new(config(""), cache.clone(), Some(refresh), false).unwrap();
    let body = claims(serde_json::json!(["tenkai-admins"]));

    assert!(ext.verify(&new.sign(&body), NOW).is_err());
    assert!(signals.try_recv().is_ok(), "unknown kid requests a refresh");

    *current.lock().unwrap() = jwks(&[&old, &new]);
    cache.refresh().unwrap();
    assert!(ext.verify(&new.sign(&body), NOW).is_ok());
    assert!(ext.verify(&old.sign(&body), NOW).is_ok());
}

#[test]
fn unreachable_keys_fail_closed_and_refresh_failure_keeps_old_keys() {
    let unreachable: Arc<dyn KeySource> =
        Arc::new(|| Err(AuthError::InvalidCredential("connection refused".into())));
    assert!(JwksCache::load(unreachable).is_err());

    let signer = Signer::new("k1");
    let fail = Arc::new(Mutex::new(false));
    let fail_state = fail.clone();
    let raw = jwks(&[&signer]);
    let source: Arc<dyn KeySource> = Arc::new(move || {
        if *fail_state.lock().unwrap() {
            Err(AuthError::InvalidCredential("provider down".into()))
        } else {
            Ok(raw.clone())
        }
    });
    let cache = Arc::new(JwksCache::with_min_interval(source, Duration::ZERO).unwrap());
    *fail.lock().unwrap() = true;
    assert!(cache.refresh().is_err());
    let ext = OidcAuthExtension::new(config(""), cache, None, false).unwrap();
    assert!(
        ext.verify(
            &signer.sign(&claims(serde_json::json!(["tenkai-admins"]))),
            NOW
        )
        .is_ok()
    );
}

#[test]
fn refresh_is_rate_limited() {
    let fetches = Arc::new(Mutex::new(0));
    let counter = fetches.clone();
    let raw = jwks(&[&Signer::new("k1")]);
    let source: Arc<dyn KeySource> = Arc::new(move || {
        *counter.lock().unwrap() += 1;
        Ok(raw.clone())
    });
    let cache = JwksCache::load(source).unwrap();
    cache.refresh().unwrap();
    cache.refresh().unwrap();
    assert_eq!(
        *fetches.lock().unwrap(),
        1,
        "refetches within the interval are skipped"
    );
}

#[test]
fn tenant_claim_is_required_on_tenant_hosts() {
    let signer = Signer::new("k1");
    let ext = extension(&[&signer], true);
    let mut with_tenant = far_future(serde_json::json!(["tenkai-admins"]));
    with_tenant["tenant"] = serde_json::json!("tenant-a");
    let context = authenticate(&ext, signer.sign(&with_tenant)).unwrap();
    assert_eq!(
        context.tenant().map(|tenant| tenant.tenant_id()),
        Some("tenant-a")
    );
    assert!(
        authenticate(
            &ext,
            signer.sign(&far_future(serde_json::json!(["tenkai-admins"])))
        )
        .is_err()
    );
}

#[test]
fn config_validation_fails_closed() {
    assert!(config("").validate().is_ok());
    for extra in [
        r#"jwks_uri = "http://idp.example.test/jwks""#,
        "jwks_uri = \"https://idp.example.test/jwks\"\njwks_file = \"/etc/jwks.json\"",
        r#"algorithms = ["HS256"]"#,
        r#"algorithms = []"#,
        "clock_skew_secs = 3600",
        "jwks_refresh_secs = 5",
    ] {
        assert!(config(extra).validate().is_err(), "{extra} must fail");
    }
    let mut insecure = config("");
    insecure.issuer = "http://idp.example.test".into();
    assert!(insecure.validate().is_err());
    let mut local = config("");
    local.issuer = "http://127.0.0.1:8081/realms/dev".into();
    assert!(
        local.validate().is_ok(),
        "loopback http is allowed for development"
    );
    let mut no_rules = config("");
    no_rules.grants.rules.clear();
    assert!(no_rules.validate().is_err());
    assert!(toml::from_str::<OidcConfig>("issuer = \"x\"\naudience = \"y\"\nclient_secret = \"s\"\n[grants]\nclaim = \"g\"\nrules = []").is_err());
}

#[test]
fn jwks_skips_unusable_keys() {
    let signer = Signer::new("k1");
    let mut doc: serde_json::Value = serde_json::from_str(&jwks(&[&signer])).unwrap();
    doc["keys"].as_array_mut().unwrap().extend([
        serde_json::json!({"kty": "oct", "kid": "sym", "k": "c2VjcmV0"}),
        serde_json::json!({"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"}),
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}),
    ]);
    let keys = KeySet::from_jwks_json(&doc.to_string()).unwrap();
    assert!(keys.get("k1").is_some());
    assert!(keys.get("sym").is_none() && keys.get("enc").is_none());
    assert!(KeySet::from_jwks_json(r#"{"keys":[]}"#).is_err());
}
