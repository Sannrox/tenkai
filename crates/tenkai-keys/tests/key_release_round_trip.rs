//! A release the ceremony writes parses through this crate, and every listed
//! data key unwraps through the provider the release names.

use std::net::TcpListener;

use sekai_keys::{Dek, KeyProvider, KeyPurpose, RuntimeProfile, TenantId, UnwrapGrant};
use tenkai_keys::kmip::{KmipKeyProvider, serve_lab_endpoint};
use tenkai_keys::pkcs11::{Pkcs11KeyProvider, TEST_USER_PIN, next_software_token};
use tenkai_keys::{
    CustomerKeyRelease, OpenError, ProviderAccess, ProviderEndpoint, ReleaseError, open_provider,
};

/// Parse the written JSON as a consumer would and unwrap every listed key.
fn unwrap_all(json: &str, access: ProviderAccess<'_>, expected: &Dek) {
    let release = CustomerKeyRelease::from_json(json).expect("consumer parses release");
    let provider = open_provider(&release, access).expect("open named provider");
    assert!(!release.data_keys.is_empty());
    for key in &release.data_keys {
        let wrapped = key.wrapped_dek().expect("decode data key");
        let grant = UnwrapGrant {
            tenant_id: wrapped.tenant_id.clone(),
            purpose: wrapped.purpose,
            expires_unix_secs: 10_000,
        };
        let outcome = provider
            .unwrap(&wrapped, &grant, "consumer", 1)
            .expect("data key unwraps");
        assert_eq!(outcome.dek.as_bytes(), expected.as_bytes());
    }
}

#[test]
fn pkcs11_ceremony_release_unwraps_through_the_named_token() {
    let Some((module, label)) = next_software_token() else {
        return;
    };
    let tenant = TenantId::new("acme").expect("tenant");
    let dek = Dek::generate();
    let endpoint = ProviderEndpoint {
        kind: "pkcs11".into(),
        token_label: label.clone(),
        module: Some(module.clone()),
    };
    let (deploy, rotate) = {
        let producer =
            Pkcs11KeyProvider::open(&module, &label, TEST_USER_PIN, RuntimeProfile::Production)
                .expect("producer opens token");
        let wrapped = producer
            .wrap(&tenant, KeyPurpose::Store, &dek)
            .expect("wrap");
        producer.rotate_kek().expect("rotate");
        let rotated = producer.rewrap(&wrapped, &dek).expect("rewrap");
        (
            CustomerKeyRelease::deploy(endpoint.clone(), &wrapped).expect("deploy"),
            CustomerKeyRelease::rotate(endpoint.clone(), &rotated).expect("rotate"),
        )
    };
    let access = ProviderAccess::Pkcs11 { pin: TEST_USER_PIN };
    for document in [&deploy, &rotate] {
        unwrap_all(&document.to_json().expect("json"), access, &dek);
    }

    let mismatch = ProviderAccess::Kmip {
        endpoint: "127.0.0.1:1".parse().expect("addr"),
    };
    let error = open_provider(&deploy, mismatch).expect_err("access for another kind");
    assert!(matches!(error, OpenError::AccessMismatch { .. }), "{error}");
}

#[test]
fn kmip_ceremony_release_unwraps_through_the_named_endpoint() {
    let endpoint = serve_lab_endpoint(TcpListener::bind("127.0.0.1:0").expect("bind"));
    let tenant = TenantId::new("acme").expect("tenant");
    let dek = Dek::generate();
    let wrapped = KmipKeyProvider::open(endpoint, RuntimeProfile::Production)
        .expect("producer opens endpoint")
        .wrap(&tenant, KeyPurpose::Store, &dek)
        .expect("wrap");
    let document = CustomerKeyRelease::deploy(
        ProviderEndpoint {
            kind: "kmip".into(),
            token_label: "lab".into(),
            module: None,
        },
        &wrapped,
    )
    .expect("deploy");
    unwrap_all(
        &document.to_json().expect("json"),
        ProviderAccess::Kmip { endpoint },
        &dek,
    );
}

#[test]
fn release_refuses_lab_only_providers_and_revoked_intent() {
    let endpoint = serve_lab_endpoint(TcpListener::bind("127.0.0.1:0").expect("bind"));
    let wrapped = KmipKeyProvider::open(endpoint, RuntimeProfile::Production)
        .expect("open")
        .wrap(
            &TenantId::new("acme").expect("tenant"),
            KeyPurpose::Store,
            &Dek::generate(),
        )
        .expect("wrap");
    let access = ProviderAccess::Kmip { endpoint };
    for kind in ["software", "file", "memory"] {
        let mut document = CustomerKeyRelease::deploy(
            ProviderEndpoint {
                kind: "kmip".into(),
                token_label: "lab".into(),
                module: None,
            },
            &wrapped,
        )
        .expect("deploy");
        document.provider.kind = kind.into();
        assert!(matches!(
            open_provider(&document, access),
            Err(OpenError::Release(ReleaseError::LabOnlyProvider(_)))
        ));
        let raw = serde_json::to_string(&document).expect("raw json");
        assert!(matches!(
            CustomerKeyRelease::from_json(&raw),
            Err(ReleaseError::LabOnlyProvider(_))
        ));
    }
    let revoked = CustomerKeyRelease::revoke(
        ProviderEndpoint {
            kind: "kmip".into(),
            token_label: "lab".into(),
            module: None,
        },
        &wrapped,
        wrapped.kek_id.as_str(),
    )
    .expect("revoke");
    assert!(matches!(
        open_provider(&revoked, access),
        Err(OpenError::Revoked)
    ));
}
