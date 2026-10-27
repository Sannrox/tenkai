use super::support::FixedReconciler;
use super::*;

/// `GET /v1/trust` (#676) grades the host's certificates and shows its
/// signing roots to a fleet-wide reader; an environment-scoped credential is
/// refused, and `/readyz` carries the worst status.
#[tokio::test]
async fn trust_posture_grades_certificates_for_fleet_readers() {
    let dir = std::env::temp_dir().join(format!("tenkai-http-trust-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["hub.example.test".into()]).unwrap();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3);
    let key = rcgen::KeyPair::generate().unwrap();
    let listener = dir.join("listener.pem");
    std::fs::write(&listener, params.self_signed(&key).unwrap().pem()).unwrap();

    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    let mut config = ServerConfig::community(
        "management-secret",
        HashMap::from([("runtime-secret".into(), "prod".into())]),
    );
    config.environment_management_assignments =
        HashMap::from([("prod-secret".into(), "prod".into())]);
    config.trust_sources = tenkai::trust_posture::TrustSources {
        certificates: vec![(
            "listener".into(),
            tenkai::trust_posture::CertificateSource::File(listener),
        )],
        warning_days: 30,
        critical_days: 7,
        ..Default::default()
    };
    let app = router(config, Arc::new(FixedReconciler::default()), store).unwrap();
    let get = |path: &'static str, bearer: Option<&'static str>| {
        let app = app.clone();
        async move {
            let mut request = Request::get(path);
            if let Some(bearer) = bearer {
                request = request.header("authorization", format!("Bearer {bearer}"));
            }
            let response = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
            )
        }
    };
    let (status, posture) = get("/v1/trust", Some("management-secret")).await;
    assert_eq!(status, StatusCode::OK, "{posture}");
    assert_eq!(posture["status"], "critical");
    assert_eq!(posture["tls"][0]["purpose"], "listener");
    assert_eq!(posture["tls"][0]["file"], "listener.pem");
    let (status, _) = get("/v1/trust", Some("prod-secret")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = get("/v1/trust", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, ready) = get("/readyz", None).await;
    assert_eq!(ready["trust"], "critical");
    let _ = std::fs::remove_dir_all(dir);
}
