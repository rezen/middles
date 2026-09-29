use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::any,
};
use http_body_util::BodyExt;
use middles::{
    App,
    config::{AptRepo, Config},
};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::TempDir;
use tower::ServiceExt;

struct Fixture {
    app: App,
    hits: Arc<AtomicUsize>,
    indexes: Arc<AtomicUsize>,
    signed: Arc<Vec<u8>>,
    _dir: TempDir,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture(age: u32) -> Fixture {
    fixture_with_gzip(age, false).await
}

async fn fixture_with_gzip(age: u32, gzip: bool) -> Fixture {
    let hits = Arc::new(AtomicUsize::new(0));
    let indexes = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let package = format!(
        "Package: demo\nVersion: 1:2.0-1\nArchitecture: all\nFilename: pool/demo_2.0_all.deb\nSHA256: {}\nSize: 7\n\n",
        "a".repeat(64)
    );
    let package = Arc::new(package.into_bytes());
    let compressed = if gzip {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&package).unwrap();
        Arc::new(encoder.finish().unwrap())
    } else {
        package.clone()
    };
    let release = Arc::new(
        format!(
            "Suite: test\nAcquire-By-Hash: no\nSHA256:\n {:x} {} main/binary-amd64/Packages{}\n",
            Sha256::digest(compressed.as_ref()),
            compressed.len(),
            if gzip { ".gz" } else { "" }
        )
        .into_bytes(),
    );
    let signed = Arc::new(format!("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{}-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n", String::from_utf8_lossy(&release)).into_bytes());
    let other_package = Arc::new(format!("Package: demo\nVersion: 1:2.0-1\nArchitecture: all\nFilename: pool/demo_2.0_all.deb\nSHA256: {}\nSize: 7\n\n", "b".repeat(64)).into_bytes());
    let other_release = Arc::new(
        format!(
            "Suite: other\nAcquire-By-Hash: no\nSHA256:\n {:x} {} main/binary-amd64/Packages\n",
            Sha256::digest(other_package.as_ref()),
            other_package.len()
        )
        .into_bytes(),
    );
    let signed_fixture = signed.clone();
    let hits_up = hits.clone();
    let indexes_up = indexes.clone();
    let router = Router::new().fallback(any(move |request: Request<Body>| {
        let package = package.clone();
        let compressed = compressed.clone();
        let hits = hits_up.clone();
        let indexes = indexes_up.clone();
        let release = release.clone();
        let signed = signed.clone();
        let other_package = other_package.clone();
        let other_release = other_release.clone();
        async move {
            match request.uri().path() {
                "/dists/test/InRelease" => {
                    (StatusCode::OK, signed.as_ref().clone()).into_response()
                }
                "/dists/test/Release" => (StatusCode::OK, release.as_ref().clone()).into_response(),
                "/dists/other/InRelease" => {
                    (StatusCode::OK, other_release.as_ref().clone()).into_response()
                }
                "/dists/other/main/binary-amd64/Packages" => {
                    (StatusCode::OK, other_package.as_ref().clone()).into_response()
                }
                "/dists/broken/InRelease" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                path if path.starts_with("/dists/test/main/binary-amd64/by-hash/SHA256/") => {
                    (StatusCode::OK, b"opaque index bytes\n".to_vec()).into_response()
                }
                "/dists/test/main/binary-amd64/Packages.xz" => {
                    StatusCode::NOT_FOUND.into_response()
                }
                "/dists/test/main/binary-amd64/Packages.gz" if gzip => {
                    indexes.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, compressed.as_ref().clone()).into_response()
                }
                "/dists/test/main/binary-amd64/Packages.gz" => {
                    StatusCode::NOT_FOUND.into_response()
                }
                "/dists/test/main/binary-amd64/Packages" => {
                    if gzip {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    indexes.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, package.as_ref().clone()).into_response()
                }
                "/pool/demo_2.0_all.deb" => {
                    hits.fetch_add(1, Ordering::SeqCst);
                    if request.method() == axum::http::Method::HEAD {
                        return (StatusCode::OK, [("content-length", "7")], Body::empty())
                            .into_response();
                    }
                    if request.headers().contains_key("range") {
                        (
                            StatusCode::PARTIAL_CONTENT,
                            [("content-range", "bytes 0-2/7")],
                            "deb",
                        )
                            .into_response()
                    } else {
                        "debdata".into_response()
                    }
                }
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.cache.path = dir.path().join("cache.sqlite3");
    config.apt.enabled = true;
    config.apt.policy.min_age_days = Some(age);
    config.apt.repos = vec![AptRepo {
        name: "test".into(),
        url: origin,
        suites: vec!["test".into()],
        components: vec!["main".into()],
        architectures: vec!["amd64".into()],
        min_age_days: None,
    }];
    config.upstream.allow_http = true;
    config.upstream.artifact_hosts = vec!["127.0.0.1".into()];
    let app = App::new(config).await.unwrap();
    Fixture {
        app,
        hits,
        indexes,
        signed: signed_fixture,
        _dir: dir,
        server,
    }
}

async fn get(app: &App, method: &str, uri: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (
        response.status(),
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

#[tokio::test]
async fn signed_passthrough_warms_age_and_denies_all_archive_methods() {
    let f = fixture(1).await;
    let (status, bytes) = get(&f.app, "GET", "/apt/test/dists/test/InRelease").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, *f.signed);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        format!("{:x}", Sha256::digest(&*f.signed))
    );
    assert_eq!(
        get(
            &f.app,
            "GET",
            &format!(
                "/apt/test/dists/test/main/binary-amd64/by-hash/SHA256/{}",
                "a".repeat(64)
            )
        )
        .await,
        (StatusCode::OK, b"opaque index bytes\n".to_vec())
    );
    for method in ["GET", "HEAD"] {
        assert_eq!(
            get(&f.app, method, "/apt/test/pool/demo_2.0_all.deb")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let check = get(&f.app, "GET", "/apt/test/check/pool/demo_2.0_all.deb").await;
    assert_eq!(check.0, StatusCode::OK);
    let evidence: serde_json::Value = serde_json::from_slice(&check.1).unwrap();
    assert_eq!(evidence["age"]["age_basis"], "local_first_seen");
    assert_eq!(evidence["age"]["eligible"], false);
    assert_eq!(evidence["install_hooks"]["status"], "unavailable");
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
    let ranged = f
        .app
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/apt/test/pool/demo_2.0_all.deb")
                .header("range", "bytes=0-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ranged.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        get(&f.app, "GET", "/apt/test/pool/demo_2.0_all.deb?x=1")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&f.app, "GET", "/apt/test/pool/%2e%2e/demo.deb").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&f.app, "POST", "/apt/test/dists/test/InRelease")
            .await
            .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        get(&f.app, "GET", "/apt/unknown/dists/test/InRelease")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&f.app, "GET", "/apt/test/dists/unknown/InRelease")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let auth = f
        .app
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/apt/test/dists/test/InRelease")
                .header("authorization", "Basic abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth.status(), StatusCode::FORBIDDEN);
    let mut disabled = (*f.app.config).clone();
    disabled.apt.enabled = false;
    assert_eq!(
        get(
            &App::new(disabled).await.unwrap(),
            "GET",
            "/apt/test/dists/test/InRelease"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let db = rusqlite::Connection::open(&f.app.config.cache.path).unwrap();
    db.execute(
        "UPDATE first_seen SET timestamp = ?1 WHERE key = ?2",
        rusqlite::params![
            chrono::Utc::now().timestamp() - 86_400,
            format!("apt:{}", "a".repeat(64))
        ],
    )
    .unwrap();
    assert_eq!(
        get(&f.app, "GET", "/apt/test/pool/demo_2.0_all.deb")
            .await
            .0,
        StatusCode::OK
    );
    let restarted = App::new((*f.app.config).clone()).await.unwrap();
    let (_, body) = get(&restarted, "GET", "/apt/test/check/pool/demo_2.0_all.deb").await;
    let evidence: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(evidence["age"]["eligible"], true);
}

#[tokio::test]
async fn eligible_archive_streams_and_counts() {
    let f = fixture(0).await;
    assert_eq!(
        get(&f.app, "GET", "/apt/test/pool/demo_2.0_all.deb").await,
        (StatusCode::OK, b"debdata".to_vec())
    );
    assert_eq!(
        get(&f.app, "HEAD", "/apt/test/pool/demo_2.0_all.deb")
            .await
            .0,
        StatusCode::OK
    );
    let stats = get(&f.app, "GET", "/stats?ecosystem=apt&package=demo").await;
    let value: serde_json::Value = serde_json::from_slice(&stats.1).unwrap();
    assert_eq!(value["totals"]["full_downloads"], 1);
    assert_eq!(value["releases"][0]["release"], "1:2.0-1_all");
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    let ranged = f
        .app
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/apt/test/pool/demo_2.0_all.deb")
                .header("range", "bytes=0-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        ranged
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        b"deb"
    );
    let stats = get(&f.app, "GET", "/stats?ecosystem=apt&package=demo").await;
    let value: serde_json::Value = serde_json::from_slice(&stats.1).unwrap();
    assert_eq!(value["totals"]["range_transfers"], 1);
}

#[test]
fn apt_restrictions_apply_only_when_enabled() {
    let mut config = Config::default();
    config.apt.policy.min_monthly_downloads = Some(10);
    assert!(config.validate().is_ok());
    config.apt.enabled = true;
    assert!(config.validate().is_err());
    config.apt.policy.min_monthly_downloads = Some(0);
    assert!(config.validate().is_err()); // no repository
}

#[tokio::test]
async fn matching_repository_override_uses_most_permissive_age() {
    let f = fixture(1).await;
    let mut config = (*f.app.config).clone();
    let mut second = config.apt.repos[0].clone();
    second.name = "permissive".into();
    second.min_age_days = Some(0);
    config.apt.repos.push(second);
    let app = App::new(config).await.unwrap();
    assert_eq!(
        get(&app, "GET", "/apt/test/pool/demo_2.0_all.deb").await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn conflicting_or_unavailable_configured_index_fails_closed() {
    let f = fixture(0).await;
    let mut config = (*f.app.config).clone();
    let mut second = config.apt.repos[0].clone();
    second.name = "other".into();
    second.suites = vec!["other".into()];
    config.apt.repos.push(second.clone());
    let app = App::new(config.clone()).await.unwrap();
    assert_eq!(
        get(&app, "GET", "/apt/test/pool/demo_2.0_all.deb").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
    config.apt.repos.pop();
    second.name = "broken".into();
    second.suites = vec!["broken".into()];
    config.apt.repos.push(second);
    let app = App::new(config).await.unwrap();
    assert_eq!(
        get(&app, "GET", "/apt/test/pool/demo_2.0_all.deb").await.0,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gzip_fallback_and_concurrent_misses_share_one_index_fetch() {
    let f = fixture_with_gzip(0, true).await;
    let (a, b) = tokio::join!(
        get(&f.app, "GET", "/apt/test/pool/demo_2.0_all.deb"),
        get(&f.app, "GET", "/apt/test/check/pool/demo_2.0_all.deb")
    );
    assert_eq!(a.0, StatusCode::OK);
    assert_eq!(b.0, StatusCode::OK);
    assert_eq!(f.indexes.load(Ordering::SeqCst), 1);
}
