use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use middles::{App, config::Config};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::TempDir;
use tower::ServiceExt;

#[derive(Clone)]
struct Mock {
    origin: String,
    hits: Arc<AtomicUsize>,
    downloads: u64,
}
struct Fixture {
    app: App,
    router: Router,
    hits: Arc<AtomicUsize>,
    _dir: TempDir,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture(days: u32, minimum: u64, downloads: u64) -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let mock = Mock {
        origin: origin.clone(),
        hits: hits.clone(),
        downloads,
    };
    let upstream = Router::new().fallback(get(mock_upstream)).with_state(mock);
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.cache.path = dir.path().join("cache.sqlite3");
    config.policy.min_age_days = days;
    config.policy.min_monthly_downloads = minimum;
    // These fixtures exercise ecosystems with monthly and hook evidence.
    config.rubygems.min_monthly_downloads = Some(0);
    config.rubygems.install_hooks = Some(middles::inspection::HookPolicy::Report);
    config.upstream.npm = origin.clone();
    config.upstream.pypi = origin.clone();
    config.upstream.packagist = origin.clone();
    config.upstream.npm_stats = origin.clone();
    config.upstream.pypi_stats = origin.clone();
    config.upstream.composer_stats = origin;
    config.upstream.allow_http = true;
    config.upstream.artifact_hosts = vec!["127.0.0.1".into()];
    let app = App::new(config).await.unwrap();
    let router = app.clone().router();
    Fixture {
        app,
        router,
        hits,
        _dir: dir,
        server,
    }
}
async fn mock_upstream(State(m): State<Mock>, request: Request<Body>) -> axum::response::Response {
    m.hits.fetch_add(1, Ordering::SeqCst);
    assert!(request.headers().get("authorization").is_none());
    let old = (Utc::now() - Duration::days(30)).to_rfc3339();
    let young = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let path = request.uri().path();
    if m.downloads == u64::MAX
        && (path.starts_with("/downloads/")
            || path.starts_with("/api/")
            || path.ends_with("/stats.json"))
    {
        return axum::Json(json!({"error": "statistics unavailable"})).into_response();
    }
    let value = match path {
        "/hooked" | "/@scope/hooked" => json!({"name":"hooked", "versions":{
            "1.0.0":{"name":"hooked","version":"1.0.0","scripts":{"test":"node test.js"},"dist":{"tarball":format!("{}/blob/hooked-1.0.0.tgz", m.origin)}},
            "2.0.0":{"name":"hooked","version":"2.0.0","scripts":{"postinstall":"node install.js","prepare":"npm run build","build":"tsc"},"dist":{"tarball":format!("{}/blob/hooked-2.0.0.tgz", m.origin)}}},
            "time":{"1.0.0":old,"2.0.0":old}, "dist-tags":{"latest":"2.0.0"}}),
        "/simple/hooked/" => json!({"meta":{"api-version":"1.1"},"name":"hooked","files":[
            {"filename":"hooked-1.0-py3-none-any.whl","url":format!("{}/blob/hooked.whl",m.origin),"upload-time":old,"hashes":{}},
            {"filename":"hooked-1.0.tar.gz","url":format!("{}/blob/hooked.tar.gz",m.origin),"upload-time":old,"hashes":{},"core-metadata":true}]}),
        "/p2/vendor/hooks.json" => json!({"minified":"composer/2.0","packages":{"vendor/hooks":[
            {"name":"vendor/hooks","version":"2.0.0","time":old,"type":"composer-plugin","extra":{"class":"Vendor\\Plugin"},"dist":{"type":"zip","url":format!("{}/blob/plugin.zip",m.origin)}},
            {"version":"1.0.0","type":"library","extra":"__unset","scripts":{"post-install-cmd":["@build"],"build":"php build.php"},"dist":{"type":"zip","url":format!("{}/blob/library.zip",m.origin)}}]}}),
        "/demo" | "/@scope/demo" => json!({"name":"demo","versions": {
            "1.0.0":{"name":"demo","version":"1.0.0","dist":{"tarball":format!("{}/blob/demo-1.0.0.tgz", m.origin), "integrity":"sha512-unchanged"}},
            "2.0.0":{"name":"demo","version":"2.0.0","dist":{"tarball":format!("{}/blob/demo-2.0.0.tgz", m.origin)}}},
            "time":{"1.0.0":old,"2.0.0":young},"dist-tags":{"latest":"2.0.0","next":"2.0.0"}}),
        "/simple/demo/" => json!({"meta":{"api-version":"1.1"},"name":"demo","files":[
            {"filename":"demo-1.0.whl","url":format!("{}/blob/demo-1.0.whl",m.origin),"upload-time":old,"requires-python":">=3.9","hashes":{"sha256":"abc"},"core-metadata":true,"yanked":false},
            {"filename":"demo-2.0.whl","url":format!("{}/blob/demo-2.0.whl",m.origin),"upload-time":young,"hashes":{},"yanked":"broken"}]}),
        "/p2/vendor/demo.json" => json!({"minified":"composer/2.0", "packages":{"vendor/demo":[
            {"name":"vendor/demo","version":"2.0.0","time":young,"type":"library","dist":{"type":"zip","url":format!("{}/blob/new.zip",m.origin),"reference":"new"},"source":{"type":"git","url":"https://github.com/example/demo.git"}},
            {"version":"1.0.0","time":old,"dist":{"type":"zip","url":format!("{}/blob/old.zip",m.origin),"reference":"old"}}]}}),
        "/downloads/point/last-month/demo" => json!({"downloads":m.downloads}),
        "/api/packages/demo/recent" => json!({"data":{"last_month":m.downloads}}),
        "/packages/vendor/demo/stats.json" => json!({"downloads":{"monthly":m.downloads}}),
        "/blob/redirect" => {
            return (
                StatusCode::FOUND,
                [("location", "http://unapproved.invalid/blob")],
            )
                .into_response();
        }
        _ if path.starts_with("/blob/") => {
            if request.headers().contains_key("range") {
                return (
                    StatusCode::PARTIAL_CONTENT,
                    [("content-range", "bytes 0-2/7")],
                    "arc",
                )
                    .into_response();
            }
            return ([("content-type", "application/octet-stream")], "archive").into_response();
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    axum::Json(value).into_response()
}
async fn request(router: &Router, path: &str, accept: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("accept", accept)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes))),
    )
}
fn path(url: &str) -> String {
    url::Url::parse(url).unwrap().path().into()
}
fn artifact_path(eco: &str, pkg: &str, version: &str, filename: &str) -> String {
    format!(
        "/artifacts/{eco}/{}/{}/{filename}",
        URL_SAFE_NO_PAD.encode(pkg),
        URL_SAFE_NO_PAD.encode(version)
    )
}

#[tokio::test]
async fn npm_filters_resolves_tags_and_gates_locked_artifacts() {
    let f = fixture(7, 0, 0).await;
    let (status, doc) = request(
        &f.router,
        "/npm/demo",
        "application/vnd.npm.install-v1+json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["versions"].as_object().unwrap().len(), 1);
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    assert_eq!(
        doc["versions"]["1.0.0"]["dist"]["integrity"],
        "sha512-unchanged"
    );
    let archive = path(
        doc["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(
        request(&f.router, &archive, "*/*").await,
        (StatusCode::OK, json!("archive"))
    );
    assert_eq!(
        request(&f.router, "/npm/demo/2.0.0", "*/*").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &f.router,
            &artifact_path("npm", "demo", "2.0.0", "package.tgz"),
            "*/*"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&f.router, "/npm/demo/-/demo-2.0.0.tgz", "*/*")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&f.router, "/npm/demo/-/demo-1.0.0.tgz", "*/*")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&f.router, "/npm/@scope%2Fdemo/latest", "*/*")
            .await
            .1["version"],
        "1.0.0"
    );
    // Only one metadata fetch for demo; archives add two requests, scoped metadata adds one.
    assert_eq!(f.hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn pip_serves_both_formats_and_gates_pep658_metadata() {
    let f = fixture(7, 0, 0).await;
    let (status, doc) = request(
        &f.router,
        "/pip/simple/Demo/",
        "application/vnd.pypi.simple.v1+json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["files"].as_array().unwrap().len(), 1);
    let url = path(doc["files"][0]["url"].as_str().unwrap());
    assert_eq!(
        request(&f.router, &(url.clone() + ".metadata"), "*/*")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(request(&f.router, &url, "*/*").await.0, StatusCode::OK);
    let html = request(&f.router, "/pip/simple/demo/", "text/html").await.1;
    assert!(
        html.as_str()
            .unwrap()
            .contains("data-requires-python=\"&gt;=3.9\"")
    );
    assert!(!html.as_str().unwrap().contains("demo-2.0.whl"));
    assert_eq!(
        request(
            &f.router,
            &artifact_path("pip", "demo", "demo-2.0.whl", "demo-2.0.whl.metadata"),
            "*/*"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn composer_first_seen_survives_restart_and_dist_has_no_source_bypass() {
    let f = fixture(7, 0, 0).await;
    let (_, index) = request(&f.router, "/composer/packages.json", "application/json").await;
    assert_eq!(
        index["metadata-url"],
        "http://127.0.0.1:8080/composer/p2/%package%.json"
    );
    let (_, doc) = request(
        &f.router,
        "/composer/p2/vendor/demo.json",
        "application/json",
    )
    .await;
    assert_eq!(doc["packages"]["vendor/demo"], json!([]));
    assert_eq!(
        request(
            &f.router,
            &artifact_path("composer", "vendor/demo", "1.0.0", "archive.zip"),
            "*/*"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Simulate a ledger warmed eight days ago, then restart with the same cache.
    let db = rusqlite::Connection::open(&f.app.config.cache.path).unwrap();
    db.execute(
        "UPDATE first_seen SET timestamp = ?1",
        [Utc::now().timestamp() - 8 * 86400],
    )
    .unwrap();
    let restarted = App::new((*f.app.config).clone()).await.unwrap().router();
    let (_, doc) = request(&restarted, "/composer/p2/vendor/demo.json", "*/*").await;
    let releases = doc["packages"]["vendor/demo"].as_array().unwrap();
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0]["version"], "1.0.0");
    assert!(releases[0].get("source").is_none());
    assert_eq!(
        request(
            &restarted,
            &path(releases[0]["dist"]["url"].as_str().unwrap()),
            "*/*"
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2); // disk metadata reused + archive
}

#[tokio::test]
async fn download_threshold_boundary_and_all_ecosystems() {
    for (count, status) in [(499, StatusCode::FORBIDDEN), (500, StatusCode::OK)] {
        let f = fixture(0, 500, count).await;
        for path in [
            "/npm/demo",
            "/pip/simple/demo/",
            "/composer/p2/vendor/demo.json",
        ] {
            assert_eq!(request(&f.router, path, "application/json").await.0, status);
            assert_eq!(request(&f.router, path, "application/json").await.0, status);
        }
        assert_eq!(f.hits.load(Ordering::SeqCst), 6);
    }
}

#[tokio::test]
async fn changed_policy_rechecks_raw_disk_cache_and_range_requests_work() {
    let f = fixture(0, 0, 0).await;
    request(&f.router, "/npm/demo", "*/*").await;
    let mut config = (*f.app.config).clone();
    config.policy.min_age_days = 7;
    let app = App::new(config).await.unwrap();
    let router = app.clone().router();
    assert_eq!(
        request(&router, "/npm/demo/2.0.0", "*/*").await.0,
        StatusCode::FORBIDDEN
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(artifact_path("npm", "demo", "1.0.0", "package.tgz"))
                .header("range", "bytes=0-2")
                .header("authorization", "private-client-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()["content-range"], "bytes 0-2/7");
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    assert!(
        app.allowed_artifact("http://169.254.169.254/latest/meta-data")
            .is_err()
    );
    assert!(
        app.allowed_artifact("http://127.0.0.1.evil.test/file")
            .is_err()
    );
    assert!(
        app.allowed_artifact("http://user:pass@127.0.0.1/file")
            .is_err()
    );
    let redirect = format!("{}/blob/redirect", f.app.config.upstream.npm);
    assert_eq!(
        app.stream_artifact(&redirect, Default::default())
            .await
            .unwrap_err()
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn archive_stream_completes_over_real_http_and_can_be_polled_after_eof() {
    let f = fixture(7, 0, 0).await;
    let archive_url = format!("{}/blob/demo-1.0.0.tgz", f.app.config.upstream.npm);
    let mut response = f
        .app
        .stream_artifact(&archive_url, Default::default())
        .await
        .unwrap();
    while let Some(frame) = response.body_mut().frame().await {
        frame.unwrap();
    }
    assert!(response.body_mut().frame().await.is_none());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = f.router.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder().gzip(true).build().unwrap();
    let response = client
        .get(format!(
            "http://{address}{}",
            artifact_path("npm", "demo", "1.0.0", "package.tgz")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.bytes().await;
    server.abort();
    assert_eq!(body.unwrap().as_ref(), b"archive");
}

#[tokio::test]
async fn missing_download_evidence_cannot_allow_metadata_or_direct_artifacts() {
    let f = fixture(0, 1, u64::MAX).await;
    for path in [
        "/npm/demo".to_string(),
        "/pip/simple/demo/".to_string(),
        "/composer/p2/vendor/demo.json".to_string(),
        artifact_path("npm", "demo", "1.0.0", "package.tgz"),
        artifact_path("pip", "demo", "demo-1.0.whl", "demo-1.0.whl"),
        artifact_path("composer", "vendor/demo", "1.0.0", "archive.zip"),
    ] {
        assert_eq!(
            request(&f.router, &path, "application/json").await.0,
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn inspection_reports_definitions_context_and_uses_existing_metadata_cache() {
    let f = fixture(7, 0, 0).await;
    let (status, doc) = request(
        &f.router,
        "/inspect/npm/@scope%2Fhooked?version=2.0.0",
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        doc["inspection"]["scripts"]["postinstall"],
        "node install.js"
    );
    assert_eq!(doc["inspection"]["scripts"]["build"], "tsc");
    assert_eq!(doc["inspection"]["dependency_execution"], true);
    assert_eq!(doc["blocked_by_hook_policy"], false);
    let (_, listing) = request(&f.router, "/npm/@scope%2Fhooked", "application/json").await;
    assert_eq!(listing["dist-tags"]["latest"], "2.0.0");
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    let (_, composer) = request(
        &f.router,
        "/inspect/composer/vendor/hooks?version=1.0.0",
        "application/json",
    )
    .await;
    assert_eq!(
        composer["inspection"]["scripts"]["post-install-cmd"],
        json!(["@build"])
    );
    assert_eq!(composer["inspection"]["dependency_execution"], false);
    let (_, python) = request(
        &f.router,
        "/inspect/pip/hooked?filename=hooked-1.0.tar.gz",
        "application/json",
    )
    .await;
    assert_eq!(python["inspection"]["status"], "unknown");
    assert_eq!(python["inspection"]["dependency_execution"], true);
    assert!(python["inspection"]["scripts"].is_null());
    assert_eq!(
        request(&f.router, "/inspect/npm/hooked", "*/*").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&f.router, "/inspect/pip/hooked?version=1.0", "*/*")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&f.router, "/inspect/npm/hooked?version=9.0.0", "*/*")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn hook_policy_gates_resolution_and_every_artifact_path() {
    let f = fixture(0, 0, 0).await;
    // Warm raw cache in report mode, then change policy without clearing it.
    request(&f.router, "/npm/hooked", "application/json").await;
    let mut config = (*f.app.config).clone();
    config.policy.install_hooks = middles::inspection::HookPolicy::Deny;
    let router = App::new(config).await.unwrap().router();
    let (_, npm) = request(&router, "/npm/hooked", "application/json").await;
    assert_eq!(npm["dist-tags"]["latest"], "1.0.0");
    assert!(npm["versions"].get("2.0.0").is_none());
    for path in [
        "/npm/hooked/2.0.0".into(),
        "/npm/hooked/-/hooked-2.0.0.tgz".into(),
        artifact_path("npm", "hooked", "2.0.0", "package.tgz"),
    ] {
        assert_eq!(
            request(&router, &path, "*/*").await.0,
            StatusCode::FORBIDDEN
        );
    }
    let (_, report) = request(&router, "/inspect/npm/hooked?version=2.0.0", "*/*").await;
    assert_eq!(report["blocked_by_hook_policy"], true);
    assert_eq!(report["other_policies_evaluated"], false);
    let (_, pip) = request(
        &router,
        "/pip/simple/hooked/",
        "application/vnd.pypi.simple.v1+json",
    )
    .await;
    assert_eq!(pip["files"].as_array().unwrap().len(), 1);
    for filename in ["hooked-1.0.tar.gz", "hooked-1.0.tar.gz.metadata"] {
        assert_eq!(
            request(
                &router,
                &artifact_path("pip", "hooked", "hooked-1.0.tar.gz", filename),
                "*/*"
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let (_, composer) = request(
        &router,
        "/composer/p2/vendor/hooks.json",
        "application/json",
    )
    .await;
    let versions = composer["packages"]["vendor/hooks"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["version"], "1.0.0");
    assert_eq!(
        request(
            &router,
            &artifact_path("composer", "vendor/hooks", "2.0.0", "archive.zip"),
            "*/*"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            &artifact_path("composer", "vendor/hooks", "1.0.0", "archive.zip"),
            "*/*"
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn local_download_stats_cover_ecosystems_ranges_and_restart() {
    let f = fixture(0, 0, 0).await;
    let (_, empty) = request(&f.router, "/stats", "application/json").await;
    assert_eq!(empty["totals"]["full_downloads"], 0);
    assert_eq!(empty["totals"]["packages"], 0);
    assert_eq!(empty["totals"]["first_download"], Value::Null);
    assert_eq!(empty["releases"], json!([]));
    for url in [
        "/npm/demo",
        "/pip/simple/demo/",
        "/composer/p2/vendor/demo.json",
    ] {
        assert_eq!(
            request(&f.router, url, "application/json").await.0,
            StatusCode::OK
        );
    }
    // Python core metadata is a resolution request, not an archive download.
    let metadata = artifact_path("pip", "demo", "demo-1.0.whl", "demo-1.0.whl.metadata");
    assert_eq!(request(&f.router, &metadata, "*/*").await.0, StatusCode::OK);
    let npm = artifact_path("npm", "demo", "1.0.0", "package.tgz");
    let head = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(&npm)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert!(
        head.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    let (_, before) = request(&f.router, "/stats", "application/json").await;
    assert_eq!(before["totals"], empty["totals"]);
    for url in [
        npm.clone(),
        "/npm/demo/-/demo-1.0.0.tgz".into(),
        "/npm/@scope/demo/-/demo-1.0.0.tgz".into(),
        artifact_path("pip", "DEMO", "demo-1.0.whl", "demo-1.0.whl"),
        artifact_path("composer", "vendor/demo", "1.0.0", "archive.zip"),
    ] {
        assert_eq!(request(&f.router, &url, "*/*").await.0, StatusCode::OK);
    }
    let range = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&npm)
                .header("range", "bytes=0-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(range.into_body().collect().await.unwrap().to_bytes(), "arc");
    let (_, stats) = request(&f.router, "/stats", "application/json").await;
    assert_eq!(stats["totals"]["full_downloads"], 5);
    assert_eq!(stats["totals"]["range_transfers"], 1);
    assert_eq!(stats["totals"]["bytes"], 38);
    assert_eq!(stats["totals"]["packages"], 4);
    assert_eq!(stats["totals"]["releases"], 4);
    assert_eq!(stats["ecosystems"].as_array().unwrap().len(), 3);
    let (_, filtered) = request(
        &f.router,
        "/stats?ecosystem=npm&package=demo",
        "application/json",
    )
    .await;
    assert_eq!(filtered["totals"]["full_downloads"], 2);
    assert_eq!(filtered["releases"][0]["release"], "1.0.0");
    let (_, pip) = request(
        &f.router,
        "/stats?ecosystem=pip&package=DEMO",
        "application/json",
    )
    .await;
    assert_eq!(pip["releases"][0]["package"], "demo");
    let (_, page) = request(&f.router, "/stats?limit=1&offset=1", "application/json").await;
    assert_eq!(page["totals"], stats["totals"]);
    assert_eq!(page["releases"][0], stats["releases"][1]);
    assert_eq!(page["releases"].as_array().unwrap().len(), 1);
    let restarted = App::new((*f.app.config).clone()).await.unwrap().router();
    assert_eq!(
        request(&restarted, "/stats", "application/json").await.1,
        stats
    );
    for query in [
        "limit=0",
        "limit=1001",
        "offset=-1",
        "ecosystem=unknown",
        "surprise=1",
    ] {
        assert_eq!(
            request(&f.router, &format!("/stats?{query}"), "*/*")
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn local_stats_exclude_denials_and_count_concurrent_downloads() {
    let f = fixture(7, 0, 0).await;
    for url in [
        "/npm/demo/-/demo-2.0.0.tgz".into(),
        artifact_path("npm", "demo", "2.0.0", "package.tgz"),
        artifact_path("pip", "demo", "demo-2.0.whl", "demo-2.0.whl"),
        artifact_path("composer", "vendor/demo", "1.0.0", "archive.zip"),
    ] {
        assert_eq!(
            request(&f.router, &url, "*/*").await.0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        request(&f.router, "/stats", "*/*").await.1["totals"]["full_downloads"],
        0
    );
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let router = f.router.clone();
        tasks.push(tokio::spawn(async move {
            request(&router, "/npm/demo/-/demo-1.0.0.tgz", "*/*").await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().0, StatusCode::OK);
    }
    let (_, stats) = request(&f.router, "/stats", "*/*").await;
    assert_eq!(stats["totals"]["full_downloads"], 12);
    assert_eq!(stats["totals"]["bytes"], 84);
    assert_eq!(stats["totals"]["packages"], 1);
}
