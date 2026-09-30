use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use http_body_util::BodyExt;
use middles::{
    App,
    config::{AdvisorySource, Config},
    policy::AdvisoryPolicy,
    registry::Ecosystem,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

#[derive(Clone)]
struct Mock {
    hits: Arc<AtomicUsize>,
    mode: Arc<AtomicUsize>,
    origin: String,
}

async fn upstream(State(mock): State<Mock>, request: Request<Body>) -> Response {
    let path = request.uri().path();
    if path == "/v1/querybatch" {
        if request.method() != "POST" {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let query: Value = serde_json::from_slice(&bytes).unwrap();
        let results = query["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                if q["version"] == "1.0.0" {
                    json!({"vulns":[{"id":"GHSA-block"}]})
                } else {
                    json!({})
                }
            })
            .collect::<Vec<_>>();
        return axum::Json(json!({"results":results})).into_response();
    }
    if path == "/v1/vulns/GHSA-block" {
        return axum::Json(json!({"id":"GHSA-block","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]})).into_response();
    }
    if path == "/v1/query" {
        mock.hits.fetch_add(1, Ordering::SeqCst);
        if request.method() != "POST" {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let query: Value = serde_json::from_slice(&bytes).unwrap();
        if !["npm", "PyPI", "Packagist", "RubyGems"]
            .iter()
            .any(|name| query["package"]["ecosystem"] == *name)
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return match mock.mode.load(Ordering::SeqCst) {
            1 => StatusCode::TOO_MANY_REQUESTS.into_response(),
            2 => (StatusCode::OK, "not json").into_response(),
            3 => axum::Json(json!({"vulns":null})).into_response(),
            _ => axum::Json(json!({"vulns":[
                {"id":"GHSA-block", "aliases":["CVE-2020-1"], "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
                {"id":"GHSA-withdrawn", "withdrawn":"2020-01-01T00:00:00Z"},
                {"id":"GHSA-waived", "aliases":["CVE-2020-2"]}
            ]})).into_response(),
        };
    }
    let old = "2020-01-01T00:00:00Z";
    match path {
        "/demo" => axum::Json(json!({"versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":format!("{}/blob/demo-1.0.0.tgz",mock.origin)}},"2.0.0":{"version":"2.0.0","dist":{"tarball":format!("{}/blob/demo-2.0.0.tgz",mock.origin)}}},"time":{"1.0.0":old,"2.0.0":old},"dist-tags":{"latest":"2.0.0"}})).into_response(),
        "/simple/demo/" => axum::Json(json!({"meta":{"api-version":"1.1"},"files":[{"filename":"demo-1.0.0-py3-none-any.whl","upload-time":old,"url":format!("{}/blob/demo.whl",mock.origin),"core-metadata":true},{"filename":"demo-2.0.0-py3-none-any.whl","upload-time":old,"url":format!("{}/blob/demo2.whl",mock.origin)}]})).into_response(),
        "/p2/vendor/demo.json" => axum::Json(json!({"packages":{"vendor/demo":[{"name":"vendor/demo","version":"1.0.0","time":old,"type":"library","dist":{"type":"zip","url":format!("{}/blob/demo.zip",mock.origin)}},{"name":"vendor/demo","version":"2.0.0","time":old,"type":"library","dist":{"type":"zip","url":format!("{}/blob/demo2.zip",mock.origin)}}]}})).into_response(),
        "/info/demo" => ([("content-type", "text/plain")], format!("---\n1.0.0 |checksum:{},created_at:{old}\n2.0.0 |checksum:{},created_at:{old}\n", "a".repeat(64), "b".repeat(64))).into_response(),
        _ if path.starts_with("/blob/") => ([("content-type","application/octet-stream")], "archive").into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn call(app: &App, path: &str) -> StatusCode {
    app.clone()
        .router()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

async fn json_call(app: &App, path: &str, accept: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .router()
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
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn advisory_inspection_cache_waivers_and_exact_artifacts() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let mode = Arc::new(AtomicUsize::new(0));
    let mock = Mock {
        hits: hits.clone(),
        mode: mode.clone(),
        origin: origin.clone(),
    };
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(upstream)).with_state(mock),
        )
        .await
        .unwrap()
    });
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.cache.path = dir.path().join("cache.sqlite3");
    config.policy.min_age_days = 0;
    config.npm.advisories = Some(AdvisoryPolicy::Deny);
    config.pip.advisories = Some(AdvisoryPolicy::Deny);
    config.composer.advisories = Some(AdvisoryPolicy::Deny);
    config.rubygems.advisories = Some(AdvisoryPolicy::Deny);
    config.policy.advisory_waivers = vec!["CVE-2020-2".into()];
    config.upstream.npm = origin.clone();
    config.upstream.pypi = origin.clone();
    config.upstream.packagist = origin.clone();
    config.upstream.rubygems = origin.clone();
    config.upstream.osv = origin.clone();
    config.upstream.allow_http = true;
    config.upstream.artifact_hosts = vec!["127.0.0.1".into()];
    let app = App::new(config.clone()).await.unwrap();
    assert_eq!(
        call(&app, "/inspect/advisories/npm/demo?version=1.0.0").await,
        StatusCode::OK
    );
    let report = app
        .advisory_report(Ecosystem::Npm, "demo", "1.0.0")
        .await
        .unwrap();
    assert_eq!(report.advisories.len(), 2);
    assert!(report.blocked_by_advisory_policy);
    assert!(report.advisories[1].waived);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(call(&app, "/npm/demo/1.0.0").await, StatusCode::FORBIDDEN);
    assert_eq!(
        call(&app, "/npm/demo/-/demo-1.0.0.tgz").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.check_advisories(Ecosystem::Pip, "demo", "1.0.0")
            .await
            .unwrap_err()
            .0,
        StatusCode::FORBIDDEN
    );
    let pip_path = url::Url::parse(&app.artifact_url(
        Ecosystem::Pip,
        "demo",
        "demo-1.0.0-py3-none-any.whl",
        "demo-1.0.0-py3-none-any.whl.metadata",
    ))
    .unwrap()
    .path()
    .to_owned();
    assert_eq!(call(&app, &pip_path).await, StatusCode::FORBIDDEN);
    let composer_path = url::Url::parse(&app.artifact_url(
        Ecosystem::Composer,
        "vendor/demo",
        "1.0.0",
        "archive.zip",
    ))
    .unwrap()
    .path()
    .to_owned();
    assert_eq!(call(&app, &composer_path).await, StatusCode::FORBIDDEN);
    assert_eq!(
        call(&app, "/rubygems/gems/demo-1.0.0.gem").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "/rubygems/quick/Marshal.4.8/demo-1.0.0.gemspec.rz").await,
        StatusCode::FORBIDDEN
    );
    let (status, npm) = json_call(&app, "/npm/demo", "application/json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(npm["versions"].get("1.0.0").is_none());
    assert!(npm["versions"].get("2.0.0").is_some());
    let (status, pip) = json_call(
        &app,
        "/pip/simple/demo/",
        "application/vnd.pypi.simple.v1+json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pip["files"].as_array().unwrap().len(), 1);
    assert_eq!(pip["files"][0]["filename"], "demo-2.0.0-py3-none-any.whl");
    let (status, composer) =
        json_call(&app, "/composer/p2/vendor/demo.json", "application/json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        composer["packages"]["vendor/demo"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(composer["packages"]["vendor/demo"][0]["version"], "2.0.0");
    let ruby = app
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/rubygems/api/v1/dependencies?gems=demo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ruby.status(), StatusCode::OK);
    let bytes = ruby.into_body().collect().await.unwrap().to_bytes();
    assert!(!bytes.windows(5).any(|w| w == b"1.0.0"));
    assert!(bytes.windows(5).any(|w| w == b"2.0.0"));
    config.npm.advisories = Some(AdvisoryPolicy::Report);
    let restarted = App::new(config).await.unwrap();
    assert!(
        restarted
            .check_advisories(Ecosystem::Npm, "demo", "1.0.0")
            .await
            .is_ok()
    );
    assert_eq!(hits.load(Ordering::SeqCst), 4); // one query per ecosystem; restart reads npm from disk
    server.abort();
}

#[tokio::test]
async fn provider_errors_deny_without_empty_evidence() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mode = Arc::new(AtomicUsize::new(1));
    let mock = Mock {
        hits: Arc::new(AtomicUsize::new(0)),
        mode: mode.clone(),
        origin: origin.clone(),
    };
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(upstream)).with_state(mock),
        )
        .await
        .unwrap()
    });
    let dir = tempfile::tempdir().unwrap();
    for state in [1, 2, 3] {
        mode.store(state, Ordering::SeqCst);
        let mut config = Config::default();
        config.cache.path = dir.path().join(format!("{state}.sqlite3"));
        config.npm.advisories = Some(AdvisoryPolicy::Deny);
        config.upstream.osv = origin.clone();
        config.upstream.allow_http = true;
        let app = App::new(config).await.unwrap();
        assert_eq!(
            app.check_advisories(Ecosystem::Npm, "demo", "1.0.0")
                .await
                .unwrap_err()
                .0,
            StatusCode::BAD_GATEWAY
        );
    }
    server.abort();
}

#[tokio::test]
async fn local_mirror_is_offline_and_fails_when_stale() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.cache.path = dir.path().join("cache.sqlite3");
    config.advisory_source = AdvisorySource::Local;
    config.npm.advisories = Some(AdvisoryPolicy::Deny);
    let app = App::new(config).await.unwrap();
    let db = rusqlite::Connection::open(&app.config.cache.path).unwrap();
    let now = chrono::Utc::now().timestamp();
    db.execute(
        "INSERT INTO advisory_imports VALUES ('npm', ?1, 1, 'fixture')",
        [now],
    )
    .unwrap();
    let record = json!({"id":"GHSA-local","affected":[{"package":{"ecosystem":"npm","name":"demo"},"versions":["1.0.0"]}],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]});
    db.execute(
        "INSERT INTO advisories VALUES ('npm','demo','GHSA-local',?1)",
        [record.to_string().into_bytes()],
    )
    .unwrap();
    let denial = app
        .check_advisories(Ecosystem::Npm, "demo", "1.0.0")
        .await
        .unwrap_err();
    assert_eq!(denial.0, StatusCode::FORBIDDEN, "{denial}");
    assert!(
        app.check_advisories(Ecosystem::Npm, "demo", "2.0.0")
            .await
            .is_ok()
    );
    let blocked = app
        .blocked_advisory_versions(Ecosystem::Npm, "demo", &["1.0.0".into(), "2.0.0".into()])
        .await
        .unwrap();
    assert!(blocked.contains("1.0.0"));
    assert!(!blocked.contains("2.0.0"));
    let (status, status_doc) =
        json_call(&app, "/inspect/advisories/status", "application/json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(status_doc["imports"][0]["ecosystem"], "npm");
    db.execute(
        "UPDATE advisory_imports SET imported_at=0 WHERE ecosystem='npm'",
        [],
    )
    .unwrap();
    assert_eq!(
        app.check_advisories(Ecosystem::Npm, "demo", "2.0.0")
            .await
            .unwrap_err()
            .0,
        StatusCode::BAD_GATEWAY
    );
}
