use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use middles::{App, config::Config, inspection::HookPolicy};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::TempDir;
use tower::ServiceExt;

#[derive(Clone)]
struct Upstream {
    info: Arc<Mutex<String>>,
    hits: Arc<AtomicUsize>,
    archives: Arc<AtomicUsize>,
}
struct Fixture {
    app: App,
    upstream: Upstream,
    _dir: TempDir,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
fn line(identity: &str, date: Option<&str>) -> String {
    format!(
        "{identity} dependency:>= 1.0&< 2.0|checksum:{},ruby:>= 2.6{}\n",
        "a".repeat(64),
        date.map(|d| format!(",created_at:{d}")).unwrap_or_default()
    )
}
async fn fixture() -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let old = (Utc::now() - Duration::days(30)).to_rfc3339();
    let young = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let info = format!(
        "---\n{}{}{}{}{}{}",
        line("1.0", Some(&old)),
        line("1.0-x86_64-linux", Some(&young)),
        line("2.0", Some(&young)),
        line("3.0.pre", None),
        line("4.0", Some("invalid")),
        line("5.0", Some("2999-01-01T00:00:00Z"))
    );
    let upstream = Upstream {
        info: Arc::new(Mutex::new(info)),
        hits: Arc::new(AtomicUsize::new(0)),
        archives: Arc::new(AtomicUsize::new(0)),
    };
    let router = Router::new()
        .fallback(get(mock))
        .with_state(upstream.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.cache.path = dir.path().join("cache.sqlite3");
    config.upstream.rubygems = origin;
    config.upstream.allow_http = true;
    config.upstream.artifact_hosts = vec!["127.0.0.1".into()];
    Fixture {
        app: App::new(config).await.unwrap(),
        upstream,
        _dir: dir,
        server,
    }
}
async fn mock(State(up): State<Upstream>, request: Request<Body>) -> Response {
    assert!(request.headers().get("authorization").is_none());
    up.hits.fetch_add(1, Ordering::SeqCst);
    match request.uri().path() {
        "/info/demo" | "/info/demo-2" => up.info.lock().unwrap().clone().into_response(),
        "/info/nonutf8" => vec![255u8].into_response(),
        "/info/oversized" => "x".repeat(1024 * 1024 + 1).into_response(),
        "/info/corrupt" => "---\n1.0 |checksum:nope".into_response(),
        "/info/failure" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        path if path.starts_with("/gems/") => {
            up.archives.fetch_add(1, Ordering::SeqCst);
            if request.headers().contains_key("range") {
                (
                    StatusCode::PARTIAL_CONTENT,
                    [("content-range", "bytes 0-2/7")],
                    "gem",
                )
                    .into_response()
            } else {
                "gemdata".into_response()
            }
        }
        path if path.starts_with("/quick/Marshal.4.8/") => {
            up.archives.fetch_add(1, Ordering::SeqCst);
            "opaque compressed gemspec".into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn request(app: &App, path: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .router()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    (
        status,
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}
fn contains(bytes: &[u8], text: &str) -> bool {
    bytes.windows(text.len()).any(|w| w == text.as_bytes())
}

#[tokio::test]
async fn dependency_api_filters_each_platform_and_caches_raw_evidence() {
    let f = fixture().await;
    let (status, bytes) = request(&f.app, "/rubygems/api/v1/dependencies?gems=demo,demo").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&bytes[..4], &[4, 8, b'[', 6]); // Marshal array of one release.
    assert!(contains(&bytes, "1.0"));
    assert!(contains(&bytes, ">= 1.0, < 2.0"));
    assert!(!contains(&bytes, "x86_64-linux"));
    assert!(!contains(&bytes, "created_at"));
    assert!(!contains(&bytes, "3.0.pre"));
    request(&f.app, "/rubygems/api/v1/dependencies?gems=demo").await;
    assert_eq!(f.upstream.hits.load(Ordering::SeqCst), 1);
    let mut config = (*f.app.config).clone();
    config.rubygems.min_age_days = Some(0);
    let restarted = App::new(config).await.unwrap();
    let (_, bytes) = request(&restarted, "/rubygems/api/v1/dependencies?gems=demo").await;
    assert_eq!(&bytes[..4], &[4, 8, b'[', 8]); // Three eligible releases, using persisted text.
    assert!(contains(&bytes, "x86_64-linux"));
    assert!(!contains(&bytes, "3.0.pre"));
    assert!(!contains(&bytes, "4.0"));
    assert!(!contains(&bytes, "5.0"));
    assert_eq!(f.upstream.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn direct_archives_and_gemspecs_cannot_bypass_age_checks() {
    let f = fixture().await;
    for path in [
        "/rubygems/gems/demo-2.0.gem",
        "/rubygems/gems/demo-1.0-x86_64-linux.gem",
        "/rubygems/quick/Marshal.4.8/demo-2.0.gemspec.rz",
    ] {
        assert_eq!(request(&f.app, path).await.0, StatusCode::FORBIDDEN);
    }
    assert_eq!(f.upstream.archives.load(Ordering::SeqCst), 0);
    assert_eq!(
        request(&f.app, "/rubygems/gems/demo-1.0.gem").await,
        (StatusCode::OK, b"gemdata".to_vec())
    );
    assert_eq!(
        request(&f.app, "/rubygems/quick/Marshal.4.8/demo-1.0.gemspec.rz")
            .await
            .0,
        StatusCode::OK
    );
    let (_, bytes) = request(&f.app, "/stats?ecosystem=rubygems&package=demo").await;
    let stats: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stats["totals"]["full_downloads"], 1);
    assert_eq!(stats["totals"]["bytes"], 7);
    assert_eq!(stats["releases"][0]["release"], "1.0");
    assert_eq!(f.upstream.archives.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unknown_filtered_and_unsupported_indexes_are_not_passthroughs() {
    let f = fixture().await;
    for path in [
        "/rubygems/versions",
        "/rubygems/specs.4.8.gz",
        "/rubygems/names",
        "/rubygems/gems/demo-99.0.gem",
    ] {
        assert_eq!(request(&f.app, path).await.0, StatusCode::NOT_FOUND);
    }
    for query in ["", "?gems=missing"] {
        assert_eq!(
            request(&f.app, &format!("/rubygems/api/v1/dependencies{query}"))
                .await
                .1,
            vec![4, 8, b'[', 0]
        );
    }
    let mut config = (*f.app.config).clone();
    config.rubygems.min_age_days = Some(100);
    let app = App::new(config).await.unwrap();
    assert_eq!(
        request(&app, "/rubygems/api/v1/dependencies?gems=demo")
            .await
            .1,
        vec![4, 8, b'[', 0]
    );
}

#[tokio::test]
async fn validates_requests_and_fails_closed_on_metadata_errors() {
    let f = fixture().await;
    for path in [
        "/rubygems/api/v1/dependencies?gems=..",
        "/rubygems/api/v1/dependencies?gems=demo%2Fevil",
        "/rubygems/gems/demo%2F1.0.gem",
        "/rubygems/gems/demo-1.0.zip",
    ] {
        assert_eq!(request(&f.app, path).await.0, StatusCode::BAD_REQUEST);
    }
    assert_eq!(f.upstream.hits.load(Ordering::SeqCst), 0);
    let many = (0..101)
        .map(|n| format!("gem{n}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        request(
            &f.app,
            &format!("/rubygems/api/v1/dependencies?gems={many}")
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for name in ["corrupt", "failure", "nonutf8"] {
        assert_eq!(
            request(
                &f.app,
                &format!("/rubygems/api/v1/dependencies?gems={name}")
            )
            .await
            .0,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            request(&f.app, &format!("/rubygems/gems/{name}-1.0.gem"))
                .await
                .0,
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(f.upstream.archives.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn numeric_names_are_resolved_against_metadata_and_ranges_are_preserved() {
    let f = fixture().await;
    let response = f
        .app
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/rubygems/gems/demo-2-1.0.gem")
                .header("range", "bytes=0-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()["content-range"], "bytes 0-2/7");
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"gem"
    );
}

#[tokio::test]
async fn concurrent_misses_share_one_text_fetch_and_yanks_take_effect_on_refresh() {
    let f = fixture().await;
    let (a, b, c) = tokio::join!(
        request(&f.app, "/rubygems/api/v1/dependencies?gems=demo"),
        request(&f.app, "/rubygems/api/v1/dependencies?gems=demo"),
        request(&f.app, "/rubygems/gems/demo-2.0.gem")
    );
    assert_eq!(a.0, StatusCode::OK);
    assert_eq!(b.0, StatusCode::OK);
    assert_eq!(c.0, StatusCode::FORBIDDEN);
    assert_eq!(f.upstream.hits.load(Ordering::SeqCst), 1);
    *f.upstream.info.lock().unwrap() = "---\n".into();
    // Explicitly expire persisted evidence and reopen to avoid wall-clock sleeps.
    let db = rusqlite::Connection::open(&f.app.config.cache.path).unwrap();
    db.execute("UPDATE responses SET expires = 0", []).unwrap();
    let restarted = App::new((*f.app.config).clone()).await.unwrap();
    assert_eq!(
        request(&restarted, "/rubygems/gems/demo-1.0.gem").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(f.upstream.archives.load(Ordering::SeqCst), 0);
}

#[test]
fn unsupported_inherited_policies_require_explicit_overrides() {
    let mut config = Config::default();
    config.policy.min_monthly_downloads = 1;
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("RubyGems monthly")
    );
    config.rubygems.min_monthly_downloads = Some(0);
    config.policy.install_hooks = HookPolicy::Deny;
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("RubyGems install-hook")
    );
    config.rubygems.install_hooks = Some(HookPolicy::Report);
    config.validate().unwrap();
    config.upstream.rubygems = "https://user:password@rubygems.org".into();
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn ambiguous_artifact_identities_and_oversized_metadata_fail_closed() {
    let f = fixture().await;
    let old = (Utc::now() - Duration::days(30)).to_rfc3339();
    // Both demo/version 2/platform 1.0 and demo-2/version 1.0 would use
    // demo-2-1.0.gem. Neither identity may authorize that collision.
    *f.upstream.info.lock().unwrap() = format!(
        "---\n{}{}",
        line("2-1.0", Some(&old)),
        line("1.0", Some(&old))
    );
    assert_eq!(
        request(&f.app, "/rubygems/gems/demo-2-1.0.gem").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.upstream.archives.load(Ordering::SeqCst), 0);
    let mut config = (*f.app.config).clone();
    config.upstream.max_metadata_mb = 1;
    let app = App::new(config).await.unwrap();
    assert_eq!(
        request(&app, "/rubygems/api/v1/dependencies?gems=oversized")
            .await
            .0,
        StatusCode::BAD_GATEWAY
    );
}
