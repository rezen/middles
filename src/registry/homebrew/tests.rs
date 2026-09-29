//! Synthetic signing key below is public test material; never configurable in production.
use super::*;
use axum::{extract::State, http::Request, response::IntoResponse};
use http_body_util::BodyExt;
use ring::{
    rand::SystemRandom,
    signature::{RSA_PSS_SHA512, RsaKeyPair},
};
use rusqlite::params;
use std::sync::{Mutex, RwLock};
use tower::ServiceExt;

const TEST_KEY: &[u8] = include_bytes!("../fixtures/homebrew-test-key.der");
const TEST_PUBLIC: &[u8] = include_bytes!("../fixtures/homebrew-test-public.der");
fn signed(payload: &Value) -> Vec<u8> {
    let protected = URL_SAFE_NO_PAD.encode(br#"{"alg":"PS512","b64":false,"crit":["b64"]}"#);
    let payload = serde_json::to_string(payload).unwrap();
    let key = RsaKeyPair::from_pkcs8(TEST_KEY).unwrap();
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PSS_SHA512,
        &SystemRandom::new(),
        format!("{protected}.{payload}").as_bytes(),
        &mut signature,
    )
    .unwrap();
    serde_json::to_vec(&json!({"payload":payload,"signatures":[{"header":{"kid":"homebrew-1"},"protected":protected,"signature":URL_SAFE_NO_PAD.encode(signature)}]})).unwrap()
}

#[test]
fn signed_api_accepts_homebrew_padding_and_rejects_tampering() {
    let payload = json!([{"name":"tool"}]);
    let body = signed(&payload);
    assert_eq!(verify_jws(&body, TEST_PUBLIC).unwrap(), payload);
    let mut jws: Value = serde_json::from_slice(&body).unwrap();
    let signature = jws["signatures"][0]["signature"].as_str().unwrap();
    jws["signatures"][0]["signature"] = json!(format!(
        "{signature}{}",
        "=".repeat((4 - signature.len() % 4) % 4)
    ));
    assert_eq!(
        verify_jws(&serde_json::to_vec(&jws).unwrap(), TEST_PUBLIC).unwrap(),
        payload
    );
    jws["payload"] = json!("[]");
    assert!(verify_jws(&serde_json::to_vec(&jws).unwrap(), TEST_PUBLIC).is_err());
}

#[derive(Clone)]
struct Object {
    body: Vec<u8>,
    media: &'static str,
    bottle: bool,
}
struct Graph {
    objects: BTreeMap<String, Object>,
    payload: Value,
    checksums: BTreeMap<String, String>,
    children: BTreeMap<String, String>,
    configs: BTreeMap<String, String>,
}
fn graph(rebuild: u64, platforms: &[&str]) -> Graph {
    graph_with_content(rebuild, platforms, 0)
}
fn graph_with_content(rebuild: u64, platforms: &[&str], content_revision: u32) -> Graph {
    let mut objects = BTreeMap::new();
    let mut files = serde_json::Map::new();
    let mut descriptors = Vec::new();
    let mut checksums = BTreeMap::new();
    let mut children = BTreeMap::new();
    let mut configs = BTreeMap::new();
    for tag in platforms {
        let (architecture, os) = platform_parts(tag);
        let bottle = format!("fixture bottle for {tag} content {content_revision}").into_bytes();
        let checksum = oci::digest(&bottle);
        let cfg = serde_json::to_vec(&json!({"architecture":architecture,"os":os,"rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","a".repeat(64))]}})).unwrap();
        let config = oci::digest(&cfg);
        let reference = format!(
            "1.0.0.{tag}{}",
            if rebuild == 0 {
                String::new()
            } else {
                format!(".{rebuild}")
            }
        );
        let annotations = json!({"com.github.package.type":"homebrew_bottle","org.opencontainers.image.ref.name":reference,"sh.brew.bottle.digest":checksum.trim_start_matches("sha256:"),"sh.brew.tab":"{}"});
        let child = serde_json::to_vec(&json!({"schemaVersion":2,"config":{"mediaType":oci::CONFIG,"digest":config,"size":cfg.len()},"layers":[{"mediaType":LAYER,"digest":checksum,"size":bottle.len()}],"annotations":annotations})).unwrap();
        let child_digest = oci::digest(&child);
        descriptors.push(json!({"mediaType":oci::MANIFEST,"digest":child_digest,"size":child.len(),"platform":{"architecture":architecture,"os":os},"annotations":annotations}));
        files.insert(tag.to_string(), json!({"sha256":checksum.trim_start_matches("sha256:"),"url":format!("https://ghcr.io/v2/homebrew/core/tool/blobs/{checksum}"),"cellar":":any_skip_relocation"}));
        for (path, body, media, bottle) in [
            (
                format!("blobs/{checksum}"),
                bottle,
                "application/octet-stream",
                true,
            ),
            (
                format!("blobs/{config}"),
                cfg,
                "application/octet-stream",
                false,
            ),
            (
                format!("manifests/{child_digest}"),
                child,
                oci::MANIFEST,
                false,
            ),
        ] {
            objects.insert(
                format!("/v2/homebrew/core/tool/{path}"),
                Object {
                    body,
                    media,
                    bottle,
                },
            );
        }
        checksums.insert(tag.to_string(), checksum);
        children.insert(tag.to_string(), child_digest);
        configs.insert(tag.to_string(), config);
    }
    let index =
        serde_json::to_vec_pretty(&json!({"schemaVersion":2,"manifests":descriptors})).unwrap();
    let reference = format!(
        "1.0.0{}",
        if rebuild == 0 {
            String::new()
        } else {
            format!("-{rebuild}")
        }
    );
    objects.insert(
        format!("/v2/homebrew/core/tool/manifests/{reference}"),
        Object {
            body: index,
            media: oci::INDEX,
            bottle: false,
        },
    );
    let payload = json!([{"name":"tool","tap":"homebrew/core","versions":{"stable":"1.0.0","bottle":true},"revision":0,"version_scheme":0,
        "ruby_source_checksum":{"sha256":"b".repeat(64)},"dependencies":[],"uses_from_macos":[],"variations":{},
        "bottle":{"stable":{"root_url":"https://ghcr.io/v2/homebrew/core","rebuild":rebuild,"files":files}}}]);
    objects.insert(
        "/api/formula.jws.json".into(),
        Object {
            body: signed(&payload),
            media: "application/json",
            bottle: false,
        },
    );
    Graph {
        objects,
        payload,
        checksums,
        children,
        configs,
    }
}
type Hit = (String, String, Option<String>);

#[derive(Clone)]
struct Upstream {
    graph: Arc<RwLock<Graph>>,
    hits: Arc<Mutex<Vec<Hit>>>,
    auth: bool,
    redirect: Arc<Mutex<Option<String>>>,
    fail_tokens: Arc<Mutex<bool>>,
}
async fn upstream(State(state): State<Upstream>, req: Request<Body>) -> Response {
    let path = req.uri().path().to_owned();
    let auth = req
        .headers()
        .get("authorization")
        .map(|v| v.to_str().unwrap().to_owned());
    state
        .hits
        .lock()
        .unwrap()
        .push((path.clone(), req.method().to_string(), auth.clone()));
    assert!(req.headers().get("cookie").is_none());
    if path == "/token" {
        assert!(auth.is_none());
        assert!(
            req.uri()
                .query()
                .unwrap()
                .contains("scope=repository%3Ahomebrew%2Fcore%2Ftool%3Apull")
        );
        return axum::Json(json!({"token":"anonymous-test-token","expires_in":60})).into_response();
    }
    if state.auth
        && path.starts_with("/v2/")
        && (auth.as_deref() != Some("Bearer anonymous-test-token")
            || *state.fail_tokens.lock().unwrap())
    {
        let host = req.headers().get("host").unwrap().to_str().unwrap();
        return Response::builder().status(401).header("www-authenticate",format!("Bearer realm=\"http://{host}/token\",service=\"ghcr.io\",scope=\"repository:homebrew/core/tool:pull\""))
            .body(Body::empty()).unwrap();
    }
    if path.starts_with("/v2/")
        && let Some(location) = state.redirect.lock().unwrap().clone()
    {
        return Response::builder()
            .status(307)
            .header("location", location)
            .body(Body::empty())
            .unwrap();
    }
    let g = state.graph.read().unwrap();
    let Some(object) = g.objects.get(&path) else {
        return (StatusCode::NOT_FOUND, "unknown fixture object").into_response();
    };
    let mut data = object.body.clone();
    let mut builder = Response::builder().header("content-type", object.media);
    if path.starts_with("/v2/") {
        builder = builder.header("docker-content-digest", oci::digest(&data));
    }
    if object.bottle && req.headers().contains_key("range") {
        data = data[..2].to_vec();
        builder = builder
            .status(206)
            .header("content-range", format!("bytes 0-1/{}", object.body.len()));
    }
    builder
        .header("content-length", data.len())
        .body(if req.method() == Method::HEAD {
            Body::empty()
        } else {
            Body::from(data)
        })
        .unwrap()
}
struct Fixture {
    app: App,
    state: Upstream,
    _dir: tempfile::TempDir,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn fixture(days: u32, auth: bool, platforms: &[&str], ttl: u64) -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = Upstream {
        graph: Arc::new(RwLock::new(graph(0, platforms))),
        hits: Arc::default(),
        auth,
        redirect: Arc::default(),
        fail_tokens: Arc::default(),
    };
    let router = Router::new()
        .fallback(any(upstream))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = crate::config::Config::default();
    cfg.cache.path = dir.path().join("cache.sqlite3");
    cfg.cache.metadata_ttl_secs = ttl;
    cfg.homebrew.enabled = true;
    cfg.homebrew.registry = origin.clone();
    cfg.homebrew.api = format!("{origin}/api");
    cfg.homebrew.platforms = platforms.iter().map(|s| s.to_string()).collect();
    cfg.homebrew.policy.min_age_days = Some(days);
    let mut app = App::new(cfg).await.unwrap();
    app.homebrew_key = TEST_PUBLIC;
    Fixture {
        app,
        state,
        _dir: dir,
        server,
    }
}
async fn request(
    app: &App,
    path: &str,
    method: Method,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().uri(path).method(method);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let response = app
        .clone()
        .router()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}
fn blob(f: &Fixture, tag: &str) -> String {
    format!(
        "/homebrew/v2/homebrew/core/tool/blobs/{}",
        f.state.graph.read().unwrap().checksums[tag]
    )
}
async fn ledger(app: &App) -> i64 {
    app.store
        .database(|db| db.query_row("SELECT COUNT(*) FROM homebrew_evidence", [], |r| r.get(0)))
        .await
        .unwrap()
}
async fn age(app: &App, days: i64) {
    app.store
        .database(move |db| {
            db.execute(
                "UPDATE first_seen SET timestamp=?1 WHERE key LIKE 'homebrew:%'",
                [Utc::now().timestamp() - days * 86_400],
            )?;
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn direct_blobs_heads_and_ranges_are_gated_before_artifact_access() {
    let f = fixture(7, false, &["arm64_tahoe"], 300).await;
    let path = blob(&f, "arm64_tahoe");
    for (method, headers) in [
        (Method::GET, vec![]),
        (Method::HEAD, vec![]),
        (Method::GET, vec![("range", "bytes=0-1")]),
    ] {
        let (status, _, body) = request(&f.app, &path, method.clone(), &headers).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        if method == Method::HEAD {
            assert!(body.is_empty());
        } else {
            assert!(String::from_utf8(body).unwrap().contains("eligible at"));
        }
    }
    assert_eq!(ledger(&f.app).await, 1);
    assert!(
        !f.state
            .hits
            .lock()
            .unwrap()
            .iter()
            .any(|(p, _, _)| path.ends_with(p))
    );
    age(&f.app, 8).await;
    let (status, headers, body) =
        request(&f.app, &path, Method::GET, &[("range", "bytes=0-1")]).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, b"fi");
    assert!(headers.contains_key("content-range"));
    let (status, _, body) = request(&f.app, &path, Method::HEAD, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
    let (status, _, body) = request(&f.app, &path, Method::HEAD, &[("range", "bytes=0-1")]).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(body.is_empty());
    let (_, _, stats) = request(&f.app, "/stats?ecosystem=homebrew", Method::GET, &[]).await;
    let stats: Value = serde_json::from_slice(&stats).unwrap();
    assert_eq!(stats["totals"]["full_downloads"], 0);
    assert_eq!(stats["totals"]["range_transfers"], 1);
    assert_eq!(stats["totals"]["bytes"], 2);
}

#[tokio::test]
async fn indexes_are_unchanged_discovery_and_unknown_digests_do_not_start_a_wait() {
    let f = fixture(7, false, &["arm64_tahoe"], 300).await;
    let raw = f.state.graph.read().unwrap().objects["/v2/homebrew/core/tool/manifests/1.0.0"]
        .body
        .clone();
    let (status, headers, body) = request(
        &f.app,
        "/homebrew/v2/homebrew/core/tool/manifests/1.0.0",
        Method::GET,
        &[("accept-encoding", "gzip")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, raw);
    assert_eq!(headers["docker-content-digest"], oci::digest(&raw));
    assert!(!headers.contains_key("content-encoding"));
    assert_eq!(ledger(&f.app).await, 0);
    let unknown = format!(
        "/homebrew/v2/homebrew/core/tool/blobs/sha256:{}",
        "f".repeat(64)
    );
    assert_eq!(
        request(&f.app, &unknown, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&f.app).await, 0);
    let child = f.state.graph.read().unwrap().children["arm64_tahoe"].clone();
    assert_eq!(
        request(
            &f.app,
            &format!("/homebrew/v2/homebrew/core/tool/manifests/{child}"),
            Method::HEAD,
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&f.app).await, 1);
}

#[tokio::test]
async fn observation_and_associations_survive_restart_and_policy_changes() {
    let f = fixture(0, false, &["arm64_tahoe"], 300).await;
    let path = blob(&f, "arm64_tahoe");
    assert_eq!(
        request(
            &f.app,
            &path,
            Method::GET,
            &[("authorization", "Bearer QQ==")]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(ledger(&f.app).await, 1);
    age(&f.app, 8).await;
    let mut config = (*f.app.config).clone();
    config.homebrew.policy.min_age_days = Some(7);
    let mut restarted = App::new(config.clone()).await.unwrap();
    restarted.homebrew_key = TEST_PUBLIC;
    let before = f.state.hits.lock().unwrap().len();
    assert_eq!(
        request(&restarted, &path, Method::GET, &[]).await.0,
        StatusCode::OK
    );
    // Only the bottle is fetched; persisted raw metadata and verified catalogue remain usable.
    assert_eq!(f.state.hits.lock().unwrap().len(), before + 1);
    config.homebrew.policy.min_age_days = Some(9);
    let mut stricter = App::new(config).await.unwrap();
    stricter.homebrew_key = TEST_PUBLIC;
    assert_eq!(
        request(&stricter, &path, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&stricter).await, 1);
}

#[tokio::test]
async fn platform_additions_do_not_reset_waits_but_rebuilds_and_definitions_do() {
    let f = fixture(7, false, &["arm64_tahoe", "arm64_linux"], 1).await;
    // Initially Linux is absent even though the operator has enabled its tag.
    *f.state.graph.write().unwrap() = graph(0, &["arm64_tahoe"]);
    let path = blob(&f, "arm64_tahoe");
    assert_eq!(
        request(&f.app, &path, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    age(&f.app, 8).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    *f.state.graph.write().unwrap() = graph(0, &["arm64_tahoe", "arm64_linux"]);
    assert_eq!(
        request(&f.app, &path, Method::GET, &[]).await.0,
        StatusCode::OK
    );
    assert_eq!(ledger(&f.app).await, 1);
    assert_eq!(
        request(&f.app, &blob(&f, "arm64_linux"), Method::GET, &[])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&f.app).await, 2);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    *f.state.graph.write().unwrap() = graph(1, &["arm64_tahoe", "arm64_linux"]);
    assert_eq!(
        request(&f.app, &path, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&f.app).await, 3);
    age(&f.app, 8).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    {
        let mut g = f.state.graph.write().unwrap();
        g.payload[0]["ruby_source_checksum"]["sha256"] = json!("c".repeat(64));
        let body = signed(&g.payload);
        g.objects.get_mut("/api/formula.jws.json").unwrap().body = body;
    }
    assert_eq!(
        request(&f.app, &path, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&f.app).await, 4);
}

#[tokio::test]
async fn changed_bottle_content_cannot_reuse_an_old_wait() {
    let f = fixture(7, false, &["arm64_tahoe"], 1).await;
    let old = blob(&f, "arm64_tahoe");
    assert_eq!(
        request(&f.app, &old, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    age(&f.app, 8).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    *f.state.graph.write().unwrap() = graph_with_content(0, &["arm64_tahoe"], 1);
    let new = blob(&f, "arm64_tahoe");
    assert_ne!(old, new);
    assert_eq!(
        request(&f.app, &new, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&f.app).await, 2);
    assert_eq!(
        request(&f.app, &old, Method::GET, &[]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(ledger(&f.app).await, 2);
}

#[test]
fn unsupported_inherited_policies_only_validate_when_enabled() {
    let mut cfg = crate::config::Config::default();
    cfg.policy.min_monthly_downloads = 1;
    cfg.rubygems.min_monthly_downloads = Some(0);
    assert!(cfg.validate().is_ok());
    cfg.homebrew.enabled = true;
    assert!(
        cfg.validate()
            .unwrap_err()
            .to_string()
            .contains("Homebrew monthly")
    );
    cfg.homebrew.policy.min_monthly_downloads = Some(0);
    cfg.policy.install_hooks = crate::inspection::HookPolicy::Deny;
    cfg.rubygems.install_hooks = Some(crate::inspection::HookPolicy::Report);
    assert!(
        cfg.validate()
            .unwrap_err()
            .to_string()
            .contains("Homebrew install-hook")
    );
    cfg.homebrew.policy.install_hooks = Some(crate::inspection::HookPolicy::Report);
    assert!(cfg.validate().is_ok());
    assert!(formula_name("7zip"));
    assert!(!formula_name("openssl@3@4"));
    assert_eq!(
        parse_path("openssl/3/manifests/3.6.4_1").unwrap().0,
        "openssl/3"
    );
}

#[tokio::test]
async fn signatures_hashes_oversized_and_missing_evidence_fail_even_at_zero_days() {
    for invalid in [
        "signature",
        "manifest",
        "config",
        "external",
        "platform",
        "definition",
        "oversized",
    ] {
        let f = fixture(0, false, &["arm64_tahoe"], 300).await;
        let path = blob(&f, "arm64_tahoe");
        {
            let mut g = f.state.graph.write().unwrap();
            match invalid {
                "signature" => {
                    let mut j: Value =
                        serde_json::from_slice(&g.objects["/api/formula.jws.json"].body).unwrap();
                    j["payload"] = json!("[]");
                    g.objects.get_mut("/api/formula.jws.json").unwrap().body =
                        serde_json::to_vec(&j).unwrap();
                }
                "manifest" => {
                    let key = format!(
                        "/v2/homebrew/core/tool/manifests/{}",
                        g.children["arm64_tahoe"]
                    );
                    g.objects.get_mut(&key).unwrap().body.push(b' ');
                }
                "config" => {
                    let key = format!("/v2/homebrew/core/tool/blobs/{}", g.configs["arm64_tahoe"]);
                    g.objects.get_mut(&key).unwrap().body.push(b' ');
                }
                "definition" => {
                    g.payload[0]["ruby_source_checksum"] = Value::Null;
                    let body = signed(&g.payload);
                    g.objects.get_mut("/api/formula.jws.json").unwrap().body = body;
                }
                "oversized" => {
                    g.objects
                        .get_mut("/v2/homebrew/core/tool/manifests/1.0.0")
                        .unwrap()
                        .body = vec![b' '; MAX_MANIFEST + 1];
                }
                "external" | "platform" => {
                    let mut doc: Value = serde_json::from_slice(
                        &g.objects["/v2/homebrew/core/tool/manifests/1.0.0"].body,
                    )
                    .unwrap();
                    if invalid == "external" {
                        doc["manifests"][0]["urls"] = json!(["https://evil.example/bottle"]);
                    } else {
                        doc["manifests"][0]["platform"]["os"] = json!("other");
                    }
                    g.objects
                        .get_mut("/v2/homebrew/core/tool/manifests/1.0.0")
                        .unwrap()
                        .body = serde_json::to_vec(&doc).unwrap();
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(
            request(&f.app, &path, Method::GET, &[]).await.0,
            StatusCode::BAD_GATEWAY,
            "{invalid}"
        );
        assert_eq!(ledger(&f.app).await, 0, "{invalid}");
        assert!(
            !f.state
                .hits
                .lock()
                .unwrap()
                .iter()
                .any(|(p, _, _)| path.ends_with(p)),
            "{invalid}"
        );
    }
}

#[tokio::test]
async fn concurrent_misses_coalesce_metadata_and_anonymous_tokens_never_reach_sqlite() {
    let f = fixture(0, true, &["arm64_tahoe"], 300).await;
    let path = blob(&f, "arm64_tahoe");
    let outcomes =
        futures_util::future::join_all((0..8).map(|_| request(&f.app, &path, Method::GET, &[])))
            .await;
    assert!(outcomes.iter().all(|r| r.0 == StatusCode::OK));
    assert_eq!(ledger(&f.app).await, 1);
    let hits = f.state.hits.lock().unwrap().clone();
    assert_eq!(hits.iter().filter(|(p, _, _)| p == "/token").count(), 1);
    assert_eq!(
        hits.iter()
            .filter(|(p, _, _)| p == "/api/formula.jws.json")
            .count(),
        1
    );
    assert!(
        !hits
            .iter()
            .any(|(_, _, auth)| auth.as_deref() == Some("Bearer QQ=="))
    );
    let persisted = f
        .app
        .store
        .database(|db| {
            let mut s = db.prepare("SELECT body FROM responses")?;
            s.query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
        .unwrap();
    assert!(persisted.iter().all(|b| {
        !b.windows(b"anonymous-test-token".len())
            .any(|v| v == b"anonymous-test-token")
    }));
    *f.state.fail_tokens.lock().unwrap() = true;
    assert_eq!(
        request(&f.app, &path, Method::GET, &[]).await.0,
        StatusCode::BAD_GATEWAY
    );
    assert!(
        f.state
            .hits
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _, _)| p == "/token")
            .count()
            <= 3
    );
}

#[tokio::test]
async fn configuration_paths_methods_credentials_and_redirects_fail_closed() {
    let f = fixture(0, false, &["arm64_tahoe"], 300).await;
    for (path, method, headers) in [
        (
            "/homebrew/v2/homebrew/core/tool/blobs/not-a-digest",
            Method::GET,
            vec![],
        ),
        (
            "/homebrew/v2/homebrew/core/tool%2Fother/blobs/x",
            Method::GET,
            vec![],
        ),
        (
            "/homebrew/v2/homebrew/core/tool/manifests/1.0.0",
            Method::POST,
            vec![],
        ),
        (
            "/homebrew/v2/homebrew/core/tool/manifests/1.0.0",
            Method::GET,
            vec![("authorization", "Bearer secret")],
        ),
        ("/homebrew/https://evil.example/bottle", Method::GET, vec![]),
        (
            "/homebrew/v2/other/core/tool/manifests/1",
            Method::GET,
            vec![],
        ),
    ] {
        assert!(
            request(&f.app, path, method, &headers)
                .await
                .0
                .is_client_error()
        );
    }
    assert!(f.state.hits.lock().unwrap().is_empty());
    *f.state.redirect.lock().unwrap() = Some("http://127.0.0.1:1/anything".into());
    assert_eq!(
        request(&f.app, &blob(&f, "arm64_tahoe"), Method::GET, &[])
            .await
            .0,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(ledger(&f.app).await, 0);
    let mut cfg = (*f.app.config).clone();
    cfg.homebrew.enabled = false;
    cfg.homebrew.policy.min_monthly_downloads = Some(1);
    assert!(cfg.validate().is_ok());
    cfg.homebrew.enabled = true;
    assert!(cfg.validate().unwrap_err().to_string().contains("monthly"));
    cfg.homebrew.policy.min_monthly_downloads = Some(0);
    cfg.homebrew.policy.install_hooks = Some(crate::inspection::HookPolicy::Deny);
    assert!(
        cfg.validate()
            .unwrap_err()
            .to_string()
            .contains("install-hook")
    );
    cfg.homebrew.policy.install_hooks = Some(crate::inspection::HookPolicy::Report);
    cfg.homebrew.registry = "http://ghcr.io".into();
    assert!(cfg.validate().is_err());
    let parsed: crate::config::Config=toml::from_str("[homebrew]\nenabled = true\nmin_age_days = 0\nmin_monthly_downloads = 0\ninstall_hooks = \"report\"\nplatforms = [\"arm64_tahoe\"]\n").unwrap();
    assert!(parsed.validate().is_ok());
}

#[tokio::test]
async fn warming_records_verified_evidence_without_artifact_transfers() {
    let f = fixture(7, false, &["arm64_tahoe"], 300).await;
    let (status, _, body) = request(&f.app, "/homebrew/warm/tool", Method::GET, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["bottles"][0]["eligible"], false);
    assert_eq!(doc["install_hooks"]["status"], "unavailable");
    assert_eq!(ledger(&f.app).await, 1);
    let (_, _, stats) = request(&f.app, "/stats?ecosystem=homebrew", Method::GET, &[]).await;
    let stats: Value = serde_json::from_slice(&stats).unwrap();
    assert_eq!(stats["totals"]["bytes"], 0);
    let config = f.state.graph.read().unwrap().configs["arm64_tahoe"].clone();
    assert_eq!(
        request(
            &f.app,
            &format!("/homebrew/v2/homebrew/core/tool/blobs/{config}"),
            Method::GET,
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Verify inclusive seconds with exactly the same clock value.
    let p = f.app.config.policy_for(Ecosystem::Homebrew);
    assert!(p.allows_timestamp(10, 10 + 7 * 86_400));
    assert!(!p.allows_timestamp(10, 9 + 7 * 86_400));
    f.app
        .store
        .database(|db| {
            db.execute(
                "DELETE FROM first_seen WHERE key LIKE 'homebrew:%'",
                params![],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        request(&f.app, &blob(&f, "arm64_tahoe"), Method::GET, &[])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}
