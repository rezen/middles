//! Official stable Homebrew bottles. Age is durable local observation, not publication time.
use crate::{
    App,
    cache::RawMetadata,
    config::HomebrewAgeBasis,
    error::{Error, Result},
    registry::{Ecosystem, oci},
    stats::Identity,
};
use axum::{
    Router,
    body::Body,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ring::signature::{RSA_PSS_2048_8192_SHA512, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_CONFIG: usize = 256 * 1024;
const MAX_DESCRIPTORS: usize = 64;
const LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

pub fn platform(value: &str) -> bool {
    matches!(
        value,
        "arm64_tahoe"
            | "arm64_sequoia"
            | "arm64_sonoma"
            | "sonoma"
            | "sequoia"
            | "arm64_linux"
            | "x86_64_linux"
    )
}
fn platform_parts(tag: &str) -> (&str, &str) {
    (
        if tag.starts_with("arm64_") {
            "arm64"
        } else {
            "amd64"
        },
        if tag.ends_with("linux") {
            "linux"
        } else {
            "darwin"
        },
    )
}
fn formula_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 214
        && value.bytes().filter(|b| *b == b'@').count() <= 1
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"@+._-".contains(&b))
}
fn repository(name: &str) -> String {
    name.replace('@', "/").replace('+', "x")
}
fn registry<'a>(app: &'a App, repo: &str) -> oci::Registry<'a> {
    oci::Registry {
        upstream: &app.config.homebrew.registry,
        repository: format!("homebrew/core/{repo}"),
    }
}

fn valid_repository(value: &str) -> bool {
    value.len() <= 214
        && value.split('/').count() <= 2
        && value.split('/').all(|p| {
            !p.is_empty()
                && p.as_bytes()[0].is_ascii_alphanumeric()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
}
fn valid_tag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub(crate) fn routes() -> Router<App> {
    Router::new().route("/homebrew/{*path}", any(handle))
}

pub(crate) async fn handle(
    State(app): State<App>,
    Path(path): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let result = dispatch(
        &app,
        &path,
        uri.path(),
        uri.query().is_some(),
        &method,
        &headers,
    )
    .await;
    match result {
        Ok(mut r) => {
            r.headers_mut().insert(
                "docker-distribution-api-version",
                "registry/2.0".parse().unwrap(),
            );
            r
        }
        Err(e) => {
            tracing::warn!(status = %e.0, reason = %e.1, "Homebrew request rejected");
            let code = match e.0 {
                StatusCode::FORBIDDEN => "DENIED",
                StatusCode::NOT_FOUND => "NAME_UNKNOWN",
                StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_ACCEPTABLE => "UNSUPPORTED",
                StatusCode::BAD_REQUEST => "NAME_INVALID",
                _ => "UNKNOWN",
            };
            let body =
                serde_json::to_vec(&json!({"errors":[{"code":code,"message":e.1}]})).unwrap();
            Response::builder()
                .status(e.0)
                .header("content-type", "application/json")
                .header("content-length", body.len())
                .header("cache-control", "no-store")
                .header("docker-distribution-api-version", "registry/2.0")
                .body(if method == Method::HEAD {
                    Body::empty()
                } else {
                    Body::from(body)
                })
                .unwrap()
        }
    }
}

fn accepted(headers: &HeaderMap, media: &str) -> Result<()> {
    if let Some(accept) = headers.get("accept") {
        let accept = accept
            .to_str()
            .map_err(|_| Error::bad("invalid Accept header"))?;
        if !accept.split(',').any(|item| {
            let mut parts = item.trim().split(';');
            let kind = parts.next().unwrap_or("");
            (kind == media || kind == "*/*" || kind == "application/*")
                && parts.all(|p| {
                    p.trim()
                        .strip_prefix("q=")
                        .is_none_or(|q| q.parse::<f32>().is_ok_and(|q| q > 0.0 && q <= 1.0))
                })
        }) {
            return Err(Error(
                StatusCode::NOT_ACCEPTABLE,
                "unsupported Homebrew representation".into(),
            ));
        }
    }
    Ok(())
}

async fn dispatch(
    app: &App,
    path: &str,
    raw_path: &str,
    query: bool,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Response> {
    if !app.config.homebrew.enabled {
        return Err(Error::missing("Homebrew adapter is disabled"));
    }
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Err(Error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Homebrew supports read-only GET and HEAD".into(),
        ));
    }
    if query || raw_path.contains('%') || path.contains(['\\', '\0']) {
        return Err(Error::bad("encoded or ambiguous Homebrew path"));
    }
    if headers
        .get_all("authorization")
        .iter()
        .any(|v| v.as_bytes() != b"Bearer QQ==")
    {
        return Err(Error::denied("Homebrew client credentials are unsupported"));
    }
    if path == "v2/" {
        return Response::builder()
            .header("content-length", "0")
            .body(Body::empty())
            .map_err(|_| Error::internal("response"));
    }
    if let Some(name) = path.strip_prefix("warm/") {
        if !formula_name(name) {
            return Err(Error::bad("invalid Homebrew formula name"));
        }
        let release = resolve(app, &repository(name)).await?;
        if release.name != name {
            return Err(Error::bad("ambiguous formula mapping"));
        }
        let mut bottles = Vec::new();
        let mut dependencies = release.dependencies(
            app.config
                .homebrew
                .platforms
                .iter()
                .any(|p| p.ends_with("linux")),
        );
        for tag in &app.config.homebrew.platforms {
            if release.file(tag).is_none() {
                continue;
            }
            let evidence = verify(app, &release, tag).await?;
            let first_seen = observe(app, &evidence).await?;
            let age = if app.config.policy_for(Ecosystem::Homebrew).min_age_days == 0 {
                None
            } else {
                Some(age_timestamp(app, &evidence, first_seen)?)
            };
            dependencies.extend(
                evidence.details["runtime_dependencies"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|d| d.as_str().map(str::to_owned)),
            );
            bottles.push(json!({"platform":tag,"identity":evidence.identity,"first_seen":first_seen,
                "age_basis":age.map(|(_,basis)| basis).unwrap_or("disabled"),
                "age_timestamp":age.map(|(timestamp,_)| timestamp),
                "eligible_at":age.map(|(timestamp,_)| eligible_at(app, timestamp)),
                "eligible":age.is_none_or(|(timestamp,_)| app.config.policy_for(Ecosystem::Homebrew).allows_timestamp(timestamp,Utc::now().timestamp()))}));
        }
        if bottles.is_empty() {
            return Err(Error::denied(
                "formula has no bottle on the configured platforms",
            ));
        }
        dependencies.sort();
        dependencies.dedup();
        let body = serde_json::to_vec(&json!({"formula":name,"dependencies":dependencies,"bottles":bottles,
            "install_hooks":{"status":"unavailable","limitations":"Bottles do not establish absence of post-install execution; formula Ruby is not executed."}})).unwrap();
        return Response::builder()
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .header("cache-control", "no-store")
            .body(if *method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(body)
            })
            .map_err(|_| Error::internal("response"));
    }
    let tail = path
        .strip_prefix("v2/homebrew/core/")
        .ok_or_else(|| Error::missing("unsupported Homebrew download class or namespace"))?;
    let (repo, endpoint, reference) = parse_path(tail)?;
    // Reject representations before network traffic or any observation.
    if endpoint == "manifests" {
        accepted(headers, oci::INDEX).or_else(|_| accepted(headers, oci::MANIFEST))?;
    } else {
        accepted(headers, "application/octet-stream")
            .or_else(|_| accepted(headers, oci::CONFIG))?;
    }
    let release = resolve(app, repo).await?;
    if endpoint == "manifests" && (reference == release.tag || reference == release.index.digest) {
        accepted(headers, oci::INDEX)?;
        return raw_response(&release.index, method);
    }
    if endpoint == "manifests" {
        for tag in &app.config.homebrew.platforms {
            if let Some(d) = release.descriptor(tag)
                && d.digest == reference
            {
                accepted(headers, oci::MANIFEST)?;
                let evidence = verify(app, &release, tag).await?;
                authorize(app, &evidence).await?;
                return raw_response(&evidence.manifest, method);
            }
        }
        return Err(Error::denied(
            "manifest is not a supported current Homebrew bottle",
        ));
    }
    let mut blocked = None;
    for tag in &app.config.homebrew.platforms {
        if release.file(tag).is_none() {
            continue;
        }
        // Known bottle digests need only their selected platform. An unknown config
        // digest can trigger at most eight verified children of this known formula.
        let is_known_bottle = app.config.homebrew.platforms.iter().any(|p| {
            release
                .file(p)
                .and_then(|v| v["sha256"].as_str())
                .is_some_and(|s| reference == format!("sha256:{s}"))
        });
        if is_known_bottle
            && release
                .file(tag)
                .and_then(|v| v["sha256"].as_str())
                .is_none_or(|s| reference != format!("sha256:{s}"))
        {
            continue;
        }
        let evidence = verify(app, &release, tag).await?;
        let bottle = reference == evidence.bottle;
        let config = reference == evidence.config.digest;
        if !bottle && !config {
            continue;
        }
        accepted(
            headers,
            if config {
                evidence.config.kind()
            } else {
                "application/octet-stream"
            },
        )?;
        if let Err(e) = authorize(app, &evidence).await {
            blocked = Some(e);
            continue;
        }
        if config {
            return raw_response(&evidence.config, method);
        }
        let identity = Identity::new(Ecosystem::Homebrew, &release.name, &evidence.release);
        return app
            .oci
            .bottle(
                app,
                registry(app, repo),
                oci::Bottle {
                    digest: reference,
                    size: evidence.size,
                },
                method.clone(),
                headers,
                identity,
            )
            .await;
    }
    Err(blocked.unwrap_or_else(|| Error::denied("digest is not a verified bottle/config on a configured platform; warm the formula metadata")))
}

fn parse_path(tail: &str) -> Result<(&str, &str, &str)> {
    let (prefix, reference) = tail
        .rsplit_once('/')
        .ok_or_else(|| Error::bad("invalid registry path"))?;
    let (repo, endpoint) = prefix
        .rsplit_once('/')
        .ok_or_else(|| Error::bad("invalid registry path"))?;
    if !valid_repository(repo)
        || !matches!(endpoint, "manifests" | "blobs")
        || !(oci::valid_digest(reference) || endpoint == "manifests" && valid_tag(reference))
    {
        return Err(Error::bad("unsupported or malformed registry identity"));
    }
    Ok((repo, endpoint, reference))
}

fn raw_response(raw: &RawMetadata, method: &Method) -> Result<Response> {
    Response::builder()
        .header("content-type", &raw.media_type)
        .header("content-length", raw.body.len())
        .header("docker-content-digest", &raw.digest)
        .header("cache-control", "no-store")
        .body(if *method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(raw.body.clone())
        })
        .map_err(|_| Error::internal("invalid verified metadata headers"))
}

pub(crate) fn verify_jws(body: &[u8], key: &[u8]) -> Result<Value> {
    let jws: Value = serde_json::from_slice(body)
        .map_err(|_| Error::upstream("invalid Homebrew signed API JSON"))?;
    let payload = jws["payload"]
        .as_str()
        .ok_or_else(|| Error::upstream("missing Homebrew signed payload"))?;
    let signatures = jws["signatures"]
        .as_array()
        .filter(|s| s.len() <= 8)
        .ok_or_else(|| Error::upstream("invalid Homebrew signatures"))?;
    let signature = signatures
        .iter()
        .find(|s| s["header"]["kid"] == "homebrew-1")
        .ok_or_else(|| Error::upstream("Homebrew signing key not found"))?;
    let protected = signature["protected"]
        .as_str()
        .filter(|s| s.len() <= 4096)
        .ok_or_else(|| Error::upstream("invalid JWS protected header"))?;
    let header = URL_SAFE_NO_PAD
        .decode(protected.trim_end_matches('='))
        .map_err(|_| Error::upstream("invalid JWS header encoding"))?;
    let header: Value =
        serde_json::from_slice(&header).map_err(|_| Error::upstream("invalid JWS header"))?;
    if header != json!({"alg":"PS512","b64":false,"crit":["b64"]}) {
        return Err(Error::upstream(
            "unsupported Homebrew JWS algorithm or critical header",
        ));
    }
    let signature = signature["signature"]
        .as_str()
        .filter(|s| s.len() <= 2048)
        .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok())
        .ok_or_else(|| Error::upstream("invalid JWS signature encoding"))?;
    let message = format!("{protected}.{payload}");
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, key)
        .verify(message.as_bytes(), &signature)
        .map_err(|_| Error::upstream("Homebrew API signature verification failed"))?;
    serde_json::from_str(payload).map_err(|_| Error::upstream("invalid signed Homebrew payload"))
}

async fn catalog(app: &App) -> Result<Arc<Value>> {
    let cfg = &app.config.homebrew;
    let url = format!("{}/formula.jws.json", cfg.api.trim_end_matches('/'));
    let key = format!(
        "homebrew-catalog-v1:{}:{}:{}",
        url,
        oci::digest(app.homebrew_key),
        cfg.platforms.join(",")
    );
    app.store.get(key, false, || async {
        let _permit = app.metadata_permits.acquire().await.map_err(|_| Error::internal("shutdown"))?;
        let response = app.artifact_client.get(&url).timeout(Duration::from_secs(app.config.upstream.timeout_secs)).send().await
            .map_err(|_| Error::upstream("Homebrew signed API request failed"))?;
        if response.status() != StatusCode::OK { return Err(Error::upstream(format!("Homebrew signed API returned {}", response.status()))); }
        let body = oci::bounded_body(response, cfg.max_api_mb * 1024 * 1024).await?;
        let platforms = cfg.platforms.clone();
        let signing_key = app.homebrew_key;
        tokio::task::spawn_blocking(move || {
            let payload = verify_jws(&body, signing_key)?;
            let formulas = payload.as_array().filter(|v| v.len() <= 20_000).ok_or_else(|| Error::upstream("invalid signed formula catalogue"))?;
            // Cache only verified policy inputs for configured platforms; omit analytics,
            // unrelated platform files and global tap commits from the derived catalogue.
            let mut catalogue = serde_json::Map::new();
            for f in formulas {
                let Some(name) = f["name"].as_str().filter(|n| formula_name(n)) else { continue; };
                if f["tap"] != "homebrew/core" { continue; }
                let mut info = serde_json::Map::new();
                for field in ["versions", "revision", "version_scheme", "ruby_source_checksum", "dependencies", "uses_from_macos", "uses_from_macos_bounds"] {
                    info.insert(field.into(), f[field].clone());
                }
                let mut files = serde_json::Map::new();
                for p in &platforms {
                    if let Some(file) = f["bottle"]["stable"]["files"].get(p) { files.insert(p.clone(), file.clone()); }
                }
                info.insert("bottle".into(), json!({"stable":{"rebuild":f["bottle"]["stable"]["rebuild"],"root_url":f["bottle"]["stable"]["root_url"],"files":files}}));
                let mut variations = serde_json::Map::new();
                for p in &platforms {
                    if let Some(v) = f["variations"].get(p) {
                        variations.insert(p.clone(), json!({"dependencies":v["dependencies"],"uses_from_macos":v["uses_from_macos"],"uses_from_macos_bounds":v["uses_from_macos_bounds"],"ruby_source_checksum":v["ruby_source_checksum"]}));
                    }
                }
                info.insert("variations".into(), Value::Object(variations));
                if catalogue.insert(name.to_owned(), Value::Object(info)).is_some() { return Err(Error::upstream("duplicate signed formula")); }
            }
            serde_json::to_vec(&catalogue).map_err(|_| Error::internal("catalogue serialization"))
        }).await.map_err(|_| Error::internal("signature verifier task failed"))?
    }).await
}

#[derive(Clone, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    platform: Option<Platform>,
    urls: Option<Value>,
}
#[derive(Clone, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}
#[derive(Deserialize)]
struct Index {
    #[serde(rename = "schemaVersion")]
    schema: u32,
    manifests: Vec<Descriptor>,
}
#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "schemaVersion")]
    schema: u32,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}
struct Release {
    name: String,
    repo: String,
    info: Value,
    version: String,
    revision: u64,
    rebuild: u64,
    tag: String,
    index: Arc<RawMetadata>,
    descriptors: Vec<Descriptor>,
}
impl Release {
    fn file(&self, tag: &str) -> Option<&Value> {
        self.info["bottle"]["stable"]["files"].get(tag)
    }
    fn platform_reference(&self, tag: &str) -> String {
        format!(
            "{}.{tag}{}",
            self.version,
            if self.rebuild == 0 {
                String::new()
            } else {
                format!(".{}", self.rebuild)
            }
        )
    }
    fn descriptor(&self, tag: &str) -> Option<&Descriptor> {
        let reference = self.platform_reference(tag);
        self.descriptors
            .iter()
            .find(|d| d.annotations.get("org.opencontainers.image.ref.name") == Some(&reference))
    }
    fn dependencies(&self, linux: bool) -> Vec<String> {
        let mut deps = Vec::new();
        for p in self.info["variations"]
            .as_object()
            .into_iter()
            .flat_map(|o| o.values())
            .chain(std::iter::once(&self.info))
        {
            for field in ["dependencies", "uses_from_macos"] {
                if field == "uses_from_macos" && !linux {
                    continue;
                }
                for dep in p[field].as_array().into_iter().flatten() {
                    if let Some(name) = dep.as_str().filter(|n| formula_name(n)) {
                        deps.push(name.to_owned());
                    }
                    if let Some(o) = dep.as_object() {
                        deps.extend(o.keys().filter(|n| formula_name(n)).cloned());
                    }
                }
            }
        }
        deps.sort();
        deps.dedup();
        deps
    }
}

async fn resolve(app: &App, repo: &str) -> Result<Release> {
    let catalogue = catalog(app).await?;
    let mut matches = catalogue
        .as_object()
        .ok_or_else(|| Error::upstream("invalid verified catalogue"))?
        .iter()
        .filter(|(name, _)| repository(name) == repo);
    let (name, info) = matches.next().ok_or_else(|| {
        Error::missing("only current stable official core formula bottles are supported")
    })?;
    if matches.next().is_some() {
        return Err(Error::denied("ambiguous Homebrew repository mapping"));
    }
    let stable = info["versions"]["stable"]
        .as_str()
        .ok_or_else(|| Error::denied("no stable formula version"))?;
    let revision = info["revision"]
        .as_u64()
        .ok_or_else(|| Error::upstream("missing formula revision"))?;
    let rebuild = info["bottle"]["stable"]["rebuild"]
        .as_u64()
        .ok_or_else(|| Error::denied("no stable bottle rebuild evidence"))?;
    if info["bottle"]["stable"]["root_url"] != "https://ghcr.io/v2/homebrew/core"
        || info["versions"]["bottle"] != true
    {
        return Err(Error::denied(
            "unsupported bottle source or source-only formula",
        ));
    }
    let version = format!(
        "{stable}{}",
        if revision == 0 {
            String::new()
        } else {
            format!("_{revision}")
        }
    );
    let tag = format!(
        "{version}{}",
        if rebuild == 0 {
            String::new()
        } else {
            format!("-{rebuild}")
        }
    );
    if !valid_tag(&tag) {
        return Err(Error::denied("unsupported Homebrew bottle version"));
    }
    let raw = app
        .oci
        .raw(
            app,
            registry(app, repo),
            &format!("manifests/{tag}"),
            oci::INDEX,
            MAX_MANIFEST,
        )
        .await?;
    if raw.kind() != oci::INDEX {
        return Err(Error::upstream("unsupported bottle index media type"));
    }
    let index: Index =
        serde_json::from_slice(&raw.body).map_err(|_| Error::upstream("invalid bottle index"))?;
    if index.schema != 2
        || index.manifests.is_empty()
        || index.manifests.len() > MAX_DESCRIPTORS
        || index.manifests.iter().any(|d| {
            d.media_type != oci::MANIFEST
                || !oci::valid_digest(&d.digest)
                || d.size == 0
                || d.size > MAX_MANIFEST as u64
                || d.urls.is_some()
        })
    {
        return Err(Error::upstream("unsupported bottle index descriptor graph"));
    }
    let mut seen = std::collections::HashSet::new();
    for d in &index.manifests {
        if let Some(reference) = d.annotations.get("org.opencontainers.image.ref.name")
            && !seen.insert(reference)
        {
            return Err(Error::upstream("ambiguous bottle platform descriptor"));
        }
    }
    Ok(Release {
        name: name.clone(),
        repo: repo.to_owned(),
        info: info.clone(),
        version,
        revision,
        rebuild,
        tag,
        index: raw,
        descriptors: index.manifests,
    })
}

struct Evidence {
    identity: String,
    release: String,
    details: Value,
    bottle: String,
    size: u64,
    manifest: Arc<RawMetadata>,
    config: Arc<RawMetadata>,
}
async fn verify(app: &App, r: &Release, tag: &str) -> Result<Evidence> {
    let file = r
        .file(tag)
        .ok_or_else(|| Error::denied("bottle platform is unavailable"))?;
    let sha = file["sha256"]
        .as_str()
        .ok_or_else(|| Error::upstream("missing signed bottle checksum"))?;
    let bottle = format!("sha256:{sha}");
    if !oci::valid_digest(&bottle)
        || file["url"] != format!("https://ghcr.io/v2/homebrew/core/{}/blobs/{bottle}", r.repo)
    {
        return Err(Error::upstream("invalid signed bottle identity"));
    }
    let source = r.info["ruby_source_checksum"]["sha256"]
        .as_str()
        .ok_or_else(|| Error::upstream("formula execution definition checksum unavailable"))?;
    if !oci::valid_digest(&format!("sha256:{source}")) {
        return Err(Error::upstream("invalid formula definition checksum"));
    }
    let d = r
        .descriptor(tag)
        .ok_or_else(|| Error::upstream("signed bottle has no platform manifest"))?;
    let (arch, os) = platform_parts(tag);
    if !d
        .platform
        .as_ref()
        .is_some_and(|p| p.architecture == arch && p.os == os)
        || d.annotations
            .get("sh.brew.bottle.digest")
            .is_none_or(|s| s != sha)
    {
        return Err(Error::upstream("index/signed bottle platform mismatch"));
    }
    let manifest = app
        .oci
        .raw(
            app,
            registry(app, &r.repo),
            &format!("manifests/{}", d.digest),
            oci::MANIFEST,
            MAX_MANIFEST,
        )
        .await?;
    if manifest.digest != d.digest
        || manifest.body.len() as u64 != d.size
        || manifest.kind() != oci::MANIFEST
    {
        return Err(Error::upstream("child manifest descriptor mismatch"));
    }
    let child: Manifest = serde_json::from_slice(&manifest.body)
        .map_err(|_| Error::upstream("invalid bottle child manifest"))?;
    if child.schema != 2
        || child.layers.len() != 1
        || child.config.media_type != oci::CONFIG
        || child.config.urls.is_some()
        || !oci::valid_digest(&child.config.digest)
        || child.config.size == 0
        || child.config.size > MAX_CONFIG as u64
        || child
            .annotations
            .get("com.github.package.type")
            .map(String::as_str)
            != Some("homebrew_bottle")
        || child.annotations.get("org.opencontainers.image.ref.name")
            != Some(&r.platform_reference(tag))
        || child
            .annotations
            .get("sh.brew.bottle.digest")
            .map(String::as_str)
            != Some(sha)
        || child.annotations.get("sh.brew.tab") != d.annotations.get("sh.brew.tab")
    {
        return Err(Error::upstream(
            "unsupported or inconsistent bottle child evidence",
        ));
    }
    let layer = &child.layers[0];
    if layer.digest != bottle
        || layer.media_type != LAYER
        || layer.urls.is_some()
        || layer.size == 0
    {
        return Err(Error::upstream(
            "bottle layer does not match signed checksum",
        ));
    }
    let config = app
        .oci
        .raw(
            app,
            registry(app, &r.repo),
            &format!("blobs/{}", child.config.digest),
            "application/octet-stream",
            MAX_CONFIG,
        )
        .await?;
    if config.digest != child.config.digest
        || config.body.len() as u64 != child.config.size
        || !matches!(
            config.kind(),
            oci::CONFIG | "application/octet-stream" | "application/json"
        )
    {
        return Err(Error::upstream("bottle config descriptor mismatch"));
    }
    let cfg: Value = serde_json::from_slice(&config.body)
        .map_err(|_| Error::upstream("invalid bottle config JSON"))?;
    if cfg["architecture"] != arch
        || cfg["os"] != os
        || cfg["rootfs"]["type"] != "layers"
        || !cfg["rootfs"]["diff_ids"]
            .as_array()
            .is_some_and(|a| a.len() == 1 && a[0].as_str().is_some_and(oci::valid_digest))
    {
        return Err(Error::upstream("bottle config platform/rootfs mismatch"));
    }
    let tab: Value = child
        .annotations
        .get("sh.brew.tab")
        .and_then(|s| serde_json::from_str(s).ok())
        .filter(Value::is_object)
        .ok_or_else(|| Error::upstream("missing or invalid bottle execution metadata"))?;
    let mut runtime_dependencies = Vec::new();
    if let Some(deps) = tab["runtime_dependencies"].as_array() {
        if deps.len() > 256 {
            return Err(Error::upstream("bottle dependency evidence too large"));
        }
        for dep in deps {
            let name = dep["full_name"]
                .as_str()
                .ok_or_else(|| Error::upstream("invalid bottle dependency identity"))?;
            let name = name.strip_prefix("homebrew/core/").unwrap_or(name);
            if !formula_name(name) {
                return Err(Error::upstream("unsupported bottle dependency namespace"));
            }
            runtime_dependencies.push(name);
        }
    }
    let details = json!({"upstream":app.config.homebrew.registry,"formula":r.name,"repository":r.repo,"version":r.version,"revision":r.revision,
        "rebuild":r.rebuild,"platform":tag,"manifest":manifest.digest,"bottle":bottle,"config":config.digest,"size":layer.size,
        "formula_definition":source,"version_scheme":r.info["version_scheme"],"cellar":file["cellar"],"runtime_dependencies":runtime_dependencies,"variation":r.info["variations"][tag],"dependencies":r.info["dependencies"],"uses_from_macos":r.info["uses_from_macos"],"uses_from_macos_bounds":r.info["uses_from_macos_bounds"],
        "oci_created":child.annotations.get("org.opencontainers.image.created")});
    let hash = oci::digest(&serde_json::to_vec(&details).unwrap());
    let identity = format!("homebrew:{hash}");
    let release = format!("{}-rebuild.{}@{tag}:{}", r.version, r.rebuild, hash);
    Ok(Evidence {
        identity,
        release,
        details,
        bottle,
        size: layer.size,
        manifest,
        config,
    })
}
async fn observe(app: &App, e: &Evidence) -> Result<i64> {
    app.store
        .observe_homebrew(
            e.identity.clone(),
            serde_json::to_string(&e.details).unwrap(),
        )
        .await
}
fn eligible_at(app: &App, timestamp: i64) -> i64 {
    timestamp
        .saturating_add(i64::from(app.config.policy_for(Ecosystem::Homebrew).min_age_days) * 86_400)
}
fn age_timestamp(app: &App, e: &Evidence, first_seen: i64) -> Result<(i64, &'static str)> {
    match app.config.homebrew.age_basis {
        HomebrewAgeBasis::LocalFirstSeen => Ok((first_seen, "local_first_seen")),
        HomebrewAgeBasis::OciCreated => {
            let created = e.details["oci_created"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.timestamp())
                .ok_or_else(|| {
                    Error::denied("missing or invalid verified OCI bottle build date")
                })?;
            if created > Utc::now().timestamp() {
                return Err(Error::denied(
                    "verified OCI bottle build date is in the future",
                ));
            }
            Ok((created, "oci_created"))
        }
    }
}
async fn authorize(app: &App, e: &Evidence) -> Result<()> {
    let first_seen = observe(app, e).await?;
    if app.config.policy_for(Ecosystem::Homebrew).min_age_days == 0 {
        return Ok(());
    }
    let (timestamp, basis) = age_timestamp(app, e, first_seen)?;
    if !app
        .config
        .policy_for(Ecosystem::Homebrew)
        .allows_timestamp(timestamp, Utc::now().timestamp())
    {
        let time = chrono::DateTime::from_timestamp(eligible_at(app, timestamp), 0)
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| eligible_at(app, timestamp).to_string());
        return Err(Error::denied(format!(
            "{}: bottle {} age basis {basis} at {timestamp}; minimum age policy; eligible at {time}",
            e.details["formula"].as_str().unwrap_or("formula"),
            e.details["platform"].as_str().unwrap_or("platform")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
