pub mod cache;
pub mod config;
pub mod error;
pub mod inspection;
pub mod policy;
pub mod registry;
mod stats;

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cache::Store;
use chrono::Utc;
use config::Config;
use error::{Error, Result};
use futures_util::{StreamExt, stream};
use registry::Ecosystem;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tower_http::{compression::CompressionLayer, trace::TraceLayer};

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub store: Store,
    client: reqwest::Client,
    artifact_client: reqwest::Client,
    // Archive streams hold a permit for the whole client transfer, so they get
    // their own pool; slow downloads must not starve metadata resolution.
    metadata_permits: Arc<Semaphore>,
    artifact_permits: Arc<Semaphore>,
}

impl App {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .user_agent(concat!("middles/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(config.upstream.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        // Archives must be byte-for-byte unchanged; do not auto-decompress Content-Encoding.
        let artifact_client = reqwest::Client::builder()
            .user_agent(concat!("middles/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(config.upstream.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .gzip(false)
            .build()?;
        let store = Store::open(config.cache.clone()).await?;
        Ok(Self {
            metadata_permits: Arc::new(Semaphore::new(config.upstream.concurrency)),
            artifact_permits: Arc::new(Semaphore::new(config.upstream.concurrency)),
            config: Arc::new(config),
            store,
            client,
            artifact_client,
        })
    }
    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/healthz",
                get(|| async { axum::Json(json!({"status":"ok"})) }),
            )
            .route("/npm/{*path}", get(registry::npm::handle))
            .route("/stats", get(stats::handle))
            .route(
                "/rubygems/api/v1/dependencies",
                get(registry::rubygems::dependencies),
            )
            .route(
                "/rubygems/gems/{filename}",
                get(registry::rubygems::download),
            )
            .route(
                "/rubygems/quick/Marshal.4.8/{filename}",
                get(registry::rubygems::gemspec),
            )
            .route("/inspect/{ecosystem}/{*package}", get(inspection::handle))
            .route("/pip/simple/{name}/", get(registry::pip::handle))
            .route("/composer/packages.json", get(registry::composer::index))
            .route("/composer/p2/{*path}", get(registry::composer::handle))
            .route(
                "/artifacts/{ecosystem}/{package}/{release}/{filename}",
                get(artifact),
            )
            .fallback(|| async { Error::missing("unsupported endpoint") })
            .layer(CompressionLayer::new())
            .layer(TraceLayer::new_for_http())
            .with_state(self)
    }
    pub async fn metadata(
        &self,
        url: String,
        accept: &'static str,
        stats: bool,
    ) -> Result<Arc<Value>> {
        let key = format!("{accept}:{url}");
        self.store
            .get(key, stats, || self.fetch_metadata(&url, accept))
            .await
    }

    pub(crate) async fn text_metadata(&self, url: String) -> Result<Arc<Value>> {
        self.store
            .get_text(url.clone(), || self.fetch_metadata(&url, "text/plain"))
            .await
    }

    async fn fetch_metadata(&self, url: &str, accept: &str) -> Result<Vec<u8>> {
        let _permit = self
            .metadata_permits
            .acquire()
            .await
            .map_err(|_| Error::internal("shutdown"))?;
        let response = self
            .client
            .get(url)
            .header("accept", accept)
            .send()
            .await
            .map_err(|e| Error::upstream(e.to_string()))?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(Error::missing("upstream package not found"));
        }
        if !status.is_success() {
            return Err(Error::upstream(format!("upstream returned {status}")));
        }
        let max = self.config.upstream.max_metadata_mb * 1024 * 1024;
        if response.content_length().is_some_and(|s| s > max as u64) {
            return Err(Error::upstream("upstream metadata too large"));
        }
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| Error::upstream(e.to_string()))?;
            if body.len().saturating_add(chunk.len()) > max {
                return Err(Error::upstream("upstream metadata too large"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
    pub async fn check_downloads(&self, ecosystem: Ecosystem, package: &str) -> Result<()> {
        let minimum = self.config.policy_for(ecosystem).min_monthly_downloads;
        if minimum == 0 {
            return Ok(());
        }
        let u = &self.config.upstream;
        let (url, pointer) = match ecosystem {
            Ecosystem::Npm => (
                format!(
                    "{}/downloads/point/last-month/{package}",
                    u.npm_stats.trim_end_matches('/')
                ),
                "/downloads",
            ),
            Ecosystem::Pip => (
                format!(
                    "{}/api/packages/{package}/recent",
                    u.pypi_stats.trim_end_matches('/')
                ),
                "/data/last_month",
            ),
            Ecosystem::Composer => (
                format!(
                    "{}/packages/{package}/stats.json",
                    u.composer_stats.trim_end_matches('/')
                ),
                "/downloads/monthly",
            ),
            // Configuration validation rejects a nonzero RubyGems threshold.
            Ecosystem::Rubygems => {
                return Err(Error::internal("no RubyGems download evidence provider"));
            }
        };
        let stats = self.metadata(url, "application/json", true).await?;
        let count = stats
            .pointer(pointer)
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                Error::upstream("download statistics unavailable; policy cannot be verified")
            })?;
        if count < minimum {
            return Err(Error::denied(format!(
                "{package}: {count} monthly downloads is below the required {minimum}"
            )));
        }
        Ok(())
    }
    pub fn artifact_url(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        release: &str,
        filename: &str,
    ) -> String {
        let filename: String = url::form_urlencoded::byte_serialize(filename.as_bytes()).collect();
        format!(
            "{}/artifacts/{ecosystem}/{}/{}/{filename}",
            self.config.public_url.trim_end_matches('/'),
            URL_SAFE_NO_PAD.encode(package),
            URL_SAFE_NO_PAD.encode(release)
        )
    }
    pub fn allowed_artifact(&self, raw: &str) -> Result<url::Url> {
        let url = url::Url::parse(raw).map_err(|_| Error::upstream("invalid artifact URL"))?;
        if !(url.scheme() == "https" || self.config.upstream.allow_http && url.scheme() == "http")
            || !url.username().is_empty()
            || url.password().is_some()
            || !url.host_str().is_some_and(|h| {
                self.config
                    .upstream
                    .artifact_hosts
                    .iter()
                    .any(|allowed| allowed == h)
            })
            || (!self.config.upstream.allow_http && url.port().is_some_and(|p| p != 443))
        {
            return Err(Error::denied(
                "artifact host or scheme not allowed by upstream.artifact_hosts",
            ));
        }
        Ok(url)
    }
    pub async fn stream_artifact(&self, raw: &str, headers: HeaderMap) -> Result<Response> {
        self.stream_download(raw, headers, None).await
    }
    pub(crate) async fn stream_download(
        &self,
        raw: &str,
        headers: HeaderMap,
        identity: Option<stats::Identity>,
    ) -> Result<Response> {
        let permit = self
            .artifact_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::internal("shutdown"))?;
        let mut url = self.allowed_artifact(raw)?;
        for redirect in 0..=5 {
            let mut request = self.artifact_client.get(url.clone());
            for name in ["range", "if-range"] {
                if let Some(value) = headers.get(name) {
                    request = request.header(name, value);
                }
            }
            let response = request
                .send()
                .await
                .map_err(|e| Error::upstream(e.to_string()))?;
            if response.status().is_redirection() {
                if redirect == 5 {
                    return Err(Error::upstream("too many artifact redirects"));
                }
                let next = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::upstream("redirect without location"))?;
                let next = url
                    .join(next)
                    .map_err(|_| Error::upstream("invalid artifact redirect"))?;
                url = self.allowed_artifact(next.as_str())?;
                continue;
            }
            if !response.status().is_success()
                && response.status() != StatusCode::RANGE_NOT_SATISFIABLE
            {
                return Err(Error::upstream(format!(
                    "artifact upstream returned {}",
                    response.status()
                )));
            }
            let mut builder = Response::builder()
                .status(response.status())
                .header("cache-control", "no-store");
            for name in [
                "content-type",
                "content-length",
                "content-range",
                "accept-ranges",
                "content-encoding",
            ] {
                if let Some(value) = response.headers().get(name) {
                    builder = builder.header(name, value);
                }
            }
            // Hold the concurrency permit until the body finishes or the client disconnects.
            let length = response.content_length();
            let partial = response.status() == StatusCode::PARTIAL_CONTENT;
            let identity = identity.filter(|_| response.status() == StatusCode::OK || partial);
            let store = self.store.clone();
            let stream = stream::unfold(
                (response.bytes_stream(), permit, identity, store, 0u64),
                move |(mut chunks, permit, mut identity, store, mut bytes)| async move {
                    let chunk = chunks.next().await;
                    match &chunk {
                        Some(Ok(chunk)) => bytes = bytes.saturating_add(chunk.len() as u64),
                        Some(Err(_)) => identity = None,
                        None => {}
                    }
                    // HTTP servers may stop polling at Content-Length without polling EOF.
                    // Persist before handing off the final chunk, or at EOF for chunked bodies.
                    let complete = match length {
                        Some(length) => bytes == length,
                        None => chunk.is_none(),
                    };
                    if complete
                        && let Some(identity) = identity.take()
                        && let Err(error) = store.record_download(identity, bytes, partial).await
                    {
                        tracing::warn!(%error, "could not record download statistics");
                    }
                    chunk.map(|chunk| (chunk, (chunks, permit, identity, store, bytes)))
                },
            );
            return builder
                .body(Body::from_stream(stream.fuse()))
                .map_err(|e| Error::internal(e.to_string()));
        }
        unreachable!()
    }
}

pub fn json_response(value: Value, content_type: &'static str) -> Response {
    (
        [
            ("content-type", content_type),
            ("cache-control", "no-store"),
        ],
        axum::Json(value),
    )
        .into_response()
}

async fn artifact(
    State(app): State<App>,
    Path((ecosystem, package, release, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    method: Method,
) -> Result<Response> {
    let decode = |s: String| {
        URL_SAFE_NO_PAD
            .decode(s)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| Error::bad("invalid artifact identity"))
    };
    let package = decode(package)?;
    let release = decode(release)?;
    let ecosystem = Ecosystem::parse(&ecosystem)?;
    let url = match ecosystem {
        Ecosystem::Npm => registry::npm::artifact(&app, &package, &release, Utc::now()).await?,
        Ecosystem::Pip => {
            registry::pip::artifact(&app, &package, &release, &filename, Utc::now()).await?
        }
        Ecosystem::Composer => registry::composer::artifact(&app, &package, &release).await?,
        Ecosystem::Rubygems => {
            return Err(Error::bad("gem archives are served from /rubygems/gems"));
        }
    };
    let package = if ecosystem == Ecosystem::Pip {
        registry::pip::normalize(&package)?
    } else {
        package
    };
    let identity = (method == Method::GET
        && !(ecosystem == Ecosystem::Pip && filename.ends_with(".metadata")))
    .then(|| stats::Identity::new(ecosystem, &package, &release));
    app.stream_download(&url, headers, identity).await
}
