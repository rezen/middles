//! Read-only, byte-preserving registry transport shared by OCI adapters.
//! Credentials are anonymous pull tokens, bounded and held only in memory.
use crate::{
    App,
    cache::RawMetadata,
    error::{Error, Result},
    stats::Identity,
};
use axum::{
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use chrono::Utc;
use futures_util::StreamExt;
use moka::future::Cache;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use url::Url;

pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const CONFIG: &str = "application/vnd.oci.image.config.v1+json";

/// The caller supplies the validated namespace; transport never discovers repositories.
pub(crate) struct Registry<'a> {
    pub upstream: &'a str,
    pub repository: String,
}

struct ReadOptions<'a> {
    method: Method,
    headers: &'a HeaderMap,
    accept: &'a str,
    metadata: bool,
}
pub(crate) struct Bottle<'a> {
    pub digest: &'a str,
    pub size: u64,
}

#[derive(Clone)]
struct Token {
    value: String,
    expires: i64,
}
#[derive(Clone)]
struct Challenge {
    realm: Url,
    service: String,
    scope: String,
}
impl Challenge {
    fn key(&self, origin: &Url) -> String {
        format!(
            "{}|{}|{}|{}",
            origin.origin().ascii_serialization(),
            self.realm,
            self.service,
            self.scope
        )
    }
}

#[derive(Clone)]
pub(crate) struct Transport {
    tokens: Cache<String, Token>,
    challenges: Cache<String, Challenge>,
}
impl Default for Transport {
    fn default() -> Self {
        Self {
            tokens: Cache::builder()
                .max_capacity(1024)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            challenges: Cache::builder()
                .max_capacity(1024)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) async fn bounded_body(response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(Error::upstream("OCI metadata exceeds the byte limit"));
    }
    let mut chunks = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|_| Error::upstream("OCI metadata transfer failed"))?;
        if body.len().saturating_add(chunk.len()) > max {
            return Err(Error::upstream("OCI metadata exceeds the byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn challenge(raw: &str, origin: &Url, repository: &str) -> Result<Challenge> {
    let bad = || Error::upstream("untrusted registry authentication challenge");
    if raw.len() > 8192 {
        return Err(bad());
    }
    let (scheme, params) = raw.split_once(' ').ok_or_else(bad)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(bad());
    }
    let mut fields = BTreeMap::new();
    for part in params.split(',') {
        let (name, value) = part.trim().split_once('=').ok_or_else(bad)?;
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or_else(bad)?;
        if value.contains(['"', '\\', '\r', '\n']) || fields.insert(name, value).is_some() {
            return Err(bad());
        }
    }
    let realm = Url::parse(fields.get("realm").ok_or_else(bad)?).map_err(|_| bad())?;
    let expected_realm = origin.join("/token").map_err(|_| bad())?;
    let service = fields.get("service").ok_or_else(bad)?.to_string();
    let scope = format!("repository:{repository}:pull");
    if realm != expected_realm
        || fields.get("scope").is_some_and(|v| **v != scope)
        || !matches!(service.as_str(), "ghcr.io") && Some(service.as_str()) != origin.host_str()
        || fields
            .keys()
            .any(|k| !matches!(*k, "realm" | "service" | "scope"))
    {
        return Err(bad());
    }
    Ok(Challenge {
        realm,
        service,
        scope,
    })
}

fn redirect_allowed(origin: &Url, next: &Url) -> bool {
    if !next.username().is_empty() || next.password().is_some() || next.fragment().is_some() {
        return false;
    }
    if next.origin() == origin.origin() {
        return true;
    }
    origin.host_str() == Some("ghcr.io")
        && next.scheme() == "https"
        && next.port_or_known_default() == Some(443)
        && next.host_str() == Some("pkg-containers.githubusercontent.com")
}

impl Transport {
    async fn token(&self, app: &App, origin: &Url, c: &Challenge, force: bool) -> Result<Token> {
        let key = c.key(origin);
        if let Some(t) = self.tokens.get(&key).await {
            if !force && t.expires > Utc::now().timestamp() + 5 {
                return Ok(t);
            }
            self.tokens.invalidate(&key).await;
        }
        self.tokens
            .try_get_with(key, async {
                let mut url = c.realm.clone();
                url.query_pairs_mut()
                    .append_pair("service", &c.service)
                    .append_pair("scope", &c.scope);
                let response = app
                    .artifact_client
                    .get(url)
                    .timeout(Duration::from_secs(app.config.upstream.timeout_secs))
                    .send()
                    .await
                    .map_err(|_| Error::upstream("registry token request failed"))?;
                if response.status() != StatusCode::OK {
                    return Err(Error::upstream("registry token service failed"));
                }
                let body = bounded_body(response, 64 * 1024).await?;
                let data: Value = serde_json::from_slice(&body)
                    .map_err(|_| Error::upstream("invalid registry token response"))?;
                let value = data["token"]
                    .as_str()
                    .or_else(|| data["access_token"].as_str())
                    .filter(|t| {
                        !t.is_empty()
                            && t.len() <= 16 * 1024
                            && t.bytes().all(|b| b.is_ascii_graphic())
                    })
                    .ok_or_else(|| Error::upstream("invalid registry token"))?
                    .to_string();
                if let Some(other) = data["access_token"].as_str()
                    && other != value
                {
                    return Err(Error::upstream("conflicting registry tokens"));
                }
                let now = Utc::now().timestamp();
                let ttl = if data["expires_in"].is_null() {
                    60
                } else {
                    data["expires_in"]
                        .as_i64()
                        .filter(|t| *t > 5)
                        .ok_or_else(|| Error::upstream("invalid token lifetime"))?
                        .min(3600)
                };
                let issued = match data["issued_at"].as_str() {
                    Some(t) => chrono::DateTime::parse_from_rfc3339(t)
                        .map_err(|_| Error::upstream("invalid token issue time"))?
                        .timestamp(),
                    None => now,
                };
                let expires = now.saturating_add(ttl).min(issued.saturating_add(ttl));
                if issued > now + 60 || expires <= now + 5 {
                    return Err(Error::upstream("expired registry token"));
                }
                Ok(Token { value, expires })
            })
            .await
            .map_err(|e: Arc<Error>| (*e).clone())
    }

    async fn request(
        &self,
        app: &App,
        registry: Registry<'_>,
        path: &str,
        options: ReadOptions<'_>,
    ) -> Result<reqwest::Response> {
        let ReadOptions {
            method,
            headers,
            accept,
            metadata,
        } = options;
        let origin = Url::parse(registry.upstream)
            .map_err(|_| Error::internal("invalid registry configuration"))?;
        let start = Url::parse(&format!(
            "{}/v2/{}/{path}",
            registry.upstream.trim_end_matches('/'),
            registry.repository
        ))
        .map_err(|_| Error::bad("invalid registry request"))?;
        let repository_key = format!(
            "{}:{}",
            origin.origin().ascii_serialization(),
            registry.repository
        );
        let known = self.challenges.get(&repository_key).await;
        let mut token = if let Some(c) = &known {
            self.tokens
                .get(&c.key(&origin))
                .await
                .filter(|t| t.expires > Utc::now().timestamp() + 5)
        } else {
            None
        };
        for attempt in 0..=2 {
            let mut url = start.clone();
            let mut response = None;
            for hop in 0..=5 {
                let mut request = app
                    .artifact_client
                    .request(method.clone(), url.clone())
                    .header("accept", accept);
                if metadata {
                    request =
                        request.timeout(Duration::from_secs(app.config.upstream.timeout_secs));
                }
                if url.origin() == origin.origin()
                    && let Some(t) = &token
                {
                    request = request.bearer_auth(&t.value);
                }
                for name in ["range", "if-range"] {
                    if let Some(v) = headers.get(name) {
                        request = request.header(name, v);
                    }
                }
                let fetched = request
                    .send()
                    .await
                    .map_err(|_| Error::upstream("registry upstream request failed"))?;
                if fetched.status().is_redirection() {
                    let next = fetched
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| url.join(v).ok())
                        .ok_or_else(|| Error::upstream("invalid registry redirect"))?;
                    if hop == 5 || !redirect_allowed(&origin, &next) {
                        return Err(Error::upstream("registry redirect rejected"));
                    }
                    // Once credentials have crossed an origin boundary, never reattach them.
                    if next.origin() != url.origin() {
                        token = None;
                    }
                    url = next;
                    continue;
                }
                response = Some((fetched, url));
                break;
            }
            let (fetched, url) =
                response.ok_or_else(|| Error::upstream("registry redirect limit"))?;
            if fetched.status() == StatusCode::UNAUTHORIZED
                && attempt < 2
                && url.origin() == origin.origin()
            {
                let raw = fetched
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        Error::upstream("registry requires an authentication challenge")
                    })?;
                let c = challenge(raw, &origin, &registry.repository)?;
                self.challenges
                    .insert(repository_key.clone(), c.clone())
                    .await;
                token = Some(self.token(app, &origin, &c, token.is_some()).await?);
                continue;
            }
            return match fetched.status() {
                StatusCode::OK
                | StatusCode::PARTIAL_CONTENT
                | StatusCode::RANGE_NOT_SATISFIABLE => Ok(fetched),
                StatusCode::NOT_FOUND => Err(Error::missing("registry object not found")),
                StatusCode::TOO_MANY_REQUESTS => Err(Error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "registry rate limited".into(),
                )),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    Err(Error::upstream("registry pull authorization failed"))
                }
                _ => Err(Error::upstream(format!(
                    "registry upstream returned {}",
                    fetched.status()
                ))),
            };
        }
        Err(Error::upstream("registry authentication retry limit"))
    }

    pub(crate) async fn raw(
        &self,
        app: &App,
        registry: Registry<'_>,
        path: &str,
        accept: &str,
        max: usize,
    ) -> Result<Arc<RawMetadata>> {
        let key = format!(
            "{}:{}:{path}:{accept}",
            registry.upstream, registry.repository
        );
        let value = app
            .store
            .raw(key, || async {
                let _permit = app
                    .metadata_permits
                    .acquire()
                    .await
                    .map_err(|_| Error::internal("shutdown"))?;
                let response = self
                    .request(
                        app,
                        registry,
                        path,
                        ReadOptions {
                            method: Method::GET,
                            headers: &HeaderMap::new(),
                            accept,
                            metadata: true,
                        },
                    )
                    .await?;
                if response.status() != StatusCode::OK {
                    return Err(Error::upstream("unexpected partial metadata"));
                }
                let media_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
                    .ok_or_else(|| Error::upstream("missing registry media type"))?;
                let reported = response
                    .headers()
                    .get("docker-content-digest")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let body = bounded_body(response, max).await?;
                let digest = digest(&body);
                if reported.is_some_and(|d| d != digest) {
                    return Err(Error::upstream("registry metadata digest mismatch"));
                }
                Ok(RawMetadata {
                    body,
                    media_type,
                    digest,
                })
            })
            .await?;
        if value.body.len() > max || digest(&value.body) != value.digest {
            return Err(Error::upstream("invalid cached registry metadata"));
        }
        Ok(value)
    }

    pub(crate) async fn bottle(
        &self,
        app: &App,
        registry: Registry<'_>,
        descriptor: Bottle<'_>,
        method: Method,
        headers: &HeaderMap,
        identity: Identity,
    ) -> Result<Response> {
        let Bottle {
            digest: checksum,
            size,
        } = descriptor;
        let permit = app
            .artifact_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::internal("shutdown"))?;
        let response = self
            .request(
                app,
                registry,
                &format!("blobs/{checksum}"),
                ReadOptions {
                    method: method.clone(),
                    headers,
                    accept: "application/octet-stream",
                    metadata: false,
                },
            )
            .await?;
        if let Some(d) = response.headers().get("docker-content-digest")
            && d.to_str().ok() != Some(checksum)
        {
            return Err(Error::upstream("bottle digest header mismatch"));
        }
        let declared_length = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if response.status() == StatusCode::OK && declared_length.is_some_and(|n| n != size) {
            return Err(Error::upstream("bottle descriptor size mismatch"));
        }
        if response.status() == StatusCode::PARTIAL_CONTENT && !headers.contains_key("range") {
            return Err(Error::upstream("unsolicited partial bottle response"));
        }
        let partial = response.status() == StatusCode::PARTIAL_CONTENT;
        let expected = if partial {
            let range = response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("bytes "))
                .and_then(|v| v.split_once('/'))
                .and_then(|(r, total)| r.split_once('-').map(|(a, b)| (a, b, total)))
                .and_then(|(a, b, total)| {
                    Some((
                        a.parse::<u64>().ok()?,
                        b.parse::<u64>().ok()?,
                        total.parse::<u64>().ok()?,
                    ))
                })
                .filter(|(a, b, total)| a <= b && *b < size && *total == size)
                .ok_or_else(|| Error::upstream("invalid bottle Content-Range"))?;
            let length = range.1 - range.0 + 1;
            if declared_length.is_some_and(|n| n != length) {
                return Err(Error::upstream("bottle range length mismatch"));
            }
            Some(length)
        } else {
            Some(size)
        };
        let mut result = app
            .stream_response(
                response,
                permit,
                (method == Method::GET).then_some(identity),
                method == Method::HEAD,
                expected,
            )
            .await?;
        result.headers_mut().insert(
            "docker-content-digest",
            checksum
                .parse()
                .map_err(|_| Error::internal("invalid verified digest"))?,
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenges_and_redirects_are_not_authority() {
        let origin = Url::parse("https://ghcr.io").unwrap();
        let good = "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:homebrew/core/hello:pull\"";
        assert!(challenge(good, &origin, "homebrew/core/hello").is_ok());
        for raw in [
            good.replace(":pull\"", ":pull,push\""),
            good.replace("ghcr.io/token", "evil.example/token"),
            good.replace("hello:pull", "other:pull"),
            format!("{good},service=\"ghcr.io\""),
        ] {
            assert!(challenge(&raw, &origin, "homebrew/core/hello").is_err());
        }
        assert!(redirect_allowed(
            &origin,
            &Url::parse("https://pkg-containers.githubusercontent.com/a?signature=redacted")
                .unwrap()
        ));
        assert!(!redirect_allowed(
            &origin,
            &Url::parse("https://evil.example/a").unwrap()
        ));
        assert!(!redirect_allowed(
            &origin,
            &Url::parse("http://ghcr.io/a").unwrap()
        ));
    }
}
