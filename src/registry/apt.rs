//! APT signed-index passthrough and checksum-based local age gate.
use crate::{
    App,
    cache::RawMetadata,
    config::AptRepo,
    error::{Error, Result},
    registry::Ecosystem,
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
use chrono::{TimeZone, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stanza {
    package: String,
    version: String,
    source_package: String,
    source_version: String,
    architecture: String,
    filename: String,
    sha256: String,
    size: u64,
}

type Index = BTreeMap<String, Vec<Stanza>>;

pub(crate) fn routes() -> Router<App> {
    Router::new().route("/apt/{*path}", any(handle))
}

async fn handle(
    State(app): State<App>,
    Path(path): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let response = dispatch(
        &app,
        &path,
        uri.path(),
        uri.query().is_some(),
        &method,
        &headers,
    )
    .await;
    match response {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(status = %error.0, reason = %error.1, "APT request rejected");
            let body = serde_json::to_vec(&json!({"error":error.1})).unwrap();
            Response::builder()
                .status(error.0)
                .header("content-type", "application/json")
                .header("cache-control", "no-store")
                .header("content-length", body.len())
                .body(if method == Method::HEAD {
                    Body::empty()
                } else {
                    Body::from(body)
                })
                .unwrap()
        }
    }
}

fn valid_path(path: &str) -> bool {
    path.len() <= 4096
        && !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 255
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-+~".contains(&b))
        })
}

async fn dispatch(
    app: &App,
    path: &str,
    raw_path: &str,
    query: bool,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Response> {
    if !app.config.apt.enabled {
        return Err(Error::missing("APT adapter is disabled"));
    }
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Err(Error(
            StatusCode::METHOD_NOT_ALLOWED,
            "APT supports GET and HEAD".into(),
        ));
    }
    if query || raw_path.contains('%') || !valid_path(path) {
        return Err(Error::bad("invalid APT path or query"));
    }
    if headers.contains_key("authorization") {
        return Err(Error::denied("APT client credentials are unsupported"));
    }
    let (name, rest) = path
        .split_once('/')
        .ok_or_else(|| Error::bad("missing APT repository path"))?;
    let repo = app
        .config
        .apt
        .repos
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| Error::missing("unknown APT repository"))?;
    if let Some(file) = rest.strip_prefix("check/") {
        if !file.ends_with(".deb") || *method != Method::GET {
            return Err(Error::bad("invalid APT diagnostic path"));
        }
        let (stanza, age, ecosystems) = authorize(app, repo, file).await?;
        let mut reports = Vec::new();
        for osv in ecosystems {
            reports.push(
                app.advisory_report_mapped(
                    Ecosystem::Apt,
                    &osv,
                    &stanza.source_package,
                    &stanza.source_version,
                )
                .await?,
            );
        }
        return Ok(json_response(&stanza, age, json!(reports)));
    }
    if rest.starts_with("dists/") {
        if [".deb", ".udeb", ".dsc", ".tar", ".tar.gz", ".tar.xz"]
            .iter()
            .any(|suffix| rest.ends_with(suffix))
        {
            return Err(Error::missing("unsupported APT download class under dists"));
        }
        let suite = rest
            .strip_prefix("dists/")
            .and_then(|p| p.split('/').next())
            .unwrap_or("");
        if !repo.suites.iter().any(|s| s == suite) {
            return Err(Error::missing("APT suite is not configured"));
        }
        let raw = dist_raw(app, repo, rest).await?;
        if let Some(suite) = rest.strip_prefix("dists/").and_then(|p| {
            p.strip_suffix("/InRelease")
                .or_else(|| p.strip_suffix("/Release"))
        }) && repo.suites.iter().any(|s| s == suite)
        {
            for component in &repo.components {
                for arch in &repo.architectures {
                    index(app, repo, suite, component, arch).await?;
                }
            }
        }
        return Response::builder()
            .header("content-type", "application/octet-stream")
            .header("content-length", raw.body.len())
            .body(if *method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(raw.body.clone())
            })
            .map_err(|_| Error::internal("APT response headers"));
    }
    if !rest.ends_with(".deb") {
        return Err(Error::missing("unsupported APT download class"));
    }
    let (stanza, age, ecosystems) = authorize(app, repo, rest).await?;
    if !age["eligible"].as_bool().unwrap_or(false) {
        let body = serde_json::to_vec(&diagnostic(&stanza, age)).unwrap();
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .header("cache-control", "no-store")
            .body(if *method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(body)
            })
            .map_err(|_| Error::internal("APT denial response"));
    }
    for osv in ecosystems {
        app.check_advisories_mapped(
            Ecosystem::Apt,
            &osv,
            &stanza.source_package,
            &stanza.source_version,
        )
        .await?;
    }
    let url = format!("{}/{}", repo.url.trim_end_matches('/'), rest);
    let identity = (*method == Method::GET).then(|| {
        Identity::new(
            Ecosystem::Apt,
            &stanza.package,
            &format!("{}_{}", stanza.version, stanza.architecture),
        )
    });
    app.stream_download_method(&url, headers.clone(), identity, *method == Method::HEAD)
        .await
}

async fn dist_raw(app: &App, repo: &AptRepo, rest: &str) -> Result<Arc<RawMetadata>> {
    let url = format!("{}/{}", repo.url.trim_end_matches('/'), rest);
    app.store
        .raw(format!("apt-dist-v1:{url}"), || async {
            let body = fetch_bounded(app, &url, app.config.apt.max_index_mb * 1024 * 1024).await?;
            let digest = format!("sha256:{:x}", Sha256::digest(&body));
            Ok(RawMetadata {
                body,
                media_type: "application/octet-stream".into(),
                digest,
            })
        })
        .await
}

struct ReleaseIndex {
    digest: String,
    by_hash: bool,
    hashes: BTreeMap<String, (String, u64)>,
}

fn parse_release(raw: &RawMetadata) -> Result<ReleaseIndex> {
    let text =
        std::str::from_utf8(&raw.body).map_err(|_| Error::upstream("invalid APT Release UTF-8"))?;
    let text = if text.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        let (_, body) = text
            .split_once("\n\n")
            .ok_or_else(|| Error::upstream("invalid InRelease cleartext"))?;
        body.split("-----BEGIN PGP SIGNATURE-----")
            .next()
            .ok_or_else(|| Error::upstream("missing InRelease cleartext"))?
    } else {
        text
    };
    let mut hashes = BTreeMap::new();
    let mut sha = false;
    let mut by_hash = false;
    for line in text.lines() {
        if line == "SHA256:" {
            sha = true;
            continue;
        }
        if line.starts_with(' ') && sha {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3
                || fields[0].len() != 64
                || !fields[0].bytes().all(|b| b.is_ascii_hexdigit())
                || !valid_path(fields[2])
            {
                return Err(Error::upstream("invalid APT Release SHA256 entry"));
            }
            let size = fields[1]
                .parse::<u64>()
                .map_err(|_| Error::upstream("invalid APT Release size"))?;
            if hashes
                .insert(fields[2].to_owned(), (fields[0].to_ascii_lowercase(), size))
                .is_some()
            {
                return Err(Error::upstream("duplicate APT Release hash entry"));
            }
            continue;
        }
        sha = false;
        if line == "Acquire-By-Hash: yes" {
            by_hash = true;
        }
    }
    if hashes.is_empty() {
        return Err(Error::upstream("APT Release has no SHA256 indexes"));
    }
    Ok(ReleaseIndex {
        digest: raw.digest.clone(),
        by_hash,
        hashes,
    })
}

async fn release_index(app: &App, repo: &AptRepo, suite: &str) -> Result<ReleaseIndex> {
    let inrelease = format!("dists/{suite}/InRelease");
    let raw = match dist_raw(app, repo, &inrelease).await {
        Ok(raw) => raw,
        Err(e) if e.0 == StatusCode::NOT_FOUND => {
            dist_raw(app, repo, &format!("dists/{suite}/Release")).await?
        }
        Err(e) => return Err(e),
    };
    parse_release(&raw)
}

fn json_response(stanza: &Stanza, age: Value, advisories: Value) -> Response {
    let mut value = diagnostic(stanza, age);
    value["advisories"] = advisories;
    let body = serde_json::to_vec(&value).unwrap();
    Response::builder()
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .unwrap()
}

fn diagnostic(stanza: &Stanza, age: Value) -> Value {
    json!({"package":stanza.package,"version":stanza.version,"source_package":stanza.source_package,"source_version":stanza.source_version,"architecture":stanza.architecture,
        "filename":stanza.filename,"sha256":stanza.sha256,"size":stanza.size,"age":age,
        "install_hooks":{"status":"unavailable","limitations":"Maintainer scripts are inside the .deb and may run as root on the client."}})
}

async fn authorize(app: &App, repo: &AptRepo, file: &str) -> Result<(Stanza, Value, Vec<String>)> {
    let mut found: Vec<(Stanza, Option<String>)> = Vec::new();
    let mut effective_days = u32::MAX;
    let mut named_listed = false;
    for candidate in &app.config.apt.repos {
        let mut listed = false;
        for suite in &candidate.suites {
            for component in &candidate.components {
                for arch in &candidate.architectures {
                    let index = index(app, candidate, suite, component, arch).await?;
                    if let Some(stanzas) = index.get(file) {
                        found.extend(
                            stanzas
                                .iter()
                                .cloned()
                                .map(|stanza| (stanza, candidate.osv_ecosystem.clone())),
                        );
                        listed = true;
                    }
                }
            }
        }
        if listed {
            if candidate.name == repo.name {
                named_listed = true;
            }
            effective_days = effective_days.min(
                candidate
                    .min_age_days
                    .unwrap_or(app.config.policy_for(Ecosystem::Apt).min_age_days),
            );
        }
    }
    if !named_listed {
        return Err(Error::missing(
            "APT archive is absent from configured indexes",
        ));
    }
    if found.iter().any(|(s, _)| {
        s.sha256 != found[0].0.sha256
            || s.size != found[0].0.size
            || s.source_package != found[0].0.source_package
            || s.source_version != found[0].0.source_version
    }) {
        return Err(Error::denied(
            "ambiguous APT archive checksum across configured indexes",
        ));
    }
    let ecosystems = found
        .iter()
        .filter_map(|(_, osv)| osv.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let stanza = found.remove(0).0;
    let first_seen = app
        .store
        .observe(vec![format!("apt:{}", stanza.sha256)])
        .await?[0];
    let days = effective_days;
    let eligible_at = first_seen.saturating_add(i64::from(days) * 86_400);
    let eligible = Utc::now().timestamp() >= eligible_at;
    let age = json!({"age_basis":"local_first_seen", "first_seen":Utc.timestamp_opt(first_seen, 0).single().map(|t| t.to_rfc3339()),
        "eligible_at":Utc.timestamp_opt(eligible_at, 0).single().map(|t| t.to_rfc3339()), "min_age_days":days,"eligible":eligible});
    if !eligible {
        tracing::info!(package = %stanza.package, version = %stanza.version, first_seen, eligible_at, "APT archive blocked by age policy");
    }
    Ok((stanza, age, ecosystems))
}

async fn index(
    app: &App,
    repo: &AptRepo,
    suite: &str,
    component: &str,
    arch: &str,
) -> Result<Index> {
    let release = release_index(app, repo, suite).await?;
    let root = format!(
        "{}/dists/{suite}/{component}/binary-{arch}/Packages",
        repo.url.trim_end_matches('/')
    );
    let key = format!("apt-index-v1:{root}:{}", release.digest);
    let value = app
        .store
        .get(key, false, || async {
            let max = app.config.apt.max_index_mb * 1024 * 1024;
            let mut body = None;
            for suffix in [".xz", ".gz", ""] {
                let relative = format!("{component}/binary-{arch}/Packages{suffix}");
                let Some((digest, size)) = release.hashes.get(&relative) else {
                    continue;
                };
                if *size > max as u64 {
                    return Err(Error::upstream("APT Release index exceeds bound"));
                }
                let url = if release.by_hash {
                    format!(
                        "{}/dists/{suite}/{component}/binary-{arch}/by-hash/SHA256/{digest}",
                        repo.url.trim_end_matches('/')
                    )
                } else {
                    format!("{root}{suffix}")
                };
                match fetch_bounded(app, &url, max).await {
                    Ok(data) => {
                        if data.len() as u64 != *size
                            || format!("{:x}", Sha256::digest(&data)) != *digest
                        {
                            return Err(Error::upstream("APT index differs from Release checksum"));
                        }
                        body = Some((data, suffix));
                        break;
                    }
                    Err(e) if e.0 == StatusCode::NOT_FOUND => continue,
                    Err(e) => return Err(e),
                }
            }
            let (body, suffix) =
                body.ok_or_else(|| Error::upstream("configured APT Packages index is absent"))?;
            let suffix = suffix.to_owned();
            let parsed = tokio::task::spawn_blocking(move || decode_index(body, &suffix, max))
                .await
                .map_err(|_| Error::internal("APT parser task failed"))??;
            if parsed
                .values()
                .flatten()
                .any(|s| s.architecture != arch && s.architecture != "all")
            {
                return Err(Error::upstream(
                    "Packages architecture differs from configured tuple",
                ));
            }
            let keys = parsed
                .values()
                .flatten()
                .map(|s| format!("apt:{}", s.sha256))
                .collect();
            app.store.observe(keys).await?;
            serde_json::to_vec(&parsed).map_err(|_| Error::internal("APT index serialization"))
        })
        .await?;
    serde_json::from_value((*value).clone())
        .map_err(|_| Error::internal("invalid cached APT index"))
}

fn decode_index(body: Vec<u8>, suffix: &str, max: usize) -> Result<Index> {
    let mut uncompressed = Vec::new();
    match suffix {
        ".xz" => {
            xz2::read::XzDecoder::new(body.as_slice())
                .take(max as u64 + 1)
                .read_to_end(&mut uncompressed)
                .map_err(|_| Error::upstream("invalid or truncated xz Packages index"))?;
        }
        ".gz" => {
            flate2::read::GzDecoder::new(body.as_slice())
                .take(max as u64 + 1)
                .read_to_end(&mut uncompressed)
                .map_err(|_| Error::upstream("invalid or truncated gzip Packages index"))?;
        }
        _ => uncompressed = body,
    }
    if uncompressed.len() > max {
        return Err(Error::upstream(
            "APT Packages index exceeds decompressed bound",
        ));
    }
    parse_index(&uncompressed)
}

async fn fetch_bounded(app: &App, raw: &str, max: usize) -> Result<Vec<u8>> {
    let _permit = app
        .metadata_permits
        .acquire()
        .await
        .map_err(|_| Error::internal("shutdown"))?;
    let mut url = app.allowed_artifact(raw)?;
    for redirect in 0..=5 {
        let response = app
            .artifact_client
            .get(url.clone())
            .header("accept-encoding", "identity")
            .timeout(Duration::from_secs(app.config.upstream.timeout_secs))
            .send()
            .await
            .map_err(|e| Error::upstream(e.to_string()))?;
        if response.status().is_redirection() {
            if redirect == 5 {
                return Err(Error::upstream("too many APT metadata redirects"));
            }
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Error::upstream("APT redirect without location"))?;
            url = app.allowed_artifact(
                url.join(location)
                    .map_err(|_| Error::upstream("invalid APT redirect"))?
                    .as_str(),
            )?;
            continue;
        }
        if response.status() == StatusCode::NOT_FOUND {
            return Err(Error::missing("APT metadata not found"));
        }
        if response.status() != StatusCode::OK {
            return Err(Error::upstream(format!(
                "APT metadata upstream returned {}",
                response.status()
            )));
        }
        if response
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v.as_bytes() != b"identity")
        {
            return Err(Error::upstream(
                "APT metadata upstream used Content-Encoding",
            ));
        }
        if response.content_length().is_some_and(|n| n > max as u64) {
            return Err(Error::upstream("APT metadata exceeds bound"));
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::upstream("truncated APT metadata"))?;
            if bytes.len().saturating_add(chunk.len()) > max {
                return Err(Error::upstream("APT metadata exceeds bound"));
            }
            bytes.extend_from_slice(&chunk);
        }
        return Ok(bytes);
    }
    unreachable!()
}

fn token(value: &str, max: usize, extra: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

fn parse_index(body: &[u8]) -> Result<Index> {
    let text = std::str::from_utf8(body).map_err(|_| Error::upstream("invalid Packages UTF-8"))?;
    let mut index: Index = BTreeMap::new();
    for block in text
        .replace("\r\n", "\n")
        .split("\n\n")
        .filter(|s| !s.trim().is_empty())
    {
        let mut fields = BTreeMap::new();
        let mut previous_identity = false;
        for line in block.lines() {
            if line.starts_with([' ', '\t']) {
                if previous_identity {
                    return Err(Error::upstream("folded Packages identity field"));
                }
                continue;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| Error::upstream("malformed Packages field"))?;
            previous_identity = matches!(
                name,
                "Package" | "Version" | "Source" | "Architecture" | "Filename" | "SHA256" | "Size"
            );
            if previous_identity && fields.insert(name, value.trim()).is_some() {
                return Err(Error::upstream("duplicate Packages identity field"));
            }
        }
        let field = |name| {
            fields
                .get(name)
                .copied()
                .ok_or_else(|| Error::upstream(format!("missing Packages {name}")))
        };
        let package = field("Package")?;
        let version = field("Version")?;
        let source = fields.get("Source").copied();
        let (source_package, source_version) = match source {
            None => (package, version),
            Some(value) if value.contains(" (") => {
                let (name, rest) = value.split_once(" (").unwrap();
                let source_version = rest
                    .strip_suffix(')')
                    .ok_or_else(|| Error::upstream("invalid Packages Source field"))?;
                (name, source_version)
            }
            Some(value) => (value, version),
        };
        let architecture = field("Architecture")?;
        let filename = field("Filename")?;
        let sha256 = field("SHA256")?;
        let size = field("Size")?
            .parse::<u64>()
            .map_err(|_| Error::upstream("invalid Packages Size"))?;
        if !token(package, 214, b"+.-")
            || !token(version, 256, b"+.:~-")
            || !token(source_package, 214, b"+.-")
            || !token(source_version, 256, b"+.:~-")
            || !token(architecture, 64, b"_-")
            || !valid_path(filename)
            || !filename.ends_with(".deb")
            || sha256.len() != 64
            || !sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || size == 0
        {
            return Err(Error::upstream("invalid Packages archive identity"));
        }
        let stanza = Stanza {
            package: package.into(),
            version: version.into(),
            source_package: source_package.into(),
            source_version: source_version.into(),
            architecture: architecture.into(),
            filename: filename.into(),
            sha256: sha256.to_ascii_lowercase(),
            size,
        };
        index.entry(filename.into()).or_default().push(stanza);
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn parser_fails_closed() {
        let good = "Package: x\nVersion: 1:2.0-1\nArchitecture: all\nFilename: pool/x_2_all.deb\nSHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nSize: 12\n\n";
        assert_eq!(
            parse_index(good.as_bytes()).unwrap()["pool/x_2_all.deb"].len(),
            1
        );
        assert!(parse_index(good.replace("Size: 12", "Size: bad").as_bytes()).is_err());
        assert!(parse_index(good.replace("pool/x_2_all.deb", "../x.deb").as_bytes()).is_err());
    }

    #[test]
    fn bounded_xz_and_gzip_decoding() {
        let good = b"Package: x\nVersion: 1\nArchitecture: all\nFilename: pool/x.deb\nSHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nSize: 1\n\n";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(good).unwrap();
        let gz = gz.finish().unwrap();
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 6);
        xz.write_all(good).unwrap();
        let xz = xz.finish().unwrap();
        assert!(decode_index(gz.clone(), ".gz", good.len()).is_ok());
        assert!(decode_index(xz.clone(), ".xz", good.len()).is_ok());
        assert!(decode_index(gz, ".gz", good.len() - 1).is_err());
        assert!(decode_index(xz, ".xz", good.len() - 1).is_err());
        assert!(decode_index(vec![0x1f, 0x8b], ".gz", 1000).is_err());
    }
}
