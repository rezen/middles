//! Request-driven RubyGems dependency API. We deliberately do not publish a partial
//! /versions catalog: Bundler falls back to this API when that endpoint is absent.
//! Upstream compact info is parsed as data; Ruby/Marshal input is never executed.
use crate::{
    App,
    error::{Error, Result},
    policy::Policy,
    stats::Identity,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{BTreeSet, HashSet};

const MAX_NAMES: usize = 100;
const MAX_CANDIDATES: usize = 8;

fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 214
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn version_valid(version: &str) -> bool {
    version.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && version.len() <= 128
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_alphanumeric()))
}

fn split_release(release: &str) -> Option<(&str, &str)> {
    let (version, platform) = release.split_once('-').unwrap_or((release, "ruby"));
    (version_valid(version)
        && !platform.is_empty()
        && platform.len() <= 128
        && platform
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
    .then_some((version, platform))
}

#[derive(Debug)]
struct Release<'a> {
    version: &'a str,
    platform: &'a str,
    dependencies: Vec<(&'a str, String)>,
    created_at: Option<&'a str>,
}

fn parse(raw: &str) -> Result<Vec<Release<'_>>> {
    let invalid = || Error::upstream("invalid RubyGems compact info");
    let (_, lines) = raw.split_once("---\n").ok_or_else(invalid)?;
    let mut releases = Vec::new();
    let mut seen = HashSet::new();
    for line in lines.lines() {
        if line.is_empty() {
            continue;
        }
        if !line.is_ascii() || line.bytes().any(|b| b.is_ascii_control()) {
            return Err(invalid());
        }
        let (identity, rest) = line.split_once(' ').ok_or_else(invalid)?;
        let (version, platform) = split_release(identity).ok_or_else(invalid)?;
        // Explicit -ruby and implicit ruby are the same artifact identity.
        if !seen.insert((version, platform)) {
            return Err(invalid());
        }
        let (deps, requirements) = rest.split_once('|').ok_or_else(invalid)?;
        let mut dependencies = Vec::new();
        if !deps.is_empty() {
            for dependency in deps.split(',') {
                let (name, constraints) = dependency.split_once(':').ok_or_else(invalid)?;
                if !name_valid(name) || !constraints_valid(constraints) {
                    return Err(invalid());
                }
                dependencies.push((name, constraints.replace('&', ", ")));
            }
        }
        let mut created_at = None;
        let mut checksum = None;
        let mut keys = HashSet::new();
        for requirement in requirements.split(',') {
            // Timestamps contain colons; split only the first one.
            let (key, value) = requirement.split_once(':').ok_or_else(invalid)?;
            if !keys.insert(key) {
                return Err(invalid());
            }
            match key {
                "created_at" => created_at = Some(value),
                "checksum" => checksum = Some(value),
                "ruby" | "rubygems" if !constraints_valid(value) => return Err(invalid()),
                _ => {}
            }
        }
        if !checksum.is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(invalid());
        }
        releases.push(Release {
            version,
            platform,
            dependencies,
            created_at,
        });
    }
    Ok(releases)
}

fn constraints_valid(value: &str) -> bool {
    value.split('&').all(|requirement| {
        let requirement = requirement.trim();
        let version = [">=", "<=", "~>", "!=", "=", ">", "<"]
            .iter()
            .find_map(|op| requirement.strip_prefix(op))
            .unwrap_or(requirement)
            .trim();
        version_valid(version)
    })
}

async fn raw(app: &App, name: &str) -> Result<std::sync::Arc<serde_json::Value>> {
    if !name_valid(name) {
        return Err(Error::bad("invalid RubyGems name"));
    }
    app.text_metadata(format!(
        "{}/info/{name}",
        app.config.upstream.rubygems.trim_end_matches('/')
    ))
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub gems: Option<String>,
}

pub async fn dependencies(
    State(app): State<App>,
    Query(query): Query<Selection>,
) -> Result<Response> {
    let names: BTreeSet<_> = query
        .gems
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .collect();
    if names.len() > MAX_NAMES || names.iter().any(|name| !name_valid(name)) {
        return Err(Error::bad(
            "RubyGems requests require at most 100 valid gem names",
        ));
    }
    let policy = app.config.policy_for("rubygems");
    let now = Utc::now();
    let max = app.config.upstream.max_metadata_mb * 1024 * 1024;
    let mut entries = Vec::new();
    let mut count = 0;
    for name in names {
        let data = match raw(&app, name).await {
            Ok(data) => data,
            Err(e) if e.0 == StatusCode::NOT_FOUND => continue,
            Err(e) => return Err(e),
        };
        for release in parse(
            data.as_str()
                .ok_or_else(|| Error::upstream("invalid cached RubyGems info"))?,
        )? {
            if !policy.allows_time(release.created_at, now) {
                continue;
            }
            marshal_release(&mut entries, name, &release);
            if entries.len() > max {
                return Err(Error::upstream("RubyGems dependency response too large"));
            }
            count += 1;
        }
    }
    let mut body = vec![4, 8, b'['];
    marshal_len(&mut body, count);
    body.extend(entries);
    Ok(binary(body))
}

fn binary(body: Vec<u8>) -> Response {
    (
        [
            ("content-type", "application/octet-stream"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response()
}

// Only emit Marshal's primitive array/hash/symbol/string subset. Never deserialize
// upstream Marshal objects or run Ruby. Lengths are bounded by metadata limits.
fn marshal_len(out: &mut Vec<u8>, value: usize) {
    if value == 0 {
        out.push(0);
    } else if value < 123 {
        out.push(value as u8 + 5);
    } else {
        let bytes = (value as u32).to_le_bytes();
        let len = 4 - bytes.iter().rev().take_while(|&&b| b == 0).count();
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
}
fn marshal_string(out: &mut Vec<u8>, value: &str) {
    out.push(b'"');
    marshal_len(out, value.len());
    out.extend_from_slice(value.as_bytes());
}
fn marshal_key(out: &mut Vec<u8>, key: &str) {
    out.push(b':');
    marshal_len(out, key.len());
    out.extend_from_slice(key.as_bytes());
}
fn marshal_release(out: &mut Vec<u8>, name: &str, release: &Release<'_>) {
    out.push(b'{');
    marshal_len(out, 4);
    for (key, value) in [
        ("name", name),
        ("number", release.version),
        ("platform", release.platform),
    ] {
        marshal_key(out, key);
        marshal_string(out, value);
    }
    marshal_key(out, "dependencies");
    out.push(b'[');
    marshal_len(out, release.dependencies.len());
    for (name, constraints) in &release.dependencies {
        out.push(b'[');
        marshal_len(out, 2);
        marshal_string(out, name);
        marshal_string(out, constraints);
    }
}

/// A filename has no unambiguous name/version delimiter. Check a bounded set of
/// syntactically possible splits against authoritative metadata, rejecting collisions.
async fn authorize(app: &App, stem: &str, now: DateTime<Utc>) -> Result<(String, String)> {
    if stem.len() > 472 || !name_valid_filename(stem) {
        return Err(Error::bad("invalid gem filename"));
    }
    let candidates: Vec<_> = stem
        .match_indices('-')
        .filter_map(|(i, _)| {
            let (name, rest) = (&stem[..i], &stem[i + 1..]);
            (name_valid(name) && split_release(rest).is_some()).then_some((name, rest))
        })
        .collect();
    if candidates.is_empty() || candidates.len() > MAX_CANDIDATES {
        return Err(Error::bad("invalid or overly ambiguous gem filename"));
    }
    let policy: Policy = app.config.policy_for("rubygems");
    let mut selected = None;
    for (name, identity) in candidates {
        let data = match raw(app, name).await {
            Ok(data) => data,
            Err(e) if e.0 == StatusCode::NOT_FOUND => continue,
            Err(e) => return Err(e),
        };
        for release in parse(
            data.as_str()
                .ok_or_else(|| Error::upstream("invalid cached RubyGems info"))?,
        )? {
            let canonical = if release.platform == "ruby" {
                release.version.to_owned()
            } else {
                format!("{}-{}", release.version, release.platform)
            };
            if canonical == identity {
                if selected.is_some() {
                    return Err(Error::denied("ambiguous gem identity"));
                }
                selected = Some((
                    name.to_owned(),
                    canonical,
                    policy.allows_time(release.created_at, now),
                ));
            }
        }
    }
    match selected {
        Some((name, identity, true)) => Ok((name, identity)),
        Some(_) => Err(Error::denied("gem does not meet the age policy")),
        None => Err(Error::missing("gem release not found")),
    }
}
fn name_valid_filename(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub async fn download(
    State(app): State<App>,
    Path(filename): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Result<Response> {
    let stem = filename
        .strip_suffix(".gem")
        .ok_or_else(|| Error::bad("expected .gem filename"))?;
    let (name, release) = authorize(&app, stem, Utc::now()).await?;
    let url = format!(
        "{}/gems/{filename}",
        app.config.upstream.rubygems.trim_end_matches('/')
    );
    let identity = (method == Method::GET).then(|| Identity::new("rubygems", &name, &release));
    app.stream_download(&url, headers, identity).await
}

pub async fn gemspec(State(app): State<App>, Path(filename): Path<String>) -> Result<Response> {
    let stem = filename
        .strip_suffix(".gemspec.rz")
        .ok_or_else(|| Error::bad("expected .gemspec.rz filename"))?;
    authorize(&app, stem, Utc::now()).await?;
    // Compressed gemspecs are bounded opaque data; never deserialize or execute them.
    let url = format!(
        "{}/quick/Marshal.4.8/{filename}",
        app.config.upstream.rubygems.trim_end_matches('/')
    );
    app.allowed_artifact(&url)?;
    Ok(binary(
        app.fetch_metadata(&url, "application/octet-stream").await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_platforms_constraints_and_timestamp_colons() {
        let info = format!(
            "---\n1.2.0.pre-x86_64-linux dep:>= 1.0&< 2.0|checksum:{},ruby:>= 2.6,created_at:2020-01-01T01:02:03Z\n",
            "a".repeat(64)
        );
        let parsed = parse(&info).unwrap();
        assert_eq!(parsed[0].platform, "x86_64-linux");
        assert_eq!(parsed[0].dependencies[0], ("dep", ">= 1.0, < 2.0".into()));
        assert_eq!(parsed[0].created_at, Some("2020-01-01T01:02:03Z"));
    }
    #[test]
    fn publication_boundary_changes_without_rewriting_cached_text() {
        let info = format!(
            "---\n1.0 |checksum:{},created_at:2020-01-01T01:02:03Z\n",
            "a".repeat(64)
        );
        let releases = parse(&info).unwrap();
        let boundary = DateTime::parse_from_rfc3339("2020-01-08T01:02:03Z")
            .unwrap()
            .with_timezone(&Utc);
        let policy = Policy::default();
        assert!(!policy.allows_time(
            releases[0].created_at,
            boundary - chrono::Duration::seconds(1)
        ));
        assert!(policy.allows_time(releases[0].created_at, boundary));
    }

    #[test]
    fn rejects_corrupt_metadata_and_duplicate_identities() {
        let line = format!("1.0 |checksum:{}\n", "a".repeat(64));
        assert!(parse(&format!("---\n{line}{line}")).is_err());
        assert!(parse("---\n1.0 |checksum:invalid\n").is_err());
        assert!(parse("not an index").is_err());
        assert!(!name_valid("../evil"));
        assert!(!constraints_valid(">= 1.0|evil"));
    }
}
