//! Exact-version published-advisory evidence from OSV. Verdicts are recomputed
//! from raw cached responses, so policy changes do not require cache eviction.
use crate::{
    App,
    config::AdvisorySource,
    error::{Error, Result},
    policy::{AdvisoryPolicy, Policy},
    registry::Ecosystem,
};
use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use chrono::Utc;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: Option<f64>,
    pub summary: Option<String>,
    pub references: Vec<String>,
    pub waived: bool,
    pub malicious: bool,
    pub denies: bool,
    pub match_uncertain: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub ecosystem: &'static str,
    pub package: String,
    pub version: String,
    pub policy: AdvisoryPolicy,
    pub advisory_deny_cvss: f64,
    pub advisories: Vec<Finding>,
    pub blocked_by_advisory_policy: bool,
    pub other_policies_evaluated: bool,
    pub limitations: Vec<&'static str>,
}

fn osv_ecosystem(ecosystem: Ecosystem) -> Result<&'static str> {
    match ecosystem {
        Ecosystem::Npm => Ok("npm"),
        Ecosystem::Pip => Ok("PyPI"),
        Ecosystem::Composer => Ok("Packagist"),
        Ecosystem::Rubygems => Ok("RubyGems"),
        Ecosystem::Homebrew | Ecosystem::Apt => Err(Error::bad(
            "advisory inspection is unavailable for this ecosystem",
        )),
    }
}

fn advisory_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn withdrawn(record: &Value) -> Result<bool> {
    match record.get("withdrawn") {
        Some(Value::String(_)) => Ok(true),
        Some(Value::Null) | None => Ok(false),
        _ => Err(Error::upstream("invalid OSV withdrawal date")),
    }
}

fn package_name(ecosystem: Ecosystem, package: &str) -> Result<String> {
    match ecosystem {
        Ecosystem::Npm => {
            crate::registry::npm_name(package)?;
            Ok(package.to_owned())
        }
        Ecosystem::Pip => crate::registry::pip::normalize(package),
        Ecosystem::Composer => {
            crate::registry::composer_name(package)?;
            Ok(package.to_owned())
        }
        Ecosystem::Rubygems => {
            if crate::registry::component(package) {
                Ok(package.to_owned())
            } else {
                Err(Error::bad("invalid RubyGems name"))
            }
        }
        _ => Err(Error::bad("unsupported advisory ecosystem")),
    }
}

/// Derive the exact release in a PyPI Simple API entry without consulting
/// release-level metadata, which can disagree with the selected file.
pub(crate) fn pip_version(package: &str, filename: &str) -> Result<String> {
    let (stem, wheel) = if let Some(stem) = filename.strip_suffix(".whl") {
        (stem, true)
    } else if let Some(stem) = filename.strip_suffix(".tar.gz") {
        (stem, false)
    } else if let Some(stem) = filename.strip_suffix(".zip") {
        (stem, false)
    } else if let Some(stem) = filename.strip_suffix(".tar.bz2") {
        (stem, false)
    } else {
        return Err(Error::upstream(
            "unsupported Python distribution filename for advisory lookup",
        ));
    };
    let (name, version) = if wheel {
        let mut parts = stem.split('-');
        (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
    } else {
        stem.rsplit_once('-')
            .ok_or_else(|| Error::upstream("Python source filename has no version"))?
    };
    if crate::registry::pip::normalize(name).ok().as_deref() != Some(package)
        || version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+!".contains(&b))
    {
        return Err(Error::upstream(
            "Python filename identity cannot be verified for advisory lookup",
        ));
    }
    Ok(version.to_owned())
}

impl App {
    pub async fn advisory_status(&self) -> Result<Value> {
        let imports = self.store.read_database(|db| {
            let mut query = db.prepare("SELECT ecosystem, imported_at, records, source FROM advisory_imports ORDER BY ecosystem")?;
            query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()
        }).await?;
        let now = Utc::now().timestamp();
        Ok(
            json!({"source":self.config.advisory_source,"max_staleness_secs":self.config.advisory_max_staleness_secs,
            "imports":imports.into_iter().map(|(ecosystem, imported_at, records, source)| json!({
                "ecosystem":ecosystem,"imported_at":chrono::DateTime::<Utc>::from_timestamp(imported_at,0).map(|t| t.to_rfc3339()),
                "age_secs":now.saturating_sub(imported_at),"stale":imported_at > now || now.saturating_sub(imported_at) > self.config.advisory_max_staleness_secs as i64,
                "records":records,"source":source
            })).collect::<Vec<_>>() }),
        )
    }
    async fn local_records(&self, osv: &str, package: &str) -> Result<Vec<Value>> {
        let imported_ecosystem = osv.split(':').next().unwrap_or(osv).to_owned();
        let osv = osv.to_owned();
        let package = package.to_owned();
        let (imported_at, bodies) = self.store.read_database(move |db| {
            let imported_at: Option<i64> = db.query_row("SELECT imported_at FROM advisory_imports WHERE ecosystem = ?1", [&imported_ecosystem], |r| r.get(0)).optional()?;
            let mut query = db.prepare("SELECT body FROM advisories WHERE ecosystem = ?1 AND (package = ?2 OR package = '*') LIMIT 10001")?;
            let bodies = query.query_map(rusqlite::params![osv, package], |r| r.get::<_, Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((imported_at, bodies))
        }).await?;
        let now = Utc::now().timestamp();
        if !imported_at
            .is_some_and(|t| t <= now && now - t <= self.config.advisory_max_staleness_secs as i64)
        {
            return Err(Error::upstream("local advisory mirror is missing or stale"));
        }
        if bodies.len() > 10_000 || bodies.iter().map(Vec::len).sum::<usize>() > 64 * 1024 * 1024 {
            return Err(Error::upstream(
                "local advisory package exceeds supported bounds",
            ));
        }
        bodies
            .into_iter()
            .map(|body| {
                serde_json::from_slice(&body)
                    .map_err(|_| Error::upstream("invalid local advisory record"))
            })
            .collect()
    }

    async fn local_blocked_versions(
        &self,
        osv: &str,
        package: &str,
        versions: &[String],
        policy: &Policy,
    ) -> Result<HashSet<String>> {
        let records = self.local_records(osv, package).await?;
        let mut blocked = HashSet::new();
        for version in versions {
            for record in &records {
                if withdrawn(record)? {
                    continue;
                }
                if local_matches(record, osv, package, version)?.is_some()
                    && finding(record, policy)?.denies
                {
                    blocked.insert(version.clone());
                    break;
                }
            }
        }
        Ok(blocked)
    }

    /// Determine which already eligible versions should be hidden from a
    /// resolver. The service, rather than local range code, matches versions.
    pub async fn blocked_advisory_versions(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        versions: &[String],
    ) -> Result<HashSet<String>> {
        if self.config.policy_for(ecosystem).advisories != AdvisoryPolicy::Deny
            || versions.is_empty()
        {
            return Ok(HashSet::new());
        }
        let osv = osv_ecosystem(ecosystem)?;
        let package = package_name(ecosystem, package)?;
        if versions.len() > 20_000
            || versions
                .iter()
                .any(|v| v.is_empty() || v.len() > 256 || v.bytes().any(|b| b.is_ascii_control()))
        {
            return Err(Error::upstream(
                "advisory version listing exceeds supported bounds",
            ));
        }
        let policy = self.config.policy_for(ecosystem);
        if self.config.advisory_source == AdvisorySource::Local {
            return self
                .local_blocked_versions(osv, &package, versions, &policy)
                .await;
        }
        let mut blocked = HashSet::new();
        for chunk in versions.chunks(128) {
            let mut ids: Vec<HashSet<String>> = vec![HashSet::new(); chunk.len()];
            let mut pending: Vec<(usize, Option<String>)> =
                (0..chunk.len()).map(|i| (i, None)).collect();
            for _ in 0..16 {
                if pending.is_empty() {
                    break;
                }
                let queries: Vec<Value> = pending
                    .iter()
                    .map(|(i, token)| {
                        let mut query =
                            json!({"version":chunk[*i],"package":{"name":package,"ecosystem":osv}});
                        if let Some(token) = token {
                            query["page_token"] = json!(token);
                        }
                        query
                    })
                    .collect();
                let body = serde_json::to_vec(&json!({"queries":queries}))
                    .map_err(|_| Error::internal("OSV batch serialization"))?;
                let url = format!(
                    "{}/v1/querybatch",
                    self.config.upstream.osv.trim_end_matches('/')
                );
                let response = self.post_metadata(url, body).await?;
                let results = response
                    .get("results")
                    .and_then(Value::as_array)
                    .filter(|r| r.len() == pending.len())
                    .ok_or_else(|| Error::upstream("invalid OSV batch result count"))?;
                let mut next = Vec::new();
                for ((i, _), result) in pending.iter().zip(results) {
                    if !result.is_object() {
                        return Err(Error::upstream("invalid OSV batch result"));
                    }
                    if let Some(vulns) = result.get("vulns") {
                        for vuln in vulns
                            .as_array()
                            .ok_or_else(|| Error::upstream("invalid OSV batch advisories"))?
                        {
                            let id = vuln
                                .get("id")
                                .and_then(Value::as_str)
                                .ok_or_else(|| Error::upstream("OSV batch advisory has no ID"))?;
                            if !advisory_id(id) {
                                return Err(Error::upstream("invalid OSV advisory ID"));
                            }
                            ids[*i].insert(id.to_owned());
                        }
                    }
                    match result.get("next_page_token") {
                        None => {}
                        Some(Value::String(token)) if token.is_empty() => {}
                        Some(Value::String(token)) if !token.is_empty() && token.len() <= 1024 => {
                            next.push((*i, Some(token.clone())))
                        }
                        _ => return Err(Error::upstream("invalid OSV batch pagination")),
                    }
                }
                pending = next;
            }
            if !pending.is_empty() {
                return Err(Error::upstream("OSV batch pagination limit exceeded"));
            }
            let unique: HashSet<_> = ids.iter().flat_map(|set| set.iter().cloned()).collect();
            if unique.len() > 10_000 {
                return Err(Error::upstream("OSV batch advisory limit exceeded"));
            }
            let mut denied = HashSet::new();
            use futures_util::stream::{self, StreamExt};
            let mut records = stream::iter(unique.into_iter().map(|id| async move {
                let url = format!(
                    "{}/v1/vulns/{id}",
                    self.config.upstream.osv.trim_end_matches('/')
                );
                let record = self
                    .metadata(url, "application/json", true)
                    .await
                    .map_err(|e| {
                        if e.0 == axum::http::StatusCode::NOT_FOUND {
                            Error::upstream("OSV advisory record not found")
                        } else {
                            e
                        }
                    })?;
                if record.get("id").and_then(Value::as_str) != Some(id.as_str()) {
                    return Err(Error::upstream("OSV advisory ID mismatch"));
                }
                Ok::<_, Error>((id, record))
            }))
            .buffer_unordered(8);
            while let Some(record) = records.next().await {
                let (id, record) = record?;
                if !withdrawn(&record)? && finding(&record, &policy)?.denies {
                    denied.insert(id);
                }
            }
            for (version, version_ids) in chunk.iter().zip(ids) {
                if version_ids.iter().any(|id| denied.contains(id)) {
                    blocked.insert(version.clone());
                }
            }
        }
        Ok(blocked)
    }

    pub(crate) async fn post_metadata(
        &self,
        url: String,
        body: Vec<u8>,
    ) -> Result<std::sync::Arc<Value>> {
        let digest = Sha256::digest(&body);
        let key = format!("post:application/json:{url}:{digest:x}");
        self.store
            .get(key, true, || async {
                let _permit = self
                    .metadata_permits
                    .acquire()
                    .await
                    .map_err(|_| Error::internal("shutdown"))?;
                let response = self
                    .client
                    .post(&url)
                    .header("accept", "application/json")
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| Error::upstream(e.to_string()))?;
                if !response.status().is_success() {
                    return Err(Error::upstream(format!(
                        "OSV returned {}",
                        response.status()
                    )));
                }
                let max = self.config.upstream.max_metadata_mb * 1024 * 1024;
                if response.content_length().is_some_and(|n| n > max as u64) {
                    return Err(Error::upstream("OSV response too large"));
                }
                let mut bytes = Vec::new();
                use futures_util::StreamExt;
                let mut chunks = response.bytes_stream();
                while let Some(chunk) = chunks.next().await {
                    let chunk = chunk.map_err(|e| Error::upstream(e.to_string()))?;
                    if bytes.len().saturating_add(chunk.len()) > max {
                        return Err(Error::upstream("OSV response too large"));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(bytes)
            })
            .await
    }

    pub async fn advisory_report(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
    ) -> Result<Report> {
        let osv = osv_ecosystem(ecosystem)?;
        let package = package_name(ecosystem, package)?;
        self.advisory_report_mapped(ecosystem, osv, &package, version)
            .await
    }

    pub(crate) async fn advisory_report_mapped(
        &self,
        ecosystem: Ecosystem,
        osv: &str,
        package: &str,
        version: &str,
    ) -> Result<Report> {
        if version.is_empty()
            || version.len() > 256
            || version.bytes().any(|b| b.is_ascii_control())
        {
            return Err(Error::bad("invalid exact version"));
        }
        let policy = self.config.policy_for(ecosystem);
        if self.config.advisory_source == AdvisorySource::Local {
            let records = self.local_records(osv, package).await?;
            let mut findings = Vec::new();
            for record in records {
                if withdrawn(&record)? {
                    continue;
                }
                if let Some(uncertain) = local_matches(&record, osv, package, version)? {
                    let mut item = finding(&record, &policy)?;
                    item.match_uncertain = uncertain;
                    findings.push(item);
                }
            }
            return Ok(make_report(
                ecosystem,
                package.to_owned(),
                version,
                &policy,
                findings,
                true,
            ));
        }
        let mut findings = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..16 {
            let mut body = json!({"version":version,"package":{"name":package,"ecosystem":osv}});
            if let Some(ref token) = token {
                body["page_token"] = json!(token);
            }
            let bytes = serde_json::to_vec(&body)
                .map_err(|_| Error::internal("OSV query serialization"))?;
            let url = format!(
                "{}/v1/query",
                self.config.upstream.osv.trim_end_matches('/')
            );
            let response = self.post_metadata(url, bytes).await?;
            if !response.is_object() {
                return Err(Error::upstream("invalid OSV query response"));
            }
            let records = match response.get("vulns") {
                None => None,
                Some(Value::Array(records)) => Some(records),
                _ => return Err(Error::upstream("invalid OSV advisory list")),
            };
            if let Some(records) = records {
                for record in records {
                    if withdrawn(record)? {
                        continue;
                    }
                    findings.push(finding(record, &policy)?);
                    if findings.len() > 10_000 {
                        return Err(Error::upstream("OSV advisory limit exceeded"));
                    }
                }
            }
            token = match response.get("next_page_token") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) if s.is_empty() => None,
                Some(Value::String(s)) if s.len() <= 1024 => Some(s.clone()),
                _ => return Err(Error::upstream("invalid OSV pagination token")),
            };
            if token.is_none() {
                break;
            }
        }
        if token.is_some() {
            return Err(Error::upstream("OSV pagination limit exceeded"));
        }
        Ok(make_report(
            ecosystem,
            package.to_owned(),
            version,
            &policy,
            findings,
            false,
        ))
    }

    pub async fn check_advisories(
        &self,
        ecosystem: Ecosystem,
        package: &str,
        version: &str,
    ) -> Result<()> {
        if self.config.policy_for(ecosystem).advisories == AdvisoryPolicy::Off {
            return Ok(());
        }
        let report = self.advisory_report(ecosystem, package, version).await?;
        self.enforce_advisory_report(package, version, report)
    }

    pub(crate) async fn check_advisories_mapped(
        &self,
        ecosystem: Ecosystem,
        osv: &str,
        package: &str,
        version: &str,
    ) -> Result<()> {
        if self.config.policy_for(ecosystem).advisories == AdvisoryPolicy::Off {
            return Ok(());
        }
        let report = self
            .advisory_report_mapped(ecosystem, osv, package, version)
            .await?;
        self.enforce_advisory_report(package, version, report)
    }

    fn enforce_advisory_report(&self, package: &str, version: &str, report: Report) -> Result<()> {
        if report.blocked_by_advisory_policy {
            let ids = report
                .advisories
                .iter()
                .filter(|f| f.denies)
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::denied(format!(
                "{package}@{version} blocked by published advisory: {ids}"
            )));
        }
        Ok(())
    }
}

fn make_report(
    ecosystem: Ecosystem,
    package: String,
    version: &str,
    policy: &Policy,
    findings: Vec<Finding>,
    local: bool,
) -> Report {
    let blocked = policy.advisories == AdvisoryPolicy::Deny && findings.iter().any(|f| f.denies);
    let mut limitations = vec![
        "Published metadata only; archives, unpublished vulnerabilities, and unknown malware are not scanned.",
        "Only this advisory policy is evaluated. Inspection grants no artifact access.",
    ];
    if local {
        limitations.push("The local mirror uses enumerated versions and Debian/Ubuntu ecosystem ranges. Unknown ranges or missing version evidence are conservatively treated as possibly affecting the package version.");
    }
    Report {
        ecosystem: ecosystem.as_str(),
        package,
        version: version.to_owned(),
        policy: policy.advisories,
        advisory_deny_cvss: policy.advisory_deny_cvss,
        advisories: findings,
        blocked_by_advisory_policy: blocked,
        other_policies_evaluated: false,
        limitations,
    }
}

/// `Some(true)` means the export could not establish whether this version is
/// affected, so the record must be handled conservatively.
fn local_matches(record: &Value, osv: &str, package: &str, version: &str) -> Result<Option<bool>> {
    let affected = record
        .get("affected")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::upstream("local advisory missing affected packages"))?;
    let mut uncertain = false;
    for entry in affected {
        let identity = entry
            .get("package")
            .ok_or_else(|| Error::upstream("local advisory missing package identity"))?;
        if identity.get("ecosystem").and_then(Value::as_str) != Some(osv)
            || !matches!(identity.get("name").and_then(Value::as_str), Some(name) if name == package || name == "*")
        {
            continue;
        }
        let versions = match entry.get("versions") {
            Some(Value::Array(versions)) => Some(versions),
            None => None,
            _ => return Err(Error::upstream("invalid local advisory versions")),
        };
        if versions.is_some_and(|versions| versions.iter().any(|v| v.as_str() == Some(version))) {
            return Ok(Some(false));
        }
        let ranges: &[Value] = match entry.get("ranges") {
            Some(Value::Array(ranges)) => ranges,
            None => &[],
            _ => return Err(Error::upstream("invalid local advisory ranges")),
        };
        if (osv.starts_with("Debian:") || osv.starts_with("Ubuntu:")) && !ranges.is_empty() {
            let mut unknown = false;
            for range in ranges {
                match debian_range_matches(range, version) {
                    Some(true) => return Ok(Some(false)),
                    Some(false) => {}
                    None => unknown = true,
                }
            }
            uncertain |= unknown;
        } else if versions.is_none_or(Vec::is_empty) {
            uncertain = true;
        }
    }
    Ok(uncertain.then_some(true))
}

fn debian_range_matches(range: &Value, version: &str) -> Option<bool> {
    use std::cmp::Ordering;
    if range.get("type")?.as_str()? != "ECOSYSTEM" {
        return None;
    }
    let events = range.get("events")?.as_array()?;
    if events.is_empty() {
        return None;
    }
    let mut introduced: Option<&str> = None;
    let mut matched = false;
    for event in events {
        let obj = event.as_object()?;
        if obj.len() != 1 {
            return None;
        }
        if let Some(start) = obj.get("introduced") {
            if introduced.is_some() {
                return None;
            }
            introduced = Some(start.as_str()?);
        } else {
            let end = obj.get("fixed").or_else(|| obj.get("last_affected"))?;
            let start = introduced.take()?;
            let after_start =
                start == "0" || crate::debian_version::compare(version, start)? != Ordering::Less;
            let comparison = crate::debian_version::compare(version, end.as_str()?)?;
            let before_end = if obj.contains_key("fixed") {
                comparison == Ordering::Less
            } else {
                comparison != Ordering::Greater
            };
            matched |= after_start && before_end;
        }
    }
    if let Some(start) = introduced {
        matched |=
            start == "0" || crate::debian_version::compare(version, start)? != Ordering::Less;
    }
    Some(matched)
}

fn finding(record: &Value, policy: &Policy) -> Result<Finding> {
    let invalid = || Error::upstream("invalid OSV advisory record");
    let id = record
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(invalid)?
        .to_owned();
    let aliases: Vec<String> = record
        .get("aliases")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|_| invalid())?
        .unwrap_or_default();
    let references: Vec<String> = record
        .get("references")
        .map(|v| {
            v.as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|r| {
                    r.get("url")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(invalid)
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let waived = std::iter::once(&id)
        .chain(aliases.iter())
        .any(|id| policy.advisory_waivers.iter().any(|waiver| waiver == id));
    let malicious = id.starts_with("MAL-")
        || aliases.iter().any(|s| s.starts_with("MAL-"))
        || record
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.starts_with("Malicious code in "))
        || record
            .pointer("/database_specific/type")
            .and_then(Value::as_str)
            .is_some_and(|s| s.eq_ignore_ascii_case("malware"));
    let severity = score(record)?;
    let denies = !waived && (malicious || severity.is_none_or(|s| s >= policy.advisory_deny_cvss));
    Ok(Finding {
        id,
        aliases,
        severity,
        summary: record
            .get("summary")
            .and_then(Value::as_str)
            .map(str::to_owned),
        references,
        waived,
        malicious,
        denies,
        match_uncertain: false,
    })
}

fn score(record: &Value) -> Result<Option<f64>> {
    let mut scores = Vec::new();
    let mut unscored_vector = false;
    let mut vectors = Vec::new();
    if let Some(value) = record.get("severity") {
        vectors.extend(
            value
                .as_array()
                .ok_or_else(|| Error::upstream("invalid OSV severity"))?,
        );
    }
    if let Some(affected) = record.get("affected") {
        for item in affected
            .as_array()
            .ok_or_else(|| Error::upstream("invalid OSV affected list"))?
        {
            if let Some(value) = item.get("severity") {
                vectors.extend(
                    value
                        .as_array()
                        .ok_or_else(|| Error::upstream("invalid OSV severity"))?,
                );
            }
        }
    }
    for entry in vectors {
        let kind = entry
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::upstream("invalid OSV severity type"))?;
        let vector = entry
            .get("score")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::upstream("invalid OSV severity vector"))?;
        let parsed = match kind {
            "CVSS_V2" => cvss_v2(vector),
            "CVSS_V3" | "CVSS_V4" => vector.parse::<cvss::Cvss>().ok().map(|v| v.score()),
            _ => None,
        };
        if let Some(value) = parsed {
            scores.push(value);
        } else if matches!(kind, "CVSS_V2" | "CVSS_V3" | "CVSS_V4") {
            unscored_vector = true;
        }
    }
    if unscored_vector {
        return Ok(None);
    }
    if let Some(score) = scores.into_iter().max_by(f64::total_cmp) {
        return Ok(Some(score));
    }
    Ok(record
        .pointer("/database_specific/severity")
        .and_then(Value::as_str)
        .and_then(qualitative))
}

fn qualitative(value: &str) -> Option<f64> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Some(3.9),
        "moderate" | "medium" => Some(6.9),
        "high" => Some(8.9),
        "critical" => Some(10.0),
        _ => None,
    }
}

fn cvss_v2(vector: &str) -> Option<f64> {
    let vector = vector.strip_prefix("CVSS:2.0/").unwrap_or(vector);
    let mut metrics = std::collections::HashMap::new();
    for part in vector.split('/') {
        let (key, value) = part.split_once(':')?;
        if metrics.insert(key, value).is_some() {
            return None;
        }
    }
    if metrics.len() != 6 {
        return None;
    }
    let lookup = |key, values: &[(&str, f64)]| -> Option<f64> {
        let value = *metrics.get(key)?;
        values
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, n)| *n)
    };
    let av = lookup("AV", &[("L", 0.395), ("A", 0.646), ("N", 1.0)])?;
    let ac = lookup("AC", &[("H", 0.35), ("M", 0.61), ("L", 0.71)])?;
    let au = lookup("Au", &[("M", 0.45), ("S", 0.56), ("N", 0.704)])?;
    let impact = [
        ("C", [("N", 0.0), ("P", 0.275), ("C", 0.660)]),
        ("I", [("N", 0.0), ("P", 0.275), ("C", 0.660)]),
        ("A", [("N", 0.0), ("P", 0.275), ("C", 0.660)]),
    ];
    let [c, i, a] = impact
        .map(|(key, values)| lookup(key, &values))
        .map(|v| v.unwrap_or(f64::NAN));
    if [c, i, a].iter().any(|n| n.is_nan()) {
        return None;
    }
    let impact = 10.41 * (1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a));
    if impact == 0.0 {
        return Some(0.0);
    }
    let raw: f64 = ((0.6 * impact) + (0.4 * 20.0 * av * ac * au) - 1.5) * 1.176;
    Some((raw * 10.0).round() / 10.0)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    version: String,
}

pub async fn inspect(
    State(app): State<App>,
    Path((ecosystem, package)): Path<(String, String)>,
    Query(selection): Query<Selection>,
) -> Result<Response> {
    let ecosystem = Ecosystem::parse(&ecosystem)?;
    let report = app
        .advisory_report(ecosystem, &package, &selection.version)
        .await?;
    Ok(crate::json_response(
        serde_json::to_value(report)
            .map_err(|_| Error::internal("advisory report serialization"))?,
        "application/json",
    ))
}

pub async fn status(State(app): State<App>) -> Result<Response> {
    Ok(crate::json_response(
        app.advisory_status().await?,
        "application/json",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cvss_and_policy_boundaries() {
        assert_eq!(cvss_v2("AV:N/AC:L/Au:N/C:C/I:C/A:C"), Some(10.0));
        assert_eq!(cvss_v2("AV:N/AC:L/Au:N/C:N/I:N/A:N"), Some(0.0));
        assert_eq!(cvss_v2("AV:N/AC:M/Au:N/C:P/I:N/A:N"), Some(4.3));
        let mut policy = Policy {
            advisories: AdvisoryPolicy::Deny,
            ..Default::default()
        };
        let high = json!({"id":"GHSA-test", "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]});
        assert_eq!(finding(&high, &policy).unwrap().severity, Some(9.8));
        assert!(finding(&high, &policy).unwrap().denies);
        policy.advisory_waivers.push("CVE-1".into());
        let alias = json!({"id":"GHSA-test","aliases":["CVE-1"]});
        assert!(!finding(&alias, &policy).unwrap().denies);
        assert!(finding(&json!({"id":"MAL-1"}), &policy).unwrap().denies);
        assert_eq!(qualitative("HIGH"), Some(8.9));
        assert_eq!(
            pip_version("my-package", "my_package-1.2.0-py3-none-any.whl").unwrap(),
            "1.2.0"
        );
        assert_eq!(
            pip_version("my-package", "my-package-1.2.0.tar.gz").unwrap(),
            "1.2.0"
        );
        assert!(pip_version("my-package", "other-1.2.0.whl").is_err());
        let unknown =
            json!({"id":"GHSA-unknown", "severity":[{"type":"CVSS_V4","score":"invalid"}]});
        assert!(finding(&unknown, &policy).unwrap().denies);
        let v4 = json!({"id":"GHSA-v4", "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}]});
        assert_eq!(finding(&v4, &policy).unwrap().severity, Some(10.0));
        let qualitative = json!({"id":"GHSA-band", "database_specific":{"severity":"HIGH"}});
        policy.advisory_deny_cvss = 8.9;
        assert!(finding(&qualitative, &policy).unwrap().denies);
        policy.advisory_deny_cvss = 9.0;
        assert!(!finding(&qualitative, &policy).unwrap().denies);
    }

    #[test]
    fn local_debian_ranges_respect_fixed_boundary() {
        let record = json!({"affected":[{"package":{"ecosystem":"Debian:12","name":"expat"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.5.0-1+deb12u1"}]}]}]});
        assert_eq!(
            local_matches(&record, "Debian:12", "expat", "2.5.0-1").unwrap(),
            Some(false)
        );
        assert_eq!(
            local_matches(&record, "Debian:12", "expat", "2.5.0-1+deb12u1").unwrap(),
            None
        );
        assert_eq!(
            local_matches(&record, "Debian:12", "other", "2.5.0-1").unwrap(),
            None
        );
        let unknown = json!({"affected":[{"package":{"ecosystem":"Debian:12","name":"expat"},"ranges":[{"type":"GIT","events":[{"introduced":"abc"}]}]}]});
        assert_eq!(
            local_matches(&unknown, "Debian:12", "expat", "2.5.0-1").unwrap(),
            Some(true)
        );
    }
}
