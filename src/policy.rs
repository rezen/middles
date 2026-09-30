use crate::inspection::HookPolicy;
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryPolicy {
    #[default]
    Off,
    Report,
    Deny,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub min_age_days: u32,
    /// Package-wide downloads in the provider's monthly window, not per-version downloads.
    pub min_monthly_downloads: u64,
    pub install_hooks: HookPolicy,
    pub advisories: AdvisoryPolicy,
    pub advisory_deny_cvss: f64,
    pub advisory_waivers: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_age_days: 7,
            min_monthly_downloads: 0,
            install_hooks: HookPolicy::Report,
            advisories: AdvisoryPolicy::Off,
            advisory_deny_cvss: 7.0,
            advisory_waivers: Vec::new(),
        }
    }
}

impl Policy {
    pub fn allows_time(&self, timestamp: Option<&str>, now: DateTime<Utc>) -> bool {
        timestamp
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .is_some_and(|t| self.allows_timestamp(t.timestamp(), now.timestamp()))
    }

    pub fn allows_timestamp(&self, timestamp: i64, now: i64) -> bool {
        now.checked_sub(timestamp)
            .is_some_and(|age| age >= i64::from(self.min_age_days) * 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inclusive_boundary_and_fail_closed_dates() {
        let p = Policy::default();
        let now = DateTime::parse_from_rfc3339("2026-09-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(p.allows_time(Some("2026-09-20T12:00:00Z"), now));
        assert!(!p.allows_time(Some("2026-09-20T12:00:01Z"), now));
        assert!(!p.allows_time(Some("2026-09-28T12:00:00Z"), now));
        assert!(!p.allows_time(None, now));
        assert!(!p.allows_time(Some("invalid"), now));
        assert!(
            !Policy {
                min_age_days: 0,
                ..p
            }
            .allows_time(None, now)
        );
    }

    #[test]
    fn advisory_defaults_and_inheritance_validation() {
        let mut config = crate::config::Config::default();
        assert_eq!(
            config
                .policy_for(crate::registry::Ecosystem::Npm)
                .advisories,
            AdvisoryPolicy::Off
        );
        config.policy.advisories = AdvisoryPolicy::Deny;
        assert!(config.validate().is_err());
        config.homebrew.policy.advisories = Some(AdvisoryPolicy::Off);
        config.apt.policy.advisories = Some(AdvisoryPolicy::Off);
        assert!(config.validate().is_ok());
        config.pip.advisory_deny_cvss = Some(10.1);
        assert!(config.validate().is_err());
    }

    #[test]
    fn apt_advisories_require_explicit_release_mapping() {
        use crate::config::{AptRepo, Config};
        let mut config = Config::default();
        config.apt.enabled = true;
        config.apt.policy.advisories = Some(AdvisoryPolicy::Report);
        config
            .upstream
            .artifact_hosts
            .push("archive.ubuntu.com".into());
        config.apt.repos = vec![AptRepo {
            name: "ubuntu".into(),
            url: "https://archive.ubuntu.com/ubuntu".into(),
            suites: vec!["noble".into()],
            components: vec!["main".into()],
            architectures: vec!["amd64".into()],
            min_age_days: None,
            osv_ecosystem: None,
        }];
        assert!(config.validate().is_err());
        config.apt.repos[0].osv_ecosystem = Some("Ubuntu:24.04:LTS".into());
        assert!(config.validate().is_ok(), "{:?}", config.validate());
        config.apt.repos[0].osv_ecosystem = Some("Ubuntu:noble".into());
        assert!(config.validate().is_err());
    }
}
