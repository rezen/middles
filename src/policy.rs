use crate::inspection::HookPolicy;
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub min_age_days: u32,
    /// Package-wide downloads in the provider's monthly window, not per-version downloads.
    pub min_monthly_downloads: u64,
    pub install_hooks: HookPolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_age_days: 7,
            min_monthly_downloads: 0,
            install_hooks: HookPolicy::Report,
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
}
