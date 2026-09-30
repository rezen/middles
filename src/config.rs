use crate::policy::Policy;
use crate::registry::Ecosystem;
use anyhow::{Context, bail};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_url: String,
    pub cache: CacheConfig,
    pub policy: Policy,
    pub advisory_source: AdvisorySource,
    pub advisory_max_staleness_secs: u64,
    pub npm: Override,
    pub pip: Override,
    pub composer: Override,
    pub rubygems: Override,
    pub homebrew: Homebrew,
    pub apt: Apt,
    pub upstream: Upstream,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorySource {
    #[default]
    Online,
    Local,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Override {
    pub min_age_days: Option<u32>,
    pub min_monthly_downloads: Option<u64>,
    pub install_hooks: Option<crate::inspection::HookPolicy>,
    pub advisories: Option<crate::policy::AdvisoryPolicy>,
    pub advisory_deny_cvss: Option<f64>,
    pub advisory_waivers: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Homebrew {
    pub enabled: bool,
    #[serde(flatten)]
    pub policy: Override,
    pub age_basis: HomebrewAgeBasis,
    pub registry: String,
    pub api: String,
    pub platforms: Vec<String>,
    pub max_api_mb: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Apt {
    pub enabled: bool,
    #[serde(flatten)]
    pub policy: Override,
    pub max_index_mb: usize,
    pub repos: Vec<AptRepo>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AptRepo {
    pub name: String,
    pub url: String,
    pub suites: Vec<String>,
    pub components: Vec<String>,
    pub architectures: Vec<String>,
    pub min_age_days: Option<u32>,
    pub osv_ecosystem: Option<String>,
}

impl Default for Apt {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: Override::default(),
            max_index_mb: 96,
            repos: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HomebrewAgeBasis {
    #[default]
    LocalFirstSeen,
    OciCreated,
}

impl Default for Homebrew {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: Override::default(),
            age_basis: HomebrewAgeBasis::default(),
            registry: "https://ghcr.io".into(),
            api: "https://formulae.brew.sh/api".into(),
            platforms: vec!["arm64_tahoe".into()],
            max_api_mb: 64,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    pub path: PathBuf,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub metadata_ttl_secs: u64,
    pub stats_ttl_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Upstream {
    pub npm: String,
    pub pypi: String,
    pub packagist: String,
    pub rubygems: String,
    pub npm_stats: String,
    pub pypi_stats: String,
    pub composer_stats: String,
    pub osv: String,
    pub artifact_hosts: Vec<String>,
    pub allow_http: bool,
    pub timeout_secs: u64,
    pub max_metadata_mb: usize,
    pub concurrency: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:6280".parse().unwrap(),
            public_url: "http://127.0.0.1:6280".into(),
            cache: CacheConfig::default(),
            policy: Policy::default(),
            advisory_source: AdvisorySource::Online,
            advisory_max_staleness_secs: 604_800,
            npm: Override::default(),
            pip: Override::default(),
            composer: Override::default(),
            rubygems: Override::default(),
            homebrew: Homebrew::default(),
            apt: Apt::default(),
            upstream: Upstream::default(),
        }
    }
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            path: "data/cache.sqlite3".into(),
            memory_mb: 64,
            disk_mb: 512,
            metadata_ttl_secs: 300,
            stats_ttl_secs: 86_400,
        }
    }
}
impl Default for Upstream {
    fn default() -> Self {
        Self {
            npm: "https://registry.npmjs.org".into(),
            pypi: "https://pypi.org".into(),
            packagist: "https://repo.packagist.org".into(),
            rubygems: "https://rubygems.org".into(),
            npm_stats: "https://api.npmjs.org".into(),
            pypi_stats: "https://pypistats.org".into(),
            composer_stats: "https://packagist.org".into(),
            osv: "https://api.osv.dev".into(),
            artifact_hosts: [
                "registry.npmjs.org",
                "files.pythonhosted.org",
                "rubygems.org",
                "api.github.com",
                "github.com",
                "codeload.github.com",
                "gitlab.com",
                "bitbucket.org",
            ]
            .map(str::to_owned)
            .to_vec(),
            allow_http: false,
            timeout_secs: 60,
            max_metadata_mb: 32,
            concurrency: 32,
        }
    }
}
impl Config {
    pub fn policy_for(&self, ecosystem: Ecosystem) -> Policy {
        let o = match ecosystem {
            Ecosystem::Npm => &self.npm,
            Ecosystem::Pip => &self.pip,
            Ecosystem::Composer => &self.composer,
            Ecosystem::Rubygems => &self.rubygems,
            Ecosystem::Homebrew => &self.homebrew.policy,
            Ecosystem::Apt => &self.apt.policy,
        };
        Policy {
            install_hooks: o.install_hooks.unwrap_or(self.policy.install_hooks),
            min_age_days: o.min_age_days.unwrap_or(self.policy.min_age_days),
            min_monthly_downloads: o
                .min_monthly_downloads
                .unwrap_or(self.policy.min_monthly_downloads),
            advisories: o.advisories.unwrap_or(self.policy.advisories),
            advisory_deny_cvss: o
                .advisory_deny_cvss
                .unwrap_or(self.policy.advisory_deny_cvss),
            advisory_waivers: o
                .advisory_waivers
                .clone()
                .unwrap_or_else(|| self.policy.advisory_waivers.clone()),
        }
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        let url = url::Url::parse(&self.public_url).context("invalid public_url")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!(
                "public_url must be an absolute HTTP(S) URL without credentials, query, or fragment"
            );
        }
        if self.cache.memory_mb == 0
            || self.cache.disk_mb == 0
            || self.cache.memory_mb > 4096
            || self.cache.disk_mb > 1_048_576
            || self.cache.metadata_ttl_secs == 0
            || self.cache.stats_ttl_secs == 0
            || self.cache.stats_ttl_secs > 31_536_000
            || self.cache.metadata_ttl_secs > 31_536_000
            || self.upstream.concurrency == 0
            || self.upstream.concurrency > 4096
            || self.upstream.max_metadata_mb == 0
            || self.upstream.max_metadata_mb > 1024
            || self.upstream.timeout_secs == 0
            || self.advisory_max_staleness_secs == 0
            || self.advisory_max_staleness_secs > 31_536_000
        {
            bail!("cache and upstream limits must be positive and within supported bounds");
        }
        for base in [
            &self.upstream.npm,
            &self.upstream.pypi,
            &self.upstream.packagist,
            &self.upstream.rubygems,
            &self.upstream.npm_stats,
            &self.upstream.pypi_stats,
            &self.upstream.composer_stats,
            &self.upstream.osv,
        ] {
            let u = url::Url::parse(base).context("invalid upstream URL")?;
            if u.host_str().is_none()
                || !(u.scheme() == "https" || self.upstream.allow_http && u.scheme() == "http")
                || !u.username().is_empty()
                || u.password().is_some()
                || u.query().is_some()
                || u.fragment().is_some()
            {
                bail!(
                    "upstream URLs require HTTPS, no credentials/query/fragment (allow_http is for local tests)"
                );
            }
        }
        let ruby = self.policy_for(Ecosystem::Rubygems);
        for ecosystem in Ecosystem::ALL {
            let policy = self.policy_for(ecosystem);
            if !policy.advisory_deny_cvss.is_finite()
                || !(0.0..=10.0).contains(&policy.advisory_deny_cvss)
            {
                bail!("advisory_deny_cvss must be between 0.0 and 10.0");
            }
            if policy.advisory_waivers.iter().any(|id| {
                id.is_empty()
                    || id.len() > 128
                    || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }) {
                bail!("advisory_waivers must contain valid advisory IDs");
            }
            if ecosystem == Ecosystem::Homebrew
                && policy.advisories == crate::policy::AdvisoryPolicy::Deny
            {
                bail!(
                    "advisory denial is unavailable for Homebrew; explicitly set advisories = \"off\" or \"report\""
                );
            }
        }
        if ruby.min_monthly_downloads != 0 {
            bail!(
                "RubyGems monthly download evidence is unavailable; set [rubygems] min_monthly_downloads = 0"
            );
        }
        if ruby.install_hooks == crate::inspection::HookPolicy::Deny {
            bail!(
                "RubyGems install-hook enforcement is unavailable; set [rubygems] install_hooks = \"report\""
            );
        }
        if self.homebrew.enabled {
            let brew = self.policy_for(Ecosystem::Homebrew);
            if brew.min_monthly_downloads != 0 {
                bail!(
                    "Homebrew monthly download evidence is unavailable; set [homebrew] min_monthly_downloads = 0"
                );
            }
            if brew.install_hooks == crate::inspection::HookPolicy::Deny {
                bail!(
                    "Homebrew install-hook enforcement is unavailable; set [homebrew] install_hooks = \"report\""
                );
            }
            for (value, official) in [
                (&self.homebrew.registry, "https://ghcr.io"),
                (&self.homebrew.api, "https://formulae.brew.sh/api"),
            ] {
                let u = url::Url::parse(value).context("invalid Homebrew upstream")?;
                let fixture = u
                    .host_str()
                    .is_some_and(|h| h == "127.0.0.1" || h == "[::1]")
                    && matches!(u.scheme(), "http" | "https");
                if value.trim_end_matches('/') != official && !fixture
                    || !u.username().is_empty()
                    || u.password().is_some()
                    || u.query().is_some()
                    || u.fragment().is_some()
                    || (fixture && !matches!(u.path(), "" | "/" | "/api"))
                {
                    bail!(
                        "Homebrew upstreams must be official HTTPS endpoints or explicit loopback fixtures"
                    );
                }
            }
            if self.homebrew.max_api_mb == 0
                || self.homebrew.max_api_mb > 128
                || self.homebrew.platforms.is_empty()
                || self.homebrew.platforms.len() > 8
                || self
                    .homebrew
                    .platforms
                    .iter()
                    .any(|p| !crate::registry::homebrew::platform(p))
                || self
                    .homebrew
                    .platforms
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    != self.homebrew.platforms.len()
            {
                bail!(
                    "Homebrew requires 1-8 distinct supported platform tags and max_api_mb within 1-128"
                );
            }
        }
        if self.apt.enabled {
            let policy = self.policy_for(Ecosystem::Apt);
            if policy.min_monthly_downloads != 0 {
                bail!(
                    "APT monthly download evidence is unavailable; set [apt] min_monthly_downloads = 0"
                );
            }
            if policy.install_hooks == crate::inspection::HookPolicy::Deny {
                bail!(
                    "APT install-hook enforcement is unavailable; set [apt] install_hooks = \"report\""
                );
            }
            if self.apt.max_index_mb == 0
                || self.apt.max_index_mb > 1024
                || self.apt.repos.is_empty()
                || self.apt.repos.len() > 32
            {
                bail!("APT requires 1-32 repositories and max_index_mb within 1-1024");
            }
            let mut names = std::collections::HashSet::new();
            for repo in &self.apt.repos {
                if policy.advisories != crate::policy::AdvisoryPolicy::Off {
                    let osv = repo.osv_ecosystem.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "APT advisory policy requires osv_ecosystem for each repository"
                        )
                    })?;
                    let valid = osv.strip_prefix("Debian:").is_some_and(|v| {
                        !v.is_empty() && v.len() <= 16 && v.bytes().all(|b| b.is_ascii_digit())
                    }) || osv.strip_prefix("Ubuntu:").is_some_and(|v| {
                        let v = v.strip_prefix("Pro:").unwrap_or(v);
                        let v = v.strip_suffix(":LTS").unwrap_or(v);
                        v.split_once('.').is_some_and(|(year, month)| {
                            year.len() == 2
                                && month.len() == 2
                                && year
                                    .bytes()
                                    .chain(month.bytes())
                                    .all(|b| b.is_ascii_digit())
                        })
                    });
                    if !valid {
                        bail!(
                            "APT osv_ecosystem must be an explicit Debian or Ubuntu release, e.g. Debian:12 or Ubuntu:24.04:LTS"
                        );
                    }
                }
                if !crate::registry::component(&repo.name) || !names.insert(&repo.name) {
                    bail!("APT repository names must be unique route-safe components");
                }
                let u = url::Url::parse(&repo.url).context("invalid APT upstream URL")?;
                if !(u.scheme() == "https" || self.upstream.allow_http && u.scheme() == "http")
                    || u.host_str()
                        .is_none_or(|h| !self.upstream.artifact_hosts.iter().any(|a| a == h))
                    || !u.username().is_empty()
                    || u.password().is_some()
                    || u.query().is_some()
                    || u.fragment().is_some()
                {
                    bail!(
                        "APT upstream must use an allowed artifact host and HTTP(S) scheme without credentials, query, or fragment"
                    );
                }
                for list in [&repo.suites, &repo.components, &repo.architectures] {
                    if list.is_empty()
                        || list.len() > 32
                        || list.iter().collect::<std::collections::HashSet<_>>().len() != list.len()
                        || list.iter().any(|v| !crate::registry::component(v))
                    {
                        bail!(
                            "APT suites, components, and architectures require distinct route-safe values"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
