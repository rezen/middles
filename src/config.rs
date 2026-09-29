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
    pub npm: Override,
    pub pip: Override,
    pub composer: Override,
    pub rubygems: Override,
    pub upstream: Upstream,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Override {
    pub min_age_days: Option<u32>,
    pub min_monthly_downloads: Option<u64>,
    pub install_hooks: Option<crate::inspection::HookPolicy>,
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
    pub artifact_hosts: Vec<String>,
    pub allow_http: bool,
    pub timeout_secs: u64,
    pub max_metadata_mb: usize,
    pub concurrency: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().unwrap(),
            public_url: "http://127.0.0.1:8080".into(),
            cache: CacheConfig::default(),
            policy: Policy::default(),
            npm: Override::default(),
            pip: Override::default(),
            composer: Override::default(),
            rubygems: Override::default(),
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
        };
        Policy {
            install_hooks: o.install_hooks.unwrap_or(self.policy.install_hooks),
            min_age_days: o.min_age_days.unwrap_or(self.policy.min_age_days),
            min_monthly_downloads: o
                .min_monthly_downloads
                .unwrap_or(self.policy.min_monthly_downloads),
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
        Ok(())
    }
}
