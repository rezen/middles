pub mod apt;
pub mod composer;
pub mod homebrew;
pub mod npm;
pub(crate) mod oci;
pub mod pip;
pub mod rubygems;

use crate::error::{Error, Result};

/// Every supported ecosystem, so dispatch sites cannot silently miss one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pip,
    Composer,
    Rubygems,
    Homebrew,
    Apt,
}

impl Ecosystem {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "npm" => Ok(Self::Npm),
            "pip" => Ok(Self::Pip),
            "composer" => Ok(Self::Composer),
            "rubygems" => Ok(Self::Rubygems),
            "homebrew" => Ok(Self::Homebrew),
            "apt" => Ok(Self::Apt),
            _ => Err(Error::bad("unknown ecosystem")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pip => "pip",
            Self::Composer => "composer",
            Self::Rubygems => "rubygems",
            Self::Homebrew => "homebrew",
            Self::Apt => "apt",
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 214
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}
pub fn composer_name(value: &str) -> Result<()> {
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() == 2 && parts.iter().all(|p| component(p)) {
        Ok(())
    } else {
        Err(Error::bad("invalid Composer package name"))
    }
}
pub fn npm_name(value: &str) -> Result<()> {
    if let Some(scoped) = value.strip_prefix('@') {
        composer_name(scoped)
    } else if component(value) {
        Ok(())
    } else {
        Err(Error::bad("invalid npm package name"))
    }
}
