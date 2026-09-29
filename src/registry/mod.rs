pub mod composer;
pub mod npm;
pub mod pip;
pub mod rubygems;

use crate::error::{Error, Result};

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
