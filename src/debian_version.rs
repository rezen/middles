//! Debian/Ubuntu package version ordering per Debian Policy §5.6.12.
use std::cmp::Ordering;

pub(crate) fn compare(left: &str, right: &str) -> Option<Ordering> {
    let (a_epoch, a_upstream, a_revision) = split(left)?;
    let (b_epoch, b_upstream, b_revision) = split(right)?;
    Some(
        a_epoch
            .cmp(&b_epoch)
            .then_with(|| compare_part(a_upstream.as_bytes(), b_upstream.as_bytes()))
            .then_with(|| compare_part(a_revision.as_bytes(), b_revision.as_bytes())),
    )
}

fn split(version: &str) -> Option<(u64, &str, &str)> {
    let (epoch, rest) = match version.split_once(':') {
        Some((epoch, rest)) => (epoch.parse::<u64>().ok()?, rest),
        None => (0, version),
    };
    let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, "0"));
    if !upstream.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || !upstream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+~-".contains(&b))
        || !revision
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+~".contains(&b))
        || revision.is_empty()
    {
        return None;
    }
    Some((epoch, upstream, revision))
}

fn order(byte: Option<u8>) -> i32 {
    match byte {
        Some(b'~') => -1,
        None | Some(b'0'..=b'9') => 0,
        Some(b) if b.is_ascii_alphabetic() => b as i32,
        Some(b) => b as i32 + 256,
    }
}

fn compare_part(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while a.get(i).is_some_and(|c| !c.is_ascii_digit())
            || b.get(j).is_some_and(|c| !c.is_ascii_digit())
        {
            let a_byte = a.get(i).copied().filter(|c| !c.is_ascii_digit());
            let b_byte = b.get(j).copied().filter(|c| !c.is_ascii_digit());
            let cmp = order(a_byte).cmp(&order(b_byte));
            if cmp != Ordering::Equal {
                return cmp;
            }
            if a_byte.is_some() {
                i += 1;
            }
            if b_byte.is_some() {
                j += 1;
            }
        }
        let a_start = i;
        let b_start = j;
        while a.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        while b.get(j).is_some_and(u8::is_ascii_digit) {
            j += 1;
        }
        let a_digits = &a[a_start..i];
        let b_digits = &b[b_start..j];
        let a_digits = a_digits
            .iter()
            .position(|b| *b != b'0')
            .map_or(&[][..], |k| &a_digits[k..]);
        let b_digits = b_digits
            .iter()
            .position(|b| *b != b'0')
            .map_or(&[][..], |k| &b_digits[k..]);
        let cmp = a_digits
            .len()
            .cmp(&b_digits.len())
            .then_with(|| a_digits.cmp(b_digits));
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn debian_policy_ordering() {
        for (older, newer) in [
            ("1.0~~", "1.0~"),
            ("1.0~", "1.0"),
            ("1.0", "1.0+a"),
            ("1.0-1", "1.0-2"),
            ("1.0-2", "1:1.0-1"),
            ("2.5.0-1", "2.5.0-1+deb12u1"),
            ("1.0-9", "1.0-10"),
        ] {
            assert_eq!(
                compare(older, newer),
                Some(Ordering::Less),
                "{older} vs {newer}"
            );
        }
        assert_eq!(compare("1.0", "1.0-0"), Some(Ordering::Equal));
        assert_eq!(compare("1.0-01", "1.0-1"), Some(Ordering::Equal));
        assert_eq!(compare("x", "1.0"), None);
    }
}
