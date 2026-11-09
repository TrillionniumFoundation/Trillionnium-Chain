//! Fixed V2 process inputs before any M15 authority/provider operation.
//!
//! An absent OPENSSL_CONF selects the installed default configuration; it does
//! not disable configuration. The optional OpenSSL build must not discover a
//! provider or engine outside the signed static image through that default.
use super::frontier::{invalid, Result};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;

const LIBRARY_ENVIRONMENT: [(&str, &str); 3] = [
    ("OPENSSL_CONF", ""),
    // A regular file cannot be a provider/engine search directory. This proc
    // object is the current executable, not a writable directory or cwd.
    ("OPENSSL_ENGINES", "/proc/self/exe"),
    ("OPENSSL_MODULES", "/proc/self/exe"),
];

pub(super) fn legacy_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("LANG".into(), "C".into()),
        ("LC_ALL".into(), "C".into()),
        ("TZ".into(), "UTC".into()),
    ])
}

pub(super) fn restricted_environment() -> BTreeMap<String, String> {
    let mut value = legacy_environment();
    value.extend(LIBRARY_ENVIRONMENT.map(|(key, value)| (key.into(), value.into())));
    value
}

fn provider_values(values: [Option<OsString>; 3]) -> Result<()> {
    if values
        .iter()
        .zip(LIBRARY_ENVIRONMENT)
        .any(|(actual, (_, expected))| actual.as_deref() != Some(OsStr::new(expected)))
    {
        return Err(invalid(
            "M15 explicit no-external-provider environment required",
        ));
    }
    Ok(())
}

fn secure_auxiliary_vector(raw: &[u8]) -> Result<bool> {
    const WORD: usize = std::mem::size_of::<usize>();
    if raw.is_empty() || raw.len() > 4096 || !raw.len().is_multiple_of(2 * WORD) {
        return Err(invalid("M15 auxiliary-vector bound/encoding"));
    }
    let mut secure = None;
    let mut ended = false;
    for row in raw.chunks_exact(2 * WORD) {
        let tag = usize::from_ne_bytes(row[..WORD].try_into().expect("native auxv word"));
        let value = usize::from_ne_bytes(row[WORD..].try_into().expect("native auxv word"));
        if ended || (tag == libc::AT_NULL as usize && value != 0) {
            return Err(invalid("M15 auxiliary-vector terminator"));
        }
        if tag == libc::AT_NULL as usize {
            ended = true;
        } else if tag == libc::AT_SECURE as usize {
            if secure.is_some() || value > 1 {
                return Err(invalid("M15 auxiliary-vector secure mode"));
            }
            secure = Some(value == 1);
        }
    }
    if !ended {
        return Err(invalid("M15 auxiliary-vector lacks terminator"));
    }
    secure.ok_or_else(|| invalid("M15 auxiliary-vector secure mode missing"))
}

fn require_unprivileged_environment() -> Result<()> {
    let mut raw = Vec::new();
    File::open("/proc/self/auxv")?
        .take(4097)
        .read_to_end(&mut raw)?;
    if secure_auxiliary_vector(&raw)?
        || rustix::process::getuid() != rustix::process::geteuid()
        || rustix::process::getgid() != rustix::process::getegid()
    {
        // OpenSSL intentionally ignores its environment controls in secure
        // execution. This profile never treats ignored settings as enforced.
        return Err(invalid("M15 secure-execution environment is unsupported"));
    }
    Ok(())
}

/// The administrator remains an outside actor, but no M15 command may consult
/// its native providers before these explicit library settings are checked.
pub(super) fn require_provider_environment() -> Result<()> {
    provider_values(LIBRARY_ENVIRONMENT.map(|(key, _)| std::env::var_os(key)))?;
    require_unprivileged_environment()
}

fn exact_values(values: impl IntoIterator<Item = (OsString, OsString)>) -> Result<()> {
    let expected = restricted_environment();
    let mut actual = BTreeMap::new();
    for (key, value) in values {
        // Retain only the six fixed entries in the validation map. Refuse an
        // unknown value before copying caller-supplied text into that map.
        if actual.len() >= expected.len() {
            return Err(invalid("M15 exact restricted environment required"));
        }
        let (Some(key), Some(value)) = (key.to_str(), value.to_str()) else {
            return Err(invalid("M15 environment encoding"));
        };
        if expected.get(key).map(String::as_str) != Some(value)
            || actual.insert(key.to_string(), value.to_string()).is_some()
        {
            return Err(invalid("M15 exact restricted environment required"));
        }
    }
    if actual != expected {
        return Err(invalid("M15 exact restricted environment required"));
    }
    Ok(())
}

/// Run before opening the release owner, and again at actual use. No helper
/// mutates this process environment after threads have started.
pub(super) fn require_exact_environment() -> Result<()> {
    exact_values(std::env::vars_os())?;
    require_unprivileged_environment()
}

#[cfg(test)]
#[path = "execution_environment_tests.rs"]
mod tests;
