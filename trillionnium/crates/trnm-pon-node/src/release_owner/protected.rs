//! Protected configuration input, separate from candidate release material.
use super::frontier::{invalid, Digest32, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

fn identity(value: &Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        value.dev(),
        value.ino(),
        value.len(),
        value.mode(),
        value.uid(),
        value.nlink(),
        value.mtime(),
        value.mtime_nsec(),
        value.ctime(),
        value.ctime_nsec(),
    )
}

/// Even error paths zeroize the input allocation; callers never log key bytes.
pub(super) fn read_private(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err(invalid(
            "M15 protected input is not an absolute canonical path",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(invalid("M15 protected input ownership, mode, or size"));
    }
    let mut raw = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() != before.len() as usize
        || raw.len() > maximum
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&fs::symlink_metadata(path)?)
    {
        return Err(invalid("M15 protected input changed while read"));
    }
    Ok(raw)
}

pub(super) fn read_pinned(
    path: &Path,
    maximum: usize,
    expected: Digest32,
) -> Result<Zeroizing<Vec<u8>>> {
    let raw = read_private(path, maximum)?;
    let actual: Digest32 = Sha256::digest(raw.as_slice()).into();
    if expected == [0; 32] || actual != expected {
        return Err(invalid("M15 protected input pin mismatch"));
    }
    Ok(raw)
}

pub(super) fn read_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let raw = read_private(path, 32)?;
    let mut seed = Zeroizing::new([0; 32]);
    if raw.len() != seed.len() {
        return Err(invalid("M15 seed must contain exactly 32 bytes"));
    }
    seed.copy_from_slice(raw.as_slice());
    Ok(seed)
}
