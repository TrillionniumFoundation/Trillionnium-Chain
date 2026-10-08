//! Bounded descriptor-relative readback for the existing growth reservation owner.
//! No allocation, migration, chain selection, or cleanup authority is granted.
use crate::{ensure, Error, Result};
use rustix::fs::{open, openat, Mode, OFlags};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub(super) const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const RESERVATION: &str = "growth-storage-reservation.bin";
const RECEIPT: &str = "growth-storage-reservation.json";

pub(super) struct Readback {
    pub bytes: Vec<u8>,
    pub reservation: Metadata,
}

fn same_object(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn same_checked_file(left: &Metadata, right: &Metadata) -> bool {
    same_object(left, right)
        && left.is_file()
        && right.is_file()
        && left.nlink() == 1
        && right.nlink() == 1
        && left.permissions().mode() & 0o777 == 0o600
        && right.permissions().mode() & 0o777 == 0o600
        && left.len() == right.len()
        && left.blocks() == right.blocks()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn checked_file(directory: &File, name: &str) -> Result<File> {
    let file = File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::from(format!("GROWTH_STORAGE_OPEN:{e}")))?,
    );
    let metadata = file.metadata()?;
    ensure(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o777 == 0o600,
        "GROWTH_STORAGE_TARGET",
    )?;
    Ok(file)
}

pub(super) fn read(target: &Path) -> Result<Readback> {
    read_with_path_readback(target, || Ok(()))
}

// Private operation boundary for deterministic fault schedules. The production
// entry supplies no effect, authority or caller-controlled hook.
fn read_with_path_readback(
    target: &Path,
    before_path_readback: impl FnOnce() -> Result<()>,
) -> Result<Readback> {
    ensure(
        target.is_absolute() && target.canonicalize()? == target,
        "GROWTH_STORAGE_TARGET",
    )?;
    let directory = File::from(
        open(
            target,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::from(format!("GROWTH_STORAGE_OPEN:{e}")))?,
    );
    let directory_meta = directory.metadata()?;
    ensure(
        directory_meta.is_dir() && directory_meta.permissions().mode() & 0o777 == 0o700,
        "GROWTH_STORAGE_TARGET",
    )?;
    let reservation = checked_file(&directory, RESERVATION)?;
    let receipt = checked_file(&directory, RECEIPT)?;
    let before = receipt.metadata()?;
    ensure(
        (1..=MAX_RECEIPT_BYTES).contains(&before.len()),
        "GROWTH_STORAGE_RECEIPT_LIMIT",
    )?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&receipt)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = receipt.metadata()?;
    ensure(
        bytes.len() as u64 == before.len()
            && bytes.len() as u64 <= MAX_RECEIPT_BYTES
            && same_checked_file(&before, &after),
        "GROWTH_STORAGE_RECEIPT_CHANGED",
    )?;
    let reservation_meta = reservation.metadata()?;
    before_path_readback()?;
    // Both payloads came from the same held directory. Path substitution cannot
    // turn those observations into a receipt for a different currently named target.
    // Recheck policy as well as inode: a late chmod/hardlink must not retain credit.
    let named_directory = fs::symlink_metadata(target)?;
    let named_reservation = fs::symlink_metadata(target.join(RESERVATION))?;
    let named_receipt = fs::symlink_metadata(target.join(RECEIPT))?;
    ensure(
        same_object(&directory_meta, &named_directory)
            && named_directory.is_dir()
            && named_directory.permissions().mode() & 0o777 == 0o700
            && same_checked_file(&reservation_meta, &named_reservation)
            && same_checked_file(&after, &named_receipt),
        "GROWTH_STORAGE_TARGET_CHANGED",
    )?;
    Ok(Readback {
        bytes,
        reservation: reservation_meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn readback_is_bounded_and_rejects_symlink_fifo_alias_and_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().canonicalize().unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let data = target.join(RESERVATION);
        let receipt = target.join(RECEIPT);
        fs::write(&data, b"allocated-fixture-not-capacity-evidence").unwrap();
        fs::write(&receipt, b"{}").unwrap();
        for path in [&data, &receipt] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read(&target).unwrap().bytes, b"{}");
        File::options()
            .write(true)
            .open(&receipt)
            .unwrap()
            .set_len(MAX_RECEIPT_BYTES + 1)
            .unwrap();
        assert!(read(&target).is_err());
        fs::remove_file(&receipt).unwrap();
        symlink(&data, &receipt).unwrap();
        assert!(read(&target).is_err());
        fs::remove_file(&receipt).unwrap();
        rustix::fs::mknodat(
            &File::open(&target).unwrap(),
            RECEIPT,
            rustix::fs::FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(read(&target).is_err());
        fs::remove_file(&receipt).unwrap();
        fs::hard_link(&data, &receipt).unwrap();
        assert!(read(&target).is_err());
        fs::remove_file(&receipt).unwrap();
        fs::write(&receipt, b"{}").unwrap();
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&target).is_err());
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(&target).unwrap().bytes, b"{}");
    }

    fn fresh_target(target: &Path) {
        fs::create_dir(target).unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [RESERVATION, RECEIPT] {
            let path = target.join(name);
            fs::write(&path, b"{}").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn late_path_policy_and_object_changes_cannot_pass_readback() {
        for case in 0..6 {
            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().canonicalize().unwrap();
            let target = parent.join("target");
            fresh_target(&target);
            assert!(read(&target).is_ok());
            let result = read_with_path_readback(&target, || {
                match case {
                    0 => fs::set_permissions(
                        target.join(RECEIPT),
                        fs::Permissions::from_mode(0o644),
                    )?,
                    1 => fs::set_permissions(
                        target.join(RESERVATION),
                        fs::Permissions::from_mode(0o644),
                    )?,
                    2 => fs::hard_link(target.join(RESERVATION), target.join("alias"))?,
                    3 => {
                        fs::rename(target.join(RECEIPT), target.join("original"))?;
                        fs::write(target.join(RECEIPT), b"{}")?;
                        fs::set_permissions(
                            target.join(RECEIPT),
                            fs::Permissions::from_mode(0o600),
                        )?;
                    }
                    4 => {
                        fs::rename(&target, parent.join("original"))?;
                        fresh_target(&target);
                    }
                    5 => fs::hard_link(target.join(RECEIPT), target.join("alias"))?,
                    _ => unreachable!(),
                }
                Ok(())
            });
            assert!(result.is_err(), "late substitution case {case} was accepted");
        }
    }
}
