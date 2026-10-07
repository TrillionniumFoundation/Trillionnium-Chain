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
            && after.len() == before.len()
            && after.mtime() == before.mtime()
            && after.mtime_nsec() == before.mtime_nsec()
            && after.ctime() == before.ctime()
            && after.ctime_nsec() == before.ctime_nsec(),
        "GROWTH_STORAGE_RECEIPT_CHANGED",
    )?;
    let reservation_meta = reservation.metadata()?;
    // Both payloads came from the same held directory. Path substitution cannot
    // turn those observations into a receipt for a different currently named target.
    let named_directory = fs::symlink_metadata(target)?;
    let named_reservation = fs::symlink_metadata(target.join(RESERVATION))?;
    let named_receipt = fs::symlink_metadata(target.join(RECEIPT))?;
    ensure(
        same_object(&directory_meta, &named_directory)
            && named_directory.is_dir()
            && named_directory.permissions().mode() & 0o777 == 0o700
            && same_object(&reservation_meta, &named_reservation)
            && named_reservation.is_file()
            && same_object(&after, &named_receipt)
            && named_receipt.is_file(),
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
}
