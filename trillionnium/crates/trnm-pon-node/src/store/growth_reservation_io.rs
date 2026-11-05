//! Descriptor-bound creation and bounded readback for the growth reservation owner.
//! No migration, chain selection, or cleanup authority is granted.
use crate::{ensure, Error, Result};
use rustix::fs::{mkdirat, open, openat, statat, AtFlags, FileType, Mode, OFlags};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub(super) const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const RESERVATION: &str = "growth-storage-reservation.bin";
const RECEIPT: &str = "growth-storage-reservation.json";

pub(super) struct Readback {
    pub bytes: Vec<u8>,
    pub reservation: Metadata,
    receipt: Metadata,
}

/// A local storage operation stays attached to these opened directories even if
/// their names are replaced. This is not a lease against another process with
/// the same UID, nor permission to remove any uncertain target on failure.
pub(super) struct Creation {
    target: PathBuf,
    parent: File,
    directory: File,
}

#[derive(Clone, Copy)]
enum CreationStage {
    ParentOpened,
    TargetCreated,
}

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

// Resolve every ancestor relative to an already opened directory. A single
// absolute open with O_NOFOLLOW would protect only the final path component.
pub(super) fn directory_components(path: &Path) -> Result<File> {
    ensure(path.is_absolute(), "GROWTH_STORAGE_TARGET")?;
    let mut directory = File::from(
        open("/", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|e| Error::from(format!("GROWTH_STORAGE_OPEN:{e}")))?,
    );
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                directory = File::from(
                    openat(&directory, name, DIRECTORY_FLAGS, Mode::empty())
                        .map_err(|e| Error::from(format!("GROWTH_STORAGE_OPEN:{e}")))?,
                );
            }
            _ => return Err("GROWTH_STORAGE_TARGET".into()),
        }
    }
    Ok(directory)
}

pub(super) fn check_named_parent(parent: &File, path: &Path) -> Result<()> {
    let named = directory_components(path)?;
    let final_named = fs::symlink_metadata(path)?;
    ensure(
        path.canonicalize()? == path
            && final_named.is_dir()
            && same_object(&parent.metadata()?, &named.metadata()?)
            && same_object(&named.metadata()?, &final_named),
        "GROWTH_STORAGE_TARGET_CHANGED",
    )
}

impl Creation {
    pub(super) fn create(target: &Path) -> Result<Self> {
        Self::create_with_progress(target, &mut |_| Ok(()))
    }

    // Private deterministic filesystem fault boundary; production supplies no
    // callback effects or caller-controlled execution hook.
    fn create_with_progress(
        target: &Path,
        progress: &mut impl FnMut(CreationStage) -> Result<()>,
    ) -> Result<Self> {
        ensure(
            target.is_absolute() && !target.exists(),
            "GROWTH_STORAGE_TARGET",
        )?;
        let parent_path = target.parent().ok_or("GROWTH_STORAGE_TARGET")?;
        let name = target.file_name().ok_or("GROWTH_STORAGE_TARGET")?;
        ensure(
            parent_path.canonicalize()? == parent_path,
            "GROWTH_STORAGE_TARGET",
        )?;
        let parent = directory_components(parent_path)?;
        check_named_parent(&parent, parent_path)?;
        let result: Result<File> = (|| {
            progress(CreationStage::ParentOpened)?;
            check_named_parent(&parent, parent_path)?;
            mkdirat(&parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                .map_err(|e| Error::from(format!("GROWTH_STORAGE_CREATE:{e}")))?;
            let named = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| Error::from(format!("GROWTH_STORAGE_OPEN:{e}")))?;
            ensure(
                FileType::from_raw_mode(named.st_mode) == FileType::Directory
                    && named.st_uid == rustix::process::geteuid().as_raw()
                    && matches!(named.st_mode & 0o7777, 0o700 | 0o2700),
                "GROWTH_STORAGE_TARGET",
            )?;
            progress(CreationStage::TargetCreated)?;
            let directory = File::from(
                openat(&parent, name, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|e| Error::from(format!("GROWTH_STORAGE_OPEN:{e}")))?,
            );
            let metadata = directory.metadata()?;
            ensure(
                metadata.is_dir()
                    && metadata.dev() == named.st_dev
                    && metadata.ino() == named.st_ino
                    && metadata.uid() == named.st_uid
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.permissions().mode() & 0o7777 == named.st_mode & 0o7777,
                "GROWTH_STORAGE_TARGET_CHANGED",
            )?;
            // fchmod acts only on the opened directory, never on a substituted
            // target pathname. The first observed entry is bound above; a same-
            // UID process replacing it before that observation is not excluded.
            // Inherited directory mode bits are cleared only after these checks.
            directory.set_permissions(fs::Permissions::from_mode(0o700))?;
            Ok(directory)
        })();
        if result.is_err() {
            let _ = parent.sync_all();
        }
        let created = Self {
            target: target.to_owned(),
            parent,
            directory: result?,
        };
        if let Err(error) = created.check_named_identity() {
            let _ = created.sync();
            return Err(error);
        }
        Ok(created)
    }

    fn check_named_identity(&self) -> Result<()> {
        let parent_path = self.target.parent().ok_or("GROWTH_STORAGE_TARGET")?;
        check_named_parent(&self.parent, parent_path)?;
        let named = directory_components(&self.target)?;
        let final_named = fs::symlink_metadata(&self.target)?;
        ensure(
            self.target.canonicalize()? == self.target
                && final_named.is_dir()
                && final_named.permissions().mode() & 0o7777 == 0o700
                && self.directory.metadata()?.permissions().mode() & 0o7777 == 0o700
                && final_named.uid() == rustix::process::geteuid().as_raw()
                && self.directory.metadata()?.uid() == rustix::process::geteuid().as_raw()
                && same_object(&self.directory.metadata()?, &named.metadata()?)
                && same_object(&named.metadata()?, &final_named),
            "GROWTH_STORAGE_TARGET_CHANGED",
        )
    }

    fn create_file(&self, name: &str) -> Result<File> {
        let file = File::from(
            openat(
                &self.directory,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|e| Error::from(format!("GROWTH_STORAGE_CREATE:{e}")))?,
        );
        let metadata = file.metadata()?;
        ensure(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode() & 0o7777 == 0o600,
            "GROWTH_STORAGE_TARGET",
        )?;
        Ok(file)
    }

    pub(super) fn create_reservation(&self) -> Result<File> {
        self.create_file(RESERVATION)
    }

    pub(super) fn create_receipt(&self) -> Result<File> {
        self.create_file(RECEIPT)
    }

    pub(super) fn sync(&self) -> Result<()> {
        self.directory.sync_all()?;
        self.parent.sync_all()?;
        Ok(())
    }

    pub(super) fn readback(&self, reservation: &File, receipt: &File) -> Result<Readback> {
        self.check_named_identity()?;
        let reservation_meta = reservation.metadata()?;
        let receipt_meta = receipt.metadata()?;
        ensure(
            reservation_meta.uid() == rustix::process::geteuid().as_raw()
                && receipt_meta.uid() == rustix::process::geteuid().as_raw(),
            "GROWTH_STORAGE_TARGET_CHANGED",
        )?;
        let readback = read_directory_with_path_readback(&self.target, &self.directory, || {
            self.check_named_identity()
        })?;
        ensure(
            same_checked_file(&reservation_meta, &readback.reservation)
                && same_checked_file(&receipt_meta, &readback.receipt),
            "GROWTH_STORAGE_TARGET_CHANGED",
        )?;
        self.check_named_identity()?;
        Ok(readback)
    }
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
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.permissions().mode() & 0o7777 == 0o600
        && right.permissions().mode() & 0o7777 == 0o600
        && left.len() == right.len()
        && left.blocks() == right.blocks()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn checked_directory(target: &Path) -> Result<File> {
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
    let metadata = directory.metadata()?;
    ensure(
        metadata.is_dir() && metadata.permissions().mode() & 0o7777 == 0o700,
        "GROWTH_STORAGE_TARGET",
    )?;
    Ok(directory)
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
            && metadata.permissions().mode() & 0o7777 == 0o600,
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
    let directory = checked_directory(target)?;
    read_directory_with_path_readback(target, &directory, before_path_readback)
}

fn read_directory_with_path_readback(
    target: &Path,
    directory: &File,
    before_path_readback: impl FnOnce() -> Result<()>,
) -> Result<Readback> {
    let directory_meta = directory.metadata()?;
    let reservation = checked_file(directory, RESERVATION)?;
    let receipt = checked_file(directory, RECEIPT)?;
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
    // Reopen one checked directory and resolve both final files relative to it.
    // Equal leaf inodes do not excuse a replaced ancestor symlink or special
    // permission bits. This is an observation fence, not a future pathname lease.
    let named_directory = checked_directory(target)?;
    let named_directory_meta = named_directory.metadata()?;
    let named_reservation = checked_file(&named_directory, RESERVATION)?.metadata()?;
    let named_receipt = checked_file(&named_directory, RECEIPT)?.metadata()?;
    let final_directory = fs::symlink_metadata(target)?;
    ensure(
        same_object(&directory_meta, &named_directory_meta)
            && same_object(&named_directory_meta, &final_directory)
            && final_directory.is_dir()
            && final_directory.permissions().mode() & 0o7777 == 0o700
            && target.canonicalize()? == target
            && same_checked_file(&reservation_meta, &named_reservation)
            && same_checked_file(&after, &named_receipt),
        "GROWTH_STORAGE_TARGET_CHANGED",
    )?;
    Ok(Readback {
        bytes,
        reservation: reservation_meta,
        receipt: after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    fn write_created_files(creation: &Creation) -> (File, File) {
        let mut reservation = creation.create_reservation().unwrap();
        // These bytes exercise the destination identity, not capacity evidence.
        reservation.write_all(b"retained reservation").unwrap();
        reservation.sync_all().unwrap();
        let mut receipt = creation.create_receipt().unwrap();
        receipt.write_all(b"{}").unwrap();
        receipt.sync_all().unwrap();
        creation.sync().unwrap();
        (reservation, receipt)
    }

    fn decoy_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o751)).unwrap();
        fs::write(path.join("sentinel"), b"must remain unchanged").unwrap();
    }

    fn assert_decoy_untouched(path: &Path) {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o751
        );
        assert_eq!(
            fs::read(path.join("sentinel")).unwrap(),
            b"must remain unchanged"
        );
        assert!(!path.join(RESERVATION).exists());
        assert!(!path.join(RECEIPT).exists());
    }

    #[test]
    fn creation_refuses_ancestor_symlink_before_any_target_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let decoy = root.join("decoy");
        decoy_directory(&decoy);
        symlink(&decoy, root.join("parent")).unwrap();
        assert!(Creation::create(&root.join("parent/target")).is_err());
        assert!(!decoy.join("target").exists());
        assert_decoy_untouched(&decoy);
    }

    #[test]
    fn creation_refuses_parent_substitution_after_open_without_writing_decoy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let parent = root.join("parent");
        fs::create_dir(&parent).unwrap();
        let decoy = root.join("decoy");
        decoy_directory(&decoy);
        let retained = root.join("retained-parent");
        let result = Creation::create_with_progress(&parent.join("target"), &mut |stage| {
            if matches!(stage, CreationStage::ParentOpened) {
                fs::rename(&parent, &retained)?;
                symlink(&decoy, &parent)?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!retained.join("target").exists());
        assert!(!decoy.join("target").exists());
        assert_decoy_untouched(&decoy);
    }

    #[test]
    fn creation_refuses_target_symlink_before_chmod_or_file_creation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let target = root.join("target");
        let retained = root.join("retained-target");
        let decoy = root.join("decoy");
        decoy_directory(&decoy);
        let result = Creation::create_with_progress(&target, &mut |stage| {
            if matches!(stage, CreationStage::TargetCreated) {
                fs::rename(&target, &retained)?;
                symlink(&decoy, &target)?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(retained.is_dir());
        assert!(!retained.join(RESERVATION).exists());
        assert!(!retained.join(RECEIPT).exists());
        assert_decoy_untouched(&decoy);
    }

    #[test]
    fn creation_refuses_real_directory_substitution_before_chmod_or_file_creation() {
        for mode in [0o700, 0o751] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let target = root.join("target");
            let retained = root.join("retained-target");
            let decoy = root.join("decoy");
            decoy_directory(&decoy);
            fs::set_permissions(&decoy, fs::Permissions::from_mode(mode)).unwrap();
            let result = Creation::create_with_progress(&target, &mut |stage| {
                if matches!(stage, CreationStage::TargetCreated) {
                    fs::rename(&target, &retained)?;
                    fs::rename(&decoy, &target)?;
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(retained.is_dir());
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
                mode
            );
            assert_eq!(
                fs::read(target.join("sentinel")).unwrap(),
                b"must remain unchanged"
            );
            for path in [&target, &retained] {
                assert!(!path.join(RESERVATION).exists());
                assert!(!path.join(RECEIPT).exists());
            }
        }
    }

    #[test]
    fn creation_writes_only_held_target_after_target_or_ancestor_replacement() {
        for ancestor in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let parent = root.join("parent");
            fs::create_dir(&parent).unwrap();
            let target = parent.join("target");
            let creation = Creation::create(&target).unwrap();
            let replacement = root.join("replacement");
            let (retained, decoy) = if ancestor {
                fs::create_dir(&replacement).unwrap();
                let decoy = replacement.join("target");
                decoy_directory(&decoy);
                let retained_parent = root.join("retained-parent");
                fs::rename(&parent, &retained_parent).unwrap();
                symlink(&replacement, &parent).unwrap();
                (retained_parent.join("target"), decoy)
            } else {
                decoy_directory(&replacement);
                let retained = root.join("retained-target");
                fs::rename(&target, &retained).unwrap();
                symlink(&replacement, &target).unwrap();
                (retained, replacement)
            };
            let (reservation, receipt) = write_created_files(&creation);
            assert!(creation.readback(&reservation, &receipt).is_err());
            assert_eq!(
                fs::read(retained.join(RESERVATION)).unwrap(),
                b"retained reservation"
            );
            assert_eq!(fs::read(retained.join(RECEIPT)).unwrap(), b"{}");
            assert_decoy_untouched(&decoy);
        }
    }

    #[test]
    fn creation_readback_binds_original_files_even_when_replacements_have_equal_bytes() {
        for name in [RESERVATION, RECEIPT] {
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().canonicalize().unwrap().join("target");
            let creation = Creation::create(&target).unwrap();
            let (reservation, receipt) = write_created_files(&creation);
            assert_eq!(
                creation.readback(&reservation, &receipt).unwrap().bytes,
                b"{}"
            );
            assert!(creation.create_reservation().is_err());
            assert!(creation.create_receipt().is_err());
            let original = target.join("retained-original");
            fs::rename(target.join(name), &original).unwrap();
            fs::write(target.join(name), fs::read(&original).unwrap()).unwrap();
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            // A cold path read can describe these new files. The live creation
            // owner must additionally bind the exact files it allocated/wrote.
            assert_eq!(read(&target).unwrap().bytes, b"{}");
            assert!(creation.readback(&reservation, &receipt).is_err());
            assert!(original.is_file());
        }
    }

    #[test]
    fn creation_readback_rejects_equal_byte_directory_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let target = root.join("target");
        let creation = Creation::create(&target).unwrap();
        let (reservation, receipt) = write_created_files(&creation);
        let retained = root.join("retained-target");
        fs::rename(&target, &retained).unwrap();
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [RESERVATION, RECEIPT] {
            fs::write(target.join(name), fs::read(retained.join(name)).unwrap()).unwrap();
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read(&target).unwrap().bytes, b"{}");
        assert!(creation.readback(&reservation, &receipt).is_err());
        assert_eq!(read(&retained).unwrap().bytes, b"{}");
    }

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
            File::open(&target).unwrap(),
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
            assert!(
                result.is_err(),
                "late substitution case {case} was accepted"
            );
        }
    }

    #[test]
    fn late_ancestor_symlink_cannot_preserve_path_acceptance() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let parent = root.join("parent");
        fs::create_dir(&parent).unwrap();
        let target = parent.join("target");
        fresh_target(&target);
        assert!(read(&target).is_ok());
        let result = read_with_path_readback(&target, || {
            let moved = root.join("moved");
            fs::rename(&parent, &moved)?;
            symlink(&moved, &parent)?;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(read(&root.join("moved/target")).unwrap().bytes, b"{}");
    }

    #[test]
    fn special_permission_bits_refuse_at_open_and_final_readback() {
        for name in [None, Some(RESERVATION), Some(RECEIPT)] {
            for special in [0o1000, 0o2000, 0o4000] {
                let temp = tempfile::tempdir().unwrap();
                let target = temp.path().canonicalize().unwrap().join("target");
                fresh_target(&target);
                let path = name.map_or_else(|| target.clone(), |name| target.join(name));
                let allowed = if name.is_some() { 0o600 } else { 0o700 };
                assert!(read(&target).is_ok());
                let result = read_with_path_readback(&target, || {
                    fs::set_permissions(&path, fs::Permissions::from_mode(allowed | special))?;
                    Ok(())
                });
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                    allowed | special
                );
                assert!(result.is_err());
                assert!(read(&target).is_err());
                fs::set_permissions(&path, fs::Permissions::from_mode(allowed)).unwrap();
                assert_eq!(read(&target).unwrap().bytes, b"{}");
            }
        }
    }
}
