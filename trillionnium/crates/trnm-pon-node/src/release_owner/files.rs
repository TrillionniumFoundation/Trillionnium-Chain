//! Single-owner files. All child I/O is relative to the held directory.
use super::frontier::{invalid, Result};
use fs2::FileExt;
use rustix::fs::{mkdirat, openat, renameat, renameat_with, Mode, OFlags, RenameFlags};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct Files {
    root: PathBuf,
    directory: File,
    lock: File,
}

fn private_regular(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(invalid(
            "M15 owner requires a private single-link regular file",
        ));
    }
    Ok(())
}

fn child_name(name: &str) -> Result<()> {
    let mut parts = Path::new(name).components();
    if name.is_empty()
        || name.as_bytes().contains(&0)
        || !matches!(parts.next(), Some(Component::Normal(value)) if value == std::ffi::OsStr::new(name))
        || parts.next().is_some()
    {
        return Err(invalid("M15 child name must be one exact normal component"));
    }
    Ok(())
}

fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.uid(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

impl Files {
    pub fn create(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return Err(invalid("M15 owner path must be absolute"));
        }
        let parent = root
            .parent()
            .ok_or_else(|| invalid("missing M15 owner parent"))?;
        if parent.canonicalize()? != parent {
            return Err(invalid("M15 owner parent is not canonical"));
        }
        let parent_fd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(parent)?;
        let name = root
            .file_name()
            .ok_or_else(|| invalid("missing M15 directory name"))?;
        mkdirat(&parent_fd, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
        let directory = File::from(openat(
            &parent_fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        directory.sync_all()?;
        parent_fd.sync_all()?;
        Self::bind(root, directory)
    }

    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() || root.canonicalize()? != root {
            return Err(invalid("M15 owner path is not canonical"));
        }
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(root)?;
        Self::bind(root, directory)
    }

    fn bind(root: &Path, directory: File) -> Result<Self> {
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(invalid("M15 owner directory must be private"));
        }
        let lock = File::from(openat(
            &directory,
            "owner.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        private_regular(&lock)?;
        lock.try_lock_exclusive()?;
        let files = Self {
            root: root.to_path_buf(),
            directory,
            lock,
        };
        files.revalidate()?;
        Ok(files)
    }

    pub fn revalidate(&self) -> Result<()> {
        let actual = fs::symlink_metadata(&self.root)?;
        let held = self.directory.metadata()?;
        if !actual.is_dir()
            || actual.dev() != held.dev()
            || actual.ino() != held.ino()
            || actual.uid() != rustix::process::geteuid().as_raw()
            || actual.mode() & 0o7777 != 0o700
        {
            return Err(invalid("M15 owner directory identity changed"));
        }
        let current = File::from(openat(
            &self.directory,
            "owner.lock",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        private_regular(&current)?;
        let a = self.lock.metadata()?;
        let b = current.metadata()?;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return Err(invalid("M15 owner lock identity changed"));
        }
        Ok(())
    }

    pub fn read(&self, name: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
        child_name(name)?;
        self.revalidate()?;
        let fd = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut file = File::from(fd);
        private_regular(&file)?;
        let before = file.metadata()?;
        if before.len() > maximum as u64 {
            return Err(invalid("M15 owner file exceeds bound"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        #[cfg(test)]
        super::files_faults::after_read(name);
        let after = file.metadata()?;
        if bytes.len() > maximum
            || before.len() != bytes.len() as u64
            || before.len() != after.len()
            || (
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            )
        {
            return Err(invalid("M15 owner file changed while read"));
        }
        private_regular(&file)?;
        let named = File::from(openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        private_regular(&named)?;
        if identity(&after) != identity(&named.metadata()?) {
            return Err(invalid("M15 named file identity changed while read"));
        }
        self.revalidate()?;
        Ok(Some(bytes))
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        child_name(name)?;
        self.revalidate()?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{name}.{}.{sequence}.tmp", std::process::id());
        let mut file = File::from(openat(
            &self.directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        private_regular(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        private_regular(&file)?;
        renameat(&self.directory, temporary.as_str(), &self.directory, name)?;
        self.directory.sync_all()?;
        self.revalidate()?;
        if self.read(name, bytes.len())?.as_deref() != Some(bytes) {
            return Err(invalid("M15 atomic publication readback differs"));
        }
        #[cfg(test)]
        super::transaction_faults::after_synced_write(name, bytes)?;
        Ok(())
    }
    /// Content-addressed evidence is create-only. A collision never replaces
    /// an existing inode, including an invalid or partially retained object.
    pub fn put_immutable(&self, name: &str, bytes: &[u8]) -> Result<()> {
        child_name(name)?;
        if let Some(current) = self.read(name, bytes.len())? {
            if current == bytes {
                return Ok(());
            }
            return Err(invalid("M15 immutable object collision"));
        }
        self.revalidate()?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{name}.{}.immutable-{sequence}.tmp", std::process::id());
        let mut file = File::from(openat(
            &self.directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        private_regular(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        private_regular(&file)?;
        self.revalidate()?;
        renameat_with(
            &self.directory,
            temporary.as_str(),
            &self.directory,
            name,
            RenameFlags::NOREPLACE,
        )?;
        self.directory.sync_all()?;
        if self.read(name, bytes.len())?.as_deref() != Some(bytes) {
            return Err(invalid("M15 immutable object readback mismatch"));
        }
        Ok(())
    }

    pub fn open_object(&self, name: &str, size: u64) -> Result<File> {
        child_name(name)?;
        self.revalidate()?;
        let file = File::from(openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        private_regular(&file)?;
        if file.metadata()?.len() != size {
            return Err(invalid("M15 catalog exact size"));
        }
        self.revalidate()?;
        Ok(file)
    }

    pub fn recheck_object(&self, name: &str, held: &File) -> Result<()> {
        let actual = self.open_object(name, held.metadata()?.len())?;
        if identity(&held.metadata()?) != identity(&actual.metadata()?) {
            return Err(invalid("M15 catalog named object changed"));
        }
        Ok(())
    }

    pub fn put_sealed(&self, name: &str, sealed: &super::sealed::Sealed) -> Result<()> {
        child_name(name)?;
        self.revalidate()?;
        match self.open_object(name, sealed.size()) {
            Ok(file) => {
                let before = identity(&file.metadata()?);
                if super::sealed::digest(&file, sealed.size())? != sealed.digest
                    || before != identity(&file.metadata()?)
                {
                    return Err(invalid("M15 existing catalog digest differs"));
                }
                return self.recheck_object(name, &file);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{name}.{}.catalog-{sequence}.tmp", std::process::id());
        let mut file = File::from(openat(
            &self.directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        private_regular(&file)?;
        sealed.copy_to(&mut file)?;
        file.sync_all()?;
        self.revalidate()?;
        sealed.recheck()?;
        renameat_with(
            &self.directory,
            temporary.as_str(),
            &self.directory,
            name,
            RenameFlags::NOREPLACE,
        )?;
        self.directory.sync_all()?;
        let actual = self.open_object(name, sealed.size())?;
        let before = identity(&actual.metadata()?);
        if super::sealed::digest(&actual, sealed.size())? != sealed.digest
            || before != identity(&actual.metadata()?)
        {
            return Err(invalid("M15 durable catalog copy differs"));
        }
        self.recheck_object(name, &actual)
    }
}

/// Prepared bytes are durable but not the canonical head. No preparation
/// callback or data write follows the service's final interval admission.
pub(super) struct Prepared<'a> {
    owner: &'a Files,
    name: String,
    temporary: String,
    bytes: Vec<u8>,
}
impl Files {
    pub fn prepare_atomic(&self, name: &str, bytes: &[u8]) -> Result<Prepared<'_>> {
        child_name(name)?;
        self.revalidate()?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{name}.{}.prepared-{sequence}.tmp", std::process::id());
        let mut file = File::from(openat(
            &self.directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        private_regular(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        let prepared = Prepared {
            owner: self,
            name: name.into(),
            temporary,
            bytes: bytes.into(),
        };
        prepared.recheck()?;
        Ok(prepared)
    }
}
impl Prepared<'_> {
    pub fn recheck(&self) -> Result<()> {
        self.owner.revalidate()?;
        if self
            .owner
            .read(&self.temporary, self.bytes.len())?
            .as_deref()
            != Some(self.bytes.as_slice())
        {
            return Err(invalid("M15 prepared exact bytes changed"));
        }
        Ok(())
    }
    /// The sole production caller has finished provisioning/local checks and
    /// the final conservative clock interval. Completion is not another grant.
    pub fn publish_after_admission(self) -> Result<()> {
        renameat(
            &self.owner.directory,
            self.temporary.as_str(),
            &self.owner.directory,
            self.name.as_str(),
        )?;
        self.owner.directory.sync_all()?;
        if self.owner.read(&self.name, self.bytes.len())?.as_deref() != Some(self.bytes.as_slice())
        {
            return Err(invalid("M15 admitted durable publication differs"));
        }
        Ok(())
    }
}
