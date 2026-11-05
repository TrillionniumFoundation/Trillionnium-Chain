//! Cold local observation never opens the source database with SQLite. A
//! closed, log-free main file is copied while its existing owner is locked;
//! any pending log requires the ordinary writer to recover and close first.
use crate::{ensure, Error, Result};
use fs2::FileExt;
use rustix::fs::{open, openat, Mode, OFlags};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub(super) const DEFAULT_SNAPSHOT_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn directory_components(path: &Path) -> Result<File> {
    ensure(path.is_absolute(), "GROWTH_OBSERVATION_DIRECTORY")?;
    let mut directory =
        File::from(open("/", DIRECTORY_FLAGS, Mode::empty()).map_err(std::io::Error::from)?);
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                directory = File::from(
                    openat(&directory, name, DIRECTORY_FLAGS, Mode::empty())
                        .map_err(std::io::Error::from)?,
                );
            }
            _ => return Err("GROWTH_OBSERVATION_DIRECTORY".into()),
        }
    }
    Ok(directory)
}

fn check_directory(held: &File, path: &Path) -> Result<()> {
    let named = directory_components(path)?;
    let observed = held.metadata()?;
    let current = named.metadata()?;
    ensure(
        current.is_dir() && (current.dev(), current.ino()) == (observed.dev(), observed.ino()),
        "GROWTH_OBSERVATION_NAMESPACE_CHANGED",
    )
}

fn no_recovery_files(path: &Path) -> Result<()> {
    for name in [
        "initializing.json",
        "native.sqlite-wal",
        "native.sqlite-shm",
        "native.sqlite-journal",
    ] {
        match fs::symlink_metadata(path.join(name)) {
            Ok(_) => return Err("GROWTH_OBSERVATION_RECOVERY_REQUIRED".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    ensure(
        !super::super::authenticated_migration_pending(path)?,
        "NATIVE_STATE_MIGRATION_PENDING",
    )?;
    ensure(
        !super::super::owner_marker_present(path)?,
        "OWNER_TASK_POLICY_REQUIRED",
    )
}

struct Input {
    path: PathBuf,
    file: File,
    observed: Metadata,
}
impl Input {
    fn open(path: &Path) -> Result<Self> {
        // No CREATE and no blocking FIFO/device open after a pathname check.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let observed = file.metadata()?;
        let input = Self {
            path: path.to_owned(),
            file,
            observed,
        };
        input.check()?;
        Ok(input)
    }
    fn check(&self) -> Result<()> {
        for current in [self.file.metadata()?, fs::symlink_metadata(&self.path)?] {
            ensure(
                current.is_file()
                    && current.nlink() == 1
                    && (
                        current.dev(),
                        current.ino(),
                        current.len(),
                        current.mtime(),
                        current.mtime_nsec(),
                        current.ctime(),
                        current.ctime_nsec(),
                    ) == (
                        self.observed.dev(),
                        self.observed.ino(),
                        self.observed.len(),
                        self.observed.mtime(),
                        self.observed.mtime_nsec(),
                        self.observed.ctime(),
                        self.observed.ctime_nsec(),
                    ),
                "GROWTH_OBSERVATION_FILE_CHANGED",
            )?;
        }
        Ok(())
    }
    fn copy(&mut self, output: &mut File) -> Result<()> {
        ensure(
            self.observed.len() >= 20,
            "GROWTH_OBSERVATION_SQLITE_FORMAT",
        )?;
        let mut header = [0u8; 20];
        self.file.read_exact(&mut header)?;
        ensure(
            &header[..16] == b"SQLite format 3\0"
                && (header[18..20] == [1, 1] || header[18..20] == [2, 2]),
            "GROWTH_OBSERVATION_SQLITE_FORMAT",
        )?;
        output.write_all(&header)?;
        let mut remaining = self.observed.len() - header.len() as u64;
        let mut buffer = [0u8; 65_536];
        while remaining != 0 {
            let bound = remaining.min(buffer.len() as u64) as usize;
            let count = self.file.read(&mut buffer[..bound])?;
            ensure(count != 0, "GROWTH_OBSERVATION_FILE_CHANGED")?;
            output.write_all(&buffer[..count])?;
            remaining -= count as u64;
        }
        let mut sentinel = [0u8; 1];
        ensure(
            self.file.read(&mut sentinel)? == 0,
            "GROWTH_OBSERVATION_FILE_CHANGED",
        )?;
        self.check()?;
        ensure(
            output.metadata()?.len() == self.observed.len(),
            "GROWTH_OBSERVATION_SNAPSHOT_LENGTH",
        )
    }
}

fn create_private_file(directory: &File, name: &str) -> Result<File> {
    let file = File::from(
        openat(
            directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(std::io::Error::from)?,
    );
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Field destruction is ordered by Node: its SQLite connection closes before
/// this guard removes private files; the source lock outlives that cleanup.
pub(in crate::store) struct Snapshot {
    temporary: Option<tempfile::TempDir>,
    directory: File,
    parent: File,
    parent_path: PathBuf,
    database: Option<File>,
    owner: Option<File>,
    source_path: PathBuf,
    source_directory: File,
    source_database: Input,
    source_owner: Input,
}
impl Snapshot {
    pub(in crate::store) fn create(path: &Path, snapshot_byte_limit: u64) -> Result<Self> {
        ensure(
            path.join("native.sqlite").is_file(),
            "GROWTH_PACKET_STATUS_EXISTING_STORE_REQUIRED",
        )?;
        let metadata = fs::symlink_metadata(path)?;
        ensure(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "NAMESPACE",
        )?;
        let source_path = path.canonicalize()?;
        let source_directory = directory_components(&source_path)?;
        let held_directory = source_directory.metadata()?;
        ensure(
            (metadata.dev(), metadata.ino()) == (held_directory.dev(), held_directory.ino()),
            "GROWTH_OBSERVATION_NAMESPACE_CHANGED",
        )?;
        let source_owner = Input::open(&source_path.join("owner.lock"))?;
        source_owner
            .file
            .try_lock_exclusive()
            .map_err(|_| Error::from("WRITER_BUSY"))?;
        check_directory(&source_directory, &source_path)?;
        source_owner.check()?;
        no_recovery_files(&source_path)?;
        let source_database = Input::open(&source_path.join("native.sqlite"))?;
        ensure(
            source_database.observed.len() <= snapshot_byte_limit,
            "GROWTH_OBSERVATION_SNAPSHOT_LIMIT",
        )?;
        let parent_path = std::env::temp_dir().canonicalize()?;
        ensure(
            !parent_path.starts_with(&source_path),
            "GROWTH_OBSERVATION_SNAPSHOT_LOCATION",
        )?;
        let parent = directory_components(&parent_path)?;
        let temporary = tempfile::Builder::new()
            .prefix("trnm-growth-observer-")
            .tempdir_in(&parent_path)?;
        let directory = directory_components(temporary.path())?;
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        let mut snapshot = Self {
            temporary: Some(temporary),
            directory,
            parent,
            parent_path,
            database: None,
            owner: None,
            source_path,
            source_directory,
            source_database,
            source_owner,
        };
        snapshot.check()?;
        let mut database = create_private_file(&snapshot.directory, "native.sqlite")?;
        let owner = create_private_file(&snapshot.directory, "owner.lock")?;
        snapshot.source_database.copy(&mut database)?;
        snapshot.database = Some(database);
        snapshot.owner = Some(owner);
        snapshot.check()?;
        Ok(snapshot)
    }
    pub(in crate::store) fn path(&self) -> &Path {
        self.temporary
            .as_ref()
            .expect("live observer snapshot")
            .path()
    }
    fn check_private_directory(&self) -> Result<()> {
        check_directory(&self.parent, &self.parent_path)?;
        check_directory(&self.directory, self.path())?;
        let metadata = self.directory.metadata()?;
        ensure(
            metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode() & 0o7777 == 0o700,
            "GROWTH_OBSERVATION_SNAPSHOT_IDENTITY",
        )
    }
    pub(in crate::store) fn check(&self) -> Result<()> {
        check_directory(&self.source_directory, &self.source_path)?;
        self.source_owner.check()?;
        no_recovery_files(&self.source_path)?;
        self.source_database.check()?;
        self.check_private_directory()?;
        for (name, held) in [
            ("native.sqlite", &self.database),
            ("owner.lock", &self.owner),
        ] {
            if let Some(held) = held {
                let named = fs::symlink_metadata(self.path().join(name))?;
                let current = held.metadata()?;
                ensure(
                    named.is_file()
                        && named.nlink() == 1
                        && named.uid() == rustix::process::geteuid().as_raw()
                        && named.permissions().mode() & 0o7777 == 0o600
                        && (named.dev(), named.ino(), named.len())
                            == (current.dev(), current.ino(), current.len()),
                    "GROWTH_OBSERVATION_SNAPSHOT_IDENTITY",
                )?;
            }
        }
        Ok(())
    }
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        let intact = self.check_private_directory().is_ok();
        if let Some(temporary) = self.temporary.take() {
            if intact {
                // SQLite has closed, and source_owner is still held here.
                let _ = temporary.close();
            } else {
                // Never recursively remove an uncertain or replaced path.
                let _ = temporary.keep();
            }
        }
    }
}
