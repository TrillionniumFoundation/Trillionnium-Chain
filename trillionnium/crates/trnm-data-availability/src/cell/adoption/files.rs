//! A private, held local namespace. Cooperating owners use SQLite locking;
//! the file lease additionally refuses replacement and hard-link aliases.
//! Arbitrary same-login memory/SQL writes are outside this local-owner API.
use std::{
    cell::Cell,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use crate::cell::{require, CellErrorV1, CellResultV1};

pub(super) struct Lease {
    pub path: PathBuf,
    file: File,
    parent: File,
    lost: Cell<bool>,
}

impl Lease {
    pub fn open(path: &Path, create: bool) -> CellResultV1<Self> {
        require(path.is_absolute(), "adoption absolute local path")?;
        let parent = path
            .parent()
            .ok_or(CellErrorV1::Invalid("adoption parent path"))?;
        require(
            parent.canonicalize()? == parent,
            "adoption canonical private parent",
        )?;
        let parent = File::open(parent)?;
        check_metadata(&parent.metadata()?, true)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(create);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = options.open(path)?;
        check_metadata(&file.metadata()?, false)?;
        let value = Self {
            path: path.to_owned(),
            file,
            parent,
            lost: Cell::new(false),
        };
        value.check()?;
        if create {
            value.file.sync_all()?;
            value.parent.sync_all()?;
        }
        Ok(value)
    }

    pub fn check(&self) -> CellResultV1<()> {
        require(!self.lost.get(), "adoption local file lease lost")?;
        let result = self.check_inner();
        if result.is_err() {
            self.lost.set(true);
        }
        result
    }

    fn check_inner(&self) -> CellResultV1<()> {
        let held = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        check_metadata(&held, false)?;
        check_metadata(&named, false)?;
        require(
            identity(&held) == identity(&named),
            "adoption database replaced",
        )?;
        let held_parent = self.parent.metadata()?;
        let named_parent = fs::symlink_metadata(
            self.path
                .parent()
                .ok_or(CellErrorV1::Invalid("adoption parent path"))?,
        )?;
        check_metadata(&held_parent, true)?;
        check_metadata(&named_parent, true)?;
        require(
            identity(&held_parent) == identity(&named_parent),
            "adoption directory replaced",
        )?;
        // This profile uses rollback journaling only. SQLite can recover a
        // genuine private hot journal after a crash; foreign sidecars refuse.
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut name = self.path.as_os_str().to_os_string();
            name.push(suffix);
            match fs::symlink_metadata(PathBuf::from(name)) {
                Ok(metadata) => {
                    check_metadata(&metadata, false)?;
                    require(suffix == "-journal", "adoption foreign journal mode")?;
                    require(metadata.len() <= 512 * 1024 * 1024, "adoption journal size")?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        require(held.len() <= 512 * 1024 * 1024, "adoption database size")
    }
}

#[cfg(unix)]
fn check_metadata(value: &fs::Metadata, directory: bool) -> CellResultV1<()> {
    use std::os::unix::fs::MetadataExt;
    require(
        if directory {
            value.is_dir()
        } else {
            value.is_file() && value.nlink() == 1
        },
        "adoption local file type/links",
    )?;
    require(
        value.uid() == rustix::process::geteuid().as_raw() && value.mode() & 0o077 == 0,
        "adoption private local ownership",
    )
}

#[cfg(not(unix))]
fn check_metadata(_value: &fs::Metadata, _directory: bool) -> CellResultV1<()> {
    Err(CellErrorV1::Invalid(
        "adoption local file profile requires Unix",
    ))
}

#[cfg(unix)]
fn identity(value: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (value.dev(), value.ino())
}

#[cfg(not(unix))]
fn identity(_value: &fs::Metadata) -> (u64, u64) {
    (0, 0)
}
