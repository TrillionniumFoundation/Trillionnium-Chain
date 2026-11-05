//! Byte-bound private copies for cold SQLite replay. No SQLite connection or
//! backup operation ever opens an input archive, and no sidecar is imported.
use super::*;
use std::fs::Metadata;
use std::path::PathBuf;

struct Input {
    path: PathBuf,
    file: File,
    observed: Metadata,
}
impl Input {
    fn open(path: &Path) -> Result<Self> {
        let input = Self::open_with_progress(path, &mut |_| Ok(()))?;
        ensure(input.observed.len() >= 20, "GROWTH_REHEARSAL_FILE")?;
        Ok(input)
    }
    fn open_with_progress(
        path: &Path,
        progress: &mut impl FnMut(FileReadProgress) -> Result<()>,
    ) -> Result<Self> {
        plain(path)?;
        progress(FileReadProgress::BeforeOpen)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let observed = file.metadata()?;
        ensure(
            observed.is_file() && observed.nlink() == 1,
            "GROWTH_REHEARSAL_FILE",
        )?;
        let input = Self {
            path: path.to_owned(),
            file,
            observed,
        };
        input.check()?;
        progress(FileReadProgress::Observed {
            bytes: input.observed.len(),
        })?;
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
                "GROWTH_REHEARSAL_FILE_CHANGED",
            )?;
        }
        Ok(())
    }
    fn copy(&mut self, output: &mut File, expected: Hash) -> Result<()> {
        ensure(self.observed.len() >= 20, "GROWTH_REHEARSAL_FILE")?;
        let mut header = [0u8; 20];
        self.file.read_exact(&mut header)?;
        ensure(
            &header[..16] == b"SQLite format 3\0" && header[18..20] == [1, 1],
            "GROWTH_REHEARSAL_SQLITE_FORMAT",
        )?;
        let mut digest = Sha256::new();
        digest.update(header);
        output.write_all(&header)?;
        self.consume_exact(self.observed.len() - header.len() as u64, |bytes| {
            digest.update(bytes);
            output.write_all(bytes)?;
            Ok(())
        })?;
        let actual: Hash = digest.finalize().into();
        ensure(actual == expected, "GROWTH_REHEARSAL_FILE_DIGEST")?;
        ensure(
            output.metadata()?.len() == self.observed.len(),
            "GROWTH_REHEARSAL_SNAPSHOT_LENGTH",
        )?;
        Ok(())
    }
    fn consume_exact(
        &mut self,
        mut remaining: u64,
        mut consume: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut buffer = [0u8; 65_536];
        while remaining != 0 {
            let bound = remaining.min(buffer.len() as u64) as usize;
            let count = self.file.read(&mut buffer[..bound])?;
            ensure(count != 0, "GROWTH_REHEARSAL_FILE_CHANGED")?;
            consume(&buffer[..count])?;
            remaining -= count as u64;
        }
        let mut sentinel = [0u8; 1];
        ensure(
            self.file.read(&mut sentinel)? == 0,
            "GROWTH_REHEARSAL_FILE_CHANGED",
        )?;
        self.check()
    }
}

/// Bound each hash to the length observed on its safely opened descriptor.
/// This is not a caller-wide byte/CPU budget; the final EOF probe consumes at
/// most one additional byte and a concurrent extension is rejected.
pub(super) fn file_hash_with_progress(
    path: &Path,
    progress: &mut impl FnMut(FileReadProgress) -> Result<()>,
) -> Result<Hash> {
    let mut input = Input::open_with_progress(path, progress)?;
    let length = input.observed.len();
    let mut digest = Sha256::new();
    input.consume_exact(length, |bytes| {
        digest.update(bytes);
        progress(FileReadProgress::Consumed {
            bytes: bytes.len() as u64,
        })
    })?;
    Ok(digest.finalize().into())
}

pub(super) fn read_receipt_bytes_with_progress(
    path: &Path,
    progress: &mut impl FnMut(FileReadProgress) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut input = Input::open_with_progress(path, progress)?;
    let length = input.observed.len();
    ensure(length <= 1_048_576, "GROWTH_REHEARSAL_RECEIPT_LIMIT")?;
    let mut bytes = Vec::with_capacity(length as usize);
    input.consume_exact(length, |chunk| {
        bytes.extend_from_slice(chunk);
        progress(FileReadProgress::Consumed {
            bytes: chunk.len() as u64,
        })
    })?;
    Ok(bytes)
}

struct Scratch {
    temporary: Option<tempfile::TempDir>,
    directory: File,
    parent: File,
    parent_path: PathBuf,
}
impl Scratch {
    fn create(archive: &Path) -> Result<Self> {
        let parent_path = std::env::temp_dir().canonicalize()?;
        ensure(
            !parent_path.starts_with(archive.canonicalize()?),
            "GROWTH_REHEARSAL_SNAPSHOT_LOCATION",
        )?;
        let parent = growth_reservation_io::directory_components(&parent_path)?;
        growth_reservation_io::check_named_parent(&parent, &parent_path)?;
        let temporary = tempfile::Builder::new()
            .prefix("trnm-growth-cold-")
            .tempdir_in(&parent_path)?;
        let directory = growth_reservation_io::directory_components(temporary.path())?;
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        let scratch = Self {
            temporary: Some(temporary),
            directory,
            parent,
            parent_path,
        };
        scratch.check()?;
        Ok(scratch)
    }
    fn path(&self) -> &Path {
        self.temporary
            .as_ref()
            .expect("live private snapshot")
            .path()
    }
    fn check(&self) -> Result<()> {
        growth_reservation_io::check_named_parent(&self.parent, &self.parent_path)?;
        growth_reservation_io::check_named_parent(&self.directory, self.path())?;
        let metadata = self.directory.metadata()?;
        ensure(
            metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode() & 0o7777 == 0o700,
            "GROWTH_REHEARSAL_SNAPSHOT_IDENTITY",
        )
    }
    fn cleanup(&mut self) -> Result<()> {
        let identity = self.check();
        let temporary = self.temporary.take().expect("live private snapshot");
        if let Err(error) = identity {
            // Never recursively remove a replacement or an uncertain path.
            let _ = temporary.keep();
            return Err(error);
        }
        temporary.close()?;
        Ok(())
    }
    fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        match (result, self.cleanup()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => {
                Err(format!("GROWTH_REHEARSAL_SNAPSHOT_CLEANUP: {error}; {cleanup}").into())
            }
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if self.temporary.is_some() {
            let _ = self.cleanup();
        }
    }
}
fn create_file(directory: &File, name: &str) -> Result<File> {
    let file = File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(std::io::Error::from)?,
    );
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    check_file(directory, name, &file)?;
    Ok(file)
}
fn check_file(directory: &File, name: &str, held: &File) -> Result<()> {
    let named = File::from(
        rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let original = held.metadata()?;
    let current = named.metadata()?;
    ensure(
        current.is_file()
            && current.nlink() == 1
            && current.uid() == rustix::process::geteuid().as_raw()
            && current.permissions().mode() & 0o7777 == 0o600
            && (current.dev(), current.ino(), current.len())
                == (original.dev(), original.ino(), original.len()),
        "GROWTH_REHEARSAL_SNAPSHOT_IDENTITY",
    )
}

pub(super) fn with_snapshot<T>(
    archive: &Path,
    source_digest: Hash,
    checkpoint_digest: Hash,
    snapshot_byte_limit: u64,
    inspect: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let mut source = Input::open(&archive.join("source/native.sqlite"))?;
    let mut checkpoint = Input::open(&archive.join("native.sqlite"))?;
    let bytes = source
        .observed
        .len()
        .checked_add(checkpoint.observed.len())
        .ok_or("GROWTH_REHEARSAL_SNAPSHOT_LIMIT")?;
    ensure(
        bytes <= snapshot_byte_limit,
        "GROWTH_REHEARSAL_SNAPSHOT_LIMIT",
    )?;
    let scratch = Scratch::create(archive)?;
    let result = (|| {
        rustix::fs::mkdirat(
            &scratch.directory,
            "source",
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
        )
        .map_err(std::io::Error::from)?;
        let source_directory =
            growth_reservation_io::directory_components(&scratch.path().join("source"))?;
        source_directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        let mut source_copy = create_file(&source_directory, "native.sqlite")?;
        let mut checkpoint_copy = create_file(&scratch.directory, "native.sqlite")?;
        let source_owner = create_file(&source_directory, "owner.lock")?;
        let checkpoint_owner = create_file(&scratch.directory, "owner.lock")?;
        source.copy(&mut source_copy, source_digest)?;
        checkpoint.copy(&mut checkpoint_copy, checkpoint_digest)?;
        scratch.check()?;
        growth_reservation_io::check_named_parent(
            &source_directory,
            &scratch.path().join("source"),
        )?;
        check_file(&source_directory, "native.sqlite", &source_copy)?;
        check_file(&scratch.directory, "native.sqlite", &checkpoint_copy)?;
        let observed = inspect(scratch.path());
        let intact = (|| {
            source.check()?;
            checkpoint.check()?;
            scratch.check()?;
            growth_reservation_io::check_named_parent(
                &source_directory,
                &scratch.path().join("source"),
            )?;
            check_file(&source_directory, "native.sqlite", &source_copy)?;
            check_file(&scratch.directory, "native.sqlite", &checkpoint_copy)?;
            check_file(&source_directory, "owner.lock", &source_owner)?;
            check_file(&scratch.directory, "owner.lock", &checkpoint_owner)
        })();
        // Always check identities, but retain the replay's original error if it
        // already rejected. A path change cannot turn a failed replay into success.
        match observed {
            Err(error) => Err(error),
            Ok(value) => intact.map(|()| value),
        }
    })();
    // The inspection's Node/SQLite handles have closed before private cleanup.
    scratch.finish(result)
}
