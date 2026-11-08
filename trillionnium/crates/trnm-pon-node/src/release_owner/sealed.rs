//! Immutable kernel objects. A sealed descriptor alone conveys no M15 authority.
use super::execution_wire::{FileIdentity, MAX_PROGRAM_BYTES};
use super::frontier::{invalid, Digest32, Result};
use rustix::fs::{
    fchmod, fcntl_add_seals, fcntl_get_seals, fcntl_getfl, memfd_create, MemfdFlags, Mode, OFlags,
    SealFlags,
};
use rustix::io::{dup3, fcntl_getfd, fcntl_setfd, DupFlags, FdFlags};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

// Proc magic links are intentional descriptor transport, never an exec path.
// NONBLOCK precedes type/seal checks so an inherited FIFO cannot hang open().
fn open_descriptor_path(path: impl AsRef<Path>) -> Result<File> {
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    if !held.metadata()?.is_file() {
        return Err(invalid("M15 inherited object is not regular"));
    }
    let before = identity(&held)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", held.as_raw_fd()))?;
    if before != identity(&held)? || before != identity(&file)? {
        return Err(invalid("M15 held proc descriptor identity changed"));
    }
    Ok(file)
}

fn seals() -> SealFlags {
    SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL | SealFlags::EXEC
}
pub(super) fn identity(file: &File) -> Result<FileIdentity> {
    let m = file.metadata()?;
    Ok(FileIdentity {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        uid: m.uid(),
        mode: m.mode(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
    })
}
pub(super) fn digest(file: &File, size: u64) -> Result<Digest32> {
    let mut hasher = Sha256::new();
    copy(file, size, |chunk| {
        hasher.update(chunk);
        Ok(())
    })?;
    Ok(hasher.finalize().into())
}
fn copy(file: &File, size: u64, mut consume: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut offset = 0;
    let mut buffer = [0; 65536];
    while offset < size {
        let length = (size - offset).min(buffer.len() as u64) as usize;
        file.read_exact_at(&mut buffer[..length], offset)?;
        consume(&buffer[..length])?;
        offset += length as u64;
    }
    let mut extra = [0; 1];
    if file.read_at(&mut extra, size)? != 0 {
        return Err(invalid("M15 executable grew beyond exact bound"));
    }
    Ok(())
}

pub(super) struct Sealed {
    file: File,
    identity: FileIdentity,
    pub digest: Digest32,
}
pub(super) struct DataBuilder(File);

impl DataBuilder {
    pub fn new() -> Result<Self> {
        Ok(Self(File::from(memfd_create(
            "trnm-m15-data",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL,
        )?)))
    }
    pub fn raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
    pub fn finish(mut self, bytes: &[u8], maximum: usize) -> Result<Sealed> {
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(invalid("M15 sealed data bound"));
        }
        self.0.write_all(bytes)?;
        fchmod(&self.0, Mode::RUSR)?;
        fcntl_add_seals(&self.0, seals())?;
        Sealed::validated(self.0, Sha256::digest(bytes).into(), bytes.len() as u64)
    }
}

impl Sealed {
    fn validated(file: File, expected: Digest32, size: u64) -> Result<Self> {
        if expected == [0; 32] || size == 0 || size > MAX_PROGRAM_BYTES {
            return Err(invalid("M15 sealed object bound"));
        }
        let actual = identity(&file)?;
        if !file.metadata()?.is_file()
            || actual.size != size
            || !fcntl_get_seals(&file)?.contains(seals())
            || digest(&file, size)? != expected
            || actual != identity(&file)?
        {
            return Err(invalid("M15 immutable descriptor/hash binding"));
        }
        // A denied write to an O_RDWR sealed memfd can still update mtime and
        // ctime before the kernel checks F_SEAL_WRITE. Retain every identity
        // check by publishing only an O_RDONLY description instead. Keep the
        // owned descriptor number: DataBuilder reserves it in LaunchAttempt
        // before writing the final handoff. dup3 atomically replaces that live
        // descriptor without a close/reallocate race and preserves CLOEXEC.
        let read_only = open_descriptor_path(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        if actual != identity(&read_only)? {
            return Err(invalid("M15 sealed read-only object changed"));
        }
        let mut held: OwnedFd = file.into();
        dup3(&read_only, &mut held, DupFlags::CLOEXEC)?;
        drop(read_only);
        let sealed = Self {
            file: File::from(held),
            identity: actual,
            digest: expected,
        };
        sealed.recheck()?;
        Ok(sealed)
    }

    pub fn from_file(
        source: &File,
        expected: Digest32,
        size: u64,
        executable: bool,
    ) -> Result<Self> {
        if size == 0 || size > MAX_PROGRAM_BYTES {
            return Err(invalid("M15 source object bound"));
        }
        let original = identity(source)?;
        if !source.metadata()?.is_file() || original.size != size {
            return Err(invalid("M15 source object is not an exact regular file"));
        }
        let kind = if executable {
            MemfdFlags::EXEC
        } else {
            MemfdFlags::NOEXEC_SEAL
        };
        let mut target = File::from(memfd_create(
            "trnm-m15-authenticated",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | kind,
        )?);
        copy(source, size, |bytes| target.write_all(bytes))?;
        #[cfg(test)]
        super::sealed_faults::after_copy();
        fchmod(
            &target,
            if executable {
                Mode::RUSR | Mode::XUSR
            } else {
                Mode::RUSR
            },
        )?;
        fcntl_add_seals(&target, seals())?;
        let sealed = Self::validated(target, expected, size)?;
        if original != identity(source)? {
            return Err(invalid("M15 source changed during sealed copy"));
        }
        Ok(sealed)
    }

    pub fn from_path(
        path: &Path,
        expected: Digest32,
        size: u64,
        executable: bool,
    ) -> Result<(Self, FileIdentity)> {
        if !path.is_absolute() {
            return Err(invalid("M15 source path must be absolute"));
        }
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let original = identity(&source)?;
        if source.metadata()?.nlink() != 1 {
            return Err(invalid("M15 source must have one link"));
        }
        let sealed = Self::from_file(&source, expected, size, executable)?;
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        if original != identity(&source)? || original != identity(&named)? {
            return Err(invalid(
                "M15 source path/object changed during authentication",
            ));
        }
        Ok((sealed, original))
    }

    /// Bounded, untrusted transport material. Authentication comes only from
    /// independent Deployment plus fresh external proof/Claim, never this hash.
    pub fn untrusted_handoff(fd: u32, maximum: usize) -> Result<Self> {
        if fd < 3 || fd > i32::MAX as u32 {
            return Err(invalid("M15 handoff descriptor"));
        }
        let file = open_descriptor_path(format!("/proc/self/fd/{fd}"))?;
        let size = file.metadata()?.len();
        if size == 0 || size > maximum as u64 || !fcntl_get_seals(&file)?.contains(seals()) {
            return Err(invalid("M15 handoff seals/bound"));
        }
        let expected = digest(&file, size)?;
        Self::validated(file, expected, size)
    }
    pub fn actual_process_image(expected: Digest32, size: u64, platform: Digest32) -> Result<Self> {
        let value = Self::validated(open_descriptor_path("/proc/self/exe")?, expected, size)?;
        super::elf::verify(&value.file, size, platform)?;
        Ok(value)
    }
    pub fn verify_elf(&self, platform: Digest32) -> Result<()> {
        self.recheck()?;
        super::elf::verify(&self.file, self.identity.size, platform)
    }
    pub fn recheck(&self) -> Result<()> {
        if self.identity != identity(&self.file)?
            || !fcntl_get_seals(&self.file)?.contains(seals())
            || (fcntl_getfl(&self.file)? & OFlags::ACCMODE) != OFlags::RDONLY
        {
            return Err(invalid("M15 sealed object identity/seals changed"));
        }
        Ok(())
    }
    pub fn read(&self, maximum: usize) -> Result<Vec<u8>> {
        self.recheck()?;
        if self.identity.size > maximum as u64 {
            return Err(invalid("M15 sealed read bound"));
        }
        let mut bytes = vec![0; self.identity.size as usize];
        self.file.read_exact_at(&mut bytes, 0)?;
        self.recheck()?;
        Ok(bytes)
    }
    pub fn copy_to(&self, destination: &mut File) -> Result<()> {
        self.recheck()?;
        copy(&self.file, self.identity.size, |bytes| {
            destination.write_all(bytes)
        })?;
        self.recheck()
    }
    pub fn require_descriptor(&self, fd: u32) -> Result<()> {
        if fd < 3 || fd > i32::MAX as u32 {
            return Err(invalid("M15 actual descriptor number"));
        }
        let actual = open_descriptor_path(format!("/proc/self/fd/{fd}"))?;
        if identity(&actual)? != self.identity {
            return Err(invalid("M15 inherited descriptor was replaced"));
        }
        self.recheck()
    }
    pub fn pass_to_exec(&self) -> Result<()> {
        self.recheck()?;
        let mut flags = fcntl_getfd(&self.file)?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(&self.file, flags)?;
        Ok(())
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
    pub fn size(&self) -> u64 {
        self.identity.size
    }
}
