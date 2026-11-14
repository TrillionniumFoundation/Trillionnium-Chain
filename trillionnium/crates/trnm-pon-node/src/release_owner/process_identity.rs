//! Observed Linux process and held working-directory identity, never an authority.
use super::execution_wire::{DirectoryIdentity, ProcessIdentity};
use super::frontier::{hash, invalid, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

fn read(path: &str, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("M15 process identity bound"));
    }
    Ok(bytes)
}

pub(super) fn actual() -> Result<ProcessIdentity> {
    let bytes = read("/proc/self/stat", 65536)?;
    let text = std::str::from_utf8(&bytes).map_err(std::io::Error::other)?;
    let (pid, _) = text
        .split_once(" (")
        .ok_or_else(|| invalid("M15 process stat prefix"))?;
    let (_, fields) = text
        .rsplit_once(") ")
        .ok_or_else(|| invalid("M15 process stat suffix"))?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let start_ticks = fields
        .get(19)
        .ok_or_else(|| invalid("M15 process birth field"))?
        .parse()
        .map_err(std::io::Error::other)?;
    let pid: u32 = pid.parse().map_err(std::io::Error::other)?;
    let boot = read("/proc/sys/kernel/random/boot_id", 128)?;
    let namespace = fs::metadata("/proc/self/ns/pid")?;
    if pid != std::process::id()
        || start_ticks == 0
        || boot.len() != 37
        || boot[36] != b'\n'
        || namespace.ino() == 0
    {
        return Err(invalid("M15 actual Linux process identity"));
    }
    Ok(ProcessIdentity {
        pid,
        uid: rustix::process::geteuid().as_raw(),
        start_ticks,
        boot_id: hash(b"TRNM/M15/LinuxBootIdentity/v1\0", &boot),
        pid_namespace_device: namespace.dev(),
        pid_namespace_inode: namespace.ino(),
    })
}

fn identity(file: &File) -> Result<DirectoryIdentity> {
    let value = file.metadata()?;
    if !value.is_dir() {
        return Err(invalid("M15 working object is not a directory"));
    }
    Ok(DirectoryIdentity {
        device: value.dev(),
        inode: value.ino(),
        uid: value.uid(),
        mode: value.mode(),
    })
}

pub(super) struct WorkingDirectory {
    path: PathBuf,
    file: File,
    expected: DirectoryIdentity,
}
impl WorkingDirectory {
    pub fn open(path: &Path, expected: &DirectoryIdentity) -> Result<Self> {
        if !path.is_absolute()
            || path.canonicalize()? != path
            || expected.uid != rustix::process::geteuid().as_raw()
            || expected.mode & 0o7777 != 0o700
        {
            return Err(invalid("M15 working-directory path/owner/mode"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)?;
        let value = Self {
            path: path.into(),
            file,
            expected: expected.clone(),
        };
        value.recheck()?;
        Ok(value)
    }
    pub fn recheck(&self) -> Result<()> {
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&self.path)?;
        if identity(&self.file)? != self.expected || identity(&named)? != self.expected {
            return Err(invalid("M15 held working-directory identity changed"));
        }
        Ok(())
    }
    pub fn enter(&self) -> Result<()> {
        self.recheck()?;
        nix::unistd::fchdir(&self.file).map_err(std::io::Error::other)?;
        self.require_current()
    }
    pub fn require_current(&self) -> Result<()> {
        self.recheck()?;
        if identity(&File::open(".")?)? != self.expected {
            return Err(invalid("M15 actual working directory mismatch"));
        }
        Ok(())
    }
}
