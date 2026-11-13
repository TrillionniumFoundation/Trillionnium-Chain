//! Local research CLI input boundary. The outer worker still owns the deadline:
//! regular-file I/O and kernel waits are not hard real-time guarantees.
use anyhow::{ensure, Result};

#[cfg(unix)]
pub fn bounded(path: &str, limit: usize) -> Result<Vec<u8>> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
    // O_NONBLOCK applies at open too, so an attacker-selected FIFO cannot hang
    // before the same-fd type check. A separate path.is_file() check would race.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "regular input file required");
    ensure!(metadata.len() <= limit as u64, "input size bound");
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input size bound");
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "input length changed while reading"
    );
    Ok(bytes)
}

#[cfg(not(unix))]
pub fn bounded(_path: &str, _limit: usize) -> Result<Vec<u8>> {
    anyhow::bail!("bounded regular-file input unsupported on this platform")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        ffi::CString,
        fs,
        os::unix::{ffi::OsStrExt, fs::symlink},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "trnm-w1-v2-input-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
        bounded(path.to_str().unwrap(), limit)
    }

    #[test]
    fn exact_regular_input_and_oversize_boundary() {
        let scratch = Scratch::new();
        let path = scratch.path("input");
        fs::write(&path, b"exact").unwrap();
        assert_eq!(read(&path, 5).unwrap(), b"exact");
        assert!(read(&path, 4)
            .unwrap_err()
            .to_string()
            .contains("input size bound"));
        assert!(read(&scratch.path("missing"), 5).is_err());
    }

    #[test]
    fn symlink_directory_and_fifo_refuse_before_stream_read() {
        let scratch = Scratch::new();
        let file = scratch.path("regular");
        fs::write(&file, b"exact").unwrap();
        let link = scratch.path("link");
        symlink(&file, &link).unwrap();
        assert!(read(&link, 5).is_err());
        assert!(read(&scratch.0, 5).is_err());
        let fifo = scratch.path("fifo");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path, no borrowed native resources.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // There is deliberately no writer. Blocking open/read would hang this
        // actual regression; O_NONBLOCK + same-fd regular check returns now.
        assert!(read(&fifo, 5)
            .unwrap_err()
            .to_string()
            .contains("regular input"));
    }
}
