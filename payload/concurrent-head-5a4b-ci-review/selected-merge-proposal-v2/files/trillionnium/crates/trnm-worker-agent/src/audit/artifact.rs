//! Bounded reads of local audit artifacts; no journal or execution authority.
//! Unlike worker journals, pretty JSON needs no trailing newline and missing
//! export/index files remain errors. Every read uses one fresh held descriptor.
use anyhow::{ensure, Result};
use rustix::fs::{flock, FlockOperation, OFlags};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
fn identity(value: &fs::Metadata) -> Identity {
    Identity {
        dev: value.dev(),
        ino: value.ino(),
        len: value.len(),
        uid: value.uid(),
        mode: value.mode(),
        links: value.nlink(),
        mtime: value.mtime(),
        mtime_nsec: value.mtime_nsec(),
        ctime: value.ctime(),
        ctime_nsec: value.ctime_nsec(),
    }
}
fn check_named(path: &Path, file: &File, expected: &Identity) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    ensure!(
        named.is_file()
            && &identity(&named) == expected
            && &identity(&file.metadata()?) == expected,
        "worker audit artifact identity changed"
    );
    Ok(())
}
fn bounded_bytes(reader: &mut impl Read, maximum: u64) -> Result<Vec<u8>> {
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("worker audit artifact bound"))?;
    let mut bytes = Vec::new();
    reader.take(limit).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "worker audit artifact byte capacity"
    );
    Ok(bytes)
}
pub(super) fn read(path: &Path) -> Result<String> {
    read_with_hook(path, || Ok(()))
}
fn read_with_hook(path: &Path, after_open: impl FnOnce() -> Result<()>) -> Result<String> {
    read_with_hooks(path, || Ok(()), after_open)
}
fn read_with_hooks(
    path: &Path,
    after_validation: impl FnOnce() -> Result<()>,
    after_open: impl FnOnce() -> Result<()>,
) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "worker audit artifact requires a regular file"
    );
    ensure!(
        metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "worker audit artifact must be owned locally and not writable by other users"
    );
    after_validation()?;
    // An exporter that uses a journal lock cannot be mistaken for a stable
    // input. Non-cooperating writes still face the complete identity checks.
    flock(&file, FlockOperation::NonBlockingLockShared)?;
    let before = identity(&metadata);
    ensure!(
        before.len <= MAX_BYTES,
        "worker audit artifact byte capacity"
    );
    check_named(path, &file, &before)?;
    after_open()?;
    // The descriptor-bound take, not only stat, caps a file that grows during
    // the read. Neither a new open nor a size-dependent unbounded allocation.
    let bytes = bounded_bytes(&mut file, MAX_BYTES)?;
    check_named(path, &file, &before)?;
    ensure!(
        bytes.len() as u64 == before.len,
        "worker audit artifact length changed"
    );
    let raw = String::from_utf8(bytes)?;
    ensure!(
        raw.lines().all(|line| line.len() <= MAX_LINE_BYTES),
        "worker audit artifact line capacity"
    );
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Write};
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn exact_stream_bound_includes_eof_and_limits_a_growing_reader() {
        for length in [0, 31, 32] {
            assert_eq!(
                bounded_bytes(&mut Cursor::new(vec![b'x'; length]), 32)
                    .unwrap()
                    .len(),
                length
            );
        }
        assert_eq!(
            bounded_bytes(&mut Cursor::new(vec![b'x'; 33]), 32)
                .unwrap_err()
                .to_string(),
            "worker audit artifact byte capacity"
        );
        struct Growing(usize);
        impl Read for Growing {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                bytes.fill(b'x');
                self.0 += bytes.len();
                Ok(bytes.len())
            }
        }
        let mut growing = Growing(0);
        assert!(bounded_bytes(&mut growing, 32).is_err());
        assert_eq!(growing.0, 33);
        struct LateError(bool);
        impl Read for LateError {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    bytes[0] = 0xff;
                    return Ok(1);
                }
                Err(io::Error::other("retained late I/O failure"))
            }
        }
        assert_eq!(
            bounded_bytes(&mut LateError(false), 32)
                .unwrap_err()
                .to_string(),
            "retained late I/O failure"
        );
    }

    #[test]
    fn pretty_index_and_jsonl_keep_original_format_and_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        for bytes in [
            b"".as_slice(),
            b"{\n  \"version\": 1\n}",
            b"{\"a\":1}\n{\"b\":2}\n",
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(read(&path).unwrap().as_bytes(), bytes);
        }
        fs::remove_file(&path).unwrap();
        assert!(read(&path).is_err());
    }

    #[test]
    fn sparse_oversize_invalid_utf8_and_oversize_record_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        File::create(&path).unwrap().set_len(MAX_BYTES + 1).unwrap();
        assert_eq!(
            read(&path).unwrap_err().to_string(),
            "worker audit artifact byte capacity"
        );
        fs::write(&path, [0xff]).unwrap();
        assert!(read(&path).is_err());
        fs::write(&path, vec![b'x'; MAX_LINE_BYTES + 1]).unwrap();
        assert_eq!(
            read(&path).unwrap_err().to_string(),
            "worker audit artifact line capacity"
        );
    }

    #[test]
    fn path_aliases_nonregular_inputs_and_untrusted_permissions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"{}").unwrap();
        let alias = dir.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(read(&alias).is_err());
        assert!(read(dir.path()).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(read(&path).is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(&path).unwrap(), "{}");
    }

    #[test]
    fn replacement_growth_and_same_length_metadata_change_after_open_are_refused() {
        for change in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("input");
            fs::write(&path, b"good").unwrap();
            let result = read_with_hook(&path, || {
                match change {
                    0 => {
                        let other = dir.path().join("replacement");
                        fs::write(&other, b"good")?;
                        fs::rename(other, &path)?;
                    }
                    1 => OpenOptions::new()
                        .append(true)
                        .open(&path)?
                        .write_all(b"x")?,
                    _ => OpenOptions::new().write(true).open(&path)?.set_times(
                        fs::FileTimes::new().set_modified(
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1),
                        ),
                    )?,
                }
                Ok(())
            });
            assert_eq!(
                result.unwrap_err().to_string(),
                "worker audit artifact identity changed"
            );
        }
    }

    #[test]
    fn a_live_writer_lock_is_not_reported_as_an_empty_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"{}").unwrap();
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock(&writer, FlockOperation::LockExclusive).unwrap();
        assert!(read(&path).is_err());
        flock(&writer, FlockOperation::Unlock).unwrap();
        assert_eq!(read(&path).unwrap(), "{}");
    }

    #[test]
    fn query_bounds_both_export_and_pretty_index_before_reporting_records() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("audit.jsonl");
        let index = super::super::audit_export_index_path(&output);
        fs::write(&output, b"").unwrap();
        fs::write(
            &index,
            serde_json::to_vec_pretty(&super::super::build_audit_export_index(&[])).unwrap(),
        )
        .unwrap();
        super::super::handle_query_audit(output.clone(), Some(7), None).unwrap();
        File::create(&output)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert_eq!(
            super::super::handle_query_audit(output.clone(), Some(7), None)
                .unwrap_err()
                .to_string(),
            "worker audit artifact byte capacity"
        );
        fs::write(&output, b"").unwrap();
        File::create(&index)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert_eq!(
            super::super::handle_query_audit(output, Some(7), None)
                .unwrap_err()
                .to_string(),
            "worker audit artifact byte capacity"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_without_a_writer_is_refused_by_nonblocking_regular_file_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert_eq!(
            read(&path).unwrap_err().to_string(),
            "worker audit artifact requires a regular file"
        );
    }

    fn validation_window_refuses_change(hard_link: bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut reached = false;
        let result = read_with_hooks(
            &path,
            || {
                reached = true;
                if hard_link {
                    fs::hard_link(&path, dir.path().join("alias"))?;
                } else {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
                }
                Ok(())
            },
            || Ok(()),
        );
        assert!(
            reached,
            "controlled mutation must occur after initial validation"
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "worker audit artifact identity changed"
        );
    }

    #[test]
    fn validation_to_lock_permission_change_is_refused() {
        validation_window_refuses_change(false);
    }

    #[test]
    fn validation_to_lock_hardlink_change_is_refused() {
        validation_window_refuses_change(true);
    }
}
