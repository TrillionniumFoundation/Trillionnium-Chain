//! Test-only local observations from the original held root and descriptor.
use crate::owner::stat_fd;
use crate::{NativeIoOwner, ROOT_COUNT};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join("trnm-owner-stat-witness-XXXXXX");
        let mut raw = CString::new(path.as_os_str().as_bytes())
            .unwrap()
            .into_bytes_with_nul();
        // mkdtemp exclusively creates a fresh private directory.
        let result = unsafe { libc::mkdtemp(raw.as_mut_ptr().cast()) };
        assert!(!result.is_null());
        assert_eq!(raw.pop(), Some(0));
        Self(std::ffi::OsString::from_vec(raw).into())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// No path, descriptor, syscall result or verdict is supplied by the observer.
// Both values are generated in-process by the unchanged original helpers.
fn fields(s: &libc::stat) -> [u64; 7] {
    [
        s.st_dev,
        s.st_ino,
        u64::from(s.st_mode),
        u64::from(s.st_uid),
        u64::from(s.st_nlink),
        u64::try_from(s.st_size).unwrap(),
        u64::try_from(s.st_blocks).unwrap(),
    ]
}

#[test]
fn original_fd_and_held_name_observation() {
    let fixture = Fixture::new();
    let roots: [PathBuf; ROOT_COUNT] =
        std::array::from_fn(|i| fixture.0.join(format!("root-{i}")));
    let owner = NativeIoOwner::create(roots).unwrap();
    let lease = owner.lease(0).unwrap();
    let root = &lease.registration.root;
    let name = "native.sqlite";
    assert!(root.stat_name(name).unwrap().is_none());

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(lease.directory().join(name))
        .unwrap();
    let mut ledger = root.lock().unwrap();
    let slot = ledger.reserve_open(name, true).unwrap();
    let bytes = [0x3c; 8193];
    for (previous, len) in [(0, 0), (0, 3), (3, 8193)] {
        file.write_all(&bytes[previous..len]).unwrap();
        file.sync_all().unwrap();

        let named = root.stat_name(name).unwrap().unwrap();
        let fd = stat_fd(file.as_raw_fd()).unwrap();
        assert_eq!(fields(&named), fields(&fd));
        assert_eq!(fd.st_mode & libc::S_IFMT, libc::S_IFREG);
        assert_eq!(fd.st_nlink, 1);
        assert_eq!(fd.st_size, len as i64);

        root.bind_fd(&mut ledger, slot, file.as_raw_fd()).unwrap();
        let object = &ledger.slots[slot].as_ref().unwrap().receipt;
        assert_eq!(object.device, Some(fd.st_dev));
        assert_eq!(object.inode, Some(fd.st_ino));
        assert!(object.linked);
        assert_eq!(object.actual_last_bytes, len as u64);
        assert_eq!(
            object.actual_last_allocated_blocks_512,
            u64::try_from(fd.st_blocks).unwrap()
        );
        // With --nocapture, downstream isolated qualification can consume both
        // observed tuples. No handle or pathname escapes the owning process.
        println!("owner-stat-v1|{len}|{:?}|{:?}", fields(&fd), fields(&named));
        if let Some(image) = std::env::var_os("TRNM_TEST_OWNED_STAT_IMAGE") {
            let result = std::process::Command::new(image)
                .current_dir(lease.directory())
                .env_clear()
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            assert!(result.status.success());
            assert!(result.stderr.is_empty());
            assert_eq!(result.stdout.len(), 112);
            for (word, expected) in result
                .stdout
                .chunks_exact(8)
                .zip(fields(&fd).into_iter().chain(fields(&named)))
            {
                assert_eq!(u64::from_le_bytes(word.try_into().unwrap()), expected);
            }
            println!("owner-stat-native-v1|{len}|paired-112");
        }
    }
}
