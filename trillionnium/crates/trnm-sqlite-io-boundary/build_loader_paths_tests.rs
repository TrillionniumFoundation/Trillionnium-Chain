//! Real Linux/tmpfs directory-capability controls. Authored, NOT RUN.
use super::{canonical_directory, LoaderPaths};
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const UNIT: &str = "trnm-sqlite-io-boundary-0123456789abcdef";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    original: Option<File>,
    cleanup: Vec<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let mounts = fs::read_to_string("/proc/self/mountinfo").expect("real Linux mount table");
        assert!(
            mounts.lines().any(|line| {
                let Some((before, after)) = line.split_once(" - ") else {
                    return false;
                };
                before.split_whitespace().nth(4) == Some("/dev/shm")
                    && after.split_whitespace().next() == Some("tmpfs")
            }),
            "these controls require actual /dev/shm tmpfs; absence is not a PASS"
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(format!(
            "/dev/shm/trnm-loader-fence-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::create_dir_all(root.join("release/build").join(UNIT).join("out")).unwrap();
        fs::create_dir(root.join("release/deps")).unwrap();
        let original = Some(File::open(&root).unwrap());
        Self {
            cleanup: vec![root.clone()],
            root,
            original,
        }
    }

    fn alias(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.original.as_ref().unwrap().as_raw_fd()
        ))
    }

    fn out(&self) -> PathBuf {
        self.root.join("release/build").join(UNIT).join("out")
    }

    fn alias_out(&self) -> PathBuf {
        self.alias().join("release/build").join(UNIT).join("out")
    }

    fn capture(&self) -> LoaderPaths {
        LoaderPaths::capture(Some(self.alias().as_os_str())).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Failure leaves the actual private fixture for the future control owner
        // to inventory; this code never cleans another experiment or service.
        if !std::thread::panicking() {
            for root in &self.cleanup {
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
}

#[test]
fn exact_inherited_alias_and_same_root_canonical_paths_are_admitted() {
    let f = Fixture::new();
    let mut paths = f.capture();
    assert_eq!(paths.out_directory(&f.alias_out()).unwrap(), f.out());
    assert_eq!(
        paths
            .target_directory(&f.root.join("release/deps"))
            .unwrap(),
        f.root.join("release/deps")
    );
    assert_eq!(
        paths
            .target_alias_directory(&f.alias().join("release"))
            .unwrap(),
        f.root.join("release")
    );
    paths.validate().unwrap();
}

#[test]
fn ordinary_canonical_route_keeps_its_original_behavior() {
    let f = Fixture::new();
    fs::set_permissions(&f.root, fs::Permissions::from_mode(0o755)).unwrap();
    let mut paths = LoaderPaths::capture(Some(f.root.as_os_str())).unwrap();
    assert_eq!(paths.target_directory(&f.out()).unwrap(), f.out());
    let link = f.root.join("out-link");
    symlink(f.out(), &link).unwrap();
    assert!(canonical_directory(&link).is_err());
    assert!(paths.target_alias_directory(&f.alias_out()).is_err());
}

#[test]
fn descriptor_spelling_requires_exact_nonstdio_decimal() {
    for value in [
        "/proc/self/fd/",
        "/proc/self/fd/00",
        "/proc/self/fd/03",
        "/proc/self/fd/+3",
        "/proc/self/fd/-3",
        "/proc/self/fd/3/",
        "/proc/self/fd/3/x",
        "/proc/self/fd/2147483648",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
    ] {
        assert!(
            LoaderPaths::capture(Some(OsStr::new(value))).is_err(),
            "{value}"
        );
    }
}

#[test]
fn another_descriptor_is_refused_even_for_the_same_directory_inode() {
    let f = Fixture::new();
    let duplicate = f.original.as_ref().unwrap().try_clone().unwrap();
    let other = PathBuf::from(format!("/proc/self/fd/{}", duplicate.as_raw_fd()));
    assert_ne!(other, f.alias());
    assert_eq!(
        duplicate.metadata().unwrap().ino(),
        f.original.as_ref().unwrap().metadata().unwrap().ino()
    );
    let mut paths = f.capture();
    assert!(paths.target_directory(&other.join("release/deps")).is_err());
    assert!(paths
        .target_alias_directory(&other.join("release/deps"))
        .is_err());
}

#[test]
fn canonical_out_directory_cannot_come_from_a_different_target() {
    let f = Fixture::new();
    let foreign = Fixture::new();
    let mut paths = f.capture();
    assert!(canonical_directory(&foreign.out()).is_ok());
    assert!(paths.out_directory(&foreign.out()).is_err());
}

#[test]
fn a_nested_profile_with_the_right_suffix_is_not_the_held_cargo_root() {
    let f = Fixture::new();
    let nested = f
        .root
        .join("foreign/nested/release/build")
        .join(UNIT)
        .join("out");
    fs::create_dir_all(&nested).unwrap();
    let mut paths = f.capture();
    assert!(canonical_directory(&nested).is_ok());
    assert!(paths.out_directory(&nested).is_err());
}

#[test]
fn literal_dot_empty_parent_and_trailing_components_are_refused() {
    let f = Fixture::new();
    let mut paths = f.capture();
    for suffix in [
        "release/./deps",
        "release//deps",
        "release/../release/deps",
        "release/deps/",
    ] {
        let spelling = PathBuf::from(format!("{}/{suffix}", f.alias().display()));
        assert!(spelling.canonicalize().is_ok());
        assert!(paths.target_directory(&spelling).is_err(), "{spelling:?}");
    }
}

#[test]
fn a_child_symlink_is_not_a_target_directory() {
    let f = Fixture::new();
    let mut paths = f.capture();
    paths.target_directory(&f.alias_out()).unwrap();
    fs::remove_dir(f.root.join("release/deps")).unwrap();
    symlink(f.root.join("release/build"), f.root.join("release/deps")).unwrap();
    assert!(paths
        .target_directory(&f.alias().join("release/deps"))
        .is_err());
}

#[test]
fn closing_the_original_descriptor_does_not_make_the_duplicate_authority_sufficient() {
    let mut f = Fixture::new();
    let mut paths = f.capture();
    paths.target_directory(&f.alias_out()).unwrap();
    drop(f.original.take());
    assert!(paths.validate().is_err());
}

#[test]
fn private_root_mode_must_remain0700() {
    let f = Fixture::new();
    let paths = f.capture();
    fs::set_permissions(&f.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(paths.validate().is_err());
}

#[test]
fn real_root_rename_and_replacement_cannot_retarget_the_capability() {
    let mut f = Fixture::new();
    let paths = f.capture();
    let old_inode = f.original.as_ref().unwrap().metadata().unwrap().ino();
    let moved = f.root.with_extension("moved");
    assert!(!moved.exists());
    fs::rename(&f.root, &moved).unwrap();
    f.cleanup.push(moved);
    DirBuilder::new().mode(0o700).create(&f.root).unwrap();
    assert_eq!(
        f.original.as_ref().unwrap().metadata().unwrap().ino(),
        old_inode
    );
    assert_ne!(fs::metadata(&f.root).unwrap().ino(), old_inode);
    assert!(paths.validate().is_err());
}

#[test]
fn replacing_an_ancestor_is_refused_even_if_the_original_out_inode_is_moved_back() {
    let f = Fixture::new();
    let mut paths = f.capture();
    paths.target_directory(&f.alias_out()).unwrap();
    let old_out_inode = fs::metadata(f.out()).unwrap().ino();
    let unit = f.root.join("release/build").join(UNIT);
    let moved = unit.with_extension("moved");
    fs::rename(&unit, &moved).unwrap();
    fs::create_dir(&unit).unwrap();
    fs::rename(moved.join("out"), unit.join("out")).unwrap();
    assert_eq!(fs::metadata(f.out()).unwrap().ino(), old_out_inode);
    assert!(paths.validate().is_err());
}

#[test]
fn held_mode_does_not_open_an_unrelated_proc_alias_as_a_canonical_loader_path() {
    let f = Fixture::new();
    let file = File::open(Path::new("/dev/shm")).unwrap();
    let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    assert!(canonical_directory(&path).is_err());
    let mut paths = f.capture();
    assert!(paths.target_alias_directory(&path).is_err());
}
