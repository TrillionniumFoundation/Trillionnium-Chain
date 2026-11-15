//! Filesystem mechanism controls, separate from signed trust and exec qualification.
use super::{files::Files, files_faults};
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn fixture() -> (tempfile::TempDir, PathBuf, Files) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("owner");
    let files = Files::create(&root).unwrap();
    (temp, root, files)
}

fn private_file(path: &Path, raw: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn child_names_are_exact_single_components_before_any_filesystem_mutation() {
    let (temp, root, files) = fixture();
    private_file(&temp.path().join("outside"), b"unchanged");
    for name in ["", ".", "..", "../outside", "/outside", "a/b", "a/", "a\0b"] {
        assert!(files.read(name, 64).is_err(), "read accepted {name:?}");
        assert!(
            files.write(name, b"changed").is_err(),
            "write accepted {name:?}"
        );
    }
    assert_eq!(fs::read(temp.path().join("outside")).unwrap(), b"unchanged");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    files.write("object-0123.json", b"exact").unwrap();
    assert_eq!(
        files.read("object-0123.json", 5).unwrap().unwrap(),
        b"exact"
    );
}

#[test]
fn symlink_fifo_directory_hardlink_and_nonprivate_modes_are_rejected() {
    let (temp, root, files) = fixture();
    private_file(&temp.path().join("outside"), b"outside");
    symlink(temp.path().join("outside"), root.join("symlink")).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        root.join("fifo"),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    fs::create_dir(root.join("directory")).unwrap();
    private_file(&root.join("hardlink"), b"same inode");
    fs::hard_link(root.join("hardlink"), temp.path().join("linked")).unwrap();
    private_file(&root.join("public"), b"public");
    fs::set_permissions(root.join("public"), Permissions::from_mode(0o644)).unwrap();
    for name in ["symlink", "fifo", "directory", "hardlink", "public"] {
        assert!(files.read(name, 64).is_err(), "accepted {name}");
    }
    assert_eq!(fs::read(temp.path().join("outside")).unwrap(), b"outside");
}

#[test]
fn exact_size_is_accepted_but_growth_after_the_held_read_is_rejected() {
    let (_temp, root, files) = fixture();
    files.write("object", &[7; 64]).unwrap();
    assert_eq!(files.read("object", 64).unwrap().unwrap(), [7; 64]);
    assert!(files.read("object", 63).is_err());
    let path = root.join("object");
    files_faults::once("object", move || {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[8]).unwrap();
        file.sync_all().unwrap();
    });
    assert!(files.read("object", 64).is_err());
    assert_eq!(fs::metadata(root.join("object")).unwrap().len(), 65);
}

#[test]
fn same_bytes_at_a_new_named_inode_do_not_pass_the_held_read() {
    let (_temp, root, files) = fixture();
    files.write("object", b"same bytes").unwrap();
    let target = root.clone();
    files_faults::once("object", move || {
        fs::rename(target.join("object"), target.join("retained-original")).unwrap();
        private_file(&target.join("object"), b"same bytes");
    });
    assert!(files.read("object", 64).is_err());
    assert_eq!(
        fs::read(root.join("retained-original")).unwrap(),
        b"same bytes"
    );
    assert_eq!(fs::read(root.join("object")).unwrap(), b"same bytes");
}

#[test]
fn in_place_rewrite_and_private_mode_drift_are_rejected_after_the_read() {
    for mode_only in [false, true] {
        let (_temp, root, files) = fixture();
        files.write("object", b"original").unwrap();
        let path = root.join("object");
        files_faults::once("object", move || {
            if mode_only {
                fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
            } else {
                let mut file = OpenOptions::new().write(true).open(&path).unwrap();
                file.write_all(b"replaced").unwrap();
                file.sync_all().unwrap();
            }
        });
        assert!(files.read("object", 64).is_err());
    }
}

#[test]
fn held_directory_and_lock_replacement_prevent_read_and_write() {
    for replace_root in [false, true] {
        let (temp, root, files) = fixture();
        files.write("object", b"original").unwrap();
        if replace_root {
            fs::rename(&root, temp.path().join("retained-root")).unwrap();
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
        } else {
            fs::rename(root.join("owner.lock"), root.join("retained-lock")).unwrap();
            private_file(&root.join("owner.lock"), b"");
        }
        assert!(files.read("object", 64).is_err());
        assert!(files.write("object", b"replacement").is_err());
        let old = if replace_root {
            temp.path().join("retained-root/object")
        } else {
            root.join("object")
        };
        assert_eq!(fs::read(old).unwrap(), b"original");
    }
}
