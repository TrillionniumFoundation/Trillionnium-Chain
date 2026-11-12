//! Public-API regressions: these also compile against the unpatched adapter.

use std::{
    fs,
    os::unix::{fs::MetadataExt, fs::PermissionsExt, net::UnixListener},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use trnm_checkpoint_store::{ExternalCheckpointAuthorityV2, UnixExternalCheckpointStoreV2};

fn private_directory() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

struct Daemon {
    child: Child,
    stderr_path: std::path::PathBuf,
}

impl Daemon {
    fn spawn(binary: &str, socket: &std::path::Path, log: &std::path::Path) -> Self {
        let stderr_path = log.with_extension("stderr");
        let stderr = fs::File::create(&stderr_path).unwrap();
        let child = Command::new(binary)
            .arg("register-new")
            .arg(socket)
            .arg(log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        Self { child, stderr_path }
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_else(|error| error.to_string())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if thread::panicking() {
            eprintln!(
                "checkpoint daemon {}: {}",
                self.stderr_path.display(),
                self.stderr()
            );
        }
    }
}

#[test]
fn rejected_nonprivate_socket_parent_does_not_unlink_existing_listener() {
    let journal_directory = private_directory();
    let socket_directory = private_directory();
    let socket = socket_directory.path().join("existing.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let original = fs::symlink_metadata(&socket).unwrap().ino();
    fs::set_permissions(socket_directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let owner =
        ExternalCheckpointAuthorityV2::register_new(journal_directory.path().join("owner.log"))
            .unwrap();
    assert!(owner.serve_unix(&socket).is_err());
    assert_eq!(
        fs::symlink_metadata(&socket).unwrap().ino(),
        original,
        "rejecting configuration must preserve the existing listener"
    );
    drop(listener);
}

#[test]
fn different_admitted_journal_cannot_replace_a_live_checkpoint_endpoint() {
    let directory = private_directory();
    let socket = directory.path().join("owner.sock");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2");
    let mut first = Daemon::spawn(binary, &socket, &directory.path().join("first.log"));
    let client = UnixExternalCheckpointStoreV2::new(&socket)
        .unwrap()
        .with_timeout(Duration::from_millis(50));
    let deadline = Instant::now() + Duration::from_secs(5);
    while client.journal_checkpoint_v1().is_err() {
        assert!(
            first.child.try_wait().unwrap().is_none(),
            "first daemon exited: {}",
            first.stderr()
        );
        assert!(
            Instant::now() < deadline,
            "first daemon did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let original = fs::symlink_metadata(&socket).unwrap().ino();
    let mut second = Daemon::spawn(binary, &socket, &directory.path().join("second.log"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert_eq!(
            fs::symlink_metadata(&socket).unwrap().ino(),
            original,
            "a different journal displaced the live listener"
        );
        if let Some(status) = second.child.try_wait().unwrap() {
            assert!(!status.success(), "second owner unexpectedly succeeded");
            assert!(
                second.stderr().contains("lock checkpoint socket owner"),
                "second owner was not rejected by the endpoint lease: {}",
                second.stderr()
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second owner did not fail closed"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(first.child.try_wait().unwrap().is_none());
    client.journal_checkpoint_v1().unwrap();
}

#[test]
fn copied_lease_record_cannot_replace_a_live_checkpoint_endpoint() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let directory = private_directory();
    let socket = directory.path().join("owner.sock");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2");
    let mut first = Daemon::spawn(binary, &socket, &directory.path().join("first.log"));
    let client = UnixExternalCheckpointStoreV2::new(&socket)
        .unwrap()
        .with_timeout(Duration::from_millis(50));
    let deadline = Instant::now() + Duration::from_secs(5);
    while client.journal_checkpoint_v1().is_err() {
        assert!(
            first.child.try_wait().unwrap().is_none(),
            "{}",
            first.stderr()
        );
        assert!(
            Instant::now() < deadline,
            "first daemon did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let original = fs::symlink_metadata(&socket).unwrap().ino();
    let lease = directory.path().join(".owner.sock.socket-owner-v1");
    let displaced = directory.path().join("retained-lease");
    let record = fs::read(&lease).unwrap();
    assert_eq!(record.len(), 56);
    let original_lease = fs::symlink_metadata(&lease).unwrap().ino();
    fs::rename(&lease, &displaced).unwrap();
    let mut replacement = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lease)
        .unwrap();
    replacement.write_all(&record).unwrap();
    replacement.sync_all().unwrap();
    drop(replacement);
    fs::File::open(directory.path())
        .unwrap()
        .sync_all()
        .unwrap();
    assert_ne!(fs::symlink_metadata(&lease).unwrap().ino(), original_lease);
    assert_eq!(fs::read(&lease).unwrap(), record);

    // The first daemon is idle and still owns its original locked inode. Do
    // not wake it into fencing before the second daemon's admission attempt.
    assert!(first.child.try_wait().unwrap().is_none());
    let mut second = Daemon::spawn(binary, &socket, &directory.path().join("second.log"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert_eq!(
            fs::symlink_metadata(&socket).unwrap().ino(),
            original,
            "a copied lease record authorized removal of a live listener"
        );
        if let Some(status) = second.child.try_wait().unwrap() {
            assert!(!status.success(), "second owner unexpectedly succeeded");
            assert!(
                second.stderr().contains("lock checkpoint socket owner"),
                "copied record was not rejected by live ownership: {}",
                second.stderr()
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second owner did not fail closed"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(first.child.try_wait().unwrap().is_none());
    assert_eq!(fs::read(&lease).unwrap(), record);
    // Restore the original lease before asking the first owner to revalidate;
    // this verifies that the refusal did not require killing the first owner.
    fs::remove_file(&lease).unwrap();
    fs::rename(&displaced, &lease).unwrap();
    client.journal_checkpoint_v1().unwrap();
}
