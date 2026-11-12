//! Public-API regressions: these also compile against the unpatched adapter.

use std::{
    fs,
    os::unix::{fs::MetadataExt, fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
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
    wait_status_reaped: bool,
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
        Self {
            child,
            stderr_path,
            wait_status_reaped: false,
        }
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_else(|error| error.to_string())
    }

    fn stop(&mut self) -> StoppedDaemon<'_> {
        let mut stopped = StoppedDaemon {
            daemon: self,
            resume_on_drop: true,
        };
        stopped.assert_alive();
        let pid = libc::pid_t::try_from(stopped.daemon.child.id()).unwrap();
        // Signal only this test's unreaped child. The guard resumes it on panic.
        assert_eq!(
            // SAFETY: this positive PID belongs to the retained, unreaped child.
            unsafe { libc::kill(pid, libc::SIGSTOP) },
            0,
            "cannot stop checkpoint daemon: {}",
            std::io::Error::last_os_error()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                Instant::now() < deadline,
                "checkpoint daemon did not acknowledge SIGSTOP"
            );
            let mut status = 0;
            // SAFETY: the child PID is retained and status is a writable integer.
            let observed =
                unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
            if observed == pid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    // waitpid consumed an exit status: neither Drop may signal
                    // this PID after it becomes available for reuse.
                    stopped.daemon.wait_status_reaped = true;
                    panic!(
                        "checkpoint daemon exited before stopping: {}",
                        stopped.daemon.stderr()
                    );
                }
                assert!(libc::WIFSTOPPED(status));
                assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
                return stopped;
            }
            if observed == -1 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ECHILD) {
                    stopped.daemon.wait_status_reaped = true;
                }
                panic!("cannot observe stopped checkpoint daemon: {error}");
            }
            assert_eq!(observed, 0);
            thread::sleep(Duration::from_millis(10));
        }
    }
}

struct StoppedDaemon<'a> {
    daemon: &'a mut Daemon,
    resume_on_drop: bool,
}

impl StoppedDaemon<'_> {
    fn assert_alive(&mut self) {
        assert!(
            !self.daemon.wait_status_reaped && self.daemon.child.try_wait().unwrap().is_none(),
            "stopped checkpoint daemon exited: {}",
            self.daemon.stderr()
        );
    }

    fn resume_child(&mut self) -> std::io::Result<()> {
        if self.daemon.wait_status_reaped || self.daemon.child.try_wait()?.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "checkpoint daemon exited before SIGCONT",
            ));
        }
        let pid = libc::pid_t::try_from(self.daemon.child.id()).unwrap();
        // SAFETY: try_wait confirmed the retained child is not reaped or exited.
        if unsafe { libc::kill(pid, libc::SIGCONT) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn resume(mut self) {
        self.resume_child().unwrap();
        self.resume_on_drop = false;
    }
}

impl Drop for StoppedDaemon<'_> {
    fn drop(&mut self) {
        if self.resume_on_drop {
            // Drop must not panic. Daemon::drop subsequently kills and waits
            // for this same child even if an assertion unwinds while stopped.
            let _ = self.resume_child();
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if !self.wait_status_reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
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
    let mut stopped = first.stop();
    let (lease, displaced, record) = replace_lease_with_copy(directory.path());

    // A liveness probe queues a connection and can wake the first daemon.
    // A confirmed stop retains its listener and locked inode while preventing
    // that queued connection from fencing it before the lease is restored.
    stopped.assert_alive();
    let mut second = Daemon::spawn(binary, &socket, &directory.path().join("second.log"));
    assert_copied_lease_refusal(&mut second, &socket, original);
    stopped.assert_alive();
    assert_eq!(fs::read(&lease).unwrap(), record);
    // Restore the original lease before asking the first owner to revalidate;
    // this verifies that the refusal did not require killing the first owner.
    fs::remove_file(&lease).unwrap();
    fs::rename(&displaced, &lease).unwrap();
    stopped.resume();
    assert!(first.child.try_wait().unwrap().is_none());
    client.journal_checkpoint_v1().unwrap();
}

fn replace_lease_with_copy(directory: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let lease = directory.join(".owner.sock.socket-owner-v1");
    let displaced = directory.join("retained-lease");
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
    fs::File::open(directory).unwrap().sync_all().unwrap();
    assert_ne!(fs::symlink_metadata(&lease).unwrap().ino(), original_lease);
    assert_eq!(fs::read(&lease).unwrap(), record);
    (lease, displaced, record)
}

fn assert_copied_lease_refusal(second: &mut Daemon, socket: &Path, original: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert_eq!(
            fs::symlink_metadata(socket).unwrap().ino(),
            original,
            "a copied lease record authorized removal of a live listener"
        );
        if let Some(status) = second.child.try_wait().unwrap() {
            assert!(!status.success(), "second owner unexpectedly succeeded");
            let stderr = second.stderr();
            assert!(
                stderr.contains("lock checkpoint socket owner")
                    && stderr.contains("checkpoint socket listener is still live"),
                "copied record was not rejected by the live-listener probe: {stderr}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second owner did not fail closed"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn copied_lease_probe_fences_owner_before_lease_restoration() {
    let directory = private_directory();
    let socket = directory.path().join("owner.sock");
    let log = directory.path().join("first.log");
    let binary = env!("CARGO_BIN_EXE_trnm-external-node-checkpoint-v2");
    let mut first = Daemon::spawn(binary, &socket, &log);
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
    let journal_before = fs::read(&log).unwrap();
    let mut stopped = first.stop();
    let (lease, displaced, record) = replace_lease_with_copy(directory.path());
    let mut second = Daemon::spawn(binary, &socket, &directory.path().join("second.log"));
    assert_copied_lease_refusal(&mut second, &socket, original);
    stopped.assert_alive();
    assert_eq!(fs::read(&lease).unwrap(), record);

    // Deliver the queued probe while the copied lease is still installed.
    // The production identity guard must fence the original owner before it
    // can serve or advance the journal; no restored lease masks that result.
    stopped.resume();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = first.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "owner did not fence the copied lease after the probe"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success(), "owner accepted the copied lease");
    assert!(
        first
            .stderr()
            .contains("checkpoint endpoint pathname identity changed"),
        "owner did not reject the copied lease identity: {}",
        first.stderr()
    );
    assert_eq!(fs::read(&log).unwrap(), journal_before);
    assert_eq!(fs::symlink_metadata(&socket).unwrap().ino(), original);
    assert_eq!(fs::read(&lease).unwrap(), record);
    assert_eq!(fs::read(&displaced).unwrap(), record);
    assert!(client.journal_checkpoint_v1().is_err());
}
