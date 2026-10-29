//! Real Linux capability and process-death controls for the fixture module.
//! These execute the actual Rust watcher; they do not claim Node/systemd proof.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
const WAIT: Duration = Duration::from_secs(5);

struct ChildGuard(Child);
impl Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Directory {
    path: PathBuf,
    retained: bool,
}
impl Directory {
    fn new(case: &str) -> Self {
        let retained = std::env::var_os("TRNM_HISTORY_LIFELINE_EVIDENCE_DIR");
        let root = retained
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!(
            "history-lifeline-{case}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self {
            path,
            retained: retained.is_some(),
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if !self.retained && !std::thread::panicking() {
            fs::remove_dir_all(&self.path).unwrap();
        } else {
            eprintln!("retained History lifeline control: {}", self.path.display());
        }
    }
}

fn publish(directory: &Path, name: &str, content: &str) {
    let pending = directory.join(format!("{name}.pending"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&pending)
        .unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.sync_all().unwrap();
    fs::rename(pending, directory.join(name)).unwrap();
}

fn helper(directory: &Path, mode: &str, stdin: Stdio) -> ChildGuard {
    let selector = format!(
        "{}::helper_entry",
        module_path!().split_once("::").unwrap().1
    );
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(directory.join(format!("{mode}.log")))
        .unwrap();
    ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                selector.as_str(),
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_HISTORY_LIFELINE_TEST_MODE", mode)
            .env("TRNM_HISTORY_LIFELINE_TEST_DIRECTORY", directory)
            .stdin(stdin)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    )
}

fn wait_file(child: &mut ChildGuard, path: &Path) {
    let deadline = Instant::now() + WAIT;
    while !path.is_file() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "helper exited before {}",
            path.display()
        );
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded helper readiness: {}", path.display());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn wait_child(child: &mut ChildGuard) -> ExitStatus {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded actual helper exit");
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn child_stdin_socket() -> UnixStream {
    let descriptor = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    UnixStream::from(descriptor.try_clone_to_owned().unwrap())
}

#[test]
#[ignore = "actual process helper; only its parent test supplies private capabilities"]
fn helper_entry() {
    let mode = std::env::var("TRNM_HISTORY_LIFELINE_TEST_MODE").unwrap();
    let directory =
        PathBuf::from(std::env::var_os("TRNM_HISTORY_LIFELINE_TEST_DIRECTORY").unwrap());
    if mode == "controller" {
        // The test parent is only a launch broker: this controller constructs
        // its own pidfd and prequeues it, exactly as the real constructor does.
        let (controller, actor) = channel_pair().unwrap();
        let mut broker = child_stdin_socket();
        broker.set_read_timeout(Some(WAIT)).unwrap();
        send_owner(&broker, &actor).unwrap();
        let mut ack = [0_u8; 1];
        broker.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [1]);
        // Retain a duplicate controller endpoint outside this process. EOF
        // cannot explain the later death result; only its real pidfd can.
        let held: OwnedFd = controller._endpoint.try_clone().unwrap().into();
        send_owner(&broker, &held).unwrap();
        broker.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [2]);
        publish(&directory, "controller-ready", "prequeued-self-pidfd\n");
        loop {
            thread::park();
        }
    }
    let owner = super::super::arm_until_process_exit().unwrap();
    publish(
        &directory,
        "entered-scope",
        &format!(
            "{{\"peer_pid\":{},\"peer_uid\":{},\"peer_gid\":{}}}\n",
            owner.peer_pid, owner.peer_uid, owner.peer_gid,
        ),
    );
    if mode == "normal" {
        publish(
            &directory,
            "normal-return",
            "watcher remains armed until actual OS exit\n",
        );
        return;
    }
    assert_eq!(mode, "watch");
    let worker_directory = directory.clone();
    thread::spawn(move || {
        while !worker_directory.join("termination-trigger").is_file() {
            thread::sleep(Duration::from_millis(2));
        }
        thread::sleep(Duration::from_millis(250));
        publish(
            &worker_directory,
            "late-worker-side-effect",
            "unclosed thread\n",
        );
    });
    publish(
        &directory,
        "watch-ready",
        "ordinary helper and worker are alive\n",
    );
    loop {
        thread::park();
    }
}

fn brokered_controller(directory: &Directory) -> (ChildGuard, OwnedFd, OwnedFd) {
    let (mut broker, endpoint) = UnixStream::pair().unwrap();
    broker.set_read_timeout(Some(WAIT)).unwrap();
    let mut child = helper(
        &directory.path,
        "controller",
        Stdio::from(OwnedFd::from(endpoint)),
    );
    // receive_record is deliberately nonblocking for the real actor. Here the
    // finite test polls only until the controlled constructor queues its record.
    fn receive_bounded(socket: &UnixStream) -> OwnedFd {
        let deadline = Instant::now() + WAIT;
        loop {
            match receive_record(socket) {
                Ok(fd) => return fd,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("controlled broker receive: {error}"),
            }
        }
    }
    let actor = receive_bounded(&broker);
    broker.write_all(&[1]).unwrap();
    let retained = receive_bounded(&broker);
    broker.write_all(&[2]).unwrap();
    wait_file(&mut child, &directory.path.join("controller-ready"));
    (child, actor, retained)
}

#[test]
fn prequeued_capability_survives_exec_and_allows_normal_exit() {
    let directory = Directory::new("normal");
    let (_controller, stdin) = super::super::channel_for_current_process().unwrap();
    let mut actor = helper(&directory.path, "normal", stdin);
    let status = wait_child(&mut actor);
    assert!(status.success());
    let observation = fs::read_to_string(directory.path.join("entered-scope")).unwrap();
    assert!(observation.contains(&format!("\"peer_pid\":{}", std::process::id())));
    assert!(directory.path.join("normal-return").is_file());
}

#[test]
fn eof_terminates_helper_while_controller_process_is_still_alive() {
    let directory = Directory::new("eof");
    let (controller, stdin) = super::super::channel_for_current_process().unwrap();
    let mut actor = helper(&directory.path, "watch", stdin);
    wait_file(&mut actor, &directory.path.join("watch-ready"));
    drop(controller);
    publish(
        &directory.path,
        "termination-trigger",
        "controller endpoint actually closed\n",
    );
    assert_eq!(wait_child(&mut actor).code(), Some(EXIT_OWNER_LOST));
    assert!(!directory.path.join("late-worker-side-effect").exists());
}

#[test]
fn actual_owner_death_terminates_all_threads_despite_retained_stream_peer() {
    let directory = Directory::new("owner-death");
    let (mut controller, actor_stdin, retained_peer) = brokered_controller(&directory);
    let mut actor = helper(&directory.path, "watch", Stdio::from(actor_stdin));
    wait_file(&mut actor, &directory.path.join("watch-ready"));
    let observation = fs::read_to_string(directory.path.join("entered-scope")).unwrap();
    assert!(observation.contains(&format!("\"peer_pid\":{}", controller.id())));
    controller.kill().unwrap();
    publish(
        &directory.path,
        "termination-trigger",
        "owned controller actually SIGKILLed\n",
    );
    assert_eq!(wait_child(&mut controller).signal(), Some(libc::SIGKILL));
    assert_eq!(wait_child(&mut actor).code(), Some(EXIT_OWNER_LOST));
    // A valid retained controller endpoint proves the socket still had a peer.
    assert!(unsafe { libc::fcntl(retained_peer.as_raw_fd(), libc::F_GETFD) } >= 0);
    assert!(!directory.path.join("late-worker-side-effect").exists());
}

#[test]
fn already_dead_owner_is_refused_before_the_scope_starts() {
    let directory = Directory::new("already-dead");
    let (mut controller, actor_stdin, _retained_peer) = brokered_controller(&directory);
    controller.kill().unwrap();
    assert_eq!(wait_child(&mut controller).signal(), Some(libc::SIGKILL));
    let mut actor = helper(&directory.path, "watch", Stdio::from(actor_stdin));
    assert_eq!(wait_child(&mut actor).code(), Some(EXIT_OWNER_LOST));
    assert!(!directory.path.join("entered-scope").exists());
    assert!(!directory.path.join("late-worker-side-effect").exists());
}

#[test]
fn wrong_or_missing_kernel_descriptor_refuses_before_scope() {
    for mode in [
        "regular-file-right",
        "missing-right",
        "ordinary-stdin",
        "multiple-rights",
        "truncated-rights",
        "wrong-preface",
        "named-socket",
    ] {
        let directory = Directory::new(mode);
        let (mut controller, endpoint) = UnixStream::pair().unwrap();
        let mut named_namespace = None;
        let stdin = match mode {
            "regular-file-right" => {
                let wrong: OwnedFd = File::open("/dev/null").unwrap().into();
                send_owner(&controller, &wrong).unwrap();
                Stdio::from(OwnedFd::from(endpoint))
            }
            "missing-right" => {
                controller.write_all(&[PREFACE]).unwrap();
                Stdio::from(OwnedFd::from(endpoint))
            }
            "ordinary-stdin" => Stdio::from(File::open("/dev/null").unwrap()),
            "multiple-rights" | "truncated-rights" | "wrong-preface" => {
                let owner = own_pidfd().unwrap();
                let count = match mode {
                    "multiple-rights" => 2,
                    "truncated-rights" => 32,
                    "wrong-preface" => 1,
                    _ => unreachable!(),
                };
                let mut byte = [if mode == "wrong-preface" {
                    0x55
                } else {
                    PREFACE
                }];
                let mut vector = libc::iovec {
                    iov_base: byte.as_mut_ptr().cast(),
                    iov_len: 1,
                };
                let mut control = [0_usize; 32];
                let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
                message.msg_iov = &mut vector;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                // Deliberately provide more actual kernel rights than the
                // protocol permits; the large case exceeds its receive buffer.
                unsafe {
                    message.msg_controllen =
                        libc::CMSG_SPACE((count * size_of::<RawFd>()) as u32) as usize;
                    assert!(message.msg_controllen <= size_of_val(&control));
                    let header = libc::CMSG_FIRSTHDR(&message);
                    assert!(!header.is_null());
                    (*header).cmsg_level = libc::SOL_SOCKET;
                    (*header).cmsg_type = libc::SCM_RIGHTS;
                    (*header).cmsg_len =
                        libc::CMSG_LEN((count * size_of::<RawFd>()) as u32) as usize;
                    for index in 0..count {
                        libc::CMSG_DATA(header)
                            .cast::<RawFd>()
                            .add(index)
                            .write(owner.as_raw_fd());
                    }
                    assert_eq!(
                        libc::sendmsg(controller.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                        1
                    );
                }
                Stdio::from(OwnedFd::from(endpoint))
            }
            "named-socket" => {
                // UNIX pathname addresses have a short fixed kernel limit;
                // evidence paths may be much longer. Use an exclusive private
                // short directory, while retaining the actual child log above.
                let namespace = Directory {
                    path: std::env::temp_dir().join(format!(
                        "hl-{}-{}",
                        std::process::id(),
                        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
                    )),
                    retained: false,
                };
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&namespace.path)
                    .unwrap();
                let address = namespace.path.join("owner.sock");
                let listener = UnixListener::bind(&address).unwrap();
                let client = UnixStream::connect(&address).unwrap();
                let (server, _) = listener.accept().unwrap();
                let metadata = fs::symlink_metadata(&address).unwrap();
                publish(
                    &directory.path,
                    "actual-named-socket",
                    &format!(
                        "path={}\npath_bytes={}\nuid={}\nmode={}\ninode={}\n",
                        address.display(),
                        address.as_os_str().as_encoded_bytes().len(),
                        metadata.uid(),
                        metadata.mode(),
                        metadata.ino(),
                    ),
                );
                let owner = own_pidfd().unwrap();
                send_owner(&server, &owner).unwrap();
                // Keep the named peer live; refusal must be the unsupported
                // pathname transport, not an already-disconnected endpoint.
                controller = server;
                named_namespace = Some(namespace);
                Stdio::from(OwnedFd::from(client))
            }
            _ => unreachable!(),
        };
        let mut actor = helper(&directory.path, "watch", stdin);
        assert!(!wait_child(&mut actor).success(), "{mode}");
        assert!(!directory.path.join("entered-scope").exists(), "{mode}");
        assert!(unsafe { libc::fcntl(controller.as_raw_fd(), libc::F_GETFD) } >= 0);
        drop(named_namespace);
    }
}

#[test]
fn unexpected_data_after_arming_cannot_keep_the_helper_running() {
    let directory = Directory::new("unexpected-data");
    let (mut controller, stdin) = super::super::channel_for_current_process().unwrap();
    let mut actor = helper(&directory.path, "watch", stdin);
    wait_file(&mut actor, &directory.path.join("watch-ready"));
    controller._endpoint.write_all(&[0xff]).unwrap();
    publish(
        &directory.path,
        "termination-trigger",
        "unexpected protocol actually sent\n",
    );
    assert_eq!(wait_child(&mut actor).code(), Some(EXIT_OWNER_LOST));
    assert!(!directory.path.join("late-worker-side-effect").exists());
}
