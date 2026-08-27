#![cfg(unix)]

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use crate::protocol::{
    decode_request, decode_response, encode_request, encode_response, LeaseOperationV1,
    LeaseRejectCodeV1, LeaseRequestV1, LeaseResponseV1, PeerLeaseScopeV1, PeerLeaseTokenV1,
    MAX_FRAME_BYTES_V1,
};
use crate::store::{ensure_private_directory, now_ms, PeerLeaseStoreV1};
use crate::PeerLeaseErrorV1;

/// Wall-clock budget for socket I/O while servicing one accepted stream.  The
/// protocol permits only one request per connection, so keeping one absolute
/// deadline for frame read and response write prevents a client from
/// resetting a per-I/O timeout forever (a slowloris pattern).
const DEFAULT_DAEMON_OPERATION_TIMEOUT_V1: Duration = Duration::from_secs(5);
// Keep the public Unix seam within the smallest `sockaddr_un.sun_path` used
// by the supported Linux/macOS fleet.  The trailing NUL consumes one byte.
const UNIX_SOCKET_PATH_MAX_BYTES_V1: usize = 103;

/// Protocol-neutral authority interface consumed by a P2P adapter.  It has
/// no consensus-message or private-key operation; a caller must still bind a
/// returned token to its own transport worker/generation before sending data.
pub trait ExternalPeerLeaseAuthorityV1 {
    fn acquire(
        &self,
        scope: PeerLeaseScopeV1,
        session_id: [u8; 32],
        generation: u64,
        ttl_ms: u64,
    ) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1>;

    fn renew(
        &self,
        token: PeerLeaseTokenV1,
        ttl_ms: u64,
    ) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1>;

    fn revalidate(&self, token: PeerLeaseTokenV1) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1>;

    fn release(&self, token: PeerLeaseTokenV1) -> Result<(), PeerLeaseErrorV1>;
}

/// A stateless Unix-socket client.  Each operation uses a fresh connection;
/// a dead/restarted daemon therefore cannot leave a client holding a live
/// transport channel by accident.
#[derive(Debug, Clone)]
pub struct UnixPeerLeaseClientV1 {
    socket_path: PathBuf,
    timeout: Duration,
}

impl UnixPeerLeaseClientV1 {
    pub fn connect(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Check only the local socket boundary. This does not grant a lease or
    /// prove host attestation; callers should still acquire and revalidate a
    /// token before commissioning a transport worker.
    pub fn preflight(&self) -> Result<(), PeerLeaseErrorV1> {
        validate_unix_socket_path_v1(&self.socket_path)?;
        let parent = self
            .socket_path
            .parent()
            .ok_or(PeerLeaseErrorV1::InvalidRequest("peer-lease socket parent"))?;
        ensure_private_directory(parent)?;
        let metadata = fs::symlink_metadata(&self.socket_path)?;
        if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(PeerLeaseErrorV1::InvalidRequest(
                "peer-lease path is not a private Unix socket",
            ));
        }
        Ok(())
    }

    fn call(&self, request: LeaseRequestV1) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        // Start the absolute operation deadline before endpoint validation so
        // validation and connect cannot each consume a fresh independent
        // timeout budget.
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        // Validate the endpoint and its private parent before entering the
        // blocking connect syscall.  The constructor remains infallible for
        // API compatibility, so every operation performs this fail-closed
        // check immediately before connecting.
        self.preflight()?;
        let mut stream = connect_until(&self.socket_path, deadline)?;
        let frame = encode_request(request);
        write_all_until(&mut stream, &frame, deadline)?;
        let response_frame = read_frame_until(&mut stream, deadline)?;
        match decode_response(&response_frame)? {
            LeaseResponseV1::Token(token) => Ok(token),
            LeaseResponseV1::Rejected(code) => Err(PeerLeaseErrorV1::Rejected(code)),
        }
    }
}

impl ExternalPeerLeaseAuthorityV1 for UnixPeerLeaseClientV1 {
    fn acquire(
        &self,
        scope: PeerLeaseScopeV1,
        session_id: [u8; 32],
        generation: u64,
        ttl_ms: u64,
    ) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        self.call(LeaseRequestV1 {
            operation: LeaseOperationV1::Acquire,
            scope,
            session_id,
            generation,
            expires_at_ms: 0,
            ttl_ms,
            record_hash: [0; 32],
        })
    }

    fn renew(
        &self,
        token: PeerLeaseTokenV1,
        ttl_ms: u64,
    ) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        self.call(LeaseRequestV1 {
            operation: LeaseOperationV1::Renew,
            scope: token.scope(),
            session_id: token.session_id(),
            generation: token.generation(),
            expires_at_ms: token.expires_at_ms(),
            ttl_ms,
            record_hash: token.record_hash(),
        })
    }

    fn revalidate(&self, token: PeerLeaseTokenV1) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        self.call(LeaseRequestV1 {
            operation: LeaseOperationV1::Revalidate,
            scope: token.scope(),
            session_id: token.session_id(),
            generation: token.generation(),
            expires_at_ms: token.expires_at_ms(),
            ttl_ms: 0,
            record_hash: token.record_hash(),
        })
    }

    fn release(&self, token: PeerLeaseTokenV1) -> Result<(), PeerLeaseErrorV1> {
        self.call(LeaseRequestV1 {
            operation: LeaseOperationV1::Release,
            scope: token.scope(),
            session_id: token.session_id(),
            generation: token.generation(),
            expires_at_ms: token.expires_at_ms(),
            ttl_ms: 0,
            record_hash: token.record_hash(),
        })
        .map(|_| ())
    }
}

/// Blocking Unix authority daemon.  The daemon is intentionally a separate
/// process boundary: clients cannot mutate the journal or mint generations.
#[derive(Debug)]
pub struct UnixPeerLeaseDaemonV1 {
    socket_path: PathBuf,
    journal_path: PathBuf,
    operation_timeout: Duration,
}

/// Short aliases used by the lab adapter and command-line tooling.
pub type PeerLeaseClientV1 = UnixPeerLeaseClientV1;
pub type PeerLeaseAuthorityDaemonV1 = UnixPeerLeaseDaemonV1;

pub fn run_daemon(
    socket_path: impl AsRef<Path>,
    journal_path: impl AsRef<Path>,
) -> Result<(), PeerLeaseErrorV1> {
    UnixPeerLeaseDaemonV1::new(socket_path, journal_path).run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixSocketIdentityV1 {
    device: u64,
    inode: u64,
}

impl UnixSocketIdentityV1 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Pins the bound listener long enough to make error/unwind cleanup
/// identity-aware.  A pathname-only unlink could otherwise remove a socket
/// installed by another same-uid process after this daemon bound its own
/// inode.  This is still a candidate guard (openat/unlinkat would be needed
/// for a hostile non-cooperating namespace), but it closes the ordinary
/// stale-path and chmod-failure cuts.
struct UnixSocketCleanupGuardV1 {
    path: PathBuf,
    identity: Option<UnixSocketIdentityV1>,
    _listener: Option<UnixListener>,
}

impl UnixSocketCleanupGuardV1 {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            identity: None,
            _listener: None,
        }
    }

    fn arm(&mut self, listener: &UnixListener) -> Result<(), PeerLeaseErrorV1> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_socket() {
            return Err(PeerLeaseErrorV1::InvalidRequest(
                "bound peer-lease path is not a Unix socket",
            ));
        }
        self.identity = Some(UnixSocketIdentityV1::from_metadata(&metadata));
        self._listener = Some(listener.try_clone()?);
        Ok(())
    }

    fn verify(&self) -> Result<(), PeerLeaseErrorV1> {
        let expected = self.identity.ok_or(PeerLeaseErrorV1::InvalidRequest(
            "peer-lease socket cleanup guard is not armed",
        ))?;
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_socket()
            || UnixSocketIdentityV1::from_metadata(&metadata) != expected
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(PeerLeaseErrorV1::InvalidRequest(
                "peer-lease socket identity or permissions changed",
            ));
        }
        Ok(())
    }
}

impl Drop for UnixSocketCleanupGuardV1 {
    fn drop(&mut self) {
        let Some(expected) = self.identity else {
            return;
        };
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && UnixSocketIdentityV1::from_metadata(&metadata) == expected
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl UnixPeerLeaseDaemonV1 {
    pub fn new(socket_path: impl AsRef<Path>, journal_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            journal_path: journal_path.as_ref().to_path_buf(),
            operation_timeout: DEFAULT_DAEMON_OPERATION_TIMEOUT_V1,
        }
    }

    /// Set the absolute wall-clock budget for each accepted stream.  The
    /// budget starts before request-frame reads and also covers response
    /// writes; time spent applying the durable operation consumes the same
    /// budget before the response is emitted.  This is primarily useful for
    /// deployments with a tighter local failure budget and for deterministic
    /// tests; the default is five seconds.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    pub const fn timeout(&self) -> Duration {
        self.operation_timeout
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// Bind and serve until the process is terminated.  Existing socket paths
    /// are removed only after the journal has been opened and verified, so a
    /// tampered journal never gets hidden by socket cleanup.
    pub fn run(&self) -> Result<(), PeerLeaseErrorV1> {
        // Reject malformed/colliding paths before opening the durable lease
        // journal or creating a socket parent.  Otherwise a bad Unix path
        // could leave authority state behind even though bind never starts.
        validate_daemon_paths_v1(&self.socket_path, &self.journal_path)?;
        let mut store = PeerLeaseStoreV1::open(&self.journal_path)?;
        let socket_parent = self
            .socket_path
            .parent()
            .ok_or(PeerLeaseErrorV1::InvalidRequest("peer-lease socket parent"))?;
        fs::create_dir_all(socket_parent)?;
        ensure_private_directory(socket_parent)?;
        if self.socket_path.exists() {
            let metadata = fs::symlink_metadata(&self.socket_path)?;
            if !metadata.file_type().is_socket() {
                return Err(PeerLeaseErrorV1::InvalidRequest(
                    "peer-lease socket path is not a socket",
                ));
            }
            fs::remove_file(&self.socket_path)?;
        }
        let mut socket_cleanup = UnixSocketCleanupGuardV1::new(self.socket_path.clone());
        let listener = UnixListener::bind(&self.socket_path)?;
        socket_cleanup.arm(&listener)?;
        set_socket_permissions(&self.socket_path)?;
        socket_cleanup.verify()?;
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    if let Err(error) =
                        serve_connection(&mut stream, &mut store, self.operation_timeout)
                    {
                        // A malformed request is isolated to its connection;
                        // authority/journal errors are returned and terminate
                        // the daemon rather than continuing unsafely.
                        match error {
                            PeerLeaseErrorV1::Rejected(
                                LeaseRejectCodeV1::ClockRollback
                                | LeaseRejectCodeV1::AuthorityCorrupt,
                            ) => return Err(error),
                            PeerLeaseErrorV1::Io(ref io_error)
                                if matches!(
                                    io_error.kind(),
                                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                                ) =>
                            {
                                continue
                            }
                            PeerLeaseErrorV1::Io(_) => return Err(error),
                            PeerLeaseErrorV1::Rejected(_)
                            | PeerLeaseErrorV1::InvalidRequest(_)
                            | PeerLeaseErrorV1::Protocol(_) => continue,
                        }
                    }
                }
                Err(error) => return Err(PeerLeaseErrorV1::Io(error)),
            }
        }
        Ok(())
    }
}

fn validate_narrow_path_v1(path: &Path, label: &'static str) -> Result<(), PeerLeaseErrorV1> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.as_os_str().as_bytes().contains(&0)
    {
        return Err(PeerLeaseErrorV1::InvalidRequest(label));
    }
    Ok(())
}

fn validate_unix_socket_path_v1(path: &Path) -> Result<(), PeerLeaseErrorV1> {
    validate_narrow_path_v1(path, "peer-lease socket path is not a narrow absolute path")?;
    if path.as_os_str().as_bytes().len() > UNIX_SOCKET_PATH_MAX_BYTES_V1 {
        return Err(PeerLeaseErrorV1::InvalidRequest(
            "peer-lease socket path exceeds Unix sun_path limit",
        ));
    }
    Ok(())
}

fn validate_daemon_paths_v1(
    socket_path: &Path,
    journal_path: &Path,
) -> Result<(), PeerLeaseErrorV1> {
    validate_unix_socket_path_v1(socket_path)?;
    validate_narrow_path_v1(
        journal_path,
        "peer-lease journal path is not a narrow absolute path",
    )?;
    let journal_name = journal_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PeerLeaseErrorV1::InvalidRequest(
            "peer-lease journal path requires a UTF-8 filename",
        ))?;
    let lock_path = journal_path.with_extension("lease-lock");
    let anchor_path = journal_path.with_file_name(format!(".{journal_name}.head-v1"));
    if journal_path == lock_path
        || journal_path == anchor_path
        || lock_path == anchor_path
        || socket_path == journal_path
        || socket_path == lock_path
        || socket_path == anchor_path
    {
        return Err(PeerLeaseErrorV1::InvalidRequest(
            "peer-lease socket/journal paths collide",
        ));
    }
    Ok(())
}

fn serve_connection(
    stream: &mut UnixStream,
    store: &mut PeerLeaseStoreV1,
    operation_timeout: Duration,
) -> Result<(), PeerLeaseErrorV1> {
    let deadline = Instant::now()
        .checked_add(operation_timeout)
        .unwrap_or_else(Instant::now);
    // On Linux, filesystem permissions are only a pathname-level guard.  The
    // kernel-provided peer credential is checked on the already-accepted
    // descriptor before any request bytes can reach the durable store.
    #[cfg(target_os = "linux")]
    authorize_peer(stream)?;
    let frame = read_frame_until(stream, deadline)?;
    let request = decode_request(&frame)?;
    remaining_timeout(deadline)?;
    let now = now_ms()?;
    remaining_timeout(deadline)?;
    let result = store.apply(request, now);
    // Applying a request may include fsyncs which cannot be interrupted by
    // this deadline.  If they finish after the budget, do not emit a response
    // that the caller could mistake for a timely commit; the caller must use
    // its recovery/uncertainty path instead.
    remaining_timeout(deadline)?;
    let fatal_error = result.as_ref().err().and_then(|error| match error {
        PeerLeaseErrorV1::Rejected(
            LeaseRejectCodeV1::ClockRollback | LeaseRejectCodeV1::AuthorityCorrupt,
        ) => Some(error),
        _ => None,
    });
    let response = match result {
        Ok(token) => LeaseResponseV1::Token(token),
        Err(PeerLeaseErrorV1::Rejected(code)) => LeaseResponseV1::Rejected(code),
        Err(PeerLeaseErrorV1::InvalidRequest(_)) => {
            LeaseResponseV1::Rejected(crate::protocol::LeaseRejectCodeV1::InvalidRequest)
        }
        Err(error) => return Err(error),
    };
    write_all_until(stream, &encode_response(response), deadline)?;
    if let Some(error) = fatal_error {
        return Err(match error {
            PeerLeaseErrorV1::Rejected(code) => PeerLeaseErrorV1::Rejected(*code),
            _ => unreachable!("fatal peer lease error classification"),
        });
    }
    Ok(())
}

/// Establish a Unix stream without an unbounded blocking `connect(2)`.  The
/// descriptor starts nonblocking, and `poll` plus `SO_ERROR` turn completion
/// into one absolute wall-clock deadline shared with subsequent frame I/O.
fn connect_until(path: &Path, deadline: Instant) -> Result<UnixStream, PeerLeaseErrorV1> {
    // Check before allocating or entering any syscall.  This also makes an
    // already-expired caller budget fail closed when the local connect would
    // otherwise complete immediately.
    remaining_timeout(deadline)?;
    let address = rustix::net::SocketAddrUnix::new(path)
        .map_err(|error| PeerLeaseErrorV1::Io(error.into()))?;
    let descriptor = new_unix_socket()?;
    let stream = UnixStream::from(descriptor);
    stream.set_nonblocking(true)?;

    loop {
        match rustix::net::connect(&stream, &address) {
            Ok(()) => break,
            Err(error) if error == rustix::io::Errno::INTR => {
                remaining_timeout(deadline)?;
            }
            Err(error) if connect_pending(error) => {
                wait_for_connect(&stream, deadline)?;
                break;
            }
            Err(error) => return Err(PeerLeaseErrorV1::Io(error.into())),
        }
    }

    // A connect can report immediate success; enforce the same deadline in
    // that path before handing the descriptor to blocking frame I/O.
    remaining_timeout(deadline)?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
fn new_unix_socket() -> Result<rustix::fd::OwnedFd, PeerLeaseErrorV1> {
    rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|error| PeerLeaseErrorV1::Io(error.into()))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
fn new_unix_socket() -> Result<rustix::fd::OwnedFd, PeerLeaseErrorV1> {
    // Apple does not expose SOCK_CLOEXEC/SOCK_NONBLOCK in rustix's
    // SocketFlags.  Set close-on-exec with the safe fcntl wrapper, then use
    // UnixStream::set_nonblocking after taking ownership of the descriptor.
    let descriptor = rustix::net::socket(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        None,
    )
    .map_err(|error| PeerLeaseErrorV1::Io(error.into()))?;
    rustix::io::fcntl_setfd(&descriptor, rustix::io::FdFlags::CLOEXEC)
        .map_err(|error| PeerLeaseErrorV1::Io(error.into()))?;
    Ok(descriptor)
}

fn connect_pending(error: rustix::io::Errno) -> bool {
    error == rustix::io::Errno::INPROGRESS
        || error == rustix::io::Errno::ALREADY
        || error == rustix::io::Errno::AGAIN
        || error == rustix::io::Errno::WOULDBLOCK
}

fn wait_for_connect(stream: &UnixStream, deadline: Instant) -> Result<(), PeerLeaseErrorV1> {
    loop {
        let timeout =
            rustix::event::Timespec::try_from(remaining_timeout(deadline)?).map_err(|error| {
                PeerLeaseErrorV1::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid peer-lease connect timeout: {error}"),
                ))
            })?;
        let mut poll_fd = [rustix::event::PollFd::new(
            stream,
            rustix::event::PollFlags::OUT
                | rustix::event::PollFlags::ERR
                | rustix::event::PollFlags::HUP,
        )];
        match rustix::event::poll(&mut poll_fd, Some(&timeout)) {
            Ok(0) => return Err(operation_timeout_error()),
            Ok(_) => match rustix::net::sockopt::socket_error(stream) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => return Err(PeerLeaseErrorV1::Io(error.into())),
                Err(error) => return Err(PeerLeaseErrorV1::Io(error.into())),
            },
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(PeerLeaseErrorV1::Io(error.into())),
        }
    }
}

#[cfg(target_os = "linux")]
fn authorize_peer(stream: &UnixStream) -> Result<(), PeerLeaseErrorV1> {
    let peer = rustix::net::sockopt::socket_peercred(stream)
        .map_err(|error| PeerLeaseErrorV1::Io(error.into()))?;
    let expected_uid = rustix::process::geteuid();
    if !peer_uid_is_authorized(peer.uid, expected_uid) {
        return Err(PeerLeaseErrorV1::Rejected(
            LeaseRejectCodeV1::UnauthorizedPeer,
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn peer_uid_is_authorized(
    peer_uid: rustix::process::Uid,
    expected_uid: rustix::process::Uid,
) -> bool {
    peer_uid == expected_uid
}

fn read_frame_until(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, PeerLeaseErrorV1> {
    read_frame_inner(stream, Some(deadline))
}

fn read_frame_inner(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, PeerLeaseErrorV1> {
    let mut header = [0u8; 8];
    match deadline {
        Some(deadline) => read_exact_until(stream, &mut header, deadline)?,
        None => stream.read_exact(&mut header)?,
    }
    if header[..4] != *b"TPLS" {
        return Err(PeerLeaseErrorV1::Protocol("invalid peer-lease frame magic"));
    }
    let body_len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    if body_len > MAX_FRAME_BYTES_V1 {
        return Err(PeerLeaseErrorV1::Protocol("peer-lease frame exceeds limit"));
    }
    let mut frame = Vec::with_capacity(8 + body_len);
    frame.extend_from_slice(&header);
    frame.resize(8 + body_len, 0);
    match deadline {
        Some(deadline) => read_exact_until(stream, &mut frame[8..], deadline)?,
        None => stream.read_exact(&mut frame[8..])?,
    }
    Ok(frame)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), PeerLeaseErrorV1> {
    let mut offset = 0usize;
    while offset < buffer.len() {
        stream.set_read_timeout(Some(remaining_timeout(deadline)?))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(PeerLeaseErrorV1::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer-lease stream closed before frame completed",
                )))
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(operation_timeout_error())
            }
            Err(error) => return Err(PeerLeaseErrorV1::Io(error)),
        }
    }
    Ok(())
}

fn write_all_until(
    stream: &mut UnixStream,
    buffer: &[u8],
    deadline: Instant,
) -> Result<(), PeerLeaseErrorV1> {
    let mut offset = 0usize;
    while offset < buffer.len() {
        stream.set_write_timeout(Some(remaining_timeout(deadline)?))?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => {
                return Err(PeerLeaseErrorV1::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "peer-lease stream accepted no frame bytes",
                )))
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(operation_timeout_error())
            }
            Err(error) => return Err(PeerLeaseErrorV1::Io(error)),
        }
    }
    stream.set_write_timeout(Some(remaining_timeout(deadline)?))?;
    stream.flush()?;
    Ok(())
}

fn remaining_timeout(deadline: Instant) -> Result<Duration, PeerLeaseErrorV1> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(operation_timeout_error());
    }
    Ok(remaining)
}

fn operation_timeout_error() -> PeerLeaseErrorV1 {
    PeerLeaseErrorV1::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "peer-lease operation deadline exceeded",
    ))
}

fn set_socket_permissions(path: &Path) -> Result<(), PeerLeaseErrorV1> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{PeerLeaseDirectionV1, PeerLeaseScopeV1};
    use std::{os::unix::net::UnixListener, thread, time::Instant};

    fn test_scope() -> PeerLeaseScopeV1 {
        PeerLeaseScopeV1::new([1; 32], [2; 32], PeerLeaseDirectionV1::Outbound, 9, [3; 32]).unwrap()
    }

    #[test]
    fn client_request_shape_binds_direction_and_token_fields() {
        let scope =
            PeerLeaseScopeV1::new([1; 32], [2; 32], PeerLeaseDirectionV1::Inbound, 9, [3; 32])
                .unwrap();
        let token = PeerLeaseTokenV1::new(scope, [4; 32], 2, 123, [5; 32]);
        let request = LeaseRequestV1 {
            operation: LeaseOperationV1::Renew,
            scope: token.scope(),
            session_id: token.session_id(),
            generation: token.generation(),
            expires_at_ms: token.expires_at_ms(),
            ttl_ms: 10_000,
            record_hash: token.record_hash(),
        };
        let round_trip =
            crate::protocol::decode_request(&crate::protocol::encode_request(request)).unwrap();
        assert_eq!(round_trip.scope.direction(), PeerLeaseDirectionV1::Inbound);
        assert_eq!(round_trip.record_hash, [5; 32]);
    }

    #[test]
    fn client_deadline_covers_fragmented_response_as_one_operation() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let response = encode_response(LeaseResponseV1::Rejected(LeaseRejectCodeV1::Unsupported));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Consume the request before dribbling the response.  Keep the
            // header intact, then put each body byte 60ms apart: every gap is
            // below the old per-I/O timeout, while the complete operation
            // exceeds the configured deadline.
            let mut request = [0u8; MAX_FRAME_BYTES_V1];
            let _ = stream.read(&mut request);
            stream.write_all(&response[..8]).unwrap();
            for byte in &response[8..] {
                thread::sleep(Duration::from_millis(60));
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let client =
            UnixPeerLeaseClientV1::connect(&socket).with_timeout(Duration::from_millis(150));
        let started = Instant::now();
        let result = client.acquire(test_scope(), [6; 32], 1, 1_000);
        let elapsed = started.elapsed();
        assert!(matches!(
            result,
            Err(PeerLeaseErrorV1::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(
            elapsed < Duration::from_secs(1),
            "operation exceeded bounded deadline: {elapsed:?}"
        );
        server.join().unwrap();
    }

    #[test]
    fn daemon_deadline_covers_fragmented_request_as_one_operation() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("authority.sock");
        let journal = directory.path().join("authority.log");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut store = PeerLeaseStoreV1::open(&journal).unwrap();
            let started = Instant::now();
            let result = serve_connection(&mut stream, &mut store, Duration::from_millis(150));
            (result, started.elapsed())
        });

        let request = encode_request(LeaseRequestV1 {
            operation: LeaseOperationV1::Acquire,
            scope: test_scope(),
            session_id: [6; 32],
            generation: 1,
            expires_at_ms: 0,
            ttl_ms: 1_000,
            record_hash: [0; 32],
        });
        let mut client = UnixStream::connect(&socket).unwrap();
        client.write_all(&request[..8]).unwrap();
        // Keep each gap below the old per-read timeout while making the
        // complete frame exceed the absolute operation budget.
        for byte in request[8..].iter().take(3) {
            thread::sleep(Duration::from_millis(60));
            if client.write_all(std::slice::from_ref(byte)).is_err() {
                break;
            }
        }

        let (result, elapsed) = server.join().unwrap();
        assert!(matches!(
            result,
            Err(PeerLeaseErrorV1::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(
            elapsed < Duration::from_secs(1),
            "daemon spent too long servicing a stalled stream: {elapsed:?}"
        );
    }

    #[test]
    fn daemon_response_write_rejects_expired_operation_deadline() {
        let (mut stream, _peer) = UnixStream::pair().unwrap();
        let result = write_all_until(&mut stream, &[0u8; 1], Instant::now());
        assert!(matches!(
            result,
            Err(PeerLeaseErrorV1::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn client_connect_rejects_expired_deadline_before_syscall() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let result = connect_until(&socket, Instant::now());
        assert!(matches!(
            result,
            Err(PeerLeaseErrorV1::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
        drop(listener);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_authorization_matches_effective_uid_only() {
        let expected = rustix::process::geteuid();
        assert!(peer_uid_is_authorized(expected, expected));
        let other = if expected == rustix::process::Uid::ROOT {
            rustix::process::Uid::from_raw(1)
        } else {
            rustix::process::Uid::ROOT
        };
        assert!(!peer_uid_is_authorized(other, expected));
    }

    #[test]
    fn socket_cleanup_guard_does_not_remove_replacement_inode() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut guard = UnixSocketCleanupGuardV1::new(socket.clone());
        guard.arm(&listener).unwrap();

        // Unlink the original name while the listener (and guard clone) stays
        // open, then install a different socket at the same pathname.  Drop
        // cleanup must not remove the replacement inode.
        fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();
        drop(listener);
        drop(guard);
        assert!(socket.exists());
        drop(replacement);
        fs::remove_file(socket).unwrap();
    }

    #[test]
    fn socket_path_validation_rejects_traversal_length_and_sidecar_collisions() {
        assert!(validate_unix_socket_path_v1(Path::new("relative.sock")).is_err());
        assert!(validate_unix_socket_path_v1(Path::new("/tmp/peer/../authority.sock")).is_err());
        let long = PathBuf::from("/tmp").join("a".repeat(UNIX_SOCKET_PATH_MAX_BYTES_V1 + 1));
        assert!(matches!(
            validate_unix_socket_path_v1(&long),
            Err(PeerLeaseErrorV1::InvalidRequest(reason))
                if reason.contains("sun_path")
        ));

        let journal = PathBuf::from("/tmp/peer-lease-authority.journal");
        let socket = journal.with_extension("lease-lock");
        assert!(matches!(
            validate_daemon_paths_v1(&socket, &journal),
            Err(PeerLeaseErrorV1::InvalidRequest(reason))
                if reason.contains("collide")
        ));
        assert!(validate_daemon_paths_v1(&journal, &journal).is_err());
    }
}
