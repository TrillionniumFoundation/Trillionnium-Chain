//! Candidate-only authenticated Unix owner for payload-replay recovery.
//!
//! The library owner is deliberately opened with a caller-selected target.
//! This module adds the missing process boundary without widening that
//! authority: a daemon opens exactly one owner, pins its payload/acknowledge
//! descriptors for the daemon lifetime, and serves only status, bounded
//! publication recovery, and an explicit caller-supplied Core acknowledgement
//! over a private Unix socket.  The target and namespace are startup inputs,
//! never request fields.
//!
//! The socket protocol authenticates the effective UID on Linux and relies on
//! a mode-0600 socket/private parent on other Unix systems.  It is a
//! candidate boundary only: there is no cryptographic MAC, host attestation,
//! HSM/KMS, whole-node anti-rollback root, or Core transaction atomicity.

use super::*;
use std::{
    os::unix::{
        ffi::OsStrExt,
        fs::FileTypeExt,
        net::{UnixListener, UnixStream},
    },
    path::Component,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Stable schema identifier for the process-bound owner protocol.
pub const PAYLOAD_REPLAY_RECOVERY_SOCKET_SCHEMA_V1: &str =
    "trnm.payload-replay-recovery-owner-socket.v1";

/// The socket owner is a candidate observation/recovery surface, not a
/// production authority.
pub const PAYLOAD_REPLAY_RECOVERY_SOCKET_CANDIDATE_V1: bool = true;

/// Production activation remains disabled.
pub const PAYLOAD_REPLAY_RECOVERY_SOCKET_PRODUCTION_ACTIVATION_V1: bool = false;

/// Transport failures caused by one accepted client are scoped to that
/// connection and never stop the listener.  Durable owner identity and
/// corruption failures retain their fail-closed policy below.
pub const PAYLOAD_REPLAY_RECOVERY_SOCKET_CLIENT_TRANSPORT_ERRORS_NON_FATAL_V1: bool = true;

/// The candidate listener intentionally serves one request at a time.  This
/// is the explicit concurrency bound retained while isolating client faults.
pub const PAYLOAD_REPLAY_RECOVERY_SOCKET_MAX_CONCURRENT_CONNECTIONS_V1: usize = 1;

#[cfg(unix)]
const SOCKET_PATH_MAX_BYTES_V1: usize = 103;
#[cfg(unix)]
const SOCKET_HEADER_BYTES_V1: usize = 12;
#[cfg(unix)]
const SOCKET_MAX_BODY_BYTES_V1: usize = 4096;
#[cfg(unix)]
const SOCKET_MAX_PROJECTION_BYTES_V1: usize = 512;
#[cfg(unix)]
const SOCKET_ACK_BODY_BYTES_V1: usize = 32 + 32 + 1 + 7;
#[cfg(unix)]
const SOCKET_ERROR_MAX_BYTES_V1: usize = 1024;
#[cfg(unix)]
const SOCKET_REQUEST_MAGIC_V1: [u8; 4] = *b"TRRQ";
#[cfg(unix)]
const SOCKET_RESPONSE_MAGIC_V1: [u8; 4] = *b"TRRS";
#[cfg(unix)]
const SOCKET_VERSION_V1: u8 = 1;
#[cfg(unix)]
const SOCKET_STATUS_KIND_V1: u8 = 1;
#[cfg(unix)]
const SOCKET_ACK_KIND_V1: u8 = 2;
#[cfg(unix)]
const SOCKET_ERROR_KIND_V1: u8 = 255;
#[cfg(unix)]
const SOCKET_STATUS_OPERATION_V1: u8 = 1;
#[cfg(unix)]
const SOCKET_RECOVER_OPERATION_V1: u8 = 2;
#[cfg(unix)]
const SOCKET_ACK_OPERATION_V1: u8 = 3;
#[cfg(unix)]
const SOCKET_DEFAULT_TIMEOUT_V1: Duration = Duration::from_secs(5);
#[cfg(unix)]
const SOCKET_IDENTITY_DOMAIN_V1: &[u8] = b"trnm.poco-g1.payload-recovery-owner-socket-identity.v1";
static SOCKET_NONCE_COUNTER_V1: AtomicU64 = AtomicU64::new(0);

/// A process-bound candidate recovery owner.  It owns one exact target for
/// its entire run; callers cannot switch WAL, namespace, or target through
/// the socket protocol.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct PayloadReplayRecoveryDaemonV1 {
    socket_path: PathBuf,
    payload_path: PathBuf,
    acknowledgement_root: PathBuf,
    namespace: PayloadReplayNamespaceV1,
    target: PayloadReplayRecoveryTargetV1,
    operation_timeout: Duration,
}

#[cfg(unix)]
impl PayloadReplayRecoveryDaemonV1 {
    pub fn new(
        socket_path: impl AsRef<Path>,
        payload_path: impl AsRef<Path>,
        acknowledgement_root: impl AsRef<Path>,
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
    ) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            payload_path: payload_path.as_ref().to_path_buf(),
            acknowledgement_root: acknowledgement_root.as_ref().to_path_buf(),
            namespace,
            target,
            operation_timeout: SOCKET_DEFAULT_TIMEOUT_V1,
        }
    }

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

    pub fn payload_path(&self) -> &Path {
        &self.payload_path
    }

    pub fn acknowledgement_root(&self) -> &Path {
        &self.acknowledgement_root
    }

    /// Open the exact owner, bind a private listener, and serve sequential
    /// one-request connections until the process is terminated or a durable
    /// authority condition becomes unsafe.  Existing socket paths are never
    /// removed implicitly; an operator must clean a stale endpoint after a
    /// hard kill, which prevents deleting another process's listener.
    pub fn run(&self) -> Result<(), PayloadReplayRecoveryErrorV1> {
        validate_socket_configuration(
            &self.socket_path,
            &self.payload_path,
            &self.acknowledgement_root,
        )?;
        self.target.validate()?;
        let mut owner = PayloadReplayRecoveryOwnerV1::open(
            &self.payload_path,
            &self.acknowledgement_root,
            self.namespace,
            self.target,
        )?;

        let parent = self
            .socket_path
            .parent()
            .ok_or(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery socket path has no parent",
            ))?
            .to_path_buf();
        let parent_file = File::open(&parent)?;
        let parent_identity = descriptor_identity(&parent_file)?;
        verify_bound_directory_identity(&parent, &parent_file, parent_identity)?;
        if fs::symlink_metadata(&self.socket_path).is_ok() {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery socket path already exists",
            ));
        }
        let listener = UnixListener::bind(&self.socket_path)?;
        set_recovery_socket_permissions(&self.socket_path)?;
        let socket_identity = socket_identity(&self.socket_path)?;
        verify_socket_identity(
            &self.socket_path,
            &parent,
            &parent_file,
            parent_identity,
            socket_identity,
        )?;
        let _cleanup = RecoverySocketCleanupGuardV1 {
            path: self.socket_path.clone(),
            identity: socket_identity,
        };
        let endpoint_identity = socket_endpoint_identity(&owner, socket_identity, daemon_nonce())?;

        for incoming in listener.incoming() {
            verify_socket_identity(
                &self.socket_path,
                &parent,
                &parent_file,
                parent_identity,
                socket_identity,
            )?;
            let mut stream = match incoming {
                Ok(stream) => stream,
                Err(error) => return Err(PayloadReplayRecoveryErrorV1::Io(error)),
            };
            let result = serve_recovery_connection(
                &mut stream,
                &mut owner,
                endpoint_identity,
                self.operation_timeout,
            );
            if let Err(error) = result {
                if let Some(fatal) = error.into_fatal_owner() {
                    return Err(fatal);
                }
                // Non-fatal owner responses (target conflicts and explicit
                // recovery-required states), as well as every client
                // transport error, are isolated to this stream.
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
/// Stateless client for the candidate owner socket.  A caller may pin the
/// first endpoint identity in durable operator state and reject a daemon
/// replacement on later calls.
#[derive(Debug, Clone)]
pub struct PayloadReplayRecoveryClientV1 {
    socket_path: PathBuf,
    timeout: Duration,
    expected_endpoint_identity: Option<[u8; 32]>,
}

#[cfg(unix)]
impl PayloadReplayRecoveryClientV1 {
    pub fn connect(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            timeout: SOCKET_DEFAULT_TIMEOUT_V1,
            expected_endpoint_identity: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_expected_endpoint_identity(mut self, identity: [u8; 32]) -> Self {
        self.expected_endpoint_identity = Some(identity);
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn expected_endpoint_identity(&self) -> Option<[u8; 32]> {
        self.expected_endpoint_identity
    }

    pub fn status(
        &self,
    ) -> Result<PayloadReplayRecoverySocketStatusV1, PayloadReplayRecoverySocketErrorV1> {
        match self.call(RecoverySocketRequestV1::Status)? {
            RecoverySocketResponseV1::Status {
                endpoint_identity,
                projection,
            } => Ok(PayloadReplayRecoverySocketStatusV1 {
                endpoint_identity,
                projection: *projection,
            }),
            RecoverySocketResponseV1::Ack { .. } => {
                Err(PayloadReplayRecoverySocketErrorV1::Protocol(
                    "recovery socket returned an acknowledgement for status",
                ))
            }
            RecoverySocketResponseV1::Error { code, message, .. } => {
                Err(PayloadReplayRecoverySocketErrorV1::Remote { code, message })
            }
        }
    }

    pub fn recover(
        &self,
    ) -> Result<PayloadReplayRecoverySocketStatusV1, PayloadReplayRecoverySocketErrorV1> {
        match self.call(RecoverySocketRequestV1::Recover)? {
            RecoverySocketResponseV1::Status {
                endpoint_identity,
                projection,
            } => Ok(PayloadReplayRecoverySocketStatusV1 {
                endpoint_identity,
                projection: *projection,
            }),
            RecoverySocketResponseV1::Ack { .. } => {
                Err(PayloadReplayRecoverySocketErrorV1::Protocol(
                    "recovery socket returned an acknowledgement for recover",
                ))
            }
            RecoverySocketResponseV1::Error { code, message, .. } => {
                Err(PayloadReplayRecoverySocketErrorV1::Remote { code, message })
            }
        }
    }

    pub fn acknowledge(
        &self,
        core_safety_revision: u64,
        core_ack_digest: [u8; 32],
    ) -> Result<PayloadReplayRecoverySocketAckV1, PayloadReplayRecoverySocketErrorV1> {
        match self.call(RecoverySocketRequestV1::Acknowledge {
            core_safety_revision,
            core_ack_digest,
        })? {
            RecoverySocketResponseV1::Ack {
                endpoint_identity,
                receipt,
            } => Ok(PayloadReplayRecoverySocketAckV1 {
                endpoint_identity,
                receipt,
            }),
            RecoverySocketResponseV1::Status { .. } => {
                Err(PayloadReplayRecoverySocketErrorV1::Protocol(
                    "recovery socket returned status for acknowledgement",
                ))
            }
            RecoverySocketResponseV1::Error { code, message, .. } => {
                Err(PayloadReplayRecoverySocketErrorV1::Remote { code, message })
            }
        }
    }

    fn call(
        &self,
        request: RecoverySocketRequestV1,
    ) -> Result<RecoverySocketResponseV1, PayloadReplayRecoverySocketErrorV1> {
        validate_socket_path(&self.socket_path)
            .map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?;
        let parent =
            self.socket_path
                .parent()
                .ok_or(PayloadReplayRecoverySocketErrorV1::Protocol(
                    "recovery socket path has no parent",
                ))?;
        let parent_file = File::open(parent)?;
        let parent_identity = descriptor_identity(&parent_file)?;
        verify_bound_directory_identity(parent, &parent_file, parent_identity)
            .map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?;
        let metadata = fs::symlink_metadata(&self.socket_path)?;
        if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(PayloadReplayRecoverySocketErrorV1::Protocol(
                "recovery socket is not a private Unix socket",
            ));
        }
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        let mut stream = connect_recovery_socket(&self.socket_path, deadline)?;
        write_recovery_frame(&mut stream, &encode_recovery_request(request), deadline)?;
        let response = read_recovery_response(&mut stream, deadline)?;
        let endpoint_identity = response.endpoint_identity();
        if let Some(expected) = self.expected_endpoint_identity {
            if endpoint_identity != expected {
                return Err(PayloadReplayRecoverySocketErrorV1::EndpointIdentityChanged);
            }
        }
        Ok(response)
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayRecoverySocketStatusV1 {
    endpoint_identity: [u8; 32],
    projection: PayloadReplayRecoveryStatusProjectionV1,
}

#[cfg(unix)]
impl PayloadReplayRecoverySocketStatusV1 {
    pub const fn endpoint_identity(self) -> [u8; 32] {
        self.endpoint_identity
    }

    pub const fn projection(self) -> PayloadReplayRecoveryStatusProjectionV1 {
        self.projection
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayRecoverySocketAckV1 {
    endpoint_identity: [u8; 32],
    receipt: PayloadReplayCoreAckReceiptV1,
}

#[cfg(unix)]
impl PayloadReplayRecoverySocketAckV1 {
    pub const fn endpoint_identity(self) -> [u8; 32] {
        self.endpoint_identity
    }

    pub const fn receipt(self) -> PayloadReplayCoreAckReceiptV1 {
        self.receipt
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub enum PayloadReplayRecoverySocketErrorV1 {
    Recovery(PayloadReplayRecoveryErrorV1),
    Io(io::Error),
    Protocol(&'static str),
    Remote { code: u16, message: String },
    EndpointIdentityChanged,
}

#[cfg(unix)]
impl std::fmt::Display for PayloadReplayRecoverySocketErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recovery(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "recovery socket I/O error: {error}"),
            Self::Protocol(message) => formatter.write_str(message),
            Self::Remote { code, message } => {
                write!(
                    formatter,
                    "recovery owner rejected request ({code}): {message}"
                )
            }
            Self::EndpointIdentityChanged => {
                formatter.write_str("recovery owner endpoint identity changed")
            }
        }
    }
}

#[cfg(unix)]
impl std::error::Error for PayloadReplayRecoverySocketErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recovery(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(unix)]
impl From<io::Error> for PayloadReplayRecoverySocketErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(unix)]
impl From<PayloadReplayRecoveryErrorV1> for PayloadReplayRecoverySocketErrorV1 {
    fn from(error: PayloadReplayRecoveryErrorV1) -> Self {
        Self::Recovery(error)
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoverySocketRequestV1 {
    Status,
    Recover,
    Acknowledge {
        core_safety_revision: u64,
        core_ack_digest: [u8; 32],
    },
}

/// Error provenance for one accepted recovery-socket connection.  Keeping
/// transport/client failures separate from owner failures prevents a peer
/// that disconnects at an unlucky point from being mistaken for a durable
/// authority-integrity fault.
#[cfg(unix)]
#[derive(Debug)]
enum RecoverySocketConnectionErrorV1 {
    Client(PayloadReplayRecoveryErrorV1),
    Owner(PayloadReplayRecoveryErrorV1),
}

#[cfg(unix)]
impl RecoverySocketConnectionErrorV1 {
    fn into_fatal_owner(self) -> Option<PayloadReplayRecoveryErrorV1> {
        match self {
            Self::Owner(error) if is_fatal_recovery_socket_error(&error) => Some(error),
            Self::Client(error) | Self::Owner(error) => {
                // Read the payload even when the caller intentionally drops
                // this per-connection diagnostic; this keeps provenance
                // explicit without logging attacker-controlled text.
                let _ = error;
                None
            }
        }
    }
}

#[cfg(unix)]
fn classify_response_write_error(
    error: PayloadReplayRecoveryErrorV1,
) -> RecoverySocketConnectionErrorV1 {
    match error {
        // All I/O returned while writing a response is peer/transport scoped.
        // In particular, BrokenPipe/ConnectionReset/TimedOut must not stop
        // the owner after it has already completed (or rejected) one request.
        PayloadReplayRecoveryErrorV1::Io(_) => RecoverySocketConnectionErrorV1::Client(error),
        // A non-I/O response construction error (for example a projection
        // that exceeds its fixed wire bound) is an owner-side invariant.
        _ => RecoverySocketConnectionErrorV1::Owner(error),
    }
}

#[cfg(unix)]
#[derive(Debug)]
enum RecoverySocketResponseV1 {
    Status {
        endpoint_identity: [u8; 32],
        projection: Box<PayloadReplayRecoveryStatusProjectionV1>,
    },
    Ack {
        endpoint_identity: [u8; 32],
        receipt: PayloadReplayCoreAckReceiptV1,
    },
    Error {
        endpoint_identity: [u8; 32],
        code: u16,
        message: String,
    },
}

#[cfg(unix)]
impl RecoverySocketResponseV1 {
    fn endpoint_identity(&self) -> [u8; 32] {
        match self {
            Self::Status {
                endpoint_identity, ..
            }
            | Self::Ack {
                endpoint_identity, ..
            }
            | Self::Error {
                endpoint_identity, ..
            } => *endpoint_identity,
        }
    }
}

#[cfg(unix)]
fn validate_socket_configuration(
    socket_path: &Path,
    payload_path: &Path,
    acknowledgement_root: &Path,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    validate_socket_path(socket_path)?;
    if socket_path == payload_path
        || socket_path == sidecar_path(payload_path, "head-v1")?
        || socket_path == sidecar_path(payload_path, "lock-v1")?
        || socket_path == acknowledgement_root
        || socket_path.starts_with(acknowledgement_root)
    {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket path collides with an authority endpoint",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_socket_path(path: &Path) -> Result<(), PayloadReplayRecoveryErrorV1> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.as_os_str().as_bytes().contains(&0)
        || path.as_os_str().as_bytes().len() > SOCKET_PATH_MAX_BYTES_V1
    {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket path is not a narrow absolute path",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_recovery_socket_permissions(path: &Path) -> Result<(), PayloadReplayRecoveryErrorV1> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoverySocketIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
}

#[cfg(unix)]
fn socket_identity(path: &Path) -> Result<RecoverySocketIdentityV1, PayloadReplayRecoveryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket is not a private single-link socket",
        ));
    }
    Ok(RecoverySocketIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
    })
}

#[cfg(unix)]
fn verify_socket_identity(
    socket_path: &Path,
    parent: &Path,
    parent_file: &File,
    parent_identity: AuthorityPathIdentityV1,
    expected: RecoverySocketIdentityV1,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    verify_bound_directory_identity(parent, parent_file, parent_identity)?;
    let observed = socket_identity(socket_path)?;
    if observed != expected {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket identity changed",
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug)]
struct RecoverySocketCleanupGuardV1 {
    path: PathBuf,
    identity: RecoverySocketIdentityV1,
}

#[cfg(unix)]
impl Drop for RecoverySocketCleanupGuardV1 {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.identity.device
            && metadata.ino() == self.identity.inode
            && metadata.uid() == self.identity.uid
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == self.identity.nlink
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn socket_endpoint_identity(
    owner: &PayloadReplayRecoveryOwnerV1,
    socket: RecoverySocketIdentityV1,
    daemon_nonce: [u8; 32],
) -> Result<[u8; 32], PayloadReplayRecoveryErrorV1> {
    let owner_identity = owner.bound_endpoint_identity_digest()?;
    let mut hasher = Sha256::new();
    hasher.update(SOCKET_IDENTITY_DOMAIN_V1);
    hasher.update(daemon_nonce);
    hasher.update(owner_identity);
    hasher.update(socket.device.to_be_bytes());
    hasher.update(socket.inode.to_be_bytes());
    hasher.update(socket.uid.to_be_bytes());
    hasher.update(socket.mode.to_be_bytes());
    hasher.update(socket.nlink.to_be_bytes());
    Ok(hasher.finalize().into())
}

#[cfg(unix)]
fn daemon_nonce() -> [u8; 32] {
    // The nonce is an endpoint-lifecycle label only; it is never used as a
    // credential.  Prefer the kernel random source and retain a deterministic
    // fallback for restricted test containers.
    let mut nonce = [0u8; 32];
    if let Ok(mut random) = File::open("/dev/urandom") {
        if random.read_exact(&mut nonce).is_ok() {
            return nonce;
        }
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = SOCKET_NONCE_COUNTER_V1.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(SOCKET_IDENTITY_DOMAIN_V1);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(counter.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(target_os = "linux")]
fn authorize_recovery_peer(stream: &UnixStream) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let peer = rustix::net::sockopt::socket_peercred(stream)
        .map_err(|error| PayloadReplayRecoveryErrorV1::Io(error.into()))?;
    if peer.uid != rustix::process::geteuid() {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket peer credentials are unauthorized",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn authorize_recovery_peer(_stream: &UnixStream) -> Result<(), PayloadReplayRecoveryErrorV1> {
    Ok(())
}

#[cfg(unix)]
fn classify_peer_authorization_error(
    error: PayloadReplayRecoveryErrorV1,
) -> RecoverySocketConnectionErrorV1 {
    match error {
        // A successfully inspected but unauthorized UID is an untrusted
        // client and must not be able to stop the owner listener.
        error @ PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket peer credentials are unauthorized",
        ) => RecoverySocketConnectionErrorV1::Client(error),
        // Failure to obtain peer credentials is a local authentication
        // boundary failure, not a transport event from the client.  Keep the
        // fail-closed owner policy for this case.
        error => RecoverySocketConnectionErrorV1::Owner(error),
    }
}

#[cfg(unix)]
fn serve_recovery_connection(
    stream: &mut UnixStream,
    owner: &mut PayloadReplayRecoveryOwnerV1,
    endpoint_identity: [u8; 32],
    timeout: Duration,
) -> Result<(), RecoverySocketConnectionErrorV1> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    // A successfully authenticated-but-untrusted peer and all frame/stream
    // failures are properties of this accepted client stream.  A peer may
    // disconnect before sending anything, send a malformed/truncated frame,
    // or hold a partial frame until the deadline; none of those conditions
    // invalidate the already-open owner.  Failure of the local peer-credential
    // lookup remains owner-fatal and is classified separately above.
    authorize_recovery_peer(stream).map_err(classify_peer_authorization_error)?;
    let request =
        read_recovery_request(stream, deadline).map_err(RecoverySocketConnectionErrorV1::Client)?;
    let response = match request {
        RecoverySocketRequestV1::Status => {
            owner
                .status_projection()
                .map(|projection| RecoverySocketResponseV1::Status {
                    endpoint_identity,
                    projection: Box::new(projection),
                })
        }
        RecoverySocketRequestV1::Recover => owner
            .recover_payload_publication()
            .and_then(|_| owner.status_projection())
            .map(|projection| RecoverySocketResponseV1::Status {
                endpoint_identity,
                projection: Box::new(projection),
            }),
        RecoverySocketRequestV1::Acknowledge {
            core_safety_revision,
            core_ack_digest,
        } => {
            let acknowledgement = match PayloadReplayCoreAcknowledgementV1::new(
                owner.target(),
                core_safety_revision,
                core_ack_digest,
            ) {
                Ok(acknowledgement) => acknowledgement,
                Err(error) => {
                    // Revision/digest validation is driven entirely by
                    // this client's request.  Return a bounded rejection
                    // but keep it client-scoped rather than treating the
                    // invalid caller fact as owner corruption.
                    let encoded = RecoverySocketResponseV1::Error {
                        endpoint_identity,
                        code: recovery_error_code(&error),
                        message: bounded_error_message(&error),
                    };
                    return match write_recovery_response(stream, &encoded, deadline) {
                        Ok(()) => Err(RecoverySocketConnectionErrorV1::Client(error)),
                        Err(write_error) => Err(classify_response_write_error(write_error)),
                    };
                }
            };
            owner
                .acknowledge_core(acknowledgement)
                .map(|receipt| RecoverySocketResponseV1::Ack {
                    endpoint_identity,
                    receipt,
                })
        }
    };
    match response {
        Ok(response) => write_recovery_response(stream, &response, deadline)
            .map_err(classify_response_write_error),
        Err(error) => {
            // Preserve a fatal owner result even if the client closes before
            // receiving its error response.  Otherwise a response-write
            // BrokenPipe would hide an identity/corruption failure and let the
            // daemon continue serving unsafe state.
            let fatal_owner_error = is_fatal_recovery_socket_error(&error);
            let encoded = RecoverySocketResponseV1::Error {
                endpoint_identity,
                code: recovery_error_code(&error),
                message: bounded_error_message(&error),
            };
            match write_recovery_response(stream, &encoded, deadline) {
                Ok(()) => Err(RecoverySocketConnectionErrorV1::Owner(error)),
                Err(_write_error) if fatal_owner_error => {
                    // The durable owner error always wins over a client
                    // transport failure at this boundary.
                    Err(RecoverySocketConnectionErrorV1::Owner(error))
                }
                Err(write_error) => Err(classify_response_write_error(write_error)),
            }
        }
    }
}

#[cfg(unix)]
fn is_fatal_recovery_socket_error(error: &PayloadReplayRecoveryErrorV1) -> bool {
    match error {
        // This helper is called only for `Owner`-provenance errors.  Every
        // owner-side InvalidRequest therefore represents a startup/path/schema
        // invariant (request-shape InvalidRequest values are tagged Client
        // before reaching this function) and must fail closed.
        PayloadReplayRecoveryErrorV1::InvalidRequest(_) => true,
        PayloadReplayRecoveryErrorV1::PayloadRecordMismatch
        | PayloadReplayRecoveryErrorV1::RecoveryRequired
        | PayloadReplayRecoveryErrorV1::AckConflict => false,
        PayloadReplayRecoveryErrorV1::PayloadJournalBusy
        | PayloadReplayRecoveryErrorV1::AckLedgerBusy => false,
        _ => true,
    }
}

#[cfg(unix)]
fn recovery_error_code(error: &PayloadReplayRecoveryErrorV1) -> u16 {
    match error {
        PayloadReplayRecoveryErrorV1::InvalidRequest(_) => 1,
        PayloadReplayRecoveryErrorV1::Io(_) => 2,
        PayloadReplayRecoveryErrorV1::PayloadJournalMissing => 3,
        PayloadReplayRecoveryErrorV1::PayloadJournalBusy => 4,
        PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt => 5,
        PayloadReplayRecoveryErrorV1::PayloadRecordMismatch => 6,
        PayloadReplayRecoveryErrorV1::PayloadHeadDiverged => 7,
        PayloadReplayRecoveryErrorV1::AckLedgerBusy => 8,
        PayloadReplayRecoveryErrorV1::AckLedgerCorrupt => 9,
        PayloadReplayRecoveryErrorV1::AckConflict => 10,
        PayloadReplayRecoveryErrorV1::AckCommitAmbiguous(_) => 11,
        PayloadReplayRecoveryErrorV1::RecoveryRequired => 12,
    }
}

#[cfg(unix)]
fn bounded_error_message(error: &PayloadReplayRecoveryErrorV1) -> String {
    let message = error.to_string();
    if message.len() <= SOCKET_ERROR_MAX_BYTES_V1 {
        return message;
    }
    let mut end = SOCKET_ERROR_MAX_BYTES_V1;
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    message[..end].to_owned()
}

#[cfg(unix)]
fn encode_recovery_request(request: RecoverySocketRequestV1) -> Vec<u8> {
    let (operation, body): (u8, Vec<u8>) = match request {
        RecoverySocketRequestV1::Status => (SOCKET_STATUS_OPERATION_V1, Vec::new()),
        RecoverySocketRequestV1::Recover => (SOCKET_RECOVER_OPERATION_V1, Vec::new()),
        RecoverySocketRequestV1::Acknowledge {
            core_safety_revision,
            core_ack_digest,
        } => {
            let mut body = Vec::with_capacity(40);
            body.extend_from_slice(&core_safety_revision.to_be_bytes());
            body.extend_from_slice(&core_ack_digest);
            (SOCKET_ACK_OPERATION_V1, body)
        }
    };
    encode_socket_frame(SOCKET_REQUEST_MAGIC_V1, operation, &body)
}

#[cfg(unix)]
fn encode_socket_frame(magic: [u8; 4], kind: u8, body: &[u8]) -> Vec<u8> {
    debug_assert!(body.len() <= SOCKET_MAX_BODY_BYTES_V1);
    let mut frame = Vec::with_capacity(SOCKET_HEADER_BYTES_V1 + body.len());
    frame.extend_from_slice(&magic);
    frame.push(SOCKET_VERSION_V1);
    frame.push(kind);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

#[cfg(unix)]
fn read_recovery_request(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<RecoverySocketRequestV1, PayloadReplayRecoveryErrorV1> {
    let (kind, body) = read_socket_frame(stream, SOCKET_REQUEST_MAGIC_V1, deadline)?;
    let request = match kind {
        SOCKET_STATUS_OPERATION_V1 if body.is_empty() => RecoverySocketRequestV1::Status,
        SOCKET_RECOVER_OPERATION_V1 if body.is_empty() => RecoverySocketRequestV1::Recover,
        SOCKET_ACK_OPERATION_V1 if body.len() == 40 => RecoverySocketRequestV1::Acknowledge {
            core_safety_revision: u64::from_be_bytes(body[..8].try_into().expect("revision")),
            core_ack_digest: body[8..].try_into().expect("ack digest"),
        },
        _ => {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery socket request shape is invalid",
            ))
        }
    };
    Ok(request)
}

#[cfg(unix)]
fn write_recovery_response(
    stream: &mut UnixStream,
    response: &RecoverySocketResponseV1,
    deadline: Instant,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let (kind, body) = match response {
        RecoverySocketResponseV1::Status {
            endpoint_identity,
            projection,
        } => {
            let projection = projection.canonical_bytes();
            if projection.len() > SOCKET_MAX_PROJECTION_BYTES_V1 {
                return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                    "recovery status projection exceeds socket bound",
                ));
            }
            let mut body = Vec::with_capacity(32 + projection.len());
            body.extend_from_slice(endpoint_identity);
            body.extend_from_slice(&projection);
            (SOCKET_STATUS_KIND_V1, body)
        }
        RecoverySocketResponseV1::Ack {
            endpoint_identity,
            receipt,
        } => {
            let mut body = Vec::with_capacity(SOCKET_ACK_BODY_BYTES_V1);
            body.extend_from_slice(endpoint_identity);
            body.extend_from_slice(&receipt.acknowledgement_hash());
            body.push(u8::from(receipt.idempotent_replay()));
            body.extend_from_slice(&[0; 7]);
            (SOCKET_ACK_KIND_V1, body)
        }
        RecoverySocketResponseV1::Error {
            endpoint_identity,
            code,
            message,
        } => {
            let message = if message.len() > SOCKET_ERROR_MAX_BYTES_V1 {
                &message[..SOCKET_ERROR_MAX_BYTES_V1]
            } else {
                message.as_str()
            };
            let mut body = Vec::with_capacity(32 + 2 + message.len());
            body.extend_from_slice(endpoint_identity);
            body.extend_from_slice(&code.to_be_bytes());
            body.extend_from_slice(message.as_bytes());
            (SOCKET_ERROR_KIND_V1, body)
        }
    };
    write_recovery_frame(
        stream,
        &encode_socket_frame(SOCKET_RESPONSE_MAGIC_V1, kind, &body),
        deadline,
    )
}

#[cfg(unix)]
fn read_recovery_response(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<RecoverySocketResponseV1, PayloadReplayRecoverySocketErrorV1> {
    let (kind, body) = read_socket_frame(stream, SOCKET_RESPONSE_MAGIC_V1, deadline)
        .map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?;
    if body.len() < 32 {
        return Err(PayloadReplayRecoverySocketErrorV1::Protocol(
            "recovery socket response is truncated",
        ));
    }
    let endpoint_identity: [u8; 32] = body[..32].try_into().expect("endpoint identity");
    match kind {
        SOCKET_STATUS_KIND_V1 => {
            let projection =
                PayloadReplayRecoveryStatusProjectionV1::from_canonical_bytes(&body[32..])
                    .map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?;
            Ok(RecoverySocketResponseV1::Status {
                endpoint_identity,
                projection: Box::new(projection),
            })
        }
        SOCKET_ACK_KIND_V1 if body.len() == 32 + SOCKET_ACK_BODY_BYTES_V1 - 32 => {
            // The expression above documents the fixed layout: endpoint
            // identity (32), hash (32), idempotence (1), reserved (7).
            let acknowledgement_hash: [u8; 32] = body[32..64].try_into().expect("ack hash");
            if body[64] > 1 || body[65..].iter().any(|byte| *byte != 0) {
                return Err(PayloadReplayRecoverySocketErrorV1::Protocol(
                    "recovery socket acknowledgement padding is invalid",
                ));
            }
            Ok(RecoverySocketResponseV1::Ack {
                endpoint_identity,
                receipt: PayloadReplayCoreAckReceiptV1 {
                    acknowledgement_hash,
                    idempotent_replay: body[64] == 1,
                },
            })
        }
        SOCKET_ERROR_KIND_V1 if body.len() >= 34 => {
            let code = u16::from_be_bytes(body[32..34].try_into().expect("error code"));
            let message = String::from_utf8(body[34..].to_vec()).map_err(|_| {
                PayloadReplayRecoverySocketErrorV1::Protocol(
                    "recovery socket error message is not UTF-8",
                )
            })?;
            Err(PayloadReplayRecoverySocketErrorV1::Remote { code, message })
        }
        _ => Err(PayloadReplayRecoverySocketErrorV1::Protocol(
            "recovery socket response kind or length is invalid",
        )),
    }
}

#[cfg(unix)]
fn read_socket_frame(
    stream: &mut UnixStream,
    expected_magic: [u8; 4],
    deadline: Instant,
) -> Result<(u8, Vec<u8>), PayloadReplayRecoveryErrorV1> {
    let mut header = [0u8; SOCKET_HEADER_BYTES_V1];
    read_exact_until_recovery(stream, &mut header, deadline)?;
    if header[..4] != expected_magic || header[4] != SOCKET_VERSION_V1 || header[6..8] != [0, 0] {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket frame header is invalid",
        ));
    }
    let body_len = u32::from_be_bytes(header[8..12].try_into().expect("body length")) as usize;
    if body_len > SOCKET_MAX_BODY_BYTES_V1 {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery socket frame exceeds bound",
        ));
    }
    let mut body = vec![0u8; body_len];
    read_exact_until_recovery(stream, &mut body, deadline)?;
    Ok((header[5], body))
}

#[cfg(unix)]
fn write_recovery_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let mut offset = 0usize;
    while offset < frame.len() {
        stream.set_write_timeout(Some(remaining_recovery_timeout(deadline)?))?;
        match stream.write(&frame[offset..]) {
            Ok(0) => {
                return Err(PayloadReplayRecoveryErrorV1::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "recovery socket accepted no response bytes",
                )))
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(PayloadReplayRecoveryErrorV1::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recovery socket operation deadline exceeded",
                )))
            }
            Err(error) => return Err(PayloadReplayRecoveryErrorV1::Io(error)),
        }
    }
    stream.set_write_timeout(Some(remaining_recovery_timeout(deadline)?))?;
    stream.flush()?;
    Ok(())
}

#[cfg(unix)]
fn read_exact_until_recovery(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let mut offset = 0usize;
    while offset < buffer.len() {
        stream.set_read_timeout(Some(remaining_recovery_timeout(deadline)?))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(PayloadReplayRecoveryErrorV1::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "recovery socket closed before frame completed",
                )))
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(PayloadReplayRecoveryErrorV1::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recovery socket operation deadline exceeded",
                )))
            }
            Err(error) => return Err(PayloadReplayRecoveryErrorV1::Io(error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn remaining_recovery_timeout(deadline: Instant) -> Result<Duration, PayloadReplayRecoveryErrorV1> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(PayloadReplayRecoveryErrorV1::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "recovery socket operation deadline exceeded",
        )));
    }
    Ok(remaining)
}

#[cfg(unix)]
fn connect_recovery_socket(
    path: &Path,
    deadline: Instant,
) -> Result<UnixStream, PayloadReplayRecoverySocketErrorV1> {
    remaining_recovery_timeout(deadline).map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?;
    let address = rustix::net::SocketAddrUnix::new(path)
        .map_err(|error| PayloadReplayRecoverySocketErrorV1::Io(error.into()))?;
    let descriptor = new_recovery_socket().map_err(PayloadReplayRecoverySocketErrorV1::Io)?;
    let stream = UnixStream::from(descriptor);
    stream
        .set_nonblocking(true)
        .map_err(PayloadReplayRecoverySocketErrorV1::Io)?;
    loop {
        match rustix::net::connect(&stream, &address) {
            Ok(()) => break,
            Err(error) if error == rustix::io::Errno::INTR => {
                remaining_recovery_timeout(deadline)
                    .map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?;
            }
            Err(error)
                if error == rustix::io::Errno::INPROGRESS
                    || error == rustix::io::Errno::ALREADY
                    || error == rustix::io::Errno::AGAIN
                    || error == rustix::io::Errno::WOULDBLOCK =>
            {
                wait_for_recovery_connect(&stream, deadline)?;
                break;
            }
            Err(error) => return Err(PayloadReplayRecoverySocketErrorV1::Io(error.into())),
        }
    }
    remaining_recovery_timeout(deadline).map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?;
    stream
        .set_nonblocking(false)
        .map_err(PayloadReplayRecoverySocketErrorV1::Io)?;
    Ok(stream)
}

#[cfg(unix)]
fn new_recovery_socket() -> Result<std::os::fd::OwnedFd, io::Error> {
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    )))]
    {
        rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(Into::into)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    ))]
    {
        let descriptor = rustix::net::socket(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            None,
        )
        .map_err(io::Error::from)?;
        rustix::io::fcntl_setfd(&descriptor, rustix::io::FdFlags::CLOEXEC)
            .map_err(io::Error::from)?;
        Ok(descriptor)
    }
}

#[cfg(unix)]
fn wait_for_recovery_connect(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(), PayloadReplayRecoverySocketErrorV1> {
    loop {
        let timeout = rustix::event::Timespec::try_from(
            remaining_recovery_timeout(deadline)
                .map_err(PayloadReplayRecoverySocketErrorV1::Recovery)?,
        )
        .map_err(|error| {
            PayloadReplayRecoverySocketErrorV1::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid recovery socket timeout: {error}"),
            ))
        })?;
        let mut poll_fd = [rustix::event::PollFd::new(
            stream,
            rustix::event::PollFlags::OUT
                | rustix::event::PollFlags::ERR
                | rustix::event::PollFlags::HUP,
        )];
        match rustix::event::poll(&mut poll_fd, Some(&timeout)) {
            Ok(0) => {
                return Err(PayloadReplayRecoverySocketErrorV1::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recovery socket connect deadline exceeded",
                )))
            }
            Ok(_) => match rustix::net::sockopt::socket_error(stream) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => return Err(PayloadReplayRecoverySocketErrorV1::Io(error.into())),
                Err(error) => return Err(PayloadReplayRecoverySocketErrorV1::Io(error.into())),
            },
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(PayloadReplayRecoverySocketErrorV1::Io(error.into())),
        }
    }
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn request_shapes_are_fixed_and_ack_binds_exact_digest() {
        let request = encode_recovery_request(RecoverySocketRequestV1::Acknowledge {
            core_safety_revision: 9,
            core_ack_digest: [0xabu8; 32],
        });
        assert_eq!(request.len(), SOCKET_HEADER_BYTES_V1 + 40);
        assert_eq!(&request[..4], b"TRRQ");
        assert_eq!(request[5], SOCKET_ACK_OPERATION_V1);
        assert_eq!(u32::from_be_bytes(request[8..12].try_into().unwrap()), 40);
        assert_eq!(&request[12..20], &9_u64.to_be_bytes());
        assert_eq!(&request[20..], &[0xabu8; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_rejects_traversal_and_long_names() {
        assert!(validate_socket_path(Path::new("relative.sock")).is_err());
        assert!(validate_socket_path(Path::new("/tmp/../owner.sock")).is_err());
        assert!(validate_socket_path(Path::new("/tmp/.owner.sock")).is_ok());
        assert!(validate_socket_path(Path::new(&format!(
            "/tmp/{}",
            "x".repeat(SOCKET_PATH_MAX_BYTES_V1)
        )))
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn error_message_is_bounded_without_promoting_truth() {
        let error = PayloadReplayRecoveryErrorV1::InvalidRequest("candidate error");
        let message = bounded_error_message(&error);
        assert_eq!(message, "candidate error");
    }

    #[cfg(unix)]
    #[test]
    fn client_transport_errors_are_not_owner_fatal() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::WriteZero,
        ] {
            let error = PayloadReplayRecoveryErrorV1::Io(io::Error::new(kind, "client"));
            let classified = classify_response_write_error(error);
            assert!(matches!(
                classified,
                RecoverySocketConnectionErrorV1::Client(_)
            ));
        }

        // The same I/O shape returned by an owner operation remains fatal;
        // only the typed client provenance makes transport failures safe to
        // continue.
        let owner_io = PayloadReplayRecoveryErrorV1::Io(io::Error::other("owner storage"));
        assert!(is_fatal_recovery_socket_error(&owner_io));
        assert!(matches!(
            classify_peer_authorization_error(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "recovery socket peer credentials are unauthorized"
            )),
            RecoverySocketConnectionErrorV1::Client(_)
        ));
        assert!(matches!(
            classify_peer_authorization_error(PayloadReplayRecoveryErrorV1::Io(io::Error::other(
                "peer credential lookup"
            ))),
            RecoverySocketConnectionErrorV1::Owner(_)
        ));
        assert!(is_fatal_recovery_socket_error(
            &PayloadReplayRecoveryErrorV1::InvalidRequest("owner path invariant")
        ));
        assert!(is_fatal_recovery_socket_error(
            &PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt
        ));
    }

    #[cfg(unix)]
    #[test]
    fn truncated_and_slow_client_frames_are_tagged_client_scoped() {
        // EOF before a complete header is the exact regression that used to
        // bubble out of `serve_recovery_connection` as a daemon-fatal I/O
        // error.
        let (peer, mut server) = UnixStream::pair().expect("socket pair");
        drop(peer);
        let eof = read_recovery_request(&mut server, Instant::now() + Duration::from_millis(100))
            .map_err(RecoverySocketConnectionErrorV1::Client)
            .expect_err("EOF must reject this client");
        assert!(matches!(
            eof,
            RecoverySocketConnectionErrorV1::Client(
                PayloadReplayRecoveryErrorV1::Io(ref error)
            ) if error.kind() == io::ErrorKind::UnexpectedEof
        ));

        // A peer that dribbles only part of a header is bounded by the same
        // absolute deadline and is likewise isolated to its connection.
        let (mut peer, mut server) = UnixStream::pair().expect("socket pair");
        peer.write_all(b"TR").expect("partial header");
        let timeout =
            read_recovery_request(&mut server, Instant::now() + Duration::from_millis(50))
                .map_err(RecoverySocketConnectionErrorV1::Client)
                .expect_err("partial frame must time out");
        assert!(matches!(
            timeout,
            RecoverySocketConnectionErrorV1::Client(
                PayloadReplayRecoveryErrorV1::Io(ref error)
            ) if error.kind() == io::ErrorKind::TimedOut
        ));
    }
}
