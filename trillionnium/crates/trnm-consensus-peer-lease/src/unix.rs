#![cfg(unix)]

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::FileTypeExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::protocol::{
    decode_request, decode_response, encode_request, encode_response, LeaseOperationV1,
    LeaseRejectCodeV1, LeaseRequestV1, LeaseResponseV1, PeerLeaseScopeV1, PeerLeaseTokenV1,
    MAX_FRAME_BYTES_V1,
};
use crate::store::{now_ms, PeerLeaseStoreV1};
use crate::PeerLeaseErrorV1;

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
        let metadata = fs::symlink_metadata(&self.socket_path)?;
        if !metadata.file_type().is_socket() {
            return Err(PeerLeaseErrorV1::InvalidRequest(
                "peer-lease path is not a Unix socket",
            ));
        }
        Ok(())
    }

    fn call(&self, request: LeaseRequestV1) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        // UnixStream::connect has no stable standard-library deadline API.
        // Start the operation deadline before connecting so a slow connect
        // cannot grant a fresh full I/O budget after it eventually returns;
        // the connect syscall itself remains an explicit platform limitation.
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        let mut stream = UnixStream::connect(&self.socket_path)?;
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

impl UnixPeerLeaseDaemonV1 {
    pub fn new(socket_path: impl AsRef<Path>, journal_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            journal_path: journal_path.as_ref().to_path_buf(),
        }
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
        let mut store = PeerLeaseStoreV1::open(&self.journal_path)?;
        if self.socket_path.exists() {
            let metadata = fs::symlink_metadata(&self.socket_path)?;
            if !metadata.file_type().is_socket() {
                return Err(PeerLeaseErrorV1::InvalidRequest(
                    "peer-lease socket path is not a socket",
                ));
            }
            fs::remove_file(&self.socket_path)?;
        }
        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&self.socket_path)?;
        set_socket_permissions(&self.socket_path)?;
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    if let Err(error) = serve_connection(&mut stream, &mut store) {
                        // A malformed request is isolated to its connection;
                        // authority/journal errors are returned and terminate
                        // the daemon rather than continuing unsafely.
                        match error {
                            PeerLeaseErrorV1::Rejected(
                                LeaseRejectCodeV1::ClockRollback
                                | LeaseRejectCodeV1::AuthorityCorrupt,
                            )
                            | PeerLeaseErrorV1::Io(_) => return Err(error),
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

fn serve_connection(
    stream: &mut UnixStream,
    store: &mut PeerLeaseStoreV1,
) -> Result<(), PeerLeaseErrorV1> {
    let frame = read_frame(stream)?;
    let request = decode_request(&frame)?;
    let now = now_ms()?;
    let result = store.apply(request, now);
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
    stream.write_all(&encode_response(response))?;
    stream.flush()?;
    if let Some(error) = fatal_error {
        return Err(match error {
            PeerLeaseErrorV1::Rejected(code) => PeerLeaseErrorV1::Rejected(*code),
            _ => unreachable!("fatal peer lease error classification"),
        });
    }
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, PeerLeaseErrorV1> {
    read_frame_inner(stream, None)
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
        let socket = directory.path().join("authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
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
}
