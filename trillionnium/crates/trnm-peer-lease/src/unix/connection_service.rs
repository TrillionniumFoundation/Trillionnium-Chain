//! Bounded socket scheduling around the one existing durable journal writer.
use super::*;
use rustix::event::{poll, PollFd, PollFlags, Timespec};

const MAX_CONNECTIONS: usize = 64;
const IO_STEPS_PER_TURN: usize = 16;

struct Connection {
    stream: UnixStream,
    deadline: Instant,
    frame: Vec<u8>,
    offset: usize,
    responding: bool,
}

impl Connection {
    fn accept(stream: UnixStream, timeout: Duration) -> Result<Self, LeaseConnectionFailureV1> {
        use LeaseConnectionFailureV1::Authority;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        #[cfg(target_os = "linux")]
        authorize_peer(&stream).map_err(|error| match error {
            PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::UnauthorizedPeer) => {
                LeaseConnectionFailureV1::Connection(error)
            }
            _ => Authority(error),
        })?;
        stream
            .set_nonblocking(true)
            .map_err(|error| Authority(error.into()))?;
        Ok(Self {
            stream,
            deadline,
            frame: vec![0; 8],
            offset: 0,
            responding: false,
        })
    }

    // A partial client owns no store or mutex while waiting for more bytes.
    fn advance(&mut self, store: &mut PeerLeaseStoreV1) -> Result<bool, LeaseConnectionFailureV1> {
        use LeaseConnectionFailureV1::{Authority, Connection as ClientFailure};
        for _ in 0..IO_STEPS_PER_TURN {
            remaining_timeout(self.deadline).map_err(ClientFailure)?;
            let result = if self.responding {
                self.stream.write(&self.frame[self.offset..])
            } else {
                self.stream.read(&mut self.frame[self.offset..])
            };
            match result {
                Ok(0) => {
                    return Err(ClientFailure(PeerLeaseErrorV1::Io(io::Error::new(
                        if self.responding {
                            io::ErrorKind::WriteZero
                        } else {
                            io::ErrorKind::UnexpectedEof
                        },
                        "peer-lease connection ended before frame completion",
                    ))))
                }
                Ok(count) => self.offset += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(ClientFailure(error.into())),
            }
            if self.offset != self.frame.len() {
                continue;
            }
            if self.responding {
                return Ok(true);
            }
            if self.frame.len() == 8 {
                if self.frame[..4] != *b"TPLS" {
                    return Err(ClientFailure(PeerLeaseErrorV1::Protocol(
                        "invalid peer-lease frame magic",
                    )));
                }
                let length = u32::from_le_bytes(self.frame[4..8].try_into().unwrap()) as usize;
                if length > MAX_FRAME_BYTES_V1 {
                    return Err(ClientFailure(PeerLeaseErrorV1::Protocol(
                        "peer-lease frame exceeds limit",
                    )));
                }
                if length != 0 {
                    self.frame.resize(8 + length, 0);
                    continue;
                }
            }
            let request = decode_request(&self.frame).map_err(ClientFailure)?;
            remaining_timeout(self.deadline).map_err(ClientFailure)?;
            let now = now_ms().map_err(Authority)?;
            remaining_timeout(self.deadline).map_err(ClientFailure)?;
            // Inspect authority failure before response deadline handling.
            self.frame = match response_for_result(store.apply(request, now)) {
                Ok(response) => encode_response(response),
                Err(error) => {
                    if Instant::now() < self.deadline {
                        if let PeerLeaseErrorV1::Rejected(code) = &error {
                            // Diagnostic only: never wait for a slow reader
                            // before fencing a failed authority.
                            let _ = self
                                .stream
                                .write(&encode_response(LeaseResponseV1::Rejected(*code)));
                        }
                    }
                    return Err(Authority(error));
                }
            };
            self.offset = 0;
            self.responding = true;
        }
        Ok(false)
    }
}

pub(super) fn serve(
    listener: &UnixListener,
    store: &mut PeerLeaseStoreV1,
    operation_timeout: Duration,
) -> Result<(), PeerLeaseErrorV1> {
    listener.set_nonblocking(true)?;
    let mut connections = Vec::<Connection>::new();
    loop {
        // Accept at most the remaining fixed capacity in one turn.
        for _ in connections.len()..MAX_CONNECTIONS {
            match listener.accept() {
                Ok((stream, _)) => match Connection::accept(stream, operation_timeout) {
                    Ok(connection) => connections.push(connection),
                    Err(LeaseConnectionFailureV1::Connection(error)) => drop(error),
                    Err(LeaseConnectionFailureV1::Authority(error)) => return Err(error),
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let mut index = 0;
        while index < connections.len() {
            match connections[index].advance(store) {
                Ok(false) => index += 1,
                Ok(true) => {
                    connections.remove(index);
                }
                Err(LeaseConnectionFailureV1::Connection(error)) => {
                    drop(error);
                    connections.remove(index);
                }
                Err(LeaseConnectionFailureV1::Authority(error)) => return Err(error),
            }
        }
        if connections.len() > 1 {
            connections.rotate_left(1);
        }
        let now = Instant::now();
        let wait = connections
            .iter()
            .map(|connection| connection.deadline.saturating_duration_since(now))
            .min()
            .unwrap_or(operation_timeout);
        if wait.is_zero() {
            continue;
        }
        let timeout = Timespec::try_from(wait).map_err(|error| {
            PeerLeaseErrorV1::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid lease daemon poll timeout: {error}"),
            ))
        })?;
        let mut descriptors = Vec::with_capacity(connections.len() + 1);
        if connections.len() < MAX_CONNECTIONS {
            descriptors.push(PollFd::new(listener, PollFlags::IN));
        }
        for connection in &connections {
            descriptors.push(PollFd::new(
                &connection.stream,
                if connection.responding {
                    PollFlags::OUT
                } else {
                    PollFlags::IN
                },
            ));
        }
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(PeerLeaseErrorV1::Io(error.into())),
        }
    }
}

pub(super) fn response_for_result(
    result: Result<PeerLeaseTokenV1, PeerLeaseErrorV1>,
) -> Result<LeaseResponseV1, PeerLeaseErrorV1> {
    match result {
        Ok(token) => Ok(LeaseResponseV1::Token(token)),
        Err(
            error @ PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::ClockRollback | LeaseRejectCodeV1::AuthorityCorrupt,
            ),
        ) => Err(error),
        Err(PeerLeaseErrorV1::Rejected(code)) => Ok(LeaseResponseV1::Rejected(code)),
        Err(PeerLeaseErrorV1::InvalidRequest(_)) => {
            Ok(LeaseResponseV1::Rejected(LeaseRejectCodeV1::InvalidRequest))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PeerLeaseDirectionV1;

    fn request() -> LeaseRequestV1 {
        LeaseRequestV1 {
            operation: LeaseOperationV1::Acquire,
            scope: PeerLeaseScopeV1::new(
                [1; 32],
                [2; 32],
                PeerLeaseDirectionV1::Outbound,
                8,
                [3; 32],
            )
            .unwrap(),
            session_id: [4; 32],
            generation: 1,
            expires_at_ms: 0,
            ttl_ms: 30_000,
            record_hash: [0; 32],
        }
    }

    fn fixture() -> (tempfile::TempDir, PeerLeaseStoreV1, Connection, UnixStream) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = PeerLeaseStoreV1::open(dir.path().join("lease.log")).unwrap();
        let (server, client) = UnixStream::pair().unwrap();
        (
            dir,
            store,
            Connection::accept(server, Duration::from_secs(2)).unwrap(),
            client,
        )
    }

    #[test]
    fn header_rejects_oversize_before_body_allocation_or_authority() {
        let (_dir, mut store, mut connection, mut client) = fixture();
        client.write_all(b"TPLS").unwrap();
        client
            .write_all(&((MAX_FRAME_BYTES_V1 + 1) as u32).to_le_bytes())
            .unwrap();
        assert!(matches!(
            connection.advance(&mut store),
            Err(LeaseConnectionFailureV1::Connection(
                PeerLeaseErrorV1::Protocol(_)
            ))
        ));
        assert_eq!(connection.frame.len(), 8);
        assert_eq!(store.last_hash(), [0; 32]);
    }

    #[test]
    fn fragmented_request_keeps_original_deadline_without_store_effects() {
        let (_dir, mut store, mut connection, mut client) = fixture();
        let frame = encode_request(request());
        let deadline = connection.deadline;
        client.write_all(&frame[..7]).unwrap();
        assert!(!connection.advance(&mut store).unwrap());
        assert_eq!(connection.deadline, deadline);
        client.write_all(&frame[7..10]).unwrap();
        assert!(!connection.advance(&mut store).unwrap());
        assert_eq!(connection.deadline, deadline);
        connection.deadline = Instant::now();
        client.write_all(&frame[10..]).unwrap();
        assert!(matches!(connection.advance(&mut store),
            Err(LeaseConnectionFailureV1::Connection(PeerLeaseErrorV1::Io(error)))
                if error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(store.last_hash(), [0; 32]);
    }

    #[test]
    fn actual_authority_failure_is_not_a_connection_failure() {
        let (dir, mut store, mut connection, mut client) = fixture();
        let anchor = dir.path().join(".lease.log.head-v1");
        fs::remove_file(&anchor).unwrap();
        fs::create_dir(&anchor).unwrap();
        client.write_all(&encode_request(request())).unwrap();
        assert!(matches!(
            connection.advance(&mut store),
            Err(LeaseConnectionFailureV1::Authority(_))
        ));
        assert!(matches!(
            store.apply(request(), now_ms().unwrap()),
            Err(PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::AuthorityCorrupt
            ))
        ));
    }
    #[test]
    fn zero_daemon_timeout_rejects_before_creating_authority_state() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("not-created");
        let error = UnixPeerLeaseDaemonV1::new(root.join("s.sock"), root.join("s.log"))
            .with_timeout(Duration::ZERO)
            .run()
            .unwrap_err();
        assert!(matches!(error, PeerLeaseErrorV1::InvalidRequest(_)));
        assert!(!root.exists());
    }
}
