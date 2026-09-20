//! Candidate authenticated socket transport for the frozen P2P session.
//!
//! This adapter is intentionally small and host-owned.  It adds bounded
//! length-prefixed records, connection and read deadlines, and a callback
//! dispatch point around [`PocoNodeP2pSessionV0`].  The session verifier still
//! owns chain/profile/peer-key/signature/replay checks; when a caller supplies
//! [`PocoNodeP2pReplayAnchorV0`], the handshake and frame reservation are
//! fsynced before the callback is exposed.  No Core, lease, signer, proposal,
//! finality, or production activation is reachable from this module.

use std::{
    fmt, io,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

use trnm_consensus_types::{Cev0AdmissionBudgetV0, ConsensusParametersV0, ValidatorSet};

use crate::{
    PocoNodeP2pAcceptedFrameV0, PocoNodeP2pReplayAnchorV0, PocoNodeP2pSessionErrorV0,
    PocoNodeP2pSessionV0, P2P_SESSION_MAX_FRAME_BYTES_V0, P2P_SESSION_MAX_HANDSHAKE_BYTES_V0,
};

/// This adapter is available only through the explicitly named candidate
/// feature and does not imply that the node has a production listener.
pub const AUTHENTICATED_TRANSPORT_RUNTIME_COMPOSITION_V0: bool = true;
pub const AUTHENTICATED_TRANSPORT_PRODUCTION_ACTIVATION_V0: bool = false;

pub const AUTHENTICATED_TRANSPORT_MAX_CONNECTIONS_V0: usize = 16;
pub const AUTHENTICATED_TRANSPORT_HANDSHAKE_TIMEOUT_V0: Duration = Duration::from_secs(2);
pub const AUTHENTICATED_TRANSPORT_FRAME_TIMEOUT_V0: Duration = Duration::from_secs(5);
pub const AUTHENTICATED_TRANSPORT_MAX_RESPONSE_BYTES_V0: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum AuthenticatedTransportErrorV0 {
    Io(io::Error),
    InvalidConfiguration,
    RecordTooLarge { declared: usize, maximum: usize },
    EmptyRecord,
    Session(PocoNodeP2pSessionErrorV0),
    ResponseTooLarge { length: usize },
}

impl fmt::Display for AuthenticatedTransportErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "authenticated transport I/O failed: {error}"),
            Self::InvalidConfiguration => {
                f.write_str("authenticated transport configuration is invalid")
            }
            Self::RecordTooLarge { declared, maximum } => {
                write!(f, "transport record {declared} exceeds maximum {maximum}")
            }
            Self::EmptyRecord => f.write_str("authenticated transport record is empty"),
            Self::Session(error) => write!(f, "authenticated session rejected record: {error}"),
            Self::ResponseTooLarge { length } => {
                write!(f, "transport response {length} exceeds configured maximum")
            }
        }
    }
}

impl std::error::Error for AuthenticatedTransportErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Session(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AuthenticatedTransportErrorV0 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A synchronous, bounded listener.  The host controls when `accept_one` is
/// polled, so this type creates no thread and cannot enter a consensus actor
/// with unbounded concurrency.
pub struct CandidateAuthenticatedP2pTransportV0 {
    listener: TcpListener,
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    max_connections: usize,
    active_connections: usize,
}

impl CandidateAuthenticatedP2pTransportV0 {
    pub fn bind(
        address: std::net::SocketAddr,
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
    ) -> Result<Self, AuthenticatedTransportErrorV0> {
        let listener = TcpListener::bind(address)?;
        Self::from_listener(listener, validator_set, parameters)
    }

    pub fn from_listener(
        listener: TcpListener,
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
    ) -> Result<Self, AuthenticatedTransportErrorV0> {
        validator_set
            .validate_against_parameters(&parameters)
            .map_err(|_| AuthenticatedTransportErrorV0::InvalidConfiguration)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            validator_set,
            parameters,
            max_connections: AUTHENTICATED_TRANSPORT_MAX_CONNECTIONS_V0,
            active_connections: 0,
        })
    }

    #[must_use]
    pub const fn production_activation_v0(&self) -> bool {
        AUTHENTICATED_TRANSPORT_PRODUCTION_ACTIVATION_V0
    }

    #[must_use]
    pub const fn active_connections(&self) -> usize {
        self.active_connections
    }

    #[must_use]
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Return the bound address so a host-owned test or supervisor can
    /// publish the chosen ephemeral port. The listener remains owned by this
    /// adapter; callers receive no raw socket handle.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, AuthenticatedTransportErrorV0> {
        self.listener.local_addr().map_err(Into::into)
    }

    pub fn set_max_connections(
        &mut self,
        maximum: usize,
    ) -> Result<(), AuthenticatedTransportErrorV0> {
        if maximum == 0 || maximum > AUTHENTICATED_TRANSPORT_MAX_CONNECTIONS_V0 {
            return Err(AuthenticatedTransportErrorV0::InvalidConfiguration);
        }
        self.max_connections = maximum;
        Ok(())
    }

    /// Poll one connection. `WouldBlock` is returned unchanged when there is
    /// no client. The callback runs only after the complete frame passes the
    /// session verifier and optional durable replay reservation.
    pub fn accept_one<F>(
        &mut self,
        budget: &mut Cev0AdmissionBudgetV0,
        mut dispatch: F,
    ) -> Result<(), AuthenticatedTransportErrorV0>
    where
        F: FnMut(&PocoNodeP2pAcceptedFrameV0<'_>) -> Result<Vec<u8>, AuthenticatedTransportErrorV0>,
    {
        self.accept_one_inner(budget, None, &mut dispatch)
    }

    /// Same as [`Self::accept_one`], with a caller-owned fsynced replay anchor.
    /// The anchor must have been opened for the expected validator-set peer;
    /// mismatched peer/context is rejected before dispatch.
    pub fn accept_one_with_replay_anchor<F>(
        &mut self,
        budget: &mut Cev0AdmissionBudgetV0,
        replay_anchor: &mut PocoNodeP2pReplayAnchorV0,
        mut dispatch: F,
    ) -> Result<(), AuthenticatedTransportErrorV0>
    where
        F: FnMut(&PocoNodeP2pAcceptedFrameV0<'_>) -> Result<Vec<u8>, AuthenticatedTransportErrorV0>,
    {
        self.accept_one_inner(budget, Some(replay_anchor), &mut dispatch)
    }

    fn accept_one_inner<F>(
        &mut self,
        budget: &mut Cev0AdmissionBudgetV0,
        replay_anchor: Option<&mut PocoNodeP2pReplayAnchorV0>,
        dispatch: &mut F,
    ) -> Result<(), AuthenticatedTransportErrorV0>
    where
        F: FnMut(&PocoNodeP2pAcceptedFrameV0<'_>) -> Result<Vec<u8>, AuthenticatedTransportErrorV0>,
    {
        let (stream, _) = self.listener.accept()?;
        if self.active_connections >= self.max_connections {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "transport connection cap reached",
            )
            .into());
        }
        self.active_connections += 1;
        let result = Self::serve_stream(
            stream,
            &self.validator_set,
            &self.parameters,
            budget,
            replay_anchor,
            dispatch,
        );
        self.active_connections = self.active_connections.saturating_sub(1);
        result
    }

    pub fn serve_stream<F>(
        mut stream: TcpStream,
        validator_set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        budget: &mut Cev0AdmissionBudgetV0,
        mut replay_anchor: Option<&mut PocoNodeP2pReplayAnchorV0>,
        dispatch: &mut F,
    ) -> Result<(), AuthenticatedTransportErrorV0>
    where
        F: FnMut(&PocoNodeP2pAcceptedFrameV0<'_>) -> Result<Vec<u8>, AuthenticatedTransportErrorV0>,
    {
        stream.set_read_timeout(Some(AUTHENTICATED_TRANSPORT_HANDSHAKE_TIMEOUT_V0))?;
        let handshake = read_record(&mut stream, P2P_SESSION_MAX_HANDSHAKE_BYTES_V0)?;
        let mut session = match replay_anchor.as_deref_mut() {
            Some(anchor) => PocoNodeP2pSessionV0::open_with_replay_anchor(
                &handshake,
                validator_set,
                parameters,
                anchor,
            ),
            None => PocoNodeP2pSessionV0::open(&handshake, validator_set, parameters),
        }
        .map_err(AuthenticatedTransportErrorV0::Session)?;

        stream.set_read_timeout(Some(AUTHENTICATED_TRANSPORT_FRAME_TIMEOUT_V0))?;
        let frame = read_record(&mut stream, P2P_SESSION_MAX_FRAME_BYTES_V0)?;
        let accepted = match replay_anchor {
            Some(anchor) => session.accept_frame_with_replay_anchor(&frame, budget, anchor),
            None => session.accept_frame(&frame, budget),
        }
        .map_err(AuthenticatedTransportErrorV0::Session)?;
        let response = dispatch(&accepted)?;
        if response.is_empty() {
            return Err(AuthenticatedTransportErrorV0::EmptyRecord);
        }
        if response.len() > AUTHENTICATED_TRANSPORT_MAX_RESPONSE_BYTES_V0 {
            return Err(AuthenticatedTransportErrorV0::ResponseTooLarge {
                length: response.len(),
            });
        }
        write_record(&mut stream, &response)?;
        stream.flush()?;
        Ok(())
    }
}

fn read_record(
    stream: &mut TcpStream,
    maximum: usize,
) -> Result<Vec<u8>, AuthenticatedTransportErrorV0> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(AuthenticatedTransportErrorV0::EmptyRecord);
    }
    if length > maximum {
        return Err(AuthenticatedTransportErrorV0::RecordTooLarge {
            declared: length,
            maximum,
        });
    }
    let mut record = vec![0u8; length];
    stream.read_exact(&mut record)?;
    Ok(record)
}

fn write_record(
    stream: &mut TcpStream,
    record: &[u8],
) -> Result<(), AuthenticatedTransportErrorV0> {
    let length = u32::try_from(record.len()).map_err(|_| {
        AuthenticatedTransportErrorV0::ResponseTooLarge {
            length: record.len(),
        }
    })?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(record)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn length_prefix_is_bounded_before_allocation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&5u32.to_be_bytes()).unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        assert!(matches!(
            read_record(&mut stream, 4),
            Err(AuthenticatedTransportErrorV0::RecordTooLarge {
                declared: 5,
                maximum: 4
            })
        ));
        sender.join().unwrap();
    }

    #[test]
    fn zero_length_record_is_rejected_without_dispatch() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&0u32.to_be_bytes()).unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        assert!(matches!(
            read_record(&mut stream, 4),
            Err(AuthenticatedTransportErrorV0::EmptyRecord)
        ));
        sender.join().unwrap();
    }
}
