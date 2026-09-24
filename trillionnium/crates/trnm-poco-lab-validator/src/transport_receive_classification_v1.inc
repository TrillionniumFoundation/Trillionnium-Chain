/// Closed, inert rejection reasons for bytes received on an established
/// authenticated connection. The reason is not consensus evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstablishedPeerInputRejectionV1 {
    TooLarge,
    Malformed,
    WrongRun,
    UnknownSender,
    InvalidSignature,
    SessionSequenceMismatch,
}

/// Failure provenance, not a policy to reconnect, quarantine or stop a mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstablishedReceiveClassV1 {
    PeerInput(EstablishedPeerInputRejectionV1),
    TransportIo,
    Internal,
}

/// Inert failure facts from one actually owned authenticated connection.
/// Private fields prevent callers from replacing the original attribution.
#[derive(Debug)]
pub struct EstablishedReceiveErrorV1 {
    class: EstablishedReceiveClassV1,
    session: Box<ConnectionSession>,
    original: FrameError,
}

impl EstablishedReceiveErrorV1 {
    fn internal(session: ConnectionSession, original: FrameError) -> Self {
        Self {
            class: EstablishedReceiveClassV1::Internal,
            session: Box::new(session),
            original,
        }
    }

    pub const fn class_v1(&self) -> EstablishedReceiveClassV1 {
        self.class
    }

    /// Authenticated transport facts only; direction/generation/lease still
    /// belong to the mesh owner and must be independently joined there.
    pub const fn session_v1(&self) -> ConnectionSession {
        *self.session
    }

    pub const fn frame_error_v1(&self) -> &FrameError {
        &self.original
    }

    pub fn into_frame_error_v1(self) -> FrameError {
        self.original
    }
}

impl std::fmt::Display for EstablishedReceiveErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "established receive {:?}: {}",
            self.class, self.original
        )
    }
}

impl std::error::Error for EstablishedReceiveErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

// Only this established-frame read boundary grants peer-input attribution.
// Handshake failures can have local causes and must not use this classifier.
fn receive_established_frame_v1<T: Read>(
    io: &mut T,
    run_id: &str,
    roles: &ValidatorKeyRoleRegistryV1,
    session: ConnectionSession,
    next_receive: &mut u64,
    poisoned: &mut bool,
    host_admitted: bool,
) -> Result<AuthenticatedFrame, EstablishedReceiveErrorV1> {
    if *poisoned {
        return Err(EstablishedReceiveErrorV1::internal(
            session,
            FrameError::Poisoned,
        ));
    }
    if !host_admitted {
        *poisoned = true;
        return Err(EstablishedReceiveErrorV1::internal(
            session,
            FrameError::ExternalIdentity(P2pIdentityErrorV1::Rejected),
        ));
    }
    let following_sequence = next_receive.checked_add(1).ok_or_else(|| {
        *poisoned = true;
        EstablishedReceiveErrorV1::internal(session, FrameError::Replay)
    })?;
    let frame = match read_framed(io, run_id, roles) {
        Ok(frame) => frame,
        Err(original) => {
            *poisoned = true;
            use EstablishedPeerInputRejectionV1 as Peer;
            let class = match &original {
                FrameError::Io(_) => EstablishedReceiveClassV1::TransportIo,
                FrameError::TooLarge => EstablishedReceiveClassV1::PeerInput(Peer::TooLarge),
                FrameError::Malformed(_) => EstablishedReceiveClassV1::PeerInput(Peer::Malformed),
                FrameError::WrongRun => EstablishedReceiveClassV1::PeerInput(Peer::WrongRun),
                FrameError::UnknownSender => {
                    EstablishedReceiveClassV1::PeerInput(Peer::UnknownSender)
                }
                FrameError::InvalidSignature => {
                    EstablishedReceiveClassV1::PeerInput(Peer::InvalidSignature)
                }
                // These variants have no peer-input producer in read_framed.
                // Preserve fail-closed behavior if that implementation changes.
                FrameError::Replay | FrameError::Poisoned | FrameError::ExternalIdentity(_) => {
                    EstablishedReceiveClassV1::Internal
                }
            };
            return Err(EstablishedReceiveErrorV1 {
                class,
                session: Box::new(session),
                original,
            });
        }
    };
    if frame.sender != session.remote
        || frame.session != session.session
        || frame.sequence != *next_receive
    {
        *poisoned = true;
        return Err(EstablishedReceiveErrorV1 {
            class: EstablishedReceiveClassV1::PeerInput(
                EstablishedPeerInputRejectionV1::SessionSequenceMismatch,
            ),
            session: Box::new(session),
            original: FrameError::Replay,
        });
    }
    *next_receive = following_sequence;
    Ok(frame)
}
