//! Pure authenticated P2P admission candidate.
//!
//! This module owns no socket, listener, DNS, TLS, peer discovery, consensus
//! authority, persistence backend, or production activation. It models the
//! exact session, replay and response-loss boundary that a real transport and
//! durable replay owner must satisfy.

use std::{error::Error, fmt};

pub const MAX_CANDIDATE_PEER_FRAME_BYTES_V0: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IoDigest32V0([u8; 32]);

impl IoDigest32V0 {
    pub fn new(bytes: [u8; 32]) -> Result<Self, PeerAdmissionErrorV0> {
        if bytes == [0; 32] {
            return Err(PeerAdmissionErrorV0::ZeroDigest);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSessionIdentityV0 {
    chain_id: IoDigest32V0,
    protocol_digest: IoDigest32V0,
    peer_id: IoDigest32V0,
    session_id: IoDigest32V0,
    profile_digest: IoDigest32V0,
    generation: u64,
}

impl PeerSessionIdentityV0 {
    pub fn new(
        chain_id: IoDigest32V0,
        protocol_digest: IoDigest32V0,
        peer_id: IoDigest32V0,
        session_id: IoDigest32V0,
        profile_digest: IoDigest32V0,
        generation: u64,
    ) -> Result<Self, PeerAdmissionErrorV0> {
        if generation == 0 {
            return Err(PeerAdmissionErrorV0::InvalidSession);
        }
        Ok(Self {
            chain_id,
            protocol_digest,
            peer_id,
            session_id,
            profile_digest,
            generation,
        })
    }

    #[must_use]
    pub const fn chain_id(self) -> IoDigest32V0 {
        self.chain_id
    }

    #[must_use]
    pub const fn protocol_digest(self) -> IoDigest32V0 {
        self.protocol_digest
    }

    #[must_use]
    pub const fn peer_id(self) -> IoDigest32V0 {
        self.peer_id
    }

    #[must_use]
    pub const fn session_id(self) -> IoDigest32V0 {
        self.session_id
    }

    #[must_use]
    pub const fn profile_digest(self) -> IoDigest32V0 {
        self.profile_digest
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeerFrameV0 {
    session: PeerSessionIdentityV0,
    replay_nonce: u64,
    payload_digest: IoDigest32V0,
    payload_bytes: usize,
}

impl AuthenticatedPeerFrameV0 {
    pub fn new(
        session: PeerSessionIdentityV0,
        replay_nonce: u64,
        payload_digest: IoDigest32V0,
        payload_bytes: usize,
    ) -> Result<Self, PeerAdmissionErrorV0> {
        if replay_nonce == 0
            || payload_bytes == 0
            || payload_bytes > MAX_CANDIDATE_PEER_FRAME_BYTES_V0
        {
            return Err(PeerAdmissionErrorV0::InvalidFrame);
        }
        Ok(Self {
            session,
            replay_nonce,
            payload_digest,
            payload_bytes,
        })
    }

    #[must_use]
    pub const fn session(self) -> PeerSessionIdentityV0 {
        self.session
    }

    #[must_use]
    pub const fn replay_nonce(self) -> u64 {
        self.replay_nonce
    }

    #[must_use]
    pub const fn payload_digest(self) -> IoDigest32V0 {
        self.payload_digest
    }

    #[must_use]
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerReplayStateV0 {
    session: PeerSessionIdentityV0,
    highest_acknowledged_nonce: u64,
    pending: Option<AuthenticatedPeerFrameV0>,
}

impl PeerReplayStateV0 {
    pub fn new(
        session: PeerSessionIdentityV0,
        highest_acknowledged_nonce: u64,
        pending: Option<AuthenticatedPeerFrameV0>,
    ) -> Result<Self, PeerAdmissionErrorV0> {
        if let Some(frame) = pending {
            let expected = highest_acknowledged_nonce
                .checked_add(1)
                .ok_or(PeerAdmissionErrorV0::ReplayOverflow)?;
            if frame.session != session || frame.replay_nonce != expected {
                return Err(PeerAdmissionErrorV0::InvalidRecoveryState);
            }
        }
        Ok(Self {
            session,
            highest_acknowledged_nonce,
            pending,
        })
    }

    #[must_use]
    pub const fn session(self) -> PeerSessionIdentityV0 {
        self.session
    }

    #[must_use]
    pub const fn highest_acknowledged_nonce(self) -> u64 {
        self.highest_acknowledged_nonce
    }

    #[must_use]
    pub const fn pending(self) -> Option<AuthenticatedPeerFrameV0> {
        self.pending
    }
}

pub trait PeerReplayRecoverySourceV0 {
    type Error;

    fn verify_recovery(&mut self, state: &PeerReplayStateV0) -> Result<(), Self::Error>;
}

pub trait PeerFrameSourceV0 {
    type Error;

    fn verify_frame(
        &mut self,
        state: PeerReplayStateV0,
        frame: &AuthenticatedPeerFrameV0,
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAdmissionErrorV0 {
    ZeroDigest,
    InvalidSession,
    InvalidFrame,
    InvalidRecoveryState,
    ReplayOverflow,
    WrongSession,
    StaleNonce,
    NonContiguousNonce,
    PendingFrame,
    ConflictingReplay,
    StaleToken,
    UnexpectedAcknowledgement,
}

impl fmt::Display for PeerAdmissionErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroDigest => "peer identity digest may not be zero",
            Self::InvalidSession => "peer session identity is invalid",
            Self::InvalidFrame => "peer frame is outside the candidate bounds",
            Self::InvalidRecoveryState => "peer replay recovery state is inconsistent",
            Self::ReplayOverflow => "peer replay nonce overflowed",
            Self::WrongSession => "peer frame belongs to a different authenticated session",
            Self::StaleNonce => "peer frame replay nonce is stale",
            Self::NonContiguousNonce => "peer frame replay nonce is not the exact successor",
            Self::PendingFrame => "an unacknowledged peer frame is already pending",
            Self::ConflictingReplay => "pending peer frame replay changed its payload",
            Self::StaleToken => "verified peer frame token no longer matches replay state",
            Self::UnexpectedAcknowledgement => {
                "peer frame acknowledgement does not match the pending frame"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for PeerAdmissionErrorV0 {}

#[derive(Debug)]
pub enum PeerRecoveryErrorV0<E> {
    Boundary(PeerAdmissionErrorV0),
    Source(E),
}

impl<E: fmt::Display> fmt::Display for PeerRecoveryErrorV0<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(formatter, "peer recovery boundary failed: {error}"),
            Self::Source(error) => write!(formatter, "peer recovery source rejected: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for PeerRecoveryErrorV0<E> {}

#[derive(Debug)]
pub enum PeerFrameVerificationErrorV0<E> {
    Boundary(PeerAdmissionErrorV0),
    Source(E),
}

impl<E: fmt::Display> fmt::Display for PeerFrameVerificationErrorV0<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(formatter, "peer frame boundary failed: {error}"),
            Self::Source(error) => write!(formatter, "peer frame source rejected: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for PeerFrameVerificationErrorV0<E> {}

#[must_use = "verified peer frame must be consumed by admit_verified"]
#[derive(Debug)]
pub struct VerifiedPeerFrameV0 {
    prior: PeerReplayStateV0,
    frame: AuthenticatedPeerFrameV0,
}

impl VerifiedPeerFrameV0 {
    #[must_use]
    pub const fn prior(&self) -> PeerReplayStateV0 {
        self.prior
    }

    #[must_use]
    pub const fn frame(&self) -> AuthenticatedPeerFrameV0 {
        self.frame
    }
}

pub struct CandidateP2pAdmissionV0 {
    state: PeerReplayStateV0,
}

impl CandidateP2pAdmissionV0 {
    pub fn recover_verified<S>(
        state: PeerReplayStateV0,
        source: &mut S,
    ) -> Result<Self, PeerRecoveryErrorV0<S::Error>>
    where
        S: PeerReplayRecoverySourceV0,
    {
        let state = PeerReplayStateV0::new(
            state.session,
            state.highest_acknowledged_nonce,
            state.pending,
        )
        .map_err(PeerRecoveryErrorV0::Boundary)?;
        source
            .verify_recovery(&state)
            .map_err(PeerRecoveryErrorV0::Source)?;
        Ok(Self { state })
    }

    #[must_use]
    pub const fn recovery_state(&self) -> PeerReplayStateV0 {
        self.state
    }

    #[must_use]
    pub const fn pending_frame(&self) -> Option<AuthenticatedPeerFrameV0> {
        self.state.pending
    }

    pub fn verify_frame<S>(
        &self,
        frame: AuthenticatedPeerFrameV0,
        source: &mut S,
    ) -> Result<VerifiedPeerFrameV0, PeerFrameVerificationErrorV0<S::Error>>
    where
        S: PeerFrameSourceV0,
    {
        if frame.session != self.state.session {
            return Err(PeerFrameVerificationErrorV0::Boundary(
                PeerAdmissionErrorV0::WrongSession,
            ));
        }
        match self.state.pending {
            Some(pending) if frame == pending => {}
            Some(pending) if frame.replay_nonce == pending.replay_nonce => {
                return Err(PeerFrameVerificationErrorV0::Boundary(
                    PeerAdmissionErrorV0::ConflictingReplay,
                ));
            }
            Some(_) => {
                return Err(PeerFrameVerificationErrorV0::Boundary(
                    PeerAdmissionErrorV0::PendingFrame,
                ));
            }
            None => {
                let expected = self.state.highest_acknowledged_nonce.checked_add(1).ok_or(
                    PeerFrameVerificationErrorV0::Boundary(PeerAdmissionErrorV0::ReplayOverflow),
                )?;
                if frame.replay_nonce < expected {
                    return Err(PeerFrameVerificationErrorV0::Boundary(
                        PeerAdmissionErrorV0::StaleNonce,
                    ));
                }
                if frame.replay_nonce != expected {
                    return Err(PeerFrameVerificationErrorV0::Boundary(
                        PeerAdmissionErrorV0::NonContiguousNonce,
                    ));
                }
            }
        }
        source
            .verify_frame(self.state, &frame)
            .map_err(PeerFrameVerificationErrorV0::Source)?;
        Ok(VerifiedPeerFrameV0 {
            prior: self.state,
            frame,
        })
    }

    pub fn admit_verified(
        &mut self,
        verified: VerifiedPeerFrameV0,
    ) -> Result<AuthenticatedPeerFrameV0, PeerAdmissionErrorV0> {
        if verified.prior != self.state {
            return Err(PeerAdmissionErrorV0::StaleToken);
        }
        match self.state.pending {
            Some(pending) if pending == verified.frame => Ok(pending),
            Some(_) => Err(PeerAdmissionErrorV0::PendingFrame),
            None => {
                self.state.pending = Some(verified.frame);
                Ok(verified.frame)
            }
        }
    }

    pub fn acknowledge(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
    ) -> Result<PeerReplayStateV0, PeerAdmissionErrorV0> {
        if self.state.pending != Some(frame) {
            return Err(PeerAdmissionErrorV0::UnexpectedAcknowledgement);
        }
        self.state.highest_acknowledged_nonce = frame.replay_nonce;
        self.state.pending = None;
        Ok(self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(byte: u8) -> IoDigest32V0 {
        IoDigest32V0::new([byte; 32]).unwrap()
    }

    fn session(generation: u64) -> PeerSessionIdentityV0 {
        PeerSessionIdentityV0::new(d(1), d(2), d(3), d(4), d(5), generation).unwrap()
    }

    fn frame(session: PeerSessionIdentityV0, nonce: u64, byte: u8) -> AuthenticatedPeerFrameV0 {
        AuthenticatedPeerFrameV0::new(session, nonce, d(byte), 128).unwrap()
    }

    struct AcceptRecovery;

    impl PeerReplayRecoverySourceV0 for AcceptRecovery {
        type Error = Infallible;

        fn verify_recovery(&mut self, _state: &PeerReplayStateV0) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingFrameSource(usize);

    impl PeerFrameSourceV0 for CountingFrameSource {
        type Error = Infallible;

        fn verify_frame(
            &mut self,
            _state: PeerReplayStateV0,
            _frame: &AuthenticatedPeerFrameV0,
        ) -> Result<(), Self::Error> {
            self.0 += 1;
            Ok(())
        }
    }

    fn admission() -> CandidateP2pAdmissionV0 {
        CandidateP2pAdmissionV0::recover_verified(
            PeerReplayStateV0::new(session(1), 0, None).unwrap(),
            &mut AcceptRecovery,
        )
        .unwrap()
    }

    #[test]
    fn contiguous_frame_is_admitted_and_acknowledged_exactly() {
        let mut admission = admission();
        let first = frame(session(1), 1, 10);
        let mut source = CountingFrameSource::default();
        let verified = admission.verify_frame(first, &mut source).unwrap();
        assert_eq!(source.0, 1);
        assert_eq!(admission.admit_verified(verified).unwrap(), first);
        assert_eq!(admission.pending_frame(), Some(first));
        assert_eq!(
            admission.acknowledge(first).unwrap(),
            PeerReplayStateV0::new(session(1), 1, None).unwrap()
        );
    }

    #[test]
    fn pending_frame_survives_recovery_and_replays_without_nonce_movement() {
        let mut admission = admission();
        let first = frame(session(1), 1, 10);
        let verified = admission
            .verify_frame(first, &mut CountingFrameSource::default())
            .unwrap();
        admission.admit_verified(verified).unwrap();
        let state = admission.recovery_state();

        let mut recovered =
            CandidateP2pAdmissionV0::recover_verified(state, &mut AcceptRecovery).unwrap();
        let replay = recovered
            .verify_frame(first, &mut CountingFrameSource::default())
            .unwrap();
        assert_eq!(recovered.admit_verified(replay).unwrap(), first);
        assert_eq!(recovered.recovery_state(), state);
        recovered.acknowledge(first).unwrap();
        let second = frame(session(1), 2, 11);
        let next = recovered
            .verify_frame(second, &mut CountingFrameSource::default())
            .unwrap();
        assert_eq!(recovered.admit_verified(next).unwrap(), second);
    }

    #[test]
    fn wrong_session_stale_gap_and_pending_conflict_precede_source_authority() {
        let mut admission = admission();
        let mut source = CountingFrameSource::default();
        assert!(matches!(
            admission.verify_frame(frame(session(2), 1, 10), &mut source),
            Err(PeerFrameVerificationErrorV0::Boundary(
                PeerAdmissionErrorV0::WrongSession
            ))
        ));
        assert!(matches!(
            admission.verify_frame(frame(session(1), 2, 10), &mut source),
            Err(PeerFrameVerificationErrorV0::Boundary(
                PeerAdmissionErrorV0::NonContiguousNonce
            ))
        ));
        assert_eq!(source.0, 0);

        let first = frame(session(1), 1, 10);
        let verified = admission.verify_frame(first, &mut source).unwrap();
        admission.admit_verified(verified).unwrap();
        assert!(matches!(
            admission.verify_frame(frame(session(1), 1, 11), &mut source),
            Err(PeerFrameVerificationErrorV0::Boundary(
                PeerAdmissionErrorV0::ConflictingReplay
            ))
        ));
        assert!(matches!(
            admission.verify_frame(frame(session(1), 2, 12), &mut source),
            Err(PeerFrameVerificationErrorV0::Boundary(
                PeerAdmissionErrorV0::PendingFrame
            ))
        ));
        admission.acknowledge(first).unwrap();
        assert!(matches!(
            admission.verify_frame(first, &mut source),
            Err(PeerFrameVerificationErrorV0::Boundary(
                PeerAdmissionErrorV0::StaleNonce
            ))
        ));
    }

    struct RejectFrame;

    impl PeerFrameSourceV0 for RejectFrame {
        type Error = &'static str;

        fn verify_frame(
            &mut self,
            _state: PeerReplayStateV0,
            _frame: &AuthenticatedPeerFrameV0,
        ) -> Result<(), Self::Error> {
            Err("transport authentication rejected")
        }
    }

    #[test]
    fn source_rejection_and_wrong_acknowledgement_do_not_mutate_state() {
        let mut admission = admission();
        let initial = admission.recovery_state();
        let first = frame(session(1), 1, 10);
        assert!(matches!(
            admission.verify_frame(first, &mut RejectFrame),
            Err(PeerFrameVerificationErrorV0::Source(
                "transport authentication rejected"
            ))
        ));
        assert_eq!(admission.recovery_state(), initial);
        assert_eq!(
            admission.acknowledge(first),
            Err(PeerAdmissionErrorV0::UnexpectedAcknowledgement)
        );
        assert_eq!(admission.recovery_state(), initial);
    }

    #[test]
    fn verified_token_is_invalid_after_replay_state_moves() {
        let mut admission = admission();
        let first = frame(session(1), 1, 10);
        let accepted = admission
            .verify_frame(first, &mut CountingFrameSource::default())
            .unwrap();
        let stale = admission
            .verify_frame(first, &mut CountingFrameSource::default())
            .unwrap();
        admission.admit_verified(accepted).unwrap();
        assert_eq!(
            admission.admit_verified(stale),
            Err(PeerAdmissionErrorV0::StaleToken)
        );
    }

    struct RejectRecovery;

    impl PeerReplayRecoverySourceV0 for RejectRecovery {
        type Error = &'static str;

        fn verify_recovery(&mut self, _state: &PeerReplayStateV0) -> Result<(), Self::Error> {
            Err("replay store authentication rejected")
        }
    }

    #[test]
    fn recovery_source_and_inconsistent_pending_state_fail_closed() {
        let state = PeerReplayStateV0::new(session(1), 0, None).unwrap();
        assert!(matches!(
            CandidateP2pAdmissionV0::recover_verified(state, &mut RejectRecovery),
            Err(PeerRecoveryErrorV0::Source(
                "replay store authentication rejected"
            ))
        ));
        assert_eq!(
            PeerReplayStateV0::new(session(1), 0, Some(frame(session(1), 2, 10))),
            Err(PeerAdmissionErrorV0::InvalidRecoveryState)
        );
        assert_eq!(
            PeerReplayStateV0::new(session(1), 0, Some(frame(session(2), 1, 10))),
            Err(PeerAdmissionErrorV0::InvalidRecoveryState)
        );
    }

    #[test]
    fn frame_and_session_bounds_are_closed() {
        assert_eq!(
            IoDigest32V0::new([0; 32]),
            Err(PeerAdmissionErrorV0::ZeroDigest)
        );
        assert_eq!(
            PeerSessionIdentityV0::new(d(1), d(2), d(3), d(4), d(5), 0),
            Err(PeerAdmissionErrorV0::InvalidSession)
        );
        assert_eq!(
            AuthenticatedPeerFrameV0::new(session(1), 0, d(10), 1),
            Err(PeerAdmissionErrorV0::InvalidFrame)
        );
        assert_eq!(
            AuthenticatedPeerFrameV0::new(
                session(1),
                1,
                d(10),
                MAX_CANDIDATE_PEER_FRAME_BYTES_V0 + 1,
            ),
            Err(PeerAdmissionErrorV0::InvalidFrame)
        );
    }
}
