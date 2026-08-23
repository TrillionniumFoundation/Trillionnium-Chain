//! D0 authenticated peer-admission helper.
//!
//! This module is the smallest active boundary around the already-authenticated
//! transport handshake.  It adds an explicit epoch/validator-set binding,
//! process-local session replay protection, and a bounded peer lease with
//! generation fencing.  The helper deliberately stops at admission: it does
//! not send consensus frames, drive a validator loop, persist consensus
//! safety state, attest a host, or release a signer capability.
//!
//! The lease authority is intentionally process-local.  A restart, machine
//! clone, or database rollback can therefore invalidate its memory; production
//! use still needs an external append-only lease/fencing authority and host
//! attestation.  Keeping that boundary explicit is part of the D0 truth
//! contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{Read, Write},
    time::{Duration, Instant},
};

use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::transport::AuthenticatedConnection;

pub const P2P_ADMISSION_PROFILE_V1: &str = "active-p2p-admission-helper-v1";
pub const P2P_ADMISSION_HELPER_ACTIVE_V1: bool = true;
pub const P2P_ADMISSION_CONSENSUS_TRANSPORT_V1: bool = false;
pub const P2P_ADMISSION_VALIDATOR_RUNTIME_V1: bool = false;
pub const P2P_ADMISSION_PRODUCTION_ACTIVATION_V1: bool = false;
pub const P2P_ADMISSION_HOST_ATTESTATION_V1: bool = false;

const MAX_LEASE_PEERS: usize = 1_024;
const MAX_SESSION_REPLAY_ENTRIES: usize = 4_096;
const MAX_LEASE_GENERATION: u64 = 1_000_000;
const MIN_LEASE_TTL: Duration = Duration::from_secs(1);
const MAX_LEASE_TTL: Duration = Duration::from_secs(120);

/// Exact context that a peer lease is allowed to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAdmissionContextV1 {
    epoch: u64,
    validator_set_id: [u8; 32],
}

impl PeerAdmissionContextV1 {
    pub fn from_validator_set(validator_set: &ValidatorSet) -> Self {
        Self {
            epoch: validator_set.epoch().get(),
            validator_set_id: validator_set.id().into_bytes(),
        }
    }

    pub fn new(epoch: u64, validator_set_id: [u8; 32]) -> Result<Self, AdmissionError> {
        if validator_set_id == [0; 32] {
            return Err(AdmissionError::InvalidContext);
        }
        Ok(Self {
            epoch,
            validator_set_id,
        })
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn validator_set_id(self) -> [u8; 32] {
        self.validator_set_id
    }
}

/// A lease token is the only process-local authority returned by this helper.
/// It is not a consensus credential and cannot be serialized into a consensus
/// message without a separately reviewed protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLeaseTokenV1 {
    peer: ValidatorId,
    context: PeerAdmissionContextV1,
    session_id: [u8; 32],
    generation: u64,
}

impl PeerLeaseTokenV1 {
    pub const fn peer(self) -> ValidatorId {
        self.peer
    }

    pub const fn context(self) -> PeerAdmissionContextV1 {
        self.context
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeaseEntry {
    token: PeerLeaseTokenV1,
    expires_at: Instant,
}

/// Fail-closed admission errors.  The variants intentionally distinguish a
/// stale lease from a replay so callers cannot silently rebind an old session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    InvalidContext,
    InvalidPeer,
    InvalidSession,
    ContextMismatch,
    ConnectionContextMissing,
    RemoteMismatch,
    SessionReplay,
    NonceReplay,
    SessionWindowFull,
    NonceWindowFull,
    PeerAlreadyLeased,
    PeerCapacity,
    LeaseNotFound,
    LeaseExpired,
    LeaseFenced,
    GenerationExhausted,
    InvalidLeaseTtl,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidContext => "admission context is invalid",
            Self::InvalidPeer => "peer identity is invalid",
            Self::InvalidSession => "session identifier is invalid",
            Self::ContextMismatch => "peer lease context differs from authority context",
            Self::ConnectionContextMissing => "connection lacks explicit epoch/set binding",
            Self::RemoteMismatch => "authenticated remote differs from expected peer",
            Self::SessionReplay => "authenticated session was already admitted",
            Self::NonceReplay => "handshake nonce binding was already admitted",
            Self::SessionWindowFull => "session replay window is exhausted",
            Self::NonceWindowFull => "handshake nonce replay window is exhausted",
            Self::PeerAlreadyLeased => "peer already has a live lease",
            Self::PeerCapacity => "peer lease capacity is exhausted",
            Self::LeaseNotFound => "peer lease is not present",
            Self::LeaseExpired => "peer lease expired",
            Self::LeaseFenced => "peer lease was fenced by a newer generation",
            Self::GenerationExhausted => "peer lease generation exhausted",
            Self::InvalidLeaseTtl => "lease TTL is outside its bounded profile",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AdmissionError {}

/// A bounded process-local peer lease/fencing authority.
///
/// Only one generation may be live for a peer.  Reconnect after an expiry gets
/// a strictly higher generation; stale release/renew operations fail closed.
/// Session IDs remain in a bounded non-evicting replay set so an old signed
/// handshake cannot be re-admitted during this process lifetime.
#[derive(Debug)]
pub struct PeerLeaseAuthorityV1 {
    context: PeerAdmissionContextV1,
    max_peers: usize,
    max_session_entries: usize,
    ttl: Duration,
    leases: BTreeMap<ValidatorId, LeaseEntry>,
    next_generation: BTreeMap<ValidatorId, u64>,
    admitted_sessions: BTreeSet<(ValidatorId, [u8; 32])>,
    admitted_nonce_bindings: BTreeSet<(ValidatorId, [u8; 32])>,
}

impl PeerLeaseAuthorityV1 {
    pub fn new(
        context: PeerAdmissionContextV1,
        max_peers: usize,
        ttl: Duration,
    ) -> Result<Self, AdmissionError> {
        if max_peers == 0 || max_peers > MAX_LEASE_PEERS {
            return Err(AdmissionError::PeerCapacity);
        }
        if !(MIN_LEASE_TTL..=MAX_LEASE_TTL).contains(&ttl) {
            return Err(AdmissionError::InvalidLeaseTtl);
        }
        Ok(Self {
            context,
            max_peers,
            max_session_entries: MAX_SESSION_REPLAY_ENTRIES.min(max_peers.saturating_mul(8)),
            ttl,
            leases: BTreeMap::new(),
            next_generation: BTreeMap::new(),
            admitted_sessions: BTreeSet::new(),
            admitted_nonce_bindings: BTreeSet::new(),
        })
    }

    pub const fn context(&self) -> PeerAdmissionContextV1 {
        self.context
    }

    pub fn active_peer_count(&self) -> usize {
        self.leases.len()
    }

    pub fn admitted_session_count(&self) -> usize {
        self.admitted_sessions.len()
    }

    /// Admit a completed, authenticated session and issue its first lease.
    pub fn admit(
        &mut self,
        peer: ValidatorId,
        context: PeerAdmissionContextV1,
        session_id: [u8; 32],
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        self.admit_with_nonce_binding(peer, context, session_id, session_id, now)
    }

    /// Test/tooling boundary for a completed handshake when the caller has
    /// retained the exact challenge/hello nonce binding.  The live
    /// `admit_authenticated_connection` path obtains this value directly from
    /// `AuthenticatedConnection`.
    pub fn admit_with_nonce_binding(
        &mut self,
        peer: ValidatorId,
        context: PeerAdmissionContextV1,
        session_id: [u8; 32],
        nonce_binding: [u8; 32],
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        self.admit_inner_with_nonce(peer, context, session_id, nonce_binding, now)
    }

    /// The active helper entry point around the signed transport handshake.
    /// No consensus payload is sent or accepted here.
    pub fn admit_authenticated_connection<T: Read + Write>(
        &mut self,
        connection: &AuthenticatedConnection<T>,
        expected_peer: ValidatorId,
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        if connection.remote() != expected_peer {
            return Err(AdmissionError::RemoteMismatch);
        }
        let (epoch, validator_set_id) = connection
            .validator_set_binding()
            .ok_or(AdmissionError::ConnectionContextMissing)?;
        let context = PeerAdmissionContextV1::new(epoch, validator_set_id)?;
        self.admit_inner_with_nonce(
            expected_peer,
            context,
            connection.session_id(),
            connection.handshake_nonce_binding(),
            now,
        )
    }

    fn admit_inner_with_nonce(
        &mut self,
        peer: ValidatorId,
        context: PeerAdmissionContextV1,
        session_id: [u8; 32],
        nonce_binding: [u8; 32],
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        if peer.is_zero() {
            return Err(AdmissionError::InvalidPeer);
        }
        if session_id == [0; 32] {
            return Err(AdmissionError::InvalidSession);
        }
        if nonce_binding == [0; 32] {
            return Err(AdmissionError::InvalidSession);
        }
        if context != self.context {
            return Err(AdmissionError::ContextMismatch);
        }
        self.cleanup(now);
        if self.admitted_sessions.contains(&(peer, session_id)) {
            return Err(AdmissionError::SessionReplay);
        }
        if self
            .admitted_nonce_bindings
            .contains(&(peer, nonce_binding))
        {
            return Err(AdmissionError::NonceReplay);
        }
        if self.leases.contains_key(&peer) {
            return Err(AdmissionError::PeerAlreadyLeased);
        }
        if self.admitted_sessions.len() >= self.max_session_entries {
            return Err(AdmissionError::SessionWindowFull);
        }
        if self.admitted_nonce_bindings.len() >= self.max_session_entries {
            return Err(AdmissionError::NonceWindowFull);
        }
        if self.leases.len() >= self.max_peers {
            return Err(AdmissionError::PeerCapacity);
        }
        let generation = self
            .next_generation
            .get(&peer)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(AdmissionError::GenerationExhausted)?;
        if generation > MAX_LEASE_GENERATION {
            return Err(AdmissionError::GenerationExhausted);
        }
        let token = PeerLeaseTokenV1 {
            peer,
            context,
            session_id,
            generation,
        };
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or(AdmissionError::GenerationExhausted)?;
        self.next_generation.insert(peer, generation);
        self.admitted_sessions.insert((peer, session_id));
        self.admitted_nonce_bindings.insert((peer, nonce_binding));
        self.leases.insert(peer, LeaseEntry { token, expires_at });
        Ok(token)
    }

    pub fn renew(
        &mut self,
        token: PeerLeaseTokenV1,
        now: Instant,
    ) -> Result<PeerLeaseTokenV1, AdmissionError> {
        let entry = self
            .leases
            .get_mut(&token.peer)
            .ok_or(AdmissionError::LeaseNotFound)?;
        if entry.token != token {
            return Err(AdmissionError::LeaseFenced);
        }
        if now >= entry.expires_at {
            self.leases.remove(&token.peer);
            return Err(AdmissionError::LeaseExpired);
        }
        entry.expires_at = now
            .checked_add(self.ttl)
            .ok_or(AdmissionError::GenerationExhausted)?;
        Ok(entry.token)
    }

    pub fn release(&mut self, token: PeerLeaseTokenV1) -> Result<(), AdmissionError> {
        let entry = self
            .leases
            .get(&token.peer)
            .ok_or(AdmissionError::LeaseNotFound)?;
        if entry.token != token {
            return Err(AdmissionError::LeaseFenced);
        }
        self.leases.remove(&token.peer);
        Ok(())
    }

    pub fn is_current(&self, token: PeerLeaseTokenV1, now: Instant) -> bool {
        self.leases
            .get(&token.peer)
            .is_some_and(|entry| entry.token == token && now < entry.expires_at)
    }

    /// Removes expired leases and returns the number of removed entries.
    pub fn cleanup(&mut self, now: Instant) -> usize {
        let before = self.leases.len();
        self.leases.retain(|_, entry| now < entry.expires_at);
        before - self.leases.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;
    use crate::{
        key_roles::{ValidatorKeyRoleBindingV1, ValidatorKeyRoleRegistryV1},
        transport::{AuthenticatedConnection, RunTransportContext},
    };

    fn context() -> PeerAdmissionContextV1 {
        let consensus_key = SigningKey::from_bytes(&[0x31; 32]);
        let validator = Validator::new(
            ValidatorId::new([0x71; 32]),
            ConsensusPublicKey::new(consensus_key.verifying_key().to_bytes()),
            VotingPower::new(1).unwrap(),
        )
        .unwrap();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x73; 32]),
            ChainId::new("trnm-poco-g3-admission-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(4),
            parameters.hash(),
            vec![validator],
        )
        .unwrap();
        PeerAdmissionContextV1::from_validator_set(&set)
    }

    fn transport_fixture() -> (
        SigningKey,
        SigningKey,
        ValidatorId,
        ValidatorId,
        ValidatorSet,
        ValidatorKeyRoleRegistryV1,
        PeerAdmissionContextV1,
        RunTransportContext,
    ) {
        let client_key = SigningKey::from_bytes(&[0x61; 32]);
        let server_key = SigningKey::from_bytes(&[0x62; 32]);
        let client_consensus_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_consensus_key = SigningKey::from_bytes(&[0x32; 32]);
        let client_operator_key = SigningKey::from_bytes(&[0x41; 32]);
        let server_operator_key = SigningKey::from_bytes(&[0x42; 32]);
        let client = ValidatorId::new([0x71; 32]);
        let server = ValidatorId::new([0x72; 32]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x73; 32]),
            ChainId::new("trnm-poco-g3-admission-transport-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(7),
            parameters.hash(),
            vec![
                Validator::new(
                    client,
                    ConsensusPublicKey::new(client_consensus_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    server,
                    ConsensusPublicKey::new(server_consensus_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let key_roles = ValidatorKeyRoleRegistryV1::new(
            &set,
            vec![
                ValidatorKeyRoleBindingV1::new(
                    client,
                    client_consensus_key.verifying_key().to_bytes(),
                    client_key.verifying_key().to_bytes(),
                    client_operator_key.verifying_key().to_bytes(),
                )
                .unwrap(),
                ValidatorKeyRoleBindingV1::new(
                    server,
                    server_consensus_key.verifying_key().to_bytes(),
                    server_key.verifying_key().to_bytes(),
                    server_operator_key.verifying_key().to_bytes(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let admission_context = PeerAdmissionContextV1::from_validator_set(&set);
        let transport_context =
            RunTransportContext::new([0x74; 32], [0x75; 32], [0x76; 32], [0x77; 32])
                .with_validator_set_binding(set.epoch().get(), set.id().into_bytes());
        (
            client_key,
            server_key,
            client,
            server,
            set,
            key_roles,
            admission_context,
            transport_context,
        )
    }

    #[test]
    fn lease_fences_replay_and_rebinds_after_bounded_cleanup() {
        let context = context();
        let mut authority = PeerLeaseAuthorityV1::new(context, 2, Duration::from_secs(5)).unwrap();
        let peer = ValidatorId::new([0x72; 32]);
        let first_session = [0x81; 32];
        let second_session = [0x82; 32];
        let now = Instant::now();
        let first = authority.admit(peer, context, first_session, now).unwrap();
        assert!(authority.is_current(first, now + Duration::from_secs(1)));
        assert_eq!(
            authority.admit(peer, context, second_session, now),
            Err(AdmissionError::PeerAlreadyLeased)
        );
        let stale = PeerLeaseTokenV1 {
            generation: first.generation().saturating_sub(1),
            ..first
        };
        assert_eq!(authority.release(stale), Err(AdmissionError::LeaseFenced));
        assert_eq!(
            authority.admit(peer, context, first_session, now + Duration::from_secs(1)),
            Err(AdmissionError::SessionReplay)
        );
        let expired = now + Duration::from_secs(6);
        assert_eq!(authority.cleanup(expired), 1);
        let rebound = authority
            .admit(peer, context, second_session, expired)
            .unwrap();
        assert_eq!(rebound.generation(), first.generation() + 1);
        assert!(!authority.is_current(first, expired));
        assert!(authority.is_current(rebound, expired));
        assert_eq!(
            authority.admit(peer, context, first_session, expired),
            Err(AdmissionError::SessionReplay)
        );

        let mut nonce_authority =
            PeerLeaseAuthorityV1::new(context, 1, Duration::from_secs(5)).unwrap();
        let nonce = [0x91; 32];
        let nonce_first = nonce_authority
            .admit_with_nonce_binding(peer, context, [0x92; 32], nonce, expired)
            .unwrap();
        nonce_authority.release(nonce_first).unwrap();
        assert_eq!(
            nonce_authority.admit_with_nonce_binding(peer, context, [0x93; 32], nonce, expired,),
            Err(AdmissionError::NonceReplay)
        );
    }

    #[test]
    fn context_requires_nonzero_set_and_exact_epoch() {
        assert_eq!(
            PeerAdmissionContextV1::new(0, [0; 32]),
            Err(AdmissionError::InvalidContext)
        );
        let context = context();
        let wrong =
            PeerAdmissionContextV1::new(context.epoch() + 1, context.validator_set_id()).unwrap();
        let peer = ValidatorId::new([0x72; 32]);
        let mut authority = PeerLeaseAuthorityV1::new(context, 1, Duration::from_secs(5)).unwrap();
        assert_eq!(
            authority.admit(peer, wrong, [0x83; 32], Instant::now()),
            Err(AdmissionError::ContextMismatch)
        );
    }

    #[test]
    fn authenticated_connection_admission_binds_epoch_set_and_session() {
        let (client_key, server_key, client, server, set, key_roles, context, transport_context) =
            transport_fixture();
        let run_id = "poco-g3-7-20260823T070000Z-a1b2c3d4";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_set = set.clone();
        let server_roles = key_roles.clone();
        let server_context = transport_context;
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = AuthenticatedConnection::accept(
                stream,
                run_id,
                server,
                &server_key,
                &server_set,
                &server_roles,
                server_context,
            )
            .unwrap();
            let mut authority =
                PeerLeaseAuthorityV1::new(context, 2, Duration::from_secs(5)).unwrap();
            let token = authority
                .admit_authenticated_connection(&connection, client, Instant::now())
                .unwrap();
            assert_eq!(token.context(), context);
            (
                connection.session_id(),
                connection.handshake_nonce_binding(),
                token,
            )
        });

        let stream = TcpStream::connect(address).unwrap();
        let connection = AuthenticatedConnection::connect(
            stream,
            run_id,
            client,
            server,
            &client_key,
            &set,
            &key_roles,
            transport_context,
        )
        .unwrap();
        assert_eq!(
            connection.validator_set_binding(),
            Some((7, set.id().into_bytes()))
        );
        let mut authority = PeerLeaseAuthorityV1::new(context, 2, Duration::from_secs(5)).unwrap();
        let token = authority
            .admit_authenticated_connection(&connection, server, Instant::now())
            .unwrap();
        assert_eq!(token.context().epoch(), 7);
        let (server_session, server_nonce_binding, server_token) = server_thread.join().unwrap();
        assert_eq!(connection.session_id(), server_session);
        assert_eq!(connection.handshake_nonce_binding(), server_nonce_binding);
        assert_ne!(server_nonce_binding, [0; 32]);
        assert_eq!(token.session_id(), server_token.session_id());

        assert_eq!(
            authority.admit_authenticated_connection(&connection, client, Instant::now()),
            Err(AdmissionError::RemoteMismatch)
        );
        assert_eq!(authority.release(token), Ok(()));
        assert_eq!(
            authority.admit_authenticated_connection(&connection, server, Instant::now()),
            Err(AdmissionError::SessionReplay)
        );
        let wrong_context = PeerAdmissionContextV1::new(8, context.validator_set_id()).unwrap();
        let mut wrong_authority =
            PeerLeaseAuthorityV1::new(wrong_context, 2, Duration::from_secs(5)).unwrap();
        assert_eq!(
            wrong_authority.admit_authenticated_connection(&connection, server, Instant::now()),
            Err(AdmissionError::ContextMismatch)
        );
    }
}
