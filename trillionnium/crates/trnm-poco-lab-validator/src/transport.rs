//! Receiver-challenged authenticated transport sessions for the G3 lab.
//!
//! Every TCP connection obtains a fresh receiver nonce before the initiator
//! proves its identity. A third, server-signed Finished record binds the exact
//! challenge/hello transcript and derived session, so neither side returns an
//! authenticated connection before explicit key confirmation. The resulting
//! session identifier cannot be replayed across a receiver restart or
//! reconnect. The connection freezes its run, key, validator set and counters;
//! any I/O, authentication, replay or exhaustion ambiguity permanently poisons
//! it. This module is a bounded transport primitive only; the consensus
//! validator event loop does not use it yet.

use std::io::{Read, Write};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

use crate::frame::{
    read_framed, run_id_sha256_v1, validate_run_id_bytes, write_framed,
    write_framed_with_external_identity, AuthenticatedFrame, FrameError, FrameKind,
};
use crate::key_roles::ValidatorKeyRoleRegistryV1;
use crate::p2p_identity::{
    P2pIdentitySignatureProducerV1, P2pIdentitySignaturePurposeV1, P2pIdentitySignatureRequestV1,
};

const HANDSHAKE_MAGIC: &[u8; 8] = b"TRNMG3H2";
const HANDSHAKE_VERSION: u16 = 2;
const CHALLENGE_TAG: u8 = 1;
const HELLO_TAG: u8 = 2;
const FINISHED_TAG: u8 = 3;
const MAX_HANDSHAKE_BYTES: usize = 512;
const CHALLENGE_DOMAIN: &[u8] = b"trnm.poco-g3.receiver-challenge.v2";
const HELLO_DOMAIN: &[u8] = b"trnm.poco-g3.initiator-hello.v2";
const FINISHED_DOMAIN: &[u8] = b"trnm.poco-g3.receiver-finished.v2";
const SESSION_DOMAIN: &[u8] = b"trnm.poco-g3.connection-session.v2";
const TRANSCRIPT_DOMAIN: &[u8] = b"trnm.poco-g3.handshake-transcript.v2";
const NETWORK_CONTEXT_DOMAIN: &[u8] = b"trnm.poco-g3.network-context.v2";
const EPOCH_SET_BINDING_DOMAIN: &[u8] = b"trnm.poco-g3.network-context.epoch-set-binding.v1";
const NODE_CONFIG_BINDING_DOMAIN: &[u8] = b"trnm.poco-g3.network-context.node-config-binding.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunTransportContext {
    pub topology_sha256: [u8; 32],
    pub candidate_source_sha256: [u8; 32],
    pub binary_sha256: [u8; 32],
    pub coordinator_manifest_sha256: [u8; 32],
    /// Optional explicit consensus epoch binding for the D0 admission
    /// helper.  The legacy `new` constructor leaves this unset so existing
    /// laboratory fixtures remain byte-compatible at the API boundary.  A
    /// helper admission context MUST set both this and `validator_set_id`;
    /// the transport digest then signs them as part of the handshake.
    epoch: Option<u64>,
    validator_set_id: Option<[u8; 32]>,
    /// Optional hash of the exact validator configuration admitted by the
    /// deployment manifest.  This is a node-identity binding, not host
    /// attestation; an independent attestor is still required before signer
    /// or consensus commissioning.
    node_config_sha256: Option<[u8; 32]>,
}

impl RunTransportContext {
    pub const fn new(
        topology_sha256: [u8; 32],
        candidate_source_sha256: [u8; 32],
        binary_sha256: [u8; 32],
        coordinator_manifest_sha256: [u8; 32],
    ) -> Self {
        Self {
            topology_sha256,
            candidate_source_sha256,
            binary_sha256,
            coordinator_manifest_sha256,
            epoch: None,
            validator_set_id: None,
            node_config_sha256: None,
        }
    }

    /// Adds an explicit epoch and validator-set binding to the authenticated
    /// handshake.  This is a transport admission fact only; it does not
    /// authorize consensus, signing, recovery, or validator activation.
    pub const fn with_validator_set_binding(
        mut self,
        epoch: u64,
        validator_set_id: [u8; 32],
    ) -> Self {
        self.epoch = Some(epoch);
        self.validator_set_id = Some(validator_set_id);
        self
    }

    pub const fn validator_set_binding(&self) -> Option<(u64, [u8; 32])> {
        match (self.epoch, self.validator_set_id) {
            (Some(epoch), Some(set_id)) => Some((epoch, set_id)),
            _ => None,
        }
    }

    /// Adds the exact public validator-config digest to the authenticated
    /// handshake context.  This prevents one validator's signed transport
    /// session from being replayed under another deployment configuration.
    /// It does not claim a cryptographic host/TEE attestation.
    pub const fn with_node_config_binding(mut self, config_sha256: [u8; 32]) -> Self {
        self.node_config_sha256 = Some(config_sha256);
        self
    }

    pub const fn node_config_binding(&self) -> Option<[u8; 32]> {
        self.node_config_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionSession {
    remote: ValidatorId,
    session: [u8; 32],
    nonce_binding: [u8; 32],
}

impl ConnectionSession {
    pub const fn remote(self) -> ValidatorId {
        self.remote
    }

    pub const fn session(self) -> [u8; 32] {
        self.session
    }

    pub const fn nonce_binding(self) -> [u8; 32] {
        self.nonce_binding
    }
}

pub struct AuthenticatedConnection<T> {
    io: T,
    local: ValidatorId,
    session: ConnectionSession,
    run_id: String,
    signing_key: SigningKey,
    key_roles: ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
    next_send: u64,
    next_receive: u64,
    poisoned: bool,
}

impl<T: Read + Write> AuthenticatedConnection<T> {
    pub fn connect(
        mut io: T,
        run_id: &str,
        local: ValidatorId,
        expected_remote: ValidatorId,
        signing_key: &SigningKey,
        validator_set: &ValidatorSet,
        key_roles: &ValidatorKeyRoleRegistryV1,
        transport_context: RunTransportContext,
    ) -> Result<Self, FrameError> {
        let session = client_handshake(
            &mut io,
            run_id,
            local,
            expected_remote,
            signing_key,
            validator_set,
            key_roles,
            transport_context,
        )?;
        Ok(Self {
            io,
            local,
            session,
            run_id: run_id.to_owned(),
            signing_key: signing_key.clone(),
            key_roles: key_roles.clone(),
            transport_context,
            next_send: 0,
            next_receive: 0,
            poisoned: false,
        })
    }

    pub fn accept(
        mut io: T,
        run_id: &str,
        local: ValidatorId,
        signing_key: &SigningKey,
        validator_set: &ValidatorSet,
        key_roles: &ValidatorKeyRoleRegistryV1,
        transport_context: RunTransportContext,
    ) -> Result<Self, FrameError> {
        let session = server_handshake(
            &mut io,
            run_id,
            local,
            signing_key,
            validator_set,
            key_roles,
            transport_context,
        )?;
        Ok(Self {
            io,
            local,
            session,
            run_id: run_id.to_owned(),
            signing_key: signing_key.clone(),
            key_roles: key_roles.clone(),
            transport_context,
            next_send: 0,
            next_receive: 0,
            poisoned: false,
        })
    }

    pub const fn remote(&self) -> ValidatorId {
        self.session.remote
    }

    pub const fn session_id(&self) -> [u8; 32] {
        self.session.session
    }

    /// Digest of the receiver challenge and initiator hello.  It is a
    /// transport-level freshness witness; callers must still keep a bounded
    /// replay window before granting a process-local lease.
    pub const fn handshake_nonce_binding(&self) -> [u8; 32] {
        self.session.nonce_binding
    }

    pub const fn topology_sha256(&self) -> [u8; 32] {
        self.transport_context.topology_sha256
    }

    /// Returns the explicit epoch/set binding carried by the handshake
    /// context.  `None` denotes a legacy fixture context and is rejected by
    /// the D0 admission helper.
    pub const fn validator_set_binding(&self) -> Option<(u64, [u8; 32])> {
        self.transport_context.validator_set_binding()
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn io_mut(&mut self) -> &mut T {
        &mut self.io
    }

    pub fn send(&mut self, kind: FrameKind, payload: Vec<u8>) -> Result<(), FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        let next_send = self.next_send.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
            FrameError::Replay
        })?;
        let frame = AuthenticatedFrame {
            sender: self.local,
            session: self.session.session,
            sequence: self.next_send,
            kind,
            payload,
        };
        if let Err(error) = write_framed(&mut self.io, &frame, &self.run_id, &self.signing_key) {
            self.poisoned = true;
            return Err(error);
        }
        self.next_send = next_send;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<AuthenticatedFrame, FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        let next_receive = self.next_receive.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
            FrameError::Replay
        })?;
        let frame = match read_framed(&mut self.io, &self.run_id, &self.key_roles) {
            Ok(frame) => frame,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if frame.sender != self.session.remote
            || frame.session != self.session.session
            || frame.sequence != self.next_receive
        {
            self.poisoned = true;
            return Err(FrameError::Replay);
        }
        self.next_receive = next_receive;
        Ok(frame)
    }
}

/// Authenticated transport connection backed by an externally owned P2P
/// identity producer.  This parallel type intentionally does not expose a
/// constructor accepting a local secret; the caller must provide the public
/// role key through the producer and the constructor checks it against the
/// committed key-role registry before touching the handshake stream.
pub struct ExternallySignedAuthenticatedConnectionV1<T> {
    io: T,
    local: ValidatorId,
    session: ConnectionSession,
    run_id: String,
    producer: Box<dyn P2pIdentitySignatureProducerV1>,
    key_roles: ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
    network_context_digest: [u8; 32],
    expected_public_key: [u8; 32],
    next_send: u64,
    next_receive: u64,
    poisoned: bool,
}

impl<T: Read + Write> ExternallySignedAuthenticatedConnectionV1<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        mut io: T,
        run_id: &str,
        local: ValidatorId,
        expected_remote: ValidatorId,
        mut producer: Box<dyn P2pIdentitySignatureProducerV1>,
        validator_set: &ValidatorSet,
        key_roles: &ValidatorKeyRoleRegistryV1,
        transport_context: RunTransportContext,
    ) -> Result<Self, FrameError> {
        require_external_identity(local, producer.as_ref(), key_roles)?;
        let expected_public_key = key_roles
            .p2p_identity_public_key(local)
            .ok_or(FrameError::UnknownSender)?;
        let network_context_digest =
            network_context_digest(validator_set, key_roles, transport_context);
        let session = client_handshake_with_external_identity(
            &mut io,
            run_id,
            local,
            expected_remote,
            producer.as_mut(),
            validator_set,
            key_roles,
            transport_context,
        )?;
        Ok(Self {
            io,
            local,
            session,
            run_id: run_id.to_owned(),
            producer,
            key_roles: key_roles.clone(),
            transport_context,
            network_context_digest,
            expected_public_key,
            next_send: 0,
            next_receive: 0,
            poisoned: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        mut io: T,
        run_id: &str,
        local: ValidatorId,
        mut producer: Box<dyn P2pIdentitySignatureProducerV1>,
        validator_set: &ValidatorSet,
        key_roles: &ValidatorKeyRoleRegistryV1,
        transport_context: RunTransportContext,
    ) -> Result<Self, FrameError> {
        require_external_identity(local, producer.as_ref(), key_roles)?;
        let expected_public_key = key_roles
            .p2p_identity_public_key(local)
            .ok_or(FrameError::UnknownSender)?;
        let network_context_digest =
            network_context_digest(validator_set, key_roles, transport_context);
        let session = server_handshake_with_external_identity(
            &mut io,
            run_id,
            local,
            producer.as_mut(),
            validator_set,
            key_roles,
            transport_context,
        )?;
        Ok(Self {
            io,
            local,
            session,
            run_id: run_id.to_owned(),
            producer,
            key_roles: key_roles.clone(),
            transport_context,
            network_context_digest,
            expected_public_key,
            next_send: 0,
            next_receive: 0,
            poisoned: false,
        })
    }

    pub const fn remote(&self) -> ValidatorId {
        self.session.remote
    }

    pub const fn session_id(&self) -> [u8; 32] {
        self.session.session
    }

    pub const fn handshake_nonce_binding(&self) -> [u8; 32] {
        self.session.nonce_binding
    }

    pub const fn validator_set_binding(&self) -> Option<(u64, [u8; 32])> {
        self.transport_context.validator_set_binding()
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn send(&mut self, kind: FrameKind, payload: Vec<u8>) -> Result<(), FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        let next_send = self.next_send.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
            FrameError::Replay
        })?;
        let frame = AuthenticatedFrame {
            sender: self.local,
            session: self.session.session,
            sequence: self.next_send,
            kind,
            payload,
        };
        if let Err(error) = write_framed_with_external_identity(
            &mut self.io,
            &frame,
            &self.run_id,
            self.session.remote,
            self.network_context_digest,
            self.session.nonce_binding,
            self.expected_public_key,
            self.producer.as_mut(),
        ) {
            self.poisoned = true;
            return Err(error);
        }
        self.next_send = next_send;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<AuthenticatedFrame, FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        let next_receive = self.next_receive.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
            FrameError::Replay
        })?;
        let frame = match read_framed(&mut self.io, &self.run_id, &self.key_roles) {
            Ok(frame) => frame,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if frame.sender != self.session.remote
            || frame.session != self.session.session
            || frame.sequence != self.next_receive
        {
            self.poisoned = true;
            return Err(FrameError::Replay);
        }
        self.next_receive = next_receive;
        Ok(frame)
    }
}

pub fn server_handshake(
    io: &mut (impl Read + Write),
    run_id: &str,
    local: ValidatorId,
    signing_key: &SigningKey,
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
) -> Result<ConnectionSession, FrameError> {
    require_local_key(local, signing_key, key_roles)?;
    let mut receiver_nonce = [0u8; 32];
    getrandom::getrandom(&mut receiver_nonce)
        .map_err(|_| FrameError::Malformed("receiver entropy unavailable"))?;
    let challenge = encode_challenge(
        run_id,
        local,
        network_context_digest(validator_set, key_roles, transport_context),
        receiver_nonce,
        signing_key,
    )?;
    write_record(io, &challenge)?;
    let hello = read_record(io)?;
    let session = decode_hello(
        &hello,
        run_id,
        local,
        receiver_nonce,
        validator_set,
        key_roles,
        transport_context,
    )?;
    let finished = encode_finished(
        run_id,
        local,
        session.remote,
        network_context_digest(validator_set, key_roles, transport_context),
        session.session,
        &challenge,
        &hello,
        signing_key,
    )?;
    write_record(io, &finished)?;
    Ok(session)
}

pub fn client_handshake(
    io: &mut (impl Read + Write),
    run_id: &str,
    local: ValidatorId,
    expected_remote: ValidatorId,
    signing_key: &SigningKey,
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
) -> Result<ConnectionSession, FrameError> {
    require_local_key(local, signing_key, key_roles)?;
    let challenge = read_record(io)?;
    let receiver_nonce = decode_challenge(
        &challenge,
        run_id,
        expected_remote,
        validator_set,
        key_roles,
        transport_context,
    )?;
    let mut sender_nonce = [0u8; 32];
    getrandom::getrandom(&mut sender_nonce)
        .map_err(|_| FrameError::Malformed("initiator entropy unavailable"))?;
    let hello = encode_hello(
        run_id,
        local,
        expected_remote,
        network_context_digest(validator_set, key_roles, transport_context),
        receiver_nonce,
        sender_nonce,
        signing_key,
    )?;
    write_record(io, &hello)?;
    let session = ConnectionSession {
        remote: expected_remote,
        session: derive_session(
            run_id,
            local,
            expected_remote,
            network_context_digest(validator_set, key_roles, transport_context),
            receiver_nonce,
            sender_nonce,
        ),
        nonce_binding: derive_nonce_binding(receiver_nonce, sender_nonce),
    };
    let finished = read_record(io)?;
    decode_finished(
        &finished,
        run_id,
        expected_remote,
        local,
        session.session,
        &challenge,
        &hello,
        validator_set,
        key_roles,
        transport_context,
    )?;
    Ok(session)
}

/// Receiver side of the typed external P2P identity handshake.  The producer
/// key is authenticated against the committed role registry before the
/// challenge is generated or written.
pub fn server_handshake_with_external_identity(
    io: &mut (impl Read + Write),
    run_id: &str,
    local: ValidatorId,
    producer: &mut dyn P2pIdentitySignatureProducerV1,
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
) -> Result<ConnectionSession, FrameError> {
    require_external_identity(local, producer, key_roles)?;
    let expected_public_key = key_roles
        .p2p_identity_public_key(local)
        .ok_or(FrameError::UnknownSender)?;
    let context_digest = network_context_digest(validator_set, key_roles, transport_context);
    let mut receiver_nonce = [0u8; 32];
    getrandom::getrandom(&mut receiver_nonce)
        .map_err(|_| FrameError::Malformed("receiver entropy unavailable"))?;
    let challenge = encode_challenge_with_external_identity(
        run_id,
        local,
        context_digest,
        receiver_nonce,
        expected_public_key,
        producer,
    )?;
    write_record(io, &challenge)?;
    let hello = read_record(io)?;
    let session = decode_hello(
        &hello,
        run_id,
        local,
        receiver_nonce,
        validator_set,
        key_roles,
        transport_context,
    )?;
    let finished = encode_finished_with_external_identity(
        run_id,
        local,
        session.remote,
        context_digest,
        session,
        &challenge,
        &hello,
        expected_public_key,
        producer,
    )?;
    write_record(io, &finished)?;
    Ok(session)
}

/// Initiator side of the typed external P2P identity handshake.
#[allow(clippy::too_many_arguments)]
pub fn client_handshake_with_external_identity(
    io: &mut (impl Read + Write),
    run_id: &str,
    local: ValidatorId,
    expected_remote: ValidatorId,
    producer: &mut dyn P2pIdentitySignatureProducerV1,
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
) -> Result<ConnectionSession, FrameError> {
    require_external_identity(local, producer, key_roles)?;
    let expected_public_key = key_roles
        .p2p_identity_public_key(local)
        .ok_or(FrameError::UnknownSender)?;
    let challenge = read_record(io)?;
    let receiver_nonce = decode_challenge(
        &challenge,
        run_id,
        expected_remote,
        validator_set,
        key_roles,
        transport_context,
    )?;
    let mut sender_nonce = [0u8; 32];
    getrandom::getrandom(&mut sender_nonce)
        .map_err(|_| FrameError::Malformed("initiator entropy unavailable"))?;
    let context_digest = network_context_digest(validator_set, key_roles, transport_context);
    let session = ConnectionSession {
        remote: expected_remote,
        session: derive_session(
            run_id,
            local,
            expected_remote,
            context_digest,
            receiver_nonce,
            sender_nonce,
        ),
        nonce_binding: derive_nonce_binding(receiver_nonce, sender_nonce),
    };
    let hello = encode_hello_with_external_identity(
        run_id,
        local,
        expected_remote,
        context_digest,
        receiver_nonce,
        sender_nonce,
        session,
        expected_public_key,
        producer,
    )?;
    write_record(io, &hello)?;
    let finished = read_record(io)?;
    decode_finished(
        &finished,
        run_id,
        expected_remote,
        local,
        session.session,
        &challenge,
        &hello,
        validator_set,
        key_roles,
        transport_context,
    )?;
    Ok(session)
}

fn encode_challenge_with_external_identity(
    run_id: &str,
    receiver: ValidatorId,
    network_context_digest: [u8; 32],
    receiver_nonce: [u8; 32],
    expected_public_key: [u8; 32],
    producer: &mut dyn P2pIdentitySignatureProducerV1,
) -> Result<Vec<u8>, FrameError> {
    let mut body = handshake_prefix(CHALLENGE_TAG, run_id)?;
    body.extend_from_slice(receiver.as_bytes());
    body.extend_from_slice(&network_context_digest);
    body.extend_from_slice(&receiver_nonce);
    let root = signing_root(CHALLENGE_DOMAIN, &body);
    let request = P2pIdentitySignatureRequestV1::new(
        P2pIdentitySignaturePurposeV1::Challenge,
        receiver,
        None,
        run_id_sha256_v1(run_id),
        network_context_digest,
        [0; 32],
        receiver_nonce,
        root,
    )
    .map_err(FrameError::ExternalIdentity)?;
    body.extend_from_slice(&sign_external_identity_request(
        producer,
        request,
        expected_public_key,
    )?);
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
fn encode_hello_with_external_identity(
    run_id: &str,
    sender: ValidatorId,
    receiver: ValidatorId,
    network_context_digest: [u8; 32],
    receiver_nonce: [u8; 32],
    sender_nonce: [u8; 32],
    session: ConnectionSession,
    expected_public_key: [u8; 32],
    producer: &mut dyn P2pIdentitySignatureProducerV1,
) -> Result<Vec<u8>, FrameError> {
    let mut body = handshake_prefix(HELLO_TAG, run_id)?;
    body.extend_from_slice(sender.as_bytes());
    body.extend_from_slice(receiver.as_bytes());
    body.extend_from_slice(&network_context_digest);
    body.extend_from_slice(&receiver_nonce);
    body.extend_from_slice(&sender_nonce);
    let root = signing_root(HELLO_DOMAIN, &body);
    let request = P2pIdentitySignatureRequestV1::new(
        P2pIdentitySignaturePurposeV1::Hello,
        sender,
        Some(receiver),
        run_id_sha256_v1(run_id),
        network_context_digest,
        session.session,
        session.nonce_binding,
        root,
    )
    .map_err(FrameError::ExternalIdentity)?;
    body.extend_from_slice(&sign_external_identity_request(
        producer,
        request,
        expected_public_key,
    )?);
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
fn encode_finished_with_external_identity(
    run_id: &str,
    sender: ValidatorId,
    receiver: ValidatorId,
    network_context_digest: [u8; 32],
    session: ConnectionSession,
    challenge: &[u8],
    hello: &[u8],
    expected_public_key: [u8; 32],
    producer: &mut dyn P2pIdentitySignatureProducerV1,
) -> Result<Vec<u8>, FrameError> {
    let mut body = handshake_prefix(FINISHED_TAG, run_id)?;
    body.extend_from_slice(sender.as_bytes());
    body.extend_from_slice(receiver.as_bytes());
    body.extend_from_slice(&network_context_digest);
    body.extend_from_slice(&session.session);
    body.extend_from_slice(&transcript_hash(challenge, hello));
    let root = signing_root(FINISHED_DOMAIN, &body);
    let request = P2pIdentitySignatureRequestV1::new(
        P2pIdentitySignaturePurposeV1::Finished,
        sender,
        Some(receiver),
        run_id_sha256_v1(run_id),
        network_context_digest,
        session.session,
        session.nonce_binding,
        root,
    )
    .map_err(FrameError::ExternalIdentity)?;
    body.extend_from_slice(&sign_external_identity_request(
        producer,
        request,
        expected_public_key,
    )?);
    Ok(body)
}

fn sign_external_identity_request(
    producer: &mut dyn P2pIdentitySignatureProducerV1,
    request: P2pIdentitySignatureRequestV1,
    expected_public_key: [u8; 32],
) -> Result<[u8; 64], FrameError> {
    let signature = producer
        .sign_v1(request)
        .map_err(FrameError::ExternalIdentity)?;
    let public_key =
        VerifyingKey::from_bytes(&expected_public_key).map_err(|_| FrameError::InvalidSignature)?;
    public_key
        .verify_strict(&request.signing_root(), &Signature::from_bytes(&signature))
        .map_err(|_| FrameError::InvalidSignature)?;
    Ok(signature)
}

fn encode_challenge(
    run_id: &str,
    receiver: ValidatorId,
    network_context_digest: [u8; 32],
    receiver_nonce: [u8; 32],
    key: &SigningKey,
) -> Result<Vec<u8>, FrameError> {
    let mut body = handshake_prefix(CHALLENGE_TAG, run_id)?;
    body.extend_from_slice(receiver.as_bytes());
    body.extend_from_slice(&network_context_digest);
    body.extend_from_slice(&receiver_nonce);
    body.extend_from_slice(&key.sign(&signing_root(CHALLENGE_DOMAIN, &body)).to_bytes());
    Ok(body)
}

fn decode_challenge(
    body: &[u8],
    run_id: &str,
    expected_receiver: ValidatorId,
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
) -> Result<[u8; 32], FrameError> {
    let mut cursor = HandshakeCursor::new(body);
    cursor.prefix(CHALLENGE_TAG, run_id)?;
    let receiver = ValidatorId::new(cursor.array("challenge receiver")?);
    if receiver != expected_receiver {
        return Err(FrameError::UnknownSender);
    }
    let context = cursor.array("challenge network-context digest")?;
    if context != network_context_digest(validator_set, key_roles, transport_context) {
        return Err(FrameError::InvalidSignature);
    }
    let nonce = cursor.array("challenge nonce")?;
    let signature: [u8; 64] = cursor.array("challenge signature")?;
    cursor.finish()?;
    verify_record(
        CHALLENGE_DOMAIN,
        &body[..body.len() - 64],
        signature,
        receiver,
        key_roles,
    )?;
    Ok(nonce)
}

fn encode_hello(
    run_id: &str,
    sender: ValidatorId,
    receiver: ValidatorId,
    network_context_digest: [u8; 32],
    receiver_nonce: [u8; 32],
    sender_nonce: [u8; 32],
    key: &SigningKey,
) -> Result<Vec<u8>, FrameError> {
    let mut body = handshake_prefix(HELLO_TAG, run_id)?;
    body.extend_from_slice(sender.as_bytes());
    body.extend_from_slice(receiver.as_bytes());
    body.extend_from_slice(&network_context_digest);
    body.extend_from_slice(&receiver_nonce);
    body.extend_from_slice(&sender_nonce);
    body.extend_from_slice(&key.sign(&signing_root(HELLO_DOMAIN, &body)).to_bytes());
    Ok(body)
}

fn decode_hello(
    body: &[u8],
    run_id: &str,
    local: ValidatorId,
    expected_receiver_nonce: [u8; 32],
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
) -> Result<ConnectionSession, FrameError> {
    let mut cursor = HandshakeCursor::new(body);
    cursor.prefix(HELLO_TAG, run_id)?;
    let sender = ValidatorId::new(cursor.array("hello sender")?);
    let receiver = ValidatorId::new(cursor.array("hello receiver")?);
    let network_context = cursor.array("hello network-context digest")?;
    let receiver_nonce = cursor.array("hello receiver nonce")?;
    let sender_nonce = cursor.array("hello sender nonce")?;
    let signature: [u8; 64] = cursor.array("hello signature")?;
    cursor.finish()?;
    if receiver != local
        || network_context != network_context_digest(validator_set, key_roles, transport_context)
        || receiver_nonce != expected_receiver_nonce
        || sender == local
    {
        return Err(FrameError::InvalidSignature);
    }
    verify_record(
        HELLO_DOMAIN,
        &body[..body.len() - 64],
        signature,
        sender,
        key_roles,
    )?;
    Ok(ConnectionSession {
        remote: sender,
        session: derive_session(
            run_id,
            sender,
            receiver,
            network_context,
            receiver_nonce,
            sender_nonce,
        ),
        nonce_binding: derive_nonce_binding(receiver_nonce, sender_nonce),
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_finished(
    run_id: &str,
    sender: ValidatorId,
    receiver: ValidatorId,
    network_context_digest: [u8; 32],
    session: [u8; 32],
    challenge: &[u8],
    hello: &[u8],
    key: &SigningKey,
) -> Result<Vec<u8>, FrameError> {
    let mut body = handshake_prefix(FINISHED_TAG, run_id)?;
    body.extend_from_slice(sender.as_bytes());
    body.extend_from_slice(receiver.as_bytes());
    body.extend_from_slice(&network_context_digest);
    body.extend_from_slice(&session);
    body.extend_from_slice(&transcript_hash(challenge, hello));
    body.extend_from_slice(&key.sign(&signing_root(FINISHED_DOMAIN, &body)).to_bytes());
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
fn decode_finished(
    body: &[u8],
    run_id: &str,
    expected_sender: ValidatorId,
    expected_receiver: ValidatorId,
    expected_session: [u8; 32],
    challenge: &[u8],
    hello: &[u8],
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    transport_context: RunTransportContext,
) -> Result<(), FrameError> {
    let mut cursor = HandshakeCursor::new(body);
    cursor.prefix(FINISHED_TAG, run_id)?;
    let sender = ValidatorId::new(cursor.array("finished sender")?);
    let receiver = ValidatorId::new(cursor.array("finished receiver")?);
    let network_context = cursor.array("finished network-context digest")?;
    let session = cursor.array("finished session")?;
    let transcript = cursor.array("finished transcript")?;
    let signature: [u8; 64] = cursor.array("finished signature")?;
    cursor.finish()?;
    if sender != expected_sender
        || receiver != expected_receiver
        || network_context != network_context_digest(validator_set, key_roles, transport_context)
        || session != expected_session
        || transcript != transcript_hash(challenge, hello)
    {
        return Err(FrameError::InvalidSignature);
    }
    verify_record(
        FINISHED_DOMAIN,
        &body[..body.len() - 64],
        signature,
        sender,
        key_roles,
    )
}

fn require_local_key(
    local: ValidatorId,
    key: &SigningKey,
    key_roles: &ValidatorKeyRoleRegistryV1,
) -> Result<(), FrameError> {
    let expected = key_roles
        .p2p_identity_public_key(local)
        .ok_or(FrameError::UnknownSender)?;
    if expected != key.verifying_key().to_bytes() {
        return Err(FrameError::InvalidSignature);
    }
    Ok(())
}

fn require_external_identity(
    local: ValidatorId,
    producer: &dyn P2pIdentitySignatureProducerV1,
    key_roles: &ValidatorKeyRoleRegistryV1,
) -> Result<(), FrameError> {
    let expected = key_roles
        .p2p_identity_public_key(local)
        .ok_or(FrameError::UnknownSender)?;
    if expected != producer.public_key_v1() {
        return Err(FrameError::InvalidSignature);
    }
    Ok(())
}

fn verify_record(
    domain: &[u8],
    body: &[u8],
    signature: [u8; 64],
    author: ValidatorId,
    key_roles: &ValidatorKeyRoleRegistryV1,
) -> Result<(), FrameError> {
    let public_key = key_roles
        .p2p_identity_public_key(author)
        .ok_or(FrameError::UnknownSender)?;
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| FrameError::InvalidSignature)?;
    key.verify_strict(
        &signing_root(domain, body),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| FrameError::InvalidSignature)
}

fn handshake_prefix(tag: u8, run_id: &str) -> Result<Vec<u8>, FrameError> {
    validate_run_id_bytes(run_id.as_bytes())?;
    let run_length = u16::try_from(run_id.len()).map_err(|_| FrameError::TooLarge)?;
    let mut output = Vec::with_capacity(16 + run_id.len());
    output.extend_from_slice(HANDSHAKE_MAGIC);
    output.extend_from_slice(&HANDSHAKE_VERSION.to_be_bytes());
    output.push(tag);
    output.extend_from_slice(&run_length.to_be_bytes());
    output.extend_from_slice(run_id.as_bytes());
    Ok(output)
}

fn transcript_hash(challenge: &[u8], hello: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hasher.update((challenge.len() as u64).to_be_bytes());
    hasher.update(challenge);
    hasher.update((hello.len() as u64).to_be_bytes());
    hasher.update(hello);
    hasher.finalize().into()
}

fn derive_session(
    run_id: &str,
    sender: ValidatorId,
    receiver: ValidatorId,
    network_context_digest: [u8; 32],
    receiver_nonce: [u8; 32],
    sender_nonce: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_DOMAIN);
    hasher.update((run_id.len() as u64).to_be_bytes());
    hasher.update(run_id.as_bytes());
    hasher.update(sender.as_bytes());
    hasher.update(receiver.as_bytes());
    hasher.update(network_context_digest);
    hasher.update(receiver_nonce);
    hasher.update(sender_nonce);
    hasher.finalize().into()
}

fn derive_nonce_binding(receiver_nonce: [u8; 32], sender_nonce: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-g3.handshake-nonce-binding.v1");
    hasher.update(receiver_nonce);
    hasher.update(sender_nonce);
    hasher.finalize().into()
}

fn network_context_digest(
    validator_set: &ValidatorSet,
    key_roles: &ValidatorKeyRoleRegistryV1,
    context: RunTransportContext,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NETWORK_CONTEXT_DOMAIN);
    hasher.update(validator_set.id().as_bytes());
    hasher.update(key_roles.digest_v1());
    hasher.update(context.topology_sha256);
    hasher.update(context.candidate_source_sha256);
    hasher.update(context.binary_sha256);
    hasher.update(context.coordinator_manifest_sha256);
    match context.validator_set_binding() {
        Some((epoch, set_id)) => {
            hasher.update(EPOCH_SET_BINDING_DOMAIN);
            hasher.update(epoch.to_be_bytes());
            hasher.update(set_id);
        }
        None => {}
    }
    if let Some(config_sha256) = context.node_config_binding() {
        hasher.update(NODE_CONFIG_BINDING_DOMAIN);
        hasher.update(config_sha256);
    }
    hasher.finalize().into()
}

fn signing_root(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn write_record(writer: &mut impl Write, body: &[u8]) -> Result<(), FrameError> {
    if body.is_empty() || body.len() > MAX_HANDSHAKE_BYTES {
        return Err(FrameError::TooLarge);
    }
    writer.write_all(&(body.len() as u16).to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

fn read_record(reader: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    let mut length = [0u8; 2];
    reader.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_HANDSHAKE_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

struct HandshakeCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> HandshakeCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn prefix(&mut self, tag: u8, run_id: &str) -> Result<(), FrameError> {
        if self.take(8, "handshake magic")? != HANDSHAKE_MAGIC
            || u16::from_be_bytes(self.array("handshake version")?) != HANDSHAKE_VERSION
            || self.take(1, "handshake tag")?[0] != tag
        {
            return Err(FrameError::Malformed("wrong handshake prefix"));
        }
        let run_length = u16::from_be_bytes(self.array("handshake run length")?) as usize;
        if self.take(run_length, "handshake run ID")? != run_id.as_bytes() {
            return Err(FrameError::WrongRun);
        }
        Ok(())
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], FrameError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FrameError::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FrameError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], FrameError> {
        Ok(self
            .take(N, field)?
            .try_into()
            .expect("handshake exact array length"))
    }

    fn finish(self) -> Result<(), FrameError> {
        if self.offset != self.bytes.len() {
            return Err(FrameError::Malformed("trailing handshake bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use crate::key_roles::{ValidatorKeyRoleBindingV1, ValidatorKeyRoleRegistryV1};
    use crate::p2p_identity::P2pIdentityErrorV1;
    use sha2::{Digest, Sha256};
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;

    const TEST_TRANSPORT_CONTEXT: RunTransportContext =
        RunTransportContext::new([0x74; 32], [0x75; 32], [0x76; 32], [0x77; 32]);

    struct RecordingExternalIdentityProducerV1 {
        key: SigningKey,
        requests: Arc<Mutex<Vec<P2pIdentitySignatureRequestV1>>>,
    }

    impl RecordingExternalIdentityProducerV1 {
        fn new(key: SigningKey, requests: Arc<Mutex<Vec<P2pIdentitySignatureRequestV1>>>) -> Self {
            Self { key, requests }
        }
    }

    impl P2pIdentitySignatureProducerV1 for RecordingExternalIdentityProducerV1 {
        fn public_key_v1(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }

        fn sign_v1(
            &mut self,
            request: P2pIdentitySignatureRequestV1,
        ) -> Result<[u8; 64], P2pIdentityErrorV1> {
            self.requests.lock().unwrap().push(request);
            Ok(self.key.sign(&request.signing_root()).to_bytes())
        }
    }

    fn fixture() -> (
        SigningKey,
        SigningKey,
        SigningKey,
        ValidatorId,
        ValidatorId,
        ValidatorSet,
        ValidatorKeyRoleRegistryV1,
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
            ChainId::new("trnm-poco-g3-transport-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
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
        (
            client_key,
            server_key,
            client_consensus_key,
            client,
            server,
            set,
            key_roles,
        )
    }

    #[test]
    fn fresh_challenge_authenticates_both_ends_and_frames() {
        let (client_key, server_key, _, client, server, set, key_roles) = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_set = set.clone();
        let server_key_roles = key_roles.clone();
        let run_id = "poco-g3-7-20260813T000000Z-1234abcd";
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut connection = AuthenticatedConnection::accept(
                stream,
                run_id,
                server,
                &server_key,
                &server_set,
                &server_key_roles,
                TEST_TRANSPORT_CONTEXT,
            )
            .unwrap();
            let frame = connection.receive().unwrap();
            assert_eq!(frame.kind, FrameKind::Health);
            assert_eq!(frame.payload, b"client-ready");
            connection
                .send(FrameKind::Health, b"server-ready".to_vec())
                .unwrap();
            connection.session_id()
        });
        let stream = TcpStream::connect(address).unwrap();
        let mut connection = AuthenticatedConnection::connect(
            stream,
            run_id,
            client,
            server,
            &client_key,
            &set,
            &key_roles,
            TEST_TRANSPORT_CONTEXT,
        )
        .unwrap();
        connection
            .send(FrameKind::Health, b"client-ready".to_vec())
            .unwrap();
        assert_eq!(connection.receive().unwrap().payload, b"server-ready");
        assert_eq!(connection.session_id(), server_thread.join().unwrap());
    }

    #[test]
    fn external_identity_producer_binds_challenge_session_and_frame() {
        let (client_key, server_key, _, client, server, set, key_roles) = fixture();
        let client_requests = Arc::new(Mutex::new(Vec::new()));
        let server_requests = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_set = set.clone();
        let server_key_roles = key_roles.clone();
        let server_requests_for_thread = Arc::clone(&server_requests);
        let run_id = "poco-g3-7-20260813T000000Z-1234abcd";
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut connection = ExternallySignedAuthenticatedConnectionV1::accept(
                stream,
                run_id,
                server,
                Box::new(RecordingExternalIdentityProducerV1::new(
                    server_key,
                    server_requests_for_thread,
                )),
                &server_set,
                &server_key_roles,
                TEST_TRANSPORT_CONTEXT,
            )
            .unwrap();
            let frame = connection.receive().unwrap();
            assert_eq!(frame.kind, FrameKind::Health);
            assert_eq!(frame.payload, b"client-ready");
            connection
                .send(FrameKind::Health, b"server-ready".to_vec())
                .unwrap();
            (
                connection.session_id(),
                connection.handshake_nonce_binding(),
            )
        });
        let stream = TcpStream::connect(address).unwrap();
        let mut connection = ExternallySignedAuthenticatedConnectionV1::connect(
            stream,
            run_id,
            client,
            server,
            Box::new(RecordingExternalIdentityProducerV1::new(
                client_key,
                Arc::clone(&client_requests),
            )),
            &set,
            &key_roles,
            TEST_TRANSPORT_CONTEXT,
        )
        .unwrap();
        connection
            .send(FrameKind::Health, b"client-ready".to_vec())
            .unwrap();
        assert_eq!(connection.receive().unwrap().payload, b"server-ready");
        let (server_session, server_nonce_binding) = server_thread.join().unwrap();
        assert_eq!(connection.session_id(), server_session);
        assert_eq!(connection.handshake_nonce_binding(), server_nonce_binding);
        assert_ne!(connection.session_id(), [0; 32]);
        assert_ne!(connection.handshake_nonce_binding(), [0; 32]);

        let client_requests = client_requests.lock().unwrap();
        assert!(client_requests.iter().any(|request| {
            request.purpose() == P2pIdentitySignaturePurposeV1::Hello
                && request.peer() == Some(server)
                && request.session() == connection.session_id()
                && request.nonce_binding() == connection.handshake_nonce_binding()
        }));
        assert!(client_requests.iter().any(|request| {
            request.purpose() == P2pIdentitySignaturePurposeV1::Frame
                && request.peer() == Some(server)
                && request.session() == connection.session_id()
                && request.nonce_binding() == connection.handshake_nonce_binding()
        }));
        let server_requests = server_requests.lock().unwrap();
        assert!(server_requests.iter().any(|request| {
            request.purpose() == P2pIdentitySignaturePurposeV1::Challenge
                && request.peer().is_none()
                && request.session() == [0; 32]
                && request.nonce_binding() != [0; 32]
        }));
        assert!(server_requests.iter().any(|request| {
            request.purpose() == P2pIdentitySignaturePurposeV1::Finished
                && request.peer() == Some(client)
                && request.session() == connection.session_id()
                && request.nonce_binding() == connection.handshake_nonce_binding()
        }));
    }

    #[test]
    fn external_identity_constructor_rejects_foreign_role_before_io() {
        let (client_key, _, _, client, server, set, key_roles) = fixture();
        let foreign_key = SigningKey::from_bytes(&[0x7f; 32]);
        let result = ExternallySignedAuthenticatedConnectionV1::connect(
            Cursor::new(Vec::<u8>::new()),
            "poco-g3-7-20260813T000000Z-1234abcd",
            client,
            server,
            Box::new(RecordingExternalIdentityProducerV1::new(
                foreign_key,
                Arc::new(Mutex::new(Vec::new())),
            )),
            &set,
            &key_roles,
            TEST_TRANSPORT_CONTEXT,
        );
        assert!(matches!(result, Err(FrameError::InvalidSignature)));
        // Keep the fixture key used by the surrounding tests type-checked and
        // make the no-I/O intent explicit: this branch never consumes it.
        assert_ne!(client_key.verifying_key().to_bytes(), [0; 32]);
    }

    #[test]
    fn each_receiver_challenge_produces_a_distinct_session() {
        let (client_key, server_key, _, client, server, set, key_roles) = fixture();
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server_set = set.clone();
            let server_key_roles = key_roles.clone();
            let server_key = server_key.clone();
            let thread = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                AuthenticatedConnection::accept(
                    stream,
                    "poco-g3-7-20260813T000000Z-1234abcd",
                    server,
                    &server_key,
                    &server_set,
                    &server_key_roles,
                    TEST_TRANSPORT_CONTEXT,
                )
                .unwrap()
                .session_id()
            });
            let stream = TcpStream::connect(address).unwrap();
            let client_session = AuthenticatedConnection::connect(
                stream,
                "poco-g3-7-20260813T000000Z-1234abcd",
                client,
                server,
                &client_key,
                &set,
                &key_roles,
                TEST_TRANSPORT_CONTEXT,
            )
            .unwrap()
            .session_id();
            assert_eq!(client_session, thread.join().unwrap());
            sessions.push(client_session);
        }
        assert_ne!(sessions[0], sessions[1]);
    }

    #[test]
    fn client_requires_server_finished_key_confirmation() {
        let (client_key, server_key, _, client, server, set, key_roles) = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let run_id = "poco-g3-7-20260813T000000Z-1234abcd";
        let server_set = set.clone();
        let server_key_roles = key_roles.clone();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let challenge = encode_challenge(
                run_id,
                server,
                network_context_digest(&server_set, &server_key_roles, TEST_TRANSPORT_CONTEXT),
                [0x91; 32],
                &server_key,
            )
            .unwrap();
            write_record(&mut stream, &challenge).unwrap();
            let _hello = read_record(&mut stream).unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        assert!(matches!(
            AuthenticatedConnection::connect(
                stream,
                run_id,
                client,
                server,
                &client_key,
                &set,
                &key_roles,
                TEST_TRANSPORT_CONTEXT,
            ),
            Err(FrameError::Io(_))
        ));
        thread.join().unwrap();
    }

    #[test]
    fn same_run_and_pair_keys_with_substituted_validator_set_are_rejected() {
        let (client_key, server_key, _, client, server, set, key_roles) = fixture();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let third_key = SigningKey::from_bytes(&[0x63; 32]);
        let alternate = ValidatorSet::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            parameters.hash(),
            vec![
                Validator::new(
                    client,
                    ConsensusPublicKey::new(client_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    server,
                    ConsensusPublicKey::new(server_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    ValidatorId::new([0x73; 32]),
                    ConsensusPublicKey::new(third_key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_ne!(set.id(), alternate.id());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let alternate_key_roles = key_roles.clone();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let challenge = encode_challenge(
                "poco-g3-7-20260813T000000Z-1234abcd",
                server,
                network_context_digest(&alternate, &alternate_key_roles, TEST_TRANSPORT_CONTEXT),
                [0x94; 32],
                &server_key,
            )
            .unwrap();
            write_record(&mut stream, &challenge).unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        assert!(matches!(
            AuthenticatedConnection::connect(
                stream,
                "poco-g3-7-20260813T000000Z-1234abcd",
                client,
                server,
                &client_key,
                &set,
                &key_roles,
                TEST_TRANSPORT_CONTEXT,
            ),
            Err(FrameError::InvalidSignature)
        ));
        thread.join().unwrap();
    }

    #[test]
    fn same_run_and_validator_set_with_substituted_topology_are_rejected() {
        let (client_key, server_key, _, client, server, set, key_roles) = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_set = set.clone();
        let server_key_roles = key_roles.clone();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let challenge = encode_challenge(
                "poco-g3-7-20260813T000000Z-1234abcd",
                server,
                network_context_digest(
                    &server_set,
                    &server_key_roles,
                    RunTransportContext::new([0x88; 32], [0x75; 32], [0x76; 32], [0x77; 32]),
                ),
                [0x95; 32],
                &server_key,
            )
            .unwrap();
            write_record(&mut stream, &challenge).unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        assert!(matches!(
            AuthenticatedConnection::connect(
                stream,
                "poco-g3-7-20260813T000000Z-1234abcd",
                client,
                server,
                &client_key,
                &set,
                &key_roles,
                TEST_TRANSPORT_CONTEXT,
            ),
            Err(FrameError::InvalidSignature)
        ));
        thread.join().unwrap();
    }

    #[test]
    fn tampered_finished_and_transcript_are_rejected() {
        let (client_key, server_key, _, client, server, set, key_roles) = fixture();
        for mode in ["signature", "transcript"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server_set = set.clone();
            let server_key_roles = key_roles.clone();
            let server_key = server_key.clone();
            let thread = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let nonce = [0x92; 32];
                let challenge = encode_challenge(
                    "poco-g3-7-20260813T000000Z-1234abcd",
                    server,
                    network_context_digest(&server_set, &server_key_roles, TEST_TRANSPORT_CONTEXT),
                    nonce,
                    &server_key,
                )
                .unwrap();
                write_record(&mut stream, &challenge).unwrap();
                let hello = read_record(&mut stream).unwrap();
                let session = decode_hello(
                    &hello,
                    "poco-g3-7-20260813T000000Z-1234abcd",
                    server,
                    nonce,
                    &server_set,
                    &server_key_roles,
                    TEST_TRANSPORT_CONTEXT,
                )
                .unwrap();
                let mut finished = encode_finished(
                    "poco-g3-7-20260813T000000Z-1234abcd",
                    server,
                    client,
                    network_context_digest(&server_set, &server_key_roles, TEST_TRANSPORT_CONTEXT),
                    session.session,
                    &challenge,
                    &hello,
                    &server_key,
                )
                .unwrap();
                if mode == "signature" {
                    *finished.last_mut().unwrap() ^= 1;
                } else {
                    let transcript_offset = finished.len() - 64 - 32;
                    finished[transcript_offset] ^= 1;
                }
                write_record(&mut stream, &finished).unwrap();
            });
            let stream = TcpStream::connect(address).unwrap();
            assert!(matches!(
                AuthenticatedConnection::connect(
                    stream,
                    "poco-g3-7-20260813T000000Z-1234abcd",
                    client,
                    server,
                    &client_key,
                    &set,
                    &key_roles,
                    TEST_TRANSPORT_CONTEXT,
                ),
                Err(FrameError::InvalidSignature)
            ));
            thread.join().unwrap();
        }
    }

    #[test]
    fn wrong_local_key_and_noncanonical_run_fail_before_handshake() {
        let (client_key, server_key, client_consensus_key, client, server, set, key_roles) =
            fixture();
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            server_handshake(
                &mut empty,
                "poco-g3-7-20260813T000000Z-1234abcd",
                server,
                &client_key,
                &set,
                &key_roles,
                TEST_TRANSPORT_CONTEXT,
            ),
            Err(FrameError::InvalidSignature)
        ));
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            server_handshake(
                &mut empty,
                "not valid!",
                server,
                &server_key,
                &set,
                &key_roles,
                TEST_TRANSPORT_CONTEXT,
            ),
            Err(FrameError::Malformed("non-canonical run ID"))
        ));
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            server_handshake(
                &mut empty,
                "poco-g3-7-20260813T000000Z-1234abcd",
                client,
                &client_consensus_key,
                &set,
                &key_roles,
                TEST_TRANSPORT_CONTEXT,
            ),
            Err(FrameError::InvalidSignature)
        ));
        assert_ne!(client, server);
    }

    struct PartialWriteFailure {
        writes: usize,
    }

    impl Read for PartialWriteFailure {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no input"))
        }
    }

    impl Write for PartialWriteFailure {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.writes == 0 {
                self.writes += 1;
                Ok(buffer.len().min(2))
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "uncertain write"))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "uncertain flush"))
        }
    }

    fn direct_connection<T>(
        io: T,
        local: ValidatorId,
        remote: ValidatorId,
        key: SigningKey,
        key_roles: ValidatorKeyRoleRegistryV1,
    ) -> AuthenticatedConnection<T> {
        AuthenticatedConnection {
            io,
            local,
            session: ConnectionSession {
                remote,
                session: [0xa5; 32],
                nonce_binding: [0xa6; 32],
            },
            run_id: "poco-g3-7-20260813T000000Z-1234abcd".to_owned(),
            signing_key: key,
            key_roles,
            transport_context: TEST_TRANSPORT_CONTEXT,
            next_send: 0,
            next_receive: 0,
            poisoned: false,
        }
    }

    #[test]
    fn uncertain_send_and_malformed_receive_permanently_poison_connection() {
        let (client_key, _, _, client, server, _set, key_roles) = fixture();
        let mut sender = direct_connection(
            PartialWriteFailure { writes: 0 },
            client,
            server,
            client_key.clone(),
            key_roles.clone(),
        );
        assert!(matches!(
            sender.send(FrameKind::Health, b"request".to_vec()),
            Err(FrameError::Io(_))
        ));
        assert!(sender.is_poisoned());
        assert!(matches!(
            sender.send(FrameKind::Health, b"retry".to_vec()),
            Err(FrameError::Poisoned)
        ));

        let mut receiver = direct_connection(
            Cursor::new(vec![0, 0, 0, 0]),
            client,
            server,
            client_key,
            key_roles,
        );
        assert!(matches!(receiver.receive(), Err(FrameError::TooLarge)));
        assert!(receiver.is_poisoned());
        assert!(matches!(receiver.receive(), Err(FrameError::Poisoned)));
    }

    #[test]
    fn exhausted_sequence_poisoning_precedes_any_io() {
        let (client_key, _, _, client, server, _set, key_roles) = fixture();
        let mut connection = direct_connection(
            Cursor::new(Vec::<u8>::new()),
            client,
            server,
            client_key,
            key_roles,
        );
        connection.next_send = u64::MAX;
        assert!(matches!(
            connection.send(FrameKind::Health, Vec::new()),
            Err(FrameError::Replay)
        ));
        assert_eq!(connection.io.position(), 0);
        assert!(connection.is_poisoned());
    }

    #[test]
    fn legacy_context_digest_is_byte_stable_while_bound_profile_changes() {
        let (_, _, _, _, _, set, key_roles) = fixture();
        let actual = network_context_digest(&set, &key_roles, TEST_TRANSPORT_CONTEXT);
        let mut legacy = Sha256::new();
        legacy.update(NETWORK_CONTEXT_DOMAIN);
        legacy.update(set.id().as_bytes());
        legacy.update(key_roles.digest_v1());
        legacy.update(TEST_TRANSPORT_CONTEXT.topology_sha256);
        legacy.update(TEST_TRANSPORT_CONTEXT.candidate_source_sha256);
        legacy.update(TEST_TRANSPORT_CONTEXT.binary_sha256);
        legacy.update(TEST_TRANSPORT_CONTEXT.coordinator_manifest_sha256);
        let expected: [u8; 32] = legacy.finalize().into();
        assert_eq!(actual, expected);

        let bound = TEST_TRANSPORT_CONTEXT
            .with_validator_set_binding(set.epoch().get(), set.id().into_bytes());
        assert_ne!(actual, network_context_digest(&set, &key_roles, bound));

        let node_bound = TEST_TRANSPORT_CONTEXT.with_node_config_binding([0x88; 32]);
        assert_ne!(actual, network_context_digest(&set, &key_roles, node_bound));
    }
}
