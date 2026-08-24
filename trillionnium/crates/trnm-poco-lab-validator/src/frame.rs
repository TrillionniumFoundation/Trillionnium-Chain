use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::ValidatorId;
#[cfg(test)]
use trnm_consensus_types::ValidatorSet;

use crate::key_roles::ValidatorKeyRoleRegistryV1;
use crate::p2p_identity::{
    P2pIdentityErrorV1, P2pIdentitySignatureProducerV1, P2pIdentitySignaturePurposeV1,
    P2pIdentitySignatureRequestV1,
};

pub trait P2pIdentityKeyResolverV1 {
    fn p2p_identity_public_key_v1(&self, validator_id: ValidatorId) -> Option<[u8; 32]>;
}

impl P2pIdentityKeyResolverV1 for ValidatorKeyRoleRegistryV1 {
    fn p2p_identity_public_key_v1(&self, validator_id: ValidatorId) -> Option<[u8; 32]> {
        self.p2p_identity_public_key(validator_id)
    }
}

// Frozen legacy fixtures predate the key-role registry. Normal builds expose
// no such resolver and the live transport can accept only the registry.
#[cfg(test)]
impl P2pIdentityKeyResolverV1 for ValidatorSet {
    fn p2p_identity_public_key_v1(&self, validator_id: ValidatorId) -> Option<[u8; 32]> {
        self.validator(validator_id)
            .map(|validator| validator.consensus_key().into_bytes())
    }
}

const FRAME_MAGIC: &[u8; 8] = b"TRNMG3F2";
const FRAME_VERSION: u16 = 2;
const FRAME_SIGNING_DOMAIN: &[u8] = b"trnm.poco-g3.authenticated-frame.v2";
pub const MAX_FRAME_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 6 * 1024 * 1024;
const SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Proposal = 1,
    Vote = 2,
    TimeoutVote = 3,
    QuorumCertificate = 4,
    TimeoutCertificate = 5,
    SubmitBatch = 6,
    Health = 7,
    /// Authenticated hop carrying one independently signed consensus
    /// statement across the frozen sparse topology.
    ConsensusRelay = 8,
    /// Independently origin-signed controlled-campaign Ready statement.
    FleetReady = 9,
    /// Independently origin-signed controlled-campaign Start statement.
    FleetStart = 10,
    /// Origin-authenticated request to enter the bounded restart quiesce
    /// protocol. This transport kind is not process-control authority.
    RestartPrepare = 11,
    /// Origin-authenticated declaration of one restart-safe durable cut.
    /// Semantic verification and N/N certification remain separate.
    RestartCut = 12,
    /// Origin-authenticated process-2 recovery readiness declaration.
    RestartRecoveryReady = 13,
    /// Origin-authenticated declaration that the common process-2 recovery
    /// start cut was observed. This frame does not activate a runtime.
    RestartRecoveryStart = 14,
    /// Dedicated process-2 catch-up wire carrier. Its inner origin signature,
    /// strict subtype decoder, and bounded admission live outside the generic
    /// consensus and five-phase restart collectors. Transport carriage alone
    /// grants no archive, journal, signer, or runtime authority.
    RestartCatchup = 15,
    /// Origin-authenticated acknowledgement that one validator has durably
    /// persisted the exact Cut/Park pair and committed its local park event.
    /// Transport carriage alone grants no handoff or recovery authority.
    RestartParkedAck = 16,
}

impl TryFrom<u8> for FrameKind {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Proposal),
            2 => Ok(Self::Vote),
            3 => Ok(Self::TimeoutVote),
            4 => Ok(Self::QuorumCertificate),
            5 => Ok(Self::TimeoutCertificate),
            6 => Ok(Self::SubmitBatch),
            7 => Ok(Self::Health),
            8 => Ok(Self::ConsensusRelay),
            9 => Ok(Self::FleetReady),
            10 => Ok(Self::FleetStart),
            11 => Ok(Self::RestartPrepare),
            12 => Ok(Self::RestartCut),
            13 => Ok(Self::RestartRecoveryReady),
            14 => Ok(Self::RestartRecoveryStart),
            15 => Ok(Self::RestartCatchup),
            16 => Ok(Self::RestartParkedAck),
            _ => Err(FrameError::Malformed("unknown frame kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedFrame {
    pub sender: ValidatorId,
    pub session: [u8; 32],
    pub sequence: u64,
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    TooLarge,
    Malformed(&'static str),
    WrongRun,
    UnknownSender,
    InvalidSignature,
    Replay,
    Poisoned,
    ExternalIdentity(P2pIdentityErrorV1),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "frame I/O: {error}"),
            Self::TooLarge => formatter.write_str("frame exceeds the bounded transport envelope"),
            Self::Malformed(reason) => write!(formatter, "malformed frame: {reason}"),
            Self::WrongRun => formatter.write_str("frame belongs to a different run"),
            Self::UnknownSender => formatter.write_str("frame sender is absent from validator set"),
            Self::InvalidSignature => {
                formatter.write_str("frame authentication signature is invalid")
            }
            Self::Replay => formatter.write_str("frame session/sequence was replayed or regressed"),
            Self::Poisoned => {
                formatter.write_str("authenticated connection is permanently poisoned")
            }
            Self::ExternalIdentity(error) => write!(formatter, "external P2P identity: {error}"),
        }
    }
}

/// Process-local, bounded replay admission for authenticated transport frames.
///
/// A validator may start a fresh random session after restart.  For each
/// sender the receiver retains at most `max_sessions_per_sender` sessions and
/// accepts only a strictly increasing sequence within each session. The
/// window fails closed when that bound is exhausted; it never evicts a session
/// and therefore never re-admits an old signed frame inside one process. This
/// is process-local ingress/DoS state, not consensus state. A validator runtime
/// MUST durably recover retired sessions or complete a receiver-authenticated
/// fresh-session handshake before accepting frames after restart. That
/// restart authority is intentionally absent from the current scaffold.
pub struct FrameReplayWindow {
    max_sessions_per_sender: usize,
    heads: BTreeMap<(ValidatorId, [u8; 32]), u64>,
    session_order: BTreeMap<ValidatorId, Vec<[u8; 32]>>,
}

impl FrameReplayWindow {
    pub fn new(max_sessions_per_sender: usize) -> Result<Self, FrameError> {
        if max_sessions_per_sender == 0 || max_sessions_per_sender > 8 {
            return Err(FrameError::Malformed("invalid replay-session bound"));
        }
        Ok(Self {
            max_sessions_per_sender,
            heads: BTreeMap::new(),
            session_order: BTreeMap::new(),
        })
    }

    pub fn admit(&mut self, frame: &AuthenticatedFrame) -> Result<(), FrameError> {
        validate_session_id(&frame.session)?;
        let key = (frame.sender, frame.session);
        if let Some(head) = self.heads.get_mut(&key) {
            if frame.sequence <= *head {
                return Err(FrameError::Replay);
            }
            *head = frame.sequence;
            return Ok(());
        }
        if frame.sequence != 0 {
            return Err(FrameError::Replay);
        }
        let sessions = self.session_order.entry(frame.sender).or_default();
        if sessions.len() == self.max_sessions_per_sender {
            return Err(FrameError::Replay);
        }
        sessions.push(frame.session);
        self.heads.insert(key, 0);
        Ok(())
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl AuthenticatedFrame {
    pub fn encode(&self, run_id: &str, key: &SigningKey) -> Result<Vec<u8>, FrameError> {
        validate_run_id_bytes(run_id.as_bytes())?;
        validate_session_id(&self.session)?;
        if self.sender.as_bytes().len() != 32 {
            return Err(FrameError::Malformed("G3 validator ID must be 32 bytes"));
        }
        if self.payload.len() > MAX_FRAME_PAYLOAD_BYTES {
            return Err(FrameError::TooLarge);
        }
        let run_len = u16::try_from(run_id.len()).map_err(|_| FrameError::TooLarge)?;
        let payload_len = u32::try_from(self.payload.len()).map_err(|_| FrameError::TooLarge)?;
        let body_len = 8usize
            .checked_add(2)
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(run_id.len()))
            .and_then(|value| value.checked_add(32 + 32 + 8 + 1 + 4))
            .and_then(|value| value.checked_add(self.payload.len()))
            .and_then(|value| value.checked_add(SIGNATURE_BYTES))
            .ok_or(FrameError::TooLarge)?;
        if body_len > MAX_FRAME_BODY_BYTES {
            return Err(FrameError::TooLarge);
        }
        let mut body = Vec::with_capacity(body_len);
        body.extend_from_slice(FRAME_MAGIC);
        body.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        body.extend_from_slice(&run_len.to_be_bytes());
        body.extend_from_slice(run_id.as_bytes());
        body.extend_from_slice(self.sender.as_bytes());
        body.extend_from_slice(&self.session);
        body.extend_from_slice(&self.sequence.to_be_bytes());
        body.push(self.kind as u8);
        body.extend_from_slice(&payload_len.to_be_bytes());
        body.extend_from_slice(&self.payload);
        let root = frame_signing_root(&body);
        body.extend_from_slice(&key.sign(&root).to_bytes());
        Ok(body)
    }

    /// Encodes a frame with a typed external P2P identity producer.  The
    /// producer receives the exact frame signing root plus the authenticated
    /// peer/session context; a returned signature is checked against the
    /// producer's public role key before the bytes are returned.
    pub fn encode_with_external_identity(
        &self,
        run_id: &str,
        remote: ValidatorId,
        network_context_digest: [u8; 32],
        nonce_binding: [u8; 32],
        expected_public_key: [u8; 32],
        producer: &mut dyn P2pIdentitySignatureProducerV1,
    ) -> Result<Vec<u8>, FrameError> {
        validate_run_id_bytes(run_id.as_bytes())?;
        validate_session_id(&self.session)?;
        if self.sender.as_bytes().len() != 32 || remote.is_zero() {
            return Err(FrameError::Malformed("G3 frame identity is invalid"));
        }
        if self.payload.len() > MAX_FRAME_PAYLOAD_BYTES {
            return Err(FrameError::TooLarge);
        }
        let run_len = u16::try_from(run_id.len()).map_err(|_| FrameError::TooLarge)?;
        let payload_len = u32::try_from(self.payload.len()).map_err(|_| FrameError::TooLarge)?;
        let body_len = 8usize
            .checked_add(2)
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(run_id.len()))
            .and_then(|value| value.checked_add(32 + 32 + 8 + 1 + 4))
            .and_then(|value| value.checked_add(self.payload.len()))
            .and_then(|value| value.checked_add(SIGNATURE_BYTES))
            .ok_or(FrameError::TooLarge)?;
        if body_len > MAX_FRAME_BODY_BYTES {
            return Err(FrameError::TooLarge);
        }
        let mut body = Vec::with_capacity(body_len);
        body.extend_from_slice(FRAME_MAGIC);
        body.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        body.extend_from_slice(&run_len.to_be_bytes());
        body.extend_from_slice(run_id.as_bytes());
        body.extend_from_slice(self.sender.as_bytes());
        body.extend_from_slice(&self.session);
        body.extend_from_slice(&self.sequence.to_be_bytes());
        body.push(self.kind as u8);
        body.extend_from_slice(&payload_len.to_be_bytes());
        body.extend_from_slice(&self.payload);
        let root = frame_signing_root(&body);
        let request = P2pIdentitySignatureRequestV1::new(
            P2pIdentitySignaturePurposeV1::Frame,
            self.sender,
            Some(remote),
            run_id_sha256_v1(run_id),
            network_context_digest,
            self.session,
            nonce_binding,
            root,
        )
        .map_err(FrameError::ExternalIdentity)?;
        let signature = producer
            .sign_v1(request)
            .map_err(FrameError::ExternalIdentity)?;
        let public_key = VerifyingKey::from_bytes(&expected_public_key)
            .map_err(|_| FrameError::InvalidSignature)?;
        public_key
            .verify_strict(&root, &Signature::from_bytes(&signature))
            .map_err(|_| FrameError::InvalidSignature)?;
        body.extend_from_slice(&signature);
        Ok(body)
    }

    pub fn decode(
        body: &[u8],
        expected_run_id: &str,
        key_roles: &impl P2pIdentityKeyResolverV1,
    ) -> Result<Self, FrameError> {
        if body.len() > MAX_FRAME_BODY_BYTES {
            return Err(FrameError::TooLarge);
        }
        if body.len() < 8 + 2 + 2 + 32 + 32 + 8 + 1 + 4 + SIGNATURE_BYTES {
            return Err(FrameError::Malformed("truncated fixed envelope"));
        }
        let mut cursor = 0usize;
        take_exact(body, &mut cursor, 8, "magic")?
            .eq(FRAME_MAGIC)
            .then_some(())
            .ok_or(FrameError::Malformed("wrong magic"))?;
        let version = u16::from_be_bytes(take_array(body, &mut cursor, "version")?);
        if version != FRAME_VERSION {
            return Err(FrameError::Malformed("wrong frame version"));
        }
        let run_len = u16::from_be_bytes(take_array(body, &mut cursor, "run length")?) as usize;
        let run = take_exact(body, &mut cursor, run_len, "run ID")?;
        validate_run_id_bytes(run)?;
        if run != expected_run_id.as_bytes() {
            return Err(FrameError::WrongRun);
        }
        let sender_bytes: [u8; 32] = take_array(body, &mut cursor, "sender")?;
        let sender = ValidatorId::new(sender_bytes);
        let p2p_identity_public_key = key_roles
            .p2p_identity_public_key_v1(sender)
            .ok_or(FrameError::UnknownSender)?;
        let session = take_array(body, &mut cursor, "session")?;
        validate_session_id(&session)?;
        let sequence = u64::from_be_bytes(take_array(body, &mut cursor, "sequence")?);
        let kind = FrameKind::try_from(
            *take_exact(body, &mut cursor, 1, "kind")?
                .first()
                .expect("one-byte kind"),
        )?;
        let payload_len =
            u32::from_be_bytes(take_array(body, &mut cursor, "payload length")?) as usize;
        if payload_len > MAX_FRAME_PAYLOAD_BYTES {
            return Err(FrameError::TooLarge);
        }
        let signed_end = cursor
            .checked_add(payload_len)
            .ok_or(FrameError::TooLarge)?;
        let payload = take_exact(body, &mut cursor, payload_len, "payload")?.to_vec();
        let signature_bytes: [u8; 64] = take_array(body, &mut cursor, "signature")?;
        if cursor != body.len() || signed_end + SIGNATURE_BYTES != body.len() {
            return Err(FrameError::Malformed("trailing frame bytes"));
        }
        let public_key = VerifyingKey::from_bytes(&p2p_identity_public_key)
            .map_err(|_| FrameError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let root = frame_signing_root(&body[..signed_end]);
        public_key
            .verify_strict(&root, &signature)
            .map_err(|_| FrameError::InvalidSignature)?;
        Ok(Self {
            sender,
            session,
            sequence,
            kind,
            payload,
        })
    }

    pub fn fingerprint(&self, run_id: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.poco-g3.frame-fingerprint.v1");
        hasher.update((run_id.len() as u64).to_be_bytes());
        hasher.update(run_id.as_bytes());
        hasher.update(self.sender.as_bytes());
        hasher.update(self.session);
        hasher.update(self.sequence.to_be_bytes());
        hasher.update([self.kind as u8]);
        hasher.update((self.payload.len() as u64).to_be_bytes());
        hasher.update(&self.payload);
        hasher.finalize().into()
    }
}

pub fn write_framed(
    writer: &mut impl Write,
    frame: &AuthenticatedFrame,
    run_id: &str,
    key: &SigningKey,
) -> Result<(), FrameError> {
    let body = frame.encode(run_id, key)?;
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn write_framed_with_external_identity(
    writer: &mut impl Write,
    frame: &AuthenticatedFrame,
    run_id: &str,
    remote: ValidatorId,
    network_context_digest: [u8; 32],
    nonce_binding: [u8; 32],
    expected_public_key: [u8; 32],
    producer: &mut dyn P2pIdentitySignatureProducerV1,
) -> Result<(), FrameError> {
    let body = frame.encode_with_external_identity(
        run_id,
        remote,
        network_context_digest,
        nonce_binding,
        expected_public_key,
        producer,
    )?;
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn read_framed(
    reader: &mut impl Read,
    expected_run_id: &str,
    key_roles: &ValidatorKeyRoleRegistryV1,
) -> Result<AuthenticatedFrame, FrameError> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BODY_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    AuthenticatedFrame::decode(&body, expected_run_id, key_roles)
}

fn frame_signing_root(signed_body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAME_SIGNING_DOMAIN);
    hasher.update((signed_body.len() as u64).to_be_bytes());
    hasher.update(signed_body);
    hasher.finalize().into()
}

pub(crate) fn run_id_sha256_v1(run_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-g3.external-p2p-run-id.v1");
    hasher.update((run_id.len() as u64).to_be_bytes());
    hasher.update(run_id.as_bytes());
    hasher.finalize().into()
}

fn take_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], FrameError> {
    let end = cursor.checked_add(length).ok_or(FrameError::TooLarge)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(FrameError::Malformed(field))?;
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<[u8; N], FrameError> {
    Ok(take_exact(bytes, cursor, N, field)?
        .try_into()
        .expect("exact array length"))
}

pub(crate) fn validate_run_id_bytes(value: &[u8]) -> Result<(), FrameError> {
    if value.is_empty()
        || value.len() > 80
        || !value.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'-' | b'T' | b'Z')
        })
    {
        return Err(FrameError::Malformed("non-canonical run ID"));
    }
    Ok(())
}

fn validate_session_id(value: &[u8; 32]) -> Result<(), FrameError> {
    if value == &[0; 32] {
        return Err(FrameError::Malformed("zero session ID"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_roles::{ValidatorKeyRoleBindingV1, ValidatorKeyRoleRegistryV1};
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    fn fixture() -> (
        SigningKey,
        SigningKey,
        ValidatorSet,
        ValidatorKeyRoleRegistryV1,
        ValidatorId,
    ) {
        let mut consensus_keys = (0..4)
            .map(|offset| SigningKey::from_bytes(&[0x42 + offset; 32]))
            .collect::<Vec<_>>();
        let mut p2p_keys = (0..4)
            .map(|offset| SigningKey::from_bytes(&[0x52 + offset; 32]))
            .collect::<Vec<_>>();
        let operator_keys = (0..4)
            .map(|offset| SigningKey::from_bytes(&[0x62 + offset; 32]))
            .collect::<Vec<_>>();
        let id = ValidatorId::new([0x11; 32]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let ids = [
            id,
            ValidatorId::new([0x12; 32]),
            ValidatorId::new([0x13; 32]),
            ValidatorId::new([0x14; 32]),
        ];
        let set = ValidatorSet::new(
            GenesisHash::new([0x22; 32]),
            ChainId::new("trnm-poco-g3-lab-v0").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            ids.iter()
                .zip(&consensus_keys)
                .map(|(validator_id, key)| {
                    Validator::new(
                        *validator_id,
                        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                        VotingPower::new(1).unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let key_roles = ValidatorKeyRoleRegistryV1::new(
            &set,
            ids.iter()
                .zip(&consensus_keys)
                .zip(&p2p_keys)
                .zip(&operator_keys)
                .map(|(((validator_id, consensus), p2p), operator)| {
                    ValidatorKeyRoleBindingV1::new(
                        *validator_id,
                        consensus.verifying_key().to_bytes(),
                        p2p.verifying_key().to_bytes(),
                        operator.verifying_key().to_bytes(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        (
            p2p_keys.remove(0),
            consensus_keys.remove(0),
            set,
            key_roles,
            id,
        )
    }

    #[test]
    fn frame_roundtrip_is_exact_and_authenticated() {
        let (key, consensus_key, _set, key_roles, id) = fixture();
        let frame = AuthenticatedFrame {
            sender: id,
            session: [0x55; 32],
            sequence: 7,
            kind: FrameKind::Vote,
            payload: b"real-vote".to_vec(),
        };
        let encoded = frame
            .encode("poco-g3-7-20260813T160000Z-0123abcd", &key)
            .unwrap();
        assert_eq!(
            AuthenticatedFrame::decode(
                &encoded,
                "poco-g3-7-20260813T160000Z-0123abcd",
                &key_roles,
            )
                .unwrap(),
            frame
        );
        assert_eq!(&encoded[..8], b"TRNMG3F2");
        assert_eq!(&encoded[8..10], &2u16.to_be_bytes());
        let substituted = frame
            .encode("poco-g3-7-20260813T160000Z-0123abcd", &consensus_key)
            .unwrap();
        assert!(matches!(
            AuthenticatedFrame::decode(
                &substituted,
                "poco-g3-7-20260813T160000Z-0123abcd",
                &key_roles,
            ),
            Err(FrameError::InvalidSignature)
        ));
        let mut mutated = encoded;
        let index = mutated.len() - 65;
        mutated[index] ^= 1;
        assert!(matches!(
            AuthenticatedFrame::decode(&mutated, "poco-g3-7-20260813T160000Z-0123abcd", &key_roles,),
            Err(FrameError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_run_trailing_and_oversize_fail_closed() {
        let (key, _consensus_key, _set, key_roles, id) = fixture();
        let frame = AuthenticatedFrame {
            sender: id,
            session: [0x55; 32],
            sequence: 8,
            kind: FrameKind::Health,
            payload: b"ok".to_vec(),
        };
        let mut encoded = frame
            .encode("poco-g3-7-20260813T160000Z-0123abcd", &key)
            .unwrap();
        assert!(matches!(
            AuthenticatedFrame::decode(&encoded, "poco-g3-7-20260813T160001Z-0123abcd", &key_roles,),
            Err(FrameError::WrongRun)
        ));
        encoded.push(0);
        assert!(matches!(
            AuthenticatedFrame::decode(&encoded, "poco-g3-7-20260813T160000Z-0123abcd", &key_roles,),
            Err(FrameError::Malformed(_))
        ));
        let oversize = AuthenticatedFrame {
            sender: id,
            session: [0x55; 32],
            sequence: 9,
            kind: FrameKind::SubmitBatch,
            payload: vec![0; MAX_FRAME_PAYLOAD_BYTES + 1],
        };
        assert!(matches!(
            oversize.encode("poco-g3-7-20260813T160000Z-0123abcd", &key),
            Err(FrameError::TooLarge)
        ));
        let zero_session = AuthenticatedFrame {
            session: [0; 32],
            ..frame
        };
        assert!(matches!(
            zero_session.encode("poco-g3-7-20260813T160000Z-0123abcd", &key),
            Err(FrameError::Malformed("zero session ID"))
        ));
        let mut replay_window = FrameReplayWindow::new(1).unwrap();
        assert!(matches!(
            replay_window.admit(&zero_session),
            Err(FrameError::Malformed("zero session ID"))
        ));
    }

    #[test]
    fn replay_window_requires_zero_start_and_strict_sequence() {
        let (key, _consensus_key, set, key_roles, _) = fixture();
        let mut window = FrameReplayWindow::new(2).unwrap();
        let mut frame = AuthenticatedFrame {
            sender: set.validators()[0].id(),
            session: [7; 32],
            sequence: 0,
            kind: FrameKind::Health,
            payload: b"health".to_vec(),
        };
        let decoded = AuthenticatedFrame::decode(
            &frame
                .encode("poco-g3-7-20260813T000000Z-00000001", &key)
                .unwrap(),
            "poco-g3-7-20260813T000000Z-00000001",
            &key_roles,
        )
        .unwrap();
        window.admit(&decoded).unwrap();
        assert!(matches!(window.admit(&decoded), Err(FrameError::Replay)));
        frame.sequence = 1;
        window.admit(&frame).unwrap();
        frame.sequence = 3;
        window.admit(&frame).unwrap();
        frame.sequence = 2;
        assert!(matches!(window.admit(&frame), Err(FrameError::Replay)));
        frame.session = [8; 32];
        frame.sequence = 1;
        assert!(matches!(window.admit(&frame), Err(FrameError::Replay)));
        frame.sequence = 0;
        window.admit(&frame).unwrap();
        frame.session = [9; 32];
        assert!(matches!(window.admit(&frame), Err(FrameError::Replay)));
        frame.session = [7; 32];
        frame.sequence = 0;
        assert!(matches!(window.admit(&frame), Err(FrameError::Replay)));
    }

    #[test]
    fn frame_kind_wire_discriminants_preserve_the_existing_abi() {
        let frozen = [
            (FrameKind::Proposal, 1),
            (FrameKind::Vote, 2),
            (FrameKind::TimeoutVote, 3),
            (FrameKind::QuorumCertificate, 4),
            (FrameKind::TimeoutCertificate, 5),
            (FrameKind::SubmitBatch, 6),
            (FrameKind::Health, 7),
            (FrameKind::ConsensusRelay, 8),
            (FrameKind::FleetReady, 9),
            (FrameKind::FleetStart, 10),
            (FrameKind::RestartPrepare, 11),
            (FrameKind::RestartCut, 12),
            (FrameKind::RestartRecoveryReady, 13),
            (FrameKind::RestartRecoveryStart, 14),
            (FrameKind::RestartCatchup, 15),
            (FrameKind::RestartParkedAck, 16),
        ];
        for (kind, discriminant) in frozen {
            assert_eq!(kind as u8, discriminant);
            assert_eq!(FrameKind::try_from(discriminant).unwrap(), kind);
        }
        assert!(FrameKind::try_from(0).is_err());
        assert!(FrameKind::try_from(17).is_err());
    }

    #[test]
    fn restart_frame_kinds_roundtrip_through_the_authenticated_envelope() {
        let (key, _consensus_key, _set, key_roles, id) = fixture();
        let run_id = "poco-g3-7-20260814T010000Z-89abcdef";
        for (sequence, kind) in [
            FrameKind::RestartPrepare,
            FrameKind::RestartCut,
            FrameKind::RestartParkedAck,
            FrameKind::RestartRecoveryReady,
            FrameKind::RestartRecoveryStart,
            FrameKind::RestartCatchup,
        ]
        .into_iter()
        .enumerate()
        {
            let frame = AuthenticatedFrame {
                sender: id,
                session: [0x77; 32],
                sequence: u64::try_from(sequence).unwrap(),
                kind,
                payload: vec![kind as u8; 32],
            };
            let encoded = frame.encode(run_id, &key).unwrap();
            assert_eq!(
                AuthenticatedFrame::decode(&encoded, run_id, &key_roles).unwrap(),
                frame
            );
        }
    }
}
