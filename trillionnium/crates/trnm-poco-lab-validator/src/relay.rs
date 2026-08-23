//! Canonical consensus relay envelope for the sparse G3 laboratory topology.
//!
//! A transport frame authenticates the current hop.  This envelope retains
//! the original consensus payload and its claimed origin so the receiver can
//! independently authenticate the claimed origin and exact embedded bytes
//! before strict consensus decoding. Proposal witness verification remains
//! deferred until the authenticated parent timestamp is available; relaying
//! never replaces that later check with hop authority.
//!
//! The message identifier excludes the mutable hop budget and relay identity;
//! every copy of the same canonical statement therefore shares one bounded
//! deduplication key.  The admission window must be updated only *after* the
//! embedded statement has passed its strict consensus, fleet-barrier, or
//! restart-protocol wire verifier. Restart traffic uses its own origin-bound,
//! non-evicting relay window rather than the view-pruned consensus window.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet, View};

use crate::frame::{AuthenticatedFrame, FrameKind, MAX_FRAME_PAYLOAD_BYTES};

const RELAY_MAGIC: &[u8; 8] = b"TRNMG3R1";
const RELAY_VERSION: u16 = 1;
const RELAY_ORIGIN_SIGNATURE_DOMAIN: &[u8] = b"trnm.poco-g3.consensus-relay-origin.v1";
const RELAY_MESSAGE_ID_DOMAIN: &[u8] = b"trnm.poco-g3.consensus-relay-message.v1";
const ORIGIN_SIGNATURE_BYTES: usize = 64;
const FIXED_BYTES: usize = 8 + 2 + 32 + 1 + 1 + 4 + ORIGIN_SIGNATURE_BYTES;
/// Maximum independently signed consensus bytes that fit after the relay
/// envelope overhead inside one authenticated transport frame.
pub const MAX_RELAY_INNER_PAYLOAD_BYTES_V0: usize = MAX_FRAME_PAYLOAD_BYTES - FIXED_BYTES;
pub const MAX_RELAY_HOPS_V0: u8 = 32;
pub const MAX_RELAY_MESSAGES_V0: usize = 131_072;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusRelayEnvelopeV0 {
    origin: ValidatorId,
    inner_kind: FrameKind,
    remaining_hops: u8,
    payload: Vec<u8>,
    origin_signature: [u8; ORIGIN_SIGNATURE_BYTES],
}

impl ConsensusRelayEnvelopeV0 {
    /// Builds an origin-authenticated relay envelope from already-produced
    /// signature bytes.  Deployed callers must use this path with an
    /// independently provisioned signer; no private key is accepted here.
    pub fn new_with_signature(
        origin: ValidatorId,
        inner_kind: FrameKind,
        remaining_hops: u8,
        payload: Vec<u8>,
        validator_set: &ValidatorSet,
        origin_signature: [u8; ORIGIN_SIGNATURE_BYTES],
    ) -> Result<Self, ConsensusRelayErrorV0> {
        validate_fields(origin, inner_kind, remaining_hops, &payload, validator_set)?;
        verify_origin_signature(
            validator_set,
            origin,
            inner_kind,
            &payload,
            &origin_signature,
        )?;
        Ok(Self {
            origin,
            inner_kind,
            remaining_hops,
            payload,
            origin_signature,
        })
    }

    /// Exact origin-signing preimage root for [`Self::new_with_signature`].
    /// The returned digest commits the validator-set namespace, origin,
    /// inner frame kind, and complete payload (but not the mutable hop
    /// budget).  It is intentionally public so a remote signer can bind its
    /// request without receiving a raw `SigningKey`.
    pub fn origin_signing_root_v0(
        origin: ValidatorId,
        inner_kind: FrameKind,
        remaining_hops: u8,
        payload: &[u8],
        validator_set: &ValidatorSet,
    ) -> Result<[u8; 32], ConsensusRelayErrorV0> {
        // The hop budget is deliberately excluded from the signed root (it is
        // mutable at each forwarding hop), but the caller must still present
        // the actual budget it will put on the envelope.  Validating that
        // value here prevents a root-only signer seam from accidentally
        // bypassing the envelope's zero/overflow hop checks.
        validate_fields(origin, inner_kind, remaining_hops, payload, validator_set)?;
        Ok(relay_origin_signing_root(
            validator_set,
            origin,
            inner_kind,
            payload,
        ))
    }

    /// Fixture-only compatibility constructor.  Deployed composition must
    /// migrate to [`Self::new_with_signature`] before its raw-key guard is
    /// removed.
    pub fn new(
        origin: ValidatorId,
        inner_kind: FrameKind,
        remaining_hops: u8,
        payload: Vec<u8>,
        validator_set: &ValidatorSet,
        origin_key: &SigningKey,
    ) -> Result<Self, ConsensusRelayErrorV0> {
        validate_fields(origin, inner_kind, remaining_hops, &payload, validator_set)?;
        let validator = validator_set
            .validator(origin)
            .ok_or(ConsensusRelayErrorV0::UnknownOrigin)?;
        if origin_key.verifying_key().as_bytes() != validator.consensus_key().as_bytes() {
            return Err(ConsensusRelayErrorV0::OriginKeyMismatch);
        }
        let root = relay_origin_signing_root(validator_set, origin, inner_kind, &payload);
        Self::new_with_signature(
            origin,
            inner_kind,
            remaining_hops,
            payload,
            validator_set,
            origin_key.sign(&root).to_bytes(),
        )
    }

    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn inner_kind(&self) -> FrameKind {
        self.inner_kind
    }

    pub const fn remaining_hops(&self) -> u8 {
        self.remaining_hops
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Stable identity of the embedded canonical statement. The relay-origin
    /// signature is deliberately not part of this identity: QC/TC may be
    /// forwarded by any validator, while author-bearing messages commit their
    /// author again in their own strict wire form. The mutable relay budget is
    /// never included. Opaque restart messages instead use the origin-bound
    /// identity from `restart_protocol`.
    pub fn message_id(&self) -> [u8; 32] {
        relay_message_id(self.inner_kind, &self.payload)
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload_len =
            u32::try_from(self.payload.len()).expect("relay constructor bounds payload to u32");
        let mut output = Vec::with_capacity(FIXED_BYTES + self.payload.len());
        output.extend_from_slice(RELAY_MAGIC);
        output.extend_from_slice(&RELAY_VERSION.to_be_bytes());
        output.extend_from_slice(self.origin.as_bytes());
        output.push(self.inner_kind as u8);
        output.push(self.remaining_hops);
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&self.payload);
        output.extend_from_slice(&self.origin_signature);
        output
    }

    pub fn decode(
        bytes: &[u8],
        validator_set: &ValidatorSet,
    ) -> Result<Self, ConsensusRelayErrorV0> {
        if bytes.len() < FIXED_BYTES || bytes.len() > MAX_FRAME_PAYLOAD_BYTES {
            return Err(ConsensusRelayErrorV0::PayloadSize);
        }
        let mut cursor = RelayCursor::new(bytes);
        if cursor.take(8)? != RELAY_MAGIC {
            return Err(ConsensusRelayErrorV0::Malformed("magic"));
        }
        if u16::from_be_bytes(cursor.array()?) != RELAY_VERSION {
            return Err(ConsensusRelayErrorV0::Malformed("version"));
        }
        let origin = ValidatorId::new(cursor.array()?);
        let inner_kind = FrameKind::try_from(cursor.byte()?)
            .map_err(|_| ConsensusRelayErrorV0::Malformed("inner kind"))?;
        let remaining_hops = cursor.byte()?;
        let payload_len = u32::from_be_bytes(cursor.array()?) as usize;
        if payload_len == 0 || payload_len.checked_add(FIXED_BYTES) != Some(bytes.len()) {
            return Err(ConsensusRelayErrorV0::Malformed("payload length"));
        }
        let payload = cursor.take(payload_len)?.to_vec();
        let origin_signature = cursor.array()?;
        cursor.finish()?;
        validate_fields(origin, inner_kind, remaining_hops, &payload, validator_set)?;
        verify_origin_signature(
            validator_set,
            origin,
            inner_kind,
            &payload,
            &origin_signature,
        )?;
        Ok(Self {
            origin,
            inner_kind,
            remaining_hops,
            payload,
            origin_signature,
        })
    }

    /// Synthetic comparison frame used only to pass the embedded statement to
    /// the strict inner decoder.  It is not a transport-authenticated
    /// frame and must never be written to a socket.
    pub(crate) fn embedded_statement_frame(&self) -> AuthenticatedFrame {
        AuthenticatedFrame {
            sender: self.origin,
            session: [0; 32],
            sequence: 0,
            kind: self.inner_kind,
            payload: self.payload.clone(),
        }
    }

    pub fn forwarded(&self) -> Option<Self> {
        (self.remaining_hops > 1).then(|| Self {
            origin: self.origin,
            inner_kind: self.inner_kind,
            remaining_hops: self.remaining_hops - 1,
            payload: self.payload.clone(),
            origin_signature: self.origin_signature,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAdmissionV0 {
    New,
    ExactReplay,
}

/// Process-local bounded deduplication.  Entries are never evicted: capacity
/// exhaustion fail-stops the lane instead of re-admitting an old message.
pub struct ConsensusRelayAdmissionWindowV0 {
    maximum_messages: usize,
    minimum_retained_view: View,
    admitted: BTreeMap<[u8; 32], View>,
}

impl ConsensusRelayAdmissionWindowV0 {
    pub fn new(maximum_messages: usize) -> Result<Self, ConsensusRelayErrorV0> {
        if maximum_messages == 0 || maximum_messages > MAX_RELAY_MESSAGES_V0 {
            return Err(ConsensusRelayErrorV0::Capacity);
        }
        Ok(Self {
            maximum_messages,
            minimum_retained_view: View::new(0),
            admitted: BTreeMap::new(),
        })
    }

    /// Call only after the embedded statement has been independently verified.
    pub fn admit_verified(
        &mut self,
        envelope: &ConsensusRelayEnvelopeV0,
    ) -> Result<RelayAdmissionV0, ConsensusRelayErrorV0> {
        self.admit_verified_at_view(envelope, View::new(0))
    }

    /// View-aware admission used by the continuous runtime. The view is
    /// derived from the independently decoded inner statement, never from the
    /// relay hop. It lets the runtime prune a finalized sliding window without
    /// allowing an old authenticated replay to consume capacity again.
    pub fn admit_verified_at_view(
        &mut self,
        envelope: &ConsensusRelayEnvelopeV0,
        statement_view: View,
    ) -> Result<RelayAdmissionV0, ConsensusRelayErrorV0> {
        let id = envelope.message_id();
        if self.admitted.contains_key(&id) {
            return Ok(RelayAdmissionV0::ExactReplay);
        }
        if statement_view < self.minimum_retained_view {
            return Err(ConsensusRelayErrorV0::StaleView);
        }
        if self.admitted.len() == self.maximum_messages {
            return Err(ConsensusRelayErrorV0::Capacity);
        }
        self.admitted.insert(id, statement_view);
        Ok(RelayAdmissionV0::New)
    }

    /// Non-mutating capacity/replay check used before a strict consensus
    /// decoder changes its own bounded collector.  The validator event loop is
    /// single-owner, so a successful `New` preflight followed by
    /// `admit_verified` cannot race another insertion.
    pub fn preflight(
        &self,
        envelope: &ConsensusRelayEnvelopeV0,
    ) -> Result<RelayAdmissionV0, ConsensusRelayErrorV0> {
        self.preflight_at_view(envelope, View::new(0))
    }

    pub fn preflight_at_view(
        &self,
        envelope: &ConsensusRelayEnvelopeV0,
        statement_view: View,
    ) -> Result<RelayAdmissionV0, ConsensusRelayErrorV0> {
        if self.admitted.contains_key(&envelope.message_id()) {
            Ok(RelayAdmissionV0::ExactReplay)
        } else if statement_view < self.minimum_retained_view {
            Err(ConsensusRelayErrorV0::StaleView)
        } else if self.admitted.len() == self.maximum_messages {
            Err(ConsensusRelayErrorV0::Capacity)
        } else {
            Ok(RelayAdmissionV0::New)
        }
    }

    pub const fn minimum_retained_view(&self) -> View {
        self.minimum_retained_view
    }

    pub fn prune_before_view(
        &mut self,
        minimum_retained_view: View,
    ) -> Result<(), ConsensusRelayErrorV0> {
        if minimum_retained_view < self.minimum_retained_view {
            return Err(ConsensusRelayErrorV0::StaleView);
        }
        self.admitted
            .retain(|_, view| *view >= minimum_retained_view);
        self.minimum_retained_view = minimum_retained_view;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.admitted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }
}

/// Minimum hop budget for the deterministic forward ring emitted by the G3
/// topology planner: every validator has edges to the next `peer_degree`
/// validators.  This is a planning bound, not a liveness guarantee under
/// faults.
pub fn required_ring_relay_hops_v0(
    validator_count: usize,
    peer_degree: usize,
) -> Result<u8, ConsensusRelayErrorV0> {
    if validator_count < 2 || peer_degree == 0 || peer_degree >= validator_count {
        return Err(ConsensusRelayErrorV0::InvalidTopology);
    }
    let distance = validator_count - 1;
    let hops = distance
        .checked_add(peer_degree - 1)
        .ok_or(ConsensusRelayErrorV0::InvalidTopology)?
        / peer_degree;
    let hops = u8::try_from(hops).map_err(|_| ConsensusRelayErrorV0::InvalidTopology)?;
    if hops == 0 || hops > MAX_RELAY_HOPS_V0 {
        return Err(ConsensusRelayErrorV0::InvalidTopology);
    }
    Ok(hops)
}

/// Worst-case unique relay statements retained per view: one proposal, up to
/// one vote and one timeout vote per validator, and one QC plus one TC. This
/// is a sliding-window budget; the runtime must advance the relay watermark
/// from authoritative Core progress.
pub fn required_relay_message_capacity_v0(
    validator_count: usize,
    retained_views: usize,
) -> Result<usize, ConsensusRelayErrorV0> {
    if validator_count == 0 || retained_views == 0 {
        return Err(ConsensusRelayErrorV0::Capacity);
    }
    validator_count
        .checked_mul(2)
        .and_then(|votes| votes.checked_add(4))
        .and_then(|per_view| per_view.checked_mul(retained_views))
        .filter(|capacity| *capacity <= MAX_RELAY_MESSAGES_V0)
        .ok_or(ConsensusRelayErrorV0::Capacity)
}

fn relay_message_id(kind: FrameKind, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_MESSAGE_ID_DOMAIN);
    hasher.update([kind as u8]);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn relay_origin_signing_root(
    validator_set: &ValidatorSet,
    origin: ValidatorId,
    kind: FrameKind,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_ORIGIN_SIGNATURE_DOMAIN);
    hasher.update(validator_set.id().as_bytes());
    hasher.update(origin.as_bytes());
    hasher.update([kind as u8]);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn verify_origin_signature(
    validator_set: &ValidatorSet,
    origin: ValidatorId,
    kind: FrameKind,
    payload: &[u8],
    signature: &[u8; ORIGIN_SIGNATURE_BYTES],
) -> Result<(), ConsensusRelayErrorV0> {
    let validator = validator_set
        .validator(origin)
        .ok_or(ConsensusRelayErrorV0::UnknownOrigin)?;
    let key = VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
        .map_err(|_| ConsensusRelayErrorV0::InvalidOriginSignature)?;
    key.verify_strict(
        &relay_origin_signing_root(validator_set, origin, kind, payload),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ConsensusRelayErrorV0::InvalidOriginSignature)
}

fn validate_fields(
    origin: ValidatorId,
    inner_kind: FrameKind,
    remaining_hops: u8,
    payload: &[u8],
    validator_set: &ValidatorSet,
) -> Result<(), ConsensusRelayErrorV0> {
    if validator_set.validator(origin).is_none() {
        return Err(ConsensusRelayErrorV0::UnknownOrigin);
    }
    require_inner_kind(inner_kind)?;
    if remaining_hops == 0 || remaining_hops > MAX_RELAY_HOPS_V0 {
        return Err(ConsensusRelayErrorV0::InvalidHopBudget);
    }
    if payload.is_empty() || payload.len() > MAX_RELAY_INNER_PAYLOAD_BYTES_V0 {
        return Err(ConsensusRelayErrorV0::PayloadSize);
    }
    Ok(())
}

fn require_inner_kind(kind: FrameKind) -> Result<(), ConsensusRelayErrorV0> {
    if matches!(
        kind,
        FrameKind::Proposal
            | FrameKind::Vote
            | FrameKind::TimeoutVote
            | FrameKind::QuorumCertificate
            | FrameKind::TimeoutCertificate
            | FrameKind::FleetReady
            | FrameKind::FleetStart
            | FrameKind::RestartPrepare
            | FrameKind::RestartCut
            | FrameKind::RestartParkedAck
            | FrameKind::RestartRecoveryReady
            | FrameKind::RestartRecoveryStart
            | FrameKind::RestartCatchup
    ) {
        Ok(())
    } else {
        Err(ConsensusRelayErrorV0::UnsupportedInnerKind)
    }
}

struct RelayCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RelayCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ConsensusRelayErrorV0> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ConsensusRelayErrorV0::Malformed("offset"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ConsensusRelayErrorV0::Malformed("truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ConsensusRelayErrorV0> {
        self.take(N)?
            .try_into()
            .map_err(|_| ConsensusRelayErrorV0::Malformed("array"))
    }

    fn byte(&mut self) -> Result<u8, ConsensusRelayErrorV0> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(ConsensusRelayErrorV0::Malformed("byte"))
    }

    fn finish(self) -> Result<(), ConsensusRelayErrorV0> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ConsensusRelayErrorV0::Malformed("trailing"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusRelayErrorV0 {
    Malformed(&'static str),
    UnknownOrigin,
    UnsupportedInnerKind,
    OriginKeyMismatch,
    InvalidOriginSignature,
    InvalidHopBudget,
    PayloadSize,
    StaleView,
    Capacity,
    InvalidTopology,
}

impl std::fmt::Display for ConsensusRelayErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(field) => write!(formatter, "malformed relay envelope: {field}"),
            Self::UnknownOrigin => formatter.write_str("relay origin is outside validator set"),
            Self::UnsupportedInnerKind => formatter.write_str(
                "relay inner kind is not a supported consensus/barrier/restart statement",
            ),
            Self::OriginKeyMismatch => {
                formatter.write_str("relay origin signing key differs from validator set")
            }
            Self::InvalidOriginSignature => {
                formatter.write_str("relay origin signature is invalid")
            }
            Self::InvalidHopBudget => formatter.write_str("relay hop budget is invalid"),
            Self::PayloadSize => formatter.write_str("relay payload crosses its bounded profile"),
            Self::StaleView => formatter.write_str("relay statement view was pruned"),
            Self::Capacity => formatter.write_str("relay admission capacity exhausted"),
            Self::InvalidTopology => formatter.write_str("relay topology is invalid"),
        }
    }
}

impl std::error::Error for ConsensusRelayErrorV0 {}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, ValidatorId, ValidatorSet, VotingPower,
    };

    use super::*;

    fn fixture_for_context(
        chain_id: &str,
        genesis_seed: u8,
    ) -> (ValidatorSet, ValidatorId, ValidatorId) {
        let first = ValidatorId::new([0x11; 32]);
        let second = ValidatorId::new([0x12; 32]);
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([genesis_seed; 32]),
            ChainId::new(chain_id).unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            vec![
                Validator::new(
                    first,
                    ConsensusPublicKey::new(
                        SigningKey::from_bytes(&[0x31; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    second,
                    ConsensusPublicKey::new(
                        SigningKey::from_bytes(&[0x32; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        (set, first, second)
    }

    fn fixture() -> (ValidatorSet, ValidatorId, ValidatorId) {
        fixture_for_context("trnm-poco-g3-relay-test", 0x21)
    }

    #[test]
    fn canonical_codec_forwarding_and_dedup_are_exact() {
        let (set, first, second) = fixture();
        let first_key = SigningKey::from_bytes(&[0x31; 32]);
        let second_key = SigningKey::from_bytes(&[0x32; 32]);
        let envelope = ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Vote,
            3,
            vec![1, 2, 3],
            &set,
            &first_key,
        )
        .unwrap();
        let bytes = envelope.encode();
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&bytes, &set).unwrap(),
            envelope
        );
        let forwarded = envelope.forwarded().unwrap();
        assert_eq!(forwarded.remaining_hops(), 2);
        assert_eq!(forwarded.message_id(), envelope.message_id());
        let alternate_relay = ConsensusRelayEnvelopeV0::new(
            second,
            FrameKind::Vote,
            1,
            vec![1, 2, 3],
            &set,
            &second_key,
        )
        .unwrap();
        assert_eq!(alternate_relay.message_id(), envelope.message_id());
        let mut window = ConsensusRelayAdmissionWindowV0::new(1).unwrap();
        assert_eq!(
            window.admit_verified(&envelope).unwrap(),
            RelayAdmissionV0::New
        );
        assert_eq!(
            window.admit_verified(&forwarded).unwrap(),
            RelayAdmissionV0::ExactReplay
        );
        assert_eq!(window.len(), 1);
    }

    #[test]
    fn malformed_nested_and_capacity_inputs_fail_closed() {
        let (set, first, _) = fixture();
        let first_key = SigningKey::from_bytes(&[0x31; 32]);
        for kind in [
            FrameKind::SubmitBatch,
            FrameKind::Health,
            FrameKind::ConsensusRelay,
        ] {
            assert!(
                ConsensusRelayEnvelopeV0::new(first, kind, 1, vec![1], &set, &first_key,).is_err()
            );
        }
        assert!(ConsensusRelayEnvelopeV0::new(
            ValidatorId::new([0x99; 32]),
            FrameKind::Vote,
            1,
            vec![1],
            &set,
            &first_key,
        )
        .is_err());
        assert!(ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Vote,
            0,
            vec![1],
            &set,
            &first_key,
        )
        .is_err());
        assert!(ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Vote,
            33,
            vec![1],
            &set,
            &first_key,
        )
        .is_err());
        assert!(ConsensusRelayAdmissionWindowV0::new(0).is_err());

        for kind in [
            FrameKind::FleetReady,
            FrameKind::FleetStart,
            FrameKind::RestartPrepare,
            FrameKind::RestartCut,
            FrameKind::RestartParkedAck,
            FrameKind::RestartRecoveryReady,
            FrameKind::RestartRecoveryStart,
            FrameKind::RestartCatchup,
        ] {
            let barrier = ConsensusRelayEnvelopeV0::new(
                first,
                kind,
                1,
                b"independently-origin-signed-barrier-payload".to_vec(),
                &set,
                &first_key,
            )
            .unwrap();
            assert_eq!(
                ConsensusRelayEnvelopeV0::decode(&barrier.encode(), &set).unwrap(),
                barrier
            );
        }

        let valid = ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Vote,
            1,
            vec![1, 2, 3],
            &set,
            &first_key,
        )
        .unwrap()
        .encode();
        for truncated in 0..valid.len() {
            assert!(ConsensusRelayEnvelopeV0::decode(&valid[..truncated], &set).is_err());
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(ConsensusRelayEnvelopeV0::decode(&trailing, &set).is_err());
        let mut wrong_magic = valid;
        wrong_magic[0] ^= 1;
        assert!(ConsensusRelayEnvelopeV0::decode(&wrong_magic, &set).is_err());
    }

    #[test]
    fn origin_signature_binds_set_origin_kind_and_exact_payload_but_not_ttl() {
        let (set, first, second) = fixture();
        let first_key = SigningKey::from_bytes(&[0x31; 32]);
        let second_key = SigningKey::from_bytes(&[0x32; 32]);
        let envelope = ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Proposal,
            3,
            b"candidate-proposal-wire".to_vec(),
            &set,
            &first_key,
        )
        .unwrap();
        let original_id = envelope.message_id();
        let original_signature = envelope.origin_signature;
        let bytes = envelope.encode();

        // The relay budget is hop-local. A legitimate forward may decrement
        // it without obtaining another origin signature or changing identity.
        let mut lower_ttl = bytes.clone();
        lower_ttl[43] = 2;
        let decoded = ConsensusRelayEnvelopeV0::decode(&lower_ttl, &set).unwrap();
        assert_eq!(decoded.message_id(), original_id);
        assert_eq!(decoded.origin_signature, original_signature);
        assert_eq!(decoded.remaining_hops(), 2);
        for invalid_ttl in [0, MAX_RELAY_HOPS_V0 + 1] {
            let mut invalid = bytes.clone();
            invalid[43] = invalid_ttl;
            assert_eq!(
                ConsensusRelayEnvelopeV0::decode(&invalid, &set),
                Err(ConsensusRelayErrorV0::InvalidHopBudget)
            );
        }

        // Every identity-bearing field and the exact claimed proposer bytes
        // are covered by the origin signature.
        let mut wrong_origin = bytes.clone();
        wrong_origin[10..42].copy_from_slice(second.as_bytes());
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&wrong_origin, &set),
            Err(ConsensusRelayErrorV0::InvalidOriginSignature)
        );
        let mut wrong_kind = bytes.clone();
        wrong_kind[42] = FrameKind::Vote as u8;
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&wrong_kind, &set),
            Err(ConsensusRelayErrorV0::InvalidOriginSignature)
        );
        let mut forged_proposal = bytes.clone();
        forged_proposal[48] ^= 1;
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&forged_proposal, &set),
            Err(ConsensusRelayErrorV0::InvalidOriginSignature)
        );
        let mut bad_signature = bytes.clone();
        *bad_signature.last_mut().unwrap() ^= 1;
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&bad_signature, &set),
            Err(ConsensusRelayErrorV0::InvalidOriginSignature)
        );
        assert_eq!(
            ConsensusRelayEnvelopeV0::new(
                first,
                FrameKind::Proposal,
                1,
                b"candidate-proposal-wire".to_vec(),
                &set,
                &second_key,
            ),
            Err(ConsensusRelayErrorV0::OriginKeyMismatch)
        );
    }

    #[test]
    fn origin_signature_rejects_wrong_domain_and_validator_set() {
        let (set, first, _) = fixture();
        let first_key = SigningKey::from_bytes(&[0x31; 32]);
        let payload = b"candidate-vote-wire".to_vec();
        let valid = ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Vote,
            1,
            payload.clone(),
            &set,
            &first_key,
        )
        .unwrap();
        let (foreign_set, _, _) = fixture_for_context("trnm-poco-g3-relay-foreign", 0x22);
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&valid.encode(), &foreign_set),
            Err(ConsensusRelayErrorV0::InvalidOriginSignature)
        );

        let mut wrong_domain_hasher = Sha256::new();
        wrong_domain_hasher.update(b"trnm.poco-g3.consensus-relay-origin.wrong");
        wrong_domain_hasher.update(set.id().as_bytes());
        wrong_domain_hasher.update(first.as_bytes());
        wrong_domain_hasher.update([FrameKind::Vote as u8]);
        wrong_domain_hasher.update((payload.len() as u64).to_be_bytes());
        wrong_domain_hasher.update(&payload);
        let wrong_domain_root: [u8; 32] = wrong_domain_hasher.finalize().into();
        let wrong_domain = ConsensusRelayEnvelopeV0 {
            origin: first,
            inner_kind: FrameKind::Vote,
            remaining_hops: 1,
            payload,
            origin_signature: first_key.sign(&wrong_domain_root).to_bytes(),
        };
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&wrong_domain.encode(), &set),
            Err(ConsensusRelayErrorV0::InvalidOriginSignature)
        );
    }

    #[test]
    fn externally_produced_origin_signature_roundtrips_v0() {
        let (set, first, _) = fixture();
        let first_key = SigningKey::from_bytes(&[0x31; 32]);
        let payload = b"remote-signed-relay-payload".to_vec();
        let root = ConsensusRelayEnvelopeV0::origin_signing_root_v0(
            first,
            FrameKind::Vote,
            2,
            &payload,
            &set,
        )
        .unwrap();
        assert_eq!(
            ConsensusRelayEnvelopeV0::origin_signing_root_v0(
                first,
                FrameKind::Vote,
                0,
                &payload,
                &set,
            ),
            Err(ConsensusRelayErrorV0::InvalidHopBudget)
        );
        let envelope = ConsensusRelayEnvelopeV0::new_with_signature(
            first,
            FrameKind::Vote,
            2,
            payload,
            &set,
            first_key.sign(&root).to_bytes(),
        )
        .unwrap();
        assert_eq!(
            ConsensusRelayEnvelopeV0::decode(&envelope.encode(), &set).unwrap(),
            envelope
        );
    }

    #[test]
    fn frozen_ring_hop_bounds_cover_g3_topologies() {
        assert_eq!(required_ring_relay_hops_v0(7, 6).unwrap(), 1);
        assert_eq!(required_ring_relay_hops_v0(31, 8).unwrap(), 4);
        assert_eq!(required_ring_relay_hops_v0(100, 8).unwrap(), 13);
        assert!(required_ring_relay_hops_v0(1, 1).is_err());
        assert!(required_ring_relay_hops_v0(7, 0).is_err());
        assert!(required_ring_relay_hops_v0(7, 7).is_err());
    }

    #[test]
    fn relay_window_prunes_by_verified_statement_view_and_rejects_old_replay() {
        let (set, first, _) = fixture();
        let key = SigningKey::from_bytes(&[0x31; 32]);
        let old = ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Vote,
            1,
            b"old-vote".to_vec(),
            &set,
            &key,
        )
        .unwrap();
        let live = ConsensusRelayEnvelopeV0::new(
            first,
            FrameKind::Vote,
            1,
            b"live-vote".to_vec(),
            &set,
            &key,
        )
        .unwrap();
        let mut window = ConsensusRelayAdmissionWindowV0::new(2).unwrap();
        window.admit_verified_at_view(&old, View::new(4)).unwrap();
        window.admit_verified_at_view(&live, View::new(6)).unwrap();
        window.prune_before_view(View::new(6)).unwrap();
        assert_eq!(window.minimum_retained_view(), View::new(6));
        assert_eq!(window.len(), 1);
        assert_eq!(
            window.preflight_at_view(&live, View::new(6)).unwrap(),
            RelayAdmissionV0::ExactReplay
        );
        assert_eq!(
            window.admit_verified_at_view(&old, View::new(4)),
            Err(ConsensusRelayErrorV0::StaleView)
        );
        assert_eq!(window.len(), 1);
        assert_eq!(
            window.prune_before_view(View::new(5)),
            Err(ConsensusRelayErrorV0::StaleView)
        );
    }

    #[test]
    fn relay_capacity_is_topology_and_retained_window_derived() {
        assert_eq!(required_relay_message_capacity_v0(7, 6).unwrap(), 108);
        assert_eq!(required_relay_message_capacity_v0(100, 6).unwrap(), 1_224);
        assert!(required_relay_message_capacity_v0(0, 6).is_err());
        assert!(required_relay_message_capacity_v0(100, 643).is_err());
    }

    #[test]
    fn relay_inner_payload_reserves_the_exact_authenticated_frame_overhead() {
        let (set, first, _) = fixture();
        assert_eq!(
            MAX_RELAY_INNER_PAYLOAD_BYTES_V0 + FIXED_BYTES,
            MAX_FRAME_PAYLOAD_BYTES
        );
        let maximum = vec![0x55; MAX_RELAY_INNER_PAYLOAD_BYTES_V0];
        assert!(validate_fields(first, FrameKind::Proposal, 1, &maximum, &set).is_ok());
        let oversized = vec![0x55; MAX_RELAY_INNER_PAYLOAD_BYTES_V0 + 1];
        assert_eq!(
            validate_fields(first, FrameKind::Proposal, 1, &oversized, &set),
            Err(ConsensusRelayErrorV0::PayloadSize)
        );
    }
}
