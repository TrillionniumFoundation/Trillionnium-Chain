//! Bounded transport admission for the five-phase laboratory restart protocol.
//!
//! This module deliberately stops below every semantic restart authority. It
//! authenticates the transport or relay origin, separates the five frozen
//! frame kinds, and admits at most one exact payload per `(origin, phase)`.
//! Payloads remain opaque: this layer does not validate a restart-safe cut,
//! form an N/N certificate, quiesce or kill a process, recover a store, append
//! a runtime journal event, activate a signer, arm a timer, or release normal
//! consensus ingress. Those operations require later typed owners and joins.
//!
//! Sparse delivery owns a restart-specific relay window. The ordinary
//! consensus relay window is view-indexed and may prune; restart protocol
//! messages instead occupy a fixed, non-evicting `5 * N` campaign budget.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet, ValidatorSetId};

use crate::{
    consensus_mesh::MeshInboundFrameV0,
    frame::{validate_run_id_bytes, AuthenticatedFrame, FrameError, FrameKind},
    relay::{ConsensusRelayEnvelopeV0, ConsensusRelayErrorV0, MAX_RELAY_INNER_PAYLOAD_BYTES_V0},
};

const RESTART_MESSAGE_ID_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-protocol-message.v1";
const RESTART_PAYLOAD_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.restart-protocol-payload.v1";
static NEXT_RESTART_ADMISSION_INSTANCE_V1: AtomicU64 = AtomicU64::new(1);
static NEXT_RESTART_RELAY_INSTANCE_V1: AtomicU64 = AtomicU64::new(1);
pub const RESTART_PROTOCOL_PHASES_V1: usize = 5;
pub const MAX_RESTART_PROTOCOL_VALIDATORS_V1: usize = 100;
pub const MAX_RESTART_PROTOCOL_ENTRIES_V1: usize =
    RESTART_PROTOCOL_PHASES_V1 * MAX_RESTART_PROTOCOL_VALIDATORS_V1;
/// A common bound for the still-opaque phase payloads. It covers the existing
/// RestartCut certificate ceiling and remains safely below the relay envelope
/// payload ceiling.
pub const MAX_RESTART_PROTOCOL_PAYLOAD_BYTES_V1: usize = 4 * 1024 * 1024;

const _: () = assert!(MAX_RESTART_PROTOCOL_PAYLOAD_BYTES_V1 <= MAX_RELAY_INNER_PAYLOAD_BYTES_V0);

/// Deterministic identity of already-authenticated restart payload bytes.
///
/// This helper is comparison vocabulary only: it cannot reserve an admission
/// slot or manufacture an admitted owner.  Higher layers use it to rederive
/// the exact Prepare/Cut identities retained by a durable composite artifact.
pub(crate) fn restart_protocol_message_id_for_parts_v1(
    validator_set_id: ValidatorSetId,
    origin: ValidatorId,
    phase: RestartProtocolPhaseV1,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RESTART_MESSAGE_ID_DOMAIN_V1);
    hasher.update(validator_set_id.as_bytes());
    hasher.update(origin.as_bytes());
    hasher.update([phase.frame_kind() as u8]);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

/// Deterministic digest of already-authenticated restart payload bytes. Like
/// the message-ID helper, this cannot reserve a slot or issue authority.
pub(crate) fn restart_protocol_payload_digest_for_parts_v1(
    validator_set_id: ValidatorSetId,
    origin: ValidatorId,
    phase: RestartProtocolPhaseV1,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RESTART_PAYLOAD_DIGEST_DOMAIN_V1);
    hasher.update(validator_set_id.as_bytes());
    hasher.update(origin.as_bytes());
    hasher.update([phase.frame_kind() as u8]);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RestartProtocolPhaseV1 {
    Prepare,
    Cut,
    ParkedAck,
    RecoveryReady,
    RecoveryStart,
}

impl RestartProtocolPhaseV1 {
    pub const fn frame_kind(self) -> FrameKind {
        match self {
            Self::Prepare => FrameKind::RestartPrepare,
            Self::Cut => FrameKind::RestartCut,
            Self::ParkedAck => FrameKind::RestartParkedAck,
            Self::RecoveryReady => FrameKind::RestartRecoveryReady,
            Self::RecoveryStart => FrameKind::RestartRecoveryStart,
        }
    }

    fn from_frame_kind(kind: FrameKind) -> Result<Self, RestartProtocolIngressErrorV1> {
        match kind {
            FrameKind::RestartPrepare => Ok(Self::Prepare),
            FrameKind::RestartCut => Ok(Self::Cut),
            FrameKind::RestartParkedAck => Ok(Self::ParkedAck),
            FrameKind::RestartRecoveryReady => Ok(Self::RecoveryReady),
            FrameKind::RestartRecoveryStart => Ok(Self::RecoveryStart),
            _ => Err(RestartProtocolIngressErrorV1::UnsupportedFrameKind),
        }
    }
}

/// Origin-authenticated but semantically opaque restart protocol bytes.
///
/// This value is intentionally Clone: it is a routing value, not an authority
/// carrier. A future phase-specific verifier must consume the bytes and issue
/// a distinct non-Clone owner before any stateful restart action is possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartProtocolMessageV1 {
    validator_set_id: ValidatorSetId,
    origin: ValidatorId,
    phase: RestartProtocolPhaseV1,
    payload: Vec<u8>,
}

impl RestartProtocolMessageV1 {
    pub const fn origin(&self) -> ValidatorId {
        self.origin
    }

    pub const fn phase(&self) -> RestartProtocolPhaseV1 {
        self.phase
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn payload_digest(&self) -> [u8; 32] {
        restart_protocol_payload_digest_for_parts_v1(
            self.validator_set_id,
            self.origin,
            self.phase,
            &self.payload,
        )
    }

    /// Restart-specific relay identity. Unlike the ordinary QC/TC relay ID,
    /// this includes the origin because these opaque phase bytes do not yet
    /// have a phase-specific decoder that can prove an embedded author field.
    pub fn message_id(&self) -> [u8; 32] {
        restart_protocol_message_id_for_parts_v1(
            self.validator_set_id,
            self.origin,
            self.phase,
            &self.payload,
        )
    }
}

/// Decodes only the restart transport boundary. `frame` must already have
/// passed [`AuthenticatedFrame::decode`] or the relay-origin verifier.
fn decode_authenticated_restart_frame_v1(
    frame: &AuthenticatedFrame,
    validator_set: &ValidatorSet,
) -> Result<RestartProtocolMessageV1, RestartProtocolIngressErrorV1> {
    if validator_set.validator(frame.sender).is_none() {
        return Err(RestartProtocolIngressErrorV1::UnknownSender);
    }
    let phase = RestartProtocolPhaseV1::from_frame_kind(frame.kind)?;
    if frame.payload.is_empty() {
        return Err(RestartProtocolIngressErrorV1::EmptyPayload);
    }
    if frame.payload.len() > MAX_RESTART_PROTOCOL_PAYLOAD_BYTES_V1 {
        return Err(RestartProtocolIngressErrorV1::PayloadTooLarge);
    }
    Ok(RestartProtocolMessageV1 {
        validator_set_id: validator_set.id(),
        origin: frame.sender,
        phase,
        payload: frame.payload.clone(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartProtocolAdmissionV1 {
    New,
    ExactReplay,
}

/// Process-local identity of one authoritative bounded restart admission map.
/// The private value prevents owners issued by separately constructed maps
/// from being combined into one semantic barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestartProtocolAdmissionInstanceV1(u64);

fn next_restart_admission_instance_v1(
) -> Result<RestartProtocolAdmissionInstanceV1, RestartProtocolIngressErrorV1> {
    NEXT_RESTART_ADMISSION_INSTANCE_V1
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map(RestartProtocolAdmissionInstanceV1)
        .map_err(|_| RestartProtocolIngressErrorV1::Capacity)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartRelayAdmissionInstanceV1(u64);

fn next_restart_relay_instance_v1(
) -> Result<RestartRelayAdmissionInstanceV1, RestartProtocolIngressErrorV1> {
    NEXT_RESTART_RELAY_INSTANCE_V1
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map(RestartRelayAdmissionInstanceV1)
        .map_err(|_| RestartProtocolIngressErrorV1::Capacity)
}

/// Fixed `5 * N` semantic slot map. Entries are never evicted or overwritten;
/// one conflicting payload permanently poisons this process-local lane.
pub struct RestartProtocolAdmissionMapV1 {
    instance: RestartProtocolAdmissionInstanceV1,
    validator_set_id: ValidatorSetId,
    origins: BTreeSet<ValidatorId>,
    maximum_entries: usize,
    entries: BTreeMap<(ValidatorId, RestartProtocolPhaseV1), [u8; 32]>,
    poisoned: bool,
}

impl RestartProtocolAdmissionMapV1 {
    pub fn new(validator_set: &ValidatorSet) -> Result<Self, RestartProtocolIngressErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RestartProtocolIngressErrorV1::InvalidValidatorSet)?;
        let maximum_entries =
            required_restart_protocol_capacity_v1(validator_set.validators().len())?;
        Ok(Self {
            instance: next_restart_admission_instance_v1()?,
            validator_set_id: validator_set.id(),
            origins: validator_set
                .validators()
                .iter()
                .map(|validator| validator.id())
                .collect(),
            maximum_entries,
            entries: BTreeMap::new(),
            poisoned: false,
        })
    }

    pub fn admit(
        &mut self,
        message: &RestartProtocolMessageV1,
    ) -> Result<RestartProtocolAdmissionV1, RestartProtocolIngressErrorV1> {
        let admission = match self.preflight(message) {
            Ok(admission) => admission,
            Err(error @ RestartProtocolIngressErrorV1::Equivocation { .. })
            | Err(error @ RestartProtocolIngressErrorV1::Capacity) => {
                self.poisoned = true;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        self.commit_preflight(message, admission);
        Ok(admission)
    }

    /// Read-only half of admission. Callers that need to reserve more than
    /// one bounded identity can preflight every owner before committing any
    /// of them.
    fn preflight(
        &self,
        message: &RestartProtocolMessageV1,
    ) -> Result<RestartProtocolAdmissionV1, RestartProtocolIngressErrorV1> {
        self.ensure_live()?;
        if message.validator_set_id != self.validator_set_id {
            return Err(RestartProtocolIngressErrorV1::WrongValidatorSet);
        }
        if !self.origins.contains(&message.origin) {
            return Err(RestartProtocolIngressErrorV1::UnknownSender);
        }
        let key = (message.origin, message.phase);
        let digest = message.payload_digest();
        if let Some(existing) = self.entries.get(&key) {
            if *existing == digest {
                return Ok(RestartProtocolAdmissionV1::ExactReplay);
            }
            return Err(RestartProtocolIngressErrorV1::Equivocation {
                origin: message.origin,
                phase: message.phase,
            });
        }
        if self.entries.len() == self.maximum_entries {
            return Err(RestartProtocolIngressErrorV1::Capacity);
        }
        Ok(RestartProtocolAdmissionV1::New)
    }

    /// Infallible commit of a preflight performed while this map was held
    /// under the same exclusive borrow. A violated assertion is an internal
    /// programming error, never an input-dependent partial-commit path.
    fn commit_preflight(
        &mut self,
        message: &RestartProtocolMessageV1,
        admission: RestartProtocolAdmissionV1,
    ) {
        let key = (message.origin, message.phase);
        let digest = message.payload_digest();
        match admission {
            RestartProtocolAdmissionV1::New => {
                assert!(
                    self.entries.insert(key, digest).is_none(),
                    "restart admission changed after preflight"
                );
            }
            RestartProtocolAdmissionV1::ExactReplay => {
                assert_eq!(
                    self.entries.get(&key),
                    Some(&digest),
                    "restart replay changed after preflight"
                );
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn maximum_entries(&self) -> usize {
        self.maximum_entries
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) const fn instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        self.instance
    }

    fn ensure_live(&self) -> Result<(), RestartProtocolIngressErrorV1> {
        if self.poisoned {
            Err(RestartProtocolIngressErrorV1::Poisoned)
        } else {
            Ok(())
        }
    }
}

pub fn required_restart_protocol_capacity_v1(
    validator_count: usize,
) -> Result<usize, RestartProtocolIngressErrorV1> {
    if !matches!(validator_count, 7 | 31 | 100) {
        return Err(RestartProtocolIngressErrorV1::InvalidValidatorSet);
    }
    validator_count
        .checked_mul(RESTART_PROTOCOL_PHASES_V1)
        .filter(|capacity| *capacity <= MAX_RESTART_PROTOCOL_ENTRIES_V1)
        .ok_or(RestartProtocolIngressErrorV1::Capacity)
}

/// Opaque, non-Clone routing action minted only by the `New` branch of one
/// bounded map. Public code may inspect its phase/payload but cannot assemble
/// another action from a cloneable [`RestartProtocolMessageV1`].
pub struct RoutedRestartProtocolActionV1 {
    admitted: AdmittedRestartProtocolMessageV1,
}

impl std::fmt::Debug for RoutedRestartProtocolActionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoutedRestartProtocolActionV1")
            .field("admitted", &self.admitted)
            .finish_non_exhaustive()
    }
}

impl RoutedRestartProtocolActionV1 {
    pub const fn phase(&self) -> RestartProtocolPhaseV1 {
        self.admitted.message.phase
    }

    pub const fn message(&self) -> &RestartProtocolMessageV1 {
        &self.admitted.message
    }

    /// Consumes the already-minted sole `New` owner. This method does not
    /// construct or duplicate admission authority.
    pub(crate) fn into_admitted_message_v1(self) -> AdmittedRestartProtocolMessageV1 {
        self.admitted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartTransportSourceV1 {
    DirectMesh,
    SparseRelayMesh,
    #[cfg(test)]
    VerifiedSignedBytes,
}

/// Compact receipt extracted by consuming the non-Clone mesh queue owner (or,
/// in tests only, by verifying exact signed frame bytes inside this module).
/// Its fields and constructors are private, so cloneable frame data cannot
/// recreate it.
struct AuthenticatedRestartTransportV1 {
    source: RestartTransportSourceV1,
    remote: ValidatorId,
    session_id: [u8; 32],
    session_generation: u64,
    outer_frame_fingerprint: [u8; 32],
}

impl std::fmt::Debug for AuthenticatedRestartTransportV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedRestartTransportV1")
            .field("source", &self.source)
            .field("remote", &self.remote)
            .field("session_id", &self.session_id)
            .field("session_generation", &self.session_generation)
            .field("outer_frame_fingerprint", &self.outer_frame_fingerprint)
            .finish_non_exhaustive()
    }
}

/// Non-Clone proof that one origin-authenticated restart message acquired a
/// fresh `(origin, phase)` slot in a bounded admission map. Phase-specific
/// semantic owners must consume this value; a decoded transport message is
/// deliberately insufficient.
#[must_use = "a freshly admitted restart slot must be consumed by its phase verifier"]
pub(crate) struct AdmittedRestartProtocolMessageV1 {
    admission_instance: RestartProtocolAdmissionInstanceV1,
    transport: AuthenticatedRestartTransportV1,
    message: RestartProtocolMessageV1,
}

impl std::fmt::Debug for AdmittedRestartProtocolMessageV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRestartProtocolMessageV1")
            .field("admission_instance", &self.admission_instance)
            .field("transport", &self.transport)
            .field("validator_set_id", &self.message.validator_set_id)
            .field("origin", &self.message.origin)
            .field("phase", &self.message.phase)
            .field("payload_digest", &self.message.payload_digest())
            .field("message_id", &self.message.message_id())
            .finish_non_exhaustive()
    }
}

impl AdmittedRestartProtocolMessageV1 {
    pub(crate) const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        self.admission_instance
    }

    pub(crate) const fn validator_set_id_v1(&self) -> ValidatorSetId {
        self.message.validator_set_id
    }

    pub(crate) const fn origin_v1(&self) -> ValidatorId {
        self.message.origin
    }

    pub(crate) const fn phase_v1(&self) -> RestartProtocolPhaseV1 {
        self.message.phase
    }

    pub(crate) fn payload_v1(&self) -> &[u8] {
        &self.message.payload
    }

    pub(crate) fn message_id_v1(&self) -> [u8; 32] {
        self.message.message_id()
    }
}

#[derive(Debug)]
pub struct RoutedRestartProtocolIngressV1 {
    pub action: Option<RoutedRestartProtocolActionV1>,
    pub admission: RestartProtocolAdmissionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartRelayAdmissionV1 {
    New,
    ExactReplay,
}

/// Non-evicting relay identity window dedicated to restart protocol traffic.
pub struct RestartRelayAdmissionWindowV1 {
    instance: RestartRelayAdmissionInstanceV1,
    validator_set_id: ValidatorSetId,
    maximum_messages: usize,
    admitted: BTreeSet<[u8; 32]>,
}

impl RestartRelayAdmissionWindowV1 {
    pub fn new(validator_set: &ValidatorSet) -> Result<Self, RestartProtocolIngressErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RestartProtocolIngressErrorV1::InvalidValidatorSet)?;
        Ok(Self {
            instance: next_restart_relay_instance_v1()?,
            validator_set_id: validator_set.id(),
            maximum_messages: required_restart_protocol_capacity_v1(
                validator_set.validators().len(),
            )?,
            admitted: BTreeSet::new(),
        })
    }

    fn preflight(
        &self,
        message: &RestartProtocolMessageV1,
    ) -> Result<RestartRelayAdmissionV1, RestartProtocolIngressErrorV1> {
        if message.validator_set_id != self.validator_set_id {
            return Err(RestartProtocolIngressErrorV1::WrongValidatorSet);
        }
        if self.admitted.contains(&message.message_id()) {
            Ok(RestartRelayAdmissionV1::ExactReplay)
        } else if self.admitted.len() == self.maximum_messages {
            Err(RestartProtocolIngressErrorV1::Capacity)
        } else {
            Ok(RestartRelayAdmissionV1::New)
        }
    }

    fn commit_preflight(
        &mut self,
        message: &RestartProtocolMessageV1,
        admission: RestartRelayAdmissionV1,
    ) {
        match admission {
            RestartRelayAdmissionV1::ExactReplay => {
                assert!(
                    self.admitted.contains(&message.message_id()),
                    "restart relay replay changed after preflight"
                );
            }
            RestartRelayAdmissionV1::New => {
                assert!(
                    self.admitted.insert(message.message_id()),
                    "restart relay admission changed after preflight"
                );
            }
        }
    }

    pub fn len(&self) -> usize {
        self.admitted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }

    pub const fn maximum_messages(&self) -> usize {
        self.maximum_messages
    }
}

#[derive(Debug)]
pub struct RoutedRestartProtocolRelayV1 {
    /// `None` for an exact relay replay or when the same semantic statement
    /// was already admitted directly. No restart authority is carried here.
    pub action: Option<RoutedRestartProtocolActionV1>,
    pub relay_admission: RestartRelayAdmissionV1,
    pub collector_admission: Option<RestartProtocolAdmissionV1>,
    pub message_id: [u8; 32],
    /// Present only for the first verified relay copy with hops remaining.
    pub forward: Option<ConsensusRelayEnvelopeV0>,
}

/// Single-owner restart transport router. It owns only bounded process-local
/// admission state and cannot perform any restart lifecycle transition.
pub struct BoundedRestartProtocolIngressV1 {
    run_id: String,
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    collector: RestartProtocolAdmissionMapV1,
}

impl BoundedRestartProtocolIngressV1 {
    pub(crate) fn new(
        run_id: &str,
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
    ) -> Result<Self, RestartProtocolIngressErrorV1> {
        validate_run_id_bytes(run_id.as_bytes()).map_err(RestartProtocolIngressErrorV1::Frame)?;
        if validator_set.validator(local_validator).is_none() {
            return Err(RestartProtocolIngressErrorV1::UnknownSender);
        }
        let collector = RestartProtocolAdmissionMapV1::new(&validator_set)?;
        Ok(Self {
            run_id: run_id.to_owned(),
            local_validator,
            validator_set,
            collector,
        })
    }

    /// Consumes the authenticated mesh queue owner. Scalar frame fields alone
    /// cannot call this boundary or mint a transport receipt.
    pub(crate) fn admit_authenticated_mesh_frame_v1(
        &mut self,
        inbound: MeshInboundFrameV0,
    ) -> Result<RoutedRestartProtocolIngressV1, RestartProtocolIngressErrorV1> {
        let remote = inbound.remote();
        let session_id = inbound.session_id();
        let session_generation = inbound.session_generation();
        let frame = inbound.into_frame();
        if remote != frame.sender || session_id != frame.session {
            return Err(RestartProtocolIngressErrorV1::AuthenticatedTransportMismatch);
        }
        let message = decode_authenticated_restart_frame_v1(&frame, &self.validator_set)?;
        let transport = AuthenticatedRestartTransportV1 {
            source: RestartTransportSourceV1::DirectMesh,
            remote,
            session_id,
            session_generation,
            outer_frame_fingerprint: frame.fingerprint(&self.run_id),
        };
        self.route_message(message, transport)
    }

    #[cfg(test)]
    pub(crate) fn admit_verified_signed_frame_bytes_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<RoutedRestartProtocolIngressV1, RestartProtocolIngressErrorV1> {
        let frame = AuthenticatedFrame::decode(bytes, &self.run_id, &self.validator_set)
            .map_err(RestartProtocolIngressErrorV1::Frame)?;
        let message = decode_authenticated_restart_frame_v1(&frame, &self.validator_set)?;
        let transport = AuthenticatedRestartTransportV1 {
            source: RestartTransportSourceV1::VerifiedSignedBytes,
            remote: frame.sender,
            session_id: frame.session,
            session_generation: 0,
            outer_frame_fingerprint: frame.fingerprint(&self.run_id),
        };
        self.route_message(message, transport)
    }

    /// Reserves the same bounded semantic and relay identities before a
    /// locally signed restart statement is exposed to the mesh. This is a
    /// transport/dedup operation only; `payload` must already have been
    /// issued by the phase-specific typed owner.
    pub(crate) fn reserve_originated_statement_v1(
        &mut self,
        phase: RestartProtocolPhaseV1,
        payload: &[u8],
        mut relay_window: Option<&mut RestartRelayAdmissionWindowV1>,
    ) -> Result<RestartProtocolOriginReservationV1, RestartProtocolIngressErrorV1> {
        self.collector.ensure_live()?;
        if payload.is_empty() {
            return Err(RestartProtocolIngressErrorV1::EmptyPayload);
        }
        if payload.len() > MAX_RESTART_PROTOCOL_PAYLOAD_BYTES_V1 {
            return Err(RestartProtocolIngressErrorV1::PayloadTooLarge);
        }
        let message = RestartProtocolMessageV1 {
            validator_set_id: self.validator_set.id(),
            origin: self.local_validator,
            phase,
            payload: payload.to_vec(),
        };

        // Both bounded owners are read before either is mutated. In
        // particular, a mismatched/full relay window cannot strand a local
        // semantic slot which no caller received authority to publish.
        let relay_preflight = relay_window
            .as_deref()
            .map(|window| window.preflight(&message))
            .transpose()?;
        let collector_preflight = match self.collector.preflight(&message) {
            Ok(admission) => admission,
            Err(error @ RestartProtocolIngressErrorV1::Equivocation { .. }) => {
                self.collector.poisoned = true;
                return Err(error);
            }
            // A reservation preflight never poisons or otherwise mutates the
            // collector on capacity/set failures.
            Err(error) => return Err(error),
        };

        match (collector_preflight, relay_preflight) {
            (RestartProtocolAdmissionV1::ExactReplay, None)
            | (
                RestartProtocolAdmissionV1::ExactReplay,
                Some(RestartRelayAdmissionV1::ExactReplay),
            ) => {
                return Err(RestartProtocolIngressErrorV1::OriginReservationAlreadyExists);
            }
            (RestartProtocolAdmissionV1::New, None)
            | (RestartProtocolAdmissionV1::New, Some(RestartRelayAdmissionV1::New)) => {}
            _ => {
                // This can only be produced by pairing a collector with a
                // relay window that did not participate in its first local
                // reservation. Never repair that ambiguity by issuing a
                // second capability.
                return Err(RestartProtocolIngressErrorV1::InconsistentAdmissionState);
            }
        }

        let message_id = message.message_id();
        let payload_digest = message.payload_digest();
        self.collector
            .commit_preflight(&message, collector_preflight);
        let relay_instance = match (relay_window.as_deref_mut(), relay_preflight) {
            (Some(window), Some(admission)) => {
                window.commit_preflight(&message, admission);
                Some(window.instance)
            }
            (None, None) => None,
            _ => unreachable!("relay preflight and owner presence differ"),
        };
        Ok(RestartProtocolOriginReservationV1 {
            admission_instance: self.collector.instance_v1(),
            relay_instance,
            validator_set_id: message.validator_set_id,
            origin: message.origin,
            phase,
            payload: message.payload,
            message_id,
            payload_digest,
        })
    }

    /// Revalidates an already-issued reservation for an exact local retry.
    /// This borrows the sole verified owner and never mints a second one.
    pub(crate) fn verify_originated_statement_exact_retry_v1(
        &self,
        reservation: &VerifiedRestartProtocolOriginReservationV1,
        relay_window: Option<&RestartRelayAdmissionWindowV1>,
    ) -> Result<(), RestartProtocolIngressErrorV1> {
        let reservation = &reservation.reservation;
        if reservation.admission_instance != self.collector.instance
            || reservation.validator_set_id != self.validator_set.id()
            || reservation.origin != self.local_validator
        {
            return Err(RestartProtocolIngressErrorV1::OriginReservationMismatch);
        }
        let message = reservation.message_v1();
        if self.collector.preflight(&message)? != RestartProtocolAdmissionV1::ExactReplay {
            return Err(RestartProtocolIngressErrorV1::InconsistentAdmissionState);
        }
        match (reservation.relay_instance, relay_window) {
            (None, None) => Ok(()),
            (Some(expected), Some(window)) => {
                if window.instance != expected
                    || window.preflight(&message)? != RestartRelayAdmissionV1::ExactReplay
                {
                    return Err(RestartProtocolIngressErrorV1::OriginReservationMismatch);
                }
                Ok(())
            }
            _ => Err(RestartProtocolIngressErrorV1::OriginReservationMismatch),
        }
    }

    pub fn admit_restart_relay_frame(
        &mut self,
        inbound: MeshInboundFrameV0,
        relay_window: &mut RestartRelayAdmissionWindowV1,
    ) -> Result<RoutedRestartProtocolRelayV1, RestartProtocolIngressErrorV1> {
        let remote = inbound.remote();
        let session_id = inbound.session_id();
        let session_generation = inbound.session_generation();
        let outer = inbound.into_frame();
        if remote != outer.sender || session_id != outer.session {
            return Err(RestartProtocolIngressErrorV1::AuthenticatedTransportMismatch);
        }
        let transport = AuthenticatedRestartTransportV1 {
            source: RestartTransportSourceV1::SparseRelayMesh,
            remote,
            session_id,
            session_generation,
            outer_frame_fingerprint: outer.fingerprint(&self.run_id),
        };
        self.admit_restart_relay_decoded_v1(outer, transport, relay_window)
    }

    #[cfg(test)]
    fn admit_verified_restart_relay_bytes_v1(
        &mut self,
        bytes: &[u8],
        relay_window: &mut RestartRelayAdmissionWindowV1,
    ) -> Result<RoutedRestartProtocolRelayV1, RestartProtocolIngressErrorV1> {
        let outer = AuthenticatedFrame::decode(bytes, &self.run_id, &self.validator_set)
            .map_err(RestartProtocolIngressErrorV1::Frame)?;
        let transport = AuthenticatedRestartTransportV1 {
            source: RestartTransportSourceV1::VerifiedSignedBytes,
            remote: outer.sender,
            session_id: outer.session,
            session_generation: 0,
            outer_frame_fingerprint: outer.fingerprint(&self.run_id),
        };
        self.admit_restart_relay_decoded_v1(outer, transport, relay_window)
    }

    fn admit_restart_relay_decoded_v1(
        &mut self,
        outer: AuthenticatedFrame,
        transport: AuthenticatedRestartTransportV1,
        relay_window: &mut RestartRelayAdmissionWindowV1,
    ) -> Result<RoutedRestartProtocolRelayV1, RestartProtocolIngressErrorV1> {
        if outer.kind != FrameKind::ConsensusRelay {
            return Err(RestartProtocolIngressErrorV1::UnsupportedFrameKind);
        }
        if self.validator_set.validator(outer.sender).is_none() {
            return Err(RestartProtocolIngressErrorV1::UnknownSender);
        }
        let envelope = ConsensusRelayEnvelopeV0::decode(&outer.payload, &self.validator_set)?;
        let embedded = envelope.embedded_statement_frame();
        let message = decode_authenticated_restart_frame_v1(&embedded, &self.validator_set)?;
        let message_id = message.message_id();
        let preflight = relay_window.preflight(&message)?;
        if preflight == RestartRelayAdmissionV1::ExactReplay {
            return Ok(RoutedRestartProtocolRelayV1 {
                action: None,
                relay_admission: RestartRelayAdmissionV1::ExactReplay,
                collector_admission: None,
                message_id,
                forward: None,
            });
        }

        let collector_admission = match self.collector.preflight(&message) {
            Ok(admission) => admission,
            Err(error @ RestartProtocolIngressErrorV1::Equivocation { .. }) => {
                // Conflicting signed semantic bytes poison the lane, but the
                // relay window remains untouched because no two-owner commit
                // occurred.
                self.collector.poisoned = true;
                return Err(error);
            }
            // Capacity/set failures leave both bounded owners unchanged.
            Err(error) => return Err(error),
        };
        self.collector
            .commit_preflight(&message, collector_admission);
        relay_window.commit_preflight(&message, preflight);
        let action = match collector_admission {
            RestartProtocolAdmissionV1::New => Some(RoutedRestartProtocolActionV1 {
                admitted: AdmittedRestartProtocolMessageV1 {
                    admission_instance: self.collector.instance_v1(),
                    transport,
                    message,
                },
            }),
            RestartProtocolAdmissionV1::ExactReplay => None,
        };
        let forward = envelope.forwarded();
        Ok(RoutedRestartProtocolRelayV1 {
            action,
            relay_admission: preflight,
            collector_admission: Some(collector_admission),
            message_id,
            forward,
        })
    }

    pub const fn collector(&self) -> &RestartProtocolAdmissionMapV1 {
        &self.collector
    }

    fn route_message(
        &mut self,
        message: RestartProtocolMessageV1,
        transport: AuthenticatedRestartTransportV1,
    ) -> Result<RoutedRestartProtocolIngressV1, RestartProtocolIngressErrorV1> {
        let admission = self.collector.admit(&message)?;
        let action = match admission {
            RestartProtocolAdmissionV1::New => Some(RoutedRestartProtocolActionV1 {
                admitted: AdmittedRestartProtocolMessageV1 {
                    admission_instance: self.collector.instance_v1(),
                    transport,
                    message,
                },
            }),
            RestartProtocolAdmissionV1::ExactReplay => None,
        };
        Ok(RoutedRestartProtocolIngressV1 { action, admission })
    }
}

#[must_use = "an originated restart slot must be consumed by its phase verifier"]
pub(crate) struct RestartProtocolOriginReservationV1 {
    admission_instance: RestartProtocolAdmissionInstanceV1,
    relay_instance: Option<RestartRelayAdmissionInstanceV1>,
    validator_set_id: ValidatorSetId,
    origin: ValidatorId,
    phase: RestartProtocolPhaseV1,
    payload: Vec<u8>,
    message_id: [u8; 32],
    payload_digest: [u8; 32],
}

impl fmt::Debug for RestartProtocolOriginReservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestartProtocolOriginReservationV1")
            .field("admission_instance", &self.admission_instance)
            .field("relay_reserved", &self.relay_instance.is_some())
            .field("validator_set_id", &self.validator_set_id)
            .field("origin", &self.origin)
            .field("phase", &self.phase)
            .field("payload_len", &self.payload.len())
            .field("message_id", &self.message_id)
            .field("payload_digest", &self.payload_digest)
            .finish_non_exhaustive()
    }
}

impl RestartProtocolOriginReservationV1 {
    fn message_v1(&self) -> RestartProtocolMessageV1 {
        RestartProtocolMessageV1 {
            validator_set_id: self.validator_set_id,
            origin: self.origin,
            phase: self.phase,
            payload: self.payload.clone(),
        }
    }

    /// Consumes the opaque reservation and joins it to exact phase-specific
    /// bytes. Sibling modules receive only the verified non-Clone owner, not
    /// raw reservation fields that could be recombined selectively.
    pub(crate) fn into_verified_for_parts_v1(
        self,
        expected_validator_set_id: ValidatorSetId,
        expected_origin: ValidatorId,
        expected_phase: RestartProtocolPhaseV1,
        expected_payload: &[u8],
    ) -> Result<VerifiedRestartProtocolOriginReservationV1, RestartProtocolIngressErrorV1> {
        let expected_message_id = restart_protocol_message_id_for_parts_v1(
            expected_validator_set_id,
            expected_origin,
            expected_phase,
            expected_payload,
        );
        let expected_payload_digest = restart_protocol_payload_digest_for_parts_v1(
            expected_validator_set_id,
            expected_origin,
            expected_phase,
            expected_payload,
        );
        if self.validator_set_id != expected_validator_set_id
            || self.origin != expected_origin
            || self.phase != expected_phase
            || self.payload.as_slice() != expected_payload
            || self.message_id != expected_message_id
            || self.payload_digest != expected_payload_digest
        {
            return Err(RestartProtocolIngressErrorV1::OriginReservationMismatch);
        }
        Ok(VerifiedRestartProtocolOriginReservationV1 { reservation: self })
    }
}

/// Non-Clone, phase-joined authority for one locally originated slot. Its
/// facts are borrowed only for comparison and exact retry; there is no escape
/// back to a forgeable scalar reservation.
#[must_use = "a verified originated restart slot must remain in its phase owner"]
pub(crate) struct VerifiedRestartProtocolOriginReservationV1 {
    reservation: RestartProtocolOriginReservationV1,
}

impl fmt::Debug for VerifiedRestartProtocolOriginReservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VerifiedRestartProtocolOriginReservationV1")
            .field(&self.reservation)
            .finish()
    }
}

impl VerifiedRestartProtocolOriginReservationV1 {
    pub(crate) const fn admission_instance_v1(&self) -> RestartProtocolAdmissionInstanceV1 {
        self.reservation.admission_instance
    }

    pub(crate) const fn validator_set_id_v1(&self) -> ValidatorSetId {
        self.reservation.validator_set_id
    }

    pub(crate) const fn origin_v1(&self) -> ValidatorId {
        self.reservation.origin
    }

    pub(crate) const fn phase_v1(&self) -> RestartProtocolPhaseV1 {
        self.reservation.phase
    }

    pub(crate) fn payload_v1(&self) -> &[u8] {
        &self.reservation.payload
    }

    pub(crate) const fn message_id_v1(&self) -> [u8; 32] {
        self.reservation.message_id
    }

    pub(crate) const fn payload_digest_v1(&self) -> [u8; 32] {
        self.reservation.payload_digest
    }

    pub(crate) const fn relay_reserved_v1(&self) -> bool {
        self.reservation.relay_instance.is_some()
    }
}

#[derive(Debug)]
pub enum RestartProtocolIngressErrorV1 {
    InvalidValidatorSet,
    WrongValidatorSet,
    UnknownSender,
    AuthenticatedTransportMismatch,
    UnsupportedFrameKind,
    EmptyPayload,
    PayloadTooLarge,
    Capacity,
    OriginReservationAlreadyExists,
    OriginReservationMismatch,
    InconsistentAdmissionState,
    Equivocation {
        origin: ValidatorId,
        phase: RestartProtocolPhaseV1,
    },
    Poisoned,
    Frame(FrameError),
    Relay(ConsensusRelayErrorV0),
}

impl fmt::Display for RestartProtocolIngressErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValidatorSet => formatter.write_str("invalid G3 restart validator set"),
            Self::WrongValidatorSet => {
                formatter.write_str("restart message belongs to another validator set")
            }
            Self::UnknownSender => formatter.write_str("restart frame sender is unknown"),
            Self::AuthenticatedTransportMismatch => {
                formatter.write_str("restart frame differs from its authenticated mesh owner")
            }
            Self::UnsupportedFrameKind => {
                formatter.write_str("frame kind is outside restart protocol ingress")
            }
            Self::EmptyPayload => formatter.write_str("restart frame payload is empty"),
            Self::PayloadTooLarge => formatter.write_str("restart frame payload crosses its bound"),
            Self::Capacity => formatter.write_str("bounded restart admission capacity exhausted"),
            Self::OriginReservationAlreadyExists => formatter.write_str(
                "exact originated restart slot is already owned; reuse its existing owner",
            ),
            Self::OriginReservationMismatch => {
                formatter.write_str("originated restart reservation facts do not match")
            }
            Self::InconsistentAdmissionState => {
                formatter.write_str("restart collector and relay reservations are inconsistent")
            }
            Self::Equivocation { origin, phase } => write!(
                formatter,
                "restart payload equivocation by {} in {phase:?}",
                hex::encode(origin.as_bytes())
            ),
            Self::Poisoned => formatter.write_str("restart protocol admission is poisoned"),
            Self::Frame(error) => write!(formatter, "restart authenticated frame: {error}"),
            Self::Relay(error) => write!(formatter, "restart relay envelope: {error}"),
        }
    }
}

impl std::error::Error for RestartProtocolIngressErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::Relay(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FrameError> for RestartProtocolIngressErrorV1 {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<ConsensusRelayErrorV0> for RestartProtocolIngressErrorV1 {
    fn from(value: ConsensusRelayErrorV0) -> Self {
        Self::Relay(value)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;

    const TEST_RUN_ID: &str = "poco-g3-7-20260818T000000Z-a1b2c3d4";
    const RESTART_KINDS: [FrameKind; RESTART_PROTOCOL_PHASES_V1] = [
        FrameKind::RestartPrepare,
        FrameKind::RestartCut,
        FrameKind::RestartParkedAck,
        FrameKind::RestartRecoveryReady,
        FrameKind::RestartRecoveryStart,
    ];

    fn fixture() -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0u8..7)
            .map(|index| SigningKey::from_bytes(&[0x31 + index; 32]))
            .collect::<Vec<_>>();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x11 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-restart-protocol-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn frame(origin: ValidatorId, kind: FrameKind, payload: Vec<u8>) -> AuthenticatedFrame {
        AuthenticatedFrame {
            sender: origin,
            session: [0x51; 32],
            sequence: 0,
            kind,
            payload,
        }
    }

    fn signed_frame(
        origin: ValidatorId,
        key: &SigningKey,
        kind: FrameKind,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        frame(origin, kind, payload)
            .encode(TEST_RUN_ID, key)
            .unwrap()
    }

    fn ingress(set: &ValidatorSet, local: ValidatorId) -> BoundedRestartProtocolIngressV1 {
        BoundedRestartProtocolIngressV1::new(TEST_RUN_ID, local, set.clone()).unwrap()
    }

    #[test]
    fn five_phases_route_once_and_fill_the_exact_five_n_bound() {
        let (set, keys) = fixture();
        let mut ingress = ingress(&set, set.validators()[0].id());
        assert_eq!(ingress.collector().maximum_entries(), 35);
        for (origin_index, validator) in set.validators().iter().enumerate() {
            for kind in RESTART_KINDS {
                let payload = vec![u8::try_from(origin_index).unwrap(), kind as u8];
                let admitted = ingress
                    .admit_verified_signed_frame_bytes_v1(&signed_frame(
                        validator.id(),
                        &keys[origin_index],
                        kind,
                        payload.clone(),
                    ))
                    .unwrap();
                assert_eq!(admitted.admission, RestartProtocolAdmissionV1::New);
                let action = admitted.action.unwrap();
                assert_eq!(action.message().origin(), validator.id());
                assert_eq!(action.message().phase().frame_kind(), kind);
                assert_eq!(action.message().payload(), payload);

                let replay = ingress
                    .admit_verified_signed_frame_bytes_v1(&signed_frame(
                        validator.id(),
                        &keys[origin_index],
                        kind,
                        payload,
                    ))
                    .unwrap();
                assert_eq!(replay.admission, RestartProtocolAdmissionV1::ExactReplay);
                assert!(replay.action.is_none());
            }
        }
        assert_eq!(ingress.collector().len(), 35);
        assert!(!ingress.collector().is_poisoned());
    }

    #[test]
    fn wrong_kind_sender_payload_and_equivocation_fail_closed() {
        let (set, keys) = fixture();
        let origin = set.validators()[0].id();
        let mut ingress = ingress(&set, origin);
        assert!(matches!(
            ingress.admit_verified_signed_frame_bytes_v1(&signed_frame(
                origin,
                &keys[0],
                FrameKind::Vote,
                vec![1],
            )),
            Err(RestartProtocolIngressErrorV1::UnsupportedFrameKind)
        ));
        assert!(matches!(
            ingress.admit_verified_signed_frame_bytes_v1(&signed_frame(
                origin,
                &keys[0],
                FrameKind::RestartCatchup,
                vec![1],
            )),
            Err(RestartProtocolIngressErrorV1::UnsupportedFrameKind)
        ));
        assert!(ingress.collector().is_empty());
        assert!(matches!(
            ingress.admit_verified_signed_frame_bytes_v1(&signed_frame(
                ValidatorId::new([0xee; 32]),
                &keys[0],
                FrameKind::RestartPrepare,
                vec![1],
            )),
            Err(RestartProtocolIngressErrorV1::Frame(
                FrameError::UnknownSender
            ))
        ));
        assert!(matches!(
            ingress.admit_verified_signed_frame_bytes_v1(&signed_frame(
                origin,
                &keys[0],
                FrameKind::RestartPrepare,
                Vec::new(),
            )),
            Err(RestartProtocolIngressErrorV1::EmptyPayload)
        ));
        assert!(matches!(
            ingress.admit_verified_signed_frame_bytes_v1(&signed_frame(
                origin,
                &keys[0],
                FrameKind::RestartPrepare,
                vec![0; MAX_RESTART_PROTOCOL_PAYLOAD_BYTES_V1 + 1],
            )),
            Err(RestartProtocolIngressErrorV1::PayloadTooLarge)
        ));

        ingress
            .admit_verified_signed_frame_bytes_v1(&signed_frame(
                origin,
                &keys[0],
                FrameKind::RestartPrepare,
                b"first".to_vec(),
            ))
            .unwrap();
        assert!(matches!(
            ingress.admit_verified_signed_frame_bytes_v1(&signed_frame(
                origin,
                &keys[0],
                FrameKind::RestartPrepare,
                b"conflict".to_vec(),
            )),
            Err(RestartProtocolIngressErrorV1::Equivocation { .. })
        ));
        assert!(ingress.collector().is_poisoned());
        assert!(matches!(
            ingress.admit_verified_signed_frame_bytes_v1(&signed_frame(
                set.validators()[1].id(),
                &keys[1],
                FrameKind::RestartPrepare,
                b"later".to_vec(),
            )),
            Err(RestartProtocolIngressErrorV1::Poisoned)
        ));
    }

    #[test]
    fn restart_relay_has_origin_bound_non_evicting_dedup() {
        let (set, keys) = fixture();
        let origin = set.validators()[0].id();
        let relay = set.validators()[1].id();
        let payload = b"opaque-prepare-statement".to_vec();
        let envelope = ConsensusRelayEnvelopeV0::new(
            origin,
            FrameKind::RestartPrepare,
            3,
            payload.clone(),
            &set,
            &keys[0],
        )
        .unwrap();
        let mut ingress = ingress(&set, set.validators()[6].id());
        let mut window = RestartRelayAdmissionWindowV1::new(&set).unwrap();
        let first = ingress
            .admit_verified_restart_relay_bytes_v1(
                &signed_frame(
                    relay,
                    &keys[1],
                    FrameKind::ConsensusRelay,
                    envelope.encode(),
                ),
                &mut window,
            )
            .unwrap();
        assert_eq!(first.relay_admission, RestartRelayAdmissionV1::New);
        assert_eq!(
            first.collector_admission,
            Some(RestartProtocolAdmissionV1::New)
        );
        assert_eq!(first.action.unwrap().message().payload(), payload);
        assert_eq!(first.forward.unwrap().remaining_hops(), 2);

        let forwarded = envelope.forwarded().unwrap();
        let replay = ingress
            .admit_verified_restart_relay_bytes_v1(
                &signed_frame(
                    set.validators()[2].id(),
                    &keys[2],
                    FrameKind::ConsensusRelay,
                    forwarded.encode(),
                ),
                &mut window,
            )
            .unwrap();
        assert_eq!(replay.relay_admission, RestartRelayAdmissionV1::ExactReplay);
        assert!(replay.action.is_none());
        assert!(replay.collector_admission.is_none());
        assert!(replay.forward.is_none());
        assert_eq!(window.len(), 1);
        assert_eq!(window.maximum_messages(), 35);

        // Identical opaque bytes from another authenticated origin must not
        // collide in the restart-specific relay identity.
        let alternate = ConsensusRelayEnvelopeV0::new(
            set.validators()[3].id(),
            FrameKind::RestartPrepare,
            1,
            payload,
            &set,
            &keys[3],
        )
        .unwrap();
        let alternate_route = ingress
            .admit_verified_restart_relay_bytes_v1(
                &signed_frame(
                    relay,
                    &keys[1],
                    FrameKind::ConsensusRelay,
                    alternate.encode(),
                ),
                &mut window,
            )
            .unwrap();
        assert_eq!(
            alternate_route.relay_admission,
            RestartRelayAdmissionV1::New
        );
        assert_ne!(alternate_route.message_id, first.message_id);
        assert_eq!(window.len(), 2);
    }

    #[test]
    fn originated_restart_statement_reserves_semantic_and_relay_identity() {
        let (set, keys) = fixture();
        let origin = set.validators()[0].id();
        let relay = set.validators()[1].id();
        let payload = b"typed-target-prepare".to_vec();
        let mut ingress = ingress(&set, origin);
        let mut window = RestartRelayAdmissionWindowV1::new(&set).unwrap();
        let first = ingress
            .reserve_originated_statement_v1(
                RestartProtocolPhaseV1::Prepare,
                &payload,
                Some(&mut window),
            )
            .unwrap();
        let first = first
            .into_verified_for_parts_v1(set.id(), origin, RestartProtocolPhaseV1::Prepare, &payload)
            .unwrap();
        assert_ne!(first.message_id_v1(), [0; 32]);
        assert_eq!(first.validator_set_id_v1(), set.id());
        assert_eq!(first.origin_v1(), origin);
        assert_eq!(first.phase_v1(), RestartProtocolPhaseV1::Prepare);
        assert_eq!(first.payload_v1(), payload);
        assert_ne!(first.payload_digest_v1(), [0; 32]);
        assert!(first.relay_reserved_v1());
        let first_message_id = first.message_id_v1();
        let admission_instance = first.admission_instance_v1();
        ingress
            .verify_originated_statement_exact_retry_v1(&first, Some(&window))
            .unwrap();

        assert!(matches!(
            ingress.reserve_originated_statement_v1(
                RestartProtocolPhaseV1::Prepare,
                &payload,
                Some(&mut window),
            ),
            Err(RestartProtocolIngressErrorV1::OriginReservationAlreadyExists)
        ));
        assert_eq!(first.message_id_v1(), first_message_id);
        assert_eq!(first.admission_instance_v1(), admission_instance);
        assert_eq!(ingress.collector().len(), 1);
        assert_eq!(window.len(), 1);

        let envelope = ConsensusRelayEnvelopeV0::new(
            origin,
            FrameKind::RestartPrepare,
            2,
            payload,
            &set,
            &keys[0],
        )
        .unwrap();
        let returned = ingress
            .admit_verified_restart_relay_bytes_v1(
                &signed_frame(
                    relay,
                    &keys[1],
                    FrameKind::ConsensusRelay,
                    envelope.encode(),
                ),
                &mut window,
            )
            .unwrap();
        assert_eq!(
            returned.relay_admission,
            RestartRelayAdmissionV1::ExactReplay
        );
        assert!(returned.action.is_none());
        assert!(returned.forward.is_none());
    }

    #[test]
    fn originated_reservation_preflight_is_atomic_and_preserves_existing_owner() {
        let (set, _) = fixture();
        let origin = set.validators()[0].id();
        let payload = b"atomic-originated-prepare".to_vec();

        let other_parameters = ConsensusParametersV0::reference_shadow_v0();
        let wrong_set = ValidatorSet::new(
            GenesisHash::new([0x22; 32]),
            ChainId::new("trnm-poco-g3-restart-protocol-other").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            other_parameters.hash(),
            set.validators().to_vec(),
        )
        .unwrap();
        let mut ingress = ingress(&set, origin);
        let mut wrong_window = RestartRelayAdmissionWindowV1::new(&wrong_set).unwrap();
        assert!(matches!(
            ingress.reserve_originated_statement_v1(
                RestartProtocolPhaseV1::Prepare,
                &payload,
                Some(&mut wrong_window),
            ),
            Err(RestartProtocolIngressErrorV1::WrongValidatorSet)
        ));
        assert!(ingress.collector().is_empty());
        assert!(wrong_window.is_empty());

        let mut full_window = RestartRelayAdmissionWindowV1::new(&set).unwrap();
        for index in 0..full_window.maximum_messages() {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
            assert!(full_window.admitted.insert(id));
        }
        assert!(matches!(
            ingress.reserve_originated_statement_v1(
                RestartProtocolPhaseV1::Prepare,
                &payload,
                Some(&mut full_window),
            ),
            Err(RestartProtocolIngressErrorV1::Capacity)
        ));
        assert!(ingress.collector().is_empty());
        assert!(!ingress.collector().is_poisoned());
        assert_eq!(full_window.len(), full_window.maximum_messages());

        let mut relay_window = RestartRelayAdmissionWindowV1::new(&set).unwrap();
        ingress.collector.maximum_entries = 0;
        assert!(matches!(
            ingress.reserve_originated_statement_v1(
                RestartProtocolPhaseV1::Prepare,
                &payload,
                Some(&mut relay_window),
            ),
            Err(RestartProtocolIngressErrorV1::Capacity)
        ));
        assert!(ingress.collector().is_empty());
        assert!(!ingress.collector().is_poisoned());
        assert!(relay_window.is_empty());
    }

    #[test]
    fn relay_outer_and_inner_kind_errors_never_touch_restart_slots() {
        let (set, keys) = fixture();
        let origin = set.validators()[0].id();
        let mut ingress = ingress(&set, origin);
        let mut window = RestartRelayAdmissionWindowV1::new(&set).unwrap();
        assert!(matches!(
            ingress.admit_verified_restart_relay_bytes_v1(
                &signed_frame(origin, &keys[0], FrameKind::RestartPrepare, vec![1],),
                &mut window,
            ),
            Err(RestartProtocolIngressErrorV1::UnsupportedFrameKind)
        ));
        let ordinary =
            ConsensusRelayEnvelopeV0::new(origin, FrameKind::Vote, 1, vec![1], &set, &keys[0])
                .unwrap();
        assert!(matches!(
            ingress.admit_verified_restart_relay_bytes_v1(
                &signed_frame(
                    origin,
                    &keys[0],
                    FrameKind::ConsensusRelay,
                    ordinary.encode(),
                ),
                &mut window,
            ),
            Err(RestartProtocolIngressErrorV1::UnsupportedFrameKind)
        ));
        let catchup = ConsensusRelayEnvelopeV0::new(
            origin,
            FrameKind::RestartCatchup,
            1,
            vec![1],
            &set,
            &keys[0],
        )
        .unwrap();
        assert!(matches!(
            ingress.admit_verified_restart_relay_bytes_v1(
                &signed_frame(
                    origin,
                    &keys[0],
                    FrameKind::ConsensusRelay,
                    catchup.encode(),
                ),
                &mut window,
            ),
            Err(RestartProtocolIngressErrorV1::UnsupportedFrameKind)
        ));
        assert!(ingress.collector().is_empty());
        assert!(window.is_empty());
    }

    #[test]
    fn restart_capacity_is_exactly_five_n_for_frozen_topologies() {
        assert_eq!(required_restart_protocol_capacity_v1(7).unwrap(), 35);
        assert_eq!(required_restart_protocol_capacity_v1(31).unwrap(), 155);
        assert_eq!(required_restart_protocol_capacity_v1(100).unwrap(), 500);
        for invalid in [0, 1, 6, 8, 30, 32, 99, 101, usize::MAX] {
            assert!(required_restart_protocol_capacity_v1(invalid).is_err());
        }
    }
}
