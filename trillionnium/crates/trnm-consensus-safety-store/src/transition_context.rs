use trnm_consensus_core::{
    PayloadTerminalResult, PayloadValidationRouteV0, SafetyState, ValidationId,
};
use trnm_consensus_types::{BlockId, View};

use crate::{hash::hash_domain, SafetyStoreErrorV0};

pub const SAFETY_TRANSITION_CONTEXT_CODEC_VERSION_V0: u16 = 0;
pub const NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0: u32 = 1;
pub const NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0: u32 = 2;

const ORDINARY_TAG_V0: u8 = 0;
const NATIVE_DETERMINISTIC_INVALID_TAG_V0: u8 = 1;
const ORDINARY_CONTEXT_BYTES_V0: usize = 3;
const NATIVE_INVALID_CONTEXT_BYTES_V0: usize = 328;
const CONTEXT_CHECKSUM_DOMAIN_V0: &str = "trnm.consensus-safety-store.transition-context.v0";

/// Inert host facts which identify the exact deterministic-invalid callback
/// whose Core transition produced one persisted SafetyState revision.
///
/// These fields are comparison material only. Construction does not grant
/// callback, application-journal, or Core authority; the application adapter
/// must derive them from its retained live owner and recovery must rebind them
/// to the exact application row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDeterministicInvalidTransitionV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    request_fingerprint: [u8; 32],
    job_immutable_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    reason_code: u32,
    artifact_checksum: [u8; 32],
    callback_payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
    delivered_job_row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
    completion_revision: u64,
}

impl NativeDeterministicInvalidTransitionV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        request_fingerprint: [u8; 32],
        job_immutable_checksum: [u8; 32],
        application_host_config_ref: [u8; 32],
        reason_code: u32,
        artifact_checksum: [u8; 32],
        callback_payload_checksum: [u8; 32],
        idempotency_key: [u8; 32],
        delivery_attempt: u64,
        delivered_job_row_checksum: [u8; 32],
        outbox_checksum: [u8; 32],
        completion_revision: u64,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if !matches!(
            reason_code,
            NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0
                | NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0
        ) || delivery_attempt == 0
            || completion_revision == 0
            || [
                request_fingerprint,
                job_immutable_checksum,
                application_host_config_ref,
                artifact_checksum,
                callback_payload_checksum,
                idempotency_key,
                delivered_job_row_checksum,
                outbox_checksum,
            ]
            .contains(&[0; 32])
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "native deterministic-invalid transition facts",
            ));
        }
        Ok(Self {
            route,
            validation_id,
            request_fingerprint,
            job_immutable_checksum,
            application_host_config_ref,
            reason_code,
            artifact_checksum,
            callback_payload_checksum,
            idempotency_key,
            delivery_attempt,
            delivered_job_row_checksum,
            outbox_checksum,
            completion_revision,
        })
    }

    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(&self) -> ValidationId {
        self.validation_id
    }

    pub const fn request_fingerprint(&self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub const fn job_immutable_checksum(&self) -> [u8; 32] {
        self.job_immutable_checksum
    }

    pub const fn application_host_config_ref(&self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn reason_code(&self) -> u32 {
        self.reason_code
    }

    pub const fn artifact_checksum(&self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.callback_payload_checksum
    }

    pub const fn idempotency_key(&self) -> [u8; 32] {
        self.idempotency_key
    }

    pub const fn delivery_attempt(&self) -> u64 {
        self.delivery_attempt
    }

    pub const fn delivered_job_row_checksum(&self) -> [u8; 32] {
        self.delivered_job_row_checksum
    }

    pub const fn outbox_checksum(&self) -> [u8; 32] {
        self.outbox_checksum
    }

    pub const fn completion_revision(&self) -> u64 {
        self.completion_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyTransitionContextV0 {
    Ordinary,
    NativeDeterministicInvalid(Box<NativeDeterministicInvalidTransitionV0>),
}

impl SafetyTransitionContextV0 {
    pub const fn ordinary() -> Self {
        Self::Ordinary
    }

    pub fn native_deterministic_invalid(facts: NativeDeterministicInvalidTransitionV0) -> Self {
        Self::NativeDeterministicInvalid(Box::new(facts))
    }

    pub fn native_invalid(&self) -> Option<&NativeDeterministicInvalidTransitionV0> {
        match self {
            Self::Ordinary => None,
            Self::NativeDeterministicInvalid(facts) => Some(facts.as_ref()),
        }
    }
}

pub fn encode_transition_context_v0(
    context: &SafetyTransitionContextV0,
) -> Result<Vec<u8>, SafetyStoreErrorV0> {
    let mut bytes = Vec::with_capacity(match context {
        SafetyTransitionContextV0::Ordinary => ORDINARY_CONTEXT_BYTES_V0,
        SafetyTransitionContextV0::NativeDeterministicInvalid(_) => NATIVE_INVALID_CONTEXT_BYTES_V0,
    });
    bytes.extend_from_slice(&SAFETY_TRANSITION_CONTEXT_CODEC_VERSION_V0.to_be_bytes());
    match context {
        SafetyTransitionContextV0::Ordinary => bytes.push(ORDINARY_TAG_V0),
        SafetyTransitionContextV0::NativeDeterministicInvalid(facts) => {
            bytes.push(NATIVE_DETERMINISTIC_INVALID_TAG_V0);
            bytes.push(match facts.route {
                PayloadValidationRouteV0::Proposal => 0,
                PayloadValidationRouteV0::Synced => 1,
            });
            bytes.extend_from_slice(facts.validation_id.block_id().as_bytes());
            bytes.extend_from_slice(&facts.validation_id.view().get().to_be_bytes());
            bytes.extend_from_slice(&facts.validation_id.generation().to_be_bytes());
            bytes.extend_from_slice(&facts.request_fingerprint);
            bytes.extend_from_slice(&facts.job_immutable_checksum);
            bytes.extend_from_slice(&facts.application_host_config_ref);
            bytes.extend_from_slice(&facts.reason_code.to_be_bytes());
            bytes.extend_from_slice(&facts.artifact_checksum);
            bytes.extend_from_slice(&facts.callback_payload_checksum);
            bytes.extend_from_slice(&facts.idempotency_key);
            bytes.extend_from_slice(&facts.delivery_attempt.to_be_bytes());
            bytes.extend_from_slice(&facts.delivered_job_row_checksum);
            bytes.extend_from_slice(&facts.outbox_checksum);
            bytes.extend_from_slice(&facts.completion_revision.to_be_bytes());
        }
    }
    Ok(bytes)
}

pub fn decode_transition_context_v0_exact(
    bytes: &[u8],
) -> Result<SafetyTransitionContextV0, SafetyStoreErrorV0> {
    if bytes.len() < ORDINARY_CONTEXT_BYTES_V0 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "truncated transition context",
        ));
    }
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version != SAFETY_TRANSITION_CONTEXT_CODEC_VERSION_V0 {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "unsupported transition-context codec",
        ));
    }
    let context = match bytes[2] {
        ORDINARY_TAG_V0 if bytes.len() == ORDINARY_CONTEXT_BYTES_V0 => {
            SafetyTransitionContextV0::Ordinary
        }
        NATIVE_DETERMINISTIC_INVALID_TAG_V0 if bytes.len() == NATIVE_INVALID_CONTEXT_BYTES_V0 => {
            let mut offset = 3usize;
            let route = match take::<1>(bytes, &mut offset)?[0] {
                0 => PayloadValidationRouteV0::Proposal,
                1 => PayloadValidationRouteV0::Synced,
                _ => {
                    return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "unknown transition route",
                    ));
                }
            };
            let block_id = BlockId::new(take::<32>(bytes, &mut offset)?);
            let view = View::new(u64::from_be_bytes(take::<8>(bytes, &mut offset)?));
            let generation = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
            let validation_id = ValidationId::new(block_id, view, generation);
            let facts = NativeDeterministicInvalidTransitionV0::new(
                route,
                validation_id,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u32::from_be_bytes(take::<4>(bytes, &mut offset)?),
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
            )?;
            if offset != bytes.len() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "transition context trailing bytes",
                ));
            }
            SafetyTransitionContextV0::native_deterministic_invalid(facts)
        }
        ORDINARY_TAG_V0 | NATIVE_DETERMINISTIC_INVALID_TAG_V0 => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "transition context has a non-canonical length",
            ));
        }
        _ => {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "unknown transition-context tag",
            ));
        }
    };
    if encode_transition_context_v0(&context)?.as_slice() != bytes {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "non-canonical transition context",
        ));
    }
    Ok(context)
}

pub fn validate_transition_context_against_state_v0(
    context: &SafetyTransitionContextV0,
    state: &SafetyState,
) -> Result<(), SafetyStoreErrorV0> {
    let newly_recorded_completion_count = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.first_recorded_revision() == state.revision())
        .count();
    let SafetyTransitionContextV0::NativeDeterministicInvalid(facts) = context else {
        if state
            .payload_validation_completions()
            .iter()
            .any(|completion| {
                completion.first_recorded_revision() == state.revision()
                    && completion.result().is_deterministically_invalid()
            })
        {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "new deterministic-invalid completion lacks transition context",
            ));
        }
        return Ok(());
    };
    if state.revision() != facts.completion_revision {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "callback transition revision does not match SafetyState",
        ));
    }
    let mut completions = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| {
            completion.route() == facts.route && completion.id() == facts.validation_id
        });
    let completion =
        completions
            .next()
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "callback transition has no exact Core completion",
            ))?;
    if completions.next().is_some()
        || newly_recorded_completion_count != 1
        || !completion.result().is_deterministically_invalid()
        || completion.first_recorded_revision() != facts.completion_revision
        || state
            .payload_validation_obligations()
            .iter()
            .any(|obligation| {
                obligation.route() == facts.route && obligation.id() == facts.validation_id
            })
        || !state.payload_terminal_facts().iter().any(|fact| {
            fact.block_id() == facts.validation_id.block_id()
                && fact.result() == PayloadTerminalResult::DeterministicallyInvalid
        })
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "callback transition is not congruent with Core state",
        ));
    }
    Ok(())
}

pub fn transition_context_checksum_v0(bytes: &[u8]) -> Result<[u8; 32], SafetyStoreErrorV0> {
    let context = decode_transition_context_v0_exact(bytes)?;
    if encode_transition_context_v0(&context)?.as_slice() != bytes {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "non-canonical transition context",
        ));
    }
    Ok(hash_domain(CONTEXT_CHECKSUM_DOMAIN_V0, &[bytes]))
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], SafetyStoreErrorV0> {
    let end = offset
        .checked_add(N)
        .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "transition context offset overflow",
        ))?;
    let value =
        bytes
            .get(*offset..end)
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "truncated transition context",
            ))?;
    *offset = end;
    value
        .try_into()
        .map_err(|_| SafetyStoreErrorV0::PersistedRepresentationMalformed("transition field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> NativeDeterministicInvalidTransitionV0 {
        NativeDeterministicInvalidTransitionV0::new(
            PayloadValidationRouteV0::Proposal,
            ValidationId::new(BlockId::new([0x11; 32]), View::new(7), 9),
            [0x21; 32],
            [0x22; 32],
            [0x23; 32],
            NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
            [0x24; 32],
            [0x25; 32],
            [0x26; 32],
            1,
            [0x27; 32],
            [0x28; 32],
            10,
        )
        .expect("valid facts")
    }

    #[test]
    fn transition_context_codec_is_exact_and_bounded() {
        let ordinary = encode_transition_context_v0(&SafetyTransitionContextV0::Ordinary)
            .expect("encode ordinary");
        assert_eq!(ordinary, [0, 0, 0]);
        assert_eq!(
            decode_transition_context_v0_exact(&ordinary).expect("decode ordinary"),
            SafetyTransitionContextV0::Ordinary
        );

        let context = SafetyTransitionContextV0::native_deterministic_invalid(facts());
        let encoded = encode_transition_context_v0(&context).expect("encode invalid context");
        assert_eq!(encoded.len(), NATIVE_INVALID_CONTEXT_BYTES_V0);
        assert_eq!(
            decode_transition_context_v0_exact(&encoded).expect("decode invalid context"),
            context
        );
        assert!(decode_transition_context_v0_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_transition_context_v0_exact(&trailing).is_err());
    }
}
