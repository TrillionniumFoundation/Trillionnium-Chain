use trnm_consensus_core::{
    native_valid_result_checksum_v0 as core_native_valid_result_checksum_v0,
    AuthenticatedGenesisApplicationParentV0, DurablePayloadValidationResultV1,
    DurableStateSyncAnchorV0, PayloadTerminalResult, PayloadValidationRouteV0, SafetyState,
    ValidationId,
};
use trnm_consensus_types::{BlockId, CertificateId, Height, StateRoot, View};

use crate::{hash::hash_domain, SafetyStoreErrorV0};

pub const SAFETY_TRANSITION_CONTEXT_CODEC_VERSION_V0: u16 = 0;
pub const NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0: u32 = 1;
pub const NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0: u32 = 2;

const ORDINARY_TAG_V0: u8 = 0;
const NATIVE_DETERMINISTIC_INVALID_TAG_V0: u8 = 1;
const NATIVE_VALID_TAG_V0: u8 = 2;
const NATIVE_FINALIZATION_APPLIED_TAG_V0: u8 = 3;
const STATE_SYNC_CHECKPOINT_BOOTSTRAP_TAG_V0: u8 = 4;
const AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_TAG_V0: u8 = 5;
const STATE_SYNC_ANCHOR_ORDINARY_PROMOTION_TAG_V0: u8 = 6;
const ORDINARY_CONTEXT_BYTES_V0: usize = 3;
const NATIVE_INVALID_CONTEXT_BYTES_V0: usize = 328;
const NATIVE_VALID_CONTEXT_BYTES_V0: usize = 328;
const NATIVE_FINALIZATION_APPLIED_CONTEXT_BYTES_V0: usize = 328;
const STATE_SYNC_CHECKPOINT_BOOTSTRAP_CONTEXT_BYTES_V0: usize = 195;
const AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_CONTEXT_BYTES_V0: usize = 219;
const STATE_SYNC_ANCHOR_ORDINARY_PROMOTION_CONTEXT_BYTES_V0: usize = 171;
const CONTEXT_CHECKSUM_DOMAIN_V0: &str = "trnm.consensus-safety-store.transition-context.v0";
const STATE_SYNC_ANCHOR_CHECKSUM_DOMAIN_V0: &str =
    "trnm.consensus-safety-store.state-sync-anchor.v0";

pub const NATIVE_VALID_POST_ACK_NONE_V0: u32 = 0;
pub const NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0: u32 = 1;
pub const NATIVE_VALID_POST_ACK_ARM_VIEW_TIMER_V0: u32 = 2;
pub const NATIVE_VALID_POST_ACK_ARM_VIEW_TIMER_THEN_FINALIZE_V0: u32 = 3;
pub const NATIVE_VALID_POST_ACK_REQUEST_TC_HIGH_QC_SYNC_V0: u32 = 4;
pub const NATIVE_VALID_POST_ACK_REQUEST_STANDALONE_QC_SYNC_V0: u32 = 5;
pub const NATIVE_VALID_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0: u32 = 6;
pub const NATIVE_VALID_POST_ACK_SAFETY_HALTED_CONFLICT_V0: u32 = 7;

pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_NONE_V0: u32 = 0;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_V0: u32 = 1;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_REQUEST_SIGNATURE_V0: u32 = 2;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_REQUEST_SIGNATURE_V0: u32 = 3;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_FINALIZE_V0: u32 = 4;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_FINALIZE_V0: u32 = 5;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_REQUEST_TC_HIGH_QC_SYNC_V0: u32 = 6;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_REQUEST_STANDALONE_QC_SYNC_V0: u32 = 7;
pub const NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0: u32 = 8;

/// Canonical comparison facts for the sole revision-zero, fresh-validator h1
/// state-sync initialization accepted by journal v6.
///
/// The anchor checksum binds the full proof through its canonical proof ID and
/// the exact authenticated parent/target coordinates. The independent state
/// record checksum binds the complete schema-v12 SafetyState bytes installed
/// in the same journal row. Decoding these facts grants no Core, application,
/// signer, or state-sync authority. Core never prepares this tag for a config
/// carrying an authenticated genesis application parent; the two bootstrap
/// modes are mutually exclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSyncCheckpointBootstrapTransitionV0 {
    anchor_checksum: [u8; 32],
    state_record_checksum: [u8; 32],
    proof_id: CertificateId,
    target_block_id: BlockId,
    target_state_root: StateRoot,
    target_height: Height,
    target_view: View,
    target_timestamp_ms: u64,
    transition_revision: u64,
}

impl StateSyncCheckpointBootstrapTransitionV0 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        anchor_checksum: [u8; 32],
        state_record_checksum: [u8; 32],
        proof_id: CertificateId,
        target_block_id: BlockId,
        target_state_root: StateRoot,
        target_height: Height,
        target_view: View,
        target_timestamp_ms: u64,
        transition_revision: u64,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if anchor_checksum == [0; 32]
            || state_record_checksum == [0; 32]
            || proof_id.is_zero()
            || target_block_id.is_zero()
            || target_height != Height::new(1)
            || target_view.get() == 0
            || target_timestamp_ms == 0
            || transition_revision != 0
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "state-sync checkpoint bootstrap transition facts",
            ));
        }
        Ok(Self {
            anchor_checksum,
            state_record_checksum,
            proof_id,
            target_block_id,
            target_state_root,
            target_height,
            target_view,
            target_timestamp_ms,
            transition_revision,
        })
    }

    pub(crate) fn from_state_record_v0(
        state: &SafetyState,
        state_record_checksum: [u8; 32],
    ) -> Result<Self, SafetyStoreErrorV0> {
        let anchor = state.state_sync_anchor().ok_or(
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync bootstrap transition has no Core anchor",
            ),
        )?;
        let target = anchor.proof().finalized_block().header();
        Self::new(
            state_sync_anchor_checksum_v0(anchor),
            state_record_checksum,
            anchor.proof_id(),
            target.id(),
            target.state_root(),
            target.height(),
            target.view(),
            target.timestamp_ms(),
            state.revision(),
        )
    }

    pub const fn anchor_checksum(&self) -> [u8; 32] {
        self.anchor_checksum
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.state_record_checksum
    }

    pub const fn proof_id(&self) -> CertificateId {
        self.proof_id
    }

    pub const fn target_block_id(&self) -> BlockId {
        self.target_block_id
    }

    pub const fn target_state_root(&self) -> StateRoot {
        self.target_state_root
    }

    pub const fn target_height(&self) -> Height {
        self.target_height
    }

    pub const fn target_view(&self) -> View {
        self.target_view
    }

    pub const fn target_timestamp_ms(&self) -> u64 {
        self.target_timestamp_ms
    }

    pub const fn transition_revision(&self) -> u64 {
        self.transition_revision
    }
}

/// Canonical durable record for the sole anchored-successor H3Valid revision
/// four to anchored-ordinary revision five transition.
///
/// This context does not replace the permanent Core anchor.  It binds the
/// complete revision-five state record, the exact h1 proof, and both retained
/// h2/h3 Valid results.  SafetyStore additionally requires the Core-owned
/// promotion manifest and the authenticated revision-four predecessor before
/// inserting this tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSyncAnchorOrdinaryPromotionTransitionV0 {
    anchor_checksum: [u8; 32],
    state_record_checksum: [u8; 32],
    proof_id: CertificateId,
    h2_valid_result_checksum: [u8; 32],
    h3_valid_result_checksum: [u8; 32],
    transition_revision: u64,
}

impl StateSyncAnchorOrdinaryPromotionTransitionV0 {
    fn new(
        anchor_checksum: [u8; 32],
        state_record_checksum: [u8; 32],
        proof_id: CertificateId,
        h2_valid_result_checksum: [u8; 32],
        h3_valid_result_checksum: [u8; 32],
        transition_revision: u64,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if anchor_checksum == [0; 32]
            || state_record_checksum == [0; 32]
            || proof_id.is_zero()
            || h2_valid_result_checksum == [0; 32]
            || h3_valid_result_checksum == [0; 32]
            || transition_revision != 5
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "state-sync anchored-ordinary promotion transition facts",
            ));
        }
        Ok(Self {
            anchor_checksum,
            state_record_checksum,
            proof_id,
            h2_valid_result_checksum,
            h3_valid_result_checksum,
            transition_revision,
        })
    }

    pub(crate) fn from_state_record_v0(
        state: &SafetyState,
        state_record_checksum: [u8; 32],
    ) -> Result<Self, SafetyStoreErrorV0> {
        let anchor = state.state_sync_anchor().ok_or(
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync promotion transition has no Core anchor",
            ),
        )?;
        let h2_id = anchor.proof().child().header().id();
        let h3_id = anchor.proof().grandchild().header().id();
        let valid_checksum = |block_id: BlockId| {
            let mut matches = state
                .payload_validation_completions()
                .iter()
                .filter(|completion| completion.id().block_id() == block_id);
            let completion =
                matches
                    .next()
                    .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                        "state-sync promotion lacks a successor Valid result",
                    ))?;
            if matches.next().is_some() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion duplicates a successor Valid result",
                ));
            }
            core_native_valid_result_checksum_v0(completion.result()).ok_or(
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion successor result is not canonically Valid",
                ),
            )
        };
        Self::new(
            state_sync_anchor_checksum_v0(anchor),
            state_record_checksum,
            anchor.proof_id(),
            valid_checksum(h2_id)?,
            valid_checksum(h3_id)?,
            state.revision(),
        )
    }

    pub const fn anchor_checksum(&self) -> [u8; 32] {
        self.anchor_checksum
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.state_record_checksum
    }

    pub const fn proof_id(&self) -> CertificateId {
        self.proof_id
    }

    pub const fn h2_valid_result_checksum(&self) -> [u8; 32] {
        self.h2_valid_result_checksum
    }

    pub const fn h3_valid_result_checksum(&self) -> [u8; 32] {
        self.h3_valid_result_checksum
    }

    pub const fn transition_revision(&self) -> u64 {
        self.transition_revision
    }
}

/// Canonical comparison facts for one operator-pinned authenticated-genesis
/// application parent installed as the revision-zero journal head.
///
/// The complete carrier remains an explicit second trust root: it is not a
/// block header and is not authenticated by GenesisQC. The independent
/// carrier binding reference prevents a field-spliced representation, while
/// the state-record checksum joins these facts to the complete schema-v12
/// SafetyState record and its exact Core/verifier/limits configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedGenesisApplicationBootstrapTransitionV0 {
    carrier: AuthenticatedGenesisApplicationParentV0,
    carrier_binding_ref: [u8; 32],
    state_record_checksum: [u8; 32],
    transition_revision: u64,
}

impl AuthenticatedGenesisApplicationBootstrapTransitionV0 {
    fn new(
        carrier: AuthenticatedGenesisApplicationParentV0,
        carrier_binding_ref: [u8; 32],
        state_record_checksum: [u8; 32],
        transition_revision: u64,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if carrier_binding_ref == [0; 32]
            || carrier_binding_ref != carrier.binding_ref_v0()
            || state_record_checksum == [0; 32]
            || transition_revision != 0
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "authenticated-genesis application bootstrap transition facts",
            ));
        }
        Ok(Self {
            carrier,
            carrier_binding_ref,
            state_record_checksum,
            transition_revision,
        })
    }

    pub(crate) fn from_state_record_v0(
        state: &SafetyState,
        state_record_checksum: [u8; 32],
    ) -> Result<Self, SafetyStoreErrorV0> {
        let carrier = state
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "authenticated-genesis bootstrap transition has no application parent",
            ))?;
        Self::new(
            carrier,
            carrier.binding_ref_v0(),
            state_record_checksum,
            state.revision(),
        )
    }

    pub const fn carrier(&self) -> AuthenticatedGenesisApplicationParentV0 {
        self.carrier
    }

    pub const fn carrier_binding_ref(&self) -> [u8; 32] {
        self.carrier_binding_ref
    }

    pub const fn state_record_checksum(&self) -> [u8; 32] {
        self.state_record_checksum
    }

    pub const fn transition_revision(&self) -> u64 {
        self.transition_revision
    }
}

/// Checksums the exact state-sync anchor geometry and canonical proof ID.
pub fn state_sync_anchor_checksum_v0(anchor: &DurableStateSyncAnchorV0) -> [u8; 32] {
    let parent = anchor.authenticated_parent();
    let target = anchor.proof().finalized_block().header();
    hash_domain(
        STATE_SYNC_ANCHOR_CHECKSUM_DOMAIN_V0,
        &[
            &parent.height().get().to_be_bytes(),
            &parent.view().get().to_be_bytes(),
            parent.block_id().as_bytes(),
            &parent.timestamp_ms().to_be_bytes(),
            anchor.proof_id().as_bytes(),
            target.id().as_bytes(),
            &target.height().get().to_be_bytes(),
            &target.view().get().to_be_bytes(),
            &target.timestamp_ms().to_be_bytes(),
            target.state_root().as_bytes(),
        ],
    )
}

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

/// Inert host facts which identify one application-sealed Valid callback and
/// the exact Core transition which accepted it.
///
/// This record is comparison material only. In particular, decoding it does
/// not recreate a request permit, application-seal proof, Core persistence
/// authority, StorageAck, or deferred effect. Recovery must authenticate the
/// application journal and remint those one-shot capabilities independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeValidTransitionV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    request_fingerprint: [u8; 32],
    job_immutable_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    valid_result_checksum: [u8; 32],
    callback_payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
    delivered_job_row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
    post_ack_action_code: u32,
    completion_revision: u64,
}

impl NativeValidTransitionV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        request_fingerprint: [u8; 32],
        job_immutable_checksum: [u8; 32],
        application_host_config_ref: [u8; 32],
        valid_result_checksum: [u8; 32],
        callback_payload_checksum: [u8; 32],
        idempotency_key: [u8; 32],
        delivery_attempt: u64,
        delivered_job_row_checksum: [u8; 32],
        outbox_checksum: [u8; 32],
        post_ack_action_code: u32,
        completion_revision: u64,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if delivery_attempt != 1
            || completion_revision == 0
            || post_ack_action_code > NATIVE_VALID_POST_ACK_SAFETY_HALTED_CONFLICT_V0
            || [
                request_fingerprint,
                job_immutable_checksum,
                application_host_config_ref,
                valid_result_checksum,
                callback_payload_checksum,
                idempotency_key,
                delivered_job_row_checksum,
                outbox_checksum,
            ]
            .contains(&[0; 32])
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "native Valid transition facts",
            ));
        }
        Ok(Self {
            route,
            validation_id,
            request_fingerprint,
            job_immutable_checksum,
            application_host_config_ref,
            valid_result_checksum,
            callback_payload_checksum,
            idempotency_key,
            delivery_attempt,
            delivered_job_row_checksum,
            outbox_checksum,
            post_ack_action_code,
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

    pub const fn valid_result_checksum(&self) -> [u8; 32] {
        self.valid_result_checksum
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

    pub const fn post_ack_action_code(&self) -> u32 {
        self.post_ack_action_code
    }

    pub const fn completion_revision(&self) -> u64 {
        self.completion_revision
    }

    #[cfg(test)]
    pub(crate) fn tamper_request_fingerprint_for_test_v0(&mut self) {
        self.request_fingerprint[0] ^= 1;
    }
}

/// Inert facts binding one exact ApplicationStore finalization apply/readback
/// to the Core SafetyState transition which consumes that ordered queue front.
///
/// Decoding this comparison record grants no application receipt, Core queue
/// permit, persistence acknowledgement, or deferred-effect authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinalizationAppliedTransitionV0 {
    source_route: PayloadValidationRouteV0,
    source_validation_id: ValidationId,
    ordinal: u64,
    application_host_config_ref: [u8; 32],
    finalization_checksum: [u8; 32],
    prior_head_checksum: [u8; 32],
    new_head_checksum: [u8; 32],
    source_artifact_checksum: [u8; 32],
    accepted_source_checksum: [u8; 32],
    applied_job_row_checksum: [u8; 32],
    receipt_row_checksum: [u8; 32],
    post_ack_action_code: u32,
    completion_revision: u64,
}

impl NativeFinalizationAppliedTransitionV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_route: PayloadValidationRouteV0,
        source_validation_id: ValidationId,
        ordinal: u64,
        application_host_config_ref: [u8; 32],
        finalization_checksum: [u8; 32],
        prior_head_checksum: [u8; 32],
        new_head_checksum: [u8; 32],
        source_artifact_checksum: [u8; 32],
        accepted_source_checksum: [u8; 32],
        applied_job_row_checksum: [u8; 32],
        receipt_row_checksum: [u8; 32],
        post_ack_action_code: u32,
        completion_revision: u64,
    ) -> Result<Self, SafetyStoreErrorV0> {
        if ordinal == 0
            || source_validation_id.view().get() == 0
            || completion_revision == 0
            || post_ack_action_code
                > NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0
            || [
                application_host_config_ref,
                finalization_checksum,
                prior_head_checksum,
                new_head_checksum,
                source_artifact_checksum,
                accepted_source_checksum,
                applied_job_row_checksum,
                receipt_row_checksum,
            ]
            .contains(&[0; 32])
            || prior_head_checksum == new_head_checksum
        {
            return Err(SafetyStoreErrorV0::InvalidProfile(
                "native finalization-applied transition facts",
            ));
        }
        Ok(Self {
            source_route,
            source_validation_id,
            ordinal,
            application_host_config_ref,
            finalization_checksum,
            prior_head_checksum,
            new_head_checksum,
            source_artifact_checksum,
            accepted_source_checksum,
            applied_job_row_checksum,
            receipt_row_checksum,
            post_ack_action_code,
            completion_revision,
        })
    }

    pub const fn source_route(&self) -> PayloadValidationRouteV0 {
        self.source_route
    }

    pub const fn source_validation_id(&self) -> ValidationId {
        self.source_validation_id
    }

    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub const fn application_host_config_ref(&self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn finalization_checksum(&self) -> [u8; 32] {
        self.finalization_checksum
    }

    pub const fn prior_head_checksum(&self) -> [u8; 32] {
        self.prior_head_checksum
    }

    pub const fn new_head_checksum(&self) -> [u8; 32] {
        self.new_head_checksum
    }

    pub const fn source_artifact_checksum(&self) -> [u8; 32] {
        self.source_artifact_checksum
    }

    pub const fn accepted_source_checksum(&self) -> [u8; 32] {
        self.accepted_source_checksum
    }

    pub const fn applied_job_row_checksum(&self) -> [u8; 32] {
        self.applied_job_row_checksum
    }

    pub const fn receipt_row_checksum(&self) -> [u8; 32] {
        self.receipt_row_checksum
    }

    pub const fn post_ack_action_code(&self) -> u32 {
        self.post_ack_action_code
    }

    pub const fn completion_revision(&self) -> u64 {
        self.completion_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyTransitionContextV0 {
    Ordinary,
    NativeDeterministicInvalid(Box<NativeDeterministicInvalidTransitionV0>),
    NativeValid(Box<NativeValidTransitionV0>),
    NativeFinalizationApplied(Box<NativeFinalizationAppliedTransitionV0>),
    StateSyncCheckpointBootstrap(Box<StateSyncCheckpointBootstrapTransitionV0>),
    AuthenticatedGenesisApplicationBootstrap(
        Box<AuthenticatedGenesisApplicationBootstrapTransitionV0>,
    ),
    StateSyncAnchorOrdinaryPromotion(Box<StateSyncAnchorOrdinaryPromotionTransitionV0>),
}

impl SafetyTransitionContextV0 {
    pub const fn ordinary() -> Self {
        Self::Ordinary
    }

    pub fn native_deterministic_invalid(facts: NativeDeterministicInvalidTransitionV0) -> Self {
        Self::NativeDeterministicInvalid(Box::new(facts))
    }

    pub fn native_valid(facts: NativeValidTransitionV0) -> Self {
        Self::NativeValid(Box::new(facts))
    }

    pub fn native_finalization_applied(facts: NativeFinalizationAppliedTransitionV0) -> Self {
        Self::NativeFinalizationApplied(Box::new(facts))
    }

    pub fn state_sync_checkpoint_bootstrap(
        facts: StateSyncCheckpointBootstrapTransitionV0,
    ) -> Self {
        Self::StateSyncCheckpointBootstrap(Box::new(facts))
    }

    pub fn authenticated_genesis_application_bootstrap(
        facts: AuthenticatedGenesisApplicationBootstrapTransitionV0,
    ) -> Self {
        Self::AuthenticatedGenesisApplicationBootstrap(Box::new(facts))
    }

    pub fn state_sync_anchor_ordinary_promotion(
        facts: StateSyncAnchorOrdinaryPromotionTransitionV0,
    ) -> Self {
        Self::StateSyncAnchorOrdinaryPromotion(Box::new(facts))
    }

    pub fn native_invalid(&self) -> Option<&NativeDeterministicInvalidTransitionV0> {
        match self {
            Self::Ordinary
            | Self::NativeValid(_)
            | Self::NativeFinalizationApplied(_)
            | Self::StateSyncCheckpointBootstrap(_)
            | Self::AuthenticatedGenesisApplicationBootstrap(_)
            | Self::StateSyncAnchorOrdinaryPromotion(_) => None,
            Self::NativeDeterministicInvalid(facts) => Some(facts.as_ref()),
        }
    }

    pub fn native_valid_transition(&self) -> Option<&NativeValidTransitionV0> {
        match self {
            Self::NativeValid(facts) => Some(facts.as_ref()),
            Self::Ordinary
            | Self::NativeDeterministicInvalid(_)
            | Self::NativeFinalizationApplied(_)
            | Self::StateSyncCheckpointBootstrap(_)
            | Self::AuthenticatedGenesisApplicationBootstrap(_)
            | Self::StateSyncAnchorOrdinaryPromotion(_) => None,
        }
    }

    pub fn native_finalization_applied_transition(
        &self,
    ) -> Option<&NativeFinalizationAppliedTransitionV0> {
        match self {
            Self::NativeFinalizationApplied(facts) => Some(facts.as_ref()),
            Self::Ordinary
            | Self::NativeDeterministicInvalid(_)
            | Self::NativeValid(_)
            | Self::StateSyncCheckpointBootstrap(_)
            | Self::AuthenticatedGenesisApplicationBootstrap(_)
            | Self::StateSyncAnchorOrdinaryPromotion(_) => None,
        }
    }

    pub fn state_sync_checkpoint_bootstrap_transition(
        &self,
    ) -> Option<&StateSyncCheckpointBootstrapTransitionV0> {
        match self {
            Self::StateSyncCheckpointBootstrap(facts) => Some(facts.as_ref()),
            Self::Ordinary
            | Self::NativeDeterministicInvalid(_)
            | Self::NativeValid(_)
            | Self::NativeFinalizationApplied(_)
            | Self::AuthenticatedGenesisApplicationBootstrap(_)
            | Self::StateSyncAnchorOrdinaryPromotion(_) => None,
        }
    }

    pub fn authenticated_genesis_application_bootstrap_transition(
        &self,
    ) -> Option<&AuthenticatedGenesisApplicationBootstrapTransitionV0> {
        match self {
            Self::AuthenticatedGenesisApplicationBootstrap(facts) => Some(facts.as_ref()),
            Self::Ordinary
            | Self::NativeDeterministicInvalid(_)
            | Self::NativeValid(_)
            | Self::NativeFinalizationApplied(_)
            | Self::StateSyncCheckpointBootstrap(_)
            | Self::StateSyncAnchorOrdinaryPromotion(_) => None,
        }
    }

    pub fn state_sync_anchor_ordinary_promotion_transition(
        &self,
    ) -> Option<&StateSyncAnchorOrdinaryPromotionTransitionV0> {
        match self {
            Self::StateSyncAnchorOrdinaryPromotion(facts) => Some(facts.as_ref()),
            Self::Ordinary
            | Self::NativeDeterministicInvalid(_)
            | Self::NativeValid(_)
            | Self::NativeFinalizationApplied(_)
            | Self::StateSyncCheckpointBootstrap(_)
            | Self::AuthenticatedGenesisApplicationBootstrap(_) => None,
        }
    }
}

pub fn encode_transition_context_v0(
    context: &SafetyTransitionContextV0,
) -> Result<Vec<u8>, SafetyStoreErrorV0> {
    let mut bytes = Vec::with_capacity(match context {
        SafetyTransitionContextV0::Ordinary => ORDINARY_CONTEXT_BYTES_V0,
        SafetyTransitionContextV0::NativeDeterministicInvalid(_) => NATIVE_INVALID_CONTEXT_BYTES_V0,
        SafetyTransitionContextV0::NativeValid(_) => NATIVE_VALID_CONTEXT_BYTES_V0,
        SafetyTransitionContextV0::NativeFinalizationApplied(_) => {
            NATIVE_FINALIZATION_APPLIED_CONTEXT_BYTES_V0
        }
        SafetyTransitionContextV0::StateSyncCheckpointBootstrap(_) => {
            STATE_SYNC_CHECKPOINT_BOOTSTRAP_CONTEXT_BYTES_V0
        }
        SafetyTransitionContextV0::AuthenticatedGenesisApplicationBootstrap(_) => {
            AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_CONTEXT_BYTES_V0
        }
        SafetyTransitionContextV0::StateSyncAnchorOrdinaryPromotion(_) => {
            STATE_SYNC_ANCHOR_ORDINARY_PROMOTION_CONTEXT_BYTES_V0
        }
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
        SafetyTransitionContextV0::NativeValid(facts) => {
            bytes.push(NATIVE_VALID_TAG_V0);
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
            bytes.extend_from_slice(&facts.valid_result_checksum);
            bytes.extend_from_slice(&facts.callback_payload_checksum);
            bytes.extend_from_slice(&facts.idempotency_key);
            bytes.extend_from_slice(&facts.delivery_attempt.to_be_bytes());
            bytes.extend_from_slice(&facts.delivered_job_row_checksum);
            bytes.extend_from_slice(&facts.outbox_checksum);
            bytes.extend_from_slice(&facts.post_ack_action_code.to_be_bytes());
            bytes.extend_from_slice(&facts.completion_revision.to_be_bytes());
        }
        SafetyTransitionContextV0::NativeFinalizationApplied(facts) => {
            bytes.push(NATIVE_FINALIZATION_APPLIED_TAG_V0);
            bytes.push(match facts.source_route {
                PayloadValidationRouteV0::Proposal => 0,
                PayloadValidationRouteV0::Synced => 1,
            });
            bytes.extend_from_slice(facts.source_validation_id.block_id().as_bytes());
            bytes.extend_from_slice(&facts.source_validation_id.view().get().to_be_bytes());
            bytes.extend_from_slice(&facts.source_validation_id.generation().to_be_bytes());
            bytes.extend_from_slice(&facts.ordinal.to_be_bytes());
            bytes.extend_from_slice(&facts.application_host_config_ref);
            bytes.extend_from_slice(&facts.finalization_checksum);
            bytes.extend_from_slice(&facts.prior_head_checksum);
            bytes.extend_from_slice(&facts.new_head_checksum);
            bytes.extend_from_slice(&facts.source_artifact_checksum);
            bytes.extend_from_slice(&facts.accepted_source_checksum);
            bytes.extend_from_slice(&facts.applied_job_row_checksum);
            bytes.extend_from_slice(&facts.receipt_row_checksum);
            bytes.extend_from_slice(&facts.post_ack_action_code.to_be_bytes());
            bytes.extend_from_slice(&facts.completion_revision.to_be_bytes());
        }
        SafetyTransitionContextV0::StateSyncCheckpointBootstrap(facts) => {
            bytes.push(STATE_SYNC_CHECKPOINT_BOOTSTRAP_TAG_V0);
            bytes.extend_from_slice(&facts.anchor_checksum);
            bytes.extend_from_slice(&facts.state_record_checksum);
            bytes.extend_from_slice(facts.proof_id.as_bytes());
            bytes.extend_from_slice(facts.target_block_id.as_bytes());
            bytes.extend_from_slice(facts.target_state_root.as_bytes());
            bytes.extend_from_slice(&facts.target_height.get().to_be_bytes());
            bytes.extend_from_slice(&facts.target_view.get().to_be_bytes());
            bytes.extend_from_slice(&facts.target_timestamp_ms.to_be_bytes());
            bytes.extend_from_slice(&facts.transition_revision.to_be_bytes());
        }
        SafetyTransitionContextV0::AuthenticatedGenesisApplicationBootstrap(facts) => {
            bytes.push(AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_TAG_V0);
            bytes.extend_from_slice(facts.carrier.genesis_block_id().as_bytes());
            bytes.extend_from_slice(&facts.carrier.timestamp_ms().to_be_bytes());
            bytes.extend_from_slice(&facts.carrier.state_version().to_be_bytes());
            bytes.extend_from_slice(facts.carrier.state_root().as_bytes());
            bytes.extend_from_slice(&facts.carrier.descriptor_ref());
            bytes.extend_from_slice(&facts.carrier.projection_profile_ref());
            bytes.extend_from_slice(&facts.carrier_binding_ref);
            bytes.extend_from_slice(&facts.state_record_checksum);
            bytes.extend_from_slice(&facts.transition_revision.to_be_bytes());
        }
        SafetyTransitionContextV0::StateSyncAnchorOrdinaryPromotion(facts) => {
            bytes.push(STATE_SYNC_ANCHOR_ORDINARY_PROMOTION_TAG_V0);
            bytes.extend_from_slice(&facts.anchor_checksum);
            bytes.extend_from_slice(&facts.state_record_checksum);
            bytes.extend_from_slice(facts.proof_id.as_bytes());
            bytes.extend_from_slice(&facts.h2_valid_result_checksum);
            bytes.extend_from_slice(&facts.h3_valid_result_checksum);
            bytes.extend_from_slice(&facts.transition_revision.to_be_bytes());
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
        NATIVE_VALID_TAG_V0 if bytes.len() == NATIVE_VALID_CONTEXT_BYTES_V0 => {
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
            let facts = NativeValidTransitionV0::new(
                route,
                validation_id,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u32::from_be_bytes(take::<4>(bytes, &mut offset)?),
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
            )?;
            if offset != bytes.len() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "transition context trailing bytes",
                ));
            }
            SafetyTransitionContextV0::native_valid(facts)
        }
        NATIVE_FINALIZATION_APPLIED_TAG_V0
            if bytes.len() == NATIVE_FINALIZATION_APPLIED_CONTEXT_BYTES_V0 =>
        {
            let mut offset = 3usize;
            let source_route = match take::<1>(bytes, &mut offset)?[0] {
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
            let facts = NativeFinalizationAppliedTransitionV0::new(
                source_route,
                ValidationId::new(block_id, view, generation),
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u32::from_be_bytes(take::<4>(bytes, &mut offset)?),
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
            )?;
            if offset != bytes.len() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "transition context trailing bytes",
                ));
            }
            SafetyTransitionContextV0::native_finalization_applied(facts)
        }
        STATE_SYNC_CHECKPOINT_BOOTSTRAP_TAG_V0
            if bytes.len() == STATE_SYNC_CHECKPOINT_BOOTSTRAP_CONTEXT_BYTES_V0 =>
        {
            let mut offset = 3usize;
            let facts = StateSyncCheckpointBootstrapTransitionV0::new(
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                CertificateId::new(take::<32>(bytes, &mut offset)?),
                BlockId::new(take::<32>(bytes, &mut offset)?),
                StateRoot::new(take::<32>(bytes, &mut offset)?),
                Height::new(u64::from_be_bytes(take::<8>(bytes, &mut offset)?)),
                View::new(u64::from_be_bytes(take::<8>(bytes, &mut offset)?)),
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
            )?;
            if offset != bytes.len() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "transition context trailing bytes",
                ));
            }
            SafetyTransitionContextV0::state_sync_checkpoint_bootstrap(facts)
        }
        AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_TAG_V0
            if bytes.len() == AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_CONTEXT_BYTES_V0 =>
        {
            let mut offset = 3usize;
            let carrier = AuthenticatedGenesisApplicationParentV0::new(
                BlockId::new(take::<32>(bytes, &mut offset)?),
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
                StateRoot::new(take::<32>(bytes, &mut offset)?),
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
            )
            .map_err(|_| {
                SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "authenticated-genesis bootstrap carrier",
                )
            })?;
            let facts = AuthenticatedGenesisApplicationBootstrapTransitionV0::new(
                carrier,
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
            )?;
            if offset != bytes.len() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "transition context trailing bytes",
                ));
            }
            SafetyTransitionContextV0::authenticated_genesis_application_bootstrap(facts)
        }
        STATE_SYNC_ANCHOR_ORDINARY_PROMOTION_TAG_V0
            if bytes.len() == STATE_SYNC_ANCHOR_ORDINARY_PROMOTION_CONTEXT_BYTES_V0 =>
        {
            let mut offset = 3usize;
            let facts = StateSyncAnchorOrdinaryPromotionTransitionV0::new(
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                CertificateId::new(take::<32>(bytes, &mut offset)?),
                take::<32>(bytes, &mut offset)?,
                take::<32>(bytes, &mut offset)?,
                u64::from_be_bytes(take::<8>(bytes, &mut offset)?),
            )?;
            if offset != bytes.len() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "transition context trailing bytes",
                ));
            }
            SafetyTransitionContextV0::state_sync_anchor_ordinary_promotion(facts)
        }
        ORDINARY_TAG_V0
        | NATIVE_DETERMINISTIC_INVALID_TAG_V0
        | NATIVE_VALID_TAG_V0
        | NATIVE_FINALIZATION_APPLIED_TAG_V0
        | STATE_SYNC_CHECKPOINT_BOOTSTRAP_TAG_V0
        | AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_TAG_V0
        | STATE_SYNC_ANCHOR_ORDINARY_PROMOTION_TAG_V0 => {
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
    let facts = match context {
        SafetyTransitionContextV0::Ordinary => {
            if state.revision() == 0
                && (state.state_sync_anchor().is_some()
                    || state
                        .authenticated_genesis_application_parent_v0()
                        .is_some())
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "revision-zero bootstrap state lacks its typed transition context",
                ));
            }
            if state.revision() == 5 && state.state_sync_anchor().is_some() {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "anchored-ordinary revision five lacks its typed promotion context",
                ));
            }
            if state
                .payload_validation_completions()
                .iter()
                .any(|completion| {
                    completion.first_recorded_revision() == state.revision()
                        && (completion.result().is_deterministically_invalid()
                            || completion.result().is_valid())
                })
            {
                return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "new terminal payload completion lacks transition context",
                ));
            }
            return Ok(());
        }
        SafetyTransitionContextV0::NativeValid(facts) => {
            return validate_native_valid_transition_against_state_v0(
                facts,
                state,
                newly_recorded_completion_count,
            );
        }
        SafetyTransitionContextV0::NativeFinalizationApplied(facts) => {
            return validate_native_finalization_applied_transition_against_state_v0(
                facts,
                state,
                newly_recorded_completion_count,
            );
        }
        SafetyTransitionContextV0::StateSyncCheckpointBootstrap(facts) => {
            return validate_state_sync_checkpoint_bootstrap_transition_against_state_v0(
                facts,
                state,
                newly_recorded_completion_count,
            );
        }
        SafetyTransitionContextV0::AuthenticatedGenesisApplicationBootstrap(facts) => {
            return validate_authenticated_genesis_application_bootstrap_transition_against_state_v0(
                facts,
                state,
                newly_recorded_completion_count,
            );
        }
        SafetyTransitionContextV0::StateSyncAnchorOrdinaryPromotion(facts) => {
            return validate_state_sync_anchor_ordinary_promotion_transition_against_state_v0(
                facts,
                state,
                newly_recorded_completion_count,
            );
        }
        SafetyTransitionContextV0::NativeDeterministicInvalid(facts) => facts,
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

fn validate_state_sync_anchor_ordinary_promotion_transition_against_state_v0(
    facts: &StateSyncAnchorOrdinaryPromotionTransitionV0,
    state: &SafetyState,
    newly_recorded_completion_count: usize,
) -> Result<(), SafetyStoreErrorV0> {
    let anchor =
        state
            .state_sync_anchor()
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync promotion transition has no Core anchor",
            ))?;
    let h2_id = anchor.proof().child().header().id();
    let h3_id = anchor.proof().grandchild().header().id();
    let exact_checksum = |block_id: BlockId| {
        let mut matches = state
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id().block_id() == block_id);
        let completion =
            matches
                .next()
                .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                    "state-sync promotion lacks one exact successor completion",
                ))?;
        if matches.next().is_some() {
            return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync promotion duplicates a successor completion",
            ));
        }
        core_native_valid_result_checksum_v0(completion.result()).ok_or(
            SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync promotion successor completion is not Valid",
            ),
        )
    };
    if state.revision() != 5
        || facts.transition_revision != 5
        || newly_recorded_completion_count != 0
        || facts.anchor_checksum != state_sync_anchor_checksum_v0(anchor)
        || facts.proof_id != anchor.proof_id()
        || facts.h2_valid_result_checksum != exact_checksum(h2_id)?
        || facts.h3_valid_result_checksum != exact_checksum(h3_id)?
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "state-sync anchored-ordinary promotion transition is not congruent with Core state",
        ));
    }
    Ok(())
}

fn validate_authenticated_genesis_application_bootstrap_transition_against_state_v0(
    facts: &AuthenticatedGenesisApplicationBootstrapTransitionV0,
    state: &SafetyState,
    newly_recorded_completion_count: usize,
) -> Result<(), SafetyStoreErrorV0> {
    let carrier = state
        .authenticated_genesis_application_parent_v0()
        .copied()
        .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "authenticated-genesis bootstrap transition has no Core carrier",
        ))?;
    if state.revision() != 0
        || facts.transition_revision != 0
        || state.state_sync_anchor().is_some()
        || newly_recorded_completion_count != 0
        || facts.carrier != carrier
        || facts.carrier_binding_ref != carrier.binding_ref_v0()
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "authenticated-genesis bootstrap transition is not congruent with Core state",
        ));
    }
    Ok(())
}

fn validate_state_sync_checkpoint_bootstrap_transition_against_state_v0(
    facts: &StateSyncCheckpointBootstrapTransitionV0,
    state: &SafetyState,
    newly_recorded_completion_count: usize,
) -> Result<(), SafetyStoreErrorV0> {
    let anchor =
        state
            .state_sync_anchor()
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "state-sync bootstrap transition has no Core anchor",
            ))?;
    let target = anchor.proof().finalized_block().header();
    if state.revision() != 0
        || facts.transition_revision != 0
        || newly_recorded_completion_count != 0
        || facts.anchor_checksum != state_sync_anchor_checksum_v0(anchor)
        || facts.proof_id != anchor.proof_id()
        || facts.target_block_id != target.id()
        || facts.target_state_root != target.state_root()
        || facts.target_height != target.height()
        || facts.target_view != target.view()
        || facts.target_timestamp_ms != target.timestamp_ms()
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "state-sync bootstrap transition is not congruent with Core state",
        ));
    }
    Ok(())
}

pub(crate) fn validate_transition_context_record_identity_v0(
    context: &SafetyTransitionContextV0,
    state_record_checksum: [u8; 32],
) -> Result<(), SafetyStoreErrorV0> {
    if context
        .state_sync_checkpoint_bootstrap_transition()
        .is_some_and(|facts| facts.state_record_checksum != state_record_checksum)
        || context
            .authenticated_genesis_application_bootstrap_transition()
            .is_some_and(|facts| facts.state_record_checksum != state_record_checksum)
        || context
            .state_sync_anchor_ordinary_promotion_transition()
            .is_some_and(|facts| facts.state_record_checksum != state_record_checksum)
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "bootstrap context identifies a different state record",
        ));
    }
    Ok(())
}

fn validate_native_finalization_applied_transition_against_state_v0(
    facts: &NativeFinalizationAppliedTransitionV0,
    state: &SafetyState,
    newly_recorded_completion_count: usize,
) -> Result<(), SafetyStoreErrorV0> {
    let applied = state.application_applied();
    let mut completions = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| {
            completion.route() == facts.source_route
                && completion.id() == facts.source_validation_id
        });
    let completion =
        completions
            .next()
            .ok_or(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "native finalization-applied transition has no exact Valid source completion",
            ))?;
    let result = completion.result();
    let artifact_ref = result.artifact_ref();
    let valid_overlay = artifact_ref.map(|artifact| artifact.overlay());
    let pending_front_is_direct = state
        .pending_finalization()
        .is_none_or(|front| front.authenticated_parent() == applied);
    if state.revision() != facts.completion_revision
        || newly_recorded_completion_count != 0
        || completions.next().is_some()
        || !result.is_valid()
        || artifact_ref.is_none_or(|artifact| {
            artifact.source_artifact_checksum() != facts.source_artifact_checksum
                || artifact.overlay().block_id() != facts.source_validation_id.block_id()
        })
        || state
            .payload_validation_obligations()
            .iter()
            .any(|obligation| {
                obligation.route() == facts.source_route
                    && obligation.id() == facts.source_validation_id
            })
        || !state.payload_terminal_facts().iter().any(|fact| {
            fact.block_id() == facts.source_validation_id.block_id()
                && fact.result() == PayloadTerminalResult::Valid
                && fact.valid_overlay() == valid_overlay
        })
        || facts.ordinal != applied.height().get()
        || facts.source_validation_id.block_id() != applied.block_id()
        || facts.source_validation_id.view() != applied.view()
        || state.pending_finalize()
            != state
                .pending_finalization()
                .map(trnm_consensus_core::DurableFinalizationV0::proof_id)
        || !pending_front_is_direct
    {
        return Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "native finalization-applied transition is not congruent with Core state",
        ));
    }
    Ok(())
}

/// Computes the canonical inert checksum bound into a NativeValid transition.
///
/// The projection covers every durable commitment and artifact-reference
/// field accepted by Core. It deliberately cannot reconstruct a live Valid
/// result or an application-seal capability.
pub fn native_valid_result_checksum_v0(
    result: DurablePayloadValidationResultV1,
) -> Result<[u8; 32], SafetyStoreErrorV0> {
    core_native_valid_result_checksum_v0(result).ok_or(
        SafetyStoreErrorV0::PersistedRepresentationMalformed(
            "native Valid context references a non-canonical Valid result",
        ),
    )
}

fn validate_native_valid_transition_against_state_v0(
    facts: &NativeValidTransitionV0,
    state: &SafetyState,
    newly_recorded_completion_count: usize,
) -> Result<(), SafetyStoreErrorV0> {
    // The context codec fixes the post-ack action code, but the current
    // SafetyState/SafetyStatePersistence API does not yet expose Core's
    // deferred-effect manifest. The host must not activate NativeValid until
    // that request-level value is compared before `persist_exact_v0` and can
    // be reminted from exact readback during recovery.
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
    let result = completion.result();
    let artifact_ref = result.artifact_ref();
    let valid_overlay = artifact_ref.map(|artifact| artifact.overlay());
    if completions.next().is_some()
        || newly_recorded_completion_count != 1
        || !result.is_valid()
        || completion.first_recorded_revision() != facts.completion_revision
        || native_valid_result_checksum_v0(result)? != facts.valid_result_checksum
        || state
            .payload_validation_obligations()
            .iter()
            .any(|obligation| {
                obligation.route() == facts.route && obligation.id() == facts.validation_id
            })
        || !state.payload_terminal_facts().iter().any(|fact| {
            fact.block_id() == facts.validation_id.block_id()
                && fact.result() == PayloadTerminalResult::Valid
                && fact.valid_overlay() == valid_overlay
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

    fn valid_facts_with(
        delivery_attempt: u64,
        post_ack_action_code: u32,
        completion_revision: u64,
    ) -> Result<NativeValidTransitionV0, SafetyStoreErrorV0> {
        NativeValidTransitionV0::new(
            PayloadValidationRouteV0::Proposal,
            ValidationId::new(BlockId::new([0x11; 32]), View::new(7), 9),
            [0x21; 32],
            [0x22; 32],
            [0x23; 32],
            [0x24; 32],
            [0x25; 32],
            [0x26; 32],
            delivery_attempt,
            [0x27; 32],
            [0x28; 32],
            post_ack_action_code,
            completion_revision,
        )
    }

    fn valid_facts() -> NativeValidTransitionV0 {
        valid_facts_with(1, NATIVE_VALID_POST_ACK_ARM_VIEW_TIMER_THEN_FINALIZE_V0, 10)
            .expect("valid native Valid facts")
    }

    fn finalization_facts_with(
        ordinal: u64,
        action: u32,
        revision: u64,
    ) -> Result<NativeFinalizationAppliedTransitionV0, SafetyStoreErrorV0> {
        NativeFinalizationAppliedTransitionV0::new(
            PayloadValidationRouteV0::Synced,
            ValidationId::new(BlockId::new([0x41; 32]), View::new(11), 13),
            ordinal,
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            [0x54; 32],
            [0x55; 32],
            [0x56; 32],
            [0x57; 32],
            [0x58; 32],
            action,
            revision,
        )
    }

    fn finalization_facts() -> NativeFinalizationAppliedTransitionV0 {
        finalization_facts_with(
            17,
            NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_FINALIZE_V0,
            19,
        )
        .expect("valid native finalization-applied facts")
    }

    fn state_sync_bootstrap_facts() -> StateSyncCheckpointBootstrapTransitionV0 {
        StateSyncCheckpointBootstrapTransitionV0::new(
            [0x61; 32],
            [0x62; 32],
            CertificateId::new([0x63; 32]),
            BlockId::new([0x64; 32]),
            StateRoot::new([0x65; 32]),
            Height::new(1),
            View::new(7),
            9,
            0,
        )
        .expect("valid state-sync bootstrap facts")
    }

    fn authenticated_genesis_bootstrap_facts(
    ) -> AuthenticatedGenesisApplicationBootstrapTransitionV0 {
        let carrier = AuthenticatedGenesisApplicationParentV0::new(
            BlockId::new([0x71; 32]),
            9,
            0,
            StateRoot::new([0x72; 32]),
            [0x73; 32],
            [0x74; 32],
        )
        .expect("valid authenticated-genesis carrier");
        AuthenticatedGenesisApplicationBootstrapTransitionV0::new(
            carrier,
            carrier.binding_ref_v0(),
            [0x75; 32],
            0,
        )
        .expect("valid authenticated-genesis bootstrap facts")
    }

    fn hex_v0(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("write to String");
        }
        encoded
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

        let context = SafetyTransitionContextV0::state_sync_checkpoint_bootstrap(
            state_sync_bootstrap_facts(),
        );
        let encoded = encode_transition_context_v0(&context)
            .expect("encode state-sync checkpoint bootstrap context");
        assert_eq!(
            encoded.len(),
            STATE_SYNC_CHECKPOINT_BOOTSTRAP_CONTEXT_BYTES_V0
        );
        assert_eq!(
            decode_transition_context_v0_exact(&encoded)
                .expect("decode state-sync checkpoint bootstrap context"),
            context
        );
        assert!(decode_transition_context_v0_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_transition_context_v0_exact(&trailing).is_err());

        let context = SafetyTransitionContextV0::authenticated_genesis_application_bootstrap(
            authenticated_genesis_bootstrap_facts(),
        );
        let encoded = encode_transition_context_v0(&context)
            .expect("encode authenticated-genesis application bootstrap context");
        assert_eq!(
            encoded.len(),
            AUTHENTICATED_GENESIS_APPLICATION_BOOTSTRAP_CONTEXT_BYTES_V0
        );
        assert_eq!(
            decode_transition_context_v0_exact(&encoded)
                .expect("decode authenticated-genesis application bootstrap context"),
            context
        );
        assert!(decode_transition_context_v0_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_transition_context_v0_exact(&trailing).is_err());

        let context = SafetyTransitionContextV0::native_finalization_applied(finalization_facts());
        let encoded =
            encode_transition_context_v0(&context).expect("encode finalization-applied context");
        assert_eq!(encoded.len(), NATIVE_FINALIZATION_APPLIED_CONTEXT_BYTES_V0);
        assert_eq!(
            decode_transition_context_v0_exact(&encoded)
                .expect("decode finalization-applied context"),
            context
        );
        assert_eq!(
            context
                .native_finalization_applied_transition()
                .expect("NativeFinalizationApplied context"),
            &finalization_facts()
        );
        assert!(decode_transition_context_v0_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_transition_context_v0_exact(&trailing).is_err());

        let context = SafetyTransitionContextV0::native_valid(valid_facts());
        let encoded = encode_transition_context_v0(&context).expect("encode Valid context");
        assert_eq!(encoded.len(), NATIVE_VALID_CONTEXT_BYTES_V0);
        assert_eq!(
            decode_transition_context_v0_exact(&encoded).expect("decode Valid context"),
            context
        );
        assert_eq!(
            context
                .native_valid_transition()
                .expect("NativeValid context"),
            &valid_facts()
        );
        assert!(decode_transition_context_v0_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_transition_context_v0_exact(&trailing).is_err());
    }

    #[test]
    fn native_valid_transition_frozen_vector_is_328_bytes() {
        let encoded =
            encode_transition_context_v0(&SafetyTransitionContextV0::native_valid(valid_facts()))
                .expect("encode frozen NativeValid context");
        assert_eq!(encoded.len(), 328);
        assert_eq!(
            hex_v0(&encoded),
            concat!(
                "00000200",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0000000000000007",
                "0000000000000009",
                "2121212121212121212121212121212121212121212121212121212121212121",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "2323232323232323232323232323232323232323232323232323232323232323",
                "2424242424242424242424242424242424242424242424242424242424242424",
                "2525252525252525252525252525252525252525252525252525252525252525",
                "2626262626262626262626262626262626262626262626262626262626262626",
                "0000000000000001",
                "2727272727272727272727272727272727272727272727272727272727272727",
                "2828282828282828282828282828282828282828282828282828282828282828",
                "00000003",
                "000000000000000a",
            )
        );
    }

    #[test]
    fn native_valid_transition_rejects_noncanonical_fields() {
        assert!(valid_facts_with(0, NATIVE_VALID_POST_ACK_NONE_V0, 10).is_err());
        assert!(valid_facts_with(2, NATIVE_VALID_POST_ACK_NONE_V0, 10).is_err());
        assert!(valid_facts_with(1, 8, 10).is_err());
        assert!(valid_facts_with(1, NATIVE_VALID_POST_ACK_NONE_V0, 0).is_err());
        for action in
            NATIVE_VALID_POST_ACK_NONE_V0..=NATIVE_VALID_POST_ACK_SAFETY_HALTED_CONFLICT_V0
        {
            assert!(valid_facts_with(1, action, 10).is_ok());
        }

        let encoded =
            encode_transition_context_v0(&SafetyTransitionContextV0::native_valid(valid_facts()))
                .expect("encode NativeValid context");
        let mut unknown_tag = encoded.clone();
        unknown_tag[2] = 0xff;
        assert!(matches!(
            decode_transition_context_v0_exact(&unknown_tag),
            Err(SafetyStoreErrorV0::PersistedRepresentationMalformed(
                "unknown transition-context tag"
            ))
        ));
        let mut unknown_route = encoded.clone();
        unknown_route[3] = 2;
        assert!(decode_transition_context_v0_exact(&unknown_route).is_err());
        let mut zero_checksum = encoded.clone();
        zero_checksum[148..180].fill(0);
        assert!(decode_transition_context_v0_exact(&zero_checksum).is_err());
        let mut wrong_attempt = encoded.clone();
        wrong_attempt[244..252].copy_from_slice(&2u64.to_be_bytes());
        assert!(decode_transition_context_v0_exact(&wrong_attempt).is_err());
        let mut unknown_action = encoded.clone();
        unknown_action[316..320].copy_from_slice(&8u32.to_be_bytes());
        assert!(decode_transition_context_v0_exact(&unknown_action).is_err());
        let mut zero_revision = encoded;
        zero_revision[320..328].fill(0);
        assert!(decode_transition_context_v0_exact(&zero_revision).is_err());
    }

    #[test]
    fn native_finalization_applied_transition_frozen_vector_is_328_bytes() {
        let encoded = encode_transition_context_v0(
            &SafetyTransitionContextV0::native_finalization_applied(finalization_facts()),
        )
        .expect("encode frozen NativeFinalizationApplied context");
        assert_eq!(encoded.len(), 328);
        assert_eq!(
            hex_v0(&encoded),
            concat!(
                "00000301",
                "4141414141414141414141414141414141414141414141414141414141414141",
                "000000000000000b",
                "000000000000000d",
                "0000000000000011",
                "5151515151515151515151515151515151515151515151515151515151515151",
                "5252525252525252525252525252525252525252525252525252525252525252",
                "5353535353535353535353535353535353535353535353535353535353535353",
                "5454545454545454545454545454545454545454545454545454545454545454",
                "5555555555555555555555555555555555555555555555555555555555555555",
                "5656565656565656565656565656565656565656565656565656565656565656",
                "5757575757575757575757575757575757575757575757575757575757575757",
                "5858585858585858585858585858585858585858585858585858585858585858",
                "00000005",
                "0000000000000013",
            )
        );
    }

    #[test]
    fn native_finalization_applied_transition_rejects_tamper_and_noncanonical_fields() {
        assert!(
            finalization_facts_with(0, NATIVE_FINALIZATION_APPLIED_POST_ACK_NONE_V0, 19).is_err()
        );
        assert!(finalization_facts_with(17, 9, 19).is_err());
        assert!(
            finalization_facts_with(17, NATIVE_FINALIZATION_APPLIED_POST_ACK_NONE_V0, 0).is_err()
        );
        for action in NATIVE_FINALIZATION_APPLIED_POST_ACK_NONE_V0
            ..=NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0
        {
            assert!(finalization_facts_with(17, action, 19).is_ok());
        }

        let encoded = encode_transition_context_v0(
            &SafetyTransitionContextV0::native_finalization_applied(finalization_facts()),
        )
        .expect("encode NativeFinalizationApplied context");
        let mut unknown_route = encoded.clone();
        unknown_route[3] = 2;
        assert!(decode_transition_context_v0_exact(&unknown_route).is_err());
        let mut zero_ordinal = encoded.clone();
        zero_ordinal[52..60].fill(0);
        assert!(decode_transition_context_v0_exact(&zero_ordinal).is_err());
        let mut zero_checksum = encoded.clone();
        zero_checksum[60..92].fill(0);
        assert!(decode_transition_context_v0_exact(&zero_checksum).is_err());
        let mut equal_heads = encoded.clone();
        equal_heads[156..188].copy_from_slice(&[0x53; 32]);
        assert!(decode_transition_context_v0_exact(&equal_heads).is_err());
        let mut unknown_action = encoded.clone();
        unknown_action[316..320].copy_from_slice(&9u32.to_be_bytes());
        assert!(decode_transition_context_v0_exact(&unknown_action).is_err());
        let mut zero_revision = encoded;
        zero_revision[320..328].fill(0);
        assert!(decode_transition_context_v0_exact(&zero_revision).is_err());
    }

    #[test]
    fn state_sync_checkpoint_bootstrap_transition_has_a_frozen_195_byte_vector() {
        let context = SafetyTransitionContextV0::state_sync_checkpoint_bootstrap(
            state_sync_bootstrap_facts(),
        );
        let encoded = encode_transition_context_v0(&context)
            .expect("encode state-sync checkpoint bootstrap context");
        assert_eq!(encoded.len(), 195);
        assert_eq!(
            hex_v0(&encoded),
            concat!(
                "000004",
                "6161616161616161616161616161616161616161616161616161616161616161",
                "6262626262626262626262626262626262626262626262626262626262626262",
                "6363636363636363636363636363636363636363636363636363636363636363",
                "6464646464646464646464646464646464646464646464646464646464646464",
                "6565656565656565656565656565656565656565656565656565656565656565",
                "0000000000000001",
                "0000000000000007",
                "0000000000000009",
                "0000000000000000",
            )
        );

        let mut wrong_height = encoded.clone();
        wrong_height[163..171].fill(0);
        assert!(decode_transition_context_v0_exact(&wrong_height).is_err());
        let mut nonzero_revision = encoded.clone();
        nonzero_revision[187..195].copy_from_slice(&1u64.to_be_bytes());
        assert!(decode_transition_context_v0_exact(&nonzero_revision).is_err());
        let mut zero_record_checksum = encoded;
        zero_record_checksum[35..67].fill(0);
        assert!(decode_transition_context_v0_exact(&zero_record_checksum).is_err());
    }

    #[test]
    fn authenticated_genesis_application_bootstrap_transition_is_tag5_and_commitment_complete() {
        let facts = authenticated_genesis_bootstrap_facts();
        let context =
            SafetyTransitionContextV0::authenticated_genesis_application_bootstrap(facts.clone());
        let encoded = encode_transition_context_v0(&context)
            .expect("encode authenticated-genesis bootstrap context");
        assert_eq!(
            hex_v0(&encoded),
            concat!(
                "000005",
                "7171717171717171717171717171717171717171717171717171717171717171",
                "0000000000000009",
                "0000000000000000",
                "7272727272727272727272727272727272727272727272727272727272727272",
                "7373737373737373737373737373737373737373737373737373737373737373",
                "7474747474747474747474747474747474747474747474747474747474747474",
                "9b524f1b6e371013366694d47b9db30d2b1b13e0280bf56122409e56e29319d2",
                "7575757575757575757575757575757575757575757575757575757575757575",
                "0000000000000000",
            )
        );
        assert_eq!(encoded.len(), 219);
        assert_eq!(&encoded[..3], &[0, 0, 5]);
        assert_eq!(
            decode_transition_context_v0_exact(&encoded)
                .expect("decode authenticated-genesis bootstrap context"),
            context
        );

        let mut nonzero_state_version = encoded.clone();
        nonzero_state_version[43..51].copy_from_slice(&1u64.to_be_bytes());
        assert!(decode_transition_context_v0_exact(&nonzero_state_version).is_err());
        let mut foreign_binding = encoded.clone();
        foreign_binding[147..179].fill(0x7f);
        assert!(decode_transition_context_v0_exact(&foreign_binding).is_err());
        let mut zero_record_checksum = encoded.clone();
        zero_record_checksum[179..211].fill(0);
        assert!(decode_transition_context_v0_exact(&zero_record_checksum).is_err());
        let mut nonzero_revision = encoded;
        nonzero_revision[211..219].copy_from_slice(&1u64.to_be_bytes());
        assert!(decode_transition_context_v0_exact(&nonzero_revision).is_err());
    }
}
