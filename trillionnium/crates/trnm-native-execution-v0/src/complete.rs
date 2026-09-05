//! Complete frozen-v0 ordinary-body execution on one pinned parent snapshot.
//!
//! This module is the active, zero-Comet extraction of the application state
//! transition. It deliberately stops at an inert full-state plan. Persistence
//! is added by the durable application owner; Core, Safety, signing, finality,
//! networking, and broadcast are outside this crate's authority.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use trnm_consensus_types::{
    ApplicationPayloadV0, BlockBodyV0, EpochGeometryV0, ExecutionEventV0,
    ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, GenesisHash, Height, ValidatorSet,
};
use trnm_finality_types::{hash_domain, SignedCommandEnvelopeV1};
use trnm_native_application::{
    ApplicationHeadV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, NativeBlockExecutionRequestV0,
    NativeEventAttributeV0, NativeEventV0, NativeExecutedBlockV0, NativeExecutionReceiptV0,
    ReceiptsRootV0, StateRootV0, ValidatorSetIdV0, MAX_BLOCK_BYTES_V0, MAX_BLOCK_TRANSACTIONS_V0,
};
use trnm_protocol::{CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1};
use trnm_runtime::{try_execute_v0, ExecutionContext, RuntimeReceipt, StateObject, TryStateViewV0};

use crate::{
    auth_tree::{self, AuthWrite},
    consensus_error,
    poco_application::{
        AuthenticatedPocoApplicationContextV0, PocoApplicationApplyFailureV0,
        PocoApplicationBlockOverlayV0, PocoApplicationOperationV0,
        POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
    },
    poco_transition::{
        auth_writes_from_sealed_poco_application_v0, scheduled_cutoff_manifest_refresh_write_v0,
        take_and_validate_production_poco_projection_v0,
    },
    runtime_event_to_consensus_v0, signer_policy_commitment_v0, stage_runtime_mutations_v0,
    store::{
        plan_complete_state_update_v0, AuthenticatedObjectRecordV0, CompleteStatePlanV0,
        CompleteStateWriteV0, InMemoryNativeExecutionStoreV0, NativeExecutionStoreV0,
        NativeStateWriteV0,
    },
    validator_lifecycle::{
        ConsensusValidatorV1, ValidatorLifecycleStateV1, ValidatorSetTransitionV1,
        ValidatorTransitionAuthorization, ValidatorTransitionScheduleFailureV1,
        VALIDATOR_LIFECYCLE_SCHEMA_V1, VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
        VALIDATOR_TRANSITION_SCHEMA_V1,
    },
    AuthorizedSignerV0,
};

const APPLICATION_GOVERNANCE_SIGNER_DOMAIN_V0: &str =
    "trnm.poco-bft.application-governance-signer.v0";
const NATIVE_RECEIPT_COMMITMENT_DOMAIN_V0: &str = "trnm.native-application.execution-receipt.v0";
const PREVIEW_REQUEST_DOMAIN_V0: &str = "trnm.native-application.block-preview-request.v0";
const PREVIEW_WRITE_PLAN_DOMAIN_V0: &str = "trnm.native-application.block-preview-write-plan.v0";

/// Independent read-only input for deterministic frozen-v0 block preview.
///
/// A preview deliberately has no block ID, expected roots, Core permit, or
/// durable-P token. It is only enough to derive the commitments which a
/// proposer can place in a final header. The final execution request must
/// still supply a distinct block ID and is recomputed from the pinned parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBlockPreviewRequestV0 {
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    parent: ApplicationHeadV0,
    height: HeightV0,
    timestamp_ms: u64,
    active_validator_set_id: ValidatorSetIdV0,
    transactions: Vec<Vec<u8>>,
    transaction_bytes: usize,
}

impl NativeBlockPreviewRequestV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainIdV0,
        genesis_hash: GenesisHashV0,
        parent: ApplicationHeadV0,
        height: HeightV0,
        timestamp_ms: u64,
        active_validator_set_id: ValidatorSetIdV0,
        transactions: Vec<Vec<u8>>,
    ) -> Result<Self> {
        ensure!(
            height.get()
                == parent
                    .height()
                    .get()
                    .checked_add(1)
                    .context("preview parent height exhausted")?,
            "preview target is not the exact parent successor"
        );
        ensure!(
            transactions.len() <= MAX_BLOCK_TRANSACTIONS_V0,
            "preview contains too many transactions"
        );
        let mut transaction_bytes = 4usize;
        for transaction in &transactions {
            transaction_bytes = transaction_bytes
                .checked_add(4)
                .and_then(|value| value.checked_add(transaction.len()))
                .context("preview transaction bytes exhausted")?;
            ensure!(
                transaction_bytes <= MAX_BLOCK_BYTES_V0,
                "preview transaction bytes exceed frozen-v0 limit"
            );
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            parent,
            height,
            timestamp_ms,
            active_validator_set_id,
            transactions,
            transaction_bytes,
        })
    }

    pub const fn chain_id(&self) -> &ChainIdV0 {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> GenesisHashV0 {
        self.genesis_hash
    }

    pub const fn parent(&self) -> &ApplicationHeadV0 {
        &self.parent
    }

    pub const fn height(&self) -> HeightV0 {
        self.height
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub const fn active_validator_set_id(&self) -> ValidatorSetIdV0 {
        self.active_validator_set_id
    }

    pub fn transactions(&self) -> &[Vec<u8>] {
        &self.transactions
    }

    pub const fn transaction_bytes(&self) -> usize {
        self.transaction_bytes
    }

    fn fingerprint_v0(&self, payload_root: [u8; 32]) -> [u8; 32] {
        hash_domain(
            PREVIEW_REQUEST_DOMAIN_V0,
            &[
                self.chain_id.as_str().as_bytes(),
                self.genesis_hash.as_bytes(),
                &self.parent.height().get().to_be_bytes(),
                self.parent.block_id().as_bytes(),
                self.parent.state_root().as_bytes(),
                self.parent.commit_id().as_bytes(),
                &self.height.get().to_be_bytes(),
                &self.timestamp_ms.to_be_bytes(),
                self.active_validator_set_id.as_bytes(),
                &payload_root,
            ],
        )
    }
}

/// Inert, read-only deterministic preview of one exact candidate body.
///
/// This value is explicitly not execution, persistence, Core, Safety, vote,
/// signing, or finality authority. A final execution always recomputes the
/// transition and checks all four roots from the final request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBlockPreviewV0 {
    request_fingerprint: Hash32V0,
    payload_root: Hash32V0,
    post_state_root: StateRootV0,
    receipts_root: ReceiptsRootV0,
    evidence_root: Hash32V0,
    receipts: Vec<NativeExecutionReceiptV0>,
    write_plan_fingerprint: Hash32V0,
    write_count: u64,
}

impl NativeBlockPreviewV0 {
    pub const fn request_fingerprint(&self) -> Hash32V0 {
        self.request_fingerprint
    }

    pub const fn payload_root(&self) -> Hash32V0 {
        self.payload_root
    }

    pub const fn post_state_root(&self) -> StateRootV0 {
        self.post_state_root
    }

    pub const fn receipts_root(&self) -> ReceiptsRootV0 {
        self.receipts_root
    }

    pub const fn evidence_root(&self) -> Hash32V0 {
        self.evidence_root
    }

    pub fn receipts(&self) -> &[NativeExecutionReceiptV0] {
        &self.receipts
    }

    pub const fn write_plan_fingerprint(&self) -> Hash32V0 {
        self.write_plan_fingerprint
    }

    pub const fn write_count(&self) -> u64 {
        self.write_count
    }
}

pub(crate) trait CompleteBlockExecutionInputV0 {
    fn chain_id_v0(&self) -> &ChainIdV0;
    fn genesis_hash_v0(&self) -> GenesisHashV0;
    fn parent_v0(&self) -> &ApplicationHeadV0;
    fn height_v0(&self) -> HeightV0;
    fn timestamp_ms_v0(&self) -> u64;
    fn active_validator_set_id_v0(&self) -> ValidatorSetIdV0;
    fn transactions_v0(&self) -> &[Vec<u8>];
}

impl CompleteBlockExecutionInputV0 for NativeBlockExecutionRequestV0 {
    fn chain_id_v0(&self) -> &ChainIdV0 {
        self.chain_id()
    }

    fn genesis_hash_v0(&self) -> GenesisHashV0 {
        self.genesis_hash()
    }

    fn parent_v0(&self) -> &ApplicationHeadV0 {
        self.parent()
    }

    fn height_v0(&self) -> HeightV0 {
        self.height()
    }

    fn timestamp_ms_v0(&self) -> u64 {
        self.timestamp_ms()
    }

    fn active_validator_set_id_v0(&self) -> ValidatorSetIdV0 {
        self.active_validator_set_id()
    }

    fn transactions_v0(&self) -> &[Vec<u8>] {
        self.transactions()
    }
}

impl CompleteBlockExecutionInputV0 for NativeBlockPreviewRequestV0 {
    fn chain_id_v0(&self) -> &ChainIdV0 {
        self.chain_id()
    }

    fn genesis_hash_v0(&self) -> GenesisHashV0 {
        self.genesis_hash()
    }

    fn parent_v0(&self) -> &ApplicationHeadV0 {
        self.parent()
    }

    fn height_v0(&self) -> HeightV0 {
        self.height()
    }

    fn timestamp_ms_v0(&self) -> u64 {
        self.timestamp_ms()
    }

    fn active_validator_set_id_v0(&self) -> ValidatorSetIdV0 {
        self.active_validator_set_id()
    }

    fn transactions_v0(&self) -> &[Vec<u8>] {
        self.transactions()
    }
}

#[derive(Debug)]
pub(crate) struct CompleteNativeExecutionV0 {
    executed: NativeExecutedBlockV0,
    plan: CompleteStatePlanV0,
    replay_identities: Vec<ReplayIdentityV0>,
    final_lifecycle: ValidatorLifecycleStateV1,
}

/// Exact replay identity carried by one accepted outer envelope.
///
/// Keeping the command, signer, and nonce in one value prevents the
/// independent-sort ambiguity that would arise from persisting separate
/// command and nonce sets.
#[derive(Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub(crate) struct ReplayIdentityV0 {
    command_id: String,
    signer_id: String,
    nonce: u64,
}

pub(crate) struct ComputedCompleteExecutionV0 {
    pub(crate) payload_root: [u8; 32],
    pub(crate) post_state_root: [u8; 32],
    pub(crate) receipts_root: [u8; 32],
    pub(crate) evidence_root: [u8; 32],
    pub(crate) native_receipts: Vec<NativeExecutionReceiptV0>,
    pub(crate) plan: CompleteStatePlanV0,
    pub(crate) replay_identities: Vec<ReplayIdentityV0>,
    pub(crate) final_lifecycle: ValidatorLifecycleStateV1,
}

impl ReplayIdentityV0 {
    pub(crate) fn command_id(&self) -> &str {
        &self.command_id
    }

    pub(crate) fn signer_id(&self) -> &str {
        &self.signer_id
    }

    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }
}

impl CompleteNativeExecutionV0 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        NativeExecutedBlockV0,
        CompleteStatePlanV0,
        Vec<ReplayIdentityV0>,
        ValidatorLifecycleStateV1,
    ) {
        (
            self.executed,
            self.plan,
            self.replay_identities,
            self.final_lifecycle,
        )
    }
}

struct CompleteOverlayView<'a> {
    store: &'a InMemoryNativeExecutionStoreV0,
    parent_version: u64,
    parent_root: jmt::RootHash,
    changes: &'a BTreeMap<String, StateObject>,
}

impl TryStateViewV0 for CompleteOverlayView<'_> {
    type Error = String;

    fn try_get(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StateObject>, Self::Error> {
        if let Some(object) = self.changes.get(object_key_hex) {
            return Ok(Some(object.clone()));
        }
        crate::store::read_authenticated_object_v0(
            self.store,
            self.parent_version,
            self.parent_root,
            object_key_hex,
        )
        .map(|value| {
            value.map(|record| StateObject {
                object_type: record.object_type().to_string(),
                version: record.object_version(),
                value_bytes: record.value().to_vec(),
            })
        })
        .map_err(|error| format!("{error:#}"))
    }
}

enum ReceiptFactsV0 {
    Runtime(RuntimeReceipt),
    Internal,
}

/// Executes the entire frozen-v0 application body against one already pinned
/// parent tree and its committed validator/parameter metadata.
pub(crate) fn execute_complete_native_block_v0(
    store: &InMemoryNativeExecutionStoreV0,
    validator_set: &ValidatorSet,
    expected_genesis_hash: GenesisHash,
    request: &trnm_native_application::NativeBlockExecutionRequestV0,
) -> Result<CompleteNativeExecutionV0> {
    let computed =
        compute_complete_native_block_v0(store, validator_set, expected_genesis_hash, request)?;
    let executed = NativeExecutedBlockV0::new(
        request.clone(),
        Hash32V0::new(computed.payload_root),
        trnm_native_application::StateRootV0::new(computed.post_state_root)?,
        trnm_native_application::ReceiptsRootV0::new(computed.receipts_root)?,
        Hash32V0::new(computed.evidence_root),
        computed.native_receipts,
    )
    .map_err(|error| anyhow!("native executed-block binding failed: {error}"))?;
    Ok(CompleteNativeExecutionV0 {
        executed,
        plan: computed.plan,
        replay_identities: computed.replay_identities,
        final_lifecycle: computed.final_lifecycle,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn compute_complete_native_block_v0<R: CompleteBlockExecutionInputV0 + ?Sized>(
    store: &InMemoryNativeExecutionStoreV0,
    validator_set: &ValidatorSet,
    expected_genesis_hash: GenesisHash,
    request: &R,
) -> Result<ComputedCompleteExecutionV0> {
    let (parent_version, parent_root) = crate::store::verify_parent_root_v0(store)?;
    ensure!(
        parent_version == request.parent_v0().height().get(),
        "complete execution parent height/JMT version mismatch"
    );
    ensure!(
        request.parent_v0().state_root().as_bytes() == &parent_root.0,
        "complete execution parent StateRoot mismatch"
    );
    ensure!(
        request.height_v0().get()
            == parent_version
                .checked_add(1)
                .context("parent height exhausted")?,
        "complete execution target is not the exact successor"
    );
    ensure!(
        request.chain_id_v0().as_str() == store.chain_id_v0()?,
        "complete execution chain ID mismatch"
    );
    ensure!(
        request.genesis_hash_v0().as_bytes() == expected_genesis_hash.as_bytes(),
        "complete execution genesis hash mismatch"
    );
    ensure!(
        validator_set.genesis_hash() == expected_genesis_hash,
        "validator set genesis hash mismatch"
    );
    ensure!(
        validator_set.chain_id().as_str() == request.chain_id_v0().as_str(),
        "validator set chain ID mismatch"
    );
    ensure!(
        validator_set.id().as_bytes() == request.active_validator_set_id_v0().as_bytes(),
        "active validator-set ID mismatch"
    );
    let parameters = store.consensus_parameters_v0()?;
    parameters
        .validate_safety_invariants()
        .map_err(consensus_error)?;
    validator_set
        .validate_against_parameters(&parameters)
        .map_err(consensus_error)?;
    crate::validate_poco_parameter_retention_v0(&parameters)?;

    let signers = store.authorized_signers_v0()?;
    let actual_signer_commitment = signer_policy_commitment_v0(signers)?;
    ensure!(
        actual_signer_commitment == store.signer_policy_commitment_v0()?,
        "pinned signer policy commitment mismatch"
    );

    let mut live = store.verified_live_values_v0(parent_version)?;
    let source_poco = take_and_validate_production_poco_projection_v0(parent_version, &mut live)?;
    let parent_lifecycle = load_validator_lifecycle_from_live_v0(&live, parent_version)?;
    ensure!(
        parent_lifecycle.chain_id == request.chain_id_v0().as_str(),
        "validator lifecycle chain binding mismatch"
    );
    ensure!(
        parent_lifecycle.authorized_signers_hash_hex == hex::encode(actual_signer_commitment),
        "validator lifecycle signer-policy binding mismatch"
    );
    let mut lifecycle = parent_lifecycle.clone();
    lifecycle.prepare_height(request.height_v0().get())?;
    validate_application_validator_projection_v0(validator_set, &lifecycle.active_validators)?;

    let application_payload =
        ApplicationPayloadV0::new(request.transactions_v0().to_vec()).map_err(consensus_error)?;
    ensure!(
        u64::from(application_payload.cev0_len()) <= u64::from(parameters.max_block_bytes()),
        "complete application payload exceeds max_block_bytes"
    );
    let body =
        BlockBodyV0::new(application_payload.clone(), Vec::new()).map_err(consensus_error)?;
    let payload_root = application_payload
        .payload_root()
        .map_err(consensus_error)?;
    let evidence_root = body.evidence_root().map_err(consensus_error)?;

    let mut command_ids = BTreeSet::new();
    let mut signer_nonces = BTreeSet::new();
    let mut replay_identities = Vec::with_capacity(request.transactions_v0().len());
    let mut changes = BTreeMap::new();
    let mut receipt_facts = Vec::with_capacity(request.transactions_v0().len());
    let mut poco_overlay: Option<PocoApplicationBlockOverlayV0> = None;
    let mut poco_raws = Vec::new();
    let mut validator_transition_count = 0usize;

    for exact_outer_bytes in request.transactions_v0() {
        let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(exact_outer_bytes)
            .context("decode exact signed command envelope")?;
        envelope
            .validate_at_strict(request.chain_id_v0().as_str(), request.timestamp_ms_v0())
            .context("strictly verify exact signed command envelope")?;
        let signer = validate_signer_v0(signers, &envelope)?;
        ensure!(
            command_ids.insert(envelope.command_id.clone()),
            "duplicate block command ID"
        );
        ensure!(
            signer_nonces.insert((envelope.signer_id.clone(), envelope.nonce)),
            "duplicate block signer nonce"
        );
        ensure!(
            !store.committed_command_id_v0(&envelope.command_id)?,
            "command ID already committed"
        );
        ensure!(
            !store.committed_signer_nonce_v0(&envelope.signer_id, envelope.nonce)?,
            "signer nonce already committed"
        );
        replay_identities.push(ReplayIdentityV0 {
            command_id: envelope.command_id.clone(),
            signer_id: envelope.signer_id.clone(),
            nonce: envelope.nonce,
        });
        let exact_inner = envelope.payload_bytes()?;

        match envelope.payload_type.as_str() {
            CANONICAL_TX_PAYLOAD_TYPE_V1 => {
                let transaction: CanonicalTxV1 = serde_json::from_slice(&exact_inner)
                    .context("decode exact canonical runtime transaction")?;
                transaction.validate()?;
                ensure!(
                    transaction.sender == envelope.signer_id,
                    "runtime envelope/transaction sender mismatch"
                );
                ensure!(
                    transaction.nonce == envelope.nonce,
                    "runtime envelope/transaction nonce mismatch"
                );
                let view = CompleteOverlayView {
                    store,
                    parent_version,
                    parent_root,
                    changes: &changes,
                };
                let runtime_context = ExecutionContext {
                    height: request.height_v0().get(),
                    signer_id: signer.signer_id(),
                    signer_role: signer.signer_role(),
                    payload_len: exact_inner.len(),
                };
                let receipt =
                    try_execute_v0(&transaction, runtime_context, &view).map_err(|failure| {
                        match failure.deterministic_failure_v0() {
                            Some(classification) => {
                                anyhow!("deterministic runtime failure: {}", classification.code())
                            }
                            None => anyhow!("authenticated runtime state unavailable: {failure}"),
                        }
                    })?;
                let staged = stage_runtime_mutations_v0(
                    &view,
                    request.height_v0().get(),
                    &changes,
                    &receipt.mutations,
                )?;
                changes.extend(staged);
                receipt_facts.push(ReceiptFactsV0::Runtime(receipt));
            }
            POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0 => {
                let operation = PocoApplicationOperationV0::decode_exact(&exact_inner)?;
                ensure!(
                    operation.target_height() == request.height_v0().get(),
                    "PoCO application target height mismatch"
                );
                if poco_overlay.is_none() {
                    let source = source_poco
                        .as_ref()
                        .context("PoCO application operation requires activated namespace")?;
                    let governance_signer = application_governance_signer_commitment_v0(&lifecycle);
                    let context = AuthenticatedPocoApplicationContextV0::new(
                        parent_version,
                        parent_root.0,
                        Height::new(request.height_v0().get()),
                        validator_set.chain_id(),
                        validator_set.genesis_hash(),
                        validator_set.epoch(),
                        parameters,
                        governance_signer,
                    )?;
                    poco_overlay = Some(PocoApplicationBlockOverlayV0::from_projection(
                        context, source,
                    )?);
                }
                match poco_overlay
                    .as_mut()
                    .expect("PoCO overlay initialized")
                    .apply_decoded_exact(&exact_inner, &operation)
                {
                    Ok(()) => {}
                    Err(PocoApplicationApplyFailureV0::DeterministicallyInvalid(reason)) => {
                        return Err(anyhow!(
                            "deterministically invalid PoCO operation: {reason:?}"
                        ));
                    }
                    Err(PocoApplicationApplyFailureV0::Invariant(reason)) => {
                        return Err(anyhow!("PoCO application invariant failed: {reason:?}"));
                    }
                }
                poco_raws.push(exact_inner);
                receipt_facts.push(ReceiptFactsV0::Internal);
            }
            VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1 => {
                let transition: ValidatorSetTransitionV1 =
                    serde_json::from_slice(&exact_inner).context("decode validator transition")?;
                ensure!(
                    serde_json::to_vec(&transition)? == exact_inner,
                    "validator transition is not canonical JSON"
                );
                ensure!(
                    transition.schema == VALIDATOR_TRANSITION_SCHEMA_V1,
                    "validator transition schema mismatch"
                );
                ensure!(
                    transition.chain_id == envelope.chain_id,
                    "validator transition chain mismatch"
                );
                ensure!(
                    transition.transition_id == envelope.command_id,
                    "validator transition command mismatch"
                );
                let authorization = ValidatorTransitionAuthorization {
                    command_id: &envelope.command_id,
                    signer_id: signer.signer_id(),
                    signer_role: signer.signer_role(),
                    nonce: envelope.nonce,
                    chain_id: envelope.chain_id.as_str(),
                    accepted_height: request.height_v0().get(),
                };
                match lifecycle.schedule(transition, authorization) {
                    Ok(()) => {}
                    Err(ValidatorTransitionScheduleFailureV1::DeterministicallyInvalid(reason)) => {
                        return Err(anyhow!(
                            "deterministically invalid validator transition: {reason:?}"
                        ));
                    }
                    Err(ValidatorTransitionScheduleFailureV1::Invariant(reason)) => {
                        return Err(anyhow!("validator transition invariant failed: {reason:?}"));
                    }
                }
                validator_transition_count = validator_transition_count
                    .checked_add(1)
                    .context("validator transition count exhausted")?;
                receipt_facts.push(ReceiptFactsV0::Internal);
            }
            _ => return Err(anyhow!("unsupported frozen-v0 application payload family")),
        }
    }

    let receipt_commitments = receipt_facts
        .iter()
        .enumerate()
        .map(|(index, facts)| {
            let index = u32::try_from(index).context("receipt index exceeds u32")?;
            let (gas, fee, events) = match facts {
                ReceiptFactsV0::Runtime(receipt) => (
                    receipt.gas_used,
                    receipt.fee_charged,
                    receipt
                        .events
                        .iter()
                        .map(runtime_event_to_consensus_v0)
                        .collect::<Result<Vec<_>>>()?,
                ),
                ReceiptFactsV0::Internal => (0, 0, Vec::new()),
            };
            ExecutionReceiptCommitmentV0::for_transaction(
                &application_payload,
                index,
                gas,
                fee,
                events,
            )
            .map_err(consensus_error)
        })
        .collect::<Result<Vec<_>>>()?;
    let execution_receipts = ExecutionReceiptsV0::new(&application_payload, receipt_commitments)
        .map_err(consensus_error)?;
    execution_receipts
        .validate_max_bytes(parameters.max_block_bytes())
        .map_err(consensus_error)?;
    let receipts_root = execution_receipts
        .receipts_root()
        .map_err(consensus_error)?;

    let mut writes = changes
        .iter()
        .map(|(key, object)| {
            let write = NativeStateWriteV0::from_object(
                key,
                &object.object_type,
                object.version,
                object.value_bytes.clone(),
            )?;
            CompleteStateWriteV0::new(write.key().to_vec(), Some(write.value().to_vec()))
        })
        .collect::<Result<Vec<_>>>()?;

    if lifecycle != parent_lifecycle || validator_transition_count > 0 {
        writes.push(validator_lifecycle_write_v0(
            request.height_v0().get(),
            &lifecycle,
        )?);
    }

    if let Some(overlay) = poco_overlay {
        let sealed = overlay.seal()?;
        ensure!(
            sealed.binds_exact_operations_v0(&poco_raws),
            "sealed PoCO plan does not bind exact operation sequence"
        );
        writes.extend(
            auth_writes_from_sealed_poco_application_v0(&sealed)?
                .into_iter()
                .map(complete_write_from_auth_v0)
                .collect::<Result<Vec<_>>>()?,
        );
    } else {
        let geometry =
            EpochGeometryV0::new(validator_set.epoch(), &parameters).map_err(consensus_error)?;
        let checkpoint_height = geometry.checkpoint_height().get();
        let cutoff_height = checkpoint_height
            .checked_sub(parameters.snapshot_lead_blocks())
            .context("scheduled PoCO cutoff height underflow")?;
        ensure!(
            cutoff_height < checkpoint_height,
            "invalid scheduled PoCO cutoff"
        );
        if request.height_v0().get() == cutoff_height {
            let projection = source_poco
                .as_ref()
                .context("scheduled PoCO cutoff requires activated namespace")?;
            writes.push(complete_write_from_auth_v0(
                scheduled_cutoff_manifest_refresh_write_v0(
                    Height::new(request.height_v0().get()),
                    projection,
                )?,
            )?);
        }
    }

    let plan =
        plan_complete_state_update_v0(store, parent_version, request.height_v0().get(), writes)?;
    let post_state_root = plan.state_root();
    ensure!(
        !post_state_root.is_zero(),
        "complete post-state root is zero"
    );
    let native_receipts = build_native_receipts_v0(&execution_receipts)?;
    Ok(ComputedCompleteExecutionV0 {
        payload_root: payload_root.into_bytes(),
        post_state_root: post_state_root.into_bytes(),
        receipts_root: receipts_root.into_bytes(),
        evidence_root: evidence_root.into_bytes(),
        native_receipts,
        plan,
        replay_identities,
        final_lifecycle: lifecycle,
    })
}

pub(crate) fn preview_complete_native_block_v0(
    store: &InMemoryNativeExecutionStoreV0,
    validator_set: &ValidatorSet,
    expected_genesis_hash: GenesisHash,
    request: &NativeBlockPreviewRequestV0,
) -> Result<NativeBlockPreviewV0> {
    let computed =
        compute_complete_native_block_v0(store, validator_set, expected_genesis_hash, request)?;
    let write_count =
        u64::try_from(computed.plan.writes().len()).context("preview write count exceeds u64")?;
    let encoded_writes =
        borsh::to_vec(computed.plan.writes()).context("encode canonical preview write plan")?;
    let request_fingerprint = request.fingerprint_v0(computed.payload_root);
    let write_plan_fingerprint = hash_domain(
        PREVIEW_WRITE_PLAN_DOMAIN_V0,
        &[
            &request_fingerprint,
            &request.height().get().to_be_bytes(),
            &write_count.to_be_bytes(),
            &computed.post_state_root,
            &computed.receipts_root,
            &encoded_writes,
        ],
    );
    Ok(NativeBlockPreviewV0 {
        request_fingerprint: Hash32V0::new(request_fingerprint),
        payload_root: Hash32V0::new(computed.payload_root),
        post_state_root: StateRootV0::new(computed.post_state_root)
            .map_err(|error| anyhow!("construct preview state root: {error}"))?,
        receipts_root: ReceiptsRootV0::new(computed.receipts_root)
            .map_err(|error| anyhow!("construct preview receipts root: {error}"))?,
        evidence_root: Hash32V0::new(computed.evidence_root),
        receipts: computed.native_receipts,
        write_plan_fingerprint: Hash32V0::new(write_plan_fingerprint),
        write_count,
    })
}

fn validate_signer_v0<'a>(
    signers: &'a [AuthorizedSignerV0],
    envelope: &SignedCommandEnvelopeV1,
) -> Result<&'a AuthorizedSignerV0> {
    let signer = signers
        .iter()
        .find(|candidate| candidate.signer_id() == envelope.signer_id)
        .context("command signer is not authorized by pinned policy")?;
    ensure!(
        signer.signer_role() == envelope.signer_role,
        "signer role mismatch"
    );
    ensure!(
        signer.public_key_hex() == envelope.public_key_hex,
        "signer public key mismatch"
    );
    Ok(signer)
}

pub(crate) fn load_validator_lifecycle_from_live_v0(
    live: &BTreeMap<Vec<u8>, Vec<u8>>,
    parent_version: u64,
) -> Result<ValidatorLifecycleStateV1> {
    let key = auth_tree::validator_state_key()?;
    let encoded = live
        .get(&key)
        .context("authenticated parent is missing validator lifecycle")?;
    let record = AuthenticatedObjectRecordV0::decode(encoded)?;
    ensure!(
        record.object_type() == VALIDATOR_LIFECYCLE_SCHEMA_V1,
        "validator lifecycle record type mismatch"
    );
    ensure!(
        record.object_version() <= parent_version,
        "validator lifecycle object version is ahead of parent"
    );
    let lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(record.value()).context("decode validator lifecycle JSON")?;
    ensure!(
        serde_json::to_vec(&lifecycle)? == record.value(),
        "validator lifecycle JSON is not canonical"
    );
    lifecycle.validate()?;
    Ok(lifecycle)
}

pub(crate) fn validator_lifecycle_seed_write_v0(
    object_version: u64,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<NativeStateWriteV0> {
    lifecycle.validate()?;
    let value = serde_json::to_vec(lifecycle).context("encode validator lifecycle JSON")?;
    let record =
        AuthenticatedObjectRecordV0::new(VALIDATOR_LIFECYCLE_SCHEMA_V1, object_version, value)?;
    NativeStateWriteV0::raw(auth_tree::validator_state_key()?, record.encode()?)
}

fn validator_lifecycle_write_v0(
    object_version: u64,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<CompleteStateWriteV0> {
    let write = validator_lifecycle_seed_write_v0(object_version, lifecycle)?;
    CompleteStateWriteV0::new(write.key().to_vec(), Some(write.value().to_vec()))
}

fn complete_write_from_auth_v0(write: AuthWrite) -> Result<CompleteStateWriteV0> {
    CompleteStateWriteV0::new(write.key().to_vec(), write.value().map(<[u8]>::to_vec))
}

pub(crate) fn validate_application_validator_projection_v0(
    set: &ValidatorSet,
    application: &[ConsensusValidatorV1],
) -> Result<()> {
    let mut expected = set
        .validators()
        .iter()
        .map(|validator| {
            (
                *validator.consensus_key().as_bytes(),
                validator.voting_power().get(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort_unstable();
    let mut actual = application
        .iter()
        .map(|validator| {
            let key = trnm_finality_types::decode_hash32(
                "application validator public key",
                &validator.public_key_hex,
            )?;
            Ok((key, validator.voting_power))
        })
        .collect::<Result<Vec<_>>>()?;
    actual.sort_unstable();
    ensure!(
        actual == expected,
        "validator lifecycle differs from active set"
    );
    Ok(())
}

fn application_governance_signer_commitment_v0(lifecycle: &ValidatorLifecycleStateV1) -> [u8; 32] {
    hash_domain(
        APPLICATION_GOVERNANCE_SIGNER_DOMAIN_V0,
        &[
            lifecycle.governance.signer_id.as_bytes(),
            lifecycle.authorized_signers_hash_hex.as_bytes(),
        ],
    )
}

fn build_native_receipts_v0(
    receipts: &ExecutionReceiptsV0,
) -> Result<Vec<NativeExecutionReceiptV0>> {
    receipts
        .receipts()
        .iter()
        .map(|receipt| {
            let events = receipt
                .events()
                .iter()
                .map(native_event_v0)
                .collect::<Result<Vec<_>>>()?;
            let encoded = receipt.try_cev0_bytes().map_err(consensus_error)?;
            NativeExecutionReceiptV0::new(
                receipt.transaction_index(),
                Hash32V0::new(*receipt.payload_leaf_hash()),
                receipt.gas_used(),
                receipt.fee_charged(),
                events,
                Hash32V0::new(hash_domain(
                    NATIVE_RECEIPT_COMMITMENT_DOMAIN_V0,
                    &[&encoded],
                )),
            )
            .map_err(|error| anyhow!("construct native execution receipt: {error}"))
        })
        .collect()
}

fn native_event_v0(event: &ExecutionEventV0) -> Result<NativeEventV0> {
    let kind = String::from_utf8(event.kind().to_vec()).context("event kind is not UTF-8")?;
    let attributes = event
        .attributes()
        .iter()
        .map(|attribute| {
            NativeEventAttributeV0::new(
                String::from_utf8(attribute.key().to_vec())
                    .context("event attribute key is not UTF-8")?,
                String::from_utf8(attribute.value().to_vec())
                    .context("event attribute value is not UTF-8")?,
            )
            .map_err(|error| anyhow!("construct native event attribute: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    NativeEventV0::new(kind, attributes)
        .map_err(|error| anyhow!("construct native execution event: {error}"))
}
