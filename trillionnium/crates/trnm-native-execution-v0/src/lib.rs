//! Active zero-Comet deterministic application and durable-P owner for frozen
//! PoCO-BFT v0.
//!
//! The owner executes an ordinary non-empty body against one authenticated,
//! pinned parent snapshot; derives the payload, complete post-state, receipt,
//! and evidence roots; atomically persists canonical execution artifact P and
//! the complete target JMT overlay; and requires immutable fresh-connection
//! readback before returning `Valid`.  It implements the application boundary,
//! but deliberately has no Core permit, Safety authority, storage ACK,
//! RequestSignature, signing key, network, or broadcast capability.
//!
//! The application owner is intentionally linear at the public API boundary:
//!
//! ```compile_fail
//! use trnm_native_execution_v0::DurableNativeApplicationV0;
//!
//! fn duplicate(owner: &DurableNativeApplicationV0) {
//!     let _copy = (*owner).clone();
//! }
//! ```
//!
//! The durable-P carrier is private and cannot be named by external crates:
//!
//! ```compile_fail
//! use trnm_native_execution_v0::DurablePV0;
//! ```

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, ensure, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use trnm_consensus_types::{
    ApplicationPayloadV0, BlockBodyV0, EvidenceRoot, ExecutionEventAttributeV0, ExecutionEventV0,
    ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, PayloadDigest, ReceiptsRoot, StateRoot,
};
use trnm_finality_types::{hash_domain, SignedCommandEnvelopeV1};
use trnm_protocol::{
    account_key, fee_policy_key, monetary_state_key, task_key, AccountV1, CanonicalCommandV1,
    CanonicalTxV1, FeePolicyV1, MonetaryStateV1, TaskV1, ACCOUNT_OBJECT_TYPE_V1,
    CANONICAL_TX_PAYLOAD_TYPE_V1, FEE_POLICY_OBJECT_TYPE_V1, MONETARY_STATE_OBJECT_TYPE_V1,
    TASK_OBJECT_TYPE_V1,
};
use trnm_runtime::{
    try_execute_v0, validate_authenticated_task_state_v0, ExecutionContext, RuntimeEvent,
    RuntimeMutation, RuntimeReceipt, StateObject, TryStateViewV0,
};

mod auth_tree;
mod canonical_lab_bootstrap;
mod complete;
mod durable;
mod poco_application;
mod poco_nullifier;
mod poco_semantics;
mod poco_snapshot;
mod poco_transition;
mod store;
mod validator_lifecycle;

pub use canonical_lab_bootstrap::{
    derive_canonical_lab_genesis_hash_v0, derive_canonical_lab_native_chain_genesis_v0,
    CanonicalLabNativeChainGenesisFactsV0, CanonicalLabNativeChainGenesisInputsV0,
    CanonicalLabNativeEmptyBootstrapBlockFactsV0, CanonicalLabNativeEmptyBootstrapPrefixV0,
    PreparedCanonicalLabNativeEmptyBootstrapBlockV0,
};
pub use complete::{NativeBlockPreviewRequestV0, NativeBlockPreviewV0};
pub use durable::{
    validate_native_finalized_execution_receipts_v0, CanonicalLabNativeApplicationConfigInputsV0,
    ConfirmedDurableExecutionHistoryRowV0, ConfirmedDurableExecutionPV0,
    ConfirmedNativeH1StateSyncTrustedBaseV0, DurableExecutionHistoryStatusV0,
    DurableNativeApplicationV0, FinalizedNativeApplicationCommitRequestV0,
    FinalizedNativeApplicationReadV0, NativeApplicationConfigV0,
    NativeApplicationExecutionErrorCodeV0, NativeApplicationExecutionErrorV0,
    NativeH1StateSyncTrustedBaseRequestV0,
};
pub use store::{
    authenticated_key_hash_v0, stored_object_key_v0, AuthenticatedObjectRecordV0,
    InMemoryNativeExecutionStoreV0, NativeExecutionStoreV0, NativeStateWriteV0,
    RuntimeObjectDeltaPlanV0, RuntimeObjectDeltaRootV0,
};

/// The historical domain labels are frozen v0 state semantics. Their names
/// do not represent a dependency or current product role.
const SIGNER_TREE_DOMAIN_V0: &str = "trnm.cometbft.authorized-signers.v1";
const SIGNER_LEAF_DOMAIN_V0: &str = "trnm.cometbft.authorized-signer.v1";

const AUTH_PROOF_RETENTION_VERSIONS_V0: u64 = 8_192;

fn validate_poco_parameter_retention_v0(
    parameters: &trnm_consensus_types::ConsensusParametersV0,
) -> Result<()> {
    ensure!(
        parameters.snapshot_lead_blocks() <= AUTH_PROOF_RETENTION_VERSIONS_V0,
        "PoCO snapshot lead exceeds authenticated JMT history retention"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedSignerV0 {
    signer_id: String,
    signer_role: String,
    public_key_hex: String,
}

impl AuthorizedSignerV0 {
    pub fn new(
        signer_id: impl Into<String>,
        signer_role: impl Into<String>,
        public_key_hex: impl Into<String>,
    ) -> Result<Self> {
        let signer = Self {
            signer_id: signer_id.into(),
            signer_role: signer_role.into(),
            public_key_hex: public_key_hex.into(),
        };
        ensure!(!signer.signer_id.is_empty(), "signer id must not be empty");
        ensure!(
            matches!(signer.signer_role.as_str(), "hepta" | "nakama" | "operator"),
            "unsupported signer role"
        );
        let key = trnm_finality_types::crypto::verifying_key_from_hex(&signer.public_key_hex)
            .context("authorized signer key is not canonical Ed25519")?;
        ensure!(!key.is_weak(), "authorized signer key is weak");
        Ok(signer)
    }

    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    pub fn signer_role(&self) -> &str {
        &self.signer_role
    }

    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }
}

pub fn signer_policy_commitment_v0(signers: &[AuthorizedSignerV0]) -> Result<[u8; 32]> {
    ensure!(
        !signers.is_empty(),
        "authorized signer policy must not be empty"
    );
    let mut canonical = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for signer in signers {
        ensure!(ids.insert(signer.signer_id.clone()), "duplicate signer id");
        ensure!(
            keys.insert(signer.public_key_hex.clone()),
            "duplicate signer key"
        );
        canonical.insert((
            signer.signer_id.clone(),
            signer.signer_role.clone(),
            signer.public_key_hex.clone(),
        ));
    }
    let leaves = canonical.into_iter().map(|(id, role, key)| {
        hash_domain(
            SIGNER_LEAF_DOMAIN_V0,
            &[id.as_bytes(), role.as_bytes(), key.as_bytes()],
        )
    });
    Ok(merkle_root_only_v0(SIGNER_TREE_DOMAIN_V0, leaves))
}

#[derive(Clone, Debug)]
pub struct NativeExecutionRequestV0 {
    parent_height: u64,
    target_height: u64,
    timestamp_ms: u64,
    exact_outer_transactions: Vec<Vec<u8>>,
    evidence_count: u32,
}

impl NativeExecutionRequestV0 {
    pub fn new_empty_evidence(
        parent_height: u64,
        target_height: u64,
        timestamp_ms: u64,
        exact_outer_transactions: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let value = Self {
            parent_height,
            target_height,
            timestamp_ms,
            exact_outer_transactions,
            evidence_count: 0,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.target_height
                == self
                    .parent_height
                    .checked_add(1)
                    .context("parent height exhausted")?,
            "target height is not the exact successor"
        );
        ensure!(
            self.evidence_count == 0,
            "candidate kernel supports empty evidence only"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutedTransactionV0 {
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    envelope: SignedCommandEnvelopeV1,
    transaction: CanonicalTxV1,
    runtime_receipt: RuntimeReceipt,
}

impl ExecutedTransactionV0 {
    pub fn exact_outer_bytes(&self) -> &[u8] {
        &self.exact_outer_bytes
    }

    pub fn exact_inner_bytes(&self) -> &[u8] {
        &self.exact_inner_bytes
    }

    pub fn envelope(&self) -> &SignedCommandEnvelopeV1 {
        &self.envelope
    }

    pub fn transaction(&self) -> &CanonicalTxV1 {
        &self.transaction
    }

    pub fn runtime_receipt(&self) -> &RuntimeReceipt {
        &self.runtime_receipt
    }
}

#[derive(Debug)]
pub struct NativeExecutionCandidateV0 {
    parent_height: u64,
    parent_state_root: StateRoot,
    target_height: u64,
    payload_root: PayloadDigest,
    runtime_object_delta_root: RuntimeObjectDeltaRootV0,
    receipts_root: ReceiptsRoot,
    evidence_root: EvidenceRoot,
    application_payload: ApplicationPayloadV0,
    execution_receipts: ExecutionReceiptsV0,
    executed_transactions: Vec<ExecutedTransactionV0>,
    final_objects: BTreeMap<String, StateObject>,
    runtime_object_delta_plan: RuntimeObjectDeltaPlanV0,
}

impl NativeExecutionCandidateV0 {
    pub const fn parent_height(&self) -> u64 {
        self.parent_height
    }
    pub const fn parent_state_root(&self) -> StateRoot {
        self.parent_state_root
    }
    pub const fn target_height(&self) -> u64 {
        self.target_height
    }
    pub const fn payload_root(&self) -> PayloadDigest {
        self.payload_root
    }
    pub const fn runtime_object_delta_root(&self) -> RuntimeObjectDeltaRootV0 {
        self.runtime_object_delta_root
    }
    pub const fn receipts_root(&self) -> ReceiptsRoot {
        self.receipts_root
    }
    pub const fn evidence_root(&self) -> EvidenceRoot {
        self.evidence_root
    }
    pub const fn application_payload(&self) -> &ApplicationPayloadV0 {
        &self.application_payload
    }
    pub const fn execution_receipts(&self) -> &ExecutionReceiptsV0 {
        &self.execution_receipts
    }
    pub fn executed_transactions(&self) -> &[ExecutedTransactionV0] {
        &self.executed_transactions
    }
    pub fn final_objects(&self) -> &BTreeMap<String, StateObject> {
        &self.final_objects
    }
    pub const fn runtime_object_delta_plan(&self) -> &RuntimeObjectDeltaPlanV0 {
        &self.runtime_object_delta_plan
    }
    pub fn into_runtime_object_delta_plan(self) -> RuntimeObjectDeltaPlanV0 {
        self.runtime_object_delta_plan
    }
}

struct OverlayView<'a, S> {
    store: &'a S,
    parent_version: u64,
    parent_root: jmt::RootHash,
    changes: &'a BTreeMap<String, StateObject>,
}

impl<S: NativeExecutionStoreV0> TryStateViewV0 for OverlayView<'_, S> {
    type Error = String;

    fn try_get(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StateObject>, Self::Error> {
        if let Some(object) = self.changes.get(object_key_hex) {
            return Ok(Some(object.clone()));
        }
        store::read_authenticated_object_v0(
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

/// Executes one exact, empty-evidence frozen-v0 body against a store-owned,
/// authenticated parent. The result is a candidate plan, never persistence or
/// application authority.
pub fn execute_authenticated_block_candidate_v0<S: NativeExecutionStoreV0>(
    store: &S,
    request: NativeExecutionRequestV0,
) -> Result<NativeExecutionCandidateV0> {
    request.validate()?;
    let (parent_version, parent_root) = store::verify_parent_root_v0(store)?;
    ensure!(
        parent_version == request.parent_height,
        "parent height/JMT version mismatch"
    );
    let chain_id = store.chain_id_v0()?;
    ensure!(!chain_id.is_empty(), "store chain id must not be empty");
    let signers = store.authorized_signers_v0()?;
    let consensus_parameters = store.consensus_parameters_v0()?;
    let actual_policy = signer_policy_commitment_v0(signers)?;
    ensure!(
        actual_policy == store.signer_policy_commitment_v0()?,
        "store signer policy commitment mismatch"
    );

    let application_payload = ApplicationPayloadV0::new(request.exact_outer_transactions.clone())
        .map_err(consensus_error)?;
    ensure!(
        u64::from(application_payload.cev0_len())
            <= u64::from(consensus_parameters.max_block_bytes()),
        "application payload exceeds store-bound max_block_bytes"
    );
    let body =
        BlockBodyV0::new(application_payload.clone(), Vec::new()).map_err(consensus_error)?;
    let evidence_root = body.evidence_root().map_err(consensus_error)?;
    let payload_root = application_payload
        .payload_root()
        .map_err(consensus_error)?;

    let mut command_ids = BTreeSet::new();
    let mut signer_nonces = BTreeSet::new();
    let mut changes = BTreeMap::new();
    let mut executed = Vec::with_capacity(request.exact_outer_transactions.len());
    let mut receipt_commitments = Vec::with_capacity(request.exact_outer_transactions.len());

    for (index, exact_outer_bytes) in request.exact_outer_transactions.iter().enumerate() {
        let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(exact_outer_bytes)
            .context("decode exact signed command envelope")?;
        envelope
            .validate_at_strict(chain_id, request.timestamp_ms)
            .context("strictly verify exact signed command envelope")?;
        ensure!(
            envelope.payload_type == CANONICAL_TX_PAYLOAD_TYPE_V1,
            "unsupported runtime payload type"
        );
        let signer = signers
            .iter()
            .find(|candidate| candidate.signer_id == envelope.signer_id)
            .context("command signer is not authorized by store policy")?;
        ensure!(
            signer.signer_role == envelope.signer_role,
            "signer role mismatch"
        );
        ensure!(
            signer.public_key_hex == envelope.public_key_hex,
            "signer public key mismatch"
        );
        ensure!(
            command_ids.insert(envelope.command_id.clone()),
            "duplicate block command id"
        );
        ensure!(
            signer_nonces.insert((envelope.signer_id.clone(), envelope.nonce)),
            "duplicate block signer nonce"
        );
        ensure!(
            !store.committed_command_id_v0(&envelope.command_id)?,
            "command id already committed"
        );
        ensure!(
            !store.committed_signer_nonce_v0(&envelope.signer_id, envelope.nonce)?,
            "signer nonce already committed"
        );
        let exact_inner_bytes = envelope.payload_bytes()?;
        let transaction: CanonicalTxV1 = serde_json::from_slice(&exact_inner_bytes)
            .context("decode exact canonical transaction semantics")?;
        transaction.validate()?;
        ensure!(
            envelope.signer_id == transaction.sender,
            "envelope/transaction sender mismatch"
        );
        ensure!(
            envelope.nonce == transaction.nonce,
            "envelope/transaction nonce mismatch"
        );

        let view = OverlayView {
            store,
            parent_version,
            parent_root,
            changes: &changes,
        };
        let context = ExecutionContext {
            height: request.target_height,
            signer_id: signer.signer_id(),
            signer_role: signer.signer_role(),
            payload_len: exact_inner_bytes.len(),
        };
        let runtime_receipt = try_execute_v0(&transaction, context, &view).map_err(|failure| {
            match failure.deterministic_failure_v0() {
                Some(classification) => {
                    anyhow!("deterministic runtime failure: {}", classification.code())
                }
                None => anyhow!("authenticated runtime state unavailable: {failure}"),
            }
        })?;
        let staged = stage_runtime_mutations_v0(
            &view,
            request.target_height,
            &changes,
            &runtime_receipt.mutations,
        )?;
        changes = staged;

        let consensus_events = runtime_receipt
            .events
            .iter()
            .map(runtime_event_to_consensus_v0)
            .collect::<Result<Vec<_>>>()?;
        let index_u32 = u32::try_from(index).context("transaction index exceeds u32")?;
        receipt_commitments.push(
            ExecutionReceiptCommitmentV0::for_transaction(
                &application_payload,
                index_u32,
                runtime_receipt.gas_used,
                runtime_receipt.fee_charged,
                consensus_events,
            )
            .map_err(consensus_error)?,
        );
        executed.push(ExecutedTransactionV0 {
            exact_outer_bytes: exact_outer_bytes.clone(),
            exact_inner_bytes,
            envelope,
            transaction,
            runtime_receipt,
        });
    }

    let execution_receipts = ExecutionReceiptsV0::new(&application_payload, receipt_commitments)
        .map_err(consensus_error)?;
    execution_receipts
        .validate_max_bytes(consensus_parameters.max_block_bytes())
        .map_err(consensus_error)?;
    let receipts_root = execution_receipts
        .receipts_root()
        .map_err(consensus_error)?;
    let writes = changes
        .iter()
        .map(|(key, object)| {
            NativeStateWriteV0::from_object(
                key,
                &object.object_type,
                object.version,
                object.value_bytes.clone(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let runtime_object_delta_plan =
        store::plan_state_update_v0(store, parent_version, request.target_height, writes)?;
    let runtime_object_delta_root = runtime_object_delta_plan.runtime_object_delta_root();

    Ok(NativeExecutionCandidateV0 {
        parent_height: request.parent_height,
        parent_state_root: StateRoot::new(parent_root.into()),
        target_height: request.target_height,
        payload_root,
        runtime_object_delta_root,
        receipts_root,
        evidence_root,
        application_payload,
        execution_receipts,
        executed_transactions: executed,
        final_objects: changes,
        runtime_object_delta_plan,
    })
}

pub(crate) fn stage_runtime_mutations_v0<View: TryStateViewV0>(
    view: &View,
    target_height: u64,
    prior: &BTreeMap<String, StateObject>,
    mutations: &[RuntimeMutation],
) -> Result<BTreeMap<String, StateObject>>
where
    View::Error: std::fmt::Display,
{
    let mut staged = prior.clone();
    let mut seen = BTreeSet::new();
    for mutation in mutations {
        ensure!(
            seen.insert(mutation.object_key_hex.clone()),
            "duplicate runtime mutation key"
        );
        let current = match staged.get(&mutation.object_key_hex) {
            Some(object) => Some(object.clone()),
            None => view
                .try_get(&mutation.object_key_hex)
                .map_err(|error| anyhow!("authenticated mutation read failed: {error}"))?,
        };
        ensure!(
            current.as_ref().map(|object| object.version) == mutation.expected_version,
            "runtime mutation expected-version mismatch"
        );
        if let Some(current) = &current {
            ensure!(
                current.object_type == mutation.object_type,
                "runtime mutation changes object type"
            );
        }
        let expected_next = current.as_ref().map_or(Ok(1), |object| {
            object
                .version
                .checked_add(1)
                .context("object version exhausted")
        })?;
        ensure!(
            mutation.next_version == expected_next,
            "runtime mutation next-version mismatch"
        );
        validate_runtime_mutation_v0(target_height, mutation)?;
        staged.insert(
            mutation.object_key_hex.clone(),
            StateObject {
                object_type: mutation.object_type.clone(),
                version: mutation.next_version,
                value_bytes: mutation.value_bytes.clone(),
            },
        );
    }
    Ok(staged)
}

fn decode_canonical_runtime_value_v0<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = serde_json::from_slice(bytes).context("decode runtime mutation value")?;
    ensure!(
        serde_json::to_vec(&value).context("re-encode runtime mutation value")? == bytes,
        "runtime mutation value is not canonical JSON"
    );
    Ok(value)
}

fn validate_runtime_mutation_v0(target_height: u64, mutation: &RuntimeMutation) -> Result<()> {
    let expected_key = match mutation.object_type.as_str() {
        ACCOUNT_OBJECT_TYPE_V1 => {
            let account: AccountV1 = decode_canonical_runtime_value_v0(&mutation.value_bytes)?;
            CanonicalCommandV1::CreditAccount {
                account: account.account.clone(),
                amount: 1,
            }
            .validate()?;
            account_key(&account.account)
        }
        TASK_OBJECT_TYPE_V1 => {
            let task: TaskV1 = decode_canonical_runtime_value_v0(&mutation.value_bytes)?;
            CanonicalCommandV1::CreateTask {
                task_id: task.task_id.clone(),
                reward: task.reward,
                worker_stake: task.worker_stake,
                result_deadline_height: task.result_deadline_height,
                challenge_window_blocks: task.challenge_window_blocks,
            }
            .validate()?;
            validate_authenticated_task_state_v0(&task, mutation.next_version, target_height)
                .map_err(|_| anyhow!("runtime task mutation is unreachable"))?;
            task_key(&task.task_id)
        }
        FEE_POLICY_OBJECT_TYPE_V1 => {
            let policy: FeePolicyV1 = decode_canonical_runtime_value_v0(&mutation.value_bytes)?;
            CanonicalCommandV1::SetFeePolicy {
                gas_price: policy.gas_price,
                base_gas: policy.base_gas,
                byte_gas: policy.byte_gas,
            }
            .validate()?;
            fee_policy_key()
        }
        MONETARY_STATE_OBJECT_TYPE_V1 => {
            let _: MonetaryStateV1 = decode_canonical_runtime_value_v0(&mutation.value_bytes)?;
            monetary_state_key()
        }
        _ => return Err(anyhow!("runtime mutation uses unsupported object type")),
    };
    ensure!(
        mutation.object_key_hex == expected_key,
        "runtime mutation canonical key mismatch"
    );
    Ok(())
}

pub(crate) fn runtime_event_to_consensus_v0(event: &RuntimeEvent) -> Result<ExecutionEventV0> {
    let mut attributes = event
        .attributes
        .iter()
        .map(|(key, value)| {
            ExecutionEventAttributeV0::new(key.as_bytes().to_vec(), value.as_bytes().to_vec())
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(consensus_error)?;
    attributes.sort_by(|left, right| left.key().cmp(right.key()));
    ExecutionEventV0::new(event.kind.as_bytes().to_vec(), attributes).map_err(consensus_error)
}

pub(crate) fn consensus_error(error: trnm_consensus_types::ValidationError) -> anyhow::Error {
    anyhow!("frozen-v0 commitment construction failed: {error:?}")
}

fn merkle_root_only_v0<I>(tree_domain: &str, leaves: I) -> [u8; 32]
where
    I: IntoIterator<Item = [u8; 32]>,
{
    let mut current = leaves.into_iter().collect::<Vec<_>>();
    if current.is_empty() {
        return hash_domain("trnm.merkle.empty.v1", &[tree_domain.as_bytes()]);
    }
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(hash_domain(
                "trnm.merkle.parent.v1",
                &[tree_domain.as_bytes(), &left, &right],
            ));
        }
        current = next;
    }
    current[0]
}

#[cfg(test)]
mod tests;
