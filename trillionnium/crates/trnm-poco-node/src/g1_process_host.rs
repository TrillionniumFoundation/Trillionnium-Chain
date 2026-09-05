//! Candidate-only real-process host for the first CheckTx -> native AppHash
//! vertical slice.
//!
//! This module is intentionally behind `g1-process-test-support`.  It owns a
//! single OS process, a bounded byte ingress, the node-owned candidate CheckTx
//! WAL, and one durable native application owner.  A successful request is
//! admitted, executed into native durable `P`, committed to `D`, and freshly
//! read back by block id.  The host does not activate production consensus or
//! claim a Core/Safety finality permit; the response labels that boundary
//! explicitly.  If a handoff or application operation is uncertain, the host
//! terminates instead of guessing or releasing an ambiguous WAL row.

#![cfg(feature = "g1-process-test-support")]
#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    thread,
    time::Duration,
};

#[cfg(any(test, feature = "g1-process-test-support"))]
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use trnm_application_tx_builder_v0::{validate_strict_json_structure_v0, BuiltCanonicalTxV0};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    BlockHeader, BlockId, BlockKind, CertifiedHeaderV0, ChainId, ConsensusParametersV0,
    ConsensusPublicKey, Epoch, EvidenceRoot, FinalityProofV0, GenesisHash, GenesisQcV0, Height,
    PayloadDigest, ProtocolVersion, QcReferenceV0, QuorumCertificate, ReceiptsRoot, Signature64,
    SignatureBytes, StateRoot as ConsensusStateRoot, Validator, ValidatorId, ValidatorSet, View,
    Vote, VotingPower,
};
use trnm_finality_types::crypto::public_key_hex;
use trnm_mempool::{AdmissionReject, CanonicalSignerId, IngressClass, TypedAdmitOutcome};
use trnm_native_application::{
    ChainIdV0, GenesisHashV0, NativeApplicationGenesisRequestV0, NativeApplicationV0,
    NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0, NativeExpectedBlockCommitmentsV0,
    ValidatorSetIdV0,
};
use trnm_native_execution_v0::{
    AuthorizedSignerV0, CanonicalLabNativeApplicationConfigInputsV0, DurableNativeApplicationV0,
    FinalizedNativeApplicationCommitRequestV0, NativeApplicationConfigV0,
    NativeApplicationExecutionErrorCodeV0, NativeBlockPreviewRequestV0, NativeBlockPreviewV0,
};
use trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1;

use crate::{
    CanonicalAdmissionContextResolverV0, CanonicalSignerIdentityResolverV0,
    NativeCommitReceiptEvidenceV0, NodeOwnedTxAdmissionBoundaryV0,
};

/// This is a candidate process composition, not a production activation.
pub const G1_PROCESS_HOST_CANDIDATE_V0: bool = true;
pub const G1_PROCESS_HOST_PRODUCTION_ACTIVATION_V0: bool = false;
pub const G1_PROCESS_HOST_EFFECT_DRIVER_PRODUCTION_V0: bool = false;
pub const G1_PROCESS_HOST_MAX_FRAME_BYTES_V0: usize = 256 * 1024;
pub const G1_PROCESS_HOST_QUEUE_CAPACITY_V0: usize = 8;
pub const G1_PROCESS_HOST_CHAIN_ID_V0: &str = "trnm-g1-process-v0";

const OPERATOR_SIGNER_ID_V0: &str = "did:operator:g1-process";
const OPERATOR_SIGNER_ROLE_V0: &str = "operator";
const OPERATOR_KEY_BYTES_V0: [u8; 32] = [0x47; 32];
const CANONICAL_SIGNER_BYTES_V0: [u8; 32] = [0xA1; 32];
const FIXTURE_NOW_UNIX_MS_V0: u64 = 1_700_000_001_000;
// Keep the application timestamp aligned with the signed-envelope fixture so
// native execution's strict context check can authenticate the exact bytes.
// The first proof carries the preceding authenticated parent timestamp one
// second earlier, satisfying the 60-second consensus step bound.
const FIXTURE_BLOCK_TIMESTAMP_MS_V0: u64 = 1_700_000_000_000;
const FIXTURE_PARENT_TIMESTAMP_MS_V0: u64 = FIXTURE_BLOCK_TIMESTAMP_MS_V0 - 1_000;
const WAL_NAMESPACE_V0: [u8; 32] = [0xC1; 32];
const GENESIS_HASH_BYTES_V0: [u8; 32] = [0xD0; 32];
const FAILPOINT_AFTER_HANDOFF_ENV_V0: &str = "TRNM_G1_PROCESS_PAUSE_AFTER_HANDOFF_MARKER";
const FAILPOINT_AFTER_APPLICATION_COMMIT_ENV_V0: &str =
    "TRNM_G1_PROCESS_PAUSE_AFTER_APPLICATION_COMMIT_MARKER";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct G1ProcessHostErrorV0 {
    code: &'static str,
    detail: String,
}

impl G1ProcessHostErrorV0 {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn debug(code: &'static str, detail: impl fmt::Debug) -> Self {
        Self::new(code, format!("{detail:?}"))
    }

    pub const fn code_v0(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for G1ProcessHostErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for G1ProcessHostErrorV0 {}

impl From<io::Error> for G1ProcessHostErrorV0 {
    fn from(error: io::Error) -> Self {
        Self::debug("io", error)
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum G1IngressRequestV0 {
    #[serde(rename = "submit")]
    Submit { generation: u64, tx_hex: String },
    #[serde(rename = "shutdown")]
    Shutdown,
}

#[derive(Debug, Serialize)]
pub struct G1IngressResponseV0 {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_digest: Option<String>,
    queue_depth: usize,
    queue_capacity: usize,
    accepted: u64,
    rejected: u64,
    backpressure_rejected: u64,
    pacemaker_generation: u64,
    production_candidate: bool,
    finality_verified: bool,
}

impl G1IngressResponseV0 {
    fn rejected(
        reason: &'static str,
        queue_depth: usize,
        accepted: u64,
        rejected: u64,
        backpressure_rejected: u64,
        generation: u64,
    ) -> Self {
        Self {
            status: "rejected",
            reason: Some(reason),
            generation: None,
            height: None,
            block_id: None,
            state_root: None,
            receipt_digest: None,
            queue_depth,
            queue_capacity: G1_PROCESS_HOST_QUEUE_CAPACITY_V0,
            accepted,
            rejected,
            backpressure_rejected,
            pacemaker_generation: generation,
            production_candidate: false,
            finality_verified: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessSignerResolverV0 {
    canonical_id: CanonicalSignerId,
}

impl CanonicalSignerIdentityResolverV0 for ProcessSignerResolverV0 {
    fn resolve_canonical_signer_id_v0(
        &self,
        transaction: &BuiltCanonicalTxV0,
    ) -> Result<CanonicalSignerId, AdmissionReject> {
        let envelope = transaction.envelope();
        let expected_key = public_key_hex(&SigningKey::from_bytes(&OPERATOR_KEY_BYTES_V0));
        if self.canonical_id.as_bytes() != CANONICAL_SIGNER_BYTES_V0
            || envelope.signer_id != OPERATOR_SIGNER_ID_V0
            || envelope.signer_role != OPERATOR_SIGNER_ROLE_V0
            || envelope.public_key_hex != expected_key
            || envelope.payload_type != CANONICAL_TX_PAYLOAD_TYPE_V1
        {
            return Err(AdmissionReject::SignerIdentityUnavailable);
        }
        Ok(self.canonical_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessAdmissionContextV0;

impl CanonicalAdmissionContextResolverV0 for ProcessAdmissionContextV0 {
    fn chain_id_v0(&self) -> &str {
        G1_PROCESS_HOST_CHAIN_ID_V0
    }

    fn now_unix_ms_v0(&self) -> u64 {
        FIXTURE_NOW_UNIX_MS_V0
    }
}

/// Metrics returned by the process after EOF. These values are process-local
/// candidate evidence and are intentionally not promoted to a package truth
/// flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct G1ProcessHostSummaryV0 {
    pub accepted: u64,
    pub rejected: u64,
    pub backpressure_rejected: u64,
    pub final_generation: u64,
    pub final_height: u64,
    pub final_state_root_nonzero: bool,
    pub production_candidate: bool,
    pub finality_verified: bool,
}

/// Single-process owner for the bounded candidate path.
pub struct G1ProcessHostV0 {
    boundary: NodeOwnedTxAdmissionBoundaryV0,
    application: DurableNativeApplicationV0,
    generation: u64,
    queue: VecDeque<()>,
    accepted: u64,
    rejected: u64,
    backpressure_rejected: u64,
    final_height: u64,
    final_state_root_nonzero: bool,
    last_timestamp_ms: u64,
}

impl fmt::Debug for G1ProcessHostV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("G1ProcessHostV0")
            .field("generation", &self.generation)
            .field("accepted", &self.accepted)
            .field("rejected", &self.rejected)
            .field("backpressure_rejected", &self.backpressure_rejected)
            .finish_non_exhaustive()
    }
}

impl G1ProcessHostV0 {
    /// Open a fresh or exactly resumable candidate root under an absolute
    /// existing directory. An unresolved WAL handoff is recoverable only when
    /// the same exact transaction, native receipt, and independently verified
    /// PoCO proof are all present in durable application state; otherwise the
    /// owner remains fail-closed and refuses ingress.
    pub fn open(run_root: impl AsRef<Path>) -> Result<Self, G1ProcessHostErrorV0> {
        let run_root = run_root.as_ref();
        validate_run_root_v0(run_root)?;
        let application_path = run_root.join("native-application.sqlite");
        let admission_path = run_root.join("tx-admission.sqlite");
        let config = application_config_v0()?;
        let genesis_request = genesis_request_v0(&config)?;
        let application = DurableNativeApplicationV0::open(&application_path, config)
            .map_err(|error| G1ProcessHostErrorV0::debug("application.open", error))?;
        match application.initialize(genesis_request) {
            Ok(_) => {}
            // `initialize` is intentionally strict and refuses a non-genesis
            // committed head.  A restart must authenticate that existing head
            // through the normal immutable readback path instead of trying to
            // reinitialize or silently overwrite it.
            Err(error)
                if error.code() == NativeApplicationExecutionErrorCodeV0::NonContiguous
                    && error.field() == "initialize.committed_head" =>
            {
                application
                    .confirmed_committed_head_v0()
                    .map_err(|error| G1ProcessHostErrorV0::debug("application.reopen", error))?;
            }
            Err(error) => {
                return Err(G1ProcessHostErrorV0::debug("application.initialize", error));
            }
        }
        // Recover the durable height and timestamp so a process restart cannot
        // replay generation zero or emit a non-increasing block timestamp.
        // The native head intentionally has no clock field; the exact latest
        // committed P row is the only admissible source for this value.
        let recovered_head = application
            .confirmed_committed_head_v0()
            .map_err(|error| G1ProcessHostErrorV0::debug("application.recovery_head", error))?;
        let (recovered_generation, recovered_height, recovered_nonzero_root, recovered_timestamp) =
            if recovered_head.height().get() == 0 {
                (0, 0, false, FIXTURE_PARENT_TIMESTAMP_MS_V0)
            } else {
                let read = application
                    .read_finalized_by_height_v0(recovered_head.height())
                    .map_err(|error| {
                        G1ProcessHostErrorV0::debug("application.recovery_row", error)
                    })?;
                (
                    recovered_head.height().get(),
                    recovered_head.height().get(),
                    !recovered_head.state_root().hash().is_zero(),
                    read.executed_v0().request().timestamp_ms(),
                )
            };
        let signer_id = CanonicalSignerId::from_bytes(CANONICAL_SIGNER_BYTES_V0)
            .map_err(|_| G1ProcessHostErrorV0::new("signer.id", "canonical signer id is zero"))?;
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_and_context_handoff_recovery(
                admission_path,
                WAL_NAMESPACE_V0,
                G1_PROCESS_HOST_QUEUE_CAPACITY_V0,
                0,
                ProcessSignerResolverV0 {
                    canonical_id: signer_id,
                },
                ProcessAdmissionContextV0,
            )
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.open", error))?;
        Self::recover_handed_off_after_restart_v0(&mut boundary, &application)?;
        Ok(Self {
            boundary,
            application,
            generation: recovered_generation,
            queue: VecDeque::with_capacity(G1_PROCESS_HOST_QUEUE_CAPACITY_V0),
            accepted: 0,
            rejected: 0,
            backpressure_rejected: 0,
            final_height: recovered_height,
            final_state_root_nonzero: recovered_nonzero_root,
            last_timestamp_ms: recovered_timestamp,
        })
    }

    /// Reconcile a process crash in the narrow window after the WAL row was
    /// handed off but before the WAL receipt transaction was acknowledged.
    /// There is deliberately no "best effort" branch: exactly one unresolved
    /// row must match exactly one durable application transaction in the
    /// current committed head, and the proof/readback join must succeed before
    /// the row can be resolved.  A crash before application commit therefore
    /// remains an `AmbiguousHandoff` and keeps startup fail-closed.
    fn recover_handed_off_after_restart_v0(
        boundary: &mut NodeOwnedTxAdmissionBoundaryV0,
        application: &DurableNativeApplicationV0,
    ) -> Result<(), G1ProcessHostErrorV0> {
        let records = boundary
            .handed_off_records_v0()
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.recovery.enumerate", error))?;
        if records.is_empty() {
            return Ok(());
        }
        if records.len() != 1 {
            return Err(G1ProcessHostErrorV0::new(
                "admission.recovery.ambiguous",
                "candidate host requires exactly one unresolved handoff",
            ));
        }
        let record = records[0];
        let head = application
            .confirmed_committed_head_v0()
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.recovery.head", error))?;
        if head.height().get() == 0 {
            return Err(G1ProcessHostErrorV0::new(
                "admission.recovery.ambiguous",
                "WAL handoff exists but the native application has no committed block",
            ));
        }
        let read = application
            .read_finalized_by_height_v0(head.height())
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.recovery.readback", error))?;
        let execution = read.executed_v0().request();
        if execution.height() != head.height()
            || execution.block_id().as_bytes() != head.block_id().as_bytes()
            || execution.expected().post_state_root().as_bytes() != head.state_root().as_bytes()
        {
            return Err(G1ProcessHostErrorV0::new(
                "admission.recovery.binding",
                "native committed head does not match its execution artifact",
            ));
        }

        let signer_id = CanonicalSignerId::from_bytes(CANONICAL_SIGNER_BYTES_V0)
            .map_err(|_| G1ProcessHostErrorV0::new("admission.recovery.signer", "zero signer"))?;
        let signer = ProcessSignerResolverV0 {
            canonical_id: signer_id,
        };
        let mut matched: Option<(BuiltCanonicalTxV0, usize)> = None;
        for (index, outer_bytes) in execution.transactions().iter().enumerate() {
            let transaction =
                BuiltCanonicalTxV0::from_exact_outer_bytes_v0(outer_bytes).map_err(|error| {
                    G1ProcessHostErrorV0::debug("admission.recovery.tx_decode", error)
                })?;
            if transaction.protocol_tx_hash_v1() != record.digest_v0() {
                continue;
            }
            let resolved_signer = signer
                .resolve_canonical_signer_id_v0(&transaction)
                .map_err(|_| {
                    G1ProcessHostErrorV0::new(
                        "admission.recovery.signer",
                        "durable handoff signer does not authenticate the recovered transaction",
                    )
                })?;
            if resolved_signer != record.signer_id_v0() {
                return Err(G1ProcessHostErrorV0::new(
                    "admission.recovery.signer",
                    "durable handoff signer differs from node-owned canonical identity",
                ));
            }
            record
                .validate_transaction_v0(&transaction, resolved_signer)
                .map_err(|error| {
                    G1ProcessHostErrorV0::debug("admission.recovery.metadata", error)
                })?;
            if matched.replace((transaction, index)).is_some() {
                return Err(G1ProcessHostErrorV0::new(
                    "admission.recovery.ambiguous",
                    "the recovered digest occurs more than once in the committed block",
                ));
            }
        }
        let (transaction, index) = matched.ok_or_else(|| {
            G1ProcessHostErrorV0::new(
                "admission.recovery.ambiguous",
                "WAL handoff transaction is absent from the committed application block",
            )
        })?;
        let receipt_digest = read
            .receipt_commitments_v0()
            .get(index)
            .ok_or_else(|| {
                G1ProcessHostErrorV0::new(
                    "admission.recovery.receipt",
                    "recovered transaction has no durable receipt commitment",
                )
            })?
            .as_bytes();
        let parent_timestamp_ms =
            authenticated_parent_timestamp_for_execution_v0(application, execution)?;
        let config = application.config_v0();
        let proof = signed_finality_proof_for_execution_v0(
            execution,
            config.validator_set_v0(),
            config.consensus_parameters_v0(),
            parent_timestamp_ms,
        )?;
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new(*execution.block_id().as_bytes()),
            Height::new(execution.height().get()),
            ConsensusStateRoot::new(*execution.expected().post_state_root().as_bytes()),
            *receipt_digest,
            *proof.id().as_bytes(),
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("admission.recovery.evidence", error))?;
        boundary
            .recover_handed_off_with_native_readback(
                &transaction,
                evidence,
                application,
                &proof,
                parent_timestamp_ms,
            )
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.recovery.commit", error))?;
        if !boundary
            .handed_off_records_v0()
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.recovery.confirm", error))?
            .is_empty()
        {
            return Err(G1ProcessHostErrorV0::new(
                "admission.recovery.incomplete",
                "durable handoff inventory remained non-empty after authenticated recovery",
            ));
        }
        Ok(())
    }

    pub const fn generation_v0(&self) -> u64 {
        self.generation
    }

    pub fn submit_hex(
        &mut self,
        generation: u64,
        tx_hex: &str,
    ) -> Result<G1IngressResponseV0, G1ProcessHostErrorV0> {
        if generation != self.generation.saturating_add(1) {
            self.rejected = self.rejected.saturating_add(1);
            return Ok(G1IngressResponseV0::rejected(
                "stale_generation",
                self.queue.len(),
                self.accepted,
                self.rejected,
                self.backpressure_rejected,
                self.generation,
            ));
        }
        if self.queue.len() >= G1_PROCESS_HOST_QUEUE_CAPACITY_V0 {
            self.rejected = self.rejected.saturating_add(1);
            self.backpressure_rejected = self.backpressure_rejected.saturating_add(1);
            return Ok(G1IngressResponseV0::rejected(
                "backpressure",
                self.queue.len(),
                self.accepted,
                self.rejected,
                self.backpressure_rejected,
                self.generation,
            ));
        }
        // Hex/outer-shape failures happen before the durable handoff.  Keep
        // them request-scoped so one malformed ingress cannot take down the
        // process; errors after `handoff` remain fatal and preserve the WAL
        // ambiguity boundary.
        // Preserve the specific pre-handoff error code.  `run_stdio_v0` uses
        // this boundary to turn malformed/oversized ingress into a normal
        // request rejection; collapsing `ingress.hex` and
        // `ingress.too_large` into a generic decode code would make the
        // machine-visible contract lie about which bound fired.
        let bytes = decode_hex_v0(tx_hex)?;
        let transaction = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&bytes)
            .map_err(|error| G1ProcessHostErrorV0::debug("ingress.decode", error))?;
        self.queue.push_back(());
        let result = self.execute_one_v0(generation, transaction);
        let _ = self.queue.pop_front();
        match result {
            Ok(response) if response.status == "committed_candidate" => {
                self.generation = generation;
                self.accepted = self.accepted.saturating_add(1);
                Ok(response)
            }
            Ok(response) => Ok(response),
            Err(error) => {
                // An error after `handoff` leaves the durable row ambiguous;
                // terminate the process instead of attempting a release.
                Err(error)
            }
        }
    }

    fn execute_one_v0(
        &mut self,
        generation: u64,
        transaction: BuiltCanonicalTxV0,
    ) -> Result<G1IngressResponseV0, G1ProcessHostErrorV0> {
        let outcome = self
            .boundary
            .check_tx_candidate_with_authorities(&transaction, IngressClass::Normal);
        if outcome != TypedAdmitOutcome::Accepted {
            self.rejected = self.rejected.saturating_add(1);
            return Ok(G1IngressResponseV0::rejected(
                admission_reject_reason_v0(outcome),
                self.queue.len(),
                self.accepted,
                self.rejected,
                self.backpressure_rejected,
                self.generation,
            ));
        }
        let mut admission = self.boundary.pop_ready_with_lifecycle().ok_or_else(|| {
            G1ProcessHostErrorV0::new("admission.ready", "accepted CheckTx had no ready item")
        })?;
        admission
            .handoff()
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.handoff", error))?;
        // Test-only pause: an external harness can SIGKILL this process at
        // the exact durable WAL handoff boundary.  No production path sets
        // this environment variable; if it is set, the host intentionally
        // remains parked until the harness kills it.
        pause_for_sigkill_marker_v0(FAILPOINT_AFTER_HANDOFF_ENV_V0);

        let parent = self
            .application
            .confirmed_committed_head_v0()
            .map_err(|error| G1ProcessHostErrorV0::debug("application.parent", error))?;
        let height = parent
            .height()
            .checked_next()
            .map_err(|error| G1ProcessHostErrorV0::debug("application.height", error))?;
        let parent_timestamp_ms = self.last_timestamp_ms;
        let timestamp_ms = FIXTURE_BLOCK_TIMESTAMP_MS_V0.max(parent_timestamp_ms.saturating_add(1));
        let tx_bytes = vec![transaction.exact_outer_bytes().to_vec()];
        let config = self.application.config_v0();
        let chain_id = ChainIdV0::new(config.chain_id_v0().to_owned())
            .map_err(|error| G1ProcessHostErrorV0::debug("application.chain_id", error))?;
        let genesis_hash = GenesisHashV0::new(config.genesis_hash_v0())
            .map_err(|error| G1ProcessHostErrorV0::debug("application.genesis", error))?;
        let validator_set_id = ValidatorSetIdV0::new(*config.validator_set_v0().id().as_bytes())
            .map_err(|error| G1ProcessHostErrorV0::debug("application.validator_set", error))?;
        let preview_request = NativeBlockPreviewRequestV0::new(
            chain_id.clone(),
            genesis_hash,
            parent.clone(),
            height,
            timestamp_ms,
            validator_set_id,
            tx_bytes.clone(),
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("application.preview.request", error))?;
        let preview = self
            .application
            .preview_block_v0(&preview_request)
            .map_err(|error| G1ProcessHostErrorV0::debug("application.preview", error))?;
        // Use the consensus header's canonical id as the native block id.  A
        // separately invented hash would not be bindable to a FinalityProof.
        let consensus_header = consensus_header_for_execution_v0(
            &parent,
            &preview,
            config.validator_set_v0(),
            config.consensus_parameters_v0(),
            height.get(),
            timestamp_ms,
        )?;
        let block_id =
            trnm_native_application::BlockIdV0::new(*consensus_header.id().as_bytes())
                .map_err(|error| G1ProcessHostErrorV0::debug("application.block_id", error))?;
        let expected = NativeExpectedBlockCommitmentsV0::new(
            preview.payload_root(),
            preview.post_state_root(),
            preview.receipts_root(),
            preview.evidence_root(),
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("application.commitments", error))?;
        let execution = NativeBlockExecutionRequestV0::new(
            chain_id,
            genesis_hash,
            parent,
            block_id,
            height,
            timestamp_ms,
            validator_set_id,
            tx_bytes,
            expected,
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("application.execution.request", error))?;
        let executed = match self
            .application
            .execute_block(execution.clone())
            .map_err(|error| G1ProcessHostErrorV0::debug("application.execute", error))?
        {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            NativeBlockExecutionResultV0::DeterministicallyInvalid(value) => {
                return Err(G1ProcessHostErrorV0::new(
                    "application.deterministic_invalid",
                    value.code(),
                ));
            }
            NativeBlockExecutionResultV0::Unavailable(value) => {
                return Err(G1ProcessHostErrorV0::debug(
                    "application.unavailable",
                    value.reason(),
                ));
            }
        };
        let receipt_digest = executed
            .receipts()
            .first()
            .ok_or_else(|| G1ProcessHostErrorV0::new("application.receipt", "missing receipt"))?
            .commitment();
        // Authenticate the fixture three-chain before mutating durable D.  A
        // plain `commit_block` would prove only local execution; the
        // finalized adapter checks the exact header/proof binding and keeps a
        // malformed proof from leaving a committed application row behind.
        let finality_proof = signed_finality_proof_for_execution_v0(
            &execution,
            config.validator_set_v0(),
            config.consensus_parameters_v0(),
            parent_timestamp_ms,
        )?;
        self.application
            .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                executed.clone(),
                finality_proof.clone(),
                parent_timestamp_ms,
            ))
            .map_err(|error| G1ProcessHostErrorV0::debug("application.commit", error))?;
        // This second test-only pause covers response-loss after durable P/D
        // commit but before the admission WAL receipt transition.  Restart
        // recovery may resolve it only through the exact app/proof join.
        pause_for_sigkill_marker_v0(FAILPOINT_AFTER_APPLICATION_COMMIT_ENV_V0);
        let read = self
            .application
            .read_finalized_by_block_id_v0(block_id)
            .map_err(|error| G1ProcessHostErrorV0::debug("application.readback", error))?;
        let head = read
            .finalized_head_v0()
            .map_err(|error| G1ProcessHostErrorV0::debug("application.head", error))?;
        if head.height() != height
            || head.block_id().as_bytes() != block_id.as_bytes()
            || head.state_root() != expected.post_state_root()
            || read.receipt_commitments_v0().first().copied()
                != Some(trnm_native_application::Hash32V0::new(
                    *receipt_digest.as_bytes(),
                ))
        {
            return Err(G1ProcessHostErrorV0::new(
                "application.binding",
                "fresh native head/readback does not match executed request",
            ));
        }
        // The same proof is carried into the WAL receipt verifier.  This is
        // fixture evidence only: the host has no Core, network, or production
        // finality authority, so the response keeps `finality_verified=false`.
        // A local release after handoff is never attempted.
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new(*block_id.as_bytes()),
            Height::new(height.get()),
            ConsensusStateRoot::new(*expected.post_state_root().as_bytes()),
            *receipt_digest.as_bytes(),
            *finality_proof.id().as_bytes(),
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("admission.evidence", error))?;
        self.boundary
            .commit_candidate_with_native_readback(
                &mut admission,
                &transaction,
                evidence,
                &self.application,
                &finality_proof,
                parent_timestamp_ms,
            )
            .map_err(|error| G1ProcessHostErrorV0::debug("admission.commit", error))?;
        self.final_height = head.height().get();
        self.final_state_root_nonzero = head.state_root().as_bytes() != &[0; 32];
        self.last_timestamp_ms = timestamp_ms;
        Ok(G1IngressResponseV0 {
            status: "committed_candidate",
            reason: Some("candidate_fixture_finality_only"),
            generation: Some(generation),
            height: Some(head.height().get()),
            block_id: Some(hex::encode(head.block_id().as_bytes())),
            state_root: Some(hex::encode(head.state_root().as_bytes())),
            receipt_digest: Some(hex::encode(receipt_digest.as_bytes())),
            // The synchronous candidate driver removes this request
            // immediately after assembling the response.
            queue_depth: self.queue.len().saturating_sub(1),
            queue_capacity: G1_PROCESS_HOST_QUEUE_CAPACITY_V0,
            accepted: self.accepted.saturating_add(1),
            rejected: self.rejected,
            backpressure_rejected: self.backpressure_rejected,
            pacemaker_generation: generation,
            production_candidate: false,
            finality_verified: false,
        })
    }

    pub fn summary_v0(&self) -> G1ProcessHostSummaryV0 {
        G1ProcessHostSummaryV0 {
            accepted: self.accepted,
            rejected: self.rejected,
            backpressure_rejected: self.backpressure_rejected,
            final_generation: self.generation,
            final_height: self.final_height,
            final_state_root_nonzero: self.final_state_root_nonzero,
            production_candidate: false,
            finality_verified: false,
        }
    }
}

/// Run the bounded newline protocol over an arbitrary reader/writer. This is
/// the API used by the real binary and by the subprocess integration test.
pub fn run_stdio_v0<R: Read, W: Write>(
    run_root: impl AsRef<Path>,
    mut reader: R,
    mut writer: W,
) -> Result<G1ProcessHostSummaryV0, G1ProcessHostErrorV0> {
    let mut host = G1ProcessHostV0::open(run_root)?;
    let mut frame = Vec::new();
    loop {
        match read_frame_bounded_v0(&mut reader, &mut frame)? {
            None => break,
            Some(FrameReadV0::TooLarge) => {
                host.rejected = host.rejected.saturating_add(1);
                let response = G1IngressResponseV0::rejected(
                    "frame_too_large",
                    host.queue.len(),
                    host.accepted,
                    host.rejected,
                    host.backpressure_rejected,
                    host.generation,
                );
                write_response_v0(&mut writer, &response)?;
            }
            Some(FrameReadV0::Complete) => {
                // Apply the same bounded duplicate/depth/field policy used
                // for transaction envelopes before deserializing the control
                // request.  Otherwise serde's last-key-wins behaviour could
                // make a duplicated `op`/`generation` field act on a value
                // different from the bytes that were authenticated/logged.
                let request_result: Result<G1IngressRequestV0, ()> =
                    if validate_strict_json_structure_v0(&frame).is_err() {
                        Err(())
                    } else {
                        serde_json::from_slice(&frame).map_err(|_| ())
                    };
                let request: G1IngressRequestV0 = match request_result {
                    Ok(value) => value,
                    Err(_) => {
                        host.rejected = host.rejected.saturating_add(1);
                        let response = G1IngressResponseV0::rejected(
                            "malformed_json",
                            host.queue.len(),
                            host.accepted,
                            host.rejected,
                            host.backpressure_rejected,
                            host.generation,
                        );
                        write_response_v0(&mut writer, &response)?;
                        continue;
                    }
                };
                match request {
                    G1IngressRequestV0::Shutdown => break,
                    G1IngressRequestV0::Submit { generation, tx_hex } => {
                        match host.submit_hex(generation, &tx_hex) {
                            Ok(response) => write_response_v0(&mut writer, &response)?,
                            Err(error) => {
                                // Decode/shape failures are per-request
                                // rejections. A post-handoff failure returns
                                // an error and ends the process, preserving the
                                // ambiguous durable WAL state.
                                if matches!(
                                    error.code_v0(),
                                    // These failures happen before the durable
                                    // handoff. Keep them request-scoped so a
                                    // malformed/oversized hex value cannot
                                    // terminate the host or strand a WAL row.
                                    "ingress.decode" | "ingress.hex" | "ingress.too_large"
                                ) {
                                    host.rejected = host.rejected.saturating_add(1);
                                    let response = G1IngressResponseV0::rejected(
                                        "invalid_transaction",
                                        host.queue.len(),
                                        host.accepted,
                                        host.rejected,
                                        host.backpressure_rejected,
                                        host.generation,
                                    );
                                    write_response_v0(&mut writer, &response)?;
                                } else {
                                    return Err(error);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    writer.flush()?;
    Ok(host.summary_v0())
}

fn write_response_v0<W: Write>(
    writer: &mut W,
    response: &G1IngressResponseV0,
) -> Result<(), G1ProcessHostErrorV0> {
    serde_json::to_writer(&mut *writer, response)
        .map_err(|error| G1ProcessHostErrorV0::debug("response.encode", error))?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn pause_for_sigkill_marker_v0(environment: &str) {
    let Some(marker) = std::env::var_os(environment).map(std::path::PathBuf::from) else {
        return;
    };
    if !marker.is_absolute() {
        return;
    }
    let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    else {
        return;
    };
    if file.write_all(b"ready\n").is_err() || file.sync_all().is_err() {
        return;
    }
    loop {
        thread::sleep(Duration::from_millis(10));
    }
}

enum FrameReadV0 {
    Complete,
    TooLarge,
}

fn read_frame_bounded_v0<R: Read>(
    reader: &mut R,
    frame: &mut Vec<u8>,
) -> io::Result<Option<FrameReadV0>> {
    frame.clear();
    let mut one = [0_u8; 1];
    let mut oversized = false;
    loop {
        match reader.read(&mut one) {
            Ok(0) => {
                if frame.is_empty() && !oversized {
                    return Ok(None);
                }
                return Ok(Some(if oversized {
                    FrameReadV0::TooLarge
                } else {
                    FrameReadV0::Complete
                }));
            }
            Ok(1) => {
                if one[0] == b'\n' {
                    return Ok(Some(if oversized {
                        FrameReadV0::TooLarge
                    } else {
                        FrameReadV0::Complete
                    }));
                }
                if !oversized {
                    if frame.len() >= G1_PROCESS_HOST_MAX_FRAME_BYTES_V0 {
                        oversized = true;
                    } else {
                        frame.push(one[0]);
                    }
                }
            }
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn decode_hex_v0(value: &str) -> Result<Vec<u8>, G1ProcessHostErrorV0> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(G1ProcessHostErrorV0::new(
            "ingress.hex",
            "hex is empty or odd length",
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| G1ProcessHostErrorV0::new("ingress.hex", "hex is not canonical"))?;
    if hex::encode(&bytes) != value {
        return Err(G1ProcessHostErrorV0::new(
            "ingress.hex",
            "hex is not lowercase canonical",
        ));
    }
    if bytes.len() > G1_PROCESS_HOST_MAX_FRAME_BYTES_V0 {
        return Err(G1ProcessHostErrorV0::new(
            "ingress.too_large",
            "transaction exceeds frame bound",
        ));
    }
    Ok(bytes)
}

fn validate_run_root_v0(path: &Path) -> Result<(), G1ProcessHostErrorV0> {
    if !path.is_absolute() {
        return Err(G1ProcessHostErrorV0::new(
            "root.path",
            "run root must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| G1ProcessHostErrorV0::debug("root.stat", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(G1ProcessHostErrorV0::new(
            "root.path",
            "run root must be a real directory",
        ));
    }
    Ok(())
}

fn consensus_header_for_execution_v0(
    parent: &trnm_native_application::ApplicationHeadV0,
    preview: &NativeBlockPreviewV0,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    height: u64,
    timestamp_ms: u64,
) -> Result<BlockHeader, G1ProcessHostErrorV0> {
    let validator_count = validator_set.validators().len();
    if validator_count == 0 || height == 0 {
        return Err(G1ProcessHostErrorV0::new(
            "application.header",
            "candidate header has no validator or non-genesis height",
        ));
    }
    parameters
        .validate_safety_invariants()
        .map_err(|error| G1ProcessHostErrorV0::debug("application.parameters", error))?;
    if parameters.hash() != validator_set.consensus_parameters_hash() {
        return Err(G1ProcessHostErrorV0::new(
            "application.parameters",
            "validator set and consensus parameters are not bound",
        ));
    }
    BlockHeader::new(
        validator_set.genesis_hash(),
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        View::new(height),
        Height::new(height),
        BlockKind::Regular,
        BlockId::new(*parent.block_id().as_bytes()),
        validator_set.validators()[(height.saturating_sub(1) as usize) % validator_count].id(),
        validator_set.id(),
        validator_set.consensus_parameters_hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        ConsensusStateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        timestamp_ms,
        None,
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("application.header", error))
}

fn authenticated_parent_timestamp_for_execution_v0(
    application: &DurableNativeApplicationV0,
    execution: &NativeBlockExecutionRequestV0,
) -> Result<u64, G1ProcessHostErrorV0> {
    let height = execution.height().get();
    if height == 1 {
        if execution.parent().height().get() != 0 {
            return Err(G1ProcessHostErrorV0::new(
                "admission.recovery.parent",
                "h1 execution parent is not genesis",
            ));
        }
        return Ok(FIXTURE_PARENT_TIMESTAMP_MS_V0);
    }
    let parent_height = height.checked_sub(1).ok_or_else(|| {
        G1ProcessHostErrorV0::new("admission.recovery.parent", "parent height underflow")
    })?;
    let parent = application
        .read_finalized_by_height_v0(trnm_native_application::HeightV0::new(parent_height))
        .map_err(|error| {
            G1ProcessHostErrorV0::debug("admission.recovery.parent_readback", error)
        })?;
    let parent_head = parent
        .finalized_head_v0()
        .map_err(|error| G1ProcessHostErrorV0::debug("admission.recovery.parent_head", error))?;
    if execution.parent().height() != parent_head.height()
        || execution.parent().block_id() != parent_head.block_id()
        || execution.parent().state_root() != parent_head.state_root()
    {
        return Err(G1ProcessHostErrorV0::new(
            "admission.recovery.parent",
            "execution parent does not match the authenticated prior application head",
        ));
    }
    Ok(parent.executed_v0().request().timestamp_ms())
}

/// Construct and immediately verify a deterministic three-chain for the
/// exact native execution header.  This helper is deliberately local to the
/// candidate process fixture: it proves that the receipt adapter consumes
/// authenticated PoCO objects, but it is not a Core vote/effect driver and
/// cannot change any production activation flag.
fn signed_finality_proof_for_execution_v0(
    execution: &NativeBlockExecutionRequestV0,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    authenticated_parent_timestamp_ms: u64,
) -> Result<FinalityProofV0, G1ProcessHostErrorV0> {
    fn validator_key_v0(index: usize) -> SigningKey {
        // application_config_v0 uses seeds 41..44 in validator order.
        SigningKey::from_bytes(&[41_u8.saturating_add(index as u8); 32])
    }

    fn signed_qc_for_coordinates_v0(
        validator_set: &ValidatorSet,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Result<QuorumCertificate, G1ProcessHostErrorV0> {
        let root = Vote::signing_root_for_set(validator_set, view, height, block_id)
            .map_err(|error| G1ProcessHostErrorV0::debug("finality.vote_root", error))?;
        let votes = validator_set
            .validators()
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, validator)| {
                let signature = SignatureBytes::from_array(
                    validator_key_v0(index).sign(root.as_bytes()).to_bytes(),
                );
                Vote::new(
                    validator_set.chain_id(),
                    validator_set.protocol_version(),
                    validator_set.epoch(),
                    view,
                    height,
                    block_id,
                    validator_set.id(),
                    validator.id(),
                    signature,
                    validator_set,
                )
                .map_err(|error| G1ProcessHostErrorV0::debug("finality.vote", error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        QuorumCertificate::new(
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            view,
            height,
            block_id,
            validator_set.id(),
            votes,
            validator_set,
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("finality.qc", error))
    }

    fn certified_v0(
        header: BlockHeader,
        justify: QcReferenceV0,
        qc: QuorumCertificate,
        validator_set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        parent_timestamp_ms: u64,
    ) -> Result<CertifiedHeaderV0, G1ProcessHostErrorV0> {
        let root = trnm_consensus_types::ProposalWitnessV0::signing_root_for(
            &header, &justify, None, None,
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("finality.proposal_root", error))?;
        let proposer_index = validator_set
            .validators()
            .iter()
            .position(|validator| validator.id() == header.proposer_id())
            .ok_or_else(|| {
                G1ProcessHostErrorV0::new("finality.proposer", "header proposer is not in set")
            })?;
        let signature = Signature64::from_array(
            validator_key_v0(proposer_index)
                .sign(root.as_bytes())
                .to_bytes(),
        );
        CertifiedHeaderV0::new(
            header,
            justify,
            None,
            None,
            signature,
            qc,
            validator_set,
            None,
            parameters,
            parent_timestamp_ms,
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("finality.certified", error))
    }

    let first_height = execution.height().get();
    let first_view = View::new(first_height);
    let expected = execution.expected();
    let h1 = BlockHeader::new(
        validator_set.genesis_hash(),
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        first_view,
        Height::new(first_height),
        BlockKind::Regular,
        BlockId::new(*execution.parent().block_id().as_bytes()),
        validator_set.validators()
            [(first_height.saturating_sub(1) as usize) % validator_set.validators().len()]
        .id(),
        validator_set.id(),
        validator_set.consensus_parameters_hash(),
        PayloadDigest::new(*expected.payload_root().as_bytes()),
        ConsensusStateRoot::new(*expected.post_state_root().as_bytes()),
        ReceiptsRoot::new(*expected.receipts_root().as_bytes()),
        EvidenceRoot::new(*expected.evidence_root().as_bytes()),
        execution.timestamp_ms(),
        None,
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("finality.h1", error))?;
    let h1_id = h1.id();
    if h1_id.as_bytes() != execution.block_id().as_bytes() {
        return Err(G1ProcessHostErrorV0::new(
            "finality.h1_binding",
            "execution block id differs from canonical consensus header id",
        ));
    }
    let q1 =
        signed_qc_for_coordinates_v0(validator_set, first_view, Height::new(first_height), h1_id)?;
    let justify_1 = if first_height == 1 {
        QcReferenceV0::genesis_anchor(
            GenesisQcV0::new(
                validator_set.genesis_hash(),
                validator_set.chain_id(),
                validator_set,
            )
            .map_err(|error| G1ProcessHostErrorV0::debug("finality.genesis_qc", error))?,
        )
    } else {
        let parent_view = View::new(
            first_height
                .checked_sub(1)
                .ok_or_else(|| G1ProcessHostErrorV0::new("finality.parent_view", "underflow"))?,
        );
        let parent_height = execution.parent().height();
        let parent_id = BlockId::new(*execution.parent().block_id().as_bytes());
        QcReferenceV0::ordinary(signed_qc_for_coordinates_v0(
            validator_set,
            parent_view,
            Height::new(parent_height.get()),
            parent_id,
        )?)
    };
    let c1 = certified_v0(
        h1.clone(),
        justify_1,
        q1.clone(),
        validator_set,
        parameters,
        authenticated_parent_timestamp_ms,
    )?;

    let h2_height = first_height
        .checked_add(1)
        .ok_or_else(|| G1ProcessHostErrorV0::new("finality.h2_height", "height overflow"))?;
    let h2 = BlockHeader::new(
        validator_set.genesis_hash(),
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        View::new(
            first_height
                .checked_add(1)
                .ok_or_else(|| G1ProcessHostErrorV0::new("finality.h2_view", "view overflow"))?,
        ),
        Height::new(h2_height),
        BlockKind::Regular,
        h1_id,
        validator_set.validators()[(first_height as usize) % validator_set.validators().len()].id(),
        validator_set.id(),
        validator_set.consensus_parameters_hash(),
        PayloadDigest::new([0x61; 32]),
        ConsensusStateRoot::new([0x62; 32]),
        ReceiptsRoot::new([0x63; 32]),
        EvidenceRoot::new([0x64; 32]),
        execution.timestamp_ms().checked_add(1).ok_or_else(|| {
            G1ProcessHostErrorV0::new("finality.h2_timestamp", "timestamp overflow")
        })?,
        None,
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("finality.h2", error))?;
    let q2 = signed_qc_for_coordinates_v0(validator_set, h2.view(), h2.height(), h2.id())?;
    let c2 = certified_v0(
        h2.clone(),
        QcReferenceV0::ordinary(q1),
        q2.clone(),
        validator_set,
        parameters,
        execution.timestamp_ms(),
    )?;

    let h3_height = h2_height
        .checked_add(1)
        .ok_or_else(|| G1ProcessHostErrorV0::new("finality.h3_height", "height overflow"))?;
    let h3 = BlockHeader::new(
        validator_set.genesis_hash(),
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        View::new(
            first_height
                .checked_add(2)
                .ok_or_else(|| G1ProcessHostErrorV0::new("finality.h3_view", "view overflow"))?,
        ),
        Height::new(h3_height),
        BlockKind::Regular,
        h2.id(),
        validator_set.validators()
            [((first_height as usize).saturating_add(1)) % validator_set.validators().len()]
        .id(),
        validator_set.id(),
        validator_set.consensus_parameters_hash(),
        PayloadDigest::new([0x71; 32]),
        ConsensusStateRoot::new([0x72; 32]),
        ReceiptsRoot::new([0x73; 32]),
        EvidenceRoot::new([0x74; 32]),
        execution.timestamp_ms().checked_add(2).ok_or_else(|| {
            G1ProcessHostErrorV0::new("finality.h3_timestamp", "timestamp overflow")
        })?,
        None,
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("finality.h3", error))?;
    let q3 = signed_qc_for_coordinates_v0(validator_set, h3.view(), h3.height(), h3.id())?;
    let c3 = certified_v0(
        h3,
        QcReferenceV0::ordinary(q2),
        q3,
        validator_set,
        parameters,
        execution.timestamp_ms().checked_add(1).ok_or_else(|| {
            G1ProcessHostErrorV0::new("finality.h3_parent_timestamp", "timestamp overflow")
        })?,
    )?;
    let proof = FinalityProofV0::new(
        c1,
        c2,
        c3,
        validator_set,
        None,
        parameters,
        authenticated_parent_timestamp_ms,
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("finality.proof", error))?;
    proof
        .verify(
            validator_set,
            None,
            parameters,
            authenticated_parent_timestamp_ms,
            &StrictEd25519Verifier,
        )
        .map_err(|error| G1ProcessHostErrorV0::debug("finality.verify", error))?;
    Ok(proof)
}

fn application_config_v0() -> Result<NativeApplicationConfigV0, G1ProcessHostErrorV0> {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let validators = (1_u8..=4)
        .map(|index| {
            let key = SigningKey::from_bytes(&[index.saturating_add(40); 32]);
            Validator::new(
                ValidatorId::new([index; 32]),
                ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                VotingPower::new(1)
                    .map_err(|error| G1ProcessHostErrorV0::debug("fixture.power", error))?,
            )
            .map_err(|error| G1ProcessHostErrorV0::debug("fixture.validator", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let validator_set = ValidatorSet::new(
        GenesisHash::new(GENESIS_HASH_BYTES_V0),
        ChainId::new(G1_PROCESS_HOST_CHAIN_ID_V0)
            .map_err(|error| G1ProcessHostErrorV0::debug("fixture.chain", error))?,
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("fixture.validator_set", error))?;
    let operator_key = SigningKey::from_bytes(&OPERATOR_KEY_BYTES_V0);
    let signer = AuthorizedSignerV0::new(
        OPERATOR_SIGNER_ID_V0,
        OPERATOR_SIGNER_ROLE_V0,
        public_key_hex(&operator_key),
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("fixture.signer", error))?;
    let inputs = CanonicalLabNativeApplicationConfigInputsV0::new(
        "g1-process-host-001",
        [0xD1; 32],
        [0xD2; 32],
        [0xD3; 32],
        [0xD4; 32],
        validator_set.validators()[0].id(),
        validator_set,
        parameters,
        vec![signer],
        OPERATOR_SIGNER_ID_V0,
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("fixture.inputs", error))?;
    NativeApplicationConfigV0::from_canonical_lab_inputs_v0(inputs)
        .map_err(|error| G1ProcessHostErrorV0::debug("fixture.config", error))
}

fn genesis_request_v0(
    config: &NativeApplicationConfigV0,
) -> Result<NativeApplicationGenesisRequestV0, G1ProcessHostErrorV0> {
    NativeApplicationGenesisRequestV0::new(
        ChainIdV0::new(config.chain_id_v0().to_owned())
            .map_err(|error| G1ProcessHostErrorV0::debug("genesis.chain", error))?,
        GenesisHashV0::new(config.genesis_hash_v0())
            .map_err(|error| G1ProcessHostErrorV0::debug("genesis.hash", error))?,
        trnm_native_application::Hash32V0::new(config.chain_descriptor_hash_v0()),
        trnm_native_application::Hash32V0::new(config.signer_policy_commitment_v0()),
        trnm_native_application::StateRootV0::new(config.initial_state_root())
            .map_err(|error| G1ProcessHostErrorV0::debug("genesis.root", error))?,
        config.initial_validator_set().clone(),
    )
    .map_err(|error| G1ProcessHostErrorV0::debug("genesis.request", error))
}

fn admission_reject_reason_v0(outcome: TypedAdmitOutcome) -> &'static str {
    match outcome {
        TypedAdmitOutcome::Rejected(AdmissionReject::Replay) => "replay",
        TypedAdmitOutcome::Rejected(AdmissionReject::SignatureRejected) => "signature_rejected",
        TypedAdmitOutcome::Rejected(AdmissionReject::SignerIdentityUnavailable) => {
            "signer_identity_unavailable"
        }
        TypedAdmitOutcome::Rejected(AdmissionReject::RecheckUnavailable) => "recheck_unavailable",
        TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalValidationFailed) => {
            "canonical_validation_failed"
        }
        TypedAdmitOutcome::Rejected(AdmissionReject::InconsistentState) => "inconsistent_state",
        TypedAdmitOutcome::Rejected(_) => "admission_rejected",
        TypedAdmitOutcome::Duplicate => "replay",
        TypedAdmitOutcome::Backpressured => "backpressure",
        TypedAdmitOutcome::Accepted => "accepted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decoder_keeps_pre_handoff_error_identity() {
        let empty = decode_hex_v0("").expect_err("empty hex must reject");
        assert_eq!(empty.code_v0(), "ingress.hex");

        let odd = decode_hex_v0("a").expect_err("odd hex must reject");
        assert_eq!(odd.code_v0(), "ingress.hex");

        let uppercase = decode_hex_v0("AA").expect_err("uppercase hex must reject");
        assert_eq!(uppercase.code_v0(), "ingress.hex");

        let oversized = decode_hex_v0(&"aa".repeat(G1_PROCESS_HOST_MAX_FRAME_BYTES_V0 + 1))
            .expect_err("oversized decoded bytes must reject");
        assert_eq!(oversized.code_v0(), "ingress.too_large");
    }
}
