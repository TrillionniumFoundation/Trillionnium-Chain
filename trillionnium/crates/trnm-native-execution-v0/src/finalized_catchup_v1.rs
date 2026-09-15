//! Proof-driven, resumable native application catch-up.
//!
//! Every new block is strictly authenticated before the existing deterministic
//! preview, durable execution and finality commit. Nonces and command replay
//! sets are reconstructed by execution, never imported from a peer snapshot.
//! A completed session can release its real application owner only after the
//! downloaded native snapshot exactly matches that reconstructed image.
//!
//! This is bounded *per-session* application catch-up, not a new consensus
//! engine, signing/recovery authority, checkpoint shortcut or bounded-history
//! storage algorithm. The existing whole-history audits remain in use.

mod stream;
pub use stream::{
    write_native_catchup_stream_v1, NativeCatchupBlockV1, NativeCatchupStreamErrorV1,
    NativeCatchupStreamLimitsV1,
};

use std::{error::Error, fmt, io};

use trnm_consensus_crypto::{
    decode_verify_finality_proof_strict_v0, FinalityExpectationV0, StrictFinalityErrorV0,
    StrictFinalityProofV0, POCO_THREE_CHAIN_PROOF_CLASS_V0,
};
use trnm_consensus_types::{
    decode_application_payload_v0_exact, BlockHeader, BlockId, BlockKind, Cev0AdmissionBudgetV0,
    Height, View,
};
use trnm_native_application::{
    ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0,
    NativeApplicationV0, NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0,
    NativeExpectedBlockCommitmentsV0, NativeSnapshotManifestV0, ReceiptsRootV0, StateRootV0,
    ValidatorSetIdV0, MAX_BLOCK_BYTES_V0,
};

use crate::{
    verify_native_snapshot_stream_v1, DurableNativeApplicationV0,
    FinalizedNativeApplicationCommitRequestV0, NativeApplicationExecutionErrorV0,
    NativeBlockPreviewRequestV0, NativeSnapshotReadLimitsV1, NativeSnapshotStreamErrorV1,
    PocoFinalityCommitErrorV0,
};

/// Non-consensus limits. Exceeding them means local unavailability, not that a
/// transaction/block is Byzantine. Retry with a separately qualified session.
#[derive(Debug, Clone, Copy)]
pub struct NativeCatchupLimitsV1 {
    maximum_blocks: u64,
    maximum_input_bytes: u64,
    maximum_transactions: u32,
}
impl NativeCatchupLimitsV1 {
    pub fn new(
        maximum_blocks: u64,
        maximum_input_bytes: u64,
        maximum_transactions: u32,
    ) -> Result<Self, NativeCatchupErrorV1> {
        if maximum_blocks == 0
            || maximum_blocks > 4096
            || maximum_input_bytes == 0
            || maximum_input_bytes > 16 * 1024 * 1024 * 1024
            || maximum_transactions == 0
            || maximum_transactions > 65_536
        {
            return Err(NativeCatchupErrorV1::Limit);
        }
        Ok(Self {
            maximum_blocks,
            maximum_input_bytes,
            maximum_transactions,
        })
    }
}

#[derive(Debug)]
pub enum NativeCatchupErrorV1 {
    Limit,
    Context,
    NonContiguous,
    Body,
    ExecutionMismatch,
    CurrentProofRequired,
    SourceChanged,
    RecoveryRequired,
    Incomplete,
    SnapshotMismatch,
    Admission(StrictFinalityErrorV0),
    Finality(PocoFinalityCommitErrorV0),
    Application(NativeApplicationExecutionErrorV0),
    Snapshot(NativeSnapshotStreamErrorV1),
    /// A mutating API was called. The exact operation may already be durable.
    /// The live owner remains fenced; reopen and revalidate the actual head.
    Uncertain(NativeApplicationExecutionErrorV0),
}
impl fmt::Display for NativeCatchupErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(e) => write!(f, "catch-up proof rejected: {e}"),
            Self::Finality(e) => write!(f, "catch-up recovery proof failed: {e}"),
            Self::Application(e) => write!(f, "catch-up application unavailable: {e}"),
            Self::Snapshot(e) => write!(f, "catch-up snapshot rejected: {e}"),
            Self::Uncertain(e) => write!(f, "catch-up durable result uncertain; reopen: {e}"),
            other => write!(f, "native catch-up: {other:?}"),
        }
    }
}
impl Error for NativeCatchupErrorV1 {}

/// One completed application operation, not a Core or checkpoint receipt.
#[derive(Debug)]
pub struct NativeCatchupReceiptV1 {
    head: ApplicationHeadV0,
    proof_id: [u8; 32],
    replayed: bool,
}
impl NativeCatchupReceiptV1 {
    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn proof_id(&self) -> &[u8; 32] {
        &self.proof_id
    }
    /// Exact committed retry did no new execution, nonce change or commit.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// The actual, exclusively held application owner. This cannot sign, vote or
/// clear a Core fence. An unfinished/uncertain session exposes no owner escape.
///
/// ```compile_fail
/// use trnm_native_execution_v0::NativeFinalizedCatchupV1;
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<NativeFinalizedCatchupV1>();
/// ```
pub struct NativeFinalizedCatchupV1 {
    application: DurableNativeApplicationV0,
    target: StrictFinalityProofV0,
    head: ApplicationHeadV0,
    parent_timestamp_ms: u64,
    parent_view: View,
    genesis_timestamp_ms: u64,
    limits: NativeCatchupLimitsV1,
    attempted_bytes: u64,
    recovery_required: bool,
}

/// Reconstructed native state with exact downloaded-snapshot equality. This
/// releases only an application owner, never a consensus/signer activation.
pub struct RestoredNativeApplicationV1 {
    application: DurableNativeApplicationV0,
    head: ApplicationHeadV0,
    snapshot_digest: [u8; 32],
    finality_proof_id: [u8; 32],
}
impl RestoredNativeApplicationV1 {
    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
    pub const fn finality_proof_id(&self) -> &[u8; 32] {
        &self.finality_proof_id
    }
    pub fn into_application(self) -> DurableNativeApplicationV0 {
        self.application
    }
}

fn parent_timestamp(
    application: &DurableNativeApplicationV0,
    height: u64,
    genesis_timestamp_ms: u64,
) -> Result<u64, NativeCatchupErrorV1> {
    if height <= 1 {
        return Ok(genesis_timestamp_ms);
    }
    Ok(application
        .read_finalized_by_height_v0(HeightV0::new(height - 1))
        .map_err(NativeCatchupErrorV1::Application)?
        .executed_v0()
        .request()
        .timestamp_ms())
}

fn require_fresh_head_v1(
    application: &DurableNativeApplicationV0,
    expected: &ApplicationHeadV0,
    recovery_required: &mut bool,
) -> Result<(), NativeCatchupErrorV1> {
    match application.confirmed_committed_head_v0() {
        Ok(actual) if &actual == expected => Ok(()),
        Ok(_) => {
            *recovery_required = true;
            Err(NativeCatchupErrorV1::SourceChanged)
        }
        Err(error) => {
            // No write has happened in this check. Nevertheless, a live
            // recovered owner must not resume after observing an unavailable
            // or replaced authority without a complete fresh recovery.
            *recovery_required = true;
            Err(NativeCatchupErrorV1::Application(error))
        }
    }
}

impl NativeFinalizedCatchupV1 {
    /// `target` must originate in independent strict proof verification. The
    /// source manifest cannot choose its trust anchor/configuration. Genesis
    /// time is explicit operator/genesis input, not a field supplied per block.
    /// A non-genesis resume requires the current head's proof and rechecks it
    /// against locally recovered parent coordinates before accepting new work.
    ///
    /// This tranche deliberately supports ordinary epoch-zero replay only.
    /// Seals, new epochs and current imported h1 bases remain outside its scope.
    pub fn recover(
        application: DurableNativeApplicationV0,
        target: StrictFinalityProofV0,
        genesis_timestamp_ms: u64,
        current_proof_bytes: Option<&[u8]>,
        limits: NativeCatchupLimitsV1,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<Self, NativeCatchupErrorV1> {
        let config = application.config_v0();
        let set = config.validator_set_v0();
        let target_header = target.proof().finalized_block().header();
        if set.epoch().get() != 0
            || target_header.block_kind() != BlockKind::Regular
            || target_header.epoch() != set.epoch()
            || target_header.genesis_hash() != set.genesis_hash()
            || target_header.chain_id() != set.chain_id()
            || target_header.protocol_version() != set.protocol_version()
            || target_header.validator_set_id() != set.id()
            || target_header.consensus_parameters_hash() != config.consensus_parameters_v0().hash()
        {
            return Err(NativeCatchupErrorV1::Context);
        }
        let head = application
            .confirmed_committed_head_v0()
            .map_err(NativeCatchupErrorV1::Application)?;
        let distance = target_header
            .height()
            .get()
            .checked_sub(head.height().get())
            .ok_or(NativeCatchupErrorV1::NonContiguous)?;
        if distance > limits.maximum_blocks {
            return Err(NativeCatchupErrorV1::Limit);
        }
        if distance == 0
            && (head.block_id().as_bytes() != target_header.id().as_bytes()
                || head.state_root().as_bytes() != target_header.state_root().as_bytes())
        {
            return Err(NativeCatchupErrorV1::Context);
        }
        let (parent_timestamp_ms, parent_view) = if head.height().get() == 0 {
            if current_proof_bytes.is_some() {
                return Err(NativeCatchupErrorV1::Context);
            }
            (genesis_timestamp_ms, View::new(0))
        } else {
            let bytes = current_proof_bytes.ok_or(NativeCatchupErrorV1::CurrentProofRequired)?;
            if bytes.len() as u64 > limits.maximum_input_bytes {
                return Err(NativeCatchupErrorV1::Limit);
            }
            let read = application
                .read_poco_finalized_bytes_v0(
                    POCO_THREE_CHAIN_PROOF_CLASS_V0,
                    bytes,
                    head.height(),
                    parent_timestamp(&application, head.height().get(), genesis_timestamp_ms)?,
                    budget,
                )
                .map_err(NativeCatchupErrorV1::Finality)?;
            let header = read.finality().proof().finalized_block().header();
            if read
                .application()
                .finalized_head_v0()
                .map_err(NativeCatchupErrorV1::Application)?
                != head
            {
                return Err(NativeCatchupErrorV1::SourceChanged);
            }
            budget
                .charge_finality_proof(read.finality().proof())
                .map_err(|e| NativeCatchupErrorV1::Admission(StrictFinalityErrorV0::Decode(e)))?;
            let committed = application
                .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                    read.application().executed_v0().clone(),
                    read.finality().proof().clone(),
                    parent_timestamp(&application, head.height().get(), genesis_timestamp_ms)?,
                ))
                .map_err(NativeCatchupErrorV1::Uncertain)?;
            if committed.head() != &head {
                return Err(NativeCatchupErrorV1::SourceChanged);
            }
            (header.timestamp_ms(), header.view())
        };
        Ok(Self {
            application,
            target,
            head,
            parent_timestamp_ms,
            parent_view,
            genesis_timestamp_ms,
            limits,
            attempted_bytes: current_proof_bytes.map_or(0, |bytes| bytes.len() as u64),
            recovery_required: false,
        })
    }

    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn recovery_required(&self) -> bool {
        self.recovery_required
    }

    /// Strict proof and read-only preview precede *all* execution/commit calls.
    /// Malformed input and local budgets cannot append a prepared row. Once a
    /// mutating API is invoked, any error makes recovery mandatory. A crash
    /// after P or commit is resolved by reopening, proving the recovered head,
    /// and retrying the identical block, not by deleting stores or rewriting
    /// replay floors. Inputs carry no local commit ID.
    pub fn apply(
        &mut self,
        header: &BlockHeader,
        payload_bytes: &[u8],
        proof_bytes: &[u8],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<NativeCatchupReceiptV1, NativeCatchupErrorV1> {
        if self.recovery_required {
            return Err(NativeCatchupErrorV1::RecoveryRequired);
        }
        let next_bytes = self
            .attempted_bytes
            .checked_add(payload_bytes.len() as u64)
            .and_then(|n| n.checked_add(proof_bytes.len() as u64))
            .ok_or(NativeCatchupErrorV1::Limit)?;
        if next_bytes > self.limits.maximum_input_bytes || payload_bytes.len() > MAX_BLOCK_BYTES_V0
        {
            return Err(NativeCatchupErrorV1::Limit);
        }
        // Rejected work is charged too. Limits do not alter validity semantics.
        self.attempted_bytes = next_bytes;
        let config = self.application.config_v0();
        let set = config.validator_set_v0();
        if header.block_kind() != BlockKind::Regular
            || header.epoch() != set.epoch()
            || header.validator_set_id() != set.id()
            || header.consensus_parameters_hash() != config.consensus_parameters_v0().hash()
            || header.genesis_hash() != set.genesis_hash()
            || header.chain_id() != set.chain_id()
            || header.protocol_version() != set.protocol_version()
        {
            return Err(NativeCatchupErrorV1::Context);
        }
        let target = self.target.proof().finalized_block().header();
        if header.height() > target.height() {
            return Err(NativeCatchupErrorV1::NonContiguous);
        }
        if header.height() == target.height() && header != target {
            return Err(NativeCatchupErrorV1::Context);
        }
        let count = payload_bytes.get(..4).ok_or(NativeCatchupErrorV1::Body)?;
        if u32::from_be_bytes(count.try_into().map_err(|_| NativeCatchupErrorV1::Body)?)
            > self.limits.maximum_transactions
        {
            return Err(NativeCatchupErrorV1::Limit);
        }
        let payload =
            decode_application_payload_v0_exact(payload_bytes, config.consensus_parameters_v0())
                .map_err(|_| NativeCatchupErrorV1::Body)?;
        if payload.transaction_count() > self.limits.maximum_transactions {
            return Err(NativeCatchupErrorV1::Limit);
        }
        if payload
            .payload_root()
            .map_err(|_| NativeCatchupErrorV1::Body)?
            != header.payload_root()
        {
            return Err(NativeCatchupErrorV1::Body);
        }
        if header.height().get() == self.head.height().get() {
            if header.id().as_bytes() != self.head.block_id().as_bytes() {
                return Err(NativeCatchupErrorV1::Context);
            }
            require_fresh_head_v1(&self.application, &self.head, &mut self.recovery_required)?;
            let read = self
                .application
                .read_poco_finalized_bytes_v0(
                    POCO_THREE_CHAIN_PROOF_CLASS_V0,
                    proof_bytes,
                    self.head.height(),
                    parent_timestamp(
                        &self.application,
                        self.head.height().get(),
                        self.genesis_timestamp_ms,
                    )?,
                    budget,
                )
                .map_err(NativeCatchupErrorV1::Finality)?;
            if read.finality().proof().finalized_block().header() != header
                || read.application().executed_v0().request().transactions()
                    != payload.transactions()
            {
                return Err(NativeCatchupErrorV1::Context);
            }
            budget
                .charge_finality_proof(read.finality().proof())
                .map_err(|e| NativeCatchupErrorV1::Admission(StrictFinalityErrorV0::Decode(e)))?;
            self.recovery_required = true;
            let committed = self
                .application
                .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                    read.application().executed_v0().clone(),
                    read.finality().proof().clone(),
                    parent_timestamp(
                        &self.application,
                        self.head.height().get(),
                        self.genesis_timestamp_ms,
                    )?,
                ))
                .map_err(NativeCatchupErrorV1::Uncertain)?;
            if committed.head() != &self.head {
                return Err(NativeCatchupErrorV1::RecoveryRequired);
            }
            self.recovery_required = false;
            return Ok(NativeCatchupReceiptV1 {
                head: self.head.clone(),
                proof_id: *read.finality().proof().id().as_bytes(),
                replayed: true,
            });
        }
        if self.head.height().get().checked_add(1) != Some(header.height().get())
            || header.parent_id().as_bytes() != self.head.block_id().as_bytes()
            || header.view() <= self.parent_view
        {
            return Err(NativeCatchupErrorV1::NonContiguous);
        }
        let verified = decode_verify_finality_proof_strict_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            proof_bytes,
            set,
            config.consensus_parameters_v0(),
            FinalityExpectationV0 {
                block_id: header.id(),
                height: header.height(),
                state_root: header.state_root(),
                receipts_root: header.receipts_root(),
                evidence_root: header.evidence_root(),
                parent_id: BlockId::new(*self.head.block_id().as_bytes()),
                parent_height: Height::new(self.head.height().get()),
                parent_timestamp_ms: self.parent_timestamp_ms,
            },
            budget,
        )
        .map_err(NativeCatchupErrorV1::Admission)?;
        if verified.proof().finalized_block().header() != header
            || verified
                .proof()
                .finalized_block()
                .justify_qc()
                .qc_ref()
                .view()
                != self.parent_view
        {
            return Err(NativeCatchupErrorV1::Context);
        }
        // Reserve the existing commit verifier's second pass before any write.
        budget
            .charge_finality_proof(verified.proof())
            .map_err(|e| NativeCatchupErrorV1::Admission(StrictFinalityErrorV0::Decode(e)))?;
        // Authenticate a new network input and reserve both crypto passes
        // before invoking the existing potentially full-history storage audit.
        // The cached predecessor is only a verification expectation: fresh
        // authoritative equality is still required before preview or mutation.
        require_fresh_head_v1(&self.application, &self.head, &mut self.recovery_required)?;
        let preview_request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(config.chain_id_v0()).map_err(|_| NativeCatchupErrorV1::Context)?,
            GenesisHashV0::new(config.genesis_hash_v0())
                .map_err(|_| NativeCatchupErrorV1::Context)?,
            self.head.clone(),
            HeightV0::new(header.height().get()),
            header.timestamp_ms(),
            ValidatorSetIdV0::new(*set.id().as_bytes())
                .map_err(|_| NativeCatchupErrorV1::Context)?,
            payload.transactions().to_vec(),
        )
        .map_err(|_| NativeCatchupErrorV1::Body)?;
        let preview = self
            .application
            .preview_block_v0(&preview_request)
            .map_err(NativeCatchupErrorV1::Application)?;
        if preview.payload_root().as_bytes() != header.payload_root().as_bytes()
            || preview.post_state_root().as_bytes() != header.state_root().as_bytes()
            || preview.receipts_root().as_bytes() != header.receipts_root().as_bytes()
            || preview.evidence_root().as_bytes() != header.evidence_root().as_bytes()
        {
            return Err(NativeCatchupErrorV1::ExecutionMismatch);
        }
        let request = NativeBlockExecutionRequestV0::new(
            preview_request.chain_id().clone(),
            preview_request.genesis_hash(),
            self.head.clone(),
            BlockIdV0::new(*header.id().as_bytes()).map_err(|_| NativeCatchupErrorV1::Context)?,
            preview_request.height(),
            header.timestamp_ms(),
            preview_request.active_validator_set_id(),
            payload.transactions().to_vec(),
            NativeExpectedBlockCommitmentsV0::new(
                Hash32V0::new(*header.payload_root().as_bytes()),
                StateRootV0::new(*header.state_root().as_bytes())
                    .map_err(|_| NativeCatchupErrorV1::Context)?,
                ReceiptsRootV0::new(*header.receipts_root().as_bytes())
                    .map_err(|_| NativeCatchupErrorV1::Context)?,
                Hash32V0::new(*header.evidence_root().as_bytes()),
            )
            .map_err(|_| NativeCatchupErrorV1::Context)?,
        )
        .map_err(|_| NativeCatchupErrorV1::Body)?;
        self.recovery_required = true;
        let executed = match self
            .application
            .execute_block(request)
            .map_err(NativeCatchupErrorV1::Uncertain)?
        {
            NativeBlockExecutionResultV0::Valid(value) => *value,
            _ => return Err(NativeCatchupErrorV1::RecoveryRequired),
        };
        #[cfg(test)]
        test_cut(&self.application, "after-prepare");
        let committed = self
            .application
            .commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
                executed.clone(),
                verified.proof().clone(),
                self.parent_timestamp_ms,
            ))
            .map_err(NativeCatchupErrorV1::Uncertain)?;
        #[cfg(test)]
        test_cut(&self.application, "after-commit");
        let read = self
            .application
            .read_finalized_by_height_v0(HeightV0::new(header.height().get()))
            .map_err(NativeCatchupErrorV1::Uncertain)?;
        if read.executed_v0() != &executed
            || read.confirmed_head_v0() != committed.head()
            || read
                .finalized_head_v0()
                .map_err(NativeCatchupErrorV1::Uncertain)?
                != *committed.head()
        {
            return Err(NativeCatchupErrorV1::RecoveryRequired);
        }
        self.head = committed.head().clone();
        self.parent_timestamp_ms = header.timestamp_ms();
        self.parent_view = header.view();
        self.recovery_required = false;
        Ok(NativeCatchupReceiptV1 {
            head: self.head.clone(),
            proof_id: *verified.proof().id().as_bytes(),
            replayed: false,
        })
    }

    /// The complete native JMT image must equal the independently reconstructed
    /// image, not merely share its latest root. Native snapshots do NOT encode
    /// command/nonce replay sets; those separate durable metadata sets have been
    /// rebuilt by actual execution. Nothing from a peer overwrites those sets
    /// or the recovered database. This comparison is deliberately stricter than
    /// root equivalence and does not support differently pruned history images.
    pub fn finish_with_snapshot<I>(
        self,
        manifest: &NativeSnapshotManifestV0,
        chunks: I,
        limits: NativeSnapshotReadLimitsV1,
    ) -> Result<RestoredNativeApplicationV1, NativeCatchupErrorV1>
    where
        I: IntoIterator<Item = io::Result<Vec<u8>>>,
    {
        if self.recovery_required {
            return Err(NativeCatchupErrorV1::RecoveryRequired);
        }
        if self.head.height().get() != self.target.finalized_height().get()
            || self.head.block_id().as_bytes() != self.target.finalized_block_id().as_bytes()
        {
            return Err(NativeCatchupErrorV1::Incomplete);
        }
        let verified = verify_native_snapshot_stream_v1(
            self.application.config_v0(),
            &self.target,
            manifest,
            chunks,
            limits,
        )
        .map_err(NativeCatchupErrorV1::Snapshot)?;
        let (head, digest, bytes) = self
            .application
            .confirm_snapshot_identity_v1()
            .map_err(NativeCatchupErrorV1::Application)?;
        if head != self.head
            || &digest != verified.snapshot_digest()
            || bytes != verified.total_bytes()
        {
            return Err(NativeCatchupErrorV1::SnapshotMismatch);
        }
        Ok(RestoredNativeApplicationV1 {
            application: self.application,
            head,
            snapshot_digest: digest,
            finality_proof_id: *verified.finality_proof_id(),
        })
    }
}

#[cfg(test)]
fn test_cut(application: &DurableNativeApplicationV0, cut: &str) {
    // Test-only process cuts, restricted to the explicit child helper and one
    // exact path. This function and environment lookup do not enter builds.
    if std::env::var("TRNM_CATCHUP_TEST_CUT").as_deref() == Ok(cut)
        && std::env::var_os("TRNM_CATCHUP_TEST_PATH").as_deref()
            == Some(application.path().as_os_str())
    {
        std::process::exit(73);
    }
}

#[cfg(test)]
mod tests {
    include!("finalized_catchup_v1/tests.rs");
    mod stream_tests {
        include!("finalized_catchup_v1/stream_tests.rs");
    }
}
