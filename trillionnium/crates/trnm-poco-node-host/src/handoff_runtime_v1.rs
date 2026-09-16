//! Candidate host join between native committed checkpoint readback and
//! durable role-specific handoff custody. No joint certificate is needed to
//! produce its constituent signatures. Ordinary votes and epoch activation
//! remain owned by Core/Safety; this wrapper cannot enable either.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use trnm_consensus_crypto::{verify_pre_handoff_context_strict_v1, StrictPreHandoffContextV1};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, HandoffSignatureProducerV1, HandoffSignerJournalErrorV1,
    HandoffSignerJournalProfileV1, SqliteHandoffSignerJournalV1, StrictNewSetHandoffAdmissionV1,
    StrictOldSetHandoffAdmissionV1,
};
use trnm_consensus_types::{
    CanonicalHandoffSignIntentV1, HandoffDescriptorV0, HandoffSignerRoleV1, SignatureBytes,
    ValidationError,
};
use trnm_native_execution_v0::{
    DurableExecutionHistoryStatusV0, DurableNativeApplicationV0, NativeApplicationExecutionErrorV0,
    PreHandoffCheckpointReceiptV1,
};

#[derive(Debug)]
pub enum CandidateHandoffRuntimeErrorV1 {
    Application(NativeApplicationExecutionErrorV0),
    ReceiptMismatch(&'static str),
    Crypto(ValidationError),
    Journal(HandoffSignerJournalErrorV1),
}

impl fmt::Display for CandidateHandoffRuntimeErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Application(error) => write!(f, "handoff application readback: {error}"),
            Self::ReceiptMismatch(field) => write!(f, "handoff receipt mismatch: {field}"),
            Self::Crypto(error) => write!(f, "handoff cryptographic admission: {error}"),
            Self::Journal(error) => write!(f, "handoff durable signer: {error}"),
        }
    }
}

impl Error for CandidateHandoffRuntimeErrorV1 {}

impl From<HandoffSignerJournalErrorV1> for CandidateHandoffRuntimeErrorV1 {
    fn from(error: HandoffSignerJournalErrorV1) -> Self {
        Self::Journal(error)
    }
}

impl From<NativeApplicationExecutionErrorV0> for CandidateHandoffRuntimeErrorV1 {
    fn from(error: NativeApplicationExecutionErrorV0) -> Self {
        Self::Application(error)
    }
}

/// Exact persisted signature result, joined to the native checkpoint that was
/// freshly read before custody. This is not a joint certificate, a publish
/// callback permit, or a successor-epoch signing authorization.
///
/// ```compile_fail
/// use trnm_poco_node_host::RecordedCandidateHandoffSignatureV1;
/// let fabricated = RecordedCandidateHandoffSignatureV1 {};
/// ```
#[derive(Debug)]
#[must_use]
pub struct RecordedCandidateHandoffSignatureV1 {
    intent: CanonicalHandoffSignIntentV1,
    signature: SignatureBytes,
    application_store_id: [u8; 32],
    checkpoint_commit_sequence: u64,
    checkpoint_artifact_digest: [u8; 32],
    context_binding: [u8; 32],
}

impl RecordedCandidateHandoffSignatureV1 {
    pub const fn intent(&self) -> &CanonicalHandoffSignIntentV1 {
        &self.intent
    }
    pub const fn signature(&self) -> SignatureBytes {
        self.signature
    }
    pub const fn application_store_id(&self) -> [u8; 32] {
        self.application_store_id
    }
    pub const fn checkpoint_commit_sequence(&self) -> u64 {
        self.checkpoint_commit_sequence
    }
    pub const fn checkpoint_artifact_digest(&self) -> [u8; 32] {
        self.checkpoint_artifact_digest
    }
    pub const fn context_binding(&self) -> [u8; 32] {
        self.context_binding
    }
}

/// Owns the actual durable handoff journal. The native owner remains linear
/// in its existing module and must be supplied with its unforgeable receipt.
/// There is intentionally no method accepting only roots or a boolean.
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictPreHandoffContextV1;
/// use trnm_native_execution_v0::PreHandoffCheckpointReceiptV1;
/// fn cryptographic_evidence_is_not_a_commit_receipt(context: StrictPreHandoffContextV1)
///     -> PreHandoffCheckpointReceiptV1 {
///     context
/// }
/// ```
pub struct CandidateHandoffRuntimeV1<W: ExternalMonotonicWatermarkV0> {
    application_path: PathBuf,
    application_store_id: [u8; 32],
    journal: SqliteHandoffSignerJournalV1<W>,
}

impl<W: ExternalMonotonicWatermarkV0> CandidateHandoffRuntimeV1<W> {
    pub fn from_owners(
        application: &DurableNativeApplicationV0,
        journal: SqliteHandoffSignerJournalV1<W>,
    ) -> Result<Self, CandidateHandoffRuntimeErrorV1> {
        application.confirmed_committed_head_v0()?;
        if application.config_v0().genesis_hash_v0()
            != *journal
                .profile()
                .old_validator_set()
                .genesis_hash()
                .as_bytes()
            || application.config_v0().chain_id_v0().as_bytes()
                != journal.profile().old_validator_set().chain_id().as_bytes()
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "commissioned chain",
            ));
        }
        Ok(Self {
            application_path: application.path().to_path_buf(),
            application_store_id: application.config_v0().store_id(),
            journal,
        })
    }

    /// Revalidates the native owner and cryptographic context before any
    /// external reconciliation. Only the same persisted role/intent may resume.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_exact(
        application: &DurableNativeApplicationV0,
        receipt: &PreHandoffCheckpointReceiptV1,
        descriptor: &HandoffDescriptorV0,
        role: HandoffSignerRoleV1,
        journal_path: impl AsRef<Path>,
        profile: HandoffSignerJournalProfileV1,
        watermark: W,
    ) -> Result<Self, CandidateHandoffRuntimeErrorV1> {
        let context = verify_receipt(application, receipt, descriptor, &profile)?;
        let intent = intent_for_role(role, descriptor, &profile)?;
        let journal = match role {
            HandoffSignerRoleV1::OldSet => {
                let admission =
                    StrictOldSetHandoffAdmissionV1::from_verified_context(&intent, &context)?;
                SqliteHandoffSignerJournalV1::recover_old_set_handoff_exact_v1(
                    journal_path,
                    profile,
                    watermark,
                    &intent,
                    &admission,
                )?
            }
            HandoffSignerRoleV1::NewSet => {
                let admission =
                    StrictNewSetHandoffAdmissionV1::from_verified_context(&intent, &context)?;
                SqliteHandoffSignerJournalV1::recover_new_set_handoff_exact_v1(
                    journal_path,
                    profile,
                    watermark,
                    &intent,
                    &admission,
                )?
            }
        };
        Self::from_owners(application, journal)
    }

    pub fn sign_handoff_exact<P: HandoffSignatureProducerV1>(
        &mut self,
        application: &DurableNativeApplicationV0,
        receipt: &PreHandoffCheckpointReceiptV1,
        descriptor: &HandoffDescriptorV0,
        role: HandoffSignerRoleV1,
        producer: &mut P,
    ) -> Result<RecordedCandidateHandoffSignatureV1, CandidateHandoffRuntimeErrorV1> {
        if application.path() != self.application_path
            || application.config_v0().store_id() != self.application_store_id
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "application owner",
            ));
        }
        let context = verify_receipt(application, receipt, descriptor, self.journal.profile())?;
        let intent = intent_for_role(role, descriptor, self.journal.profile())?;
        let signature = match role {
            HandoffSignerRoleV1::OldSet => {
                let admission =
                    StrictOldSetHandoffAdmissionV1::from_verified_context(&intent, &context)?;
                self.journal
                    .sign_old_set_handoff_exact_v1(&intent, &admission, producer)?
            }
            HandoffSignerRoleV1::NewSet => {
                let admission =
                    StrictNewSetHandoffAdmissionV1::from_verified_context(&intent, &context)?;
                self.journal
                    .sign_new_set_handoff_exact_v1(&intent, &admission, producer)?
            }
        };
        Ok(RecordedCandidateHandoffSignatureV1 {
            intent,
            signature,
            application_store_id: self.application_store_id,
            checkpoint_commit_sequence: receipt.durable_row().commit_sequence_v0().ok_or(
                CandidateHandoffRuntimeErrorV1::ReceiptMismatch("committed sequence"),
            )?,
            checkpoint_artifact_digest: receipt.durable_row().artifact_digest_v0(),
            context_binding: context.binding_ref(),
        })
    }
}

fn intent_for_role(
    role: HandoffSignerRoleV1,
    descriptor: &HandoffDescriptorV0,
    profile: &HandoffSignerJournalProfileV1,
) -> Result<CanonicalHandoffSignIntentV1, CandidateHandoffRuntimeErrorV1> {
    let constructor = match role {
        HandoffSignerRoleV1::OldSet => CanonicalHandoffSignIntentV1::old_set,
        HandoffSignerRoleV1::NewSet => CanonicalHandoffSignIntentV1::new_set,
    };
    constructor(
        descriptor,
        profile.old_validator_set(),
        profile.new_validator_set(),
        profile.old_consensus_parameters(),
        profile.new_consensus_parameters(),
        profile.author(),
    )
    .map_err(CandidateHandoffRuntimeErrorV1::Crypto)
}

fn verify_receipt(
    application: &DurableNativeApplicationV0,
    receipt: &PreHandoffCheckpointReceiptV1,
    descriptor: &HandoffDescriptorV0,
    profile: &HandoffSignerJournalProfileV1,
) -> Result<StrictPreHandoffContextV1, CandidateHandoffRuntimeErrorV1> {
    let row = receipt.durable_row();
    let header = receipt.header();
    let fields = descriptor.fields();
    if !row.belongs_to_application_at_path_v0(application, application.path())
        || row.store_id_v0() != application.config_v0().store_id()
        || row.status_v0() != DurableExecutionHistoryStatusV0::Committed
        || row.commit_sequence_v0().is_none()
        || receipt.post_execution_authorization_id() == [0; 32]
    {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "committed native owner",
        ));
    }
    if fields.checkpoint_block_id != header.id()
        || fields.checkpoint_height != header.height()
        || fields.checkpoint_state_root != header.state_root()
        || receipt.checkpoint_finality().finalized_block().header() != header
        || profile.old_validator_set() != receipt.old_validator_set()
        || profile.new_validator_set() != receipt.new_validator_set()
        || profile.old_consensus_parameters() != receipt.old_parameters()
        || profile.new_consensus_parameters() != receipt.new_parameters()
    {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "descriptor or signer profile",
        ));
    }
    let target = row.target_head_v0()?;
    let fresh = application.read_finalized_by_block_id_v0(target.block_id())?;
    let fresh_row = fresh.durable_row_v0();
    if fresh_row.target_head_v0()? != target
        || fresh_row.p_sequence_v0() != row.p_sequence_v0()
        || fresh_row.p_digest_v0() != row.p_digest_v0()
        || fresh_row.artifact_digest_v0() != row.artifact_digest_v0()
        || fresh_row.overlay_digest_v0() != row.overlay_digest_v0()
        || fresh_row.commit_sequence_v0() != row.commit_sequence_v0()
    {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "fresh checkpoint readback",
        ));
    }
    verify_pre_handoff_context_strict_v1(
        receipt.checkpoint_finality(),
        &receipt.next_epoch_commitment(),
        descriptor,
        receipt.old_validator_set(),
        receipt.old_parameters(),
        receipt.new_validator_set(),
        receipt.new_parameters(),
        receipt.checkpoint_parent_header(),
    )
    .map_err(CandidateHandoffRuntimeErrorV1::Crypto)
}
