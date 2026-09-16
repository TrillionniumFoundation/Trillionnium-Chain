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
use trnm_consensus_safety_store::{
    ConfirmedOldEpochSafetyHeadV1, OldEpochJournalErrorV1, SqliteOldEpochSafetyJournalV1,
};
use trnm_consensus_signer_journal::{
    ConfirmedOrdinarySignerRetirementV1, ConfirmedSignerNodeCheckpointFactsV0,
    ExternalMonotonicWatermarkV0, ExternalSignerRetirementV1, HandoffSignatureProducerV1,
    HandoffSignerJournalErrorV1, HandoffSignerJournalProfileV1, RetiredSqliteSignerJournalV1,
    SignerJournalErrorV0, SignerJournalProfileV0, SignerRetirementHostCutV1,
    SqliteHandoffSignerJournalV1, SqliteSignerJournalV0, StrictNewSetHandoffAdmissionV1,
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
    OrdinarySigner(SignerJournalErrorV0),
    Safety(OldEpochJournalErrorV1),
    OriginalOrdinaryRecoveryUnavailable,
}

impl fmt::Display for CandidateHandoffRuntimeErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Application(error) => write!(f, "handoff application readback: {error}"),
            Self::ReceiptMismatch(field) => write!(f, "handoff receipt mismatch: {field}"),
            Self::Crypto(error) => write!(f, "handoff cryptographic admission: {error}"),
            Self::Journal(error) => write!(f, "handoff durable signer: {error}"),
            Self::OrdinarySigner(error) => write!(f, "ordinary signer retirement: {error}"),
            Self::Safety(error) => write!(f, "terminal outgoing Safety cut: {error}"),
            Self::OriginalOrdinaryRecoveryUnavailable => write!(
                f,
                "retired restart requires durable original ordinary node-checkpoint join"
            ),
        }
    }
}

impl Error for CandidateHandoffRuntimeErrorV1 {}
impl From<SignerJournalErrorV0> for CandidateHandoffRuntimeErrorV1 {
    fn from(e: SignerJournalErrorV0) -> Self {
        Self::OrdinarySigner(e)
    }
}
impl From<OldEpochJournalErrorV1> for CandidateHandoffRuntimeErrorV1 {
    fn from(e: OldEpochJournalErrorV1) -> Self {
        Self::Safety(e)
    }
}

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
    original_ordinary: Option<OriginalOrdinaryCustodyV1>,
}

/// Live-process selection made before retirement. An independently obtained
/// exact ordinary checkpoint capability fixes both the original owner and its
/// scope/journal/full profile. It cannot be reconstructed from retired scalars.
struct OriginalOrdinaryCustodyV1 {
    path: PathBuf,
    facts: ConfirmedSignerNodeCheckpointFactsV0,
}
impl OriginalOrdinaryCustodyV1 {
    fn commission<W: ExternalMonotonicWatermarkV0>(
        ordinary: &mut SqliteSignerJournalV0<W>,
        facts: ConfirmedSignerNodeCheckpointFactsV0,
    ) -> Result<Self, CandidateHandoffRuntimeErrorV1> {
        if !facts.belongs_to_operational_journal_at_path_v0(ordinary, ordinary.path()) {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "original ordinary checkpoint owner",
            ));
        }
        let fresh = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        if fresh.journal_id() != facts.journal_id()
            || fresh.profile_checksum() != facts.profile_checksum()
            || fresh.identity() != facts.identity()
            || fresh.exact_watermark() != facts.exact_watermark()
            || fresh.pending_intent().is_some()
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "original ordinary commissioning cut",
            ));
        }
        Ok(Self {
            path: ordinary.path().to_path_buf(),
            facts,
        })
    }
    fn require_operational<W: ExternalMonotonicWatermarkV0>(
        &self,
        ordinary: &mut SqliteSignerJournalV0<W>,
    ) -> Result<(), CandidateHandoffRuntimeErrorV1> {
        if !self
            .facts
            .belongs_to_operational_journal_at_path_v0(ordinary, &self.path)
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "substituted original ordinary owner",
            ));
        }
        let fresh = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        if fresh.journal_id() != self.facts.journal_id()
            || fresh.profile_checksum() != self.facts.profile_checksum()
            || fresh.identity() != self.facts.identity()
            || fresh.exact_watermark().sequence() < self.facts.exact_watermark().sequence()
            || fresh.pending_intent().is_some()
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "original ordinary identity or source cut",
            ));
        }
        Ok(())
    }
    fn require_retired<W: ExternalSignerRetirementV1>(
        &self,
        retired: &RetiredSqliteSignerJournalV1<W>,
    ) -> Result<(), CandidateHandoffRuntimeErrorV1> {
        if !self
            .facts
            .belongs_to_retired_journal_at_path_v1(retired, &self.path)
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "substituted original retired owner",
            ));
        }
        Ok(())
    }
}

impl<W: ExternalMonotonicWatermarkV0> CandidateHandoffRuntimeV1<W> {
    /// New-only commissioning. An old/continuing member must use the explicit
    /// original-ordinary-owner constructor before retiring any custody.
    pub fn from_owners(
        application: &DurableNativeApplicationV0,
        journal: SqliteHandoffSignerJournalV1<W>,
    ) -> Result<Self, CandidateHandoffRuntimeErrorV1> {
        require_new_only(HandoffSignerRoleV1::NewSet, journal.profile())?;
        Self::from_joined_owners(application, journal, None)
    }
    /// Consumes facts obtained independently from the original live ordinary
    /// owner at commissioning. The same affine selection survives retirement;
    /// a different journal/scope using the same key cannot replace it later.
    pub fn from_owners_with_original_ordinary_v1<RW: ExternalMonotonicWatermarkV0>(
        application: &DurableNativeApplicationV0,
        journal: SqliteHandoffSignerJournalV1<W>,
        ordinary: &mut SqliteSignerJournalV0<RW>,
        original_facts: ConfirmedSignerNodeCheckpointFactsV0,
    ) -> Result<Self, CandidateHandoffRuntimeErrorV1> {
        verify_ordinary_profile(ordinary.profile(), journal.profile())?;
        if ordinary.profile().external_watermark_scope()
            == journal.profile().external_watermark_scope()
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "ordinary and handoff scopes must be explicit and distinct",
            ));
        }
        let original = OriginalOrdinaryCustodyV1::commission(ordinary, original_facts)?;
        Self::from_joined_owners(application, journal, Some(original))
    }
    fn from_joined_owners(
        application: &DurableNativeApplicationV0,
        journal: SqliteHandoffSignerJournalV1<W>,
        original_ordinary: Option<OriginalOrdinaryCustodyV1>,
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
            original_ordinary,
        })
    }

    /// Retire the real old ordinary owner only after fresh native and terminal
    /// outgoing Safety readbacks. Scalar host cuts are derived here, not supplied.
    #[allow(clippy::too_many_arguments)]
    pub fn retire_ordinary_before_handoff_v1<RW: ExternalSignerRetirementV1>(
        &self,
        application: &DurableNativeApplicationV0,
        receipt: &PreHandoffCheckpointReceiptV1,
        descriptor: &HandoffDescriptorV0,
        safety: &SqliteOldEpochSafetyJournalV1,
        safety_head: &ConfirmedOldEpochSafetyHeadV1,
        mut ordinary: SqliteSignerJournalV0<RW>,
    ) -> Result<
        (
            RetiredSqliteSignerJournalV1<RW>,
            ConfirmedOrdinarySignerRetirementV1,
        ),
        CandidateHandoffRuntimeErrorV1,
    > {
        if application.path() != self.application_path
            || application.config_v0().store_id() != self.application_store_id
        {
            return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "commissioned application owner",
            ));
        }
        let original = self.original_ordinary.as_ref().ok_or(
            CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "original ordinary custody was not commissioned",
            ),
        )?;
        original.require_operational(&mut ordinary)?;
        let profile = self.journal.profile();
        let context = verify_receipt(application, receipt, descriptor, profile)?;
        verify_ordinary_profile(ordinary.profile(), profile)?;
        let host = verify_terminal_safety(application, receipt, profile, safety, safety_head)?;
        let intent = intent_for_role(HandoffSignerRoleV1::OldSet, descriptor, profile)?;
        let mut retired = ordinary.retire_for_handoff_v1(&context, &intent, host)?;
        let confirmed = retired.confirm_retirement_v1()?;
        Ok((retired, confirmed))
    }
    /// New-only validators have no old ordinary custody. Continuing and removed
    /// validators must use the explicit retired-owner path below.
    pub fn sign_handoff_exact<P: HandoffSignatureProducerV1>(
        &mut self,
        application: &DurableNativeApplicationV0,
        receipt: &PreHandoffCheckpointReceiptV1,
        descriptor: &HandoffDescriptorV0,
        role: HandoffSignerRoleV1,
        producer: &mut P,
    ) -> Result<RecordedCandidateHandoffSignatureV1, CandidateHandoffRuntimeErrorV1> {
        require_new_only(role, self.journal.profile())?;
        self.sign_with_joined_owners(application, receipt, descriptor, role, producer)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn sign_retired_handoff_exact_v1<
        RW: ExternalSignerRetirementV1,
        P: HandoffSignatureProducerV1,
    >(
        &mut self,
        application: &DurableNativeApplicationV0,
        receipt: &PreHandoffCheckpointReceiptV1,
        descriptor: &HandoffDescriptorV0,
        role: HandoffSignerRoleV1,
        safety: &SqliteOldEpochSafetyJournalV1,
        safety_head: &ConfirmedOldEpochSafetyHeadV1,
        retired: &mut RetiredSqliteSignerJournalV1<RW>,
        confirmed: &ConfirmedOrdinarySignerRetirementV1,
        producer: &mut P,
    ) -> Result<RecordedCandidateHandoffSignatureV1, CandidateHandoffRuntimeErrorV1> {
        let original = self.original_ordinary.as_ref().ok_or(
            CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "original ordinary custody was not commissioned",
            ),
        )?;
        verify_retired_join(
            original,
            application,
            receipt,
            descriptor,
            self.journal.profile(),
            safety,
            safety_head,
            retired,
            confirmed,
        )?;
        let recorded =
            self.sign_with_joined_owners(application, receipt, descriptor, role, producer)?;
        // A producer may block or fail independently; re-read every custody cut
        // again before a persisted handoff signature leaves this host boundary.
        let original = self.original_ordinary.as_ref().ok_or(
            CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
                "original ordinary custody disappeared",
            ),
        )?;
        verify_retired_join(
            original,
            application,
            receipt,
            descriptor,
            self.journal.profile(),
            safety,
            safety_head,
            retired,
            confirmed,
        )?;
        Ok(recorded)
    }
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
        require_new_only(role, &profile)?;
        Self::recover_joined_exact(
            application,
            receipt,
            descriptor,
            role,
            journal_path,
            profile,
            watermark,
        )
    }
    /// Fenced until a terminal14O/14E durable whole-node checkpoint independently
    /// reconstructs the original ordinary custody selection. Always returns
    /// OriginalOrdinaryRecoveryUnavailable without reading or reconciling owners.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_with_retired_ordinary_exact_v1<RW: ExternalSignerRetirementV1>(
        application: &DurableNativeApplicationV0,
        receipt: &PreHandoffCheckpointReceiptV1,
        descriptor: &HandoffDescriptorV0,
        role: HandoffSignerRoleV1,
        journal_path: impl AsRef<Path>,
        profile: HandoffSignerJournalProfileV1,
        watermark: W,
        safety: &SqliteOldEpochSafetyJournalV1,
        safety_head: &ConfirmedOldEpochSafetyHeadV1,
        retired: &mut RetiredSqliteSignerJournalV1<RW>,
        confirmed: &ConfirmedOrdinarySignerRetirementV1,
    ) -> Result<Self, CandidateHandoffRuntimeErrorV1> {
        // No durable terminal14O/14E whole-node checkpoint producer currently
        // reestablishes the independently selected original ordinary owner.
        // Do not infer it from the supplied retired owner or reconcile any CAS.
        let _ = (
            application,
            receipt,
            descriptor,
            role,
            journal_path,
            profile,
            watermark,
            safety,
            safety_head,
            retired,
            confirmed,
        );
        Err(CandidateHandoffRuntimeErrorV1::OriginalOrdinaryRecoveryUnavailable)
    }
    /// Revalidates the native owner and cryptographic context before any
    /// external reconciliation. Only the same persisted role/intent may resume.
    #[allow(clippy::too_many_arguments)]
    fn recover_joined_exact(
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

    fn sign_with_joined_owners<P: HandoffSignatureProducerV1>(
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

fn require_new_only(
    role: HandoffSignerRoleV1,
    profile: &HandoffSignerJournalProfileV1,
) -> Result<(), CandidateHandoffRuntimeErrorV1> {
    let new_key = profile
        .new_validator_set()
        .validator(profile.author())
        .map(|v| v.consensus_key());
    let reused_old_key = new_key.is_some_and(|key| {
        profile
            .old_validator_set()
            .validators()
            .iter()
            .any(|old| old.consensus_key() == key)
    });
    if role != HandoffSignerRoleV1::NewSet
        || profile
            .old_validator_set()
            .validator(profile.author())
            .is_some()
        || reused_old_key
    {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "old/continuing validator requires actual retired ordinary owner",
        ));
    }
    Ok(())
}
fn verify_ordinary_profile(
    ordinary: &SignerJournalProfileV0,
    handoff: &HandoffSignerJournalProfileV1,
) -> Result<(), CandidateHandoffRuntimeErrorV1> {
    if ordinary.validator_set() != handoff.old_validator_set()
        || ordinary.author() != handoff.author()
        || ordinary.signer_profile_ref() != handoff.signer_profile_ref()
    {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "ordinary/handoff custody profile",
        ));
    }
    Ok(())
}
fn verify_terminal_safety(
    application: &DurableNativeApplicationV0,
    receipt: &PreHandoffCheckpointReceiptV1,
    profile: &HandoffSignerJournalProfileV1,
    safety: &SqliteOldEpochSafetyJournalV1,
    head: &ConfirmedOldEpochSafetyHeadV1,
) -> Result<SignerRetirementHostCutV1, CandidateHandoffRuntimeErrorV1> {
    if !head.belongs_to_store_at_path_v1(safety, safety.path_v1()) {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "outgoing Safety owner",
        ));
    }
    let (fresh, terminal) = safety.prepare_terminal_recovery_v1(head.pin_v1())?;
    if terminal.config().validator_set() != profile.old_validator_set()
        || terminal.config().local_validator() != profile.author()
        || terminal.state().last_finalization_proof() != Some(receipt.checkpoint_finality())
        || receipt.durable_row().store_id_v0() != application.config_v0().store_id()
        || fresh.state_record_checksum_v1() != head.state_record_checksum_v1()
    {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "outgoing Safety/native checkpoint join",
        ));
    }
    Ok(SignerRetirementHostCutV1 {
        owner_generation: fresh.owner_generation_v1(),
        native_committed_cut: receipt.committed_owner_cut_ref_v1(),
        safety_revision: fresh.revision_v1(),
        safety_record_checksum: fresh.state_record_checksum_v1(),
    })
}
#[allow(clippy::too_many_arguments)]
fn verify_retired_join<RW: ExternalSignerRetirementV1>(
    original: &OriginalOrdinaryCustodyV1,
    application: &DurableNativeApplicationV0,
    receipt: &PreHandoffCheckpointReceiptV1,
    descriptor: &HandoffDescriptorV0,
    profile: &HandoffSignerJournalProfileV1,
    safety: &SqliteOldEpochSafetyJournalV1,
    safety_head: &ConfirmedOldEpochSafetyHeadV1,
    retired: &mut RetiredSqliteSignerJournalV1<RW>,
    confirmed: &ConfirmedOrdinarySignerRetirementV1,
) -> Result<(), CandidateHandoffRuntimeErrorV1> {
    original.require_retired(retired)?;
    let context = verify_receipt(application, receipt, descriptor, profile)?;
    let expected_host = verify_terminal_safety(application, receipt, profile, safety, safety_head)?;
    verify_ordinary_profile(retired.profile_v1(), profile)?;
    let expected_intent = intent_for_role(HandoffSignerRoleV1::OldSet, descriptor, profile)?;
    let record = confirmed.record_v1();
    if record.host_cut_v1() != expected_host
        || record.pre_handoff_binding_v1() != context.binding_ref()
        || record.descriptor_digest_v1()
            != *expected_intent.preimage().descriptor_digest().as_bytes()
        || record.old_handoff_intent_fingerprint_v1() != *expected_intent.fingerprint().as_bytes()
        || record.source_profile_checksum_v1() != retired.profile_v1().profile_checksum()
        || !confirmed.belongs_to_owner_v1(retired)
    {
        return Err(CandidateHandoffRuntimeErrorV1::ReceiptMismatch(
            "fresh ordinary retirement owner/context/cut",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "handoff_runtime_v1_tests.rs"]
mod tests;
