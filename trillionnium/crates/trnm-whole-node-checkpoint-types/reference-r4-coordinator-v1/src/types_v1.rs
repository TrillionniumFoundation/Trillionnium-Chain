pub const SAFETY_FINALIZATION_TAG_V1: u8 = 3;
pub const PRODUCTION_ACTIVATION_V1: bool = false;
pub const PRODUCTION_SIGNATURE_AUTHORITY_V1: bool = false;
pub const PRIVATE_KEY_HANDLING_V1: bool = false;
pub const AUTOMATIC_MIXED_CUT_REPAIR_V1: bool = false;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub fn new(value: [u8; 32]) -> Option<Self> {
        if value == [0; 32] {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Digest32(")?;
        for byte in &self.0[..4] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoordinatorConfigV1 {
    namespace_scope: Digest32,
    application_store_id: Digest32,
    safety_store_id: Digest32,
    signer_journal_id: Digest32,
    checkpoint_scope: Digest32,
    node_id: Digest32,
    signer_key_id: Digest32,
    custody_policy_hash: Digest32,
    process_generation: u64,
}

impl CoordinatorConfigV1 {
    pub const fn new(
        namespace_scope: Digest32,
        application_store_id: Digest32,
        safety_store_id: Digest32,
        signer_journal_id: Digest32,
        checkpoint_scope: Digest32,
        node_id: Digest32,
        signer_key_id: Digest32,
        custody_policy_hash: Digest32,
        process_generation: u64,
    ) -> Option<Self> {
        if process_generation == 0 {
            return None;
        }
        Some(Self {
            namespace_scope,
            application_store_id,
            safety_store_id,
            signer_journal_id,
            checkpoint_scope,
            node_id,
            signer_key_id,
            custody_policy_hash,
            process_generation,
        })
    }

    pub const fn namespace_scope(&self) -> Digest32 {
        self.namespace_scope
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignTargetV1 {
    pub epoch: u64,
    pub view: u64,
    pub height: u64,
    pub block_id: Digest32,
    pub body_hash: Digest32,
    pub application_root: Digest32,
    pub receipts_root: Digest32,
    pub safety_state_hash: Digest32,
    pub sign_intent_hash: Digest32,
    pub signing_root: Digest32,
}

impl SignTargetV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        view: u64,
        height: u64,
        block_id: Digest32,
        body_hash: Digest32,
        application_root: Digest32,
        receipts_root: Digest32,
        safety_state_hash: Digest32,
        sign_intent_hash: Digest32,
        signing_root: Digest32,
    ) -> Option<Self> {
        if height == 0 {
            return None;
        }
        Some(Self {
            epoch,
            view,
            height,
            block_id,
            body_hash,
            application_root,
            receipts_root,
            safety_state_hash,
            sign_intent_hash,
            signing_root,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationFinalizationReadbackV1 {
    namespace_scope: Digest32,
    store_id: Digest32,
    sequence: u64,
    height: u64,
    block_id: Digest32,
    body_hash: Digest32,
    application_root: Digest32,
    receipts_root: Digest32,
    durable: bool,
}

impl ApplicationFinalizationReadbackV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        namespace_scope: Digest32,
        store_id: Digest32,
        sequence: u64,
        height: u64,
        block_id: Digest32,
        body_hash: Digest32,
        application_root: Digest32,
        receipts_root: Digest32,
        durable: bool,
    ) -> Self {
        Self {
            namespace_scope,
            store_id,
            sequence,
            height,
            block_id,
            body_hash,
            application_root,
            receipts_root,
            durable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafetyTag3ReadbackV1 {
    namespace_scope: Digest32,
    store_id: Digest32,
    revision: u64,
    epoch: u64,
    view: u64,
    height: u64,
    block_id: Digest32,
    body_hash: Digest32,
    application_root: Digest32,
    safety_state_hash: Digest32,
    transition_tag: u8,
    durable: bool,
}

impl SafetyTag3ReadbackV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        namespace_scope: Digest32,
        store_id: Digest32,
        revision: u64,
        epoch: u64,
        view: u64,
        height: u64,
        block_id: Digest32,
        body_hash: Digest32,
        application_root: Digest32,
        safety_state_hash: Digest32,
        transition_tag: u8,
        durable: bool,
    ) -> Self {
        Self {
            namespace_scope,
            store_id,
            revision,
            epoch,
            view,
            height,
            block_id,
            body_hash,
            application_root,
            safety_state_hash,
            transition_tag,
            durable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignerPreparedIntentReadbackV1 {
    namespace_scope: Digest32,
    journal_id: Digest32,
    sequence: u64,
    epoch: u64,
    view: u64,
    block_id: Digest32,
    sign_intent_hash: Digest32,
    signing_root: Digest32,
    signer_key_id: Digest32,
    custody_policy_hash: Digest32,
    process_generation: u64,
    durable: bool,
}

impl SignerPreparedIntentReadbackV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        namespace_scope: Digest32,
        journal_id: Digest32,
        sequence: u64,
        epoch: u64,
        view: u64,
        block_id: Digest32,
        sign_intent_hash: Digest32,
        signing_root: Digest32,
        signer_key_id: Digest32,
        custody_policy_hash: Digest32,
        process_generation: u64,
        durable: bool,
    ) -> Self {
        Self {
            namespace_scope,
            journal_id,
            sequence,
            epoch,
            view,
            block_id,
            sign_intent_hash,
            signing_root,
            signer_key_id,
            custody_policy_hash,
            process_generation,
            durable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateCutV1 {
    target: SignTargetV1,
    application: ApplicationFinalizationReadbackV1,
    safety: SafetyTag3ReadbackV1,
    signer: SignerPreparedIntentReadbackV1,
}

impl CandidateCutV1 {
    pub const fn new(
        target: SignTargetV1,
        application: ApplicationFinalizationReadbackV1,
        safety: SafetyTag3ReadbackV1,
        signer: SignerPreparedIntentReadbackV1,
    ) -> Self {
        Self {
            target,
            application,
            safety,
            signer,
        }
    }

    pub const fn target(&self) -> SignTargetV1 {
        self.target
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WholeNodeCheckpointV1 {
    checkpoint_scope: Digest32,
    namespace_scope: Digest32,
    application_store_id: Digest32,
    safety_store_id: Digest32,
    signer_journal_id: Digest32,
    generation: u64,
    predecessor_generation: u64,
    target: SignTargetV1,
    application_sequence: u64,
    safety_revision: u64,
    signer_sequence: u64,
    external_watermark_sequence: u64,
    node_id: Digest32,
    signer_key_id: Digest32,
    custody_policy_hash: Digest32,
    process_generation: u64,
}

impl WholeNodeCheckpointV1 {
    pub const fn checkpoint_scope(&self) -> Digest32 {
        self.checkpoint_scope
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn target(&self) -> SignTargetV1 {
        self.target
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalWatermarkV1 {
    namespace_scope: Digest32,
    checkpoint_scope: Digest32,
    application_store_id: Digest32,
    safety_store_id: Digest32,
    journal_id: Digest32,
    sequence: u64,
    checkpoint_generation: u64,
    epoch: u64,
    view: u64,
    height: u64,
    safety_revision: u64,
    signer_sequence: u64,
    signing_root: Digest32,
    node_id: Digest32,
    signer_key_id: Digest32,
    custody_policy_hash: Digest32,
    process_generation: u64,
}

impl ExternalWatermarkV1 {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorErrorV1 {
    Fenced,
    NamespaceMismatch,
    StoreIdentityMismatch,
    CustodyBindingMismatch,
    ProcessGenerationMismatch,
    ApplicationNotDurable,
    SafetyNotDurable,
    SignerIntentNotDurable,
    WrongSafetyTransitionTag,
    ZeroSequence,
    ApplicationTargetMismatch,
    SafetyTargetMismatch,
    SignerTargetMismatch,
    CheckpointWatermarkMismatch,
    HeightRollback,
    RoundRollback,
    SameHeightConflict,
    SequenceRollback,
    ArithmeticOverflow,
    MixedCommit,
    ThirdState,
}

impl fmt::Display for CoordinatorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Fenced => "coordinator is permanently fenced",
            Self::NamespaceMismatch => "namespace mismatch",
            Self::StoreIdentityMismatch => "store identity mismatch",
            Self::CustodyBindingMismatch => "signer key or custody-policy binding mismatch",
            Self::ProcessGenerationMismatch => "process generation mismatch",
            Self::ApplicationNotDurable => "application readback is not durable",
            Self::SafetyNotDurable => "Safety tag-3 readback is not durable",
            Self::SignerIntentNotDurable => "signer intent is not durable",
            Self::WrongSafetyTransitionTag => "Safety transition is not tag 3",
            Self::ZeroSequence => "a durable sequence is zero",
            Self::ApplicationTargetMismatch => "application target mismatch",
            Self::SafetyTargetMismatch => "Safety target mismatch",
            Self::SignerTargetMismatch => "signer target mismatch",
            Self::CheckpointWatermarkMismatch => "checkpoint and watermark do not bind one cut",
            Self::HeightRollback => "height rollback",
            Self::RoundRollback => "epoch/view rollback",
            Self::SameHeightConflict => "same-height target conflict",
            Self::SequenceRollback => "durable sequence rollback",
            Self::ArithmeticOverflow => "monotonic counter overflow",
            Self::MixedCommit => "checkpoint/watermark mixed commit",
            Self::ThirdState => "checkpoint/watermark unknown third state",
        })
    }
}

impl std::error::Error for CoordinatorErrorV1 {}

#[derive(Debug)]
pub struct CommitPlanV1 {
    checkpoint: WholeNodeCheckpointV1,
    watermark: ExternalWatermarkV1,
}

impl CommitPlanV1 {
    pub const fn checkpoint(&self) -> &WholeNodeCheckpointV1 {
        &self.checkpoint
    }

    pub const fn watermark(&self) -> &ExternalWatermarkV1 {
        &self.watermark
    }
}

#[must_use = "dropping the permit must never be treated as a successful signature"]
#[derive(Debug)]
pub struct SignaturePermitV1 {
    target: SignTargetV1,
    checkpoint_generation: u64,
    checkpoint_scope: Digest32,
    namespace_scope: Digest32,
    application_store_id: Digest32,
    safety_store_id: Digest32,
    signer_journal_id: Digest32,
    node_id: Digest32,
    signer_key_id: Digest32,
    custody_policy_hash: Digest32,
    process_generation: u64,
}

impl SignaturePermitV1 {
    pub const fn target(&self) -> SignTargetV1 {
        self.target
    }

    pub const fn checkpoint_generation(&self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_scope(&self) -> Digest32 {
        self.checkpoint_scope
    }

    pub const fn namespace_scope(&self) -> Digest32 {
        self.namespace_scope
    }

    pub const fn application_store_id(&self) -> Digest32 {
        self.application_store_id
    }

    pub const fn safety_store_id(&self) -> Digest32 {
        self.safety_store_id
    }

    pub const fn signer_journal_id(&self) -> Digest32 {
        self.signer_journal_id
    }

    pub const fn node_id(&self) -> Digest32 {
        self.node_id
    }

    pub const fn signer_key_id(&self) -> Digest32 {
        self.signer_key_id
    }

    pub const fn custody_policy_hash(&self) -> Digest32 {
        self.custody_policy_hash
    }

    pub const fn process_generation(&self) -> u64 {
        self.process_generation
    }
}

#[derive(Debug)]
