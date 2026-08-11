use std::{collections::VecDeque, path::Path};

use trnm_consensus_core::{
    Core, CoreConfig, Effect, Input, OutboundMessage, SafetyHalt, SafetyState, SignId, SignIntent,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    RecoveredSafetyStateV0, SafetyTransitionContextV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, JournalCapacityV0,
    SignatureProducerErrorV0, SignatureProducerV0, SignerJournalErrorV0, SignerWatermarkV0,
    SqliteSignerJournalV0,
};
use trnm_consensus_types::{
    CanonicalSignPreimageV0, CanonicalSignable, Epoch, GenesisQcV0, SignIntentFingerprintV0,
    SignatureBytes, SigningRoot, View,
};

use crate::{
    effect_name_v0, head_has_current_invalid_completion_v0, reject_activation_request,
    validate_signer_safety_revision_v0, HostBootstrapModeV0, HostLifecyclePhaseV0,
    PocoNodeHostErrorV0, PocoNodeStartConfigV0, ProductionActivationBlockedV0,
};

const MAXIMUM_BOUNDED_HOST_EFFECTS_PER_CALL_V0: usize = 16;

/// Caller-visible actions emitted by the bounded ordinary host.
///
/// The host retains the live Core, SafetyStore, signer journal, and signature
/// producer. Callers receive no persistence request, sign intent, mutable Core
/// reference, or arbitrary effect-driving capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocoNodeHostActionV0 {
    ArmViewTimer { epoch: Epoch, view: View },
    Broadcast(Box<PocoNodeSignedOutboundV0>),
    SafetyHalted(Box<SafetyHalt>),
}

/// Process-test-only checkpoints in the bounded timeout signing path.
///
/// These names describe exact userspace boundaries. They are intentionally
/// absent from default and release builds and do not claim power-loss,
/// hardware-fsync, or production signer evidence.
#[cfg(feature = "recovery-process-test-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeTimeoutSigningProcessCheckpointPhaseV0 {
    SafetyPersistedBeforeStorageAck,
    SignatureRequestedBeforeJournal,
    ProducerEnteredAfterIntentWatermark,
    ProducerGeneratedBeforeReturn,
    SignaturePersistedBeforeSignatureReady,
    BroadcastProducedBeforeReturn,
}

#[cfg(feature = "recovery-process-test-support")]
impl PocoNodeTimeoutSigningProcessCheckpointPhaseV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SafetyPersistedBeforeStorageAck => "safety_persisted_before_storage_ack",
            Self::SignatureRequestedBeforeJournal => "signature_requested_before_journal",
            Self::ProducerEnteredAfterIntentWatermark => "producer_entered_after_intent_watermark",
            Self::ProducerGeneratedBeforeReturn => "producer_generated_before_return",
            Self::SignaturePersistedBeforeSignatureReady => {
                "signature_persisted_before_signature_ready"
            }
            Self::BroadcastProducedBeforeReturn => "broadcast_produced_before_return",
        }
    }
}

/// One Core-produced outbound message bound to the exact durable signer
/// authorization which released it.
///
/// Fields are deliberately private: callers can inspect or clone a host
/// result, but cannot construct a value which appears to have crossed the
/// SafetyStore and signer-journal barriers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeSignedOutboundV0 {
    intent_fingerprint: SignIntentFingerprintV0,
    authorizing_safety_revision: u64,
    message: OutboundMessage,
}

impl PocoNodeSignedOutboundV0 {
    pub const fn intent_fingerprint(&self) -> SignIntentFingerprintV0 {
        self.intent_fingerprint
    }

    pub const fn authorizing_safety_revision(&self) -> u64 {
        self.authorizing_safety_revision
    }

    pub const fn message(&self) -> &OutboundMessage {
        &self.message
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingSignedOutboundV0 {
    intent_fingerprint: SignIntentFingerprintV0,
    authorizing_safety_revision: u64,
    signing_root: SigningRoot,
    signature: SignatureBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedTimeoutRuntimeStatusV0 {
    Active,
    FailStopped,
}

/// Non-cloneable owner of one Core, its safety store, signer journal, and
/// injected exact-idempotent signature producer.
///
/// There is intentionally no mutable Core accessor, caller-selected `step`,
/// detached signer, application adapter, or escape hatch returning owned
/// parts. Only `Resume` and a timeout derived from the authenticated Core state
/// are exposed in this slice.
pub struct PocoNodeHostV0<W, P> {
    core: Core,
    safety_store: SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    signer_journal: SqliteSignerJournalV0<W>,
    signature_producer: P,
    bootstrap_mode: HostBootstrapModeV0,
    runtime_status: BoundedTimeoutRuntimeStatusV0,
}

impl<W: ExternalMonotonicWatermarkV0, P: SignatureProducerV0> PocoNodeHostV0<W, P> {
    /// Creates the epoch-zero Core, initializes its journal at revision zero,
    /// and binds future persistence to this exact Core instance.
    ///
    /// The safety store is initialized before the signer journal. There is no
    /// atomic transaction across the two SQLite stores or the external
    /// watermark. An interrupted partial initialization is intentionally not
    /// repaired here: subsequent recovery fails closed and requires explicit
    /// operator quarantine or recovery.
    pub fn initialize_new(
        config: PocoNodeStartConfigV0,
        genesis_qc: GenesisQcV0,
        external_watermark: W,
        signature_producer: P,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(&config)?;
        let core_config = config.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = config;
        let verifier = StrictEd25519Verifier;
        let core =
            Core::new(core_config, genesis_qc, &verifier).map_err(PocoNodeHostErrorV0::core)?;
        let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
            safety_store_path,
            safety_store_profile,
            verifier,
            core.safety_state(),
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let mut signer_journal = SqliteSignerJournalV0::initialize_new(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        let safety_head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        validate_signer_safety_revision_v0(&signer_journal, &safety_head)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signature_producer,
            bootstrap_mode: HostBootstrapModeV0::InitializedGenesis,
            runtime_status: BoundedTimeoutRuntimeStatusV0::Active,
        })
    }

    /// Opens and authenticates an ordinary exact journal head, recovers Core,
    /// and binds the journal to that recovered instance.
    ///
    /// Obligation-bearing or native-invalid-context heads fail before Core
    /// construction. The application-aware validation recovery host remains
    /// the only route for those heads.
    pub fn open_existing(
        config: PocoNodeStartConfigV0,
        external_watermark: W,
        signature_producer: P,
    ) -> Result<Self, PocoNodeHostErrorV0> {
        reject_activation_request(&config)?;
        let core_config = config.core_config().clone();
        let PocoNodeStartConfigV0 {
            safety_store_path,
            safety_store_profile,
            signer_journal_path,
            signer_journal_profile,
        } = config;
        let verifier = StrictEd25519Verifier;
        let mut safety_store = SqliteSafetyStateStoreV0::open_existing(
            safety_store_path,
            safety_store_profile,
            verifier,
        )
        .map_err(PocoNodeHostErrorV0::safety_store)?;
        let head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        if !matches!(
            head.transition_context(),
            SafetyTransitionContextV0::Ordinary
        ) || head_has_current_invalid_completion_v0(head.state())
        {
            return Err(PocoNodeHostErrorV0::ValidationRecoveryAwareOpenRequired {
                revision: head.revision(),
            });
        }
        let obligation_count = head.state().payload_validation_obligations().len();
        if obligation_count != 0 {
            return Err(
                PocoNodeHostErrorV0::AuthenticatedObligationReplayUnavailable {
                    revision: head.revision(),
                    obligation_count,
                },
            );
        }
        validate_bounded_timeout_bootstrap_v0(&head)?;
        let mut signer_journal = SqliteSignerJournalV0::open_existing(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let core = Core::recover(core_config, head.state().clone(), &verifier)
            .map_err(PocoNodeHostErrorV0::core)?;
        if core.safety_state() != head.state() {
            return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
        }
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        validate_signer_safety_revision_v0(&signer_journal, &head)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signature_producer,
            bootstrap_mode: HostBootstrapModeV0::RecoveredExisting,
            runtime_status: BoundedTimeoutRuntimeStatusV0::Active,
        })
    }

    pub const fn bootstrap_mode(&self) -> HostBootstrapModeV0 {
        self.bootstrap_mode
    }

    pub const fn lifecycle_phase(&self) -> HostLifecyclePhaseV0 {
        HostLifecyclePhaseV0::BoundedTimeoutSigning
    }

    pub const fn core_config(&self) -> &CoreConfig {
        self.core.config()
    }

    /// Exposes state facts, not the live Core or a persistence binding.
    pub const fn safety_state(&self) -> &SafetyState {
        self.core.safety_state()
    }

    pub fn safety_store_path(&self) -> &Path {
        self.safety_store.path()
    }

    pub fn signer_journal_path(&self) -> &Path {
        self.signer_journal.path()
    }

    /// Authenticates and returns the current exact external/local signer head.
    ///
    /// This is fallible and mutable because a failed sign attempt may have
    /// advanced one durable side of the local/external join. No cached value is
    /// presented as authoritative after such a window.
    pub fn signer_journal_head(&mut self) -> Result<SignerWatermarkV0, PocoNodeHostErrorV0> {
        self.signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)
    }

    pub fn signer_journal_capacity(&self) -> Result<JournalCapacityV0, PocoNodeHostErrorV0> {
        self.signer_journal
            .capacity()
            .map_err(PocoNodeHostErrorV0::signer_journal)
    }

    pub fn safety_head(&self) -> Result<RecoveredSafetyStateV0, PocoNodeHostErrorV0> {
        self.safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
    }

    /// Resumes only the authenticated durable outbox already owned by Core.
    ///
    /// In this slice an idle Core yields its timer, while an exact persisted
    /// timeout sign intent is journaled/signed/replayed and converted to an
    /// outbound message. Every other production effect remains fail-closed.
    pub fn resume_v0(&mut self) -> Result<Vec<PocoNodeHostActionV0>, PocoNodeHostErrorV0> {
        self.require_active_runtime_v0()?;
        let result = (|| {
            let effects = self
                .core
                .step(Input::Resume, &StrictEd25519Verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            self.drive_bounded_effects_v0(effects)
        })();
        self.finish_runtime_call_v0(result)
    }

    /// Drives one local timeout for the exact epoch/view currently held by
    /// Core. Callers cannot supply or advance either consensus coordinate.
    pub fn on_local_timeout_v0(
        &mut self,
    ) -> Result<Vec<PocoNodeHostActionV0>, PocoNodeHostErrorV0> {
        self.require_active_runtime_v0()?;
        let result = (|| {
            let epoch = self.core.safety_state().epoch();
            let view = self.core.safety_state().current_view();
            let effects = self
                .core
                .step(Input::LocalTimeout { epoch, view }, &StrictEd25519Verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            self.drive_bounded_effects_v0(effects)
        })();
        self.finish_runtime_call_v0(result)
    }

    /// Required-feature-only observation of exact process-SIGKILL boundaries.
    ///
    /// The observer cannot alter an input, persistence request, sign intent,
    /// signature, or Core effect. The process helper uses it only to announce
    /// and hold a child at a named userspace boundary before the parent sends
    /// SIGKILL.
    #[cfg(feature = "recovery-process-test-support")]
    #[doc(hidden)]
    pub fn on_local_timeout_with_process_checkpoint_observer_v0<F>(
        &mut self,
        observer: &mut F,
    ) -> Result<Vec<PocoNodeHostActionV0>, PocoNodeHostErrorV0>
    where
        F: FnMut(PocoNodeTimeoutSigningProcessCheckpointPhaseV0),
    {
        self.require_active_runtime_v0()?;
        let result = (|| {
            let epoch = self.core.safety_state().epoch();
            let view = self.core.safety_state().current_view();
            let effects = self
                .core
                .step(Input::LocalTimeout { epoch, view }, &StrictEd25519Verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            self.drive_bounded_effects_with_checkpoint_v0(effects, Some(observer))
        })();
        self.finish_runtime_call_v0(result)
    }

    #[cfg(test)]
    pub(crate) fn drive_test_effects_v0(
        &mut self,
        effects: Vec<Effect>,
    ) -> Result<Vec<PocoNodeHostActionV0>, PocoNodeHostErrorV0> {
        self.drive_bounded_effects_v0(effects)
    }

    fn drive_bounded_effects_v0(
        &mut self,
        effects: Vec<Effect>,
    ) -> Result<Vec<PocoNodeHostActionV0>, PocoNodeHostErrorV0> {
        #[cfg(feature = "recovery-process-test-support")]
        {
            self.drive_bounded_effects_with_checkpoint_v0(effects, None)
        }
        #[cfg(not(feature = "recovery-process-test-support"))]
        {
            self.drive_bounded_effects_with_checkpoint_v0(effects)
        }
    }

    fn require_active_runtime_v0(&self) -> Result<(), PocoNodeHostErrorV0> {
        if self.runtime_status == BoundedTimeoutRuntimeStatusV0::FailStopped {
            return Err(PocoNodeHostErrorV0::BoundedTimeoutHostFailStopped);
        }
        Ok(())
    }

    fn finish_runtime_call_v0<T>(
        &mut self,
        result: Result<T, PocoNodeHostErrorV0>,
    ) -> Result<T, PocoNodeHostErrorV0> {
        if result
            .as_ref()
            .is_err_and(|error| !is_retryable_exact_timeout_error_v0(error))
        {
            self.runtime_status = BoundedTimeoutRuntimeStatusV0::FailStopped;
        }
        result
    }

    fn drive_bounded_effects_with_checkpoint_v0(
        &mut self,
        effects: Vec<Effect>,
        #[cfg(feature = "recovery-process-test-support")] mut checkpoint: Option<
            &mut dyn FnMut(PocoNodeTimeoutSigningProcessCheckpointPhaseV0),
        >,
    ) -> Result<Vec<PocoNodeHostActionV0>, PocoNodeHostErrorV0> {
        validate_bounded_effect_batch_v0(&effects)?;
        let mut pending = VecDeque::from(effects);
        let mut actions = Vec::new();
        let mut processed = 0_usize;
        let mut freshly_persisted_signing_revision = None;
        let mut pending_signed_outbound = None;
        while let Some(effect) = pending.pop_front() {
            processed = processed
                .checked_add(1)
                .ok_or(PocoNodeHostErrorV0::BoundedEffectLimitExceeded)?;
            if processed > MAXIMUM_BOUNDED_HOST_EFFECTS_PER_CALL_V0 {
                return Err(PocoNodeHostErrorV0::BoundedEffectLimitExceeded);
            }
            let next = match effect {
                Effect::PersistSafetyState(request) => {
                    if freshly_persisted_signing_revision.is_some() {
                        return Err(PocoNodeHostErrorV0::MultipleBoundedPersistenceEffects);
                    }
                    let barrier = request.barrier();
                    self.safety_store
                        .persist_exact_v0(&request, &SafetyTransitionContextV0::ordinary())
                        .map_err(PocoNodeHostErrorV0::safety_store)?;
                    let confirmed = self
                        .safety_store
                        .head()
                        .map_err(PocoNodeHostErrorV0::safety_store)?;
                    if confirmed.revision() != barrier.get()
                        || confirmed.state() != request.state()
                        || !matches!(
                            confirmed.transition_context(),
                            SafetyTransitionContextV0::Ordinary
                        )
                    {
                        return Err(PocoNodeHostErrorV0::OrdinaryPersistenceReadbackMismatch {
                            expected_revision: barrier.get(),
                            actual_revision: confirmed.revision(),
                        });
                    }
                    let pending_sign = confirmed.state().pending_sign().ok_or(
                        PocoNodeHostErrorV0::MissingTimeoutIntentAfterPersistence {
                            revision: confirmed.revision(),
                        },
                    )?;
                    if !matches!(pending_sign, SignIntent::TimeoutVote { .. }) {
                        return Err(PocoNodeHostErrorV0::UnsupportedTimeoutSigningIntentKind);
                    }
                    if pending_sign.authorizing_safety_revision() != confirmed.revision() {
                        return Err(PocoNodeHostErrorV0::SignIntentSafetyRevisionMismatch {
                            intent_revision: pending_sign.authorizing_safety_revision(),
                            safety_revision: confirmed.revision(),
                        });
                    }
                    validate_bounded_timeout_bootstrap_v0(&confirmed)?;
                    validate_signer_safety_revision_v0(&self.signer_journal, &confirmed)?;
                    freshly_persisted_signing_revision = Some(confirmed.revision());
                    #[cfg(feature = "recovery-process-test-support")]
                    if let Some(observer) = checkpoint.as_deref_mut() {
                        observer(
                            PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SafetyPersistedBeforeStorageAck,
                        );
                    }
                    self.core
                        .step(Input::StorageAck { barrier }, &StrictEd25519Verifier)
                        .map_err(PocoNodeHostErrorV0::core)?
                }
                Effect::RequestSignature { intent } => {
                    if !matches!(intent.preimage(), CanonicalSignPreimageV0::TimeoutVote(_)) {
                        return Err(PocoNodeHostErrorV0::UnsupportedTimeoutSigningIntentKind);
                    }
                    let confirmed = self
                        .safety_store
                        .head()
                        .map_err(PocoNodeHostErrorV0::safety_store)?;
                    if !matches!(
                        confirmed.transition_context(),
                        SafetyTransitionContextV0::Ordinary
                    ) {
                        return Err(PocoNodeHostErrorV0::NonOrdinarySigningHead {
                            revision: confirmed.revision(),
                        });
                    }
                    validate_bounded_timeout_bootstrap_v0(&confirmed)?;
                    if self.core.safety_state() != confirmed.state() {
                        return Err(PocoNodeHostErrorV0::SigningCoreSafetyHeadMismatch {
                            core_revision: self.core.safety_state().revision(),
                            safety_revision: confirmed.revision(),
                        });
                    }
                    let durable_intent = confirmed.state().pending_sign().ok_or(
                        PocoNodeHostErrorV0::MissingDurableTimeoutSignIntent {
                            revision: confirmed.revision(),
                        },
                    )?;
                    if !matches!(durable_intent, SignIntent::TimeoutVote { .. })
                        || durable_intent.authorizing_safety_revision()
                            != intent.authorizing_safety_revision()
                        || durable_intent.view() != intent.preimage().context().view()
                        || durable_intent.signing_root() != intent.signing_root()
                    {
                        return Err(PocoNodeHostErrorV0::DurableSignIntentMismatch {
                            revision: confirmed.revision(),
                        });
                    }
                    validate_signer_safety_revision_v0(&self.signer_journal, &confirmed)?;
                    if intent.authorizing_safety_revision() == 0
                        || intent.authorizing_safety_revision() > confirmed.revision()
                    {
                        return Err(PocoNodeHostErrorV0::SignIntentSafetyRevisionMismatch {
                            intent_revision: intent.authorizing_safety_revision(),
                            safety_revision: confirmed.revision(),
                        });
                    }
                    if let Some(fresh_revision) = freshly_persisted_signing_revision {
                        if intent.authorizing_safety_revision() != fresh_revision {
                            return Err(PocoNodeHostErrorV0::SignIntentSafetyRevisionMismatch {
                                intent_revision: intent.authorizing_safety_revision(),
                                safety_revision: fresh_revision,
                            });
                        }
                    }
                    if pending_signed_outbound.is_some() {
                        return Err(PocoNodeHostErrorV0::MultipleSignedOutboundContexts);
                    }
                    #[cfg(feature = "recovery-process-test-support")]
                    if let Some(observer) = checkpoint.as_deref_mut() {
                        observer(
                            PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SignatureRequestedBeforeJournal,
                        );
                    }
                    let signature = self
                        .signer_journal
                        .sign_exact_v0(&intent, &mut self.signature_producer)
                        .map_err(PocoNodeHostErrorV0::signer_journal)?;
                    self.signer_journal
                        .external_head()
                        .map_err(PocoNodeHostErrorV0::signer_journal)?;
                    let after_sign = self
                        .safety_store
                        .head()
                        .map_err(PocoNodeHostErrorV0::safety_store)?;
                    if after_sign != confirmed || after_sign.state() != self.core.safety_state() {
                        return Err(PocoNodeHostErrorV0::SigningHeadChangedDuringProducer {
                            before_revision: confirmed.revision(),
                            after_revision: after_sign.revision(),
                        });
                    }
                    validate_signer_safety_revision_v0(&self.signer_journal, &after_sign)?;
                    pending_signed_outbound = Some(PendingSignedOutboundV0 {
                        intent_fingerprint: intent.fingerprint(),
                        authorizing_safety_revision: intent.authorizing_safety_revision(),
                        signing_root: intent.signing_root(),
                        signature,
                    });
                    #[cfg(feature = "recovery-process-test-support")]
                    if let Some(observer) = checkpoint.as_deref_mut() {
                        observer(
                            PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SignaturePersistedBeforeSignatureReady,
                        );
                    }
                    self.core
                        .step(
                            Input::SignatureReady {
                                id: SignId::new(intent.signing_root()),
                                signature,
                            },
                            &StrictEd25519Verifier,
                        )
                        .map_err(PocoNodeHostErrorV0::core)?
                }
                Effect::Broadcast(message) => {
                    let signed = pending_signed_outbound
                        .take()
                        .ok_or(PocoNodeHostErrorV0::MissingSignedOutboundContext)?;
                    let OutboundMessage::TimeoutVote(timeout_vote) = &message else {
                        return Err(PocoNodeHostErrorV0::UnsupportedTimeoutSigningIntentKind);
                    };
                    if timeout_vote.signing_root() != signed.signing_root
                        || timeout_vote.signature() != &signed.signature
                    {
                        return Err(PocoNodeHostErrorV0::SignedOutboundMismatch);
                    }
                    let outbound = PocoNodeSignedOutboundV0 {
                        intent_fingerprint: signed.intent_fingerprint,
                        authorizing_safety_revision: signed.authorizing_safety_revision,
                        message,
                    };
                    #[cfg(feature = "recovery-process-test-support")]
                    if let Some(observer) = checkpoint.as_deref_mut() {
                        observer(
                            PocoNodeTimeoutSigningProcessCheckpointPhaseV0::BroadcastProducedBeforeReturn,
                        );
                    }
                    actions.push(PocoNodeHostActionV0::Broadcast(Box::new(outbound)));
                    Vec::new()
                }
                Effect::ArmViewTimer { epoch, view } => {
                    actions.push(PocoNodeHostActionV0::ArmViewTimer { epoch, view });
                    Vec::new()
                }
                Effect::SafetyHalted(halt) => {
                    actions.push(PocoNodeHostActionV0::SafetyHalted(halt));
                    Vec::new()
                }
                effect => {
                    return Err(PocoNodeHostErrorV0::UnsupportedBoundedHostEffect {
                        effect: effect_name_v0(&effect),
                    });
                }
            };
            validate_bounded_effect_batch_v0(&next)?;
            for effect in next.into_iter().rev() {
                pending.push_front(effect);
            }
        }
        if pending_signed_outbound.is_some() {
            return Err(PocoNodeHostErrorV0::UnconsumedSignedOutboundContext);
        }
        Ok(actions)
    }

    /// No production-running state is constructible in this slice.
    pub fn production_activation_check(&self) -> Result<(), ProductionActivationBlockedV0> {
        Err(ProductionActivationBlockedV0::new())
    }
}

fn is_retryable_exact_timeout_error_v0(error: &PocoNodeHostErrorV0) -> bool {
    match error {
        PocoNodeHostErrorV0::SignerJournal(error) => matches!(
            error.as_ref(),
            SignerJournalErrorV0::SignatureProducer(SignatureProducerErrorV0::Unavailable)
                | SignerJournalErrorV0::ExternalWatermark {
                    source: ExternalWatermarkErrorV0::Unavailable,
                    ..
                }
        ),
        _ => false,
    }
}

fn validate_bounded_timeout_bootstrap_v0(
    safety_head: &RecoveredSafetyStateV0,
) -> Result<(), PocoNodeHostErrorV0> {
    if matches!(
        safety_head.state().pending_sign(),
        Some(SignIntent::Vote { .. })
    ) {
        return Err(PocoNodeHostErrorV0::UnsupportedTimeoutSigningIntentKind);
    }
    if safety_head.state().pending_finalize().is_some() {
        return Err(PocoNodeHostErrorV0::UnsupportedBoundedBootstrapState {
            revision: safety_head.revision(),
            state: "pending_finalize",
        });
    }
    if safety_head.state().pending_tc_high_qc_sync().is_some() {
        return Err(PocoNodeHostErrorV0::UnsupportedBoundedBootstrapState {
            revision: safety_head.revision(),
            state: "pending_tc_high_qc_sync",
        });
    }
    if safety_head.state().pending_standalone_qc_sync().is_some() {
        return Err(PocoNodeHostErrorV0::UnsupportedBoundedBootstrapState {
            revision: safety_head.revision(),
            state: "pending_standalone_qc_sync",
        });
    }
    Ok(())
}

fn validate_bounded_effect_batch_v0(effects: &[Effect]) -> Result<(), PocoNodeHostErrorV0> {
    if let Some(effect) = effects.iter().find(|effect| {
        !matches!(
            effect,
            Effect::PersistSafetyState(_)
                | Effect::RequestSignature { .. }
                | Effect::Broadcast(_)
                | Effect::ArmViewTimer { .. }
                | Effect::SafetyHalted(_)
        )
    }) {
        return Err(PocoNodeHostErrorV0::UnsupportedBoundedHostEffect {
            effect: effect_name_v0(effect),
        });
    }
    Ok(())
}
