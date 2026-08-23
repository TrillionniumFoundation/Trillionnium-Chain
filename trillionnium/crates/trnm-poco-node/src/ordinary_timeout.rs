use std::{collections::VecDeque, path::Path};

#[cfg(feature = "node-event-wal")]
use sha2::{Digest, Sha256};

use trnm_consensus_core::{
    Core, CoreConfig, Effect, Input, OutboundMessage, SafetyHalt, SafetyState, SignId, SignIntent,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
#[cfg(feature = "safety-rules-sidecar")]
use trnm_consensus_safety_rules::SafetyRulesDurableTransitionStoreV1;
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

#[cfg(feature = "safety-rules-sidecar")]
use crate::safety_rules_sidecar::{
    clear_pending_timeout_marker_v1, load_pending_timeout_marker_v1,
    write_pending_timeout_marker_v1, PendingTimeoutMarkerV1, SafetyRulesSemanticSidecarV1,
};
use crate::{
    effect_name_v0, head_has_current_invalid_completion_v0, reject_activation_request,
    validate_signer_safety_revision_v0, HostBootstrapModeV0, HostLifecyclePhaseV0,
    PocoNodeHostErrorV0, PocoNodeStartConfigV0, ProductionActivationBlockedV0,
};

#[cfg(feature = "node-event-wal")]
use crate::node_event_wal::{
    NodeEventCommitReceiptV1, NodeEventIntentV1, NodeEventRecoveryV1, NodeEventWalV1,
    PocoNodeHostEventWalErrorV1,
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

#[cfg(feature = "node-event-wal")]
const HOST_TIMEOUT_EVENT_DOMAIN_V1: &[u8] = b"trnm.poco-node.timeout-event.v1\0";

/// Exact projection used to bind one timeout event to the host's authenticated
/// SafetyStore predecessor.  It is deliberately private: callers obtain an
/// intent only through [`PocoNodeHostV0::prepare_timeout_event_v1`], after the
/// host has re-derived the transition from its own Core state.
#[cfg(feature = "node-event-wal")]
#[derive(Debug, Clone)]
struct TimeoutEventProjectionV1 {
    predecessor_record_checksum: [u8; 32],
    event_id: [u8; 32],
    payload_digest: [u8; 32],
    expected_revision: u64,
    expected_successor_state: SafetyState,
}

#[cfg(feature = "node-event-wal")]
fn timeout_event_id_v1(
    predecessor_record_checksum: [u8; 32],
    payload_digest: [u8; 32],
    expected_revision: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HOST_TIMEOUT_EVENT_DOMAIN_V1);
    hasher.update(predecessor_record_checksum);
    hasher.update(payload_digest);
    hasher.update(expected_revision.to_be_bytes());
    hasher.finalize().into()
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
    #[cfg(feature = "safety-rules-sidecar")]
    pending_timeout_marker: Option<PendingTimeoutMarkerV1>,
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
            #[cfg(feature = "safety-rules-sidecar")]
            pending_timeout_marker: None,
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
        #[cfg(feature = "safety-rules-sidecar")]
        if let Some(marker) = load_pending_timeout_marker_v1(safety_store.path())
            .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?
        {
            return Err(
                PocoNodeHostErrorV0::SafetyRulesSidecarPendingRecoveryRequired {
                    revision: marker.revision(),
                },
            );
        }
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
            #[cfg(feature = "safety-rules-sidecar")]
            pending_timeout_marker: None,
        })
    }

    /// Explicitly repairs one durable timeout transition after the process
    /// crashed in the window guarded by the SafetyRules semantic sidecar
    /// marker.  Ordinary `open_existing` intentionally remains fail-closed;
    /// callers must present the independently administered sidecar namespace
    /// and capability so a copied marker cannot select a different authority.
    ///
    /// This is a one-shot repair owner.  It never signs during repair and it
    /// does not enable production activation.  After the marker is cleared,
    /// `resume_v0` replays the exact durable timeout intent through the normal
    /// signer-journal path.
    #[cfg(feature = "safety-rules-sidecar")]
    pub fn open_existing_with_safety_rules_external_v1<SW>(
        config: PocoNodeStartConfigV0,
        external_watermark: W,
        signature_producer: P,
        safety_rules_external: SW,
        scope: [u8; 32],
        journal_id: [u8; 32],
        capability: [u8; 32],
    ) -> Result<Self, PocoNodeHostErrorV0>
    where
        SW: ExternalMonotonicWatermarkV0,
    {
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
        let safety_journal_id = safety_store.journal_id_v0();
        let marker = load_pending_timeout_marker_v1(safety_store.path())
            .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?
            .ok_or(PocoNodeHostErrorV0::SafetyRulesSidecarRecoveryNotPending)?;
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

        // Authenticate the signer namespace, profile, external watermark,
        // and durable journal identity before touching either recovery
        // authority.  A shape-valid but foreign signer database must never be
        // able to consume this marker and leave the sidecar/SafetyStore
        // advanced under a different signing owner.
        let mut signer_journal = SqliteSignerJournalV0::open_existing(
            signer_journal_path,
            signer_journal_profile,
            external_watermark,
        )
        .map_err(PocoNodeHostErrorV0::signer_journal)?;
        signer_journal
            .external_head()
            .map_err(PocoNodeHostErrorV0::signer_journal)?;
        let signer_journal_id = signer_journal.journal_id();
        if marker.signer_journal_id().is_none() {
            return Err(PocoNodeHostErrorV0::safety_rules_sidecar(
                crate::safety_rules_sidecar::SafetyRulesSemanticSidecarErrorV1::PendingMarkerSignerIdentityUnavailable,
            ));
        }
        if !marker.matches_signer_journal(signer_journal_id) {
            return Err(PocoNodeHostErrorV0::safety_rules_sidecar(
                crate::safety_rules_sidecar::SafetyRulesSemanticSidecarErrorV1::PendingMarkerSignerIdentityMismatch,
            ));
        }
        validate_signer_safety_revision_v0(&signer_journal, &head)?;

        // A marker can survive either side of the local SQLite boundary.  If
        // the authenticated head is already the marker's successor, obtain
        // the journal's retained predecessor and regenerate the transition
        // from that state.  Calling LocalTimeout on the successor itself
        // would be rejected as a concurrent sign intent and would make the
        // recovery owner unable to handle the SQLite-before-clear window.
        let retained_predecessor = if head.revision() == marker.revision()
            && matches!(
                head.state().pending_sign(),
                Some(SignIntent::TimeoutVote { .. })
            ) {
            let predecessor = safety_store
                .authenticated_predecessor_v0()
                .map_err(PocoNodeHostErrorV0::safety_store)?
                .ok_or(PocoNodeHostErrorV0::RecoveredTransitionHeadMismatch)?;
            if !matches!(
                predecessor.transition_context(),
                SafetyTransitionContextV0::Ordinary
            ) || head_has_current_invalid_completion_v0(predecessor.state())
            {
                return Err(PocoNodeHostErrorV0::ValidationRecoveryAwareOpenRequired {
                    revision: predecessor.revision(),
                });
            }
            validate_bounded_timeout_bootstrap_v0(&predecessor)?;
            Some(predecessor)
        } else {
            None
        };
        let predecessor_state = retained_predecessor
            .as_ref()
            .map_or(head.state(), RecoveredSafetyStateV0::state);

        // Recompute the exact Core transition from the authenticated local
        // predecessor.  No marker field is trusted as a substitute for this
        // deterministic reconstruction.
        let mut predecessor_core =
            Core::recover(core_config.clone(), predecessor_state.clone(), &verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
        // Capture the binding for the authenticated local predecessor before
        // LocalTimeout mutates this Core into its successor. The SafetyStore
        // must be affined to the state it currently owns before the recovered
        // transition is persisted.
        let predecessor_binding = predecessor_core.safety_state_persistence_binding_v0();
        let epoch = predecessor_core.safety_state().epoch();
        let view = predecessor_core.safety_state().current_view();
        let effects = predecessor_core
            .step(Input::LocalTimeout { epoch, view }, &verifier)
            .map_err(PocoNodeHostErrorV0::core)?;
        let request = match effects.as_slice() {
            [Effect::PersistSafetyState(request)] => request,
            [] => {
                return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffectSet {
                    expected: 1,
                    actual: 0,
                })
            }
            _ => {
                return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffectSet {
                    expected: 1,
                    actual: effects.len(),
                })
            }
        };
        let transition = request.safety_rules_shadow_transition_v1().ok_or(
            PocoNodeHostErrorV0::SafetyRulesShadowTransitionMismatch {
                revision: request.barrier().get(),
            },
        )?;
        let mut sidecar = SafetyRulesSemanticSidecarV1::open(
            safety_rules_external,
            scope,
            journal_id,
            capability,
            transition.predecessor_state_digest(),
        )
        .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?;
        let namespace_digest = sidecar.namespace_digest_v1();
        if !marker.matches_namespace(namespace_digest, safety_journal_id)
            || !marker.matches_transition(transition, namespace_digest, safety_journal_id)
        {
            return Err(PocoNodeHostErrorV0::safety_rules_sidecar(
                crate::safety_rules_sidecar::SafetyRulesSemanticSidecarErrorV1::PendingMarkerConflict,
            ));
        }

        let predecessor_digest = transition.predecessor_state_digest();
        let successor_state = request.state();
        let local_is_successor = retained_predecessor.is_some() && head.state() == successor_state;
        let local_is_predecessor = retained_predecessor.is_none()
            && head.state() != successor_state
            && head
                .revision()
                .checked_add(1)
                .is_some_and(|revision| revision == request.barrier().get());
        if !local_is_predecessor && !local_is_successor {
            return Err(PocoNodeHostErrorV0::RecoveredTransitionHeadMismatch);
        }
        let external_exact = sidecar.observed_transition_matches_v1(transition);
        if local_is_successor && !external_exact {
            // The write order is marker -> sidecar -> SQLite.  A successor
            // local head without this exact external target is therefore an
            // impossible or tampered combination.
            return Err(PocoNodeHostErrorV0::RecoveredTransitionHeadMismatch);
        }
        if external_exact {
            // Exact retry after an external CAS: sidecar's in-memory binding
            // must name the regenerated successor before it re-reads the
            // external target/facts.
            sidecar.rebind_state_digest(transition.successor_state().digest());
        } else {
            sidecar.rebind_state_digest(predecessor_digest);
        }
        sidecar
            .persist_transition_v1(transition)
            .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?;

        let core = if local_is_predecessor {
            safety_store
                .bind_core_v0(predecessor_binding)
                .map_err(PocoNodeHostErrorV0::safety_store)?;
            safety_store
                .persist_exact_v0(request, &SafetyTransitionContextV0::ordinary())
                .map_err(PocoNodeHostErrorV0::safety_store)?;
            let confirmed = safety_store
                .head()
                .map_err(PocoNodeHostErrorV0::safety_store)?;
            if confirmed.state() != successor_state
                || confirmed.revision() != request.barrier().get()
            {
                return Err(PocoNodeHostErrorV0::OrdinaryPersistenceReadbackMismatch {
                    expected_revision: request.barrier().get(),
                    actual_revision: confirmed.revision(),
                });
            }
            let ack_effects = predecessor_core
                .step(
                    Input::StorageAck {
                        barrier: request.barrier(),
                    },
                    &verifier,
                )
                .map_err(PocoNodeHostErrorV0::core)?;
            if !matches!(ack_effects.as_slice(), [Effect::RequestSignature { .. }]) {
                return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffectSet {
                    expected: 1,
                    actual: ack_effects.len(),
                });
            }
            predecessor_core
        } else {
            let successor_core = Core::recover(core_config, successor_state.clone(), &verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            if successor_core.safety_state() != successor_state {
                return Err(PocoNodeHostErrorV0::RecoveredHeadMismatch);
            }
            safety_store
                .bind_core_v0(successor_core.safety_state_persistence_binding_v0())
                .map_err(PocoNodeHostErrorV0::safety_store)?;
            successor_core
        };

        let recovered_head = safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        validate_signer_safety_revision_v0(&signer_journal, &recovered_head)?;
        // Keep the fence in place until every local authority needed by the
        // returned owner has been authenticated.  If signer-journal reopen or
        // the final revision join fails, a later explicit recovery can retry
        // against the same marker and exact sidecar target.
        clear_pending_timeout_marker_v1(safety_store.path(), marker)
            .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?;
        Ok(Self {
            core,
            safety_store,
            signer_journal,
            signature_producer,
            bootstrap_mode: HostBootstrapModeV0::RecoveredExisting,
            runtime_status: BoundedTimeoutRuntimeStatusV0::Active,
            pending_timeout_marker: None,
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

    /// Derive the timeout event tuple from the authenticated SafetyStore
    /// predecessor and a throw-away Core evaluator.  The live Core is not
    /// mutated while an event intent is being prepared; the returned tuple is
    /// therefore comparison material for the WAL, not an effect capability.
    #[cfg(feature = "node-event-wal")]
    fn timeout_event_projection_from_state_v1(
        &self,
        predecessor_state: &SafetyState,
        predecessor_record_checksum: [u8; 32],
    ) -> Result<TimeoutEventProjectionV1, PocoNodeHostEventWalErrorV1> {
        let mut evaluator = Core::recover(
            self.core.config().clone(),
            predecessor_state.clone(),
            &StrictEd25519Verifier,
        )
        .map_err(PocoNodeHostErrorV0::core)
        .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        let epoch = predecessor_state.epoch();
        let view = predecessor_state.current_view();
        let effects = evaluator
            .step(Input::LocalTimeout { epoch, view }, &StrictEd25519Verifier)
            .map_err(PocoNodeHostErrorV0::core)
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        let request = match effects.as_slice() {
            [Effect::PersistSafetyState(request)] => request,
            _ => return Err(PocoNodeHostEventWalErrorV1::BindingMismatch),
        };
        let transition = request
            .safety_rules_shadow_transition_v1()
            .ok_or(PocoNodeHostEventWalErrorV1::BindingMismatch)?;
        let Some(SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view: pending_view,
            signing_root,
            ..
        }) = request.state().pending_sign()
        else {
            return Err(PocoNodeHostEventWalErrorV1::BindingMismatch);
        };
        let canonical = transition.canonical_intent();
        let expected_revision = request.barrier().get();
        if transition.successor_state().revision() != expected_revision
            || transition.successor_state().last_timeout_view() != Some(*pending_view)
            || canonical.authorizing_safety_revision() != *authorizing_safety_revision
            || canonical.preimage().context().view() != *pending_view
            || canonical.signing_root() != *signing_root
            || !matches!(
                canonical.preimage(),
                CanonicalSignPreimageV0::TimeoutVote(_)
            )
        {
            return Err(PocoNodeHostEventWalErrorV1::BindingMismatch);
        }
        let payload_digest = transition.candidate_digest().into_bytes();
        let event_id = timeout_event_id_v1(
            predecessor_record_checksum,
            payload_digest,
            expected_revision,
        );
        Ok(TimeoutEventProjectionV1 {
            predecessor_record_checksum,
            event_id,
            payload_digest,
            expected_revision,
            expected_successor_state: request.state().clone(),
        })
    }

    #[cfg(feature = "node-event-wal")]
    fn timeout_event_projection_v1(
        &self,
    ) -> Result<TimeoutEventProjectionV1, PocoNodeHostEventWalErrorV1> {
        let head = self
            .safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        if !matches!(
            head.transition_context(),
            SafetyTransitionContextV0::Ordinary
        ) || head.state() != self.core.safety_state()
            || head.state().pending_sign().is_some()
        {
            return Err(PocoNodeHostEventWalErrorV1::BindingMismatch);
        }
        validate_bounded_timeout_bootstrap_v0(&head).map_err(PocoNodeHostEventWalErrorV1::Host)?;
        self.timeout_event_projection_from_state_v1(head.state(), head.state_record_checksum())
    }

    #[cfg(feature = "node-event-wal")]
    fn validate_timeout_event_intent_v1(
        &self,
        intent: NodeEventIntentV1,
        projection: &TimeoutEventProjectionV1,
    ) -> Result<(), PocoNodeHostEventWalErrorV1> {
        if intent.event_id() != projection.event_id
            || intent.predecessor_digest() != projection.predecessor_record_checksum
            || intent.payload_digest() != projection.payload_digest
        {
            return Err(PocoNodeHostEventWalErrorV1::BindingMismatch);
        }
        Ok(())
    }

    #[cfg(feature = "node-event-wal")]
    fn timeout_event_readback_v1(
        &self,
        projection: &TimeoutEventProjectionV1,
    ) -> Result<[u8; 32], PocoNodeHostEventWalErrorV1> {
        let head = self
            .safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        if !matches!(
            head.transition_context(),
            SafetyTransitionContextV0::Ordinary
        ) || head.revision() != projection.expected_revision
            || head.state() != &projection.expected_successor_state
        {
            return Err(PocoNodeHostEventWalErrorV1::BindingMismatch);
        }
        Ok(head.state_record_checksum())
    }

    /// Prepare a timeout intent in the node-event WAL from the host's current
    /// authenticated predecessor.  No Core effect is driven until the caller
    /// invokes [`Self::on_local_timeout_with_event_wal_v1`].
    #[cfg(feature = "node-event-wal")]
    pub fn prepare_timeout_event_v1(
        &self,
        wal: &mut NodeEventWalV1,
    ) -> Result<NodeEventIntentV1, PocoNodeHostEventWalErrorV1> {
        self.require_active_runtime_v0()
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        let projection = self.timeout_event_projection_v1()?;
        wal.prepare_event_v1(
            projection.event_id,
            projection.predecessor_record_checksum,
            projection.payload_digest,
        )
        .map_err(Into::into)
    }

    /// Run one timeout through the real bounded host while enforcing
    /// `event-WAL intent -> Core/SafetyStore effect -> exact SafetyStore
    /// readback -> event-WAL commit` ordering.
    #[cfg(feature = "node-event-wal")]
    pub fn on_local_timeout_with_event_wal_v1(
        &mut self,
        wal: &mut NodeEventWalV1,
    ) -> Result<NodeEventCommitReceiptV1, PocoNodeHostEventWalErrorV1> {
        self.require_active_runtime_v0()
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        let projection = self.timeout_event_projection_v1()?;
        let intent = wal
            .prepare_event_v1(
                projection.event_id,
                projection.predecessor_record_checksum,
                projection.payload_digest,
            )
            .map_err(PocoNodeHostEventWalErrorV1::Wal)?;
        self.on_local_timeout_v0()
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        let commit_digest = self.timeout_event_readback_v1(&projection)?;
        self.validate_timeout_event_intent_v1(intent, &projection)?;
        wal.commit_event_v1(intent, commit_digest)
            .map_err(PocoNodeHostEventWalErrorV1::Wal)
    }

    /// Reconcile a pending timeout event after reopening the host and WAL.
    /// A successor is accepted only when the retained authenticated
    /// predecessor regenerates the exact event tuple and the current head is
    /// an exact successor readback.  If the head is still the predecessor,
    /// the effect remains uncertain and the WAL is deliberately left pending.
    #[cfg(feature = "node-event-wal")]
    pub fn recover_pending_timeout_event_with_wal_v1(
        &mut self,
        wal: &mut NodeEventWalV1,
    ) -> Result<Option<NodeEventCommitReceiptV1>, PocoNodeHostEventWalErrorV1> {
        self.require_active_runtime_v0()
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        let recovery = wal
            .revalidate_v1()
            .map_err(PocoNodeHostEventWalErrorV1::Wal)?;
        let NodeEventRecoveryV1::Pending(intent) = recovery else {
            return Ok(None);
        };
        let head = self
            .safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)
            .map_err(PocoNodeHostEventWalErrorV1::Host)?;
        if head.state_record_checksum() == intent.predecessor_digest() {
            return Err(PocoNodeHostEventWalErrorV1::RecoveryReadbackRequired);
        }
        let predecessor = self
            .safety_store
            .authenticated_predecessor_v0()
            .map_err(PocoNodeHostErrorV0::safety_store)
            .map_err(PocoNodeHostEventWalErrorV1::Host)?
            .ok_or(PocoNodeHostEventWalErrorV1::RecoveryReadbackRequired)?;
        if predecessor.state_record_checksum() != intent.predecessor_digest() {
            return Err(PocoNodeHostEventWalErrorV1::BindingMismatch);
        }
        if predecessor.revision().checked_add(1) != Some(head.revision()) {
            return Err(PocoNodeHostEventWalErrorV1::BindingMismatch);
        }
        let projection = self.timeout_event_projection_from_state_v1(
            predecessor.state(),
            predecessor.state_record_checksum(),
        )?;
        self.validate_timeout_event_intent_v1(intent, &projection)?;
        let commit_digest = self.timeout_event_readback_v1(&projection)?;
        wal.commit_event_v1(intent, commit_digest)
            .map(Some)
            .map_err(PocoNodeHostEventWalErrorV1::Wal)
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

    /// Drives one local timeout while binding Core's exact comparison-only
    /// SafetyRules transition to an independently durable semantic sidecar.
    ///
    /// The sidecar CAS is deliberately performed before the local SQLite
    /// SafetyStore write.  If either boundary fails, this host call is
    /// terminally fail-stopped; a caller must not retry because the sidecar
    /// may already have advanced even when the local write did not.  This is
    /// an explicit composition seam only: it does not enable production
    /// activation or make the inert SafetyRules kernel authoritative.
    #[cfg(feature = "safety-rules-sidecar")]
    pub fn on_local_timeout_with_safety_rules_sidecar_v1<SW>(
        &mut self,
        sidecar: &mut SafetyRulesSemanticSidecarV1<SW>,
    ) -> Result<Vec<PocoNodeHostActionV0>, PocoNodeHostErrorV0>
    where
        SW: ExternalMonotonicWatermarkV0,
    {
        self.require_active_runtime_v0()?;
        let result = (|| {
            // Evaluate the transition on a freshly recovered, throw-away
            // Core first.  The live Core must not mutate its SafetyState
            // until the independently administered semantic CAS has accepted
            // the exact transition tuple.  The scratch owner carries no
            // persistence affinity that can be installed into the live owner;
            // its effects are comparison material only.
            let predecessor = self.core.safety_state().clone();
            let core_config = self.core.config().clone();
            let epoch = predecessor.epoch();
            let view = predecessor.current_view();
            let mut evaluator =
                Core::recover(core_config, predecessor.clone(), &StrictEd25519Verifier)
                    .map_err(PocoNodeHostErrorV0::core)?;
            let evaluated_effects = evaluator
                .step(Input::LocalTimeout { epoch, view }, &StrictEd25519Verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            let marker = persist_timeout_shadow_sidecar_before_sqlite_v1(
                self.safety_store.path(),
                self.safety_store.journal_id_v0(),
                self.signer_journal.journal_id(),
                &evaluated_effects,
                sidecar,
            )?;
            self.pending_timeout_marker = Some(marker);

            // Re-check the live owner immediately before installation.  A
            // concurrent caller cannot normally obtain this non-Clone host,
            // but treating any divergence as a hard fence keeps the CAS and
            // Core state affine even if a future owner wrapper changes.
            if self.core.safety_state() != &predecessor {
                return Err(PocoNodeHostErrorV0::SafetyRulesShadowTransitionMismatch {
                    revision: predecessor.revision().saturating_add(1),
                });
            }
            let effects = self
                .core
                .step(Input::LocalTimeout { epoch, view }, &StrictEd25519Verifier)
                .map_err(PocoNodeHostErrorV0::core)?;
            if effects != evaluated_effects {
                return Err(PocoNodeHostErrorV0::SafetyRulesShadowTransitionMismatch {
                    revision: predecessor.revision().saturating_add(1),
                });
            }
            self.drive_bounded_effects_v0(effects)
        })();
        self.finish_runtime_call_v0(result)
    }

    /// Test-only crash injection point immediately after the external
    /// semantic reservation and before the local SafetyStore write.  Keeping
    /// this inside the owner ensures the fixture exercises the same marker,
    /// transition and Core ordering as the bounded runtime path; it is not a
    /// public recovery shortcut.
    #[cfg(all(test, feature = "safety-rules-sidecar"))]
    pub(crate) fn prepare_timeout_sidecar_crash_for_test_v1<SW>(
        &mut self,
        sidecar: &mut SafetyRulesSemanticSidecarV1<SW>,
    ) -> Result<(), PocoNodeHostErrorV0>
    where
        SW: ExternalMonotonicWatermarkV0,
    {
        self.require_active_runtime_v0()?;
        let epoch = self.core.safety_state().epoch();
        let view = self.core.safety_state().current_view();
        let effects = self
            .core
            .step(Input::LocalTimeout { epoch, view }, &StrictEd25519Verifier)
            .map_err(PocoNodeHostErrorV0::core)?;
        let marker = persist_timeout_shadow_sidecar_before_sqlite_v1(
            self.safety_store.path(),
            self.safety_store.journal_id_v0(),
            self.signer_journal.journal_id(),
            &effects,
            sidecar,
        )?;
        self.pending_timeout_marker = Some(marker);
        Ok(())
    }

    /// Test-only crash injection point after both the semantic sidecar and
    /// SQLite barriers, but before the marker is removed.  This models a
    /// process dying after a durable local successor write and exercises the
    /// retained-predecessor recovery branch.
    #[cfg(all(test, feature = "safety-rules-sidecar"))]
    pub(crate) fn prepare_timeout_sidecar_sqlite_before_clear_for_test_v1<SW>(
        &mut self,
        sidecar: &mut SafetyRulesSemanticSidecarV1<SW>,
    ) -> Result<(), PocoNodeHostErrorV0>
    where
        SW: ExternalMonotonicWatermarkV0,
    {
        self.require_active_runtime_v0()?;
        let epoch = self.core.safety_state().epoch();
        let view = self.core.safety_state().current_view();
        let effects = self
            .core
            .step(Input::LocalTimeout { epoch, view }, &StrictEd25519Verifier)
            .map_err(PocoNodeHostErrorV0::core)?;
        let marker = persist_timeout_shadow_sidecar_before_sqlite_v1(
            self.safety_store.path(),
            self.safety_store.journal_id_v0(),
            self.signer_journal.journal_id(),
            &effects,
            sidecar,
        )?;
        self.pending_timeout_marker = Some(marker);
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            return Err(PocoNodeHostErrorV0::UnexpectedRecoveryEffectSet {
                expected: 1,
                actual: effects.len(),
            });
        };
        self.safety_store
            .persist_exact_v0(request, &SafetyTransitionContextV0::ordinary())
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        let confirmed = self
            .safety_store
            .head()
            .map_err(PocoNodeHostErrorV0::safety_store)?;
        if confirmed.state() != request.state() || confirmed.revision() != request.barrier().get() {
            return Err(PocoNodeHostErrorV0::OrdinaryPersistenceReadbackMismatch {
                expected_revision: request.barrier().get(),
                actual_revision: confirmed.revision(),
            });
        }
        Ok(())
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
        #[cfg(feature = "safety-rules-sidecar")]
        if let Some(marker) = load_pending_timeout_marker_v1(self.safety_store.path())
            .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?
        {
            return Err(
                PocoNodeHostErrorV0::SafetyRulesSidecarPendingRecoveryRequired {
                    revision: marker.revision(),
                },
            );
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
                    #[cfg(feature = "safety-rules-sidecar")]
                    self.clear_pending_timeout_marker_after_safety_persist_v1()?;
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

    #[cfg(feature = "safety-rules-sidecar")]
    fn clear_pending_timeout_marker_after_safety_persist_v1(
        &mut self,
    ) -> Result<(), PocoNodeHostErrorV0> {
        let Some(marker) = self.pending_timeout_marker.take() else {
            return Ok(());
        };
        clear_pending_timeout_marker_v1(self.safety_store.path(), marker)
            .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)
    }

    /// No production-running state is constructible in this slice.
    pub fn production_activation_check(&self) -> Result<(), ProductionActivationBlockedV0> {
        Err(ProductionActivationBlockedV0::new())
    }
}

#[cfg(feature = "safety-rules-sidecar")]
fn persist_timeout_shadow_sidecar_before_sqlite_v1<SW>(
    safety_store_path: &Path,
    safety_journal_id: [u8; 32],
    signer_journal_id: [u8; 32],
    effects: &[Effect],
    sidecar: &mut SafetyRulesSemanticSidecarV1<SW>,
) -> Result<PendingTimeoutMarkerV1, PocoNodeHostErrorV0>
where
    SW: ExternalMonotonicWatermarkV0,
{
    validate_bounded_effect_batch_v0(effects)?;
    let mut request = None;
    for effect in effects {
        if let Effect::PersistSafetyState(candidate) = effect {
            if request.replace(candidate).is_some() {
                return Err(PocoNodeHostErrorV0::MultipleBoundedPersistenceEffects);
            }
        }
    }
    let request =
        request.ok_or(PocoNodeHostErrorV0::SafetyRulesShadowTransitionMismatch { revision: 0 })?;
    let transition = request.safety_rules_shadow_transition_v1().ok_or(
        PocoNodeHostErrorV0::SafetyRulesShadowTransitionMismatch {
            revision: request.barrier().get(),
        },
    )?;
    let Some(SignIntent::TimeoutVote {
        authorizing_safety_revision,
        view,
        signing_root,
        ..
    }) = request.state().pending_sign()
    else {
        return Err(PocoNodeHostErrorV0::SafetyRulesShadowTransitionMismatch {
            revision: request.barrier().get(),
        });
    };
    let canonical = transition.canonical_intent();
    if transition.kind() != trnm_consensus_safety_rules::InertSafetyTransitionKindV1::TimeoutVote
        || transition.successor_state().revision() != request.barrier().get()
        || transition.successor_state().last_timeout_view() != Some(*view)
        || canonical.authorizing_safety_revision() != *authorizing_safety_revision
        || canonical.signing_root() != *signing_root
    {
        return Err(PocoNodeHostErrorV0::SafetyRulesShadowTransitionMismatch {
            revision: request.barrier().get(),
        });
    }
    let marker = PendingTimeoutMarkerV1::from_transition(
        transition,
        sidecar.namespace_digest_v1(),
        safety_journal_id,
        signer_journal_id,
    )
    .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?;
    write_pending_timeout_marker_v1(safety_store_path, marker)
        .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?;
    sidecar
        .persist_transition_v1(transition)
        .map_err(PocoNodeHostErrorV0::safety_rules_sidecar)?;
    Ok(marker)
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
