//! Narrow live Valid-callback delivery boundary.
//!
//! The application journal releases [`NativeValidationValidCallbackV0`] only
//! after one complete-body Valid result, its artifact, callback outbox,
//! speculative overlay, source binding, and accounting image were committed
//! and read back exactly.  This module consumes that process-local authority
//! into the matching live consensus [`Core`]. The callback owns an opaque
//! proof joining the exact pending-slot permit to the separate Core authority
//! installed in the private ApplicationStore; Core accepts no raw permit,
//! commitments, or artifact input. Owner-preserving typestates then enforce
//! application Delivered, exact SafetyStore persistence/readback, application
//! Acked, and the one matching `StorageAck`. No type here reopens a durable
//! callback, remints restart authority, or claims a complete node host.

#![cfg_attr(not(test), allow(dead_code))]

use trnm_consensus_core::{
    native_valid_result_checksum_v0, ApplicationNativeValidDeliveryFactsV0,
    ApplicationSealedNativeValidTransitionV0, ApplicationSealedValidV0,
    AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
    AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0, BarrierId, Core, CoreError,
    DurablePayloadValidationResultV1, Effect, Input, NativeValidPostAckActionV0,
    PayloadTerminalResult, PayloadValidationRouteV0, SafetyState, SafetyStatePersistenceBindingV0,
    SafetyStatePersistenceV0, SignIntent, StateSyncAnchorSuccessorReplayV0,
    ValidatedPayloadArtifactRefV0, ValidationId,
};
use trnm_consensus_safety_store::{
    ConfirmedNativeValidHeadV0, NativeValidSafetyStatePreflightV0, NativeValidTransitionV0,
    SafetyPersistDispositionV0, SafetyStoreErrorV0, SafetyTransitionContextV0,
    SqliteSafetyStateStoreV0,
};
use trnm_consensus_types::{SignatureVerifier, ValidatedBlockCommitmentsV0};

use crate::store::{
    native_validation_request_fingerprint_v0, ApplicationStore,
    ConfirmedNativeValidationValidAckedV0, ConfirmedNativeValidationValidDeliveredV0,
    LiveNativeValidationValidCallbackV0, NativeValidationValidJournalFailpointV0,
    NativeValidationValidJournalTransitionFailureCauseV0,
};

/// Inert application facts which remain joined to one live callback owner.
///
/// These values are useful when a later host constructs a versioned
/// SafetyStore transition context.  They are comparison data only: this type
/// has no public constructor and cannot recreate a callback, commitments, an
/// overlay insertion capability, or a Core input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeValidationValidAppFactsV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    request_fingerprint: [u8; 32],
    immutable_checksum: [u8; 32],
    artifact_checksum: [u8; 32],
    artifact_ref: ValidatedPayloadArtifactRefV0,
    callback_payload_checksum: [u8; 32],
    idempotency_key: [u8; 32],
    delivery_attempt: u64,
}

impl NativeValidationValidAppFactsV0 {
    pub const fn route(self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id(self) -> ValidationId {
        self.validation_id
    }

    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub const fn immutable_checksum(self) -> [u8; 32] {
        self.immutable_checksum
    }

    pub const fn artifact_checksum(self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub const fn artifact_ref(self) -> ValidatedPayloadArtifactRefV0 {
        self.artifact_ref
    }

    pub const fn callback_payload_checksum(self) -> [u8; 32] {
        self.callback_payload_checksum
    }

    pub const fn idempotency_key(self) -> [u8; 32] {
        self.idempotency_key
    }

    pub const fn delivery_attempt(self) -> u64 {
        self.delivery_attempt
    }
}

/// Re-derives the inert App facts from the still-live callback and the exact
/// durable D readback. Every immutable field is joined independently; only
/// the delivery attempt is advanced, and only from the callback's exact
/// persisted P attempt to its single confirmed D successor. Calling this
/// again at C->K/release is idempotent for the already-derived facts.
fn join_native_validation_valid_app_facts_at_delivery_v0(
    facts: NativeValidationValidAppFactsV0,
    live: &LiveNativeValidationValidCallbackV0,
    delivery: &ConfirmedNativeValidationValidDeliveredV0,
) -> Option<NativeValidationValidAppFactsV0> {
    let expected_delivery_attempt = live.delivery_attempt().checked_add(1)?;
    if facts.route != live.route()
        || facts.validation_id != live.validation_id()
        || facts.request_fingerprint != live.request_fingerprint()
        || facts.immutable_checksum != live.immutable_checksum()
        || facts.artifact_checksum != live.artifact_checksum()
        || facts.artifact_ref != live.artifact_ref()
        || facts.callback_payload_checksum != live.callback_payload_checksum()
        || facts.idempotency_key != live.idempotency_key()
        || !matches!(
            facts.delivery_attempt,
            attempt
                if attempt == live.delivery_attempt()
                    || attempt == delivery.delivery_attempt()
        )
        || delivery.delivery_attempt() != expected_delivery_attempt
    {
        return None;
    }
    Some(NativeValidationValidAppFactsV0 {
        route: live.route(),
        validation_id: live.validation_id(),
        request_fingerprint: live.request_fingerprint(),
        immutable_checksum: live.immutable_checksum(),
        artifact_checksum: live.artifact_checksum(),
        artifact_ref: live.artifact_ref(),
        callback_payload_checksum: live.callback_payload_checksum(),
        idempotency_key: live.idempotency_key(),
        delivery_attempt: delivery.delivery_attempt(),
    })
}

/// Unique process-local authority for one atomically sealed Valid callback.
///
/// It is deliberately non-`Clone`, non-serializable, has no public
/// constructor, and exposes no live commitments.  Only the application store
/// seal path can supply the private inner owner.
///
/// ```compile_fail
/// use trnm_consensus_app::NativeValidationValidCallbackV0;
///
/// fn assert_clone<T: Clone>() {}
///
/// fn duplicate_is_forbidden() {
///     assert_clone::<NativeValidationValidCallbackV0>();
/// }
/// ```
#[must_use = "a live Valid callback must be submitted to its exact Core or retained"]
pub struct NativeValidationValidCallbackV0 {
    live: Box<LiveNativeValidationValidCallbackV0>,
    facts: NativeValidationValidAppFactsV0,
}

impl std::fmt::Debug for NativeValidationValidCallbackV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeValidationValidCallbackV0")
            .field("facts", &self.facts)
            .field("retains_live_commitments", &true)
            .finish_non_exhaustive()
    }
}

impl NativeValidationValidCallbackV0 {
    pub(crate) fn from_live_v0(live: Box<LiveNativeValidationValidCallbackV0>) -> Self {
        let facts = NativeValidationValidAppFactsV0 {
            route: live.route(),
            validation_id: live.validation_id(),
            request_fingerprint: live.request_fingerprint(),
            immutable_checksum: live.immutable_checksum(),
            artifact_checksum: live.artifact_checksum(),
            artifact_ref: live.artifact_ref(),
            callback_payload_checksum: live.callback_payload_checksum(),
            idempotency_key: live.idempotency_key(),
            delivery_attempt: live.delivery_attempt(),
        };
        Self { live, facts }
    }

    /// Returns inert comparison facts without releasing the live callback
    /// authority retained by this owner.
    pub const fn app_facts_v0(&self) -> NativeValidationValidAppFactsV0 {
        self.facts
    }

    /// Consumes this exact sealed callback into the matching live Core.
    ///
    /// The route, validation identity, commitments, and artifact reference are
    /// selected internally.  A binding failure or a transactional Core
    /// rejection returns the unchanged owner.  Once `Core::step` succeeds,
    /// any effect/state mismatch is terminal and quarantines the owner rather
    /// than allowing a second callback submission.
    pub fn submit_to_core_v0<V: SignatureVerifier>(
        self,
        core: &mut Core,
        verifier: &V,
    ) -> Result<CoreAcceptedNativeValidationValidV0, NativeValidationValidCallbackFailureV0> {
        submit_to_core_target_v0(self, core, verifier)
    }

    /// App-private bridge for the dedicated anchored-successor replay owner.
    ///
    /// This delegates through only the wrapper's exact sealed-Valid surface;
    /// neither the callback nor its caller can obtain the wrapper's inner
    /// generic Core.
    pub(crate) fn submit_to_state_sync_anchor_successor_v0<V: SignatureVerifier>(
        self,
        replay: &mut StateSyncAnchorSuccessorReplayV0,
        verifier: &V,
    ) -> Result<CoreAcceptedNativeValidationValidV0, NativeValidationValidCallbackFailureV0> {
        submit_to_core_target_v0(self, replay, verifier)
    }

    /// App-private bridge into the dedicated authenticated-genesis h1 Core
    /// owner. The opaque application proof never crosses this module boundary;
    /// the only successful public result is Core's typed rev2 persistence
    /// carrier joined to the still-live application callback.
    pub(crate) fn submit_to_authenticated_genesis_h1_v0<V: SignatureVerifier>(
        self,
        owner: &mut AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        verifier: &V,
    ) -> Result<NativeAuthenticatedGenesisH1CoreAcceptedValidV0, CoreError> {
        let completion_persistence =
            owner.accept_application_sealed_valid_v0(self.live.application_proof(), verifier)?;
        let valid_result_checksum = validate_authenticated_genesis_h1_core_accepted_callback_v0(
            &self,
            &completion_persistence,
        )
        .ok_or(CoreError::AuthenticatedGenesisApplicationH1OfflineRejected(
            "typed rev2 carrier differs from the App-sealed h1 Valid callback",
        ))?;
        Ok(NativeAuthenticatedGenesisH1CoreAcceptedValidV0 {
            callback: self,
            completion_persistence,
            valid_result_checksum,
        })
    }
}

/// Opaque App-owned P stage after the dedicated Core h1 wrapper accepted the
/// sealed callback and returned its exact typed rev2 carrier.
///
/// This owner deliberately exposes neither callback, application proof,
/// generic persistence request, transition context, nor Core effect. Node may
/// only retain the typed Core carrier and hand the whole owner back to the
/// dedicated App host for P->D.
#[derive(Debug)]
#[must_use = "the typed h1 rev2 carrier must enter application Delivered"]
pub struct NativeAuthenticatedGenesisH1CoreAcceptedValidV0 {
    callback: NativeValidationValidCallbackV0,
    completion_persistence: AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
    valid_result_checksum: [u8; 32],
}

pub(crate) enum NativeAuthenticatedGenesisH1MarkDeliveredFailureV0 {
    Safety(SafetyStoreErrorV0),
    Application(NativeValidationValidJournalTransitionFailureCauseV0),
    Core(CoreError),
}

impl NativeAuthenticatedGenesisH1CoreAcceptedValidV0 {
    pub const fn completion_persistence_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
        &self.completion_persistence
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.completion_persistence.validation_id_v0()
    }

    pub(crate) fn preflight_and_mark_application_delivered_v0<V: SignatureVerifier>(
        self,
        application_store: &ApplicationStore,
        core_owner: &AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
    ) -> Result<
        NativeAuthenticatedGenesisH1DeliveredValidV0,
        NativeAuthenticatedGenesisH1MarkDeliveredFailureV0,
    > {
        let preflight = safety_store
            .preflight_authenticated_genesis_application_h1_native_valid_exact_v0(
                &self.completion_persistence,
            )
            .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Safety)?;
        if preflight.journal_id_v0() != safety_store.journal_id_v0()
            || preflight.verifier_profile_ref_v0() != safety_store.verifier_profile_ref_v0()
            || preflight.revision_v0() != 2
            || preflight.post_ack_action_v0() != NativeValidPostAckActionV0::None
        {
            return Err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Safety(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 2,
                    actual_revision: preflight.revision_v0(),
                },
            ));
        }
        let application_delivery = application_store
            .mark_native_validation_valid_callback_delivered_v0(
                &self.callback.live,
                2,
                self.valid_result_checksum,
                &preflight,
            )
            .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Application)?;
        let mut callback = self.callback;
        let Some(facts) = join_native_validation_valid_app_facts_at_delivery_v0(
            callback.facts,
            &callback.live,
            &application_delivery,
        )
        .filter(|facts| facts.delivery_attempt == 1) else {
            return Err(
                NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Application(
                    NativeValidationValidJournalTransitionFailureCauseV0::Invariant(
                        crate::store::NativeValidationReservationInvariantV0::StateMismatch,
                    ),
                ),
            );
        };
        callback.facts = facts;
        let delivery_facts = ApplicationNativeValidDeliveryFactsV0::new(
            facts.route,
            facts.validation_id,
            facts.request_fingerprint,
            facts.immutable_checksum,
            callback.live.host_config_ref(),
            self.valid_result_checksum,
            facts.callback_payload_checksum,
            facts.idempotency_key,
            application_delivery.delivery_attempt(),
            application_delivery.delivered_job_row_checksum(),
            application_delivery.outbox_checksum(),
            application_delivery.post_ack_action(),
            2,
        )
        .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Core)?;
        let sealed_transition = core_owner
            .seal_authenticated_genesis_h1_native_valid_transition_v0(
                self.completion_persistence,
                delivery_facts,
            )
            .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Core)?;
        Ok(NativeAuthenticatedGenesisH1DeliveredValidV0 {
            callback,
            valid_result_checksum: self.valid_result_checksum,
            preflight,
            application_delivery,
            sealed_transition,
        })
    }

    /// Rejoins a reexecuted attempt-zero callback to the already durable h1
    /// `D` row.  The App confirmation is strictly read-only: unlike the fresh
    /// path above it never invokes the P-to-D writer or advances the outbox
    /// attempt.  Core's fresh rev2 carrier and the live Safety rev1 preflight
    /// must independently reproduce the persisted accepted envelope.
    pub(crate) fn preflight_and_confirm_existing_application_delivered_v0<V: SignatureVerifier>(
        self,
        application_store: &ApplicationStore,
        core_owner: &AuthenticatedGenesisApplicationH1OfflineApplicationOwnerV0,
        safety_store: &SqliteSafetyStateStoreV0<V>,
        expected_cut: &crate::store::NativeAuthenticatedGenesisH1ObligationTakeoverCutV0,
    ) -> Result<
        NativeAuthenticatedGenesisH1DeliveredValidV0,
        NativeAuthenticatedGenesisH1MarkDeliveredFailureV0,
    > {
        let preflight = safety_store
            .preflight_authenticated_genesis_application_h1_native_valid_exact_v0(
                &self.completion_persistence,
            )
            .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Safety)?;
        if preflight.journal_id_v0() != safety_store.journal_id_v0()
            || preflight.verifier_profile_ref_v0() != safety_store.verifier_profile_ref_v0()
            || preflight.revision_v0() != 2
            || preflight.post_ack_action_v0() != NativeValidPostAckActionV0::None
        {
            return Err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Safety(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 2,
                    actual_revision: preflight.revision_v0(),
                },
            ));
        }
        let application_delivery = application_store
            .confirm_authenticated_genesis_h1_delivered_takeover_v0(
                &self.callback.live,
                2,
                self.valid_result_checksum,
                &preflight,
                expected_cut,
            )
            .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Application)?;
        let mut callback = self.callback;
        let Some(facts) = join_native_validation_valid_app_facts_at_delivery_v0(
            callback.facts,
            &callback.live,
            &application_delivery,
        )
        .filter(|facts| facts.delivery_attempt == 1) else {
            return Err(
                NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Application(
                    NativeValidationValidJournalTransitionFailureCauseV0::Invariant(
                        crate::store::NativeValidationReservationInvariantV0::StateMismatch,
                    ),
                ),
            );
        };
        callback.facts = facts;
        let delivery_facts = ApplicationNativeValidDeliveryFactsV0::new(
            facts.route,
            facts.validation_id,
            facts.request_fingerprint,
            facts.immutable_checksum,
            callback.live.host_config_ref(),
            self.valid_result_checksum,
            facts.callback_payload_checksum,
            facts.idempotency_key,
            application_delivery.delivery_attempt(),
            application_delivery.delivered_job_row_checksum(),
            application_delivery.outbox_checksum(),
            application_delivery.post_ack_action(),
            2,
        )
        .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Core)?;
        let sealed_transition = core_owner
            .seal_authenticated_genesis_h1_native_valid_transition_v0(
                self.completion_persistence,
                delivery_facts,
            )
            .map_err(NativeAuthenticatedGenesisH1MarkDeliveredFailureV0::Core)?;
        Ok(NativeAuthenticatedGenesisH1DeliveredValidV0 {
            callback,
            valid_result_checksum: self.valid_result_checksum,
            preflight,
            application_delivery,
            sealed_transition,
        })
    }
}

/// Exact App D stage for the authenticated-genesis h1 Valid. The callback and
/// tag-2 transition remain private; the only forward operation is dedicated
/// SafetyStore persistence followed by exact authenticated readback.
#[must_use = "application Delivered must reach exact dedicated SafetyStore persistence"]
pub struct NativeAuthenticatedGenesisH1DeliveredValidV0 {
    callback: NativeValidationValidCallbackV0,
    valid_result_checksum: [u8; 32],
    preflight: NativeValidSafetyStatePreflightV0,
    application_delivery: ConfirmedNativeValidationValidDeliveredV0,
    sealed_transition: ApplicationSealedNativeValidTransitionV0,
}

impl std::fmt::Debug for NativeAuthenticatedGenesisH1DeliveredValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAuthenticatedGenesisH1DeliveredValidV0")
            .field("facts", &self.callback.facts)
            .field(
                "barrier",
                &self
                    .sealed_transition
                    .completion_persistence_v0()
                    .barrier_v0(),
            )
            .field("retains_core_sealed_transition", &true)
            .finish_non_exhaustive()
    }
}

impl NativeAuthenticatedGenesisH1DeliveredValidV0 {
    pub const fn completion_persistence_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
        self.sealed_transition.completion_persistence_v0()
    }

    pub fn persist_and_confirm_safety_v0<V: SignatureVerifier>(
        self,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
    ) -> Result<NativeAuthenticatedGenesisH1SafetyPersistedValidV0, SafetyStoreErrorV0> {
        if safety_store.journal_id_v0() != self.preflight.journal_id_v0()
            || safety_store.verifier_profile_ref_v0() != self.preflight.verifier_profile_ref_v0()
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 2,
                    actual_revision: self.preflight.revision_v0(),
                },
            );
        }
        let confirmed = safety_store
            .persist_authenticated_genesis_application_h1_native_valid_exact_v0(
                &self.sealed_transition,
            )?;
        if confirmed.journal_id_v0() != self.preflight.journal_id_v0()
            || confirmed.verifier_profile_ref_v0() != self.preflight.verifier_profile_ref_v0()
            || confirmed.state_record_checksum() != self.preflight.state_record_checksum_v0()
        {
            return Err(
                SafetyStoreErrorV0::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                    expected_revision: 2,
                    actual_revision: confirmed.revision(),
                },
            );
        }
        Ok(NativeAuthenticatedGenesisH1SafetyPersistedValidV0 {
            callback: self.callback,
            sealed_transition: self.sealed_transition,
            valid_result_checksum: self.valid_result_checksum,
            application_delivery: self.application_delivery,
            confirmed,
        })
    }
}

/// Exact Safety C stage. Only the dedicated App host may consume it into K.
#[must_use = "confirmed h1 Safety persistence must enter application Acked"]
pub struct NativeAuthenticatedGenesisH1SafetyPersistedValidV0 {
    callback: NativeValidationValidCallbackV0,
    sealed_transition: ApplicationSealedNativeValidTransitionV0,
    valid_result_checksum: [u8; 32],
    application_delivery: ConfirmedNativeValidationValidDeliveredV0,
    confirmed: ConfirmedNativeValidHeadV0,
}

impl std::fmt::Debug for NativeAuthenticatedGenesisH1SafetyPersistedValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAuthenticatedGenesisH1SafetyPersistedValidV0")
            .field("facts", &self.callback.facts)
            .field(
                "barrier",
                &self
                    .sealed_transition
                    .completion_persistence_v0()
                    .barrier_v0(),
            )
            .field("confirmed_revision", &self.confirmed.revision())
            .finish_non_exhaustive()
    }
}

impl NativeAuthenticatedGenesisH1SafetyPersistedValidV0 {
    pub const fn completion_persistence_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
        self.sealed_transition.completion_persistence_v0()
    }

    pub(crate) fn acknowledge_application_v0(
        self,
        application_store: &ApplicationStore,
    ) -> Result<
        NativeAuthenticatedGenesisH1AckedValidV0,
        NativeValidationValidJournalTransitionFailureCauseV0,
    > {
        let app_facts = join_native_validation_valid_app_facts_at_delivery_v0(
            self.callback.facts,
            &self.callback.live,
            &self.application_delivery,
        )
        .filter(|facts| facts.delivery_attempt == 1)
        .ok_or(
            NativeValidationValidJournalTransitionFailureCauseV0::Invariant(
                crate::store::NativeValidationReservationInvariantV0::StateMismatch,
            ),
        )?;
        let application_ack = application_store.acknowledge_native_validation_valid_callback_v0(
            &self.callback.live,
            &self.application_delivery,
            &self.confirmed,
        )?;
        let acked_job_row_checksum = application_ack.acked_job_row_checksum_v0();
        drop((
            self.callback,
            self.application_delivery,
            self.confirmed,
            application_ack,
        ));
        Ok(NativeAuthenticatedGenesisH1AckedValidV0 {
            sealed_transition: self.sealed_transition,
            app_facts,
            valid_result_checksum: self.valid_result_checksum,
            acked_job_row_checksum,
        })
    }
}

/// Exact App K stage. It retains only inert App facts and Core's typed rev2
/// carrier; the live callback and outbox authority have been retired.
#[derive(Debug)]
#[must_use = "application Acked must close the dedicated Core h1 owner"]
pub struct NativeAuthenticatedGenesisH1AckedValidV0 {
    sealed_transition: ApplicationSealedNativeValidTransitionV0,
    app_facts: NativeValidationValidAppFactsV0,
    valid_result_checksum: [u8; 32],
    acked_job_row_checksum: [u8; 32],
}

/// Fresh, copy-only proof that the exact authenticated-genesis h1 App source
/// remains at stable `K` after Core completed rev2. It carries no callback,
/// store, overlay mutation authority, Core owner, or Safety persistence token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeAuthenticatedGenesisH1CompletedAppConfirmationV0 {
    validation_id: ValidationId,
    valid_result_checksum: [u8; 32],
    acked_job_row_checksum: [u8; 32],
    artifact_checksum: [u8; 32],
    overlay_checksum: [u8; 32],
    application_host_config_ref: [u8; 32],
    delivered_job_row_checksum: [u8; 32],
    outbox_checksum: [u8; 32],
    completion_carrier_checksum: [u8; 32],
}

impl NativeAuthenticatedGenesisH1CompletedAppConfirmationV0 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new_v0(
        validation_id: ValidationId,
        valid_result_checksum: [u8; 32],
        acked_job_row_checksum: [u8; 32],
        artifact_checksum: [u8; 32],
        overlay_checksum: [u8; 32],
        application_host_config_ref: [u8; 32],
        delivered_job_row_checksum: [u8; 32],
        outbox_checksum: [u8; 32],
        completion_carrier_checksum: [u8; 32],
    ) -> Self {
        Self {
            validation_id,
            valid_result_checksum,
            acked_job_row_checksum,
            artifact_checksum,
            overlay_checksum,
            application_host_config_ref,
            delivered_job_row_checksum,
            outbox_checksum,
            completion_carrier_checksum,
        }
    }

    pub const fn validation_id_v0(self) -> ValidationId {
        self.validation_id
    }

    pub const fn valid_result_checksum_v0(self) -> [u8; 32] {
        self.valid_result_checksum
    }

    pub const fn acked_job_row_checksum_v0(self) -> [u8; 32] {
        self.acked_job_row_checksum
    }

    pub const fn artifact_checksum_v0(self) -> [u8; 32] {
        self.artifact_checksum
    }

    pub const fn overlay_checksum_v0(self) -> [u8; 32] {
        self.overlay_checksum
    }

    /// Host-configuration commitment reconstructed from the exact live App
    /// owner and checked against both the stable K row and Core-sealed D
    /// predecessor inside the same fixed snapshot.
    pub const fn application_host_config_ref_v0(self) -> [u8; 32] {
        self.application_host_config_ref
    }

    /// Canonical Delivered row checksum reconstructed from the fixed-snapshot
    /// K row plus the Core-sealed D outbox provenance.
    pub const fn delivered_job_row_checksum_v0(self) -> [u8; 32] {
        self.delivered_job_row_checksum
    }

    /// Canonical retired outbox checksum independently reconstructed from the
    /// fixed-snapshot job identity, artifact, callback and delivery attempt.
    pub const fn outbox_checksum_v0(self) -> [u8; 32] {
        self.outbox_checksum
    }

    pub const fn completion_carrier_checksum_v0(self) -> [u8; 32] {
        self.completion_carrier_checksum
    }
}

impl NativeAuthenticatedGenesisH1AckedValidV0 {
    pub const fn completion_persistence_v0(
        &self,
    ) -> &AuthenticatedGenesisApplicationH1CompletionPersistenceV0 {
        self.sealed_transition.completion_persistence_v0()
    }

    pub const fn app_facts_v0(&self) -> NativeValidationValidAppFactsV0 {
        self.app_facts
    }

    pub const fn valid_result_checksum_v0(&self) -> [u8; 32] {
        self.valid_result_checksum
    }

    pub const fn acked_job_row_checksum_v0(&self) -> [u8; 32] {
        self.acked_job_row_checksum
    }

    pub(crate) const fn sealed_transition_v0(&self) -> &ApplicationSealedNativeValidTransitionV0 {
        &self.sealed_transition
    }

    pub(crate) fn confirm_completed_application_v0(
        &self,
        application_store: &ApplicationStore,
        completed: &trnm_consensus_core::AuthenticatedGenesisApplicationH1CompletedV0,
    ) -> Result<NativeAuthenticatedGenesisH1CompletedAppConfirmationV0, anyhow::Error> {
        application_store.confirm_authenticated_genesis_h1_completed_exact_v0(
            self.app_facts,
            self.sealed_transition.delivery_facts_v0(),
            self.valid_result_checksum,
            self.acked_job_row_checksum,
            self.sealed_transition.carrier_checksum_v0(),
            completed,
        )
    }
}

fn validate_authenticated_genesis_h1_core_accepted_callback_v0(
    callback: &NativeValidationValidCallbackV0,
    carrier: &AuthenticatedGenesisApplicationH1CompletionPersistenceV0,
) -> Option<[u8; 32]> {
    let facts = callback.facts;
    let persistence = carrier.persistence_v0();
    let state = persistence.state();
    let commitments = callback.live.validated_commitments();
    let artifact_ref = callback.live.artifact_ref();
    let [completion] = state.payload_validation_completions() else {
        return None;
    };
    let [terminal] = state.payload_terminal_facts() else {
        return None;
    };
    let result_matches = match completion.result() {
        DurablePayloadValidationResultV1::Valid {
            commitments: durable,
            artifact_ref: durable_artifact,
        } => {
            durable.block_id() == commitments.block_id()
                && durable.logical_block_size() == commitments.logical_block_size()
                && durable.transaction_count() == commitments.transaction_count()
                && durable.evidence_count() == commitments.evidence_count()
                && durable_artifact == artifact_ref
        }
        DurablePayloadValidationResultV1::Unavailable
        | DurablePayloadValidationResultV1::DeterministicallyInvalid => false,
    };
    if facts.route != PayloadValidationRouteV0::Synced
        || carrier.validation_id_v0() != facts.validation_id
        || persistence.barrier().get() != 2
        || state.revision() != 2
        || persistence.native_valid_post_ack_action_v0() != Some(NativeValidPostAckActionV0::None)
        || persistence.native_finalization_applied_v0().is_some()
        || !state.payload_validation_obligations().is_empty()
        || completion.route() != PayloadValidationRouteV0::Synced
        || completion.id() != facts.validation_id
        || completion.first_recorded_revision() != 2
        || !result_matches
        || terminal.block_id() != facts.validation_id.block_id()
        || terminal.result() != PayloadTerminalResult::Valid
        || terminal.valid_overlay() != Some(facts.artifact_ref.overlay())
        || terminal.first_recorded_revision() != 2
    {
        return None;
    }
    native_valid_result_checksum_v0(completion.result())
}

/// Private common target for ordinary Core delivery and the deliberately
/// narrow h1-anchor successor replay owner. It exposes only the two inputs
/// required by the existing P/D/C/K typestate and never releases a raw Core.
trait NativeValidCoreTargetV0 {
    fn safety_state_v0(&self) -> &SafetyState;

    fn persistence_binding_v0(&self) -> SafetyStatePersistenceBindingV0;

    fn step_application_sealed_valid_target_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<Vec<Effect>, CoreError>;

    fn step_storage_ack_target_v0<V: SignatureVerifier>(
        &mut self,
        barrier: BarrierId,
        verifier: &V,
    ) -> Result<Vec<Effect>, CoreError>;
}

impl NativeValidCoreTargetV0 for Core {
    fn safety_state_v0(&self) -> &SafetyState {
        self.safety_state()
    }

    fn persistence_binding_v0(&self) -> SafetyStatePersistenceBindingV0 {
        self.safety_state_persistence_binding_v0()
    }

    fn step_application_sealed_valid_target_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<Vec<Effect>, CoreError> {
        self.step_application_sealed_valid_v0(proof, verifier)
    }

    fn step_storage_ack_target_v0<V: SignatureVerifier>(
        &mut self,
        barrier: BarrierId,
        verifier: &V,
    ) -> Result<Vec<Effect>, CoreError> {
        self.step(Input::StorageAck { barrier }, verifier)
    }
}

impl NativeValidCoreTargetV0 for StateSyncAnchorSuccessorReplayV0 {
    fn safety_state_v0(&self) -> &SafetyState {
        self.safety_state()
    }

    fn persistence_binding_v0(&self) -> SafetyStatePersistenceBindingV0 {
        self.safety_state_persistence_binding_v0()
    }

    fn step_application_sealed_valid_target_v0<V: SignatureVerifier>(
        &mut self,
        proof: &ApplicationSealedValidV0,
        verifier: &V,
    ) -> Result<Vec<Effect>, CoreError> {
        self.step_application_sealed_valid_v0(proof, verifier)
    }

    fn step_storage_ack_target_v0<V: SignatureVerifier>(
        &mut self,
        barrier: BarrierId,
        verifier: &V,
    ) -> Result<Vec<Effect>, CoreError> {
        self.step_storage_ack_v0(barrier, verifier)
    }
}

fn submit_to_core_target_v0<T: NativeValidCoreTargetV0, V: SignatureVerifier>(
    callback: NativeValidationValidCallbackV0,
    target: &mut T,
    verifier: &V,
) -> Result<CoreAcceptedNativeValidationValidV0, NativeValidationValidCallbackFailureV0> {
    let before_revision = target.safety_state_v0().revision();
    let before_pending_sign = target.safety_state_v0().pending_sign().cloned();
    let commitments = callback.live.validated_commitments();
    let artifact_ref = callback.facts.artifact_ref;

    if let Err(cause) = bind_live_valid_callback_v0(
        target.safety_state_v0(),
        &callback,
        commitments,
        artifact_ref,
    ) {
        return Err(NativeValidationValidCallbackFailureV0::Rejected(Box::new(
            RejectedNativeValidationValidCallbackV0 {
                callback,
                cause: NativeValidationValidCallbackRejectionV0::Binding(cause),
            },
        )));
    }

    let effects = match target
        .step_application_sealed_valid_target_v0(callback.live.application_proof(), verifier)
    {
        Ok(effects) => effects,
        Err(error) => {
            return Err(NativeValidationValidCallbackFailureV0::Rejected(Box::new(
                RejectedNativeValidationValidCallbackV0 {
                    callback,
                    cause: NativeValidationValidCallbackRejectionV0::Core(error),
                },
            )));
        }
    };

    match validate_core_accepted_valid_callback_v0(
        target.safety_state_v0(),
        &callback,
        commitments,
        artifact_ref,
        before_revision,
        before_pending_sign.as_ref(),
        &effects,
    ) {
        Ok((persistence, completion_revision, valid_result_checksum)) => {
            Ok(CoreAcceptedNativeValidationValidV0 {
                callback,
                persistence,
                completion_revision,
                valid_result_checksum,
            })
        }
        Err(cause) => Err(NativeValidationValidCallbackFailureV0::AcceptedInvariant(
            Box::new(InvalidCoreAcceptedNativeValidationValidV0 {
                callback,
                observed_state: target.safety_state_v0().clone(),
                observed_effects: effects,
                cause,
            }),
        )),
    }
}

// Existing store-level conformance tests inspect the same facts they checked
// before the public opaque wrapper was introduced.  Keep these accessors
// test-only: production consumers receive only inert `app_facts_v0` and can
// neither borrow the issuing store nor detach the live commitments.
#[cfg(test)]
impl NativeValidationValidCallbackV0 {
    pub(crate) const fn route(&self) -> PayloadValidationRouteV0 {
        self.facts.route
    }

    pub(crate) const fn validation_id(&self) -> ValidationId {
        self.facts.validation_id
    }

    pub(crate) const fn request_fingerprint(&self) -> [u8; 32] {
        self.facts.request_fingerprint
    }

    pub(crate) const fn immutable_checksum(&self) -> [u8; 32] {
        self.facts.immutable_checksum
    }

    pub(crate) const fn artifact_checksum(&self) -> [u8; 32] {
        self.facts.artifact_checksum
    }

    pub(crate) const fn artifact_ref(&self) -> ValidatedPayloadArtifactRefV0 {
        self.facts.artifact_ref
    }

    pub(crate) const fn callback_payload_checksum(&self) -> [u8; 32] {
        self.facts.callback_payload_checksum
    }

    pub(crate) const fn idempotency_key(&self) -> [u8; 32] {
        self.facts.idempotency_key
    }

    pub(crate) const fn delivery_attempt(&self) -> u64 {
        self.facts.delivery_attempt
    }

    pub(crate) const fn disposition(&self) -> crate::store::NativeValidationValidSealDispositionV0 {
        self.live.disposition()
    }

    pub(crate) const fn state(&self) -> crate::store::NativeValidationJobStateV0 {
        self.live.state()
    }

    pub(crate) fn is_bound_to_store_v0(&self, store: &crate::store::ApplicationStore) -> bool {
        self.live.is_bound_to_store_v0(store)
    }

    pub(crate) const fn validated_commitments(
        &self,
    ) -> trnm_consensus_types::ValidatedBlockCommitmentsV0 {
        self.live.validated_commitments()
    }
}

/// Failure detected before Core accepted the callback.
#[derive(Debug)]
pub enum NativeValidationValidCallbackRejectionV0 {
    Binding(NativeValidationValidCallbackBindFailureV0),
    Core(CoreError),
}

/// Exact pre-step binding failure. Every variant leaves both Core and the
/// callback owner unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeValidationValidCallbackBindFailureV0 {
    MissingObligation,
    DuplicateCoreIdentity,
    RouteMismatch,
    RequestFingerprintDerivation,
    RequestFingerprintMismatch,
    CommitmentBlockMismatch,
    ArtifactSourceMismatch,
    ArtifactTargetMismatch,
    ArtifactParentMismatch,
}

/// A rejected submission retains the unique callback owner for exact retry.
#[must_use = "a rejected live callback still owns its exact retry authority"]
pub struct RejectedNativeValidationValidCallbackV0 {
    callback: NativeValidationValidCallbackV0,
    cause: NativeValidationValidCallbackRejectionV0,
}

impl std::fmt::Debug for RejectedNativeValidationValidCallbackV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RejectedNativeValidationValidCallbackV0")
            .field("cause", &self.cause)
            .field("retains_live_callback", &true)
            .finish()
    }
}

impl RejectedNativeValidationValidCallbackV0 {
    pub const fn cause(&self) -> &NativeValidationValidCallbackRejectionV0 {
        &self.cause
    }

    pub fn into_callback_v0(self) -> NativeValidationValidCallbackV0 {
        self.callback
    }
}

/// A Core-success postcondition failure is never retryable as another
/// callback.  The live owner is quarantined inside this terminal carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreAcceptedNativeValidationValidInvariantV0 {
    UnexpectedEffectSet,
    BarrierRevisionMismatch,
    PersistedStateMismatch,
    RevisionTransitionMismatch,
    ObligationRetained,
    CompletionMissingOrChanged,
    CompletionRevisionMismatch,
    TerminalFactMissingOrChanged,
    TerminalFactRevisionMismatch,
    UnexpectedSigningTransition,
    ValidResultChecksumMismatch,
}

#[must_use = "a post-Core invariant failure retains quarantined callback context"]
pub struct InvalidCoreAcceptedNativeValidationValidV0 {
    callback: NativeValidationValidCallbackV0,
    observed_state: SafetyState,
    observed_effects: Vec<Effect>,
    cause: CoreAcceptedNativeValidationValidInvariantV0,
}

impl std::fmt::Debug for InvalidCoreAcceptedNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvalidCoreAcceptedNativeValidationValidV0")
            .field("cause", &self.cause)
            .field("facts", &self.callback.facts)
            .field("observed_state", &self.observed_state)
            .field("observed_effects", &self.observed_effects)
            .field("quarantines_live_callback", &true)
            .finish_non_exhaustive()
    }
}

impl InvalidCoreAcceptedNativeValidationValidV0 {
    pub const fn cause(&self) -> CoreAcceptedNativeValidationValidInvariantV0 {
        self.cause
    }

    pub const fn observed_state(&self) -> &SafetyState {
        &self.observed_state
    }

    pub fn observed_effects(&self) -> &[Effect] {
        &self.observed_effects
    }
}

#[must_use = "a callback failure retains either retryable or quarantined authority"]
pub enum NativeValidationValidCallbackFailureV0 {
    Rejected(Box<RejectedNativeValidationValidCallbackV0>),
    AcceptedInvariant(Box<InvalidCoreAcceptedNativeValidationValidV0>),
}

impl std::fmt::Debug for NativeValidationValidCallbackFailureV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(failure) => formatter.debug_tuple("Rejected").field(failure).finish(),
            Self::AcceptedInvariant(failure) => formatter
                .debug_tuple("AcceptedInvariant")
                .field(failure)
                .finish(),
        }
    }
}

/// Core accepted the exact Valid callback and emitted its one opaque safety
/// persistence request.  This stage remains live until a future host persists
/// that request with a Valid-specific transition context and confirms exact
/// readback; it intentionally exposes no `StorageAck` authority here.
#[must_use = "Core acceptance still requires exact SafetyStore persistence"]
pub struct CoreAcceptedNativeValidationValidV0 {
    callback: NativeValidationValidCallbackV0,
    persistence: SafetyStatePersistenceV0,
    completion_revision: u64,
    valid_result_checksum: [u8; 32],
}

impl std::fmt::Debug for CoreAcceptedNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreAcceptedNativeValidationValidV0")
            .field("facts", &self.callback.facts)
            .field("barrier", &self.persistence.barrier())
            .field("completion_revision", &self.completion_revision)
            .field("valid_result_checksum", &self.valid_result_checksum)
            .finish_non_exhaustive()
    }
}

impl CoreAcceptedNativeValidationValidV0 {
    pub const fn app_facts_v0(&self) -> NativeValidationValidAppFactsV0 {
        self.callback.facts
    }

    pub const fn persistence_request_v0(&self) -> &SafetyStatePersistenceV0 {
        &self.persistence
    }

    pub const fn barrier_v0(&self) -> BarrierId {
        self.persistence.barrier()
    }

    pub const fn completion_revision_v0(&self) -> u64 {
        self.completion_revision
    }

    pub const fn valid_result_checksum_v0(&self) -> [u8; 32] {
        self.valid_result_checksum
    }

    /// Runs the non-mutating exact SafetyStore preflight while retaining the
    /// already-accepted callback owner on every failure.
    pub(crate) fn preflight_safety_store_v0<V: SignatureVerifier>(
        self,
        safety_store: &SqliteSafetyStateStoreV0<V>,
    ) -> Result<
        PreflightedCoreAcceptedNativeValidationValidV0,
        FailedPreflightCoreAcceptedNativeValidationValidV0,
    > {
        match safety_store.preflight_bound_native_valid_persistence_v0(&self.persistence) {
            Ok(preflight) => Ok(PreflightedCoreAcceptedNativeValidationValidV0 {
                callback: self.callback,
                persistence: self.persistence,
                completion_revision: self.completion_revision,
                valid_result_checksum: self.valid_result_checksum,
                preflight,
            }),
            Err(error) => Err(FailedPreflightCoreAcceptedNativeValidationValidV0 {
                owner: Box::new(self),
                error: Box::new(error),
            }),
        }
    }
}

#[must_use = "a failed preflight retains the accepted callback owner"]
pub(crate) struct FailedPreflightCoreAcceptedNativeValidationValidV0 {
    owner: Box<CoreAcceptedNativeValidationValidV0>,
    error: Box<SafetyStoreErrorV0>,
}

impl std::fmt::Debug for FailedPreflightCoreAcceptedNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedPreflightCoreAcceptedNativeValidationValidV0")
            .field("error", &self.error)
            .field("facts", &self.owner.callback.facts)
            .field("retains_accepted_owner", &true)
            .finish()
    }
}

impl FailedPreflightCoreAcceptedNativeValidationValidV0 {
    pub fn error(&self) -> &SafetyStoreErrorV0 {
        self.error.as_ref()
    }

    pub fn into_owner_v0(self) -> CoreAcceptedNativeValidationValidV0 {
        *self.owner
    }
}

#[must_use = "preflighted Valid acceptance must enter application Delivered"]
pub(crate) struct PreflightedCoreAcceptedNativeValidationValidV0 {
    callback: NativeValidationValidCallbackV0,
    persistence: SafetyStatePersistenceV0,
    completion_revision: u64,
    valid_result_checksum: [u8; 32],
    preflight: NativeValidSafetyStatePreflightV0,
}

impl std::fmt::Debug for PreflightedCoreAcceptedNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreflightedCoreAcceptedNativeValidationValidV0")
            .field("facts", &self.callback.facts)
            .field("revision", &self.completion_revision)
            .field(
                "state_record_checksum",
                &self.preflight.state_record_checksum_v0(),
            )
            .finish_non_exhaustive()
    }
}

impl PreflightedCoreAcceptedNativeValidationValidV0 {
    pub(crate) fn mark_application_delivered_v0(
        self,
        application_store: &ApplicationStore,
    ) -> Result<
        DeliveredCoreAcceptedNativeValidationValidV0,
        FailedMarkApplicationDeliveredNativeValidationValidV0,
    > {
        self.mark_application_delivered_inner_v0(application_store, None)
    }

    #[cfg(test)]
    fn mark_application_delivered_with_test_failpoint_v0(
        self,
        application_store: &ApplicationStore,
        failpoint: NativeValidationValidJournalFailpointV0,
    ) -> Result<
        DeliveredCoreAcceptedNativeValidationValidV0,
        FailedMarkApplicationDeliveredNativeValidationValidV0,
    > {
        self.mark_application_delivered_inner_v0(application_store, Some(failpoint))
    }

    fn mark_application_delivered_inner_v0(
        self,
        application_store: &ApplicationStore,
        #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<
            NativeValidationValidJournalFailpointV0,
        >,
    ) -> Result<
        DeliveredCoreAcceptedNativeValidationValidV0,
        FailedMarkApplicationDeliveredNativeValidationValidV0,
    > {
        #[cfg(test)]
        let marked = match failpoint {
            Some(failpoint) => application_store
                .mark_native_validation_valid_callback_delivered_with_test_failpoint_v0(
                    &self.callback.live,
                    self.completion_revision,
                    self.valid_result_checksum,
                    &self.preflight,
                    failpoint,
                ),
            None => application_store.mark_native_validation_valid_callback_delivered_v0(
                &self.callback.live,
                self.completion_revision,
                self.valid_result_checksum,
                &self.preflight,
            ),
        };
        #[cfg(not(test))]
        let marked = application_store.mark_native_validation_valid_callback_delivered_v0(
            &self.callback.live,
            self.completion_revision,
            self.valid_result_checksum,
            &self.preflight,
        );
        match marked {
            Ok(application_delivery) => {
                let Some(facts) = join_native_validation_valid_app_facts_at_delivery_v0(
                    self.callback.facts,
                    &self.callback.live,
                    &application_delivery,
                ) else {
                    return Err(FailedMarkApplicationDeliveredNativeValidationValidV0 {
                        owner: Box::new(self),
                        cause: MarkApplicationDeliveredNativeValidationValidCauseV0::Store(
                            Box::new(
                                NativeValidationValidJournalTransitionFailureCauseV0::Invariant(
                                    crate::store::NativeValidationReservationInvariantV0::
                                        StateMismatch,
                                ),
                            ),
                        ),
                    });
                };
                let mut callback = self.callback;
                callback.facts = facts;
                let transition = match NativeValidTransitionV0::new(
                    facts.route,
                    facts.validation_id,
                    facts.request_fingerprint,
                    facts.immutable_checksum,
                    callback.live.host_config_ref(),
                    self.valid_result_checksum,
                    facts.callback_payload_checksum,
                    facts.idempotency_key,
                    application_delivery.delivery_attempt(),
                    application_delivery.delivered_job_row_checksum(),
                    application_delivery.outbox_checksum(),
                    application_delivery.post_ack_action().code(),
                    self.completion_revision,
                ) {
                    Ok(transition) => transition,
                    Err(error) => {
                        return Err(FailedMarkApplicationDeliveredNativeValidationValidV0 {
                            owner: Box::new(PreflightedCoreAcceptedNativeValidationValidV0 {
                                callback,
                                persistence: self.persistence,
                                completion_revision: self.completion_revision,
                                valid_result_checksum: self.valid_result_checksum,
                                preflight: self.preflight,
                            }),
                            cause: MarkApplicationDeliveredNativeValidationValidCauseV0::Context(
                                Box::new(error),
                            ),
                        });
                    }
                };
                Ok(DeliveredCoreAcceptedNativeValidationValidV0 {
                    callback,
                    persistence: self.persistence,
                    preflight: self.preflight,
                    application_delivery,
                    context: SafetyTransitionContextV0::native_valid(transition),
                })
            }
            Err(error) => Err(FailedMarkApplicationDeliveredNativeValidationValidV0 {
                owner: Box::new(self),
                cause: MarkApplicationDeliveredNativeValidationValidCauseV0::Store(Box::new(error)),
            }),
        }
    }
}

pub(crate) enum MarkApplicationDeliveredNativeValidationValidCauseV0 {
    Store(Box<NativeValidationValidJournalTransitionFailureCauseV0>),
    Context(Box<SafetyStoreErrorV0>),
}

impl std::fmt::Debug for MarkApplicationDeliveredNativeValidationValidCauseV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => formatter.debug_tuple("Store").field(error).finish(),
            Self::Context(error) => formatter.debug_tuple("Context").field(error).finish(),
        }
    }
}

#[must_use = "a failed application Delivered transition retains the preflighted owner"]
pub(crate) struct FailedMarkApplicationDeliveredNativeValidationValidV0 {
    owner: Box<PreflightedCoreAcceptedNativeValidationValidV0>,
    cause: MarkApplicationDeliveredNativeValidationValidCauseV0,
}

impl std::fmt::Debug for FailedMarkApplicationDeliveredNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedMarkApplicationDeliveredNativeValidationValidV0")
            .field("cause", &self.cause)
            .field("retains_preflighted_owner", &true)
            .finish()
    }
}

impl FailedMarkApplicationDeliveredNativeValidationValidV0 {
    pub const fn cause(&self) -> &MarkApplicationDeliveredNativeValidationValidCauseV0 {
        &self.cause
    }

    pub fn into_owner_v0(self) -> PreflightedCoreAcceptedNativeValidationValidV0 {
        *self.owner
    }
}

#[must_use = "application Delivered must reach exact SafetyStore persistence"]
pub(crate) struct DeliveredCoreAcceptedNativeValidationValidV0 {
    callback: NativeValidationValidCallbackV0,
    persistence: SafetyStatePersistenceV0,
    preflight: NativeValidSafetyStatePreflightV0,
    application_delivery: ConfirmedNativeValidationValidDeliveredV0,
    context: SafetyTransitionContextV0,
}

impl std::fmt::Debug for DeliveredCoreAcceptedNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeliveredCoreAcceptedNativeValidationValidV0")
            .field("facts", &self.callback.facts)
            .field("barrier", &self.persistence.barrier())
            .field(
                "delivered_job_row_checksum",
                &self.application_delivery.delivered_job_row_checksum(),
            )
            .finish_non_exhaustive()
    }
}

pub(crate) enum PersistNativeValidationValidSafetyCauseV0 {
    Retryable {
        persist: Option<Box<SafetyStoreErrorV0>>,
        confirm: Box<SafetyStoreErrorV0>,
    },
    Quarantined {
        persist: Option<Box<SafetyStoreErrorV0>>,
        confirm: Box<SafetyStoreErrorV0>,
    },
    StoreIdentityMismatch,
}

impl std::fmt::Debug for PersistNativeValidationValidSafetyCauseV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retryable { persist, confirm } => formatter
                .debug_struct("Retryable")
                .field("persist", persist)
                .field("confirm", confirm)
                .finish(),
            Self::Quarantined { persist, confirm } => formatter
                .debug_struct("Quarantined")
                .field("persist", persist)
                .field("confirm", confirm)
                .finish(),
            Self::StoreIdentityMismatch => formatter.write_str("StoreIdentityMismatch"),
        }
    }
}

#[must_use = "a retryable safety failure retains Delivered; quarantine must not be resubmitted"]
pub(crate) struct FailedPersistNativeValidationValidSafetyV0 {
    owner: Box<DeliveredCoreAcceptedNativeValidationValidV0>,
    cause: Box<PersistNativeValidationValidSafetyCauseV0>,
}

impl std::fmt::Debug for FailedPersistNativeValidationValidSafetyV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedPersistNativeValidationValidSafetyV0")
            .field("cause", &self.cause)
            .field("facts", &self.owner.callback.facts)
            .field("retains_delivered_owner", &true)
            .finish()
    }
}

impl FailedPersistNativeValidationValidSafetyV0 {
    pub fn cause(&self) -> &PersistNativeValidationValidSafetyCauseV0 {
        self.cause.as_ref()
    }

    /// Only failures classified as unavailable/absent are retryable. Exact
    /// conflicts and cross-store readbacks remain quarantined in this type.
    pub fn into_retryable_owner_v0(
        self,
    ) -> Result<
        DeliveredCoreAcceptedNativeValidationValidV0,
        FailedPersistNativeValidationValidSafetyV0,
    > {
        if matches!(
            self.cause.as_ref(),
            PersistNativeValidationValidSafetyCauseV0::Retryable { .. }
        ) {
            Ok(*self.owner)
        } else {
            Err(self)
        }
    }
}

impl DeliveredCoreAcceptedNativeValidationValidV0 {
    pub(crate) fn persist_and_confirm_safety_v0<V: SignatureVerifier>(
        self,
        safety_store: &mut SqliteSafetyStateStoreV0<V>,
    ) -> Result<SafetyPersistedNativeValidationValidV0, FailedPersistNativeValidationValidSafetyV0>
    {
        let persist = safety_store
            .persist_exact_v0(&self.persistence, &self.context)
            .map(|_disposition: SafetyPersistDispositionV0| ());
        let persist_error = persist.err().map(Box::new);
        match safety_store
            .confirmed_native_valid_head_exact_v0(self.persistence.state(), &self.context)
        {
            Ok(confirmed)
                if confirmed.journal_id_v0() == self.preflight.journal_id_v0()
                    && confirmed.verifier_profile_ref_v0()
                        == self.preflight.verifier_profile_ref_v0()
                    && confirmed.state_record_checksum()
                        == self.preflight.state_record_checksum_v0() =>
            {
                drop(persist_error);
                Ok(SafetyPersistedNativeValidationValidV0 {
                    callback: self.callback,
                    persistence: self.persistence,
                    application_delivery: self.application_delivery,
                    context: self.context,
                    confirmed,
                })
            }
            Ok(_foreign) => Err(FailedPersistNativeValidationValidSafetyV0 {
                owner: Box::new(self),
                cause: Box::new(PersistNativeValidationValidSafetyCauseV0::StoreIdentityMismatch),
            }),
            Err(confirm) => {
                let retryable = persist_error
                    .as_deref()
                    .is_none_or(native_valid_safety_error_is_retryable_v0)
                    && native_valid_safety_error_is_retryable_v0(&confirm);
                let cause = if retryable {
                    PersistNativeValidationValidSafetyCauseV0::Retryable {
                        persist: persist_error,
                        confirm: Box::new(confirm),
                    }
                } else {
                    PersistNativeValidationValidSafetyCauseV0::Quarantined {
                        persist: persist_error,
                        confirm: Box::new(confirm),
                    }
                };
                Err(FailedPersistNativeValidationValidSafetyV0 {
                    owner: Box::new(self),
                    cause: Box::new(cause),
                })
            }
        }
    }
}

fn native_valid_safety_error_is_retryable_v0(error: &SafetyStoreErrorV0) -> bool {
    matches!(
        error,
        SafetyStoreErrorV0::Locked
            | SafetyStoreErrorV0::Io { .. }
            | SafetyStoreErrorV0::Sqlite { .. }
            | SafetyStoreErrorV0::CommitNotApplied { .. }
            | SafetyStoreErrorV0::MissingNativeValidTransition { .. }
    )
}

#[must_use = "confirmed SafetyStore persistence must enter application Acked"]
pub(crate) struct SafetyPersistedNativeValidationValidV0 {
    callback: NativeValidationValidCallbackV0,
    persistence: SafetyStatePersistenceV0,
    application_delivery: ConfirmedNativeValidationValidDeliveredV0,
    context: SafetyTransitionContextV0,
    confirmed: ConfirmedNativeValidHeadV0,
}

#[must_use = "an application acknowledgement failure retains exact SafetyStore readback"]
pub(crate) struct FailedAcknowledgeApplicationNativeValidationValidV0 {
    owner: Box<SafetyPersistedNativeValidationValidV0>,
    cause: Box<NativeValidationValidJournalTransitionFailureCauseV0>,
}

impl std::fmt::Debug for FailedAcknowledgeApplicationNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedAcknowledgeApplicationNativeValidationValidV0")
            .field("cause", &self.cause)
            .field("retains_confirmed_safety_owner", &true)
            .finish()
    }
}

impl FailedAcknowledgeApplicationNativeValidationValidV0 {
    pub fn cause(&self) -> &NativeValidationValidJournalTransitionFailureCauseV0 {
        self.cause.as_ref()
    }

    pub fn into_owner_v0(self) -> SafetyPersistedNativeValidationValidV0 {
        *self.owner
    }
}

impl SafetyPersistedNativeValidationValidV0 {
    pub(crate) fn acknowledge_application_v0(
        self,
        application_store: &ApplicationStore,
    ) -> Result<AckedNativeValidationValidV0, FailedAcknowledgeApplicationNativeValidationValidV0>
    {
        self.acknowledge_application_inner_v0(application_store, None)
    }

    #[cfg(test)]
    fn acknowledge_application_with_test_failpoint_v0(
        self,
        application_store: &ApplicationStore,
        failpoint: NativeValidationValidJournalFailpointV0,
    ) -> Result<AckedNativeValidationValidV0, FailedAcknowledgeApplicationNativeValidationValidV0>
    {
        self.acknowledge_application_inner_v0(application_store, Some(failpoint))
    }

    fn acknowledge_application_inner_v0(
        self,
        application_store: &ApplicationStore,
        #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<
            NativeValidationValidJournalFailpointV0,
        >,
    ) -> Result<AckedNativeValidationValidV0, FailedAcknowledgeApplicationNativeValidationValidV0>
    {
        #[cfg(test)]
        let acknowledged = match failpoint {
            Some(failpoint) => application_store
                .acknowledge_native_validation_valid_callback_with_test_failpoint_v0(
                    &self.callback.live,
                    &self.application_delivery,
                    &self.confirmed,
                    failpoint,
                ),
            None => application_store.acknowledge_native_validation_valid_callback_v0(
                &self.callback.live,
                &self.application_delivery,
                &self.confirmed,
            ),
        };
        #[cfg(not(test))]
        let acknowledged = application_store.acknowledge_native_validation_valid_callback_v0(
            &self.callback.live,
            &self.application_delivery,
            &self.confirmed,
        );
        match acknowledged {
            Ok(application_ack) => Ok(AckedNativeValidationValidV0 {
                callback: self.callback,
                persistence: self.persistence,
                application_delivery: self.application_delivery,
                application_ack,
                context: self.context,
                confirmed: self.confirmed,
            }),
            Err(cause) => Err(FailedAcknowledgeApplicationNativeValidationValidV0 {
                owner: Box::new(self),
                cause: Box::new(cause),
            }),
        }
    }
}

#[must_use = "application Acked still gates Core StorageAck"]
pub(crate) struct AckedNativeValidationValidV0 {
    callback: NativeValidationValidCallbackV0,
    persistence: SafetyStatePersistenceV0,
    application_delivery: ConfirmedNativeValidationValidDeliveredV0,
    application_ack: ConfirmedNativeValidationValidAckedV0,
    context: SafetyTransitionContextV0,
    confirmed: ConfirmedNativeValidHeadV0,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ReleaseNativeValidationValidCauseV0 {
    ApplicationDeliveryFactsMismatch,
    CoreAffinityMismatch,
    CoreStateMismatch,
    Core(Box<CoreError>),
}

impl std::fmt::Debug for ReleaseNativeValidationValidCauseV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApplicationDeliveryFactsMismatch => {
                formatter.write_str("ApplicationDeliveryFactsMismatch")
            }
            Self::CoreAffinityMismatch => formatter.write_str("CoreAffinityMismatch"),
            Self::CoreStateMismatch => formatter.write_str("CoreStateMismatch"),
            Self::Core(error) => formatter.debug_tuple("Core").field(error).finish(),
        }
    }
}

#[must_use = "a rejected StorageAck retains its exact acknowledged owner"]
pub(crate) struct RejectedReleaseNativeValidationValidV0 {
    owner: Box<AckedNativeValidationValidV0>,
    cause: ReleaseNativeValidationValidCauseV0,
}

impl RejectedReleaseNativeValidationValidV0 {
    pub const fn cause(&self) -> &ReleaseNativeValidationValidCauseV0 {
        &self.cause
    }

    pub fn into_owner_v0(self) -> AckedNativeValidationValidV0 {
        *self.owner
    }
}

#[must_use = "a successful but mismatched StorageAck is quarantined"]
pub(crate) struct InvalidReleasedNativeValidationValidV0 {
    owner: Box<AckedNativeValidationValidV0>,
    observed_state: SafetyState,
    effects: Vec<Effect>,
}

pub(crate) enum FailedReleaseNativeValidationValidV0 {
    Rejected(Box<RejectedReleaseNativeValidationValidV0>),
    ReleasedInvariant(Box<InvalidReleasedNativeValidationValidV0>),
}

impl std::fmt::Debug for FailedReleaseNativeValidationValidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(failure) => formatter
                .debug_struct("Rejected")
                .field("cause", &failure.cause)
                .field("retains_acked_owner", &true)
                .finish(),
            Self::ReleasedInvariant(failure) => formatter
                .debug_struct("ReleasedInvariant")
                .field("facts", &failure.owner.callback.facts)
                .field("observed_state", &failure.observed_state)
                .field("effects", &failure.effects)
                .field("quarantines_acked_owner", &true)
                .finish(),
        }
    }
}

#[must_use = "released effects must be driven by the production host"]
pub(crate) struct ReleasedNativeValidationValidV0 {
    app_facts: NativeValidationValidAppFactsV0,
    effects: Vec<Effect>,
}

impl ReleasedNativeValidationValidV0 {
    pub const fn app_facts_v0(&self) -> NativeValidationValidAppFactsV0 {
        self.app_facts
    }

    pub fn effects_v0(&self) -> &[Effect] {
        &self.effects
    }
}

impl AckedNativeValidationValidV0 {
    pub(crate) fn release_core_storage_ack_v0<V: SignatureVerifier>(
        self,
        core: &mut Core,
        verifier: &V,
    ) -> Result<ReleasedNativeValidationValidV0, FailedReleaseNativeValidationValidV0> {
        release_core_storage_ack_target_v0(self, core, verifier)
    }

    pub(crate) fn release_state_sync_anchor_successor_storage_ack_v0<V: SignatureVerifier>(
        self,
        replay: &mut StateSyncAnchorSuccessorReplayV0,
        verifier: &V,
    ) -> Result<ReleasedNativeValidationValidV0, FailedReleaseNativeValidationValidV0> {
        release_core_storage_ack_target_v0(self, replay, verifier)
    }
}

fn release_core_storage_ack_target_v0<T: NativeValidCoreTargetV0, V: SignatureVerifier>(
    owner: AckedNativeValidationValidV0,
    target: &mut T,
    verifier: &V,
) -> Result<ReleasedNativeValidationValidV0, FailedReleaseNativeValidationValidV0> {
    let Some(app_facts) = join_native_validation_valid_app_facts_at_delivery_v0(
        owner.callback.facts,
        &owner.callback.live,
        &owner.application_delivery,
    ) else {
        return Err(FailedReleaseNativeValidationValidV0::Rejected(Box::new(
            RejectedReleaseNativeValidationValidV0 {
                owner: Box::new(owner),
                cause: ReleaseNativeValidationValidCauseV0::ApplicationDeliveryFactsMismatch,
            },
        )));
    };
    if !target.persistence_binding_v0().accepts(&owner.persistence) {
        return Err(FailedReleaseNativeValidationValidV0::Rejected(Box::new(
            RejectedReleaseNativeValidationValidV0 {
                owner: Box::new(owner),
                cause: ReleaseNativeValidationValidCauseV0::CoreAffinityMismatch,
            },
        )));
    }
    if target.safety_state_v0() != owner.persistence.state() {
        return Err(FailedReleaseNativeValidationValidV0::Rejected(Box::new(
            RejectedReleaseNativeValidationValidV0 {
                owner: Box::new(owner),
                cause: ReleaseNativeValidationValidCauseV0::CoreStateMismatch,
            },
        )));
    }
    let action = owner.application_delivery.post_ack_action();
    let barrier = owner.persistence.barrier();
    let effects = match target.step_storage_ack_target_v0(barrier, verifier) {
        Ok(effects) => effects,
        Err(error) => {
            return Err(FailedReleaseNativeValidationValidV0::Rejected(Box::new(
                RejectedReleaseNativeValidationValidV0 {
                    owner: Box::new(owner),
                    cause: ReleaseNativeValidationValidCauseV0::Core(Box::new(error)),
                },
            )));
        }
    };
    if target.safety_state_v0() != owner.persistence.state()
        || !native_valid_effects_match_action_v0(action, &effects)
    {
        return Err(FailedReleaseNativeValidationValidV0::ReleasedInvariant(
            Box::new(InvalidReleasedNativeValidationValidV0 {
                owner: Box::new(owner),
                observed_state: target.safety_state_v0().clone(),
                effects,
            }),
        ));
    }
    drop((
        owner.callback,
        owner.persistence,
        owner.application_delivery,
        owner.application_ack,
        owner.context,
        owner.confirmed,
    ));
    Ok(ReleasedNativeValidationValidV0 { app_facts, effects })
}

fn native_valid_effects_match_action_v0(
    action: NativeValidPostAckActionV0,
    effects: &[Effect],
) -> bool {
    matches!(
        (action, effects),
        (NativeValidPostAckActionV0::None, [])
            | (
                NativeValidPostAckActionV0::RequestSignature,
                [Effect::RequestSignature { .. }]
            )
            | (
                NativeValidPostAckActionV0::ArmViewTimer,
                [Effect::ArmViewTimer { .. }]
            )
            | (
                NativeValidPostAckActionV0::RequestTcHighQcSync,
                [Effect::RequestTcHighQcSync { .. }]
            )
            | (
                NativeValidPostAckActionV0::RequestStandaloneQcSync,
                [Effect::RequestStandaloneQcSync { .. }],
            )
            | (
                NativeValidPostAckActionV0::SafetyHaltedConflict,
                [Effect::SafetyHalted(_)]
            )
            | (
                NativeValidPostAckActionV0::ArmViewTimerThenFinalize,
                [Effect::ArmViewTimer { .. }, Effect::Finalize(_)],
            )
            | (
                NativeValidPostAckActionV0::ArmViewTimerThenRequestStandaloneQcSync,
                [
                    Effect::ArmViewTimer { .. },
                    Effect::RequestStandaloneQcSync { .. }
                ],
            )
    )
}

fn bind_live_valid_callback_v0(
    safety_state: &SafetyState,
    callback: &NativeValidationValidCallbackV0,
    commitments: ValidatedBlockCommitmentsV0,
    artifact_ref: ValidatedPayloadArtifactRefV0,
) -> Result<(), NativeValidationValidCallbackBindFailureV0> {
    let facts = callback.facts;
    let same_id_obligations: Vec<_> = safety_state
        .payload_validation_obligations()
        .iter()
        .filter(|obligation| obligation.id() == facts.validation_id)
        .collect();
    let same_id_completions = safety_state
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.id() == facts.validation_id)
        .count();
    if same_id_obligations.len() > 1 || same_id_completions > 0 {
        return Err(NativeValidationValidCallbackBindFailureV0::DuplicateCoreIdentity);
    }
    let Some(obligation) = same_id_obligations.first() else {
        return Err(NativeValidationValidCallbackBindFailureV0::MissingObligation);
    };
    if obligation.route() != facts.route {
        return Err(NativeValidationValidCallbackBindFailureV0::RouteMismatch);
    }
    let fingerprint = native_validation_request_fingerprint_v0(
        obligation.route(),
        obligation.id(),
        obligation.proposal().block(),
        obligation.parent(),
    )
    .map_err(|_| NativeValidationValidCallbackBindFailureV0::RequestFingerprintDerivation)?;
    if fingerprint != facts.request_fingerprint {
        return Err(NativeValidationValidCallbackBindFailureV0::RequestFingerprintMismatch);
    }

    if commitments.block_id() != facts.validation_id.block_id() {
        return Err(NativeValidationValidCallbackBindFailureV0::CommitmentBlockMismatch);
    }
    if artifact_ref.source_artifact_checksum() != facts.artifact_checksum {
        return Err(NativeValidationValidCallbackBindFailureV0::ArtifactSourceMismatch);
    }
    if artifact_ref.overlay().block_id() != facts.validation_id.block_id() {
        return Err(NativeValidationValidCallbackBindFailureV0::ArtifactTargetMismatch);
    }
    if artifact_ref.overlay().parent_block_id()
        != obligation.proposal().block().header().parent_id()
    {
        return Err(NativeValidationValidCallbackBindFailureV0::ArtifactParentMismatch);
    }
    Ok(())
}

fn validate_core_accepted_valid_callback_v0(
    safety_state: &SafetyState,
    callback: &NativeValidationValidCallbackV0,
    commitments: ValidatedBlockCommitmentsV0,
    artifact_ref: ValidatedPayloadArtifactRefV0,
    before_revision: u64,
    before_pending_sign: Option<&SignIntent>,
    effects: &[Effect],
) -> Result<(SafetyStatePersistenceV0, u64, [u8; 32]), CoreAcceptedNativeValidationValidInvariantV0>
{
    let [Effect::PersistSafetyState(persistence)] = effects else {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::UnexpectedEffectSet);
    };
    let state = persistence.state();
    if persistence.barrier().get() != state.revision() {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::BarrierRevisionMismatch);
    }
    if state != safety_state {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::PersistedStateMismatch);
    }
    if before_revision.checked_add(1) != Some(state.revision()) {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::RevisionTransitionMismatch);
    }

    let facts = callback.facts;
    if state
        .payload_validation_obligations()
        .iter()
        .any(|obligation| obligation.id() == facts.validation_id)
    {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::ObligationRetained);
    }
    let mut completions = state
        .payload_validation_completions()
        .iter()
        .filter(|completion| completion.id() == facts.validation_id);
    let Some(completion) = completions.next() else {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::CompletionMissingOrChanged);
    };
    let completion_matches = match completion.result() {
        DurablePayloadValidationResultV1::Valid {
            commitments: durable,
            artifact_ref: durable_artifact,
        } => {
            durable.block_id() == commitments.block_id()
                && durable.logical_block_size() == commitments.logical_block_size()
                && durable.transaction_count() == commitments.transaction_count()
                && durable.evidence_count() == commitments.evidence_count()
                && durable_artifact == artifact_ref
        }
        DurablePayloadValidationResultV1::Unavailable
        | DurablePayloadValidationResultV1::DeterministicallyInvalid => false,
    };
    if completions.next().is_some() || completion.route() != facts.route || !completion_matches {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::CompletionMissingOrChanged);
    }
    if completion.first_recorded_revision() != state.revision() {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::CompletionRevisionMismatch);
    }

    let Some(terminal) = state.payload_terminal_fact(facts.validation_id.block_id()) else {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::TerminalFactMissingOrChanged);
    };
    if terminal.result() != PayloadTerminalResult::Valid
        || terminal.valid_overlay() != Some(facts.artifact_ref.overlay())
    {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::TerminalFactMissingOrChanged);
    }
    if terminal.first_recorded_revision() > state.revision() {
        return Err(CoreAcceptedNativeValidationValidInvariantV0::TerminalFactRevisionMismatch);
    }

    let after_pending_sign = state.pending_sign();
    if after_pending_sign != before_pending_sign {
        match (facts.route, after_pending_sign) {
            (
                PayloadValidationRouteV0::Proposal,
                Some(SignIntent::Vote {
                    authorizing_safety_revision,
                    block_id,
                    ..
                }),
            ) if *authorizing_safety_revision == state.revision()
                && *block_id == facts.validation_id.block_id() => {}
            _ => {
                return Err(
                    CoreAcceptedNativeValidationValidInvariantV0::UnexpectedSigningTransition,
                );
            }
        }
    }

    let valid_result_checksum = native_valid_result_checksum_v0(completion.result())
        .ok_or(CoreAcceptedNativeValidationValidInvariantV0::ValidResultChecksumMismatch)?;
    Ok((
        persistence.clone(),
        completion.first_recorded_revision(),
        valid_result_checksum,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use trnm_consensus_core::{Input, PayloadValidationRouteV0, SafetyStateRecordLimitsV0};
    use trnm_consensus_safety_store::{
        SafetyPersistDispositionV0, SafetyStateStoreProfileV0, SqliteSafetyStateStoreV0,
    };
    use trnm_consensus_types::{SignatureBytes, SignatureVerifier, SigningRoot, Validator};

    use crate::{
        native_payload_validation::{
            durable_valid_seal_test_fixture_v0,
            durable_valid_seal_test_fixture_with_authenticated_safety_v0,
        },
        store::{
            NativeValidationJobStateV0, NativeValidationValidJournalFailpointV0,
            NativeValidationValidSealDecisionV0,
        },
        NativeConsensusApplicationHostConfigV0, NativeConsensusApplicationHostV0,
        NativeConsensusApplicationValidCompletionSourceV0,
    };

    use super::{
        CoreAcceptedNativeValidationValidV0, NativeValidationValidCallbackFailureV0,
        NativeValidationValidCallbackRejectionV0, NativeValidationValidCallbackV0,
    };

    #[derive(Clone, Copy)]
    struct CoreRootSignatures;

    impl SignatureVerifier for CoreRootSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature.as_bytes()[..32] == signing_root.as_bytes()[..]
                && signature.as_bytes()[32..] == signing_root.as_bytes()[..]
        }
    }

    fn live_safety_store_path_v0(route: PayloadValidationRouteV0) -> (PathBuf, PathBuf) {
        let route = match route {
            PayloadValidationRouteV0::Proposal => "proposal",
            PayloadValidationRouteV0::Synced => "synced",
        };
        let root = std::env::temp_dir().join(format!(
            "trnm-live-valid-{route}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create live Valid safety-store directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect live Valid safety-store directory");
        let path = root.join("safety.sqlite3");
        (root, path)
    }

    fn sealed_live_callback_v0(
        route: PayloadValidationRouteV0,
    ) -> (trnm_consensus_core::Core, NativeValidationValidCallbackV0) {
        let mut fixture = durable_valid_seal_test_fixture_v0(route);
        let core = fixture.take_core_v0();
        let prepared = fixture.take_prepared_v0();
        let live = match fixture
            .store_v0()
            .seal_durable_valid_and_enqueue_callback_v0(prepared)
            .expect("atomically seal genuine all-family Valid callback")
        {
            NativeValidationValidSealDecisionV0::CallbackPending(live) => live,
            NativeValidationValidSealDecisionV0::Existing(_) => {
                panic!("fresh genuine Valid callback unexpectedly already existed")
            }
        };
        (core, *live)
    }

    fn assert_core_accepted_v0(accepted: &CoreAcceptedNativeValidationValidV0) {
        assert_eq!(
            accepted.barrier_v0().get(),
            accepted.persistence_request_v0().state().revision()
        );
        assert_eq!(
            accepted.completion_revision_v0(),
            accepted.persistence_request_v0().state().revision()
        );
        assert_eq!(
            accepted.app_facts_v0().artifact_ref().overlay().block_id(),
            accepted.app_facts_v0().validation_id().block_id()
        );
        assert_eq!(
            accepted
                .app_facts_v0()
                .artifact_ref()
                .source_artifact_checksum(),
            accepted.app_facts_v0().artifact_checksum()
        );
    }

    #[test]
    fn owner_preserving_failure_recovery_surfaces_remain_reachable_v0() {
        fn retain_method_v0<T>(_method: T) {}

        retain_method_v0(super::FailedPreflightCoreAcceptedNativeValidationValidV0::error);
        retain_method_v0(super::FailedPreflightCoreAcceptedNativeValidationValidV0::into_owner_v0);
        retain_method_v0(super::FailedPersistNativeValidationValidSafetyV0::cause);
        retain_method_v0(
            super::FailedPersistNativeValidationValidSafetyV0::into_retryable_owner_v0,
        );
        retain_method_v0(super::RejectedReleaseNativeValidationValidV0::cause);
        retain_method_v0(super::RejectedReleaseNativeValidationValidV0::into_owner_v0);
    }

    #[test]
    fn genuine_proposal_and_synced_valid_callbacks_cross_only_the_core_persist_boundary_v0() {
        for route in [
            PayloadValidationRouteV0::Proposal,
            PayloadValidationRouteV0::Synced,
        ] {
            let (mut core, callback) = sealed_live_callback_v0(route);
            let callback_facts = callback.app_facts_v0();
            let before_revision = core.safety_state().revision();
            let before_last_voted_view = core.safety_state().last_voted_view();
            let before_pending_sign = core.safety_state().pending_sign().cloned();
            assert!(
                before_pending_sign.is_none(),
                "the callback boundary fixture must start without an older sign outbox"
            );
            if route == PayloadValidationRouteV0::Proposal {
                // Genuine three-chain finality leaves the lock one generation
                // ahead of the finalized tip. This fixture intentionally
                // validates another direct finalized-tip child, so Valid may
                // be persisted but cannot authorize a vote: it neither
                // extends that newer lock nor carries a higher-view justify.
                let obligation = core
                    .safety_state()
                    .payload_validation_obligations()
                    .iter()
                    .find(|obligation| obligation.id() == callback_facts.validation_id())
                    .expect("the live Proposal callback retains its exact Core obligation");
                let proposal = obligation.proposal();
                let finalized = core.safety_state().finalized();
                let locked = core.safety_state().locked_qc().qc_ref();
                let justify = proposal.witness().justify_qc().qc_ref();

                assert_eq!(
                    proposal.block().header().view(),
                    core.safety_state().current_view(),
                    "the fixture must reach the ordinary current-view vote gate"
                );
                assert_eq!(
                    proposal.block().header().parent_id(),
                    finalized.block_id(),
                    "the finalized-parent application fixture must expose its exact branch"
                );
                assert_ne!(
                    locked.block_id(),
                    finalized.block_id(),
                    "genuine three-chain finality must retain the newer HotStuff lock"
                );
                assert_ne!(
                    proposal.block().id(),
                    locked.block_id(),
                    "the new finalized-parent proposal must not be the locked descendant"
                );
                assert!(
                    justify.view() <= locked.view(),
                    "the finalized-parent fixture must not unlock the newer HotStuff lock"
                );
            }
            let accepted = callback
                .submit_to_core_v0(&mut core, &CoreRootSignatures)
                .expect("submit exact sealed callback to its issuing Core");
            assert_core_accepted_v0(&accepted);
            assert_eq!(core.safety_state().revision(), before_revision + 1);
            assert_eq!(accepted.app_facts_v0().route(), route);
            assert!(core
                .safety_state()
                .payload_validation_obligations()
                .iter()
                .all(|obligation| { obligation.id() != accepted.app_facts_v0().validation_id() }));

            let pending_sign = core.safety_state().pending_sign();
            match route {
                PayloadValidationRouteV0::Proposal => {
                    assert_eq!(
                        pending_sign,
                        before_pending_sign.as_ref(),
                        "sealing Valid application state must not bypass the HotStuff lock gate"
                    );
                    assert_eq!(
                        core.safety_state().last_voted_view(),
                        before_last_voted_view,
                        "a lock-blocked Valid proposal must not advance the vote watermark"
                    );
                }
                PayloadValidationRouteV0::Synced => {
                    assert_eq!(pending_sign, before_pending_sign.as_ref());
                    assert_eq!(
                        core.safety_state().last_voted_view(),
                        before_last_voted_view,
                        "the synced route must never create a vote watermark"
                    );
                }
            }
        }
    }

    #[test]
    fn proposal_and_synced_valid_run_crash_safe_p_d_c_k_storage_ack_v0() {
        for route in [
            PayloadValidationRouteV0::Proposal,
            PayloadValidationRouteV0::Synced,
        ] {
            let mut fixture = durable_valid_seal_test_fixture_v0(route);
            let core_config = fixture.core_config_v0().clone();
            let genesis_state = fixture.genesis_state_v0().clone();
            let history = fixture.take_safety_history_v0();
            let mut core = fixture.take_core_v0();
            let prepared = fixture.take_prepared_v0();
            let application_store = fixture.store_v0();
            let callback = match application_store
                .seal_durable_valid_and_enqueue_callback_v0(prepared)
                .expect("atomically seal genuine all-family Valid callback")
            {
                NativeValidationValidSealDecisionV0::CallbackPending(callback) => *callback,
                NativeValidationValidSealDecisionV0::Existing(_) => {
                    panic!("fresh live Valid flow unexpectedly reopened an existing callback")
                }
            };

            let (safety_root, safety_path) = live_safety_store_path_v0(route);
            let safety_profile = SafetyStateStoreProfileV0::new(
                core_config,
                [0x91; 32],
                SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
                    .expect("construct live Valid safety record limits"),
                192 * 1024 * 1024,
            )
            .expect("construct live Valid safety-store profile");
            let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
                &safety_path,
                safety_profile,
                CoreRootSignatures,
                &genesis_state,
            )
            .expect("initialize the live Valid journal from revision zero");
            safety_store
                .bind_core_v0(core.safety_state_persistence_binding_v0())
                .expect("bind the exact issuing Core to its SafetyStore");
            assert!(
                !history.is_empty(),
                "fixture must retain its real Core history"
            );
            for (index, (persistence, context)) in history.into_iter().enumerate() {
                assert_eq!(
                    persistence.state().revision(),
                    u64::try_from(index).expect("history index fits u64") + 1,
                    "recorded Core persistence history must be gap-free from genesis"
                );
                assert_eq!(
                    safety_store
                        .persist_exact_v0(&persistence, &context)
                        .expect("replay exact historical Core persistence"),
                    SafetyPersistDispositionV0::Inserted
                );
            }
            assert_eq!(
                safety_store
                    .head()
                    .expect("read replayed pre-callback safety head")
                    .state(),
                core.safety_state()
            );

            let accepted = callback
                .submit_to_core_v0(&mut core, &CoreRootSignatures)
                .expect("Core accepts the exact live Valid callback");
            let preflighted = accepted
                .preflight_safety_store_v0(&safety_store)
                .expect("preflight exact bound Core persistence without writing");
            let delivered = preflighted
                .mark_application_delivered_v0(application_store)
                .expect("advance application callback P to exact D");
            let expected_action = delivered.application_delivery.post_ack_action();
            let delivered_work = application_store
                .load_native_validation_recovery_work_v0()
                .expect("deep-read application D");
            assert_eq!(delivered_work.len(), 1);
            assert_eq!(
                delivered_work[0].state(),
                NativeValidationJobStateV0::Delivered
            );

            let persisted = delivered
                .persist_and_confirm_safety_v0(&mut safety_store)
                .expect("persist and exactly confirm C after application D");
            assert_eq!(
                safety_store
                    .confirmed_native_valid_head_v0()
                    .expect("read exact live native Valid head")
                    .state(),
                core.safety_state()
            );
            let acked = persisted
                .acknowledge_application_v0(application_store)
                .expect("advance exact application D to K and retire its outbox");
            let acked_work = application_store
                .load_native_validation_recovery_work_v0()
                .expect("deep-read application K");
            assert_eq!(acked_work.len(), 1);
            assert_eq!(acked_work[0].state(), NativeValidationJobStateV0::Acked);

            let released = acked
                .release_core_storage_ack_v0(&mut core, &CoreRootSignatures)
                .expect("release StorageAck only after exact application K");
            assert_eq!(released.app_facts_v0().route(), route);
            assert!(super::native_valid_effects_match_action_v0(
                expected_action,
                released.effects_v0()
            ));
            assert!(released.effects_v0().iter().all(|effect| !matches!(
                effect,
                trnm_consensus_core::Effect::PersistSafetyState(_)
            )));

            drop(safety_store);
            fs::remove_dir_all(safety_root).expect("remove live Valid safety-store test directory");
        }
    }

    fn authored_ordinary_native_valid_c_d_fixture_v0() -> (
        PathBuf,
        PathBuf,
        trnm_consensus_core::CoreConfig,
        crate::ConsensusAppConfig,
        trnm_consensus_core::SafetyState,
        PathBuf,
    ) {
        let route = PayloadValidationRouteV0::Synced;
        let (safety_root, safety_path) = live_safety_store_path_v0(route);
        let authoring_safety_path = safety_path.clone();
        let (core_config, application_config, recovery_state, application_root) =
            std::thread::Builder::new()
                .name("native-valid-c-d-authoring".to_owned())
                .stack_size(32 * 1024 * 1024)
                .spawn(move || {
                    let (mut fixture, mut safety_store) =
                        durable_valid_seal_test_fixture_with_authenticated_safety_v0(
                            route,
                            &authoring_safety_path,
                        );
                    let core_config = fixture.core_config_v0().clone();
                    let application_config = fixture.application_config_v0();
                    let mut core = fixture.take_core_v0();
                    let prepared = fixture.take_prepared_v0();
                    let application_store = fixture.store_v0();
                    let callback = match application_store
                        .seal_durable_valid_and_enqueue_callback_v0(prepared)
                        .expect("seal genuine native-Valid callback")
                    {
                        NativeValidationValidSealDecisionV0::CallbackPending(callback) => *callback,
                        NativeValidationValidSealDecisionV0::Existing(_) => {
                            panic!("fresh native-Valid recovery fixture unexpectedly existed")
                        }
                    };
                    let accepted = callback
                        .submit_to_core_v0(&mut core, &CoreRootSignatures)
                        .expect("Core accepts genuine native-Valid callback");
                    let delivered = accepted
                        .preflight_safety_store_v0(&safety_store)
                        .expect("preflight exact native-Valid Safety persistence")
                        .mark_application_delivered_v0(application_store)
                        .expect("advance genuine App callback P to D");
                    let persisted = delivered
                        .persist_and_confirm_safety_v0(&mut safety_store)
                        .expect("persist genuine native-Valid C after App D");
                    drop(persisted);
                    let recovery_state = core.safety_state().clone();
                    assert_eq!(
                        application_store
                            .load_native_validation_recovery_work_v0()
                            .expect("deep-read genuine C+D source")[0]
                            .state(),
                        NativeValidationJobStateV0::Delivered,
                    );
                    let application_root = fixture.preserve_application_namespace_for_recovery_v0();
                    drop((core, safety_store, fixture));
                    (
                        core_config,
                        application_config,
                        recovery_state,
                        application_root,
                    )
                })
                .expect("spawn large-stack genuine C+D authoring thread")
                .join()
                .expect("join genuine C+D authoring thread");
        (
            safety_root,
            safety_path,
            core_config,
            application_config,
            recovery_state,
            application_root,
        )
    }

    fn open_authored_native_valid_safety_store_v0(
        safety_path: &std::path::Path,
        core_config: trnm_consensus_core::CoreConfig,
    ) -> SqliteSafetyStateStoreV0<CoreRootSignatures> {
        let safety_profile = SafetyStateStoreProfileV0::new(
            core_config,
            [0x93; 32],
            SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
                .expect("reconstruct recovery Safety record limits"),
            192 * 1024 * 1024,
        )
        .expect("reconstruct recovery SafetyStore profile");
        SqliteSafetyStateStoreV0::open_existing(safety_path, safety_profile, CoreRootSignatures)
            .expect("default-stack reopen of authored native-Valid SafetyStore")
    }

    #[test]
    fn ordinary_native_valid_completion_recovery_rejects_unbacked_historical_core_completions_v0() {
        let route = PayloadValidationRouteV0::Synced;
        let (
            safety_root,
            safety_path,
            core_config,
            application_config,
            recovery_state,
            application_root,
        ) = authored_ordinary_native_valid_c_d_fixture_v0();
        let safety_store =
            open_authored_native_valid_safety_store_v0(&safety_path, core_config.clone());
        let host = NativeConsensusApplicationHostV0::open_existing_v0(
            NativeConsensusApplicationHostConfigV0::from_authenticated_safety_store_v0(
                application_config,
                &safety_store,
            )
            .expect("derive exact App host config from live SafetyStore"),
        )
        .expect("open existing-only App recovery host");

        assert!(recovery_state.payload_validation_obligations().is_empty());
        assert_eq!(
            recovery_state
                .payload_validation_completions()
                .iter()
                .filter(|completion| {
                    completion.first_recorded_revision() == recovery_state.revision()
                })
                .count(),
            1,
            "the genuine Core history has exactly one current completion",
        );
        assert!(
            recovery_state
                .payload_validation_completions()
                .iter()
                .any(|completion| {
                    completion.first_recorded_revision() < recovery_state.revision()
                }),
            "a genuine positive-height ordinary parent permanently retains historical Valid completions",
        );
        let session = trnm_consensus_core::Core::begin_native_valid_completion_recovery_v0(
            core_config,
            recovery_state,
            &CoreRootSignatures,
        )
        .expect("begin exact current native-Valid recovery challenge");
        assert_eq!(session.challenge().route_v0(), route);
        let error = host
            .recover_native_valid_completion_v0(
                session.challenge(),
                &safety_store,
                &safety_path,
                safety_store
                    .confirmed_native_valid_head_v0()
                    .expect("confirm exact native-Valid Safety head"),
            )
            .expect_err(
                "an App namespace that omits genuine historical Core Valid sources must fail closed",
            );
        assert_eq!(
            error,
            crate::NativeConsensusApplicationHostErrorV0::NativeValidCompletionRecoveryUnavailable,
        );
        drop((session, host, safety_store));
        fs::remove_dir_all(safety_root)
            .expect("remove fail-closed native-Valid recovery SafetyStore directory");
        fs::remove_dir_all(application_root)
            .expect("remove fail-closed native-Valid recovery AppStore directory");
    }

    #[test]
    fn model_only_native_valid_stable_cut_kernel_closes_c_d_to_k_and_reopens_c_k_v0() {
        let route = PayloadValidationRouteV0::Synced;
        let (
            safety_root,
            safety_path,
            core_config,
            application_config,
            recovery_state,
            application_root,
        ) = authored_ordinary_native_valid_c_d_fixture_v0();
        let safety_store =
            open_authored_native_valid_safety_store_v0(&safety_path, core_config.clone());
        let open_host = || {
            NativeConsensusApplicationHostV0::open_existing_v0(
                NativeConsensusApplicationHostConfigV0::from_authenticated_safety_store_v0(
                    application_config.clone(),
                    &safety_store,
                )
                .expect("derive exact model-only App host configuration"),
            )
            .expect("open model-only stable-cut App host")
        };
        let session = trnm_consensus_core::Core::begin_native_valid_completion_recovery_v0(
            core_config.clone(),
            recovery_state.clone(),
            &CoreRootSignatures,
        )
        .expect("begin model-only current completion challenge");

        let host = open_host();
        let safety = safety_store
            .confirmed_native_valid_head_v0()
            .expect("confirm model-only C+D Safety head");
        assert_eq!(
            host.exercise_native_valid_completion_stable_cut_kernel_for_test_v0(
                session.challenge(),
                &safety_store,
                &safety_path,
                &safety,
            )
            .expect("model-only detached kernel advances exact C+D to C+K"),
            NativeConsensusApplicationValidCompletionSourceV0::Delivered,
        );
        drop((safety, host));

        let host = open_host();
        let safety = safety_store
            .confirmed_native_valid_head_v0()
            .expect("confirm unchanged Safety head for model-only C+K reopen");
        assert_eq!(
            host.exercise_native_valid_completion_stable_cut_kernel_for_test_v0(
                session.challenge(),
                &safety_store,
                &safety_path,
                &safety,
            )
            .expect("model-only detached kernel confirms exact C+K idempotently"),
            NativeConsensusApplicationValidCompletionSourceV0::Acked,
        );
        assert_eq!(session.challenge().route_v0(), route);
        drop((safety, host, session, safety_store));
        fs::remove_dir_all(safety_root)
            .expect("remove model-only native-Valid recovery SafetyStore directory");
        fs::remove_dir_all(application_root)
            .expect("remove model-only native-Valid recovery AppStore directory");
    }

    #[test]
    fn valid_d_and_k_failpoints_rollback_or_confirm_exact_commit_v0() {
        let route = PayloadValidationRouteV0::Synced;
        let mut fixture = durable_valid_seal_test_fixture_v0(route);
        let core_config = fixture.core_config_v0().clone();
        let genesis_state = fixture.genesis_state_v0().clone();
        let history = fixture.take_safety_history_v0();
        let mut core = fixture.take_core_v0();
        let prepared = fixture.take_prepared_v0();
        let application_store = fixture.store_v0();
        let callback = match application_store
            .seal_durable_valid_and_enqueue_callback_v0(prepared)
            .expect("seal failpoint Valid callback")
        {
            NativeValidationValidSealDecisionV0::CallbackPending(callback) => *callback,
            NativeValidationValidSealDecisionV0::Existing(_) => {
                panic!("fresh failpoint fixture unexpectedly existed")
            }
        };
        let (safety_root, safety_path) = live_safety_store_path_v0(route);
        let profile = SafetyStateStoreProfileV0::new(
            core_config,
            [0x92; 32],
            SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
                .expect("construct failpoint record limits"),
            192 * 1024 * 1024,
        )
        .expect("construct failpoint SafetyStore profile");
        let mut safety_store = SqliteSafetyStateStoreV0::initialize_new(
            &safety_path,
            profile,
            CoreRootSignatures,
            &genesis_state,
        )
        .expect("initialize failpoint SafetyStore");
        safety_store
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .expect("bind failpoint issuing Core");
        for (persistence, context) in history {
            safety_store
                .persist_exact_v0(&persistence, &context)
                .expect("replay failpoint fixture history");
        }

        let accepted = callback
            .submit_to_core_v0(&mut core, &CoreRootSignatures)
            .expect("Core accepts failpoint Valid callback");
        let preflighted = accepted
            .preflight_safety_store_v0(&safety_store)
            .expect("preflight failpoint persistence");
        let failure = preflighted
            .mark_application_delivered_with_test_failpoint_v0(
                application_store,
                NativeValidationValidJournalFailpointV0::DeliveryBeforeCommit,
            )
            .expect_err("delivery precommit failpoint must retain P owner");
        let _cause = failure.cause();
        let preflighted = failure.into_owner_v0();
        assert_eq!(
            application_store
                .load_native_validation_recovery_work_v0()
                .expect("read rolled-back P")[0]
                .state(),
            NativeValidationJobStateV0::CallbackPending
        );
        let delivered = preflighted
            .mark_application_delivered_with_test_failpoint_v0(
                application_store,
                NativeValidationValidJournalFailpointV0::DeliveryAfterCommitBeforeReturn,
            )
            .expect("delivery uncertainty must resolve by exact D readback");
        assert_eq!(
            application_store
                .load_native_validation_recovery_work_v0()
                .expect("read confirmed D")[0]
                .state(),
            NativeValidationJobStateV0::Delivered
        );

        let persisted = delivered
            .persist_and_confirm_safety_v0(&mut safety_store)
            .expect("persist failpoint native Valid C");
        let failure = match persisted.acknowledge_application_with_test_failpoint_v0(
            application_store,
            NativeValidationValidJournalFailpointV0::AcknowledgementBeforeCommit,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("acknowledgement precommit failpoint unexpectedly committed K"),
        };
        let _cause = failure.cause();
        let persisted = failure.into_owner_v0();
        assert_eq!(
            application_store
                .load_native_validation_recovery_work_v0()
                .expect("read rolled-back D")[0]
                .state(),
            NativeValidationJobStateV0::Delivered
        );
        let acked = persisted
            .acknowledge_application_with_test_failpoint_v0(
                application_store,
                NativeValidationValidJournalFailpointV0::AcknowledgementAfterCommitBeforeReturn,
            )
            .expect("ack uncertainty must resolve by exact K readback");
        assert_eq!(
            application_store
                .load_native_validation_recovery_work_v0()
                .expect("read confirmed K")[0]
                .state(),
            NativeValidationJobStateV0::Acked
        );
        let _released = acked
            .release_core_storage_ack_v0(&mut core, &CoreRootSignatures)
            .expect("release exact StorageAck after failpoint-confirmed K");

        drop(safety_store);
        fs::remove_dir_all(safety_root).expect("remove failpoint SafetyStore directory");
    }

    #[test]
    fn foreign_core_clone_rejects_the_store_proof_and_returns_same_callback_for_retry_v0() {
        let (mut issuing_core, callback) =
            sealed_live_callback_v0(PayloadValidationRouteV0::Proposal);
        let mut busy_core = issuing_core.clone();
        let epoch = busy_core.safety_state().epoch();
        let view = busy_core.safety_state().current_view();
        let effects = busy_core
            .step(Input::LocalTimeout { epoch, view }, &CoreRootSignatures)
            .expect("make cloned Core await a safety persistence barrier");
        assert!(matches!(
            effects.as_slice(),
            [trnm_consensus_core::Effect::PersistSafetyState(_)]
        ));

        let failure = callback
            .submit_to_core_v0(&mut busy_core, &CoreRootSignatures)
            .expect_err("busy Core must transactionally reject the callback");
        let callback = match failure {
            NativeValidationValidCallbackFailureV0::Rejected(rejected) => {
                assert!(matches!(
                    rejected.cause(),
                    NativeValidationValidCallbackRejectionV0::Core(
                        trnm_consensus_core::CoreError::ApplicationSealedValidMismatch(_)
                    )
                ));
                rejected.into_callback_v0()
            }
            NativeValidationValidCallbackFailureV0::AcceptedInvariant(_) => {
                panic!("busy Core unexpectedly accepted the callback")
            }
        };

        let accepted = callback
            .submit_to_core_v0(&mut issuing_core, &CoreRootSignatures)
            .expect("retry the unchanged callback on the issuing Core");
        assert_core_accepted_v0(&accepted);
    }

    #[test]
    fn issuing_core_busy_returns_callback_then_storage_ack_allows_same_owner_retry_v0() {
        let (mut core, callback) = sealed_live_callback_v0(PayloadValidationRouteV0::Proposal);
        let epoch = core.safety_state().epoch();
        let view = core.safety_state().current_view();
        let busy_effects = core
            .step(Input::LocalTimeout { epoch, view }, &CoreRootSignatures)
            .expect("make the issuing Core wait on an unrelated safety barrier");
        let [trnm_consensus_core::Effect::PersistSafetyState(busy_persistence)] =
            busy_effects.as_slice()
        else {
            panic!("local timeout must expose exactly one safety persistence barrier")
        };

        let failure = callback
            .submit_to_core_v0(&mut core, &CoreRootSignatures)
            .expect_err("issuing Core must return Busy without consuming the callback owner");
        let callback = match failure {
            NativeValidationValidCallbackFailureV0::Rejected(rejected) => {
                assert!(matches!(
                    rejected.cause(),
                    NativeValidationValidCallbackRejectionV0::Core(
                        trnm_consensus_core::CoreError::Busy(
                            "waiting for durable safety-state acknowledgement"
                        )
                    )
                ));
                rejected.into_callback_v0()
            }
            NativeValidationValidCallbackFailureV0::AcceptedInvariant(_) => {
                panic!("busy issuing Core unexpectedly accepted the callback")
            }
        };

        let released = core
            .step(
                Input::StorageAck {
                    barrier: busy_persistence.barrier(),
                },
                &CoreRootSignatures,
            )
            .expect("acknowledge the unrelated issuing-Core barrier");
        assert!(matches!(
            released.as_slice(),
            [trnm_consensus_core::Effect::RequestSignature { .. }]
        ));

        let accepted = callback
            .submit_to_core_v0(&mut core, &CoreRootSignatures)
            .expect("retry the unchanged callback owner on the same issuing Core");
        assert_core_accepted_v0(&accepted);
    }

    #[test]
    fn core_store_binding_installs_one_authority_and_keeps_original_after_rejection_v0() {
        let mut fixture = durable_valid_seal_test_fixture_v0(PayloadValidationRouteV0::Proposal);
        let mut issuing_core = fixture.take_core_v0();
        assert!(matches!(
            issuing_core.issue_application_seal_authority_v0(),
            Err(trnm_consensus_core::CoreError::ApplicationSealAuthorityAlreadyIssued)
        ));

        let foreign_core = issuing_core.clone();
        let foreign_authority = foreign_core
            .issue_application_seal_authority_v0()
            .expect("a public Core clone has a fresh foreign seal affinity");
        assert!(fixture
            .store_v0()
            .install_core_application_seal_authority_v0(foreign_authority)
            .is_err());

        let prepared = fixture.take_prepared_v0();
        let callback = match fixture
            .store_v0()
            .seal_durable_valid_and_enqueue_callback_v0(prepared)
            .expect("the rejected second install must not replace the original authority")
        {
            NativeValidationValidSealDecisionV0::CallbackPending(callback) => callback,
            NativeValidationValidSealDecisionV0::Existing(_) => {
                panic!("fresh one-authority fixture unexpectedly existed")
            }
        };
        let accepted = callback
            .submit_to_core_v0(&mut issuing_core, &CoreRootSignatures)
            .expect("the original Core/store binding remains usable");
        assert_core_accepted_v0(&accepted);
    }
}
