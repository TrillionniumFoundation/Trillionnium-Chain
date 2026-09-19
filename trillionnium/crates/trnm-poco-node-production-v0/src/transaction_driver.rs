//! Node-owned transaction lifecycle composition.
//!
//! This module is the narrow adapter between a node owner and M05's durable
//! transaction coordinator.  It deliberately contains no listener, socket,
//! signer implementation, peer selection, or finality verifier.  Those
//! authorities are supplied by the host through the typed ports below.  The
//! adapter therefore makes the required order executable without turning a
//! candidate fixture into a production claim.

use std::error::Error;

use crate::{
    bind_durable_finalized_readback_to_native_state_sync_store_v1,
    bind_finalized_readback_to_native_state_sync_store_v1,
    DurableFinalizedTxNativeStateSyncBindingErrorV0, FinalizedTxNativeStateSyncApplyErrorV0,
    FinalizedTxNativeStateSyncApplyV0, FinalizedTxNativeStateSyncBindingV0,
};
use trnm_state_sync_v0::SqliteNativeStateSyncStoreV1;

use trnm_tx_lifecycle_v0::{
    AuthenticatedTxBroadcasterV0, AuthorizationVerifierV0, CoreSafetyPermitClaimV0,
    CoreSafetyPermitVerifierV0, DurableTxJournalV0, DurableTxRecordV0, ExecutionReceiptV0,
    FinalizedReadbackV0, FinalizedTxReadbackSourceV0, NonExportableTxSignerV0, OrderedPositionV0,
    ProductionTxCoordinatorV0, ProposalHandoffV0, ReplayFloorWitnessV0, TxAdmissionErrorV0,
    TxAdmissionReceiptV0, TxBroadcastResultV0, TxCollectErrorV0, TxFinalizationErrorV0, TxIdV0,
    TxIntentV0, TxRecordV0, TxTransitionErrorV0,
};

/// This adapter is executable composition evidence only.  A live node must
/// still bind the ports to its authenticated CheckTx owner, signer/HSM,
/// network peer authority, application executor and finality proof source.
pub const NODE_OWNED_TX_COMPOSITION_V0: bool = true;
pub const NODE_OWNED_TX_PRODUCTION_ACTIVATION_V0: bool = false;

/// Node-owned CheckTx authority.
///
/// The adapter never accepts a caller-provided height.  The implementation
/// must authenticate the complete `TxIntentV0` and return the current height
/// from the same authoritative parent view used for nonce/balance checks.
/// Returning `Ok` is only an admission decision; it does not reserve or
/// persist anything until the adapter calls M05's durable journal.
pub trait NodeOwnedTxCheckTxV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_check_tx(&mut self, intent: &TxIntentV0) -> Result<u64, Self::Error>;
}

/// Errors from the node-owned CheckTx -> durable admission composition.
#[derive(Debug)]
pub enum NodeOwnedTxCheckTxErrorV0<CheckTxError, AuthorizationError, JournalError> {
    CheckTx(CheckTxError),
    Admission(TxAdmissionErrorV0<AuthorizationError, JournalError>),
}

impl<C, A, J> std::fmt::Display for NodeOwnedTxCheckTxErrorV0<C, A, J>
where
    C: std::fmt::Display,
    A: std::fmt::Display,
    J: std::fmt::Display,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CheckTx(error) => write!(formatter, "node-owned CheckTx rejected: {error}"),
            Self::Admission(error) => {
                write!(formatter, "durable transaction admission failed: {error}")
            }
        }
    }
}

impl<C, A, J> Error for NodeOwnedTxCheckTxErrorV0<C, A, J>
where
    C: Error + 'static,
    A: Error + 'static,
    J: Error + 'static,
{
}

/// The complete set of node-owned M05 effect ports.
///
/// `ProductionTxNodeAdapterV0` owns these values and invokes them only after
/// the coordinator has persisted the corresponding predecessor.  A host may
/// implement these ports with a real HSM, peer transport and application
/// finality service; test fixtures remain visibly separate because the
/// activation flag above is immutable and false.
pub struct ProductionTxNodeAdapterV0<V, J, P, S, B, R> {
    coordinator: ProductionTxCoordinatorV0<V>,
    journal: J,
    permit_verifier: P,
    signer: S,
    broadcaster: B,
    readback: R,
    chain_id: trnm_tx_lifecycle_v0::Digest32V0,
}

impl<V, J, P, S, B, R> ProductionTxNodeAdapterV0<V, J, P, S, B, R>
where
    V: AuthorizationVerifierV0,
{
    /// Construct a node-owned composition session around the exact ports.
    /// The constructor does not open a listener or enable production effects.
    #[must_use]
    pub fn new(
        chain_id: trnm_tx_lifecycle_v0::Digest32V0,
        authorization: V,
        journal: J,
        permit_verifier: P,
        signer: S,
        broadcaster: B,
        readback: R,
    ) -> Self {
        Self {
            coordinator: ProductionTxCoordinatorV0::new(chain_id, authorization),
            journal,
            permit_verifier,
            signer,
            broadcaster,
            readback,
            chain_id,
        }
    }

    /// Recover the coordinator from the journal before exposing any effect
    /// port.  A malformed or incomplete journal leaves construction failed.
    pub fn recover(
        chain_id: trnm_tx_lifecycle_v0::Digest32V0,
        authorization: V,
        mut journal: J,
        permit_verifier: P,
        signer: S,
        broadcaster: B,
        readback: R,
    ) -> Result<Self, trnm_tx_lifecycle_v0::TxRecoveryErrorV0<J::Error>>
    where
        J: DurableTxJournalV0,
    {
        let coordinator =
            ProductionTxCoordinatorV0::recover(chain_id, authorization, &mut journal)?;
        Ok(Self {
            coordinator,
            journal,
            permit_verifier,
            signer,
            broadcaster,
            readback,
            chain_id,
        })
    }

    #[must_use]
    pub const fn chain_id(&self) -> trnm_tx_lifecycle_v0::Digest32V0 {
        self.chain_id
    }

    #[must_use]
    pub const fn production_activation_v0(&self) -> bool {
        NODE_OWNED_TX_PRODUCTION_ACTIVATION_V0
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.coordinator.is_poisoned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::Infallible,
        io,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    use trnm_tx_lifecycle_v0::{
        AccountIdV0, BroadcastIntentV0, BroadcastReceiptV0, DurableSignedTxEnvelopeV0,
        DurableTxRecordV0, DurableTxReplacementV0, FinalizedTxClaimV0, RecoveredTxRecordV0,
        ReplayFloorWitnessV0, SignedTxEnvelopeV0, TxSignRequestV0, TxSignatureReceiptV0,
    };

    struct AcceptAuthorization;
    impl AuthorizationVerifierV0 for AcceptAuthorization {
        type Error = Infallible;
        fn verify(
            &self,
            _sender: AccountIdV0,
            _digest: trnm_tx_lifecycle_v0::Digest32V0,
            _authorization: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FailingJournal {
        calls: Arc<AtomicUsize>,
    }
    impl DurableTxJournalV0 for FailingJournal {
        type Error = io::Error;
        fn load_latest(
            &mut self,
            _chain_id: trnm_tx_lifecycle_v0::Digest32V0,
        ) -> Result<Vec<RecoveredTxRecordV0>, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
        fn compare_and_append(
            &mut self,
            _previous: Option<trnm_tx_lifecycle_v0::Digest32V0>,
            _record: &TxRecordV0,
        ) -> Result<DurableTxRecordV0, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
        fn compare_and_replace(
            &mut self,
            _previous: trnm_tx_lifecycle_v0::Digest32V0,
            _replaced: &TxRecordV0,
            _admitted: &TxRecordV0,
        ) -> Result<DurableTxReplacementV0, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
        fn delete_collected(
            &mut self,
            _tx_id: TxIdV0,
            _record: trnm_tx_lifecycle_v0::Digest32V0,
            _floor: ReplayFloorWitnessV0,
        ) -> Result<trnm_tx_lifecycle_v0::Digest32V0, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
        fn persist_sign_intent(
            &mut self,
            _intent: trnm_tx_lifecycle_v0::DurableTxSignIntentV0,
        ) -> Result<trnm_tx_lifecycle_v0::DurableTxSignIntentV0, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
        fn load_sign_intent(
            &mut self,
            _tx_id: TxIdV0,
        ) -> Result<Option<trnm_tx_lifecycle_v0::DurableTxSignIntentV0>, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
        fn persist_signed_envelope(
            &mut self,
            _envelope: DurableSignedTxEnvelopeV0,
        ) -> Result<DurableSignedTxEnvelopeV0, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
        fn load_signed_envelope(
            &mut self,
            _tx_id: TxIdV0,
        ) -> Result<Option<DurableSignedTxEnvelopeV0>, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("journal"))
        }
    }

    struct RejectingCheckTx {
        calls: Arc<AtomicUsize>,
    }
    impl NodeOwnedTxCheckTxV0 for RejectingCheckTx {
        type Error = io::Error;
        fn verify_check_tx(&mut self, _intent: &TxIntentV0) -> Result<u64, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("checktx unavailable"))
        }
    }

    struct RejectingPermit;
    impl CoreSafetyPermitVerifierV0 for RejectingPermit {
        type Error = io::Error;
        fn verify_core_safety_permit(
            &self,
            _claim: &CoreSafetyPermitClaimV0,
        ) -> Result<(), Self::Error> {
            Err(io::Error::other("permit"))
        }
    }
    struct RejectingSigner;
    impl NonExportableTxSignerV0 for RejectingSigner {
        type Error = io::Error;
        fn sign_transaction(
            &mut self,
            _request: &TxSignRequestV0,
        ) -> Result<TxSignatureReceiptV0, Self::Error> {
            Err(io::Error::other("signer"))
        }
    }
    struct RejectingBroadcaster;
    impl AuthenticatedTxBroadcasterV0 for RejectingBroadcaster {
        type Error = io::Error;
        fn broadcast_authenticated(
            &mut self,
            _intent: BroadcastIntentV0,
            _envelope: &SignedTxEnvelopeV0,
        ) -> Result<BroadcastReceiptV0, Self::Error> {
            Err(io::Error::other("broadcast"))
        }
    }
    struct RejectingReadback;
    impl FinalizedTxReadbackSourceV0 for RejectingReadback {
        type Error = io::Error;
        fn read_finalized_transaction(
            &mut self,
            _tx_id: TxIdV0,
        ) -> Result<FinalizedTxClaimV0, Self::Error> {
            Err(io::Error::other("readback"))
        }
    }

    fn intent() -> TxIntentV0 {
        TxIntentV0 {
            chain_id: trnm_tx_lifecycle_v0::Digest32V0([1; 32]),
            sender: trnm_tx_lifecycle_v0::Digest32V0([2; 32]),
            nonce: 1,
            fee_bid: 1,
            valid_until_height: 2,
            resource_limits: trnm_tx_lifecycle_v0::ResourceLimitsV0 {
                max_compute: 1,
                max_state_reads: 1,
                max_state_writes: 1,
                max_event_bytes: 1,
            },
            payload: vec![3],
            authorization: vec![4],
        }
    }

    #[test]
    fn checktx_rejection_is_before_any_durable_admission_write() {
        let journal_calls = Arc::new(AtomicUsize::new(0));
        let checktx_calls = Arc::new(AtomicUsize::new(0));
        let mut adapter = ProductionTxNodeAdapterV0::new(
            trnm_tx_lifecycle_v0::Digest32V0([9; 32]),
            AcceptAuthorization,
            FailingJournal {
                calls: Arc::clone(&journal_calls),
            },
            RejectingPermit,
            RejectingSigner,
            RejectingBroadcaster,
            RejectingReadback,
        );
        let result = adapter.check_tx_and_admit(
            &mut RejectingCheckTx {
                calls: Arc::clone(&checktx_calls),
            },
            intent(),
        );
        assert!(matches!(result, Err(NodeOwnedTxCheckTxErrorV0::CheckTx(_))));
        assert_eq!(checktx_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal_calls.load(Ordering::SeqCst), 0);
        assert!(!adapter.production_activation_v0());
    }
}

impl<V, J, P, S, B, R> ProductionTxNodeAdapterV0<V, J, P, S, B, R>
where
    V: AuthorizationVerifierV0,
    J: DurableTxJournalV0,
    P: CoreSafetyPermitVerifierV0,
    S: NonExportableTxSignerV0,
    B: AuthenticatedTxBroadcasterV0,
    R: FinalizedTxReadbackSourceV0,
{
    /// Run node-owned CheckTx and only then create the durable M05 record.
    /// The exact intent is passed unchanged between both owners, preventing a
    /// caller from checking one envelope and persisting another.
    pub fn check_tx_and_admit<A>(
        &mut self,
        check_tx: &mut A,
        intent: TxIntentV0,
    ) -> Result<TxAdmissionReceiptV0, NodeOwnedTxCheckTxErrorV0<A::Error, V::Error, J::Error>>
    where
        A: NodeOwnedTxCheckTxV0,
    {
        let current_height = check_tx
            .verify_check_tx(&intent)
            .map_err(NodeOwnedTxCheckTxErrorV0::CheckTx)?;
        self.coordinator
            .admit_and_persist(&mut self.journal, intent, current_height)
            .map_err(NodeOwnedTxCheckTxErrorV0::Admission)
    }

    pub fn admit_and_persist(
        &mut self,
        intent: TxIntentV0,
        current_height: u64,
    ) -> Result<TxAdmissionReceiptV0, TxAdmissionErrorV0<V::Error, J::Error>> {
        self.coordinator
            .admit_and_persist(&mut self.journal, intent, current_height)
    }

    pub fn persist_proposal(
        &mut self,
        tx_id: TxIdV0,
        handoff: ProposalHandoffV0,
    ) -> Result<DurableTxRecordV0, TxTransitionErrorV0<J::Error>> {
        self.coordinator
            .persist_proposal(&mut self.journal, tx_id, handoff)
    }

    pub fn persist_ordered(
        &mut self,
        tx_id: TxIdV0,
        ordered: OrderedPositionV0,
    ) -> Result<DurableTxRecordV0, TxTransitionErrorV0<J::Error>> {
        self.coordinator
            .persist_ordered(&mut self.journal, tx_id, ordered)
    }

    pub fn persist_execution(
        &mut self,
        execution: ExecutionReceiptV0,
    ) -> Result<DurableTxRecordV0, TxTransitionErrorV0<J::Error>> {
        self.coordinator
            .persist_execution(&mut self.journal, execution)
    }

    /// Persist sign intent and signed envelope, broadcast the exact retained
    /// bytes, and poison the owner on an uncertain transport result. Recovery
    /// must reopen this adapter with the same journal and retry the same bytes.
    pub fn sign_and_broadcast(
        &mut self,
        claim: CoreSafetyPermitClaimV0,
    ) -> TxBroadcastResultV0<P::Error, S::Error, B::Error, J::Error> {
        self.coordinator.sign_and_broadcast(
            &self.permit_verifier,
            &mut self.signer,
            &mut self.broadcaster,
            &mut self.journal,
            claim,
        )
    }

    pub fn apply_finalized_readback(
        &mut self,
        tx_id: TxIdV0,
    ) -> Result<FinalizedReadbackV0, TxFinalizationErrorV0<R::Error, J::Error>> {
        self.coordinator
            .apply_finalized_readback(&mut self.readback, &mut self.journal, tx_id)
    }

    /// Candidate-only composition of the durable transaction finality
    /// readback and one fresh native state-sync store readback. The finality
    /// transition is committed first; a later sync mismatch or SQLite error
    /// therefore does not roll it back and is returned as `Sync`. Callers must
    /// recover/retry the read-only join before publishing the combined result.
    pub fn apply_finalized_readback_and_bind_native_sync_v1(
        &mut self,
        tx_id: TxIdV0,
        store: &SqliteNativeStateSyncStoreV1,
    ) -> Result<
        FinalizedTxNativeStateSyncApplyV0,
        FinalizedTxNativeStateSyncApplyErrorV0<R::Error, J::Error>,
    > {
        let finalized = self
            .apply_finalized_readback(tx_id)
            .map_err(FinalizedTxNativeStateSyncApplyErrorV0::Finality)?;
        let sync_binding = bind_finalized_readback_to_native_state_sync_store_v1(&finalized, store)
            .map_err(FinalizedTxNativeStateSyncApplyErrorV0::Sync)?;
        Ok(FinalizedTxNativeStateSyncApplyV0 {
            finalized,
            sync_binding,
        })
    }

    /// Retry only the read-only transaction-to-state-sync join after a crash
    /// or response loss that occurred after finality was durably committed.
    /// The recovered lifecycle is the authority for `finalized`; no external
    /// finality source is called and no journal frame is appended. Callers
    /// must use this method for the recovery boundary instead of submitting a
    /// second finality readback request.
    pub fn bind_durable_finalized_readback_to_native_sync_v1(
        &self,
        tx_id: TxIdV0,
        store: &SqliteNativeStateSyncStoreV1,
    ) -> Result<FinalizedTxNativeStateSyncBindingV0, DurableFinalizedTxNativeStateSyncBindingErrorV0>
    {
        let finalized = self
            .coordinator
            .lifecycle()
            .map_err(DurableFinalizedTxNativeStateSyncBindingErrorV0::Finality)?
            .finalized_readback(tx_id)
            .map_err(DurableFinalizedTxNativeStateSyncBindingErrorV0::Lifecycle)?;
        bind_durable_finalized_readback_to_native_state_sync_store_v1(&finalized, store)
            .map_err(DurableFinalizedTxNativeStateSyncBindingErrorV0::Sync)
    }

    pub fn tombstone_and_collect(
        &mut self,
        tx_id: TxIdV0,
        replay_floor: ReplayFloorWitnessV0,
    ) -> Result<TxRecordV0, TxCollectErrorV0<J::Error>> {
        self.coordinator
            .tombstone_and_collect(&mut self.journal, tx_id, replay_floor)
    }

    pub fn into_parts(self) -> (ProductionTxCoordinatorV0<V>, J, P, S, B, R) {
        (
            self.coordinator,
            self.journal,
            self.permit_verifier,
            self.signer,
            self.broadcaster,
            self.readback,
        )
    }
}
