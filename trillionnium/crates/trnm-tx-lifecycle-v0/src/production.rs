//! Production orchestration ports for the deterministic transaction lifecycle.
//!
//! The coordinator never owns a filesystem, socket, key, or finality source.
//! It requires durable compare-and-append records before acknowledging an
//! admission or exposing a broadcast effect. Any ambiguous durable failure
//! poisons the in-memory coordinator and requires source-bound recovery.

use super::*;
use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableTxRecordV0 {
    pub tx_id: TxIdV0,
    pub previous_record_digest: Digest32V0,
    pub record_digest: Digest32V0,
    pub journal_sequence: u64,
    pub durable_receipt_digest: Digest32V0,
}

impl DurableTxRecordV0 {
    pub fn validate(
        self,
        expected_previous: Option<Digest32V0>,
        record: &TxRecordV0,
    ) -> Result<Self, ProductionTxErrorV0> {
        let expected_previous = expected_previous.unwrap_or(Digest32V0([0; 32]));
        if self.tx_id != record.tx_id
            || self.previous_record_digest != expected_previous
            || self.record_digest != record.canonical_record_digest_v0()
            || self.journal_sequence == 0
            || self.durable_receipt_digest == Digest32V0([0; 32])
        {
            return Err(ProductionTxErrorV0::DurableReceiptMismatch);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredTxRecordV0 {
    pub record: TxRecordV0,
    pub durable: DurableTxRecordV0,
}

pub trait DurableTxJournalV0 {
    type Error: Error + Send + Sync + 'static;

    fn load_latest(
        &mut self,
        chain_id: Digest32V0,
    ) -> Result<Vec<RecoveredTxRecordV0>, Self::Error>;

    fn compare_and_append(
        &mut self,
        expected_previous_record_digest: Option<Digest32V0>,
        record: &TxRecordV0,
    ) -> Result<DurableTxRecordV0, Self::Error>;

    fn delete_collected(
        &mut self,
        tx_id: TxIdV0,
        final_record_digest: Digest32V0,
        replay_floor: ReplayFloorWitnessV0,
    ) -> Result<Digest32V0, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreSafetyPermitClaimV0 {
    pub tx_id: TxIdV0,
    pub tx_record_digest: Digest32V0,
    pub safety_state_digest: Digest32V0,
    pub authority_receipt_digest: Digest32V0,
    pub permit_digest: Digest32V0,
}

impl CoreSafetyPermitClaimV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.tx.core-safety-permit.v0",
            &[
                &self.tx_id.0,
                &self.tx_record_digest.0,
                &self.safety_state_digest.0,
                &self.authority_receipt_digest.0,
            ],
        )
    }

    pub fn validate(
        self,
        tx_id: TxIdV0,
        record_digest: Digest32V0,
    ) -> Result<Self, ProductionTxErrorV0> {
        if self.tx_id != tx_id
            || self.tx_record_digest != record_digest
            || self.safety_state_digest == Digest32V0([0; 32])
            || self.authority_receipt_digest == Digest32V0([0; 32])
            || self.permit_digest == Digest32V0([0; 32])
            || self.permit_digest != self.canonical_digest()
        {
            return Err(ProductionTxErrorV0::InvalidCoreSafetyPermit);
        }
        Ok(self)
    }
}

pub trait CoreSafetyPermitVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_core_safety_permit(&self, claim: &CoreSafetyPermitClaimV0)
        -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedCoreSafetyPermitV0 {
    tx_id: TxIdV0,
    record_digest: Digest32V0,
    safety_state_digest: Digest32V0,
    authority_receipt_digest: Digest32V0,
    permit_digest: Digest32V0,
}

impl VerifiedCoreSafetyPermitV0 {
    #[must_use]
    pub const fn tx_id(&self) -> TxIdV0 {
        self.tx_id
    }

    #[must_use]
    pub const fn record_digest(&self) -> Digest32V0 {
        self.record_digest
    }

    #[must_use]
    pub const fn safety_state_digest(&self) -> Digest32V0 {
        self.safety_state_digest
    }

    #[must_use]
    pub const fn authority_receipt_digest(&self) -> Digest32V0 {
        self.authority_receipt_digest
    }

    #[must_use]
    pub const fn permit_digest(&self) -> Digest32V0 {
        self.permit_digest
    }
}

pub fn verify_core_safety_permit_v0<V>(
    verifier: &V,
    claim: CoreSafetyPermitClaimV0,
    tx_id: TxIdV0,
    record_digest: Digest32V0,
) -> Result<VerifiedCoreSafetyPermitV0, CoreSafetyPermitErrorV0<V::Error>>
where
    V: CoreSafetyPermitVerifierV0,
{
    let claim = claim
        .validate(tx_id, record_digest)
        .map_err(CoreSafetyPermitErrorV0::Protocol)?;
    verifier
        .verify_core_safety_permit(&claim)
        .map_err(CoreSafetyPermitErrorV0::Verifier)?;
    Ok(VerifiedCoreSafetyPermitV0 {
        tx_id,
        record_digest,
        safety_state_digest: claim.safety_state_digest,
        authority_receipt_digest: claim.authority_receipt_digest,
        permit_digest: claim.permit_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSignRequestV0 {
    pub tx_id: TxIdV0,
    pub record_digest: Digest32V0,
    pub safety_state_digest: Digest32V0,
    pub authority_receipt_digest: Digest32V0,
    pub permit_digest: Digest32V0,
    pub request_digest: Digest32V0,
}

impl TxSignRequestV0 {
    #[must_use]
    pub fn from_permit(permit: &VerifiedCoreSafetyPermitV0) -> Self {
        let mut request = Self {
            tx_id: permit.tx_id,
            record_digest: permit.record_digest,
            safety_state_digest: permit.safety_state_digest,
            authority_receipt_digest: permit.authority_receipt_digest,
            permit_digest: permit.permit_digest,
            request_digest: Digest32V0([0; 32]),
        };
        request.request_digest = request.canonical_digest();
        request
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.tx.non-exportable-sign-request.v0",
            &[
                &self.tx_id.0,
                &self.record_digest.0,
                &self.safety_state_digest.0,
                &self.authority_receipt_digest.0,
                &self.permit_digest.0,
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxSignatureReceiptV0 {
    pub request_digest: Digest32V0,
    pub signature: Vec<u8>,
    pub signature_digest: Digest32V0,
    pub signer_attestation_digest: Digest32V0,
    pub receipt_digest: Digest32V0,
}

impl TxSignatureReceiptV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.tx.non-exportable-signature-receipt.v0",
            &[
                &self.request_digest.0,
                &self.signature,
                &self.signer_attestation_digest.0,
            ],
        )
    }

    pub fn validate(&self, request: &TxSignRequestV0) -> Result<(), ProductionTxErrorV0> {
        if self.request_digest != request.request_digest
            || self.signature.is_empty()
            || self.signature.len() > MAX_AUTHORIZATION_BYTES_V0
            || self.signature_digest
                != Digest32V0::hash(b"trnm.tx.signature-bytes.v0", &[&self.signature])
            || self.signer_attestation_digest == Digest32V0([0; 32])
            || self.receipt_digest == Digest32V0([0; 32])
            || self.receipt_digest != self.canonical_digest()
        {
            return Err(ProductionTxErrorV0::SignatureReceiptMismatch);
        }
        Ok(())
    }
}

pub trait NonExportableTxSignerV0 {
    type Error: Error + Send + Sync + 'static;

    fn sign_transaction(
        &mut self,
        request: &TxSignRequestV0,
    ) -> Result<TxSignatureReceiptV0, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTxEnvelopeV0 {
    pub tx_id: TxIdV0,
    pub permit_digest: Digest32V0,
    pub signature: Vec<u8>,
    pub signature_digest: Digest32V0,
    pub signer_attestation_digest: Digest32V0,
    pub envelope_digest: Digest32V0,
}

impl SignedTxEnvelopeV0 {
    #[must_use]
    pub fn new(
        permit: &VerifiedCoreSafetyPermitV0,
        signature: TxSignatureReceiptV0,
    ) -> Result<Self, ProductionTxErrorV0> {
        let request = TxSignRequestV0::from_permit(permit);
        signature.validate(&request)?;
        let envelope_digest = Digest32V0::hash(
            b"trnm.tx.signed-envelope.v0",
            &[
                &permit.tx_id.0,
                &permit.permit_digest.0,
                &signature.signature_digest.0,
                &signature.signer_attestation_digest.0,
            ],
        );
        Ok(Self {
            tx_id: permit.tx_id,
            permit_digest: permit.permit_digest,
            signature: signature.signature,
            signature_digest: signature.signature_digest,
            signer_attestation_digest: signature.signer_attestation_digest,
            envelope_digest,
        })
    }
}

pub trait AuthenticatedTxBroadcasterV0 {
    type Error: Error + Send + Sync + 'static;

    fn broadcast_authenticated(
        &mut self,
        intent: BroadcastIntentV0,
        envelope: &SignedTxEnvelopeV0,
    ) -> Result<BroadcastReceiptV0, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedTxClaimV0 {
    pub tx_id: TxIdV0,
    pub ordered: OrderedPositionV0,
    pub execution: ExecutionReceiptV0,
    pub finality: FinalityWitnessV0,
    pub source_authentication_digest: Digest32V0,
    pub claim_digest: Digest32V0,
}

impl FinalizedTxClaimV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.tx.finalized-readback-claim.v0",
            &[
                &self.tx_id.0,
                &ordered_position_digest_v0(self.ordered).0,
                &execution_receipt_digest_v0(self.execution).0,
                &finality_witness_digest_v0(self.finality).0,
                &self.source_authentication_digest.0,
            ],
        )
    }

    pub fn validate(self) -> Result<Self, ProductionTxErrorV0> {
        if self.tx_id != self.execution.tx_id
            || self.ordered != self.execution.ordered
            || self.finality.block_id != self.ordered.block_id
            || self.finality.height != self.ordered.height
            || self.finality.state_root != self.execution.post_state_root
            || self.source_authentication_digest == Digest32V0([0; 32])
            || self.claim_digest == Digest32V0([0; 32])
            || self.claim_digest != self.canonical_digest()
        {
            return Err(ProductionTxErrorV0::FinalizedReadbackMismatch);
        }
        Ok(self)
    }
}

pub trait FinalizedTxReadbackSourceV0 {
    type Error: Error + Send + Sync + 'static;

    fn read_finalized_transaction(
        &mut self,
        tx_id: TxIdV0,
    ) -> Result<FinalizedTxClaimV0, Self::Error>;
}

pub struct ProductionTxCoordinatorV0<V> {
    lifecycle: TxLifecycleV0<V>,
    durable: BTreeMap<TxIdV0, DurableTxRecordV0>,
    poisoned: bool,
}

impl<V> ProductionTxCoordinatorV0<V>
where
    V: AuthorizationVerifierV0,
{
    #[must_use]
    pub fn new(chain_id: Digest32V0, verifier: V) -> Self {
        Self {
            lifecycle: TxLifecycleV0::new(chain_id, verifier),
            durable: BTreeMap::new(),
            poisoned: false,
        }
    }

    pub fn recover<J>(
        chain_id: Digest32V0,
        verifier: V,
        journal: &mut J,
    ) -> Result<Self, TxRecoveryErrorV0<J::Error>>
    where
        J: DurableTxJournalV0,
    {
        let recovered = journal
            .load_latest(chain_id)
            .map_err(TxRecoveryErrorV0::Journal)?;
        let (lifecycle, durable) =
            TxLifecycleV0::restore_recovered_v0(chain_id, verifier, recovered)
                .map_err(TxRecoveryErrorV0::Protocol)?;
        Ok(Self {
            lifecycle,
            durable,
            poisoned: false,
        })
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn lifecycle(&self) -> Result<&TxLifecycleV0<V>, ProductionTxErrorV0> {
        self.require_live()?;
        Ok(&self.lifecycle)
    }

    pub fn admit_and_persist<J>(
        &mut self,
        journal: &mut J,
        intent: TxIntentV0,
        current_height: u64,
    ) -> Result<TxAdmissionReceiptV0, TxAdmissionErrorV0<V::Error, J::Error>>
    where
        J: DurableTxJournalV0,
    {
        self.require_live().map_err(TxAdmissionErrorV0::Protocol)?;
        let tx_id = self
            .lifecycle
            .admit(intent, current_height)
            .map_err(TxAdmissionErrorV0::Lifecycle)?;
        if let Some(existing) = self.durable.get(&tx_id).copied() {
            let record = self
                .lifecycle
                .record(tx_id)
                .map_err(|error| TxAdmissionErrorV0::Protocol(error.into()))?;
            if record.phase != TxPhaseV0::Admitted {
                return Ok(TxAdmissionReceiptV0 {
                    tx_id,
                    wal_sequence: existing.journal_sequence,
                    record_digest: existing.record_digest,
                    durable_receipt_digest: existing.durable_receipt_digest,
                });
            }
        }

        let admitted = self
            .lifecycle
            .record(tx_id)
            .map_err(|error| TxAdmissionErrorV0::Protocol(error.into()))?
            .clone();
        let first = match journal.compare_and_append(None, &admitted) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.poisoned = true;
                return Err(TxAdmissionErrorV0::Journal(error));
            }
        };
        let first = first
            .validate(None, &admitted)
            .map_err(TxAdmissionErrorV0::Protocol)?;
        self.lifecycle
            .persist_wal(tx_id, first.journal_sequence)
            .map_err(|error| TxAdmissionErrorV0::Protocol(error.into()))?;
        let wal_persisted = self
            .lifecycle
            .record(tx_id)
            .map_err(|error| TxAdmissionErrorV0::Protocol(error.into()))?
            .clone();
        let second = match journal.compare_and_append(Some(first.record_digest), &wal_persisted) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.poisoned = true;
                return Err(TxAdmissionErrorV0::Journal(error));
            }
        };
        let second = second
            .validate(Some(first.record_digest), &wal_persisted)
            .map_err(TxAdmissionErrorV0::Protocol)?;
        self.durable.insert(tx_id, second);
        Ok(TxAdmissionReceiptV0 {
            tx_id,
            wal_sequence: first.journal_sequence,
            record_digest: second.record_digest,
            durable_receipt_digest: second.durable_receipt_digest,
        })
    }

    pub fn persist_proposal<J>(
        &mut self,
        journal: &mut J,
        tx_id: TxIdV0,
        handoff: ProposalHandoffV0,
    ) -> Result<DurableTxRecordV0, TxTransitionErrorV0<J::Error>>
    where
        J: DurableTxJournalV0,
    {
        self.require_live().map_err(TxTransitionErrorV0::Protocol)?;
        self.lifecycle
            .handoff_proposal(tx_id, handoff)
            .map_err(|error| TxTransitionErrorV0::Protocol(error.into()))?;
        self.persist_current(journal, tx_id)
            .map_err(TxTransitionErrorV0::from)
    }

    pub fn persist_ordered<J>(
        &mut self,
        journal: &mut J,
        tx_id: TxIdV0,
        ordered: OrderedPositionV0,
    ) -> Result<DurableTxRecordV0, TxTransitionErrorV0<J::Error>>
    where
        J: DurableTxJournalV0,
    {
        self.require_live().map_err(TxTransitionErrorV0::Protocol)?;
        self.lifecycle
            .mark_ordered(tx_id, ordered)
            .map_err(|error| TxTransitionErrorV0::Protocol(error.into()))?;
        self.persist_current(journal, tx_id)
            .map_err(TxTransitionErrorV0::from)
    }

    pub fn persist_execution<J>(
        &mut self,
        journal: &mut J,
        execution: ExecutionReceiptV0,
    ) -> Result<DurableTxRecordV0, TxTransitionErrorV0<J::Error>>
    where
        J: DurableTxJournalV0,
    {
        self.require_live().map_err(TxTransitionErrorV0::Protocol)?;
        let tx_id = execution.tx_id;
        self.lifecycle
            .mark_executed(execution)
            .map_err(|error| TxTransitionErrorV0::Protocol(error.into()))?;
        self.persist_current(journal, tx_id)
            .map_err(TxTransitionErrorV0::from)
    }

    pub fn sign_and_broadcast<P, S, B, J>(
        &mut self,
        permit_verifier: &P,
        signer: &mut S,
        broadcaster: &mut B,
        journal: &mut J,
        claim: CoreSafetyPermitClaimV0,
    ) -> Result<BroadcastReceiptV0, TxBroadcastErrorV0<P::Error, S::Error, B::Error, J::Error>>
    where
        P: CoreSafetyPermitVerifierV0,
        S: NonExportableTxSignerV0,
        B: AuthenticatedTxBroadcasterV0,
        J: DurableTxJournalV0,
    {
        self.require_live().map_err(TxBroadcastErrorV0::Protocol)?;
        let tx_id = claim.tx_id;
        let record_digest = self
            .durable
            .get(&tx_id)
            .ok_or(TxBroadcastErrorV0::Protocol(
                ProductionTxErrorV0::MissingDurableRecord,
            ))?
            .record_digest;
        let permit = verify_core_safety_permit_v0(permit_verifier, claim, tx_id, record_digest)
            .map_err(TxBroadcastErrorV0::Permit)?;
        let request = TxSignRequestV0::from_permit(&permit);
        let signature = signer
            .sign_transaction(&request)
            .map_err(TxBroadcastErrorV0::Signer)?;
        let envelope =
            SignedTxEnvelopeV0::new(&permit, signature).map_err(TxBroadcastErrorV0::Protocol)?;
        let intent = self
            .lifecycle
            .create_broadcast_intent(tx_id, envelope.envelope_digest)
            .map_err(|error| TxBroadcastErrorV0::Protocol(error.into()))?;
        self.persist_current(journal, tx_id)
            .map_err(TxBroadcastErrorV0::Transition)?;
        let receipt = broadcaster
            .broadcast_authenticated(intent, &envelope)
            .map_err(TxBroadcastErrorV0::Broadcast)?;
        self.lifecycle
            .confirm_broadcast(receipt)
            .map_err(|error| TxBroadcastErrorV0::Protocol(error.into()))?;
        self.persist_current(journal, tx_id)
            .map_err(TxBroadcastErrorV0::Transition)?;
        Ok(receipt)
    }

    pub fn apply_finalized_readback<R, J>(
        &mut self,
        source: &mut R,
        journal: &mut J,
        tx_id: TxIdV0,
    ) -> Result<FinalizedReadbackV0, TxFinalizationErrorV0<R::Error, J::Error>>
    where
        R: FinalizedTxReadbackSourceV0,
        J: DurableTxJournalV0,
    {
        self.require_live()
            .map_err(TxFinalizationErrorV0::Protocol)?;
        let claim = source
            .read_finalized_transaction(tx_id)
            .map_err(TxFinalizationErrorV0::Readback)?
            .validate()
            .map_err(TxFinalizationErrorV0::Protocol)?;
        if claim.tx_id != tx_id {
            return Err(TxFinalizationErrorV0::Protocol(
                ProductionTxErrorV0::FinalizedReadbackMismatch,
            ));
        }
        let phase = self
            .lifecycle
            .record(tx_id)
            .map_err(|error| TxFinalizationErrorV0::Protocol(error.into()))?
            .phase;
        if phase == TxPhaseV0::Proposed {
            self.lifecycle
                .mark_ordered(tx_id, claim.ordered)
                .map_err(|error| TxFinalizationErrorV0::Protocol(error.into()))?;
            self.persist_current(journal, tx_id)
                .map_err(TxFinalizationErrorV0::Transition)?;
        }
        let phase = self
            .lifecycle
            .record(tx_id)
            .map_err(|error| TxFinalizationErrorV0::Protocol(error.into()))?
            .phase;
        if phase == TxPhaseV0::Ordered {
            self.lifecycle
                .mark_executed(claim.execution)
                .map_err(|error| TxFinalizationErrorV0::Protocol(error.into()))?;
            self.persist_current(journal, tx_id)
                .map_err(TxFinalizationErrorV0::Transition)?;
        }
        self.lifecycle
            .finalize(tx_id, claim.finality)
            .map_err(|error| TxFinalizationErrorV0::Protocol(error.into()))?;
        self.persist_current(journal, tx_id)
            .map_err(TxFinalizationErrorV0::Transition)?;
        self.lifecycle
            .finalized_readback(tx_id)
            .map_err(|error| TxFinalizationErrorV0::Protocol(error.into()))
    }

    pub fn tombstone_and_collect<J>(
        &mut self,
        journal: &mut J,
        tx_id: TxIdV0,
        replay_floor: ReplayFloorWitnessV0,
    ) -> Result<TxRecordV0, TxCollectErrorV0<J::Error>>
    where
        J: DurableTxJournalV0,
    {
        self.require_live().map_err(TxCollectErrorV0::Protocol)?;
        self.lifecycle
            .tombstone_finalized(tx_id)
            .map_err(|error| TxCollectErrorV0::Protocol(error.into()))?;
        let tombstone = self
            .persist_current(journal, tx_id)
            .map_err(TxCollectErrorV0::Transition)?;
        let collected = self
            .lifecycle
            .collect(tx_id, replay_floor)
            .map_err(|error| TxCollectErrorV0::Protocol(error.into()))?;
        let deletion_digest =
            match journal.delete_collected(tx_id, tombstone.record_digest, replay_floor) {
                Ok(digest) => digest,
                Err(error) => {
                    self.poisoned = true;
                    return Err(TxCollectErrorV0::Journal(error));
                }
            };
        if deletion_digest == Digest32V0([0; 32]) {
            self.poisoned = true;
            return Err(TxCollectErrorV0::Protocol(
                ProductionTxErrorV0::DurableDeleteMismatch,
            ));
        }
        self.durable.remove(&tx_id);
        Ok(collected)
    }

    fn require_live(&self) -> Result<(), ProductionTxErrorV0> {
        if self.poisoned {
            Err(ProductionTxErrorV0::CoordinatorPoisoned)
        } else {
            Ok(())
        }
    }

    fn persist_current<J>(
        &mut self,
        journal: &mut J,
        tx_id: TxIdV0,
    ) -> Result<DurableTxRecordV0, PersistTxErrorV0<J::Error>>
    where
        J: DurableTxJournalV0,
    {
        let previous = self
            .durable
            .get(&tx_id)
            .copied()
            .ok_or(PersistTxErrorV0::Protocol(
                ProductionTxErrorV0::MissingDurableRecord,
            ))?;
        let record = self
            .lifecycle
            .record(tx_id)
            .map_err(|error| PersistTxErrorV0::Protocol(error.into()))?
            .clone();
        let receipt = match journal.compare_and_append(Some(previous.record_digest), &record) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.poisoned = true;
                return Err(PersistTxErrorV0::Journal(error));
            }
        };
        let receipt = receipt
            .validate(Some(previous.record_digest), &record)
            .map_err(PersistTxErrorV0::Protocol)?;
        self.durable.insert(tx_id, receipt);
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxAdmissionReceiptV0 {
    pub tx_id: TxIdV0,
    pub wal_sequence: u64,
    pub record_digest: Digest32V0,
    pub durable_receipt_digest: Digest32V0,
}

impl TxRecordV0 {
    #[must_use]
    pub fn canonical_record_digest_v0(&self) -> Digest32V0 {
        let wal = optional_u64_digest_v0(b"trnm.tx.record.wal.v0", self.wal_sequence);
        let proposal = self.proposal.map_or(
            Digest32V0::hash(b"trnm.tx.record.proposal.none.v0", &[]),
            proposal_handoff_digest_v0,
        );
        let ordered = self.ordered.map_or(
            Digest32V0::hash(b"trnm.tx.record.ordered.none.v0", &[]),
            ordered_position_digest_v0,
        );
        let execution = self.execution.map_or(
            Digest32V0::hash(b"trnm.tx.record.execution.none.v0", &[]),
            execution_receipt_digest_v0,
        );
        let finality = self.finality.map_or(
            Digest32V0::hash(b"trnm.tx.record.finality.none.v0", &[]),
            finality_witness_digest_v0,
        );
        let broadcast_intent = self.broadcast_intent.map_or(
            Digest32V0::hash(b"trnm.tx.record.broadcast-intent.none.v0", &[]),
            broadcast_intent_digest_v0,
        );
        let broadcast_receipt = self.broadcast_receipt.map_or(
            Digest32V0::hash(b"trnm.tx.record.broadcast-receipt.none.v0", &[]),
            broadcast_receipt_digest_v0,
        );
        let tombstone = self.tombstone.map_or(
            Digest32V0::hash(b"trnm.tx.record.tombstone.none.v0", &[]),
            tombstone_digest_v0,
        );
        Digest32V0::hash(
            b"trnm.tx.durable-record.v0",
            &[
                &self.tx_id.0,
                &[self.phase as u8],
                &self.lifecycle_sequence.to_be_bytes(),
                &wal.0,
                &proposal.0,
                &ordered.0,
                &execution.0,
                &finality.0,
                &broadcast_intent.0,
                &broadcast_receipt.0,
                &tombstone.0,
            ],
        )
    }
}

impl<V> TxLifecycleV0<V>
where
    V: AuthorizationVerifierV0,
{
    fn restore_recovered_v0(
        chain_id: Digest32V0,
        verifier: V,
        recovered: Vec<RecoveredTxRecordV0>,
    ) -> Result<(Self, BTreeMap<TxIdV0, DurableTxRecordV0>), ProductionTxErrorV0> {
        if chain_id == Digest32V0([0; 32]) {
            return Err(ProductionTxErrorV0::WrongChain);
        }
        let mut records = BTreeMap::new();
        let mut durable = BTreeMap::new();
        let mut active_nonce = BTreeMap::new();
        let mut finalized_nonce: BTreeMap<AccountIdV0, u64> = BTreeMap::new();
        let mut next_broadcast_sequence = 0_u64;
        for recovered_record in recovered {
            let record = recovered_record.record;
            validate_recovered_record_v0(chain_id, &record)?;
            recovered_record.durable.validate(
                if recovered_record.durable.previous_record_digest == Digest32V0([0; 32]) {
                    None
                } else {
                    Some(recovered_record.durable.previous_record_digest)
                },
                &record,
            )?;
            if records.insert(record.tx_id, record.clone()).is_some()
                || durable
                    .insert(record.tx_id, recovered_record.durable)
                    .is_some()
            {
                return Err(ProductionTxErrorV0::DuplicateRecoveredTransaction);
            }
            if let Some(intent) = record.broadcast_intent {
                next_broadcast_sequence = next_broadcast_sequence.max(
                    intent
                        .intent_sequence
                        .checked_add(1)
                        .ok_or(ProductionTxErrorV0::SequenceOverflow)?,
                );
            }
            if record.finality.is_some() {
                finalized_nonce
                    .entry(record.intent.sender)
                    .and_modify(|value| *value = (*value).max(record.intent.nonce))
                    .or_insert(record.intent.nonce);
            }
            if !matches!(record.phase, TxPhaseV0::Finalized | TxPhaseV0::Tombstoned)
                && active_nonce
                    .insert((record.intent.sender, record.intent.nonce), record.tx_id)
                    .is_some()
            {
                return Err(ProductionTxErrorV0::DuplicateActiveNonce);
            }
        }
        Ok((
            Self {
                chain_id,
                verifier,
                records,
                active_nonce,
                finalized_nonce,
                next_broadcast_sequence,
            },
            durable,
        ))
    }
}

fn validate_recovered_record_v0(
    chain_id: Digest32V0,
    record: &TxRecordV0,
) -> Result<(), ProductionTxErrorV0> {
    record
        .intent
        .validate()
        .map_err(|_| ProductionTxErrorV0::InvalidRecoveredRecord)?;
    if record.intent.chain_id != chain_id || record.tx_id != record.intent.tx_id() {
        return Err(ProductionTxErrorV0::InvalidRecoveredRecord);
    }
    let wal_present = record.wal_sequence.is_some();
    let proposal_present = record.proposal.is_some();
    let ordered_present = record.ordered.is_some();
    let execution_present = record.execution.is_some();
    let finality_present = record.finality.is_some();
    let tombstone_present = record.tombstone.is_some();
    let valid_shape = match record.phase {
        TxPhaseV0::Admitted => {
            !wal_present
                && !proposal_present
                && !ordered_present
                && !execution_present
                && !finality_present
                && !tombstone_present
        }
        TxPhaseV0::WalPersisted => {
            wal_present
                && !proposal_present
                && !ordered_present
                && !execution_present
                && !finality_present
                && !tombstone_present
        }
        TxPhaseV0::Proposed => {
            wal_present
                && proposal_present
                && !ordered_present
                && !execution_present
                && !finality_present
                && !tombstone_present
        }
        TxPhaseV0::Ordered => {
            wal_present
                && proposal_present
                && ordered_present
                && !execution_present
                && !finality_present
                && !tombstone_present
        }
        TxPhaseV0::Executed => {
            wal_present
                && proposal_present
                && ordered_present
                && execution_present
                && !finality_present
                && !tombstone_present
        }
        TxPhaseV0::Finalized => {
            wal_present
                && proposal_present
                && ordered_present
                && execution_present
                && finality_present
                && !tombstone_present
        }
        TxPhaseV0::Tombstoned => tombstone_present,
    };
    if !valid_shape
        || (record.phase == TxPhaseV0::Admitted && record.lifecycle_sequence != 0)
        || (record.phase != TxPhaseV0::Admitted && record.lifecycle_sequence == 0)
        || record.broadcast_receipt.is_some_and(|receipt| {
            record.broadcast_intent.is_none_or(|intent| {
                receipt.tx_id != intent.tx_id
                    || receipt.intent_sequence != intent.intent_sequence
                    || receipt.envelope_digest != intent.envelope_digest
                    || receipt.transport_receipt_digest == Digest32V0([0; 32])
            })
        })
    {
        return Err(ProductionTxErrorV0::InvalidRecoveredRecord);
    }
    if let Some(execution) = record.execution {
        execution
            .validate(record.tx_id)
            .map_err(|_| ProductionTxErrorV0::InvalidRecoveredRecord)?;
        if record.ordered != Some(execution.ordered) {
            return Err(ProductionTxErrorV0::InvalidRecoveredRecord);
        }
    }
    if let Some(finality) = record.finality {
        let ordered = record
            .ordered
            .ok_or(ProductionTxErrorV0::InvalidRecoveredRecord)?;
        let execution = record
            .execution
            .ok_or(ProductionTxErrorV0::InvalidRecoveredRecord)?;
        if finality.block_id != ordered.block_id
            || finality.height != ordered.height
            || finality.state_root != execution.post_state_root
            || finality.finality_proof_digest == Digest32V0([0; 32])
        {
            return Err(ProductionTxErrorV0::InvalidRecoveredRecord);
        }
    }
    Ok(())
}

fn optional_u64_digest_v0(domain: &[u8], value: Option<u64>) -> Digest32V0 {
    value.map_or_else(
        || Digest32V0::hash(domain, &[&[0]]),
        |value| Digest32V0::hash(domain, &[&[1], &value.to_be_bytes()]),
    )
}

fn proposal_handoff_digest_v0(value: ProposalHandoffV0) -> Digest32V0 {
    Digest32V0::hash(
        b"trnm.tx.record.proposal.v0",
        &[&value.proposal_id.0, &value.proposal_index.to_be_bytes()],
    )
}

fn ordered_position_digest_v0(value: OrderedPositionV0) -> Digest32V0 {
    Digest32V0::hash(
        b"trnm.tx.record.ordered.v0",
        &[
            &value.block_id.0,
            &value.height.to_be_bytes(),
            &value.transaction_index.to_be_bytes(),
        ],
    )
}

fn execution_receipt_digest_v0(value: ExecutionReceiptV0) -> Digest32V0 {
    Digest32V0::hash(
        b"trnm.tx.record.execution.v0",
        &[
            &value.tx_id.0,
            &ordered_position_digest_v0(value.ordered).0,
            &value.pre_state_root.0,
            &value.post_state_root.0,
            &value.receipt_digest.0,
            &value.event_root.0,
            &value.fee_charged.to_be_bytes(),
            &[u8::from(value.success)],
        ],
    )
}

fn finality_witness_digest_v0(value: FinalityWitnessV0) -> Digest32V0 {
    Digest32V0::hash(
        b"trnm.tx.record.finality.v0",
        &[
            &value.block_id.0,
            &value.height.to_be_bytes(),
            &value.state_root.0,
            &value.finality_proof_digest.0,
        ],
    )
}

fn broadcast_intent_digest_v0(value: BroadcastIntentV0) -> Digest32V0 {
    Digest32V0::hash(
        b"trnm.tx.record.broadcast-intent.v0",
        &[
            &value.tx_id.0,
            &value.intent_sequence.to_be_bytes(),
            &value.envelope_digest.0,
        ],
    )
}

fn broadcast_receipt_digest_v0(value: BroadcastReceiptV0) -> Digest32V0 {
    Digest32V0::hash(
        b"trnm.tx.record.broadcast-receipt.v0",
        &[
            &value.tx_id.0,
            &value.intent_sequence.to_be_bytes(),
            &value.envelope_digest.0,
            &value.transport_receipt_digest.0,
        ],
    )
}

fn tombstone_digest_v0(value: TombstoneReasonV0) -> Digest32V0 {
    match value {
        TombstoneReasonV0::Replaced { by } => {
            Digest32V0::hash(b"trnm.tx.record.tombstone.replaced.v0", &[&by.0])
        }
        TombstoneReasonV0::Finalized => {
            Digest32V0::hash(b"trnm.tx.record.tombstone.finalized.v0", &[])
        }
        TombstoneReasonV0::Expired => Digest32V0::hash(b"trnm.tx.record.tombstone.expired.v0", &[]),
        TombstoneReasonV0::Rejected => {
            Digest32V0::hash(b"trnm.tx.record.tombstone.rejected.v0", &[])
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionTxErrorV0 {
    WrongChain,
    CoordinatorPoisoned,
    MissingDurableRecord,
    DurableReceiptMismatch,
    DurableDeleteMismatch,
    InvalidCoreSafetyPermit,
    SignatureReceiptMismatch,
    FinalizedReadbackMismatch,
    InvalidRecoveredRecord,
    DuplicateRecoveredTransaction,
    DuplicateActiveNonce,
    SequenceOverflow,
    Lifecycle(TxLifecycleErrorV0),
}

impl From<TxLifecycleErrorV0> for ProductionTxErrorV0 {
    fn from(value: TxLifecycleErrorV0) -> Self {
        Self::Lifecycle(value)
    }
}

impl fmt::Display for ProductionTxErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongChain => f.write_str("transaction production coordinator chain is invalid"),
            Self::CoordinatorPoisoned => {
                f.write_str("transaction production coordinator requires durable recovery")
            }
            Self::MissingDurableRecord => f.write_str("transaction has no durable journal record"),
            Self::DurableReceiptMismatch => {
                f.write_str("transaction durable journal receipt is misbound")
            }
            Self::DurableDeleteMismatch => {
                f.write_str("transaction durable deletion receipt is invalid")
            }
            Self::InvalidCoreSafetyPermit => {
                f.write_str("transaction lacks an exact Core/Safety signing permit")
            }
            Self::SignatureReceiptMismatch => {
                f.write_str("non-exportable transaction signature receipt is misbound")
            }
            Self::FinalizedReadbackMismatch => {
                f.write_str("finalized transaction readback is unauthenticated or misbound")
            }
            Self::InvalidRecoveredRecord => {
                f.write_str("recovered transaction record violates lifecycle invariants")
            }
            Self::DuplicateRecoveredTransaction => {
                f.write_str("durable recovery returned a duplicate transaction")
            }
            Self::DuplicateActiveNonce => {
                f.write_str("durable recovery returned conflicting active nonces")
            }
            Self::SequenceOverflow => f.write_str("transaction durable sequence overflow"),
            Self::Lifecycle(error) => {
                write!(f, "transaction lifecycle rejected operation: {error}")
            }
        }
    }
}

impl Error for ProductionTxErrorV0 {}

#[derive(Debug)]
pub enum CoreSafetyPermitErrorV0<E> {
    Protocol(ProductionTxErrorV0),
    Verifier(E),
}

impl<E: fmt::Display> fmt::Display for CoreSafetyPermitErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "Core/Safety permit rejected: {error}"),
            Self::Verifier(error) => write!(f, "Core/Safety permit verifier failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for CoreSafetyPermitErrorV0<E> {}

#[derive(Debug)]
pub enum PersistTxErrorV0<E> {
    Protocol(ProductionTxErrorV0),
    Journal(E),
}

impl<E: fmt::Display> fmt::Display for PersistTxErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "transaction transition rejected: {error}"),
            Self::Journal(error) => write!(f, "transaction journal append failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for PersistTxErrorV0<E> {}

#[derive(Debug)]
pub enum TxAdmissionErrorV0<AuthorizationError, JournalError> {
    Protocol(ProductionTxErrorV0),
    Lifecycle(TxLifecycleHostErrorV0<AuthorizationError>),
    Journal(JournalError),
}

impl<A: fmt::Display, J: fmt::Display> fmt::Display for TxAdmissionErrorV0<A, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "transaction admission rejected: {error}"),
            Self::Lifecycle(error) => write!(f, "transaction admission failed: {error}"),
            Self::Journal(error) => write!(f, "transaction admission journal failed: {error}"),
        }
    }
}

impl<A, J> Error for TxAdmissionErrorV0<A, J>
where
    A: Error + 'static,
    J: Error + 'static,
{
}

#[derive(Debug)]
pub enum TxRecoveryErrorV0<E> {
    Protocol(ProductionTxErrorV0),
    Journal(E),
}

impl<E: fmt::Display> fmt::Display for TxRecoveryErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "transaction recovery rejected: {error}"),
            Self::Journal(error) => write!(f, "transaction recovery journal failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for TxRecoveryErrorV0<E> {}

#[derive(Debug)]
pub enum TxTransitionErrorV0<E> {
    Protocol(ProductionTxErrorV0),
    Journal(E),
}

impl<E> From<PersistTxErrorV0<E>> for TxTransitionErrorV0<E> {
    fn from(value: PersistTxErrorV0<E>) -> Self {
        match value {
            PersistTxErrorV0::Protocol(error) => Self::Protocol(error),
            PersistTxErrorV0::Journal(error) => Self::Journal(error),
        }
    }
}

impl<E: fmt::Display> fmt::Display for TxTransitionErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "transaction transition rejected: {error}"),
            Self::Journal(error) => write!(f, "transaction transition journal failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for TxTransitionErrorV0<E> {}

#[derive(Debug)]
pub enum TxBroadcastErrorV0<PermitError, SignerError, BroadcastError, JournalError> {
    Protocol(ProductionTxErrorV0),
    Permit(CoreSafetyPermitErrorV0<PermitError>),
    Signer(SignerError),
    Broadcast(BroadcastError),
    Transition(PersistTxErrorV0<JournalError>),
}

impl<P, S, B, J> fmt::Display for TxBroadcastErrorV0<P, S, B, J>
where
    P: fmt::Display,
    S: fmt::Display,
    B: fmt::Display,
    J: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "transaction broadcast rejected: {error}"),
            Self::Permit(error) => write!(f, "transaction broadcast permit failed: {error}"),
            Self::Signer(error) => write!(f, "transaction signer failed: {error}"),
            Self::Broadcast(error) => write!(f, "authenticated broadcast failed: {error}"),
            Self::Transition(error) => write!(f, "broadcast durable transition failed: {error}"),
        }
    }
}

impl<P, S, B, J> Error for TxBroadcastErrorV0<P, S, B, J>
where
    P: Error + 'static,
    S: Error + 'static,
    B: Error + 'static,
    J: Error + 'static,
{
}

#[derive(Debug)]
pub enum TxFinalizationErrorV0<ReadbackError, JournalError> {
    Protocol(ProductionTxErrorV0),
    Readback(ReadbackError),
    Transition(PersistTxErrorV0<JournalError>),
}

impl<R: fmt::Display, J: fmt::Display> fmt::Display for TxFinalizationErrorV0<R, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "finalized transaction rejected: {error}"),
            Self::Readback(error) => write!(f, "finalized readback source failed: {error}"),
            Self::Transition(error) => write!(f, "finality durable transition failed: {error}"),
        }
    }
}

impl<R, J> Error for TxFinalizationErrorV0<R, J>
where
    R: Error + 'static,
    J: Error + 'static,
{
}

#[derive(Debug)]
pub enum TxCollectErrorV0<JournalError> {
    Protocol(ProductionTxErrorV0),
    Transition(PersistTxErrorV0<JournalError>),
    Journal(JournalError),
}

impl<J: fmt::Display> fmt::Display for TxCollectErrorV0<J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "transaction collection rejected: {error}"),
            Self::Transition(error) => write!(f, "tombstone durable transition failed: {error}"),
            Self::Journal(error) => write!(f, "durable transaction deletion failed: {error}"),
        }
    }
}

impl<J: Error + 'static> Error for TxCollectErrorV0<J> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    struct AcceptAuthorization;

    impl AuthorizationVerifierV0 for AcceptAuthorization {
        type Error = Infallible;

        fn verify(
            &self,
            _sender: AccountIdV0,
            _signing_digest: Digest32V0,
            _authorization: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemoryJournal {
        latest: BTreeMap<TxIdV0, RecoveredTxRecordV0>,
        next_sequence: u64,
    }

    impl DurableTxJournalV0 for MemoryJournal {
        type Error = Infallible;

        fn load_latest(
            &mut self,
            _chain_id: Digest32V0,
        ) -> Result<Vec<RecoveredTxRecordV0>, Self::Error> {
            Ok(self.latest.values().cloned().collect())
        }

        fn compare_and_append(
            &mut self,
            expected_previous_record_digest: Option<Digest32V0>,
            record: &TxRecordV0,
        ) -> Result<DurableTxRecordV0, Self::Error> {
            self.next_sequence += 1;
            let durable = DurableTxRecordV0 {
                tx_id: record.tx_id,
                previous_record_digest: expected_previous_record_digest
                    .unwrap_or(Digest32V0([0; 32])),
                record_digest: record.canonical_record_digest_v0(),
                journal_sequence: self.next_sequence,
                durable_receipt_digest: Digest32V0::hash(
                    b"memory.tx.journal.v0",
                    &[&self.next_sequence.to_be_bytes(), &record.tx_id.0],
                ),
            };
            self.latest.insert(
                record.tx_id,
                RecoveredTxRecordV0 {
                    record: record.clone(),
                    durable,
                },
            );
            Ok(durable)
        }

        fn delete_collected(
            &mut self,
            tx_id: TxIdV0,
            _final_record_digest: Digest32V0,
            _replay_floor: ReplayFloorWitnessV0,
        ) -> Result<Digest32V0, Self::Error> {
            self.latest.remove(&tx_id);
            Ok(d(99))
        }
    }

    struct AcceptPermit;

    impl CoreSafetyPermitVerifierV0 for AcceptPermit {
        type Error = Infallible;

        fn verify_core_safety_permit(
            &self,
            _claim: &CoreSafetyPermitClaimV0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct MemorySigner;

    impl NonExportableTxSignerV0 for MemorySigner {
        type Error = Infallible;

        fn sign_transaction(
            &mut self,
            request: &TxSignRequestV0,
        ) -> Result<TxSignatureReceiptV0, Self::Error> {
            let signature = vec![7; 64];
            let mut receipt = TxSignatureReceiptV0 {
                request_digest: request.request_digest,
                signature_digest: Digest32V0::hash(b"trnm.tx.signature-bytes.v0", &[&signature]),
                signature,
                signer_attestation_digest: d(70),
                receipt_digest: d(0),
            };
            receipt.receipt_digest = receipt.canonical_digest();
            Ok(receipt)
        }
    }

    struct MemoryBroadcaster;

    impl AuthenticatedTxBroadcasterV0 for MemoryBroadcaster {
        type Error = Infallible;

        fn broadcast_authenticated(
            &mut self,
            intent: BroadcastIntentV0,
            envelope: &SignedTxEnvelopeV0,
        ) -> Result<BroadcastReceiptV0, Self::Error> {
            Ok(BroadcastReceiptV0 {
                tx_id: intent.tx_id,
                intent_sequence: intent.intent_sequence,
                envelope_digest: envelope.envelope_digest,
                transport_receipt_digest: d(71),
            })
        }
    }

    struct MemoryFinality {
        claim: FinalizedTxClaimV0,
    }

    impl FinalizedTxReadbackSourceV0 for MemoryFinality {
        type Error = Infallible;

        fn read_finalized_transaction(
            &mut self,
            _tx_id: TxIdV0,
        ) -> Result<FinalizedTxClaimV0, Self::Error> {
            Ok(self.claim)
        }
    }

    fn intent() -> TxIntentV0 {
        TxIntentV0 {
            chain_id: d(1),
            sender: d(2),
            nonce: 3,
            fee_bid: 100,
            valid_until_height: 100,
            resource_limits: ResourceLimitsV0 {
                max_compute: 1_000,
                max_state_reads: 10,
                max_state_writes: 10,
                max_event_bytes: 1_024,
            },
            payload: vec![4, 5],
            authorization: vec![6; 64],
        }
    }

    fn ordered() -> OrderedPositionV0 {
        OrderedPositionV0 {
            block_id: d(20),
            height: 9,
            transaction_index: 0,
        }
    }

    fn execution(tx_id: TxIdV0) -> ExecutionReceiptV0 {
        ExecutionReceiptV0 {
            tx_id,
            ordered: ordered(),
            pre_state_root: d(21),
            post_state_root: d(22),
            receipt_digest: d(23),
            event_root: d(24),
            fee_charged: 10,
            success: true,
        }
    }

    #[test]
    fn admission_is_durable_before_ack_and_restart_recovers_exact_state() {
        let mut journal = MemoryJournal::default();
        let mut coordinator = ProductionTxCoordinatorV0::new(d(1), AcceptAuthorization);
        let receipt = coordinator
            .admit_and_persist(&mut journal, intent(), 1)
            .unwrap();
        assert!(receipt.wal_sequence > 0);
        assert_eq!(
            coordinator
                .lifecycle()
                .unwrap()
                .record(receipt.tx_id)
                .unwrap()
                .phase,
            TxPhaseV0::WalPersisted
        );
        let recovered =
            ProductionTxCoordinatorV0::recover(d(1), AcceptAuthorization, &mut journal).unwrap();
        assert_eq!(
            recovered
                .lifecycle()
                .unwrap()
                .record(receipt.tx_id)
                .unwrap()
                .phase,
            TxPhaseV0::WalPersisted
        );
    }

    #[test]
    fn sign_broadcast_finalize_and_gc_are_durably_ordered() {
        let mut journal = MemoryJournal::default();
        let mut coordinator = ProductionTxCoordinatorV0::new(d(1), AcceptAuthorization);
        let admission = coordinator
            .admit_and_persist(&mut journal, intent(), 1)
            .unwrap();
        coordinator
            .persist_proposal(
                &mut journal,
                admission.tx_id,
                ProposalHandoffV0 {
                    proposal_id: d(19),
                    proposal_index: 0,
                },
            )
            .unwrap();
        let current_digest = coordinator.durable[&admission.tx_id].record_digest;
        let mut permit = CoreSafetyPermitClaimV0 {
            tx_id: admission.tx_id,
            tx_record_digest: current_digest,
            safety_state_digest: d(30),
            authority_receipt_digest: d(31),
            permit_digest: d(0),
        };
        permit.permit_digest = permit.canonical_digest();
        coordinator
            .sign_and_broadcast(
                &AcceptPermit,
                &mut MemorySigner,
                &mut MemoryBroadcaster,
                &mut journal,
                permit,
            )
            .unwrap();

        let exec = execution(admission.tx_id);
        let finality = FinalityWitnessV0 {
            block_id: exec.ordered.block_id,
            height: exec.ordered.height,
            state_root: exec.post_state_root,
            finality_proof_digest: d(25),
        };
        let mut claim = FinalizedTxClaimV0 {
            tx_id: admission.tx_id,
            ordered: exec.ordered,
            execution: exec,
            finality,
            source_authentication_digest: d(26),
            claim_digest: d(0),
        };
        claim.claim_digest = claim.canonical_digest();
        let readback = coordinator
            .apply_finalized_readback(&mut MemoryFinality { claim }, &mut journal, admission.tx_id)
            .unwrap();
        assert_eq!(readback.finality, finality);
        coordinator
            .tombstone_and_collect(
                &mut journal,
                admission.tx_id,
                ReplayFloorWitnessV0 {
                    account: d(2),
                    minimum_replayable_nonce: 4,
                    finalized_height: 9,
                    authority_digest: d(40),
                },
            )
            .unwrap();
        assert!(journal.latest.is_empty());
    }
}
