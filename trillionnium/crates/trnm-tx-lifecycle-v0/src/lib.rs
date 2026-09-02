#![forbid(unsafe_code)]
//! Deterministic transaction lifecycle for the native PoCO-BFT v0 path.
//!
//! The core owns no filesystem, socket, clock, signer, or executor.  It emits
//! exact durable intents and accepts only typed, digest-bound receipts from
//! those adapters.  A production host must persist each returned record before
//! exposing the corresponding effect.

use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt};

pub const TX_LIFECYCLE_VERSION_V0: u16 = 0;
pub const MAX_TX_BYTES_V0: usize = 1024 * 1024;
pub const MAX_AUTHORIZATION_BYTES_V0: usize = 16 * 1024;
pub const MAX_RESULT_BYTES_V0: usize = 1024 * 1024;
pub const MAX_EVENTS_ROOT_INPUT_BYTES_V0: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32V0(pub [u8; 32]);

impl Digest32V0 {
    #[must_use]
    pub fn hash(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update((domain.len() as u64).to_be_bytes());
        h.update(domain);
        for part in parts {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        Self(h.finalize().into())
    }
}

pub type AccountIdV0 = Digest32V0;
pub type TxIdV0 = Digest32V0;
pub type BlockIdV0 = Digest32V0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimitsV0 {
    pub max_compute: u64,
    pub max_state_reads: u32,
    pub max_state_writes: u32,
    pub max_event_bytes: u32,
}

impl ResourceLimitsV0 {
    pub fn validate(self) -> Result<Self, TxLifecycleErrorV0> {
        if self.max_compute == 0
            || self.max_state_reads == 0
            || self.max_state_writes == 0
            || self.max_event_bytes == 0
            || self.max_event_bytes as usize > MAX_EVENTS_ROOT_INPUT_BYTES_V0
        {
            return Err(TxLifecycleErrorV0::InvalidResourceLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIntentV0 {
    pub chain_id: Digest32V0,
    pub sender: AccountIdV0,
    pub nonce: u64,
    pub fee_bid: u128,
    pub valid_until_height: u64,
    pub resource_limits: ResourceLimitsV0,
    pub payload: Vec<u8>,
    pub authorization: Vec<u8>,
}

impl TxIntentV0 {
    pub fn validate(&self) -> Result<(), TxLifecycleErrorV0> {
        self.resource_limits.validate()?;
        if self.payload.is_empty() || self.payload.len() > MAX_TX_BYTES_V0 {
            return Err(TxLifecycleErrorV0::TransactionOutOfBounds);
        }
        if self.authorization.is_empty() || self.authorization.len() > MAX_AUTHORIZATION_BYTES_V0 {
            return Err(TxLifecycleErrorV0::AuthorizationOutOfBounds);
        }
        if self.fee_bid == 0 || self.valid_until_height == 0 {
            return Err(TxLifecycleErrorV0::InvalidAdmissionEnvelope);
        }
        Ok(())
    }

    #[must_use]
    pub fn signing_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.tx.signing.v0",
            &[
                &self.chain_id.0,
                &self.sender.0,
                &self.nonce.to_be_bytes(),
                &self.fee_bid.to_be_bytes(),
                &self.valid_until_height.to_be_bytes(),
                &self.resource_limits.max_compute.to_be_bytes(),
                &self.resource_limits.max_state_reads.to_be_bytes(),
                &self.resource_limits.max_state_writes.to_be_bytes(),
                &self.resource_limits.max_event_bytes.to_be_bytes(),
                &self.payload,
            ],
        )
    }

    #[must_use]
    pub fn tx_id(&self) -> TxIdV0 {
        Digest32V0::hash(
            b"trnm.tx.id.v0",
            &[&self.signing_digest().0, &self.authorization],
        )
    }
}

pub trait AuthorizationVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify(
        &self,
        sender: AccountIdV0,
        signing_digest: Digest32V0,
        authorization: &[u8],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TxPhaseV0 {
    Admitted = 0,
    WalPersisted = 1,
    Proposed = 2,
    Ordered = 3,
    Executed = 4,
    Finalized = 5,
    Tombstoned = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TombstoneReasonV0 {
    Replaced { by: TxIdV0 },
    Finalized,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalHandoffV0 {
    pub proposal_id: Digest32V0,
    pub proposal_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedPositionV0 {
    pub block_id: BlockIdV0,
    pub height: u64,
    pub transaction_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionReceiptV0 {
    pub tx_id: TxIdV0,
    pub ordered: OrderedPositionV0,
    pub pre_state_root: Digest32V0,
    pub post_state_root: Digest32V0,
    pub receipt_digest: Digest32V0,
    pub event_root: Digest32V0,
    pub fee_charged: u128,
    pub success: bool,
}

impl ExecutionReceiptV0 {
    pub fn validate(&self, expected_tx: TxIdV0) -> Result<(), TxLifecycleErrorV0> {
        if self.tx_id != expected_tx
            || self.ordered.height == 0
            || self.fee_charged == 0
            || self.fee_charged > u128::MAX / 2
        {
            return Err(TxLifecycleErrorV0::ExecutionReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalityWitnessV0 {
    pub block_id: BlockIdV0,
    pub height: u64,
    pub state_root: Digest32V0,
    pub finality_proof_digest: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BroadcastIntentV0 {
    pub tx_id: TxIdV0,
    pub intent_sequence: u64,
    pub envelope_digest: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BroadcastReceiptV0 {
    pub tx_id: TxIdV0,
    pub intent_sequence: u64,
    pub envelope_digest: Digest32V0,
    pub transport_receipt_digest: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayFloorWitnessV0 {
    pub account: AccountIdV0,
    pub minimum_replayable_nonce: u64,
    pub finalized_height: u64,
    pub authority_digest: Digest32V0,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedReadbackV0 {
    pub tx_id: TxIdV0,
    pub sender: AccountIdV0,
    pub nonce: u64,
    pub ordered: OrderedPositionV0,
    pub execution: ExecutionReceiptV0,
    pub finality: FinalityWitnessV0,
    pub broadcast: Option<BroadcastReceiptV0>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxRecordV0 {
    pub intent: TxIntentV0,
    pub tx_id: TxIdV0,
    pub phase: TxPhaseV0,
    pub lifecycle_sequence: u64,
    pub wal_sequence: Option<u64>,
    pub proposal: Option<ProposalHandoffV0>,
    pub ordered: Option<OrderedPositionV0>,
    pub execution: Option<ExecutionReceiptV0>,
    pub finality: Option<FinalityWitnessV0>,
    pub broadcast_intent: Option<BroadcastIntentV0>,
    pub broadcast_receipt: Option<BroadcastReceiptV0>,
    pub tombstone: Option<TombstoneReasonV0>,
}

impl TxRecordV0 {
    fn advance(&mut self, next: TxPhaseV0) -> Result<(), TxLifecycleErrorV0> {
        let valid = matches!(
            (self.phase, next),
            (TxPhaseV0::Admitted, TxPhaseV0::WalPersisted)
                | (TxPhaseV0::WalPersisted, TxPhaseV0::Proposed)
                | (TxPhaseV0::Proposed, TxPhaseV0::Ordered)
                | (TxPhaseV0::Ordered, TxPhaseV0::Executed)
                | (TxPhaseV0::Executed, TxPhaseV0::Finalized)
                | (TxPhaseV0::Admitted, TxPhaseV0::Tombstoned)
                | (TxPhaseV0::WalPersisted, TxPhaseV0::Tombstoned)
                | (TxPhaseV0::Finalized, TxPhaseV0::Tombstoned)
        );
        if !valid {
            return Err(TxLifecycleErrorV0::InvalidPhaseTransition);
        }
        self.lifecycle_sequence = self
            .lifecycle_sequence
            .checked_add(1)
            .ok_or(TxLifecycleErrorV0::SequenceOverflow)?;
        self.phase = next;
        Ok(())
    }
}

pub struct TxLifecycleV0<V> {
    chain_id: Digest32V0,
    verifier: V,
    records: BTreeMap<TxIdV0, TxRecordV0>,
    active_nonce: BTreeMap<(AccountIdV0, u64), TxIdV0>,
    finalized_nonce: BTreeMap<AccountIdV0, u64>,
    next_broadcast_sequence: u64,
}

impl<V> TxLifecycleV0<V>
where
    V: AuthorizationVerifierV0,
{
    #[must_use]
    pub fn new(chain_id: Digest32V0, verifier: V) -> Self {
        Self {
            chain_id,
            verifier,
            records: BTreeMap::new(),
            active_nonce: BTreeMap::new(),
            finalized_nonce: BTreeMap::new(),
            next_broadcast_sequence: 0,
        }
    }

    pub fn admit(
        &mut self,
        intent: TxIntentV0,
        current_height: u64,
    ) -> Result<TxIdV0, TxLifecycleHostErrorV0<V::Error>> {
        intent
            .validate()
            .map_err(TxLifecycleHostErrorV0::Lifecycle)?;
        if intent.chain_id != self.chain_id {
            return Err(TxLifecycleHostErrorV0::Lifecycle(
                TxLifecycleErrorV0::WrongChain,
            ));
        }
        if current_height == 0 || current_height > intent.valid_until_height {
            return Err(TxLifecycleHostErrorV0::Lifecycle(
                TxLifecycleErrorV0::Expired,
            ));
        }
        if self
            .finalized_nonce
            .get(&intent.sender)
            .is_some_and(|nonce| intent.nonce <= *nonce)
        {
            return Err(TxLifecycleHostErrorV0::Lifecycle(
                TxLifecycleErrorV0::Replay,
            ));
        }
        self.verifier
            .verify(
                intent.sender,
                intent.signing_digest(),
                &intent.authorization,
            )
            .map_err(TxLifecycleHostErrorV0::Authorization)?;

        let tx_id = intent.tx_id();
        if self.records.contains_key(&tx_id) {
            return Ok(tx_id);
        }

        let nonce_key = (intent.sender, intent.nonce);
        if let Some(previous_id) = self.active_nonce.get(&nonce_key).copied() {
            let previous =
                self.records
                    .get(&previous_id)
                    .ok_or(TxLifecycleHostErrorV0::Lifecycle(
                        TxLifecycleErrorV0::StateCorruption,
                    ))?;
            if !matches!(
                previous.phase,
                TxPhaseV0::Admitted | TxPhaseV0::WalPersisted
            ) || intent.fee_bid <= previous.intent.fee_bid
            {
                return Err(TxLifecycleHostErrorV0::Lifecycle(
                    TxLifecycleErrorV0::ReplacementRejected,
                ));
            }
            let previous =
                self.records
                    .get_mut(&previous_id)
                    .ok_or(TxLifecycleHostErrorV0::Lifecycle(
                        TxLifecycleErrorV0::StateCorruption,
                    ))?;
            previous
                .advance(TxPhaseV0::Tombstoned)
                .map_err(TxLifecycleHostErrorV0::Lifecycle)?;
            previous.tombstone = Some(TombstoneReasonV0::Replaced { by: tx_id });
        }

        self.records.insert(
            tx_id,
            TxRecordV0 {
                intent,
                tx_id,
                phase: TxPhaseV0::Admitted,
                lifecycle_sequence: 0,
                wal_sequence: None,
                proposal: None,
                ordered: None,
                execution: None,
                finality: None,
                broadcast_intent: None,
                broadcast_receipt: None,
                tombstone: None,
            },
        );
        self.active_nonce.insert(nonce_key, tx_id);
        Ok(tx_id)
    }

    pub fn persist_wal(
        &mut self,
        tx_id: TxIdV0,
        wal_sequence: u64,
    ) -> Result<(), TxLifecycleErrorV0> {
        let record = self.record_mut(tx_id)?;
        if let Some(existing) = record.wal_sequence {
            return if existing == wal_sequence {
                Ok(())
            } else {
                Err(TxLifecycleErrorV0::ReceiptSubstitution)
            };
        }
        record.advance(TxPhaseV0::WalPersisted)?;
        record.wal_sequence = Some(wal_sequence);
        Ok(())
    }

    pub fn handoff_proposal(
        &mut self,
        tx_id: TxIdV0,
        handoff: ProposalHandoffV0,
    ) -> Result<(), TxLifecycleErrorV0> {
        let record = self.record_mut(tx_id)?;
        if handoff.proposal_index == u32::MAX {
            return Err(TxLifecycleErrorV0::InvalidProposalHandoff);
        }
        if let Some(existing) = record.proposal {
            return if existing == handoff {
                Ok(())
            } else {
                Err(TxLifecycleErrorV0::ReceiptSubstitution)
            };
        }
        record.advance(TxPhaseV0::Proposed)?;
        record.proposal = Some(handoff);
        Ok(())
    }

    pub fn mark_ordered(
        &mut self,
        tx_id: TxIdV0,
        position: OrderedPositionV0,
    ) -> Result<(), TxLifecycleErrorV0> {
        if position.height == 0 || position.transaction_index == u32::MAX {
            return Err(TxLifecycleErrorV0::InvalidOrderedPosition);
        }
        let record = self.record_mut(tx_id)?;
        if let Some(existing) = record.ordered {
            return if existing == position {
                Ok(())
            } else {
                Err(TxLifecycleErrorV0::ReceiptSubstitution)
            };
        }
        record.advance(TxPhaseV0::Ordered)?;
        record.ordered = Some(position);
        Ok(())
    }

    pub fn mark_executed(&mut self, receipt: ExecutionReceiptV0) -> Result<(), TxLifecycleErrorV0> {
        receipt.validate(receipt.tx_id)?;
        let record = self.record_mut(receipt.tx_id)?;
        if record.ordered != Some(receipt.ordered) {
            return Err(TxLifecycleErrorV0::ExecutionReceiptMismatch);
        }
        if receipt.fee_charged > record.intent.fee_bid {
            return Err(TxLifecycleErrorV0::ExecutionReceiptMismatch);
        }
        if let Some(existing) = record.execution {
            return if existing == receipt {
                Ok(())
            } else {
                Err(TxLifecycleErrorV0::ReceiptSubstitution)
            };
        }
        record.advance(TxPhaseV0::Executed)?;
        record.execution = Some(receipt);
        Ok(())
    }

    pub fn create_broadcast_intent(
        &mut self,
        tx_id: TxIdV0,
        envelope_digest: Digest32V0,
    ) -> Result<BroadcastIntentV0, TxLifecycleErrorV0> {
        if let Some(existing) = self.record(tx_id)?.broadcast_intent {
            return if existing.envelope_digest == envelope_digest {
                Ok(existing)
            } else {
                Err(TxLifecycleErrorV0::ReceiptSubstitution)
            };
        }
        let sequence = self.next_broadcast_sequence;
        self.next_broadcast_sequence = self
            .next_broadcast_sequence
            .checked_add(1)
            .ok_or(TxLifecycleErrorV0::SequenceOverflow)?;
        let intent = BroadcastIntentV0 {
            tx_id,
            intent_sequence: sequence,
            envelope_digest,
        };
        self.record_mut(tx_id)?.broadcast_intent = Some(intent);
        Ok(intent)
    }

    pub fn confirm_broadcast(
        &mut self,
        receipt: BroadcastReceiptV0,
    ) -> Result<(), TxLifecycleErrorV0> {
        let record = self.record_mut(receipt.tx_id)?;
        let intent = record
            .broadcast_intent
            .ok_or(TxLifecycleErrorV0::MissingBroadcastIntent)?;
        if intent.tx_id != receipt.tx_id
            || intent.intent_sequence != receipt.intent_sequence
            || intent.envelope_digest != receipt.envelope_digest
        {
            return Err(TxLifecycleErrorV0::ReceiptSubstitution);
        }
        if let Some(existing) = record.broadcast_receipt {
            return if existing == receipt {
                Ok(())
            } else {
                Err(TxLifecycleErrorV0::ReceiptSubstitution)
            };
        }
        record.broadcast_receipt = Some(receipt);
        Ok(())
    }

    pub fn finalize(
        &mut self,
        tx_id: TxIdV0,
        witness: FinalityWitnessV0,
    ) -> Result<(), TxLifecycleErrorV0> {
        let (sender, nonce, ordered) = {
            let record = self.record(tx_id)?;
            (
                record.intent.sender,
                record.intent.nonce,
                record
                    .ordered
                    .ok_or(TxLifecycleErrorV0::InvalidPhaseTransition)?,
            )
        };
        if witness.block_id != ordered.block_id || witness.height != ordered.height {
            return Err(TxLifecycleErrorV0::FinalityWitnessMismatch);
        }
        let record = self.record_mut(tx_id)?;
        if let Some(existing) = record.finality {
            return if existing == witness {
                Ok(())
            } else {
                Err(TxLifecycleErrorV0::ReceiptSubstitution)
            };
        }
        record.advance(TxPhaseV0::Finalized)?;
        record.finality = Some(witness);
        self.finalized_nonce
            .entry(sender)
            .and_modify(|value| *value = (*value).max(nonce))
            .or_insert(nonce);
        self.active_nonce.remove(&(sender, nonce));
        Ok(())
    }

    pub fn finalized_readback(
        &self,
        tx_id: TxIdV0,
    ) -> Result<FinalizedReadbackV0, TxLifecycleErrorV0> {
        let record = self.record(tx_id)?;
        if !matches!(record.phase, TxPhaseV0::Finalized | TxPhaseV0::Tombstoned) {
            return Err(TxLifecycleErrorV0::NotFinalized);
        }
        Ok(FinalizedReadbackV0 {
            tx_id,
            sender: record.intent.sender,
            nonce: record.intent.nonce,
            ordered: record.ordered.ok_or(TxLifecycleErrorV0::StateCorruption)?,
            execution: record
                .execution
                .ok_or(TxLifecycleErrorV0::StateCorruption)?,
            finality: record.finality.ok_or(TxLifecycleErrorV0::StateCorruption)?,
            broadcast: record.broadcast_receipt,
        })
    }

    pub fn tombstone_finalized(&mut self, tx_id: TxIdV0) -> Result<(), TxLifecycleErrorV0> {
        let record = self.record_mut(tx_id)?;
        if record.phase == TxPhaseV0::Tombstoned
            && record.tombstone == Some(TombstoneReasonV0::Finalized)
        {
            return Ok(());
        }
        record.advance(TxPhaseV0::Tombstoned)?;
        record.tombstone = Some(TombstoneReasonV0::Finalized);
        Ok(())
    }

    pub fn collect(
        &mut self,
        tx_id: TxIdV0,
        replay_floor: ReplayFloorWitnessV0,
    ) -> Result<TxRecordV0, TxLifecycleErrorV0> {
        let record = self.record(tx_id)?;
        if record.phase != TxPhaseV0::Tombstoned {
            return Err(TxLifecycleErrorV0::GcNotAuthorized);
        }
        let finality_height = record.finality.map_or(0, |value| value.height);
        if replay_floor.account != record.intent.sender
            || replay_floor.minimum_replayable_nonce <= record.intent.nonce
            || replay_floor.finalized_height < finality_height
            || replay_floor.authority_digest == Digest32V0([0; 32])
        {
            return Err(TxLifecycleErrorV0::GcNotAuthorized);
        }
        self.records
            .remove(&tx_id)
            .ok_or(TxLifecycleErrorV0::UnknownTransaction)
    }

    #[must_use]
    pub fn record(&self, tx_id: TxIdV0) -> Result<&TxRecordV0, TxLifecycleErrorV0> {
        self.records
            .get(&tx_id)
            .ok_or(TxLifecycleErrorV0::UnknownTransaction)
    }

    fn record_mut(&mut self, tx_id: TxIdV0) -> Result<&mut TxRecordV0, TxLifecycleErrorV0> {
        self.records
            .get_mut(&tx_id)
            .ok_or(TxLifecycleErrorV0::UnknownTransaction)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxLifecycleErrorV0 {
    InvalidResourceLimits,
    TransactionOutOfBounds,
    AuthorizationOutOfBounds,
    InvalidAdmissionEnvelope,
    WrongChain,
    Expired,
    Replay,
    ReplacementRejected,
    UnknownTransaction,
    InvalidPhaseTransition,
    InvalidProposalHandoff,
    InvalidOrderedPosition,
    ExecutionReceiptMismatch,
    FinalityWitnessMismatch,
    MissingBroadcastIntent,
    ReceiptSubstitution,
    NotFinalized,
    GcNotAuthorized,
    SequenceOverflow,
    StateCorruption,
}

impl fmt::Display for TxLifecycleErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidResourceLimits => "invalid transaction resource limits",
            Self::TransactionOutOfBounds => "transaction payload is outside the protocol bound",
            Self::AuthorizationOutOfBounds => "authorization is outside the protocol bound",
            Self::InvalidAdmissionEnvelope => "invalid admission envelope",
            Self::WrongChain => "transaction is bound to another chain",
            Self::Expired => "transaction validity height has expired",
            Self::Replay => "transaction nonce is below the finalized replay floor",
            Self::ReplacementRejected => {
                "transaction replacement is not strictly fee-increasing and pre-order"
            }
            Self::UnknownTransaction => "unknown transaction",
            Self::InvalidPhaseTransition => "invalid transaction lifecycle transition",
            Self::InvalidProposalHandoff => "invalid proposal handoff",
            Self::InvalidOrderedPosition => "invalid ordered position",
            Self::ExecutionReceiptMismatch => {
                "execution receipt is not bound to the ordered transaction"
            }
            Self::FinalityWitnessMismatch => "finality witness is not bound to the ordered block",
            Self::MissingBroadcastIntent => "broadcast receipt has no durable intent",
            Self::ReceiptSubstitution => "idempotent receipt differs from the retained receipt",
            Self::NotFinalized => "finalized readback requested before finality",
            Self::GcNotAuthorized => "tombstone garbage collection lacks replay-floor authority",
            Self::SequenceOverflow => "transaction lifecycle sequence overflow",
            Self::StateCorruption => "transaction lifecycle state is internally inconsistent",
        })
    }
}

impl Error for TxLifecycleErrorV0 {}

#[derive(Debug)]
pub enum TxLifecycleHostErrorV0<AuthorizationError> {
    Lifecycle(TxLifecycleErrorV0),
    Authorization(AuthorizationError),
}

impl<A: fmt::Display> fmt::Display for TxLifecycleHostErrorV0<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lifecycle(error) => write!(f, "transaction lifecycle rejected request: {error}"),
            Self::Authorization(error) => write!(f, "transaction authorization failed: {error}"),
        }
    }
}

impl<A> Error for TxLifecycleHostErrorV0<A> where A: Error + 'static {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

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

    fn d(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    fn intent(fee_bid: u128) -> TxIntentV0 {
        TxIntentV0 {
            chain_id: d(1),
            sender: d(2),
            nonce: 7,
            fee_bid,
            valid_until_height: 100,
            resource_limits: ResourceLimitsV0 {
                max_compute: 10_000,
                max_state_reads: 10,
                max_state_writes: 10,
                max_event_bytes: 1024,
            },
            payload: vec![3, 4, 5],
            authorization: vec![6; 64],
        }
    }

    fn position() -> OrderedPositionV0 {
        OrderedPositionV0 {
            block_id: d(8),
            height: 9,
            transaction_index: 0,
        }
    }

    fn execution(tx_id: TxIdV0) -> ExecutionReceiptV0 {
        ExecutionReceiptV0 {
            tx_id,
            ordered: position(),
            pre_state_root: d(10),
            post_state_root: d(11),
            receipt_digest: d(12),
            event_root: d(13),
            fee_charged: 5,
            success: true,
        }
    }

    #[test]
    fn full_lifecycle_is_idempotent_and_gc_is_proof_gated() {
        let mut lifecycle = TxLifecycleV0::new(d(1), AcceptAuthorization);
        let tx_id = lifecycle.admit(intent(10), 1).unwrap();
        lifecycle.persist_wal(tx_id, 1).unwrap();
        lifecycle
            .handoff_proposal(
                tx_id,
                ProposalHandoffV0 {
                    proposal_id: d(7),
                    proposal_index: 0,
                },
            )
            .unwrap();
        lifecycle.mark_ordered(tx_id, position()).unwrap();
        lifecycle.mark_executed(execution(tx_id)).unwrap();
        let broadcast = lifecycle.create_broadcast_intent(tx_id, d(14)).unwrap();
        let broadcast_receipt = BroadcastReceiptV0 {
            tx_id,
            intent_sequence: broadcast.intent_sequence,
            envelope_digest: broadcast.envelope_digest,
            transport_receipt_digest: d(15),
        };
        lifecycle.confirm_broadcast(broadcast_receipt).unwrap();
        let finality = FinalityWitnessV0 {
            block_id: position().block_id,
            height: position().height,
            state_root: execution(tx_id).post_state_root,
            finality_proof_digest: d(16),
        };
        lifecycle.finalize(tx_id, finality).unwrap();
        lifecycle.finalize(tx_id, finality).unwrap();
        let readback = lifecycle.finalized_readback(tx_id).unwrap();
        assert_eq!(readback.broadcast, Some(broadcast_receipt));
        lifecycle.tombstone_finalized(tx_id).unwrap();
        assert_eq!(
            lifecycle
                .collect(
                    tx_id,
                    ReplayFloorWitnessV0 {
                        account: d(2),
                        minimum_replayable_nonce: 7,
                        finalized_height: 9,
                        authority_digest: d(17),
                    }
                )
                .unwrap_err(),
            TxLifecycleErrorV0::GcNotAuthorized
        );
        lifecycle
            .collect(
                tx_id,
                ReplayFloorWitnessV0 {
                    account: d(2),
                    minimum_replayable_nonce: 8,
                    finalized_height: 9,
                    authority_digest: d(17),
                },
            )
            .unwrap();
        assert_eq!(
            lifecycle.record(tx_id).unwrap_err(),
            TxLifecycleErrorV0::UnknownTransaction
        );
    }

    #[test]
    fn replacement_requires_strictly_higher_fee_and_preorder_phase() {
        let mut lifecycle = TxLifecycleV0::new(d(1), AcceptAuthorization);
        let first = lifecycle.admit(intent(10), 1).unwrap();
        let same_fee = lifecycle.admit(intent(10), 1).unwrap();
        assert_eq!(first, same_fee);

        let replacement = lifecycle.admit(intent(11), 1).unwrap();
        assert_ne!(first, replacement);
        assert_eq!(
            lifecycle.record(first).unwrap().phase,
            TxPhaseV0::Tombstoned
        );
        assert_eq!(
            lifecycle.record(first).unwrap().tombstone,
            Some(TombstoneReasonV0::Replaced { by: replacement })
        );
    }

    #[test]
    fn receipt_substitution_fails_closed() {
        let mut lifecycle = TxLifecycleV0::new(d(1), AcceptAuthorization);
        let tx_id = lifecycle.admit(intent(10), 1).unwrap();
        lifecycle.persist_wal(tx_id, 1).unwrap();
        assert_eq!(
            lifecycle.persist_wal(tx_id, 2).unwrap_err(),
            TxLifecycleErrorV0::ReceiptSubstitution
        );
    }
}
