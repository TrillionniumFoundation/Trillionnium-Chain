//! Transport-neutral public transaction ingress for the production-shaped node.
//!
//! This module is the missing dispatch boundary between a host-owned public
//! transport and [`ProductionTxNodeAdapterV0`].  It deliberately does not
//! open a socket, decode a wire format, authenticate a peer, call a signer, or
//! decide finality.  A transport owner must decode and authenticate the exact
//! `TxIntentV0`, construct [`PublicTxIngressRequestV0`], and call
//! [`ProductionTxPublicIngressV0::submit`].  The submit method then dispatches
//! directly into the same node-owned CheckTx and durable M05 admission path;
//! it cannot bypass CheckTx or acknowledge before the journal receipt exists.
//!
//! The object is a composition seam, not production activation.  The
//! production listener, peer/HSM authority, proposal owner and finality
//! readback remain external ports and the activation constant stays false.

use std::{error::Error, fmt};

use trnm_tx_lifecycle_v0::{TxAdmissionReceiptV0, TxIntentV0, TxLifecycleErrorV0};

use crate::{NodeOwnedTxCheckTxErrorV0, NodeOwnedTxCheckTxV0, ProductionTxNodeAdapterV0};

/// This dispatch boundary is available for composition tests and host wiring.
pub const NODE_OWNED_PUBLIC_TX_INGRESS_COMPOSITION_V0: bool = true;

/// A public transport is not production-enabled merely because it binds this
/// object.  A future release must set this only after the independently
/// authenticated listener, peer/HSM, proposal and finality gates are verified.
pub const NODE_OWNED_PUBLIC_TX_INGRESS_PRODUCTION_ACTIVATION_V0: bool = false;

const MAX_PUBLIC_TX_REQUEST_ID_BYTES_V0: usize = 64;

/// Correlation identity carried by a public request.
///
/// This ID is returned unchanged in the admission response.  It is not a
/// transaction nonce and does not provide idempotency: retries must carry the
/// exact same typed intent, whose M05 transaction ID/WAL semantics provide the
/// durable retry behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicTxIngressRequestV0 {
    request_id: String,
    intent: TxIntentV0,
}

impl PublicTxIngressRequestV0 {
    /// Construct a request after the transport has decoded its exact typed
    /// intent.  Request IDs are deliberately restricted to the same closed
    /// ASCII profile used by the native candidate client, so an HTTP/RPC or
    /// Unix transport cannot smuggle control or ambiguous Unicode data into
    /// logs and response correlation.
    pub fn new(
        request_id: impl Into<String>,
        intent: TxIntentV0,
    ) -> Result<Self, PublicTxIngressRequestErrorV0> {
        let request_id = request_id.into();
        validate_request_id_v0(&request_id)?;
        intent
            .validate()
            .map_err(PublicTxIngressRequestErrorV0::InvalidIntent)?;
        Ok(Self { request_id, intent })
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn intent(&self) -> &TxIntentV0 {
        &self.intent
    }

    /// Consume the request after the ingress owner has accepted it.
    #[must_use]
    pub fn into_parts(self) -> (String, TxIntentV0) {
        (self.request_id, self.intent)
    }
}

fn validate_request_id_v0(request_id: &str) -> Result<(), PublicTxIngressRequestErrorV0> {
    if request_id.is_empty() || request_id.len() > MAX_PUBLIC_TX_REQUEST_ID_BYTES_V0 {
        return Err(PublicTxIngressRequestErrorV0::InvalidRequestId);
    }
    if !request_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(PublicTxIngressRequestErrorV0::InvalidRequestId);
    }
    Ok(())
}

/// Local validation failure before a request reaches the CheckTx owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicTxIngressRequestErrorV0 {
    InvalidRequestId,
    InvalidIntent(TxLifecycleErrorV0),
}

impl fmt::Display for PublicTxIngressRequestErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestId => {
                formatter.write_str("public transaction request ID is invalid")
            }
            Self::InvalidIntent(error) => {
                write!(formatter, "public transaction intent is invalid: {error}")
            }
        }
    }
}

impl Error for PublicTxIngressRequestErrorV0 {}

/// Receipt returned by the public dispatch boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicTxAdmissionReceiptV0 {
    request_id: String,
    receipt: TxAdmissionReceiptV0,
}

impl PublicTxAdmissionReceiptV0 {
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub const fn receipt(&self) -> TxAdmissionReceiptV0 {
        self.receipt
    }
}

/// Errors returned by the public dispatch boundary.
#[derive(Debug)]
pub enum PublicTxIngressErrorV0<CheckTxError, AuthorizationError, JournalError> {
    /// The request intent is bound to a different chain. Reject before the
    /// host CheckTx owner sees it, so a misbound transport cannot make a
    /// cross-chain request observable to node-local admission logic.
    ChainMismatch,
    Admission(NodeOwnedTxCheckTxErrorV0<CheckTxError, AuthorizationError, JournalError>),
}

/// Public admission result with the CheckTx, authorization and journal errors.
pub type PublicTxIngressResultV0<C, A, J> =
    Result<PublicTxAdmissionReceiptV0, PublicTxIngressErrorV0<C, A, J>>;

impl<C, A, J> fmt::Display for PublicTxIngressErrorV0<C, A, J>
where
    C: fmt::Display,
    A: fmt::Display,
    J: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainMismatch => formatter
                .write_str("public transaction intent chain does not match the node-owned chain"),
            Self::Admission(error) => {
                write!(formatter, "public transaction admission failed: {error}")
            }
        }
    }
}

impl<C, A, J> Error for PublicTxIngressErrorV0<C, A, J>
where
    C: Error + 'static,
    A: Error + 'static,
    J: Error + 'static,
{
}

/// Node-owned public transaction dispatch.
///
/// The transport owner supplies the authenticated CheckTx implementation and
/// the already-constructed [`ProductionTxNodeAdapterV0`].  `submit` consumes
/// one request and performs the ordered CheckTx -> M05 durable admission
/// transition.  No network or production effect is created by this type.
pub struct ProductionTxPublicIngressV0<A, V, J, P, S, B, R> {
    adapter: ProductionTxNodeAdapterV0<V, J, P, S, B, R>,
    check_tx: A,
}

impl<A, V, J, P, S, B, R> ProductionTxPublicIngressV0<A, V, J, P, S, B, R>
where
    V: trnm_tx_lifecycle_v0::AuthorizationVerifierV0,
{
    #[must_use]
    pub fn new(adapter: ProductionTxNodeAdapterV0<V, J, P, S, B, R>, check_tx: A) -> Self {
        Self { adapter, check_tx }
    }

    #[must_use]
    pub const fn production_activation_v0(&self) -> bool {
        NODE_OWNED_PUBLIC_TX_INGRESS_PRODUCTION_ACTIVATION_V0
    }

    #[must_use]
    pub const fn adapter(&self) -> &ProductionTxNodeAdapterV0<V, J, P, S, B, R> {
        &self.adapter
    }

    pub fn adapter_mut(&mut self) -> &mut ProductionTxNodeAdapterV0<V, J, P, S, B, R> {
        &mut self.adapter
    }
}

impl<A, V, J, P, S, B, R> ProductionTxPublicIngressV0<A, V, J, P, S, B, R>
where
    A: NodeOwnedTxCheckTxV0,
    V: trnm_tx_lifecycle_v0::AuthorizationVerifierV0,
    J: trnm_tx_lifecycle_v0::DurableTxJournalV0,
    P: trnm_tx_lifecycle_v0::CoreSafetyPermitVerifierV0,
    S: trnm_tx_lifecycle_v0::NonExportableTxSignerV0,
    B: trnm_tx_lifecycle_v0::AuthenticatedTxBroadcasterV0,
    R: trnm_tx_lifecycle_v0::FinalizedTxReadbackSourceV0,
{
    /// Dispatch one validated public request into node-owned CheckTx and WAL
    /// admission.  The request ID is copied only after the WAL receipt exists,
    /// so a transport ACK cannot race the durable admission boundary.
    pub fn submit(
        &mut self,
        request: PublicTxIngressRequestV0,
    ) -> PublicTxIngressResultV0<A::Error, V::Error, J::Error> {
        let (request_id, intent) = request.into_parts();
        if intent.chain_id != self.adapter.chain_id() {
            return Err(PublicTxIngressErrorV0::ChainMismatch);
        }
        let receipt = self
            .adapter
            .check_tx_and_admit(&mut self.check_tx, intent)
            .map_err(PublicTxIngressErrorV0::Admission)?;
        Ok(PublicTxAdmissionReceiptV0 {
            request_id,
            receipt,
        })
    }

    #[must_use]
    pub fn into_parts(self) -> (ProductionTxNodeAdapterV0<V, J, P, S, B, R>, A) {
        (self.adapter, self.check_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{convert::Infallible, io};
    use trnm_tx_lifecycle_v0::{
        AccountIdV0, AuthenticatedTxBroadcasterV0, BroadcastIntentV0, BroadcastReceiptV0,
        CoreSafetyPermitVerifierV0, DurableSignedTxEnvelopeV0, DurableTxJournalV0,
        DurableTxRecordV0, DurableTxReplacementV0, FinalizedTxClaimV0, FinalizedTxReadbackSourceV0,
        NonExportableTxSignerV0, RecoveredTxRecordV0, ReplayFloorWitnessV0, SignedTxEnvelopeV0,
        TxIdV0, TxRecordV0, TxSignRequestV0, TxSignatureReceiptV0,
    };

    struct AcceptCheckTx;
    impl NodeOwnedTxCheckTxV0 for AcceptCheckTx {
        type Error = io::Error;
        fn verify_check_tx(&mut self, _intent: &TxIntentV0) -> Result<u64, Self::Error> {
            Ok(1)
        }
    }

    struct UnexpectedCheckTx;
    impl NodeOwnedTxCheckTxV0 for UnexpectedCheckTx {
        type Error = io::Error;
        fn verify_check_tx(&mut self, _intent: &TxIntentV0) -> Result<u64, Self::Error> {
            Err(io::Error::other("cross-chain intent reached CheckTx"))
        }
    }

    struct AcceptAuthorization;
    impl trnm_tx_lifecycle_v0::AuthorizationVerifierV0 for AcceptAuthorization {
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

    #[derive(Default)]
    struct MemoryJournal {
        latest: Option<RecoveredTxRecordV0>,
    }

    impl DurableTxJournalV0 for MemoryJournal {
        type Error = io::Error;
        fn load_latest(
            &mut self,
            _chain_id: trnm_tx_lifecycle_v0::Digest32V0,
        ) -> Result<Vec<RecoveredTxRecordV0>, Self::Error> {
            Ok(self.latest.clone().into_iter().collect())
        }
        fn compare_and_append(
            &mut self,
            expected_previous: Option<trnm_tx_lifecycle_v0::Digest32V0>,
            record: &TxRecordV0,
        ) -> Result<DurableTxRecordV0, Self::Error> {
            if expected_previous
                != self
                    .latest
                    .as_ref()
                    .map(|stored| stored.durable.record_digest)
            {
                return Err(io::Error::other("unexpected predecessor"));
            }
            let record_digest = record.canonical_record_digest_v0();
            let journal_sequence = self
                .latest
                .as_ref()
                .map_or(1, |stored| stored.durable.journal_sequence + 1);
            let durable = DurableTxRecordV0 {
                tx_id: record.tx_id,
                previous_record_digest: expected_previous
                    .unwrap_or(trnm_tx_lifecycle_v0::Digest32V0([0; 32])),
                record_digest,
                journal_sequence,
                durable_receipt_digest: trnm_tx_lifecycle_v0::Digest32V0([7; 32]),
            };
            self.latest = Some(RecoveredTxRecordV0 {
                record: record.clone(),
                durable,
            });
            Ok(durable)
        }
        fn compare_and_replace(
            &mut self,
            _previous: trnm_tx_lifecycle_v0::Digest32V0,
            _replaced: &TxRecordV0,
            _admitted: &TxRecordV0,
        ) -> Result<DurableTxReplacementV0, Self::Error> {
            Err(io::Error::other("replacement not exercised"))
        }
        fn delete_collected(
            &mut self,
            _tx_id: TxIdV0,
            _record: trnm_tx_lifecycle_v0::Digest32V0,
            _floor: ReplayFloorWitnessV0,
        ) -> Result<trnm_tx_lifecycle_v0::Digest32V0, Self::Error> {
            Ok(trnm_tx_lifecycle_v0::Digest32V0([8; 32]))
        }
        fn persist_sign_intent(
            &mut self,
            _intent: trnm_tx_lifecycle_v0::DurableTxSignIntentV0,
        ) -> Result<trnm_tx_lifecycle_v0::DurableTxSignIntentV0, Self::Error> {
            Err(io::Error::other("signing not exercised"))
        }
        fn load_sign_intent(
            &mut self,
            _tx_id: TxIdV0,
        ) -> Result<Option<trnm_tx_lifecycle_v0::DurableTxSignIntentV0>, Self::Error> {
            Ok(None)
        }
        fn persist_signed_envelope(
            &mut self,
            _envelope: DurableSignedTxEnvelopeV0,
        ) -> Result<DurableSignedTxEnvelopeV0, Self::Error> {
            Err(io::Error::other("signing not exercised"))
        }
        fn load_signed_envelope(
            &mut self,
            _tx_id: TxIdV0,
        ) -> Result<Option<DurableSignedTxEnvelopeV0>, Self::Error> {
            Ok(None)
        }
    }

    struct RejectPermit;
    impl CoreSafetyPermitVerifierV0 for RejectPermit {
        type Error = io::Error;
        fn verify_core_safety_permit(
            &self,
            _claim: &trnm_tx_lifecycle_v0::CoreSafetyPermitClaimV0,
        ) -> Result<(), Self::Error> {
            Err(io::Error::other("not exercised"))
        }
    }
    struct RejectSigner;
    impl NonExportableTxSignerV0 for RejectSigner {
        type Error = io::Error;
        fn sign_transaction(
            &mut self,
            _request: &TxSignRequestV0,
        ) -> Result<TxSignatureReceiptV0, Self::Error> {
            Err(io::Error::other("not exercised"))
        }
    }
    struct RejectBroadcaster;
    impl AuthenticatedTxBroadcasterV0 for RejectBroadcaster {
        type Error = io::Error;
        fn broadcast_authenticated(
            &mut self,
            _intent: BroadcastIntentV0,
            _envelope: &SignedTxEnvelopeV0,
        ) -> Result<BroadcastReceiptV0, Self::Error> {
            Err(io::Error::other("not exercised"))
        }
    }
    struct RejectReadback;
    impl FinalizedTxReadbackSourceV0 for RejectReadback {
        type Error = io::Error;
        fn read_finalized_transaction(
            &mut self,
            _tx_id: TxIdV0,
        ) -> Result<FinalizedTxClaimV0, Self::Error> {
            Err(io::Error::other("not exercised"))
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
    fn request_validation_is_closed_before_dispatch() {
        assert!(matches!(
            PublicTxIngressRequestV0::new("bad id", intent()),
            Err(PublicTxIngressRequestErrorV0::InvalidRequestId)
        ));
        assert!(matches!(
            PublicTxIngressRequestV0::new("\u{202e}", intent()),
            Err(PublicTxIngressRequestErrorV0::InvalidRequestId)
        ));
    }

    #[test]
    fn submit_dispatches_checktx_before_durable_ack_and_preserves_request_id() {
        let adapter = ProductionTxNodeAdapterV0::new(
            trnm_tx_lifecycle_v0::Digest32V0([1; 32]),
            AcceptAuthorization,
            MemoryJournal::default(),
            RejectPermit,
            RejectSigner,
            RejectBroadcaster,
            RejectReadback,
        );
        let mut ingress = ProductionTxPublicIngressV0::new(adapter, AcceptCheckTx);
        let request = PublicTxIngressRequestV0::new("req-1", intent()).unwrap();
        let response = ingress.submit(request).unwrap();
        assert_eq!(response.request_id(), "req-1");
        assert_eq!(response.receipt().wal_sequence, 1);
        assert!(!ingress.production_activation_v0());
    }

    #[test]
    fn cross_chain_intent_is_rejected_before_checktx_dispatch() {
        let adapter = ProductionTxNodeAdapterV0::new(
            trnm_tx_lifecycle_v0::Digest32V0([1; 32]),
            AcceptAuthorization,
            MemoryJournal::default(),
            RejectPermit,
            RejectSigner,
            RejectBroadcaster,
            RejectReadback,
        );
        let mut ingress = ProductionTxPublicIngressV0::new(adapter, UnexpectedCheckTx);
        let mut foreign = intent();
        foreign.chain_id = trnm_tx_lifecycle_v0::Digest32V0([9; 32]);
        let request = PublicTxIngressRequestV0::new("foreign-chain", foreign).unwrap();
        assert!(matches!(
            ingress.submit(request),
            Err(PublicTxIngressErrorV0::ChainMismatch)
        ));
        assert!(!ingress.production_activation_v0());
    }
}
