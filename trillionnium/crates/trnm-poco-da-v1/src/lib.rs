//! Candidate-only local transaction-batch DA kernel for PoCO AI-native v1.
//!
//! The crate is deliberately non-normative and cannot activate protocol v1,
//! authorize Order votes, or release a production DA attestation.
//!
//! The durable signing carrier is intentionally linear and cannot be forged
//! or copied outside this crate:
//!
//! ```compile_fail
//! use trnm_poco_da_v1::DurableAttestationIntentV1;
//! fn copy_intent(intent: DurableAttestationIntentV1) {
//!     let _copy = intent.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use trnm_poco_da_v1::DurableAttestationIntentV1;
//! let _forged = DurableAttestationIntentV1 {};
//! ```
//!
//! Production byte deletion is likewise unreachable until a later Node/CAS
//! tranche owns the sole authority issuer:
//!
//! ```compile_fail
//! use trnm_poco_da_v1::FinalizedGcPermitV1;
//! let _forged = FinalizedGcPermitV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_da_v1::FinalizedGcPermitV1;
//! fn copy_permit(permit: FinalizedGcPermitV1) {
//!     let _copy = permit.clone();
//! }
//! ```
//!
//! Signed retrieval response intents and verified repair proofs are likewise
//! linear and cannot be forged or copied by downstream callers:
//!
//! ```compile_fail
//! use trnm_poco_da_v1::RetrievalResponseIntentV1;
//! fn copy_response(intent: RetrievalResponseIntentV1) {
//!     let _copy = intent.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use trnm_poco_da_v1::RetrievalResponseIntentV1;
//! let _forged = RetrievalResponseIntentV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_da_v1::VerifiedRetrievalProofV1;
//! fn copy_proof(proof: VerifiedRetrievalProofV1) {
//!     let _copy = proof.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use trnm_poco_da_v1::VerifiedRetrievalProofV1;
//! let _forged = VerifiedRetrievalProofV1 {};
//! ```

#![forbid(unsafe_code)]

mod codec;
mod error;
mod retrieval;
mod store;
mod types;

pub use error::{DaErrorCodeV1, DaErrorV1, DaResultV1};
pub use retrieval::{
    DaChunkInclusionProofV1, MerkleStepV1, RetrievalProofV1, RetrievalReceiptBodyV1,
    RetrievalRequestBodyV1, RetrievalRequestV1, RetrievalRequesterAuthorityV1,
    RetrievalResponseIntentV1, RetrievalResponseV1, ReturnedChunkEntryV1, VerifiedRetrievalProofV1,
};
pub use store::{
    AttestationPreparationOutcomeV1, BatchAdmissionOutcomeV1, BatchAvailabilityStateV1,
    CertifiedBatchFactsV1, CertifiedBatchV1, DaCertifiedBatchFreshReadbackV1, DaFreshReadbackV1,
    DaStoreConfigV1, DurableAttestationIntentV1, FinalizedGcPermitV1, LocalRetrievalV1,
    PocoDaStoreV1,
};
pub use types::{
    AttestorEquivocationEvidenceV1, AvailabilityCertificateIdV1, AvailabilityCertificateV1,
    BatchIdV1, ChunkIdV1, DaAttestationBodyV1, DaAttestationIdV1, DaAttestationV1,
    DaAuthorAuthorityV1, DaBatchAuthorV1, DaBatchEnvelopeV1, DaCommitteeDescriptorV1,
    DaCommitteeIdV1, DaMemberV1, DaNamespaceV1, DaObjectKindV1, DaObligationIdV1, DaObligationV1,
    DaPolicyV1, Hash32V1, ProtocolContextV1, TypedDaObjectIdV1, UnsignedTransactionBatchV1,
    WithholdingEvidenceIdV1,
};

#[cfg(test)]
mod tests;
