#![no_std]
#![forbid(unsafe_code)]
//! Inert, cumulative whole-node checkpoint records.
//!
//! The types and exact codec in this crate describe public data only. They do
//! not authenticate referenced stores, grant a lease, perform persistence or
//! CAS, mint an application-valid or SafetyRules authorization, or permit a
//! signer/HSM invocation. A decoded record is freely copyable data and never a
//! committed capability.

extern crate alloc;

mod codec;
mod ids;
mod model;
mod reference;

pub use codec::{decode_whole_node_checkpoint_v1_exact, MAX_WHOLE_NODE_CHECKPOINT_BYTES_V1};
pub use ids::{
    ApplicationValidationGenerationV1, ProcessGenerationV1, WholeNodeCheckpointChecksumV1,
    WholeNodeCheckpointGenerationV1, WholeNodeCheckpointScopeV1, WholeNodeCheckpointTypeErrorV1,
    WholeNodeCutDigestV1, MAX_WHOLE_NODE_PUBLIC_DESCRIPTOR_BYTES_V1,
};
pub use model::{
    AppAttestorCutRefV1, ApplicationCutRefV1, ApplicationValidationCutRefV1,
    ApplicationValidationLineageCutRefV1, ChainCutRefV1, CoreSafetyCutRefV1, ProcessFenceRefV1,
    ProcessFencesCutRefV1, RemoteSafetyCutRefV1, RoleBindingsCutRefV1, SignOperationCutRefV1,
    SignOperationKindV1, SignerCutRefV1, SignerJournalStateV1, WholeNodeCheckpointErrorV1,
    WholeNodeCheckpointPhaseV1, WholeNodeCheckpointResultV1, WholeNodeCheckpointV1,
    WHOLE_NODE_CHECKPOINT_SCHEMA_V1,
};
pub use reference::{
    decode_whole_node_checkpoint_ref_v1_exact, WholeNodeCheckpointRefV1,
    WHOLE_NODE_CHECKPOINT_REF_BYTES_V1, WHOLE_NODE_CHECKPOINT_REF_SCHEMA_V1,
};

/// Canonical decoding and construction establish data shape only.
pub const WHOLE_NODE_CHECKPOINT_DECODED_RECORD_AUTHORITY_V1: bool = false;
/// Projecting or decoding a checkpoint reference grants no checkpoint authority.
pub const WHOLE_NODE_CHECKPOINT_REFERENCE_AUTHORITY_V1: bool = false;
/// An epoch-transition phase tag grants no epoch activation authority.
pub const WHOLE_NODE_CHECKPOINT_EPOCH_ACTIVATION_AUTHORITY_V1: bool = false;
/// No application-valid authority is created by a referenced validation cut.
pub const WHOLE_NODE_CHECKPOINT_APPLICATION_VALIDATION_AUTHORITY_V1: bool = false;
/// No HotStuff or SafetyRules decision is made by this crate.
pub const WHOLE_NODE_CHECKPOINT_SAFETY_RULES_AUTHORITY_V1: bool = false;
/// No checkpoint value grants access to a signer or private key.
pub const WHOLE_NODE_CHECKPOINT_SIGNER_AUTHORITY_V1: bool = false;
/// Process and lease fence fields are untrusted data until externally joined.
pub const WHOLE_NODE_CHECKPOINT_LEASE_AUTHORITY_V1: bool = false;
/// Role/profile checksums are bindings, not role authority.
pub const WHOLE_NODE_CHECKPOINT_ROLE_BINDING_AUTHORITY_V1: bool = false;
/// This crate contains no persistence implementation.
pub const WHOLE_NODE_CHECKPOINT_PERSISTENCE_AUTHORITY_V1: bool = false;
/// This crate contains no checkpoint store.
pub const WHOLE_NODE_CHECKPOINT_STORE_V1: bool = false;
/// This crate contains no compare-and-swap operation or trait.
pub const WHOLE_NODE_CHECKPOINT_SUCCESSOR_CAS_V1: bool = false;
/// A checksum chain alone is not external anti-rollback authority.
pub const WHOLE_NODE_CHECKPOINT_EXTERNAL_ANTI_ROLLBACK_AUTHORITY_V1: bool = false;
/// This crate cannot produce an application validation attestation.
pub const WHOLE_NODE_CHECKPOINT_APPLICATION_ATTESTATION_PRODUCER_V1: bool = false;
/// This crate cannot produce a consensus signature.
pub const WHOLE_NODE_CHECKPOINT_SIGNATURE_PRODUCER_V1: bool = false;
/// No HSM/KMS adapter is present.
pub const WHOLE_NODE_CHECKPOINT_HSM_ADAPTER_V1: bool = false;
/// No node or service runtime is activated.
pub const WHOLE_NODE_CHECKPOINT_RUNTIME_ACTIVATION_V1: bool = false;
/// Schema v1 cannot bridge an EpochActive reference into a full signing cycle.
pub const WHOLE_NODE_CHECKPOINT_POST_EPOCH_SIGNING_CYCLE_BRIDGE_V1: bool = false;
/// This first types slice is not a production candidate.
pub const WHOLE_NODE_CHECKPOINT_PRODUCTION_CANDIDATE_V1: bool = false;
/// Production activation remains closed.
pub const WHOLE_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V1: bool = false;
/// Production consensus activation remains closed.
pub const WHOLE_NODE_CHECKPOINT_PRODUCTION_CONSENSUS_ACTIVATION_V1: bool = false;

#[cfg(test)]
mod tests;
