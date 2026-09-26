#![forbid(unsafe_code)]
//! Wiring-only authority boundary and typed, non-activating fact adapters.

#[path = "facade.rs"]
mod facade;
pub use facade::*;

mod confirmed_application_safety;
pub use confirmed_application_safety::{
    ConfirmedApplicationSafetyAuthorityV0, ConfirmedSafetyContinuationV0,
};

#[cfg(feature = "persistent-authority-candidate")]
pub use trnm_poco_node::{
    confirm_retired_epoch_node_checkpoint_v1, ConfirmedRetiredEpochNodeCheckpointV1,
    EpochRetirementCheckpointErrorV1, ExternalNodeCheckpointFieldsV0,
    ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0, SqliteExternalNodeCheckpointStoreV0,
};
