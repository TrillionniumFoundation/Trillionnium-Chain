#![forbid(unsafe_code)]
//! Wiring-only PoCO node host composition.

#[path = "facade.rs"]
mod facade;
pub use facade::*;

#[cfg(feature = "persistent-authority-candidate")]
mod confirmed_application_safety;

#[cfg(feature = "candidate-networked-authority")]
mod p2p_ingress_bridge;
#[cfg(feature = "candidate-networked-authority")]
pub use p2p_ingress_bridge::*;

#[cfg(feature = "candidate-networked-authority")]
mod persistent_p2p_ingress_bridge;
#[cfg(feature = "candidate-networked-authority")]
pub use persistent_p2p_ingress_bridge::*;
#[cfg(feature = "candidate-networked-authority")]
pub use trnm_poco_node::{
    AuthenticatedTransportErrorV0, CandidateAuthenticatedP2pTransportV0,
    AUTHENTICATED_TRANSPORT_FRAME_TIMEOUT_V0, AUTHENTICATED_TRANSPORT_HANDSHAKE_TIMEOUT_V0,
    AUTHENTICATED_TRANSPORT_MAX_CONNECTIONS_V0, AUTHENTICATED_TRANSPORT_MAX_RESPONSE_BYTES_V0,
    AUTHENTICATED_TRANSPORT_PRODUCTION_ACTIVATION_V0,
    AUTHENTICATED_TRANSPORT_RUNTIME_COMPOSITION_V0,
};

#[cfg(feature = "persistent-authority-candidate")]
mod handoff_runtime_v1;
#[cfg(feature = "persistent-authority-candidate")]
pub use handoff_runtime_v1::*;

#[cfg(feature = "persistent-authority-candidate")]
pub use trnm_poco_node_authority::{
    confirm_retired_epoch_node_checkpoint_v1, ConfirmedRetiredEpochNodeCheckpointV1,
    EpochRetirementCheckpointErrorV1, ExternalNodeCheckpointFieldsV0,
    ExternalNodeCheckpointStoreV0, ExternalNodeCheckpointV0, SqliteExternalNodeCheckpointStoreV0,
};
