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
