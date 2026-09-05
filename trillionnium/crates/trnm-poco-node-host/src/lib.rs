#![forbid(unsafe_code)]
//! Wiring-only PoCO node host composition.

#[path = "facade.rs"]
mod facade;
pub use facade::*;

#[cfg(feature = "persistent-authority-candidate")]
mod confirmed_application_safety;
