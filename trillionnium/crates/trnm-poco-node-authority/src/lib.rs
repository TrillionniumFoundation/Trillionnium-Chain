#![forbid(unsafe_code)]
//! Wiring-only authority boundary and typed, non-activating fact adapters.

#[path = "facade.rs"]
mod facade;
pub use facade::*;

mod confirmed_application_safety;
pub use confirmed_application_safety::{
    ConfirmedApplicationSafetyAuthorityV0, ConfirmedSafetyContinuationV0,
};
