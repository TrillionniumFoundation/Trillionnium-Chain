//! Candidate-only five-plane fresh-readback consistency join.
//!
//! The confirmed carrier cannot be forged or cloned by downstream code:
//!
//! ```compile_fail
//! use trnm_poco_cross_plane_readback_v1::ConfirmedCrossPlaneReadbackV1;
//! let _forged = ConfirmedCrossPlaneReadbackV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_cross_plane_readback_v1::ConfirmedCrossPlaneReadbackV1;
//! fn duplicate(value: ConfirmedCrossPlaneReadbackV1) { let _copy = value.clone(); }
//! ```

#![forbid(unsafe_code)]

mod codec;
mod error;
mod join;
mod types;

pub use error::{
    CrossPlaneReadbackErrorCodeV1, CrossPlaneReadbackErrorV1, CrossPlaneReadbackResultV1,
};
pub use join::{fresh_join_cross_plane_v1, CrossPlaneStoresV1};
pub use types::{
    ConfirmedCrossPlaneReadbackV1, CrossPlaneJoinRequestV1, CrossPlaneReadbackProjectionV1,
    CrossPlaneStoreHeadV1, Hash32V1,
};

#[cfg(test)]
mod tests;
