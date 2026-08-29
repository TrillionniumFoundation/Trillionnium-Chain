#![forbid(unsafe_code)]
//! Candidate-only G1-R4 cross-store coordination reference.
//!
//! This crate owns no key, signature producer, persistent store, network
//! service, production constructor, activation flag, or release authority. It
//! models the final authority join required before a signer adapter may accept
//! a request:
//!
//! 1. exact Application finalization readback;
//! 2. exact Safety tag-3 readback;
//! 3. exact prepared SignerJournal intent;
//! 4. exact whole-node checkpoint CAS target;
//! 5. exact external monotonic watermark CAS target;
//! 6. fresh readback of both CAS targets.
//!
//! The returned [`SignaturePermitV1`] is intentionally opaque and neither
//! `Clone` nor `Copy`. A production composition must replace the freely
//! constructible reference readbacks with non-forgeable carriers from their
//! owning stores before this shape can become signing authority.

use core::fmt;

include!("types_v1.rs");
include!("coordinator_v1.rs");

#[cfg(test)]
mod tests {
    use super::*;
    include!("tests_v1.rs");
}
