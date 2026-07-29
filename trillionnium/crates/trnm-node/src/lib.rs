//! Frozen legacy TRNM harness surfaces.
//!
//! The binaries in this package require the explicit `legacy-harness` feature
//! and are not production candidates. Canonical state transition lives in
//! `trnm-consensus-app -> trnm-runtime`; this library remains temporarily
//! available only for shared types and historical regression fixtures.

pub mod live;
