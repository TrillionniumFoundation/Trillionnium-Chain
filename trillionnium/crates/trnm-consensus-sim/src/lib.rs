#![forbid(unsafe_code)]
//! Deterministic, in-memory fault simulator for the epoch-0 PoCO-BFT core.
//!
//! This crate intentionally owns no sockets, database, wall clock, or signing
//! service. A seeded event queue drives the core's effect boundary and records
//! a replay-stable trace.

mod simulator;
mod trace;

pub use simulator::{
    MessageKind, NodeId, NodeSnapshot, SimConfig, SimError, Simulator, GENESIS_BLOCK_ID,
};
pub use trace::{Trace, TraceDigest, TraceEntry};
