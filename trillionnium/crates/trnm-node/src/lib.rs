//! Native Trillionnium Chain consensus implementation.
//!
//! `trnm-chain-node` and `trnm-chain-validator` are the canonical consensus
//! binaries. This crate owns proposal, voting, quorum, round-change,
//! anti-equivocation, recovery, and finality surfaces for the self-developed
//! chain. No external consensus implementation is supported.

pub mod live;
