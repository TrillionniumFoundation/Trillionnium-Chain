//! Production-oriented TRNM devnet surfaces.
//!
//! The historical simulator is exposed only as `trnm-sim` for benchmark
//! replay. New Hepta/Nakama integration uses the canonical live, signed,
//! durable path exposed here and by the `trnm-chain-node` and
//! `trnm-chain-validator` binaries.

pub mod live;
