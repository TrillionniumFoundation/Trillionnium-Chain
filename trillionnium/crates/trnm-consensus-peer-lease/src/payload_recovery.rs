//! Candidate-only external payload-replay recovery and Core acknowledgement boundary.
//!
//! The implementation is split into included, item-complete source units so
//! the recovery contract, WAL verifier, acknowledgement ledger and tests remain
//! reviewable without creating public submodule authority.

include!("payload_recovery/part_01_types.rs");
include!("payload_recovery/part_02_owner.rs");
include!("payload_recovery/part_03_wal.rs");
include!("payload_recovery/part_04_io_ack.rs");
include!("payload_recovery/part_05_tests.rs");
