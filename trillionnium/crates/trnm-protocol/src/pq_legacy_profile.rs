//! The existing PNQ2 contract, shared by its live owner and profile descriptor.
//!
//! These are the original network domains, encodings and limits. Referencing
//! them from the descriptor must not change legacy signed or persisted bytes.
//! A future change needs its own versioned wire/profile and migration decision;
//! this module neither negotiates an algorithm nor enables a production owner.

use crate::pq_frame::TPQ1_SIGNED_BYTES;

pub const PROFILE: &str = "native-pq-network-owner-v2";
pub const RESPONSE_SCHEMA: &str = "native-pq-network-response-v2";
pub const TRANSPORT_MODE: &str = "loopback-signed-plaintext-dev-only";

// All four domains use the original SHA-256 pon_wire::hash framing.
pub const POLICY_DOMAIN: &[u8] = b"native-pq-network-policy-v2";
pub const PEER_CONTEXT_DOMAIN: &[u8] = b"native-pq-network-peer-context-v2";
pub const OPERATION_DOMAIN: &[u8] = b"native-pq-network-operation-v2";
pub const RESPONSE_BYTES_DOMAIN: &[u8] = b"native-pq-network-response-bytes-v2";

pub const REQUEST_MAGIC: &[u8; 4] = b"PNQ2";
pub const RESPONSE_MAGIC: &[u8; 4] = b"PNP2";
// TPQ1 purpose 6 is peer authorization. Request and response are separated
// by their owner-context direction, not new TPQ1 purpose assignments.
pub const PEER_PURPOSE: u8 = 6;
pub const REQUEST_DIRECTION: u8 = 1;
pub const RESPONSE_DIRECTION: u8 = 2;

pub const MAX_WIRE: usize = 2 * 1024 * 1024;
pub const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_RECORDS: u64 = 4096;
pub const MAX_PEERS: usize = 64;
pub const MAX_INGRESS_CONNECTIONS: u64 = 64;
pub const MAX_INGRESS_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_INBOUND_VERIFICATIONS: u64 = 64;
pub const MAX_LIFETIME_SECONDS: u64 = 60;
// Magic, body length and the signed TPQ1 frame are not JSON payload bytes.
pub const MAX_SIGNED_PAYLOAD_BYTES: usize = MAX_WIRE - 8 - TPQ1_SIGNED_BYTES;
