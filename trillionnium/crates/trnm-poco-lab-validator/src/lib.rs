#![forbid(unsafe_code)]
//! Real-process, real-network PoCO-BFT laboratory validator for the G3 LAN campaign.
//!
//! This crate is intentionally distinct from both the in-memory simulator and
//! the fail-closed production-node binary. Its candidate boundary verifies a
//! closed deployment bundle, commissions the authenticated native h1->h2->h3
//! takeover into real Core/Safety/App/checkpoint/signer authority, establishes
//! the exact seven-validator direct persistent mesh, and drives bounded
//! Proposal/Vote/QC/TimeoutVote/TC progress under a generation-aware
//! pacemaker. The 31/100 sparse layouts and independently authenticated relay
//! statements remain planning-only until their durable capacity profiles are
//! separately verified. A durable signed
//! process-event chain and terminal consensus, metrics, and final-state
//! reports remain causally bound to the coordinator digest. The implementation
//! is connected as a candidate, but no successful multihost LAN consensus
//! campaign has yet established runtime truth. Restart/catch-up, the fault and
//! performance matrices, and geo-WAN campaign also remain open. Consequently
//! all observed runtime, G3, geo-WAN, and production-activation truth bits stay
//! false.

pub mod bootstrap_material;
pub mod collector;
pub mod config;
pub mod consensus_mesh;
pub mod consensus_report;
pub mod consensus_runtime;
pub mod continuous_runtime;
pub mod crypto;
pub mod degraded_window;
pub mod epoch_handoff_evidence;
pub mod fleet_barrier;
pub mod fleet_barrier_evidence;
pub mod frame;
pub mod key_roles;
pub mod loop_driver;
pub mod network;
/// Active D0 peer-admission helper.  This is bounded handshake/lease
/// authority only; it does not drive consensus transport or a validator loop.
pub mod p2p_admission;
pub mod pacemaker;
pub mod process_event;
pub mod relay;
pub mod restart_catchup;
pub mod restart_cut;
pub mod restart_protocol;
// Phase-bound direct-seven park aggregation is private and inert until one
// composite durable owner is consumed by the journal-first runtime tranche.
#[allow(dead_code)]
mod restart_park_protocol;
// Phase-bound direct-seven ParkedAck aggregation consumes the local durable
// Cut/Park journal witness and retains the exact three-artifact owner. It is
// still private until the process-1 runtime and process-2 gate consume it.
#[allow(dead_code)]
mod restart_parked_ack_protocol;
// Typed Ready/Start collection remains private and authority-free until the
// process-2 journal transition consumes its durable artifacts.
#[allow(dead_code)]
mod recovery_barrier;
// Typed Ready/Start artifacts are durable but remain private, inert barrier
// vocabulary. No runtime or activation path consumes these owners yet.
#[allow(dead_code)]
mod recovery_barrier_store;
// Canonical zero-delta cut persistence is an independent, private, inert
// artifact boundary. It exposes no scheduler, Ready/Start, or activation API.
#[allow(dead_code)]
mod recovery_zero_delta_store;
// Canonical direct-seven park-certificate persistence is a private, inert
// content-addressed boundary. It grants no signer, barrier, or process-control
// authority and does not replace the separately retained RestartCut artifact.
#[allow(dead_code)]
mod restart_park_store;
// Canonical direct-seven parked-ack persistence is a separate, private,
// content-addressed boundary. It grants no signer, recovery, or activation
// authority and cannot replace the retained Cut/Park certificate pair.
#[allow(dead_code)]
mod restart_parked_ack_store;
// The durable artifact boundary is wired by the operational RestartCut
// tranche; keeping it private prevents premature process-control use.
#[allow(dead_code)]
mod restart_cut_store;
pub mod runtime;
pub mod runtime_control;
pub mod runtime_evidence;
pub mod signed_replay_archive;
pub mod startup_rejection;
pub mod transport;
pub mod wire;
pub mod workload_corpus;

/// This binary must never be interpreted as a production activation surface.
pub const PRODUCTION_CANDIDATE: bool = false;
pub const PRODUCTION_CONSENSUS_ACTIVATION: bool = false;
pub const GEO_WAN_EVIDENCE: bool = false;
pub const SIMULATOR_DEPENDENCY: bool = false;
pub const REAL_CORE_CONFIG: bool = true;
/// Statically reachable inside the bounded laboratory entry; not evidence that
/// a validator process has completed on another host.
pub const REAL_CORE_RUNTIME: bool = true;
pub const SAFETY_STORE_RUNTIME: bool = true;
pub const SIGNER_JOURNAL_RUNTIME: bool = true;
pub const NATIVE_EXECUTION_RUNTIME: bool = true;
/// A continuation-only, one-Proposal authority path exists. It is not a
/// continuous validator loop and does not sign or broadcast.
pub const ONE_SHOT_AUTHORITY_RUNTIME: bool = true;
pub const STRICT_CONSENSUS_INGRESS: bool = true;
pub const WEIGHTED_VOTE_QC_COLLECTOR: bool = true;
pub const TIMEOUT_TC_COLLECTOR: bool = true;
pub const BOUNDED_CONSENSUS_INGRESS_LOOP_SCAFFOLD: bool = true;
pub const SPARSE_TOPOLOGY_CONSENSUS_RELAY_CANDIDATE: bool = true;
pub const SPARSE_TOPOLOGY_CONSENSUS_RELAY_ORIGIN_SIGNATURE: bool = true;
pub const SPARSE_TOPOLOGY_CONSENSUS_RELAY_EXACT_REPLAY_COLLECTOR_MUTATION: bool = false;
pub const SPARSE_TOPOLOGY_CONSENSUS_RELAY_PROPOSAL_WITNESS_VERIFIED_AT_RELAY: bool = false;
pub const SPARSE_TOPOLOGY_CONSENSUS_RELAY_AMPLIFICATION_BOUND_PROVEN: bool = false;
pub const SPARSE_TOPOLOGY_CONSENSUS_RELAY_RUNTIME_WIRED: bool = true;
pub const SIGNED_PROCESS_EVENT_JOURNAL: bool = true;
pub const COORDINATOR_ANCHOR_CAUSAL_BINDING: bool = true;
pub const EXTERNAL_WALL_CLOCK_TEMPORAL_PROVENANCE: bool = false;
pub const CONTINUOUS_CONSENSUS_RUNTIME: bool = true;
pub const AUTHENTICATED_FRESH_SESSION_RUNTIME: bool = true;
/// The live handshake and authenticated frame envelope use only the committed
/// P2P identity role, never the consensus public key.
pub const P2P_IDENTITY_KEY_ROLE_RUNTIME_WIRED: bool = true;
/// Operator/recovery statements still use explicitly named consensus signing
/// in this slice; migrating them requires a separately versioned protocol.
pub const OPERATOR_RECOVERY_KEY_ROLE_RUNTIME_WIRED: bool = false;
/// No production remote consensus signer is activated by laboratory key-role
/// material or transport separation.
pub const REMOTE_CONSENSUS_SIGNER_ACTIVATION: bool = false;
/// `ContinuousValidatorAuthorityV0` exposes an explicit producer-injection
/// composition seam for Vote/TimeoutVote owners. The normal runtime does not
/// construct one from this seam yet.
pub const REMOTE_CONSENSUS_SIGNER_INJECTION_API: bool = true;
/// The deployed bounded loop still uses its fixture producer unless a caller
/// explicitly composes the authority through the injection API.
pub const REMOTE_CONSENSUS_SIGNER_RUNTIME_WIRED: bool = false;
/// The continuous authority remains parameterized over the laboratory local
/// watermark; external whole-node watermark injection is a separate gate.
pub const EXTERNAL_MONOTONIC_WATERMARK_RUNTIME_INJECTED: bool = false;
/// Exact directed peer sessions are owned by the bounded continuous authority.
/// This is an implementation fact, not multihost observation evidence.
pub const PERSISTENT_AUTHENTICATED_PEER_MESH_CANDIDATE: bool = true;
pub const PERSISTENT_AUTHENTICATED_PEER_MESH_RUNTIME_WIRED: bool = true;
/// Every directed mesh worker now requires an injected external lease seam;
/// the default runtime deliberately supplies a rejecting authority.
pub const EXTERNAL_P2P_FENCING_TRAIT: bool = true;
pub const EXTERNAL_P2P_FENCING_AUTHORITY: bool = false;
pub const EXTERNAL_P2P_FENCING_HARD_GATE: bool = true;
pub const GENERATION_AWARE_PACEMAKER_CANDIDATE: bool = true;
pub const GENERATION_AWARE_PACEMAKER_RUNTIME_WIRED: bool = true;
pub const PRIVATE_RUNTIME_CONTROL_CANDIDATE: bool = true;
/// The private control socket is owned and polled by the first-process
/// continuous runtime. This does not claim restart activation or a completed
/// fault campaign.
pub const PRIVATE_RUNTIME_CONTROL_RUNTIME_WIRED: bool = true;
pub const AUTHENTICATED_FRAME_RESTART_REPLAY_AUTHORITY: bool = false;
/// Exact deployed anchored-ordinary Ready cuts can be reopened and joined into
/// an inert, replay-fenced owner. Revision>5 exposes comparison-only signed
/// ancestry replay coordinates; Core/effects remain private and no runtime
/// activation or network catch-up authority is released.
pub const DEPLOYED_ORDINARY_CUT_RECOVERY_OWNER: bool = true;
pub const DEPLOYED_ORDINARY_RECOVERY_ACTIVATION: bool = false;
pub const DEPLOYED_ORDINARY_NETWORK_CATCH_UP: bool = false;
pub const COHERENT_WHOLE_AUTHORITY_ROOT_ROLLBACK_PROTECTION: bool = false;
pub const VALIDATOR_RUNTIME_STARTED: bool = false;
