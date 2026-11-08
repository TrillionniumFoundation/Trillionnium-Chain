//! Cold exact-packet reconciliation over the original native storage owner.
//! The source is never opened by SQLite, recovered, or exposed as a mutable Node.
use super::{growth::observer, NativeOwners, Node, StateBackend};
use crate::{ensure, Packet, Result, Settings};
use serde_json::Value;
use std::path::Path;

/// The two existing complete-State backends accepted by the local packet CLI.
/// This selector grants no Growth, external-owner, or PQ-owner compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketObservationBackend {
    LegacyV2,
    AuthenticatedV1,
}

/// Local temporary-copy bound only. The library call has no process CPU cap;
/// the local packet-status CLI supplies its separate Linux process envelope.
pub const DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT: u64 =
    observer::DEFAULT_SNAPSHOT_BYTE_LIMIT;

/// Observe a closed, initialized store without executing native recovery.
///
/// The existing cold-snapshot implementation holds the original owner lock,
/// rejects recovery files and outside-owner markers, and copies at most the
/// caller's byte limit. Only that private copy is opened by SQLite. The normal
/// schema/context, active state, authenticated history, durable replay/outbox,
/// budget-record and ancestry checks still run. An unfinished reorg is refused.
///
/// The observation has the same local-only authority as `Node::exact_packet_observation`.
/// Neither an absent packet nor an inactive retained packet authorizes a retry,
/// activation, compensation, model installation, or Runtime FinalUse.
pub fn observe_existing_packet(
    path: &Path,
    settings: Settings,
    packet: &Packet,
    backend: PacketObservationBackend,
    workers: usize,
    snapshot_byte_limit: u64,
) -> Result<Value> {
    ensure([1, 2, 4, 8].contains(&workers), "WORKERS")?;
    ensure(
        !settings.is_permanent_account_growth_v2(),
        "PACKET_OBSERVATION_BACKEND",
    )?;
    ensure(
        path.join("native.sqlite").is_file(),
        "PACKET_STATUS_EXISTING_STORE_REQUIRED",
    )?;
    ensure(
        !super::owner_marker_present(path)?,
        "OWNER_TASK_POLICY_REQUIRED",
    )?;
    let snapshot = observer::Snapshot::create(path, snapshot_byte_limit)?;
    let mut node = Node::open_selected(
        snapshot.path(),
        settings,
        workers,
        None,
        NativeOwners {
            policy: None,
            mining: None,
            continuous: None,
            pq_network: None,
            pq_witness: None,
        },
        match backend {
            PacketObservationBackend::LegacyV2 => StateBackend::Legacy,
            PacketObservationBackend::AuthenticatedV1 => StateBackend::AuthenticatedV1,
        },
        true,
    )?;
    snapshot.check()?;
    // Keep the source lock and identity checks through the final observation;
    // Node's existing field order closes SQLite before private-file cleanup.
    node.growth_observer_snapshot = Some(snapshot);
    let observation = node.exact_packet_observation(packet)?;
    ensure(
        node.db.total_changes() == 0,
        "PACKET_OBSERVATION_STORAGE_WRITE",
    )?;
    Ok(observation)
}

impl Node {
    /// Keep recovery's original typed journal/candidate checks without starting
    /// its write phase. Outside owners are excluded by this opener's context.
    pub(super) fn check_packet_observation_recovery(&self) -> Result<()> {
        self.namespace()?;
        let journal = self.checked_reorg_intent()?;
        ensure(
            journal.as_ref().is_none_or(|(_, _, _, _, done)| *done != 0),
            "REORG_IN_PROGRESS",
        )?;
        let best = self.recovery_target()?;
        let _ = self.activation_selection(best)?;
        Ok(())
    }
}
