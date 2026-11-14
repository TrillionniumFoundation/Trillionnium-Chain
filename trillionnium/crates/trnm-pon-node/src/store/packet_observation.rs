//! Cold exact-packet reconciliation over the original native storage owner.
//! The source is never opened by SQLite, recovered, or exposed as a mutable Node.
use super::{growth::observer, NativeOwners, Node, StateBackend};
use crate::resource_owner_v1::{
    ClassV1, OperationBindingV1, ResourceOwnerV1, ResourceRequestV1, ResourceReservationV1,
    ResourcesV1,
};
use crate::{ensure, Packet, Result, Settings};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use trnm_protocol::pon_wire::Hash;

/// The two existing complete-State backends accepted by the local packet CLI.
/// This selector grants no Growth, external-owner, or PQ-owner compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PacketObservationBackend {
    LegacyV2,
    AuthenticatedV1,
}

/// Local temporary-copy bound only. The library call has no process CPU cap;
/// the local packet-status CLI supplies its separate Linux process envelope.
pub const DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT: u64 =
    observer::DEFAULT_SNAPSHOT_BYTE_LIMIT;

/// Explicit local reader contract. These are declared reservation units, not
/// measurements of physical CPU or all SQLite I/O. The supervisor consumes the
/// entire reservation even on a successful read; native qualification remains
/// separate. Neither a caller identity nor a new process obtains new principal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketObservationResourceContractV1 {
    pub profile_id: Hash,
    pub operation_id: Hash,
    pub packet_sha256: Hash,
    /// The closed snapshot's active block commitment, as returned by
    /// Node::active().0. This is not the literal State-root byte string and
    /// grants no remote currentness, external authority or safe-retry right.
    pub parent_state: Hash,
    pub deadline_unix_ms: u64,
    pub backend: PacketObservationBackend,
    pub workers: usize,
    pub snapshot_byte_limit: u64,
    pub cpu_seconds: u64,
    pub wall_seconds: u64,
    pub logical_now: Option<u64>,
}

impl PacketObservationResourceContractV1 {
    /// Bind the actual native context and every declared reader option. Paths
    /// do not stand in for bytes: the packet's complete SHA-256 is verified by
    /// the parent, child and native entry. Only the bootstrap lane is selectable.
    pub fn request(&self, settings: &Settings) -> Result<ResourceRequestV1> {
        ensure(
            self.profile_id != [0; 32]
                && self.operation_id != [0; 32]
                && self.packet_sha256 != [0; 32]
                && self.deadline_unix_ms > 0,
            "PACKET_OBSERVATION_RESOURCE_BINDING",
        )?;
        ensure(
            [1, 2, 4, 8].contains(&self.workers)
                && (1..=30).contains(&self.cpu_seconds)
                && (1..=120).contains(&self.wall_seconds)
                && (1..=DEFAULT_PACKET_OBSERVATION_SNAPSHOT_BYTE_LIMIT)
                    .contains(&self.snapshot_byte_limit),
            "PACKET_OBSERVATION_BUDGET",
        )?;
        ensure(
            !settings.is_permanent_account_growth_v2(),
            "PACKET_OBSERVATION_BACKEND",
        )?;
        let encoded = serde_json::to_vec(&json!({
            "contract":self,
            "network":hex::encode(settings.network()),
            "parameters":hex::encode(settings.parameters()),
            "genesis":hex::encode(settings.genesis()),
        }))?;
        let mut hash = Sha256::new();
        hash.update(b"pon-resource-owned-packet-observation-v1\0");
        hash.update(encoded);
        // The I/O principal accounts the declared private-copy/input/output
        // allowance. It does not assert a measured bound on SQLite rereads.
        let io_bytes = self
            .snapshot_byte_limit
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(3 * 1_048_576 + 2 * 131_072))
            .ok_or("PACKET_OBSERVATION_BUDGET")?;
        Ok(ResourceRequestV1 {
            binding: OperationBindingV1 {
                operation_id: self.operation_id,
                request_digest: hash.finalize().into(),
                parent_state: self.parent_state,
                deadline_unix_ms: self.deadline_unix_ms,
            },
            class: ClassV1::Bootstrap,
            execution: ResourcesV1 {
                cpu_ns: self.cpu_seconds * 1_000_000_000,
                io_bytes,
            },
            cleanup: ResourcesV1 {
                cpu_ns: 25_000_000,
                io_bytes: 4096,
            },
            recovery_of: None,
        })
    }
}

fn unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| "PACKET_OBSERVATION_CLOCK".into())
}

/// One claimed native entry over the original account. Consuming the claim
/// prevents reuse by this adapter. It never settles the reservation: the parent
/// must independently establish worker exit and private-directory cleanup.
/// Direct library callers still need their own process envelope.
pub fn observe_existing_packet_owned(
    path: &Path,
    settings: Settings,
    packet_bytes: &[u8],
    contract: &PacketObservationResourceContractV1,
    reservation: ResourceReservationV1,
) -> Result<Value> {
    reservation.validate_running(path, unix_ms()?)?;
    let request = contract.request(&settings)?;
    ensure(
        reservation.request() == &request && reservation.profile_id()? == contract.profile_id,
        "PACKET_OBSERVATION_RESOURCE_BINDING",
    )?;
    ensure(
        packet_bytes.len() <= 1_048_576
            && <Hash>::from(Sha256::digest(packet_bytes)) == contract.packet_sha256,
        "PACKET_OBSERVATION_PACKET_BINDING",
    )?;
    let packet = Packet::decode(packet_bytes)?;
    let observation = observe_existing_packet_inner(
        path,
        settings,
        &packet,
        contract.backend,
        contract.workers,
        contract.snapshot_byte_limit,
        Some(&reservation),
    )?;
    reservation.validate_running(path, unix_ms()?)?;
    Ok(json!({
        "schema":"pon-resource-owned-packet-observation-v1",
        "resource_profile":hex::encode(contract.profile_id),
        "operation_id":hex::encode(request.binding.operation_id),
        "request_digest":hex::encode(request.binding.request_digest),
        "packet_sha256":hex::encode(contract.packet_sha256),
        "parent_state":hex::encode(contract.parent_state),
        "deadline_unix_ms":contract.deadline_unix_ms,
        "native_source_unchanged":true,
        "source_scope":["native.sqlite","owner.lock"],
        "native_read_only":true,
        "native_observation":observation,
        "physical_resource_bound_qualified":false,
        "honest_service_bound_qualified":false,
    }))
}

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
    ensure(
        !ResourceOwnerV1::is_present(path)?,
        "PACKET_OBSERVATION_RESOURCE_PROFILE_REQUIRED",
    )?;
    observe_existing_packet_inner(
        path,
        settings,
        packet,
        backend,
        workers,
        snapshot_byte_limit,
        None,
    )
}

fn observe_existing_packet_inner(
    path: &Path,
    settings: Settings,
    packet: &Packet,
    backend: PacketObservationBackend,
    workers: usize,
    snapshot_byte_limit: u64,
    reservation: Option<&ResourceReservationV1>,
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
    let snapshot = observer::Snapshot::create_with_preflight(path, snapshot_byte_limit, || {
        if let Some(reservation) = reservation {
            reservation.validate_running(path, unix_ms()?)
        } else {
            // Adoption takes the same original owner lock. Recheck before any
            // copying so an earlier pathname check cannot race adoption.
            ensure(
                !ResourceOwnerV1::is_present(path)?,
                "PACKET_OBSERVATION_RESOURCE_PROFILE_REQUIRED",
            )
        }
    })?;
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
    if let Some(reservation) = reservation {
        reservation.validate_running(path, unix_ms()?)?;
        ensure(
            node.active()?.0 == reservation.request().binding.parent_state,
            "PACKET_OBSERVATION_PARENT_STATE",
        )?;
    }
    let observation = node.exact_packet_observation(packet)?;
    ensure(
        node.db.total_changes() == 0,
        "PACKET_OBSERVATION_STORAGE_WRITE",
    )?;
    node.growth_observer_snapshot
        .as_ref()
        .ok_or("PACKET_OBSERVATION_SNAPSHOT")?
        .check()?;
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
