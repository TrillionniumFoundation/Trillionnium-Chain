//! Complete bounded census of one held native owner's admitted PNP1 view.
//! Every output comes from one rolled-back read snapshot and actual W1/M06
//! replay. This does not attest world coverage, global readiness or wall time.
use super::{canonical, state_merge, Node, StateBackend, Work};
use crate::{consensus, ensure, sequence_root, Error, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_commitment::ExecutionRequest;
use trnm_mvcc_fee::pon_executor::{ExecutionProgress, LEGACY_TASK_PROFILE};
use trnm_protocol::pon_wire::{hash, Hash};

pub const MAX_CENSUS_BLOCKS: usize = 256;
pub const MAX_CENSUS_PACKET_BYTES: u64 = 16 * 1024 * 1024;

/// Local work limits, not consensus parameters. Exhaustion returns no census.
#[derive(Clone, Copy, Debug)]
pub struct OwnerCensusLimits {
    pub maximum_blocks: usize,
    pub maximum_packet_bytes: u64,
}
impl Default for OwnerCensusLimits {
    fn default() -> Self {
        Self {
            maximum_blocks: MAX_CENSUS_BLOCKS,
            maximum_packet_bytes: MAX_CENSUS_PACKET_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OwnerCensusProgress {
    BeforeSnapshot,
    Enumerate { index: usize },
    BeforePacket { index: usize },
    Work(pon_work::VerificationProgress),
    State,
    Execution(ExecutionProgress),
    BeforeOutput,
    SnapshotReleased,
}

static NEXT_OBSERVER: AtomicU64 = AtomicU64::new(1);

pub(super) struct OwnerObserver {
    instance: u64,
    epoch: Instant,
    attempts: u64,
}
impl OwnerObserver {
    fn new() -> Result<Self> {
        let instance = NEXT_OBSERVER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::from("OWNER_CENSUS_ID_EXHAUSTED"))?;
        Ok(Self {
            instance,
            epoch: Instant::now(),
            attempts: 0,
        })
    }
    fn elapsed(&self) -> Result<u64> {
        u64::try_from(self.epoch.elapsed().as_nanos())
            .map_err(|_| "OWNER_CENSUS_CLOCK_RANGE".into())
    }
}

/// Private fields and no Deserialize: caller-supplied scores are not observations.
#[derive(Clone, Debug, Serialize)]
pub struct OwnerCensusBlock {
    id: String,
    parent: Option<String>,
    height: u64,
    chainwork_hex: String,
    required_work_hex: String,
    target: Option<String>,
    timestamp: Option<u64>,
    packet_sha256: Option<String>,
    proof_sha256: Option<String>,
    packet_bytes: usize,
    ancestry_time_eligible: bool,
    active_chain_member: bool,
    full_native_work_replayed: bool,
    full_native_application_replayed: bool,
    retained_state_and_deltas_equal: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct OwnerCensus {
    schema: &'static str,
    packet_profile: &'static str,
    state_backend: &'static str,
    task_profile: String,
    network: String,
    parameters: String,
    genesis: String,
    owner_process_id: u32,
    owner_observation_instance: u64,
    owner_attempt: u64,
    owner_identity_scope: &'static str,
    directory_device: u64,
    directory_inode: u64,
    database_device: u64,
    database_inode: u64,
    lock_device: u64,
    lock_inode: u64,
    started_ns: u64,
    ended_ns: u64,
    clock_scope: &'static str,
    observed_now: u64,
    observed_now_source: &'static str,
    future_skew_seconds: u64,
    confirmation_depth: u64,
    confirmation_work_multiplier: u64,
    active_tip: String,
    active_generation: u64,
    state_slot: u64,
    active_score_hex: String,
    active_time_eligible: bool,
    eligible_max_score_hex: String,
    eligible_max_ids: Vec<String>,
    raw_selection_deficit_hex: Option<String>,
    rows: Vec<OwnerCensusBlock>,
    total_packet_bytes: u64,
    local_view_commitment: String,
    complete_for_all_admitted_rows_in_snapshot: bool,
    local_candidate_relation_rechecked: bool,
    exact_source_schema_rechecked: bool,
    snapshot_released_without_commit: bool,
    owner_caches_may_refresh: bool,
    unadmitted_local_packets_covered: bool,
    remote_private_branches_covered: bool,
    global_ready_attested: bool,
    world_coverage_attested: bool,
    physical_clock_authenticated: bool,
    exported_artifact_authenticated: bool,
    probabilistic_environment_bound: bool,
    six_successor_risk_qualified: bool,
    execution_authority: bool,
    excluded_scope: [&'static str; 7],
}

fn digest(bytes: &[u8]) -> String {
    crate::operator_task_policy::digest_bytes(bytes)
}

impl Node {
    pub fn native_owner_census(
        &self,
        observed_now: u64,
        limits: OwnerCensusLimits,
    ) -> Result<OwnerCensus> {
        self.native_owner_census_with_progress(observed_now, limits, &|_| Ok(()))
    }

    /// Explicit local diagnostic, never added to an unmetered public read lane.
    /// The original owner supplies deadline/CPU cancellation via progress.
    /// Unsupported profiles, partial budgets and failures return no census.
    pub fn native_owner_census_with_progress(
        &self,
        observed_now: u64,
        limits: OwnerCensusLimits,
        progress: &(impl Fn(OwnerCensusProgress) -> Result<()> + Sync),
    ) -> Result<OwnerCensus> {
        ensure(
            (1..=MAX_CENSUS_BLOCKS).contains(&limits.maximum_blocks)
                && (1..=MAX_CENSUS_PACKET_BYTES).contains(&limits.maximum_packet_bytes),
            "OWNER_CENSUS_LIMITS",
        )?;
        ensure(
            matches!(
                self.state_backend,
                StateBackend::Legacy | StateBackend::AuthenticatedV1
            ) && self.settings.task_profile() == LEGACY_TASK_PROFILE
                && self.owner_policy.is_none()
                && self.mining_owner.is_none()
                && self.continuous_owner.is_none(),
            "OWNER_CENSUS_PROFILE_UNSUPPORTED",
        )?;
        let (instance, attempt, started_ns) = {
            let mut cell = self.native_owner_observer.borrow_mut();
            if cell.is_none() {
                *cell = Some(OwnerObserver::new()?);
            }
            let observer = cell.as_mut().ok_or("OWNER_CENSUS_ID_EXHAUSTED")?;
            observer.attempts = observer
                .attempts
                .checked_add(1)
                .ok_or("OWNER_CENSUS_ID_EXHAUSTED")?;
            (observer.instance, observer.attempts, observer.elapsed()?)
        };
        progress(OwnerCensusProgress::BeforeSnapshot)?;
        self.ready()?;
        self.storage_context()?;
        let before = self.admission_state_epoch()?;
        let tx = self.db.unchecked_transaction()?;
        // Bind the SQL relation itself, not only its metadata hash or a schema
        // counter. Otherwise an earlier filtering VIEW could hide a real fork.
        // This ephemeral in-memory database is the source-DDL oracle used by
        // native cold open; it never opens a second connection to this owner.
        let expected_db = rusqlite::Connection::open_in_memory()?;
        expected_db.execute_batch(&self.state_backend.ddl())?;
        let expected_schema = super::schema(&expected_db)?;
        ensure(
            super::schema(&self.db)? == expected_schema,
            "OWNER_CENSUS_SCHEMA",
        )
        .map_err(Error::local_integrity)?;
        let schema_version: u64 = self
            .db
            .query_row("PRAGMA schema_version", [], |r| r.get(0))?;
        self.storage_context()?;
        let (tip, generation) = self.active()?;
        let slot = self.slot()?;
        let result = (|| -> Result<_> {
            let mut ids = Vec::new();
            {
                // LIMIT+1 is an exhaustion detector, not a successful prefix.
                let mut statement = self
                    .db
                    .prepare("SELECT id,length(packet) FROM blocks ORDER BY height,id LIMIT ?")?;
                let mut query = statement.query([limits.maximum_blocks + 1])?;
                let mut bytes = 0_u64;
                while let Some(row) = query.next()? {
                    progress(OwnerCensusProgress::Enumerate { index: ids.len() })?;
                    ensure(
                        ids.len() < limits.maximum_blocks,
                        "OWNER_CENSUS_BLOCK_BUDGET",
                    )?;
                    let id = super::bytes32(super::fixed_blob::<32>(row, 0)?)?;
                    let length: Option<u64> = row.get(1)?;
                    bytes = bytes
                        .checked_add(length.unwrap_or(0))
                        .ok_or("OWNER_CENSUS_BYTE_BUDGET")?;
                    ensure(
                        bytes <= limits.maximum_packet_bytes,
                        "OWNER_CENSUS_BYTE_BUDGET",
                    )?;
                    ids.push((id, length));
                }
            }
            let genesis = self.settings.genesis();
            ensure(
                ids.first().map(|r| r.0) == Some(genesis),
                "OWNER_CENSUS_GENESIS",
            )
            .map_err(Error::local_integrity)?;
            let genesis_row = self.record(genesis)?;
            let genesis_state =
                self.state_at_with_progress(genesis, &mut || progress(OwnerCensusProgress::State))?;
            ensure(
                genesis_row.parent.is_none()
                    && genesis_row.height == 0
                    && genesis_row.work == Work::default()
                    && ids[0].1.is_none()
                    && genesis_state == self.settings.initial
                    && self.settings.state_root(&genesis_state)? == genesis_row.root,
                "OWNER_CENSUS_GENESIS",
            )
            .map_err(Error::local_integrity)?;
            // This is a complete actual-KV/root read, not only an active pointer.
            let (checked_tip, checked_generation, _) =
                self.read_active_with_progress(&mut || progress(OwnerCensusProgress::State))?;
            ensure(
                (checked_tip, checked_generation) == (tip, generation),
                "STALE_VIEW",
            )?;
            let skew = self.settings.limit("future_skew_seconds")?;
            let bound = observed_now as u128 + skew as u128;
            let mut by_id: BTreeMap<Hash, (Option<Hash>, u64, Work, bool)> = BTreeMap::new();
            by_id.insert(genesis, (None, 0, Work::default(), true));
            let mut rows = vec![OwnerCensusBlock {
                id: hex::encode(genesis),
                parent: None,
                height: 0,
                chainwork_hex: hex::encode(Work::default().bytes()),
                required_work_hex: hex::encode(Work::default().bytes()),
                target: None,
                timestamp: None,
                packet_sha256: None,
                proof_sha256: None,
                packet_bytes: 0,
                ancestry_time_eligible: true,
                active_chain_member: false,
                full_native_work_replayed: false,
                full_native_application_replayed: false,
                retained_state_and_deltas_equal: true,
            }];
            let mut total_packet_bytes = 0_u64;
            for (index, &(id, length)) in ids.iter().enumerate().skip(1) {
                progress(OwnerCensusProgress::BeforePacket { index })?;
                let packet = self.packet(id)?;
                let bytes = packet.encode_for_settings(&self.settings)?;
                ensure(length == Some(bytes.len() as u64), "STORAGE_PACKET")
                    .map_err(Error::local_integrity)?;
                let h = &packet.header;
                let parent = by_id
                    .get(&h.parent)
                    .ok_or_else(|| Error::from("OWNER_CENSUS_PARENT").local_integrity())?;
                let parent_work = parent.2;
                let parent_eligible = parent.3;
                let record = self.record(id)?;
                let weight = consensus::required_work(h.target)?;
                ensure(
                    h.network == self.settings.network()
                        && h.parameters == self.settings.parameters()
                        && parent.1.checked_add(1) == Some(h.height)
                        && record.work == parent_work.checked_add(weight)?,
                    "OWNER_CENSUS_HEADER",
                )
                .map_err(Error::local_integrity)?;
                let recent = self
                    .recent_with_progress(h.parent, &mut || progress(OwnerCensusProgress::State))?;
                ensure(
                    h.target
                        == self.target_from_recent(
                            consensus::BranchTargetHeight::after(parent.1)?,
                            &recent,
                        )?,
                    "TARGET",
                )
                .map_err(Error::local_integrity)?;
                // MTP is a validity predicate; current future eligibility is
                // separately accumulated through every ancestor below.
                consensus::check_time(
                    h.timestamp,
                    &recent.iter().take(11).map(|r| r.0).collect::<Vec<_>>(),
                    u64::MAX,
                    skew,
                )
                .map_err(Error::local_integrity)?;
                ensure(
                    h.transactions == sequence_root("transactions", &packet.transactions),
                    "ROOT",
                )
                .map_err(Error::local_integrity)?;
                pon_work::verify_with_progress(
                    h.challenge(),
                    h.work_task,
                    h.target,
                    &packet.proof,
                    &mut |p| progress(OwnerCensusProgress::Work(p)),
                )
                .map_err(|error| match error {
                    pon_work::VerificationError::Relation(error) => {
                        Error::from(format!("WORK:{error:?}")).local_integrity()
                    }
                    pon_work::VerificationError::Cancelled(error) => error,
                })?;
                let parent_state = self
                    .check_admission_parent(&packet, &mut || progress(OwnerCensusProgress::State))?
                    .state;
                let executed = self.execute_derived_with_progress(
                    &parent_state,
                    ExecutionRequest {
                        timestamp: Some(h.timestamp),
                        transactions: &packet.transactions,
                        height: h.height,
                        miner: h.miner,
                        parent_id: h.parent,
                        workers: self.workers,
                    },
                    &|p| progress(OwnerCensusProgress::Execution(p)),
                )?;
                let output = executed.output;
                let actual =
                    self.state_at_with_progress(id, &mut || progress(OwnerCensusProgress::State))?;
                ensure(
                    output.root == h.state
                        && sequence_root("receipts", &output.receipts) == h.receipts
                        && actual == output.state,
                    "OWNER_CENSUS_TRANSITION",
                )
                .map_err(Error::local_integrity)?;
                let mut expected_deltas = Vec::new();
                for entry in state_merge::entries(&parent_state, &output.state) {
                    progress(OwnerCensusProgress::State)?;
                    if entry.before != entry.after {
                        expected_deltas.push((
                            entry.key.clone(),
                            entry.before.map(canonical).transpose()?,
                            entry.after.map(canonical).transpose()?,
                        ));
                    }
                }
                ensure(
                    self.delta_rows_with_progress(id, &mut || {
                        progress(OwnerCensusProgress::State)
                    })? == expected_deltas,
                    "OWNER_CENSUS_DELTAS",
                )
                .map_err(Error::local_integrity)?;
                let eligible = parent_eligible && h.timestamp as u128 <= bound;
                by_id.insert(id, (Some(h.parent), h.height, record.work, eligible));
                total_packet_bytes += bytes.len() as u64;
                rows.push(OwnerCensusBlock {
                    id: hex::encode(id),
                    parent: Some(hex::encode(h.parent)),
                    height: h.height,
                    chainwork_hex: hex::encode(record.work.bytes()),
                    required_work_hex: hex::encode(weight.bytes()),
                    target: Some(hex::encode(h.target)),
                    timestamp: Some(h.timestamp),
                    packet_sha256: Some(digest(&bytes)),
                    proof_sha256: Some(digest(&packet.proof)),
                    packet_bytes: bytes.len(),
                    ancestry_time_eligible: eligible,
                    active_chain_member: false,
                    full_native_work_replayed: true,
                    full_native_application_replayed: true,
                    retained_state_and_deltas_equal: true,
                });
            }
            let mut active_path = BTreeSet::new();
            let mut cursor = Some(tip);
            while let Some(id) = cursor {
                ensure(active_path.insert(hex::encode(id)), "OWNER_CENSUS_PARENT")
                    .map_err(Error::local_integrity)?;
                cursor = by_id.get(&id).ok_or("OWNER_CENSUS_ACTIVE_MISSING")?.0;
            }
            for row in &mut rows {
                row.active_chain_member = active_path.contains(&row.id);
            }
            let active = by_id.get(&tip).ok_or("OWNER_CENSUS_ACTIVE_MISSING")?;
            let maximum = by_id
                .values()
                .filter(|r| r.3)
                .map(|r| r.2)
                .max()
                .ok_or("OWNER_CENSUS_GENESIS")?;
            let maximum_ids = by_id
                .iter()
                .filter(|(_, r)| r.3 && r.2 == maximum)
                .map(|(id, _)| hex::encode(id))
                .collect::<Vec<_>>();
            let deficit = active
                .3
                .then(|| maximum.checked_sub(active.2))
                .transpose()?
                .map(|w| hex::encode(w.bytes()));
            progress(OwnerCensusProgress::BeforeOutput)?;
            self.ready()?;
            self.storage_context()?;
            ensure(
                self.active()? == (tip, generation) && self.slot()? == slot,
                "STALE_VIEW",
            )?;
            ensure(
                self.db.total_changes() == before.total_changes,
                "OWNER_CENSUS_WRITE",
            )
            .map_err(Error::local_integrity)?;
            ensure(
                self.db
                    .query_row("PRAGMA schema_version", [], |r| r.get::<_, u64>(0))?
                    == schema_version,
                "OWNER_CENSUS_SCHEMA_CHANGED",
            )
            .map_err(Error::local_integrity)?;
            ensure(
                super::schema(&self.db)? == expected_schema,
                "OWNER_CENSUS_SCHEMA",
            )
            .map_err(Error::local_integrity)?;
            Ok((
                rows,
                total_packet_bytes,
                active.2,
                active.3,
                maximum,
                maximum_ids,
                deficit,
                skew,
            ))
        })();
        // Always roll back the read transaction, including callback writes or
        // DDL. Preserve the original cancellation/failure identity if one exists.
        let released = tx.rollback();
        let (
            rows,
            total_packet_bytes,
            active_score,
            active_eligible,
            maximum,
            maximum_ids,
            deficit,
            skew,
        ) = match result {
            Ok(value) => {
                released?;
                value
            }
            Err(error) => {
                self.invalidate_commitment();
                let _ = released;
                return Err(error);
            }
        };
        progress(OwnerCensusProgress::SnapshotReleased)?;
        self.ready()?;
        self.storage_context()?;
        ensure(
            self.admission_state_epoch()? == before,
            "OWNER_CENSUS_EPOCH_CHANGED",
        )?;
        ensure(
            self.active()? == (tip, generation) && self.slot()? == slot,
            "STALE_VIEW",
        )?;
        let lock = self.owner.metadata()?;
        let ended_ns = self
            .native_owner_observer
            .borrow()
            .as_ref()
            .ok_or("OWNER_CENSUS_ID_EXHAUSTED")?
            .elapsed()?;
        let view_bytes = serde_json::to_vec(&(
            self.settings.network(),
            self.settings.parameters(),
            self.settings.genesis(),
            tip,
            generation,
            slot,
            observed_now,
            &rows,
        ))?;
        Ok(OwnerCensus {
            schema: "pon-native-owner-census-v1", packet_profile: "PNP1",
            state_backend: if self.state_backend == StateBackend::Legacy { "legacy-v2" } else { "authenticated-v1" },
            task_profile: self.settings.task_profile().to_owned(), network: hex::encode(self.settings.network()),
            parameters: hex::encode(self.settings.parameters()), genesis: hex::encode(self.settings.genesis()),
            owner_process_id: std::process::id(), owner_observation_instance: instance, owner_attempt: attempt,
            owner_identity_scope: "one Node incarnation in this process invocation; not a globally authenticated principal",
            directory_device: self.directory_id.0, directory_inode: self.directory_id.1,
            database_device: self.database_id.0, database_inode: self.database_id.1,
            lock_device: lock.dev(), lock_inode: lock.ino(), started_ns, ended_ns,
            clock_scope: "process-local Instant since first owner census; not globally synchronized",
            observed_now, observed_now_source: "caller-supplied validation clock; not the Instant lifecycle clock",
            future_skew_seconds: skew,
            confirmation_depth: self.settings.limit("confirmation_depth")?,
            confirmation_work_multiplier: self.settings.limit("confirmation_work_multiplier")?,
            active_tip: hex::encode(tip), active_generation: generation, state_slot: slot,
            active_score_hex: hex::encode(active_score.bytes()), active_time_eligible: active_eligible,
            eligible_max_score_hex: hex::encode(maximum.bytes()), eligible_max_ids: maximum_ids,
            raw_selection_deficit_hex: deficit, rows, total_packet_bytes,
            local_view_commitment: hex::encode(hash(b"pon-native-local-owner-view-v1", &[&view_bytes])),
            complete_for_all_admitted_rows_in_snapshot: true, local_candidate_relation_rechecked: true,
            exact_source_schema_rechecked: true,
            snapshot_released_without_commit: true, owner_caches_may_refresh: true,
            unadmitted_local_packets_covered: false, remote_private_branches_covered: false,
            global_ready_attested: false, world_coverage_attested: false, physical_clock_authenticated: false,
            exported_artifact_authenticated: false, probabilistic_environment_bound: false,
            six_successor_risk_qualified: false, execution_authority: false,
            excluded_scope: ["unadmitted local bytes and pending jobs", "remote and private branches",
                "first global readiness and parent-binding times", "initial residual preprocessing state",
                "network delivery or retention envelopes", "PNP2/PQ/other task profiles and policy owners",
                "trusted identity, clock and lifecycle-export attestation"],
        })
    }
}
