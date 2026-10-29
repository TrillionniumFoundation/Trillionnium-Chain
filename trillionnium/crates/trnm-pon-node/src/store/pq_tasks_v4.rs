//! New task wrapper; all execution, work, publication and recovery stay with Node.
use super::{Hook, Node};
use crate::pq_tasks_v4::PqPacketV4;
use crate::{ensure, Hash, PoolBatch, PoolLimits, PoolReceipt, PoolStatus, Result, Settings};
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeMap;
use std::path::Path;
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2 as pq, State};
use trnm_protocol::pq_native_accounts_v2::{AccountProfile, UnverifiedEnvelope};
use trnm_protocol::qualified_work_task::pq_lifecycle_v4::{DemandLeaseV4, DemandRevocationV4};
const LOCAL_REVOCATION_LIMIT: usize = 1024;
const LOCAL_REVOCATIONS_DDL: &str = "\nCREATE TABLE local_pq_task_revocations_v4(ordinal INTEGER PRIMARY KEY CHECK(ordinal>=1 AND ordinal<=1024),lease BLOB UNIQUE NOT NULL CHECK(length(lease)=32),demand BLOB NOT NULL CHECK(length(demand)=32),block BLOB NOT NULL REFERENCES blocks(id),generation INTEGER NOT NULL CHECK(generation>0));";
pub(super) fn ddl(base: String) -> String {
    let statements = super::pq_accounts_v2::ddl(base)
        .replace("local_pq_statements_v2", "local_pq_statements_v4")
        .replace(
            "local_pq_removed_statements_v2",
            "local_pq_removed_statements_v4",
        );
    format!("{statements}{LOCAL_REVOCATIONS_DDL}")
}
pub struct PqNodeV4 {
    inner: Node,
}

impl Node {
    /// A detached block is outside the ordinary active-chain cold scan. Bind
    /// every retained event's actual transaction bytes to its checked header;
    /// header/block identity alone cannot authorize the withdrawal history.
    fn pq_tasks_revocation_packet(&self, block: Hash) -> Result<crate::Packet> {
        let packet = self.packet(block)?;
        ensure(
            packet.header.network == self.settings.network()
                && packet.header.parameters == self.settings.parameters()
                && packet.header.transactions
                    == super::sequence_root("transactions", &packet.transactions),
            "PQ4_REVOCATION_PACKET_MEMBERSHIP",
        )?;
        Ok(packet)
    }

    /// Invoked only inside the original activation publication transaction.
    /// Events and local withdrawal evidence commit together or both roll back.
    pub(super) fn pq_tasks_remember_revocations(&self, block: Hash, generation: u64) -> Result<()> {
        if !self.settings.is_native_pq_v4() {
            return Ok(());
        }
        ensure(!self.db.is_autocommit(), "PQ4_REVOCATION_PUBLICATION")?;
        ensure(
            self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE generation=? AND kind=1 AND block=?)",
                params![generation, block.as_slice()],
                |r| r.get::<_, bool>(0),
            )?,
            "PQ4_REVOCATION_EVENT",
        )?;
        for raw in &self.pq_tasks_revocation_packet(block)?.transactions {
            let command = UnverifiedEnvelope::decode_for_profile(raw, AccountProfile::TasksV4)
                .map_err(|_| "PQ4_REVOCATION_PACKET")?;
            if command.kind != 20 {
                continue;
            }
            let revoked =
                DemandRevocationV4::decode(command.payload).map_err(|_| "PQ4_REVOCATION_PACKET")?;
            let existing = self
                .db
                .query_row(
                    "SELECT demand FROM local_pq_task_revocations_v4 WHERE lease=?",
                    [revoked.lease_id.as_slice()],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            if let Some(demand) = existing {
                ensure(demand == revoked.demand_id, "PQ4_REVOCATION_HISTORY")?;
                continue;
            }
            let count: usize = self.db.query_row(
                "SELECT COUNT(*) FROM local_pq_task_revocations_v4",
                [],
                |r| r.get(0),
            )?;
            ensure(count < LOCAL_REVOCATION_LIMIT, "PQ4_REVOCATION_CAPACITY")?;
            ensure(
                self.db.execute(
                    "INSERT INTO local_pq_task_revocations_v4 VALUES(?,?,?,?,?)",
                    params![
                        count + 1,
                        revoked.lease_id.as_slice(),
                        revoked.demand_id.as_slice(),
                        block.as_slice(),
                        generation
                    ],
                )? == 1,
                "PQ4_REVOCATION_HISTORY",
            )?;
        }
        Ok(())
    }

    /// Independent readback of every first activation of an actual revoked
    /// lease. Detached events remain evidence; a deleted/replaced local row is
    /// refused, never silently reconstructed by a task-production request.
    pub(super) fn pq_tasks_check_revocation_history(&self) -> Result<()> {
        if !self.settings.is_native_pq_v4() {
            return Ok(());
        }
        let mut expected = BTreeMap::<Hash, (usize, Hash, Hash, u64)>::new();
        let mut query = self.db.prepare(
            "SELECT generation,block FROM events WHERE kind=1 ORDER BY generation,ordinal",
        )?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let generation: u64 = row.get(0)?;
            let block = super::bytes32(row.get(1)?)?;
            for raw in &self.pq_tasks_revocation_packet(block)?.transactions {
                let command = UnverifiedEnvelope::decode_for_profile(raw, AccountProfile::TasksV4)
                    .map_err(|_| "PQ4_REVOCATION_PACKET")?;
                if command.kind != 20 {
                    continue;
                }
                let revoked = DemandRevocationV4::decode(command.payload)
                    .map_err(|_| "PQ4_REVOCATION_PACKET")?;
                let ordinal = expected.len() + 1;
                expected.entry(revoked.lease_id).or_insert((
                    ordinal,
                    revoked.demand_id,
                    block,
                    generation,
                ));
                ensure(
                    expected.len() <= LOCAL_REVOCATION_LIMIT,
                    "PQ4_REVOCATION_CAPACITY",
                )?;
            }
        }
        let mut actual = BTreeMap::new();
        let mut query = self.db.prepare("SELECT ordinal,lease,demand,block,generation FROM local_pq_task_revocations_v4 ORDER BY ordinal")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let ordinal: usize = row.get(0)?;
            let lease = super::bytes32(row.get(1)?)?;
            let demand = super::bytes32(row.get(2)?)?;
            let block = super::bytes32(row.get(3)?)?;
            let generation: u64 = row.get(4)?;
            ensure(
                ordinal == actual.len() + 1
                    && actual
                        .insert(lease, (ordinal, demand, block, generation))
                        .is_none()
                    && actual.len() <= LOCAL_REVOCATION_LIMIT,
                "PQ4_REVOCATION_HISTORY",
            )?;
        }
        ensure(actual == expected, "PQ4_REVOCATION_HISTORY")
    }

    /// Local mining policy only. It never changes remote block validity or the
    /// branch-relative M06 state root. Once this owner activated a revocation,
    /// a heavier chain cannot silently restore local permission for that lease.
    pub(crate) fn pq_tasks_check_local_permission(&self, lease: &DemandLeaseV4) -> Result<()> {
        ensure(self.settings.is_native_pq_v4(), "PQ4_PROFILE_REQUIRED")?;
        self.pq_tasks_check_revocation_history()?;
        let id = lease.id().map_err(|_| "PQ4_TASK_LEASE")?;
        ensure(
            !self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM local_pq_task_revocations_v4 WHERE lease=?)",
                [id.as_slice()],
                |r| r.get::<_, bool>(0),
            )?,
            "PQ4_LOCAL_TASK_REVOKED",
        )
    }
}
impl PqNodeV4 {
    pub fn open(path: &Path, settings: Settings, workers: usize) -> Result<Self> {
        Self::open_inner(path, settings, workers, None)
    }
    pub fn open_with_fault(
        path: &Path,
        settings: Settings,
        workers: usize,
        hook: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<Self> {
        Self::open_inner(path, settings, workers, Some(hook))
    }
    fn open_inner(
        path: &Path,
        settings: Settings,
        workers: usize,
        hook: Option<&mut Hook<'_>>,
    ) -> Result<Self> {
        let inner = super::pq_accounts_v2::open_pq_node(
            path,
            settings,
            workers,
            hook,
            crate::native_packet::Profile::Pq4,
        )?;
        inner.pq_tasks_check_revocation_history()?;
        Ok(Self { inner })
    }
    pub fn settings(&self) -> &Settings {
        self.inner.settings()
    }
    pub fn active(&self) -> Result<(Hash, u64)> {
        self.inner.active()
    }
    pub fn state_at(&self, tip: Hash) -> Result<State> {
        self.inner.state_at(tip)
    }
    /// Actual retained State supplies this signing digest. It is not a cached
    /// permission: admission/execution re-read the selected parent and keys.
    pub fn authority_digest(&self, tip: Hash, account: Hash) -> Result<[u8; 48]> {
        Ok(pq::authority_digest(
            &self.inner.state_at(tip)?,
            account,
            &self.inner.settings.app,
        )?)
    }
    pub fn packet(&self, id: Hash) -> Result<PqPacketV4> {
        PqPacketV4::from_packet(self.inner.packet(id)?)
    }
    pub fn enable_local_mempool(&mut self, limits: PoolLimits) -> Result<Hash> {
        self.inner.enable_local_mempool(limits)
    }
    pub fn pool_submit(&mut self, raw: Vec<u8>) -> Result<PoolReceipt> {
        self.inner.pool_submit(raw)
    }
    pub fn pool_submit_bundle(&mut self, raws: Vec<Vec<u8>>) -> Result<PoolReceipt> {
        self.inner.pool_submit_bundle(raws)
    }
    pub fn pool_status(&mut self) -> Result<PoolStatus> {
        self.inner.pool_status()
    }
    pub fn pool_status_snapshot(&self) -> Result<PoolStatus> {
        self.inner.pool_status_snapshot()
    }
    pub fn pool_mining_batch(
        &mut self,
        parent: Hash,
        generation: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<PoolBatch> {
        self.inner
            .pool_mining_batch(parent, generation, max_records, max_bytes)
    }
    pub fn pool_validate_batch(&mut self, batch: &PoolBatch) -> Result<usize> {
        self.inner.pool_validate_batch(batch)
    }
    pub fn pool_prune_terminal(&mut self, group: Hash) -> Result<()> {
        self.inner.pool_prune_terminal(group)
    }
    pub fn make(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        attempts: u64,
    ) -> Result<PqPacketV4> {
        let (model, input, _, _) = self.settings().consensus_maintenance_material()?;
        PqPacketV4::from_packet(self.inner.make_with_registered_material(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            &model,
            &input,
        )?)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn make_with_registered_material(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        attempts: u64,
        model: &[u8],
        input: &[u8],
    ) -> Result<PqPacketV4> {
        PqPacketV4::from_packet(self.inner.make_with_registered_material(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            model,
            input,
        )?)
    }
    pub fn local_revocation_count(&self) -> Result<usize> {
        self.inner.pq_tasks_check_revocation_history()?;
        Ok(self.inner.db.query_row(
            "SELECT COUNT(*) FROM local_pq_task_revocations_v4",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn admit(&mut self, packet: &PqPacketV4, observed_now: u64) -> Result<Hash> {
        self.inner.admit(&packet.inner, observed_now)
    }
    pub fn activate(&mut self, target: Hash) -> Result<Hash> {
        self.inner.activate(target)
    }
    pub fn activate_with_fault(
        &mut self,
        target: Hash,
        hook: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<Hash> {
        self.inner.activate_with_fault(target, Some(hook))
    }
}
