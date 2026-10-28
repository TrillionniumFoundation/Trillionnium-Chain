//! Private composition over the original Node writer. No Node escape or listener.
use super::{Hook, NativeOwners, NativeStoreOpening, Node, StateBackend};
use crate::pq_native_v1::PqPacketV1;
use crate::{ensure, Hash, PoolBatch, PoolLimits, PoolReceipt, PoolStatus, Result, Settings};
use std::path::Path;
use trnm_mvcc_fee::pon_executor::State;

pub(super) const OLD_RAW_CHECK: &str = "CHECK(length(raw)>0 AND length(raw)<=2048)";
const NEW_RAW_CHECK: &str = "CHECK(length(raw)>=5617 AND length(raw)<=6129)";
const STATEMENTS_DDL:&str="\nCREATE TABLE local_pq_statements_v1(group_id BLOB NOT NULL,position INTEGER NOT NULL,statement BLOB UNIQUE NOT NULL CHECK(length(statement)=48),PRIMARY KEY(group_id,position),FOREIGN KEY(group_id,position) REFERENCES local_pool_rows(group_id,position) ON DELETE CASCADE);\nCREATE TABLE local_pq_removed_statements_v1(statement BLOB PRIMARY KEY NOT NULL CHECK(length(statement)=48),removal_ordinal INTEGER UNIQUE NOT NULL,FOREIGN KEY(removal_ordinal) REFERENCES local_pool_removals(ordinal));";
pub(super) fn ddl(base: String) -> String {
    format!(
        "{}{}",
        base.replacen(OLD_RAW_CHECK, NEW_RAW_CHECK, 1),
        STATEMENTS_DDL
    )
}

/// A new profile owns the original actual Node. No Deref, `into_node`, legacy
/// network listener, operator mutation, migration or authority-upgrade entry.
pub struct PqNodeV1 {
    inner: Node,
}
impl PqNodeV1 {
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
        ensure(settings.is_native_pq_v1(), "PQ_PROFILE_REQUIRED")?;
        settings.native_pq_context()?;
        ensure(
            StateBackend::AuthenticatedV1
                .ddl()
                .matches(OLD_RAW_CHECK)
                .count()
                == 1,
            "PQ_SCHEMA_LAYOUT",
        )?;
        let inner = Node::open_selected_with_io(
            path,
            settings,
            workers,
            hook,
            NativeOwners {
                policy: None,
                mining: None,
                continuous: None,
            },
            NativeStoreOpening {
                state_backend: StateBackend::AuthenticatedV1,
                growth_observation_only: false,
                native_io: None,
                pq_explicit: Some(crate::native_packet::Profile::Pq1),
            },
        )?;
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
    pub fn packet(&self, id: Hash) -> Result<PqPacketV1> {
        PqPacketV1::from_packet(self.inner.packet(id)?)
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
    ) -> Result<PqPacketV1> {
        let (model, input, _, _) = self.settings().consensus_maintenance_material()?;
        PqPacketV1::from_packet(self.inner.make_with_registered_material(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            &model,
            &input,
        )?)
    }
    pub fn admit(&mut self, packet: &PqPacketV1, observed_now: u64) -> Result<Hash> {
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
