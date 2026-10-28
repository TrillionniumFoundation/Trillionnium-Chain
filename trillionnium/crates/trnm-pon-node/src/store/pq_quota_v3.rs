//! New quota wrapper; all mutation/recovery stays with the original Node.
use super::{Hook, Node};
use crate::pq_quota_v3::PqPacketV3;
use crate::{Hash, PoolBatch, PoolLimits, PoolReceipt, PoolStatus, Result, Settings};
use std::path::Path;
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2 as pq, State};
pub(super) fn ddl(base: String) -> String {
    super::pq_accounts_v2::ddl(base)
        .replace("local_pq_statements_v2", "local_pq_statements_v3")
        .replace(
            "local_pq_removed_statements_v2",
            "local_pq_removed_statements_v3",
        )
}
pub struct PqNodeV3 {
    inner: Node,
}
impl PqNodeV3 {
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
        Ok(Self {
            inner: super::pq_accounts_v2::open_pq_node(
                path,
                settings,
                workers,
                hook,
                crate::native_packet::Profile::Pq3,
            )?,
        })
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
    /// Exact immutable claim statement only; real prior/new proofs and State
    /// nonce/permission checks remain mandatory in the original execution path.
    pub fn migration_claim_payload(&self, account: Hash) -> Result<Vec<u8>> {
        Ok(pq::migration_claim_payload(
            &self.inner.settings.app,
            account,
        )?)
    }
    pub fn packet(&self, id: Hash) -> Result<PqPacketV3> {
        PqPacketV3::from_packet(self.inner.packet(id)?)
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
    ) -> Result<PqPacketV3> {
        let (model, input, _, _) = self.settings().consensus_maintenance_material()?;
        PqPacketV3::from_packet(self.inner.make_with_registered_material(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            &model,
            &input,
        )?)
    }
    pub fn admit(&mut self, packet: &PqPacketV3, observed_now: u64) -> Result<Hash> {
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
