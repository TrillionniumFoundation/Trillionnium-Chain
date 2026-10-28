//! Private composition over the original Node writer. No Node escape or listener.
use super::{Hook, NativeOwners, NativeStoreOpening, Node, StateBackend};
use crate::pq_accounts_v2::PqPacketV2;
use crate::{ensure, Hash, PoolBatch, PoolLimits, PoolReceipt, PoolStatus, Result, Settings};
use std::path::Path;
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2 as pq, State};

pub(super) const OLD_RAW_CHECK: &str = "CHECK(length(raw)>0 AND length(raw)<=2048)";
const NEW_RAW_CHECK: &str = "CHECK(length(raw)>=3741 AND length(raw)<=9432)";
const STATEMENTS_DDL:&str="\nCREATE TABLE local_pq_statements_v2(group_id BLOB NOT NULL,position INTEGER NOT NULL,statement BLOB UNIQUE NOT NULL CHECK(length(statement)=48),PRIMARY KEY(group_id,position),FOREIGN KEY(group_id,position) REFERENCES local_pool_rows(group_id,position) ON DELETE CASCADE);\nCREATE TABLE local_pq_removed_statements_v2(statement BLOB PRIMARY KEY NOT NULL CHECK(length(statement)=48),removal_ordinal INTEGER UNIQUE NOT NULL,FOREIGN KEY(removal_ordinal) REFERENCES local_pool_removals(ordinal));";
pub(super) fn ddl(base: String) -> String {
    format!(
        "{}{}",
        base.replacen(OLD_RAW_CHECK, NEW_RAW_CHECK, 1),
        STATEMENTS_DDL
    )
}

/// A new profile owns the original actual Node. No Deref, `into_node`, legacy
/// network listener or operator mutation. Registration/rotation/claim remain
/// actual fully signed commands through the same M05/M06/PoN Node.
pub struct PqNodeV2 {
    inner: Node,
}
impl PqNodeV2 {
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
            inner: open_pq_node(
                path,
                settings,
                workers,
                hook,
                crate::native_packet::Profile::Pq2,
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
    /// Immutable statement bytes only; no claim eligibility or dispatch grant.
    pub fn migration_claim_payload(&self, account: Hash) -> Result<Vec<u8>> {
        Ok(pq::migration_claim_payload(
            &self.inner.settings.app,
            account,
        )?)
    }
    pub fn packet(&self, id: Hash) -> Result<PqPacketV2> {
        PqPacketV2::from_packet(self.inner.packet(id)?)
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
    ) -> Result<PqPacketV2> {
        let (model, input, _, _) = self.settings().consensus_maintenance_material()?;
        PqPacketV2::from_packet(self.inner.make_with_registered_material(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            &model,
            &input,
        )?)
    }
    pub fn admit(&mut self, packet: &PqPacketV2, observed_now: u64) -> Result<Hash> {
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

pub(super) fn open_pq_node(
    path: &Path,
    settings: Settings,
    workers: usize,
    hook: Option<&mut Hook<'_>>,
    profile: crate::native_packet::Profile,
) -> Result<Node> {
    ensure(settings.packet_profile() == profile, "PQ_PROFILE_REQUIRED")?;
    settings.native_pq_accounts_context()?;
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
            pq_explicit: Some(profile),
        },
    )?;
    Ok(inner)
}
impl Node {
    /// Capture a separately pinned CURRENT source checkpoint from the original
    /// unowned authenticated Node. A caller must explicitly supply the opaque
    /// independent prior-PQ trust object; this method cannot infer that trust
    /// from old Ed signatures or certify source finality/retirement/asset locks.
    /// Controlled service/mining/History owners refuse rather than bypass their
    /// existing operation budgets. No source mutation or destination activation.
    pub fn pin_native_pq_migration_checkpoint(
        &self,
        registry: pq::TrustedPqPrecommitments,
        pinned_checkpoint: Hash,
    ) -> Result<pq::TrustedMigrationAnchor> {
        ensure(
            !self.settings.is_native_pq()
                && self.state_backend == StateBackend::AuthenticatedV1
                && self.native_io.is_none()
                && self.growth_observer_snapshot.is_none()
                && self.owner_policy.is_none()
                && self.mining_owner.is_none()
                && self.continuous_owner.is_none()
                && self.public_service_cpu.is_none()
                && self.public_service_epoch_listeners == 0
                && !self.public_service_epoch_unknown,
            "PQ2_SOURCE_OWNER_PROFILE",
        )?;
        self.ready()?;
        self.storage_context()?;
        let active = self.active()?;
        ensure(
            active.0 == pinned_checkpoint && pinned_checkpoint != self.settings.genesis(),
            "PQ2_SOURCE_ACTIVE_CHECKPOINT",
        )?;
        let packet = self.packet(pinned_checkpoint)?;
        // Do not turn stored-packet existence or a caller's Boolean into a new
        // verified-work claim. This executes the ORIGINAL complete W1 verifier.
        pon_work::verify_reference(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .map_err(|_| "PQ2_SOURCE_WORK")?;
        let state = self.state_at(pinned_checkpoint)?;
        ensure(
            self.settings.state_root(&state)? == packet.header.state && self.active()? == active,
            "PQ2_SOURCE_CHECKPOINT_CHANGED",
        )?;
        let trace = packet
            .proof
            .get(pon_work::PROOF_BYTES - 32..)
            .ok_or("PQ2_SOURCE_WORK")?
            .try_into()
            .map_err(|_| "PQ2_SOURCE_WORK")?;
        Ok(registry.pin_checkpoint(
            pinned_checkpoint,
            pq::CheckpointMaterial {
                genesis: self.settings.genesis(),
                header: packet.header,
                trace,
                state,
            },
            &self.settings.app,
        )?)
    }
}
