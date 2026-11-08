//! PNP2 confirmation from the existing cold-audited native growth owner.
//! Each requested body replays the original W1 and M06 transition. The complete
//! selected ancestry is reobserved under one current read snapshot. No peer
//! work total, earlier clock verdict, permanent-account materialization, or
//! production/finality/execution grant is substituted for those checks.
use super::*;
use crate::{ConfirmationBatch, Observation};
use trnm_protocol::pon_wire::hash;

impl Node {
    // Caller holds one read snapshot in the unchanged audited storage epoch.
    // Keep only the bounded requested identities, never a full-chain vector.
    fn growth_observed_members_in_read(
        &self,
        tip: Hash,
        observed_now: u64,
        requested: &BTreeSet<Hash>,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<(BTreeSet<Hash>, u64)> {
        ensure(!self.db.is_autocommit(), "GROWTH_READ_SNAPSHOT_REQUIRED")?;
        let observed = self.record(tip)?;
        let mut current = tip;
        let mut expected_height = observed.height;
        let mut expected_work = observed.work;
        let mut checked = 0_u64;
        let mut found = BTreeSet::new();
        let bound = observed_now as u128 + self.settings.limit("future_skew_seconds")? as u128;
        while current != self.settings.genesis() {
            progress(checked)?;
            let link = self.growth_evaluation_header_link(current)?;
            ensure(
                link.record.height == expected_height
                    && link.record.work == expected_work
                    && link.record.work
                        == link
                            .parent_work
                            .checked_add(consensus::required_work(link.header.target)?)?,
                "GROWTH_HEADER_RECORD",
            )
            .map_err(Error::local_integrity)?;
            ensure(link.header.timestamp as u128 <= bound, "TIME_DEFERRED")?;
            if requested.contains(&current) {
                found.insert(current);
            }
            current = link.header.parent;
            expected_height = link.record.height.checked_sub(1).ok_or("HEIGHT")?;
            expected_work = link.parent_work;
            checked = checked.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
        }
        let genesis = self.record(current)?;
        ensure(
            genesis.parent.is_none()
                && genesis.height == 0
                && genesis.work == consensus::Work::default()
                && expected_height == 0
                && expected_work == genesis.work,
            "GROWTH_HEADER_RECORD",
        )
        .map_err(Error::local_integrity)?;
        progress(checked)?;
        Ok((found, checked))
    }

    /// Current-clock observation for the existing check_observed_history and
    /// activate_observed entries. Activation still uses the original growth
    /// owner, strictly greater required work, original reorg journal and gates.
    pub(in crate::store) fn growth_check_observed_history_with_progress(
        &self,
        tip: Hash,
        observed_now: u64,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        progress()?;
        self.growth_guard()?;
        self.ready()?;
        let read = self.db.unchecked_transaction()?;
        self.growth_guard()?;
        let changes = self.db.total_changes();
        self.growth_parent(tip)?;
        self.growth_observed_members_in_read(tip, observed_now, &BTreeSet::new(), &mut |_| {
            progress()
        })?;
        self.growth_guard()?;
        ensure(
            self.db.total_changes() == changes,
            "GROWTH_OBSERVATION_WRITE",
        )
        .map_err(Error::local_integrity)?;
        read.rollback()?;
        // data_version is snapshot-local. A foreign WAL commit during any
        // callback must still refuse after the read snapshot has ended.
        progress()?;
        self.growth_guard()
    }

    /// Real growth-owner batch confirmation with the original full W1/M06
    /// progress checkpoints. Cancellation returns no partial batch. The default
    /// Node::confirmation(s) entries dispatch here; callers needing progress
    /// use this typed callback instead of the legacy non-Sync FnMut callback.
    pub fn growth_confirmations_with_progress(
        &self,
        queries: &[(Hash, Hash)],
        observed_now: u64,
        progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
    ) -> Result<ConfirmationBatch> {
        ensure((1..=256).contains(&queries.len()), "CONFIRMATION_LIMIT")?;
        let unique: BTreeSet<_> = queries.iter().copied().collect();
        ensure(unique.len() == queries.len(), "DUPLICATE_QUERY")?;
        progress(GrowthProgress::BeforeObservation)?;
        self.growth_guard()?;
        self.ready()?;
        let read = self.db.unchecked_transaction()?;
        self.growth_guard()?;
        let changes = self.db.total_changes();
        let (tip, generation) = self.active()?;
        let observed = self.record(tip)?;
        // Bind the real complete working commitment and account checkpoint,
        // without asking the growth owner for a nonexistent materialized State.
        self.growth_parent(tip)?;
        let mut included = BTreeMap::new();
        for (transaction, block) in queries {
            if !included.contains_key(block) {
                progress(GrowthProgress::ConfirmationBody {
                    index: included.len(),
                })?;
                ensure(*block != self.settings.genesis(), "GENESIS_HAS_NO_PACKET")?;
                self.growth_check_retained_transition_with_progress(*block, None, progress)?;
                let packet = self.growth_load_packet(*block)?;
                let link = self.growth_evaluation_header_link(*block)?;
                ensure(
                    link.record.work
                        == link
                            .parent_work
                            .checked_add(consensus::required_work(link.header.target)?)?
                        && packet.header.ledger.transactions
                            == sequence_root("transactions", &packet.transactions),
                    "GROWTH_HEADER_RECORD",
                )
                .map_err(Error::local_integrity)?;
                let members: BTreeSet<_> = packet
                    .transactions
                    .iter()
                    .map(|raw| hash(b"tx-id", &[raw]))
                    .collect();
                included.insert(*block, (link.record, packet.header.ledger.target, members));
            }
            ensure(included[block].2.contains(transaction), "MEMBERSHIP")?;
        }
        let requested = included.keys().copied().collect();
        let (found, checked) =
            self.growth_observed_members_in_read(tip, observed_now, &requested, &mut |index| {
                progress(GrowthProgress::ConfirmationAncestor { index })
            })?;
        let depth_required = self.settings.limit("confirmation_depth")?;
        let multiplier = self.settings.limit("confirmation_work_multiplier")?;
        let mut observations = Vec::with_capacity(queries.len());
        for (transaction, block) in queries {
            let (row, target, _) = &included[block];
            let present = found.contains(block);
            let delta = present
                .then(|| observed.work.checked_sub(row.work))
                .transpose()?;
            let depth = present
                .then(|| observed.height.checked_sub(row.height).ok_or("HEIGHT"))
                .transpose()?;
            let threshold = consensus::required_work(*target)?.mul_small(multiplier)?;
            observations.push(Observation {
                transaction: hex::encode(transaction),
                genesis: hex::encode(self.settings.genesis()),
                policy: "installed-depth-and-required-work".into(),
                required_work_delta: hex::encode(threshold.bytes()),
                network: hex::encode(self.settings.network()),
                parameters: hex::encode(self.settings.parameters()),
                included_block: hex::encode(block),
                observed_tip: hex::encode(tip),
                included_height: row.height,
                observed_height: observed.height,
                depth,
                work_delta: delta.map(|work| hex::encode(work.bytes())),
                active_generation: generation,
                observed_now,
                confirmed: depth.is_some_and(|value| value >= depth_required)
                    && delta.is_some_and(|value| value >= threshold),
                reorged: !present,
                finalized: false,
                execution_authority: false,
            });
        }
        progress(GrowthProgress::ObservationReady)?;
        self.growth_guard()?;
        ensure(self.active()? == (tip, generation), "STALE_VIEW")?;
        ensure(
            self.db.total_changes() == changes,
            "GROWTH_OBSERVATION_WRITE",
        )
        .map_err(Error::local_integrity)?;
        read.rollback()?;
        self.growth_guard()?;
        Ok(ConfirmationBatch {
            observations,
            ancestry_checked: checked,
            distinct_bodies_checked: included.len(),
        })
    }
}
