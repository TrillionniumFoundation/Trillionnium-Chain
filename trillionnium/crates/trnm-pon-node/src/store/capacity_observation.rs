//! Local capacity obligations under one checked active branch generation.
//! No observation is a transaction, mining, storage or admission authority.
use super::Node;
use crate::{ensure, Error, Result};
use serde::Serialize;
use trnm_mvcc_fee::continuity_v1;

/// A current state-key observation, not a forecast of the next block's admission.
/// Private fields and no Deserialize keep this separate from caller-provided data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapacityObservation {
    schema: &'static str,
    network: String,
    parameters: String,
    genesis: String,
    observed_tip: String,
    active_generation: u64,
    observed_height: u64,
    state_root: String,
    maximum_keys: usize,
    actual_keys: usize,
    retained_account_keys: usize,
    actual_non_account_keys: usize,
    credit_account_reserve: usize,
    archive_reserve: usize,
    reward_queue_reserve: usize,
    required_keys: usize,
    unreserved_keys: usize,
    next_block_admission_guaranteed: bool,
}

impl Node {
    /// Reads actual canonical KV bytes and verifies the committed root through
    /// read_active. The capacity arithmetic reuses the sole revision12 algorithm.
    pub fn capacity_observation(&self) -> Result<CapacityObservation> {
        self.capacity_observation_with_progress(&mut || Ok(()))
    }

    /// Actual state reads and account counting check progress every 256 rows.
    /// Existing capacity/root arithmetic remain bounded nonpreemptive stages.
    /// Neither a partial observation nor an old active generation is published.
    pub fn capacity_observation_with_progress(
        &self,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<CapacityObservation> {
        ensure(
            continuity_v1::enabled(&self.settings.app),
            "CONTINUITY_PROFILE",
        )?;
        self.ready()?;
        let slot = self.slot()?;
        let (tip, generation, state) = self.read_active_with_progress(progress)?;
        let observed = self.record(tip).map_err(Error::local_integrity)?;
        progress()?;
        let capacity = continuity_v1::capacity(&state, observed.height, &self.settings.app)
            .map_err(|error| Error::from(error).local_integrity())?;
        let unreserved_keys = continuity_v1::MAX_KEYS
            .checked_sub(capacity.required_keys)
            .ok_or_else(|| Error::from("STATE_CAPACITY").local_integrity())?;
        let mut accounts = 0;
        for (index, key) in state.keys().enumerate() {
            if index % 256 == 0 {
                progress()?;
            }
            accounts += usize::from(key.starts_with("account:"));
        }
        progress()?;
        ensure(
            self.active()? == (tip, generation) && self.slot()? == slot,
            "STALE_VIEW",
        )?;
        Ok(CapacityObservation {
            schema: "pon-continuity-capacity-observation-v1",
            network: hex::encode(self.settings.network()),
            parameters: hex::encode(self.settings.parameters()),
            genesis: hex::encode(self.settings.genesis()),
            observed_tip: hex::encode(tip),
            active_generation: generation,
            observed_height: observed.height,
            state_root: hex::encode(observed.root),
            maximum_keys: continuity_v1::MAX_KEYS,
            actual_keys: capacity.actual_keys,
            retained_account_keys: accounts,
            actual_non_account_keys: capacity.actual_keys - accounts,
            credit_account_reserve: capacity.credit_account_reserve,
            archive_reserve: capacity.archive_reserve,
            reward_queue_reserve: capacity.reward_queue_reserve,
            required_keys: capacity.required_keys,
            unreserved_keys,
            next_block_admission_guaranteed: false,
        })
    }
}
