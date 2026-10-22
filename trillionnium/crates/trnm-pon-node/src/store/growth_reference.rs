//! Current local facts for the explicit complete-State growth reference.
use super::Node;
use crate::{ensure, Result};
use serde::Serialize;
use trnm_mvcc_fee::{continuity_v1, growth_profile_v2};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrowthReferenceObservation {
    schema: &'static str,
    network: String,
    parameters: String,
    genesis: String,
    tip: String,
    generation: u64,
    height: u64,
    state_root: String,
    permanent_accounts: u64,
    working_keys: u64,
    required_permanent_accounts: u64,
    required_working_keys: u64,
    maximum_permanent_accounts: u64,
    maximum_working_keys: u64,
    complete_state_required: bool,
    bounded_witness_qualified: bool,
    production_activation: bool,
}
impl Node {
    pub fn growth_reference_observation(&self) -> Result<GrowthReferenceObservation> {
        ensure(
            growth_profile_v2::enabled(&self.settings.app),
            "GROWTH_PROFILE",
        )?;
        self.ready()?;
        let (tip, generation, state) = self.read_active()?;
        let row = self.record(tip)?;
        let commitment = growth_profile_v2::commitment(&state, &self.settings.app)?;
        ensure(commitment.id() == row.root, "ROOT")?;
        let capacity = continuity_v1::capacity(&state, row.height, &self.settings.app)?;
        let required_accounts = commitment
            .account_count
            .checked_add(capacity.credit_account_reserve as u64)
            .ok_or("RANGE")?;
        let required_working = commitment
            .working_count
            .checked_add(capacity.archive_reserve as u64)
            .and_then(|n| n.checked_add(capacity.reward_queue_reserve as u64))
            .ok_or("RANGE")?;
        ensure(self.active()? == (tip, generation), "STALE_VIEW")?;
        Ok(GrowthReferenceObservation {
            schema: "pon-native-growth-reference-observation-v2",
            network: hex::encode(self.settings.network()),
            parameters: hex::encode(self.settings.parameters()),
            genesis: hex::encode(self.settings.genesis()),
            tip: hex::encode(tip),
            generation,
            height: row.height,
            state_root: hex::encode(row.root),
            permanent_accounts: commitment.account_count,
            working_keys: commitment.working_count,
            required_permanent_accounts: required_accounts,
            required_working_keys: required_working,
            maximum_permanent_accounts: commitment.maximum_permanent_accounts,
            maximum_working_keys: commitment.maximum_working_keys,
            complete_state_required: true,
            bounded_witness_qualified: false,
            production_activation: false,
        })
    }
}

#[cfg(test)]
#[path = "growth_reference_tests.rs"]
mod tests;
