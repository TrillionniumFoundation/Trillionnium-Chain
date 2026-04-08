use crate::{MonetaryState, StateStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTickEvent {
    pub block_height: u64,
    pub interval_blocks: u64,
    pub cooldown_blocks: u64,
    pub minted: u128,
    pub burned: u128,
    pub net_delta: i128,
    pub total_minted: u128,
    pub total_burned: u128,
    pub net_issuance: i128,
    pub tick_count: u64,
    pub interval_param_version: u64,
    pub issuance_param_version: u64,
    pub burn_param_version: u64,
    pub cooldown_param_version: u64,
}

impl StateStore {
    fn monetary_tick_config(&self) -> Option<(u64, u64, u128, u128, u64, u64, u64, u64)> {
        let (_, interval_param) =
            self.gov_param_ref_for_key("monetary_policy_tick_interval_blocks")?;
        let (_, cooldown_param) =
            self.gov_param_ref_for_key("monetary_policy_tick_cooldown_blocks")?;
        let (_, issuance_param) = self.gov_param_ref_for_key("monetary_base_issuance_per_tick")?;
        let (_, burn_param) = self.gov_param_ref_for_key("monetary_base_burn_per_tick")?;

        let interval = interval_param.value.parse::<u64>().ok()?;
        let cooldown = cooldown_param.value.parse::<u64>().ok()?;
        let minted = issuance_param.value.parse::<u128>().ok()?;
        let burned = burn_param.value.parse::<u128>().ok()?;

        if !(1..=100_000).contains(&interval)
            || !(1..=100_000).contains(&cooldown)
            || minted > 1_000_000_000_000u128
            || burned > 1_000_000_000_000u128
        {
            return None;
        }

        Some((
            interval,
            cooldown,
            minted,
            burned,
            interval_param.version,
            issuance_param.version,
            burn_param.version,
            cooldown_param.version,
        ))
    }

    pub fn monetary_state(&self) -> &MonetaryState {
        &self.monetary_state
    }

    pub fn should_trigger_policy_tick(&self, block_height: u64) -> bool {
        let Some((interval, cooldown, _, _, _, _, _, _)) = self.monetary_tick_config() else {
            return false;
        };
        let cooldown_allows = self.monetary_state.tick_count == 0
            || self
                .monetary_state
                .last_tick_height
                .saturating_add(cooldown)
                <= block_height;
        block_height > 0
            && block_height % interval == 0
            && cooldown_allows
            && self.monetary_state.last_tick_height < block_height
    }

    pub fn policy_tick(&mut self, block_height: u64) -> Option<PolicyTickEvent> {
        let (
            interval_blocks,
            cooldown_blocks,
            minted,
            burned,
            interval_param_version,
            issuance_param_version,
            burn_param_version,
            cooldown_param_version,
        ) = self.monetary_tick_config()?;

        let cooldown_allows = self.monetary_state.tick_count == 0
            || self
                .monetary_state
                .last_tick_height
                .saturating_add(cooldown_blocks)
                <= block_height;

        if !(block_height > 0
            && block_height % interval_blocks == 0
            && cooldown_allows
            && self.monetary_state.last_tick_height < block_height)
        {
            return None;
        }
        let net_delta = minted as i128 - burned as i128;

        self.invalidate_state_root_cache();
        self.monetary_state.last_tick_height = block_height;
        self.monetary_state.tick_count = self.monetary_state.tick_count.saturating_add(1);
        self.monetary_state.total_minted = self.monetary_state.total_minted.saturating_add(minted);
        self.monetary_state.total_burned = self.monetary_state.total_burned.saturating_add(burned);
        self.monetary_state.net_issuance =
            self.monetary_state.net_issuance.saturating_add(net_delta);

        Some(PolicyTickEvent {
            block_height,
            interval_blocks,
            cooldown_blocks,
            minted,
            burned,
            net_delta,
            total_minted: self.monetary_state.total_minted,
            total_burned: self.monetary_state.total_burned,
            net_issuance: self.monetary_state.net_issuance,
            tick_count: self.monetary_state.tick_count,
            interval_param_version,
            issuance_param_version,
            burn_param_version,
            cooldown_param_version,
        })
    }
}
