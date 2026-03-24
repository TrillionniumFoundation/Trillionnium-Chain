use super::*;

impl StateStore {
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
