use super::*;

impl StateStore {
    pub fn pending_gov_update(&self, key: &str) -> Option<PendingGovParamUpdate> {
        self.pending_gov_updates.get(key).cloned()
    }

    pub fn restore_pending_gov_update(
        &mut self,
        key: &str,
        snapshot: Option<PendingGovParamUpdate>,
    ) {
        self.invalidate_state_root_cache();
        match snapshot {
            Some(snapshot) => {
                if snapshot.key != key {
                    self.pending_gov_updates.remove(key);
                    return;
                }
                self.pending_gov_updates
                    .insert(snapshot.key.clone(), snapshot);
            }
            None => {
                self.pending_gov_updates.remove(key);
            }
        }
    }

    pub fn is_emergency_paused(&self) -> bool {
        self.gov_param_value("emergency_pause") == Some("true")
    }

    pub fn gov_param_u64(&self, key: &str) -> Option<u64> {
        self.gov_param_value(key)?.parse::<u64>().ok()
    }

    pub fn gov_param_u128(&self, key: &str) -> Option<u128> {
        self.gov_param_value(key)?.parse::<u128>().ok()
    }

    pub fn gov_param_string(&self, key: &str) -> Option<String> {
        Some(self.gov_param_value(key)?.to_string())
    }

    pub fn monetary_state(&self) -> &MonetaryState {
        &self.monetary_state
    }

    pub fn monetary_state_snapshot(&self) -> MonetaryStateSnapshot {
        self.monetary_state.clone()
    }

    pub fn restore_monetary_state(&mut self, snapshot: MonetaryStateSnapshot) {
        self.invalidate_state_root_cache();
        self.monetary_state = snapshot;
    }
}
