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

    pub fn gov_param_snapshot(&self, key: &str) -> Option<GovParamObject> {
        let (_, param) = self.gov_param_ref_for_key(key)?;
        Some(param.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::GovParamObject;

    #[test]
    fn emergency_pause_requires_canonical_key_index_and_object_binding() {
        let mut state = StateStore::default();
        state
            .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
            .expect("canonical emergency_pause binding should succeed");
        assert!(
            state.is_emergency_paused(),
            "canonical emergency_pause binding should enable the pause gate"
        );

        state.gov_param_key_index.insert("emergency_pause".into(), 8_001);
        state.objects.insert(
            8_001,
            VersionedObject {
                version: 1,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7_999,
                    key: "emergency_pause".into(),
                    value: "true".into(),
                    version: 1,
                }),
            },
        );
        assert!(
            !state.is_emergency_paused(),
            "pause gate must fail closed when the indexed object key_id mismatches the registry slot"
        );

        state.gov_param_key_index.insert("emergency_pause".into(), 7_999);
        state.objects.insert(
            7_999,
            VersionedObject {
                version: 2,
                value: ObjectValue::GovParam(GovParamObject {
                    key_id: 7_999,
                    key: " emergency_pause".into(),
                    value: "true".into(),
                    version: 2,
                }),
            },
        );
        assert!(
            !state.is_emergency_paused(),
            "pause gate must fail closed when the indexed object key is non-canonical"
        );
    }
}
