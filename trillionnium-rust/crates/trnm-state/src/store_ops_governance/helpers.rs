use super::*;

impl StateStore {
    pub(super) fn upsert_gov_param_unchecked(
        &mut self,
        key_id: u64,
        key: String,
        value: String,
    ) -> Result<ObjectRef, String> {
        if let Some(existing_id) = self.gov_param_key_index.get(&key).copied() {
            if existing_id != key_id {
                return Err(format!(
                    "governance key id mismatch for {}: existing_id={}, attempted_id={}",
                    key, existing_id, key_id
                ));
            }
        }

        if let Some(current) = self.objects.get(&key_id) {
            let new_version = current.version + 1;
            let old_key = match &current.value {
                ObjectValue::GovParam(p) => p.key.clone(),
                _ => {
                    return Err(format!(
                        "governance key_id collision: object {} exists and is not GovParam",
                        key_id
                    ));
                }
            };

            if old_key != key {
                return Err(format!(
                    "governance key id mismatch for id {}: existing_key={}, attempted_key={}",
                    key_id, old_key, key
                ));
            }

            self.invalidate_state_root_cache();
            self.gov_param_key_index.insert(key.clone(), key_id);
            self.objects.insert(
                key_id,
                VersionedObject {
                    version: new_version,
                    value: ObjectValue::GovParam(GovParamObject {
                        key_id,
                        key,
                        value,
                        version: new_version,
                    }),
                },
            );
            Ok(ObjectRef {
                id: key_id,
                version: new_version,
            })
        } else {
            self.invalidate_state_root_cache();
            self.gov_param_key_index.insert(key.clone(), key_id);
            self.objects.insert(
                key_id,
                VersionedObject {
                    version: 1,
                    value: ObjectValue::GovParam(GovParamObject {
                        key_id,
                        key,
                        value,
                        version: 1,
                    }),
                },
            );
            Ok(ObjectRef {
                id: key_id,
                version: 1,
            })
        }
    }

    pub(super) fn gov_param_value(&self, key: &str) -> Option<&str> {
        let id = self.gov_param_key_index.get(key)?;
        let object = self.objects.get(id)?;
        match &object.value {
            ObjectValue::GovParam(p) if p.key == key && p.key_id == *id => Some(p.value.as_str()),
            _ => None,
        }
    }

    pub(super) fn gov_param_ref_for_key(&self, key: &str) -> Option<(u64, &GovParamObject)> {
        let id = self.gov_param_key_index.get(key).copied()?;
        let object = self.objects.get(&id)?;
        match &object.value {
            ObjectValue::GovParam(p) if p.key == key && p.key_id == id => Some((id, p)),
            _ => None,
        }
    }

    pub(super) fn monetary_tick_config(
        &self,
    ) -> Option<(u64, u64, u128, u128, u64, u64, u64, u64)> {
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
}
