use crate::*;

impl StateStore {
    pub fn restore_task(&mut self, id: u64, snapshot: Option<TaskObject>) {
        self.invalidate_state_root_cache();
        self.remove_gov_param_key_index_for_id(id);
        match snapshot {
            Some(task) => {
                if task.task_id != id {
                    self.objects.remove(&id);
                    return;
                }
                self.objects.insert(
                    id,
                    VersionedObject {
                        version: task.version,
                        value: ObjectValue::Task(task),
                    },
                );
            }
            None => {
                self.objects.remove(&id);
            }
        }
    }

    pub fn restore_gov_param(&mut self, key_id: u64, snapshot: Option<GovParamObject>) {
        self.invalidate_state_root_cache();
        self.remove_gov_param_key_index_for_id(key_id);
        match snapshot {
            Some(snapshot) => {
                if snapshot.key_id != key_id {
                    self.objects.remove(&key_id);
                    return;
                }
                if let Some(existing_id) = self.gov_param_key_index.get(&snapshot.key).copied() {
                    if existing_id != key_id {
                        self.objects.remove(&key_id);
                        return;
                    }
                }
                self.gov_param_key_index
                    .insert(snapshot.key.clone(), snapshot.key_id);
                self.objects.insert(
                    key_id,
                    VersionedObject {
                        version: snapshot.version,
                        value: ObjectValue::GovParam(snapshot),
                    },
                );
            }
            None => {
                self.objects.remove(&key_id);
            }
        }
    }

    pub fn restore_balance(&mut self, address: &str, snapshot: Option<u128>) {
        self.invalidate_state_root_cache();
        match snapshot {
            Some(0) | None => {
                self.balances.remove(address);
            }
            Some(amount) => {
                self.balances.insert(address.to_string(), amount);
            }
        }
    }
}
