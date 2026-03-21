use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ObjectValue, StateStore, VersionedObject};
use trnm_types::TaskObject;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub height: u64,
    pub state_root_hex: String,
    pub wal_entry_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalMeta {
    pub height: u64,
    pub round: u64,
    pub proposal_hash: String,
    pub committed: bool,
    pub state_root_hex: String,
    pub prev_hash_hex: Option<String>,
}

impl WalMeta {
    pub fn content_hash_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.proposal_hash.as_bytes());
        hasher.update([self.committed as u8]);
        hasher.update(self.state_root_hex.as_bytes());
        if let Some(prev) = &self.prev_hash_hex {
            hasher.update(prev.as_bytes());
        } else {
            hasher.update(b"genesis");
        }
        hex::encode(hasher.finalize())
    }
}

impl StateStore {
    pub fn restore_task(&mut self, id: u64, snapshot: Option<TaskObject>) {
        self.invalidate_state_root_cache();
        match snapshot {
            Some(task) => {
                if task.task_id != id || task.version == 0 {
                    if matches!(
                        self.objects.get(&id).map(|object| &object.value),
                        Some(ObjectValue::Task(_))
                    ) {
                        self.objects.remove(&id);
                    }
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
                if matches!(
                    self.objects.get(&id).map(|object| &object.value),
                    Some(ObjectValue::Task(_))
                ) {
                    self.objects.remove(&id);
                }
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

pub fn verify_wal_and_find_checkpoint(
    checkpoints: &[CheckpointMeta],
    wal_entries: &[WalMeta],
) -> Result<Option<CheckpointMeta>, String> {
    let mut prev_hash: Option<String> = None;
    let mut prev_height: Option<u64> = None;
    let mut best_checkpoint: Option<CheckpointMeta> = None;

    for e in wal_entries {
        if let Some(last_height) = prev_height {
            if e.height <= last_height {
                return Ok(best_checkpoint);
            }
        } else if e.prev_hash_hex.is_none() && e.height > 1 {
            return Ok(best_checkpoint);
        }
        if e.prev_hash_hex != prev_hash {
            return Ok(best_checkpoint);
        }
        if !e.committed {
            return Ok(best_checkpoint);
        }
        let cur_hash = e.content_hash_hex();
        prev_hash = Some(cur_hash.clone());
        prev_height = Some(e.height);

        for cp in checkpoints.iter().filter(|cp| cp.height == e.height) {
            if cp.state_root_hex == e.state_root_hex
                && cur_hash.as_str() == cp.wal_entry_hash_hex.as_str()
            {
                let should_replace = best_checkpoint
                    .as_ref()
                    .map(|best| cp.height >= best.height)
                    .unwrap_or(true);
                if should_replace {
                    best_checkpoint = Some(cp.clone());
                }
            }
        }
    }

    Ok(best_checkpoint)
}
