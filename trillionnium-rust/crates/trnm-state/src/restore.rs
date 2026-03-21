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

fn hash_len_framed_str(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn has_canonical_metadata(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed == value
}

fn has_complete_checkpoint_meta(checkpoint: &CheckpointMeta) -> bool {
    has_canonical_metadata(&checkpoint.state_root_hex)
        && has_canonical_metadata(&checkpoint.wal_entry_hash_hex)
}

fn has_complete_wal_meta(entry: &WalMeta) -> bool {
    has_canonical_metadata(&entry.proposal_hash)
        && has_canonical_metadata(&entry.state_root_hex)
        && entry
            .prev_hash_hex
            .as_ref()
            .map(|prev| has_canonical_metadata(prev))
            .unwrap_or(true)
}

impl WalMeta {
    pub fn content_hash_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hash_len_framed_str(&mut hasher, &self.proposal_hash);
        hasher.update([self.committed as u8]);
        hash_len_framed_str(&mut hasher, &self.state_root_hex);
        if let Some(prev) = &self.prev_hash_hex {
            hasher.update([1]);
            hash_len_framed_str(&mut hasher, prev);
        } else {
            hasher.update([0]);
        }
        hex::encode(hasher.finalize())
    }
}

impl StateStore {
    pub fn restore_task(&mut self, id: u64, snapshot: Option<TaskObject>) {
        self.invalidate_state_root_cache();
        match snapshot {
            Some(task) if task.task_id == id => {
                self.objects.insert(
                    id,
                    VersionedObject {
                        version: task.version,
                        value: ObjectValue::Task(task),
                    },
                );
            }
            Some(_) | None => {
                self.objects.remove(&id);
            }
        }
    }

    pub fn restore_balance(&mut self, address: &str, snapshot: Option<u128>) {
        self.invalidate_state_root_cache();
        match snapshot {
            Some(amount) => {
                self.balances.insert(address.to_string(), amount);
            }
            None => {
                self.balances.remove(address);
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
        }
        if !has_complete_wal_meta(e) {
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

        let matching_height: Vec<&CheckpointMeta> =
            checkpoints.iter().filter(|cp| cp.height == e.height).collect();
        if matching_height.iter().any(|cp| !has_complete_checkpoint_meta(cp)) {
            return Ok(best_checkpoint);
        }
        let canonical_matches = matching_height
            .iter()
            .filter(|cp| {
                cp.state_root_hex == e.state_root_hex
                    && cur_hash.as_str() == cp.wal_entry_hash_hex.as_str()
            })
            .count();
        if matching_height.len() > 1 && canonical_matches != 1 {
            return Ok(best_checkpoint);
        }
        if !matching_height.is_empty() && canonical_matches == 0 {
            return Ok(best_checkpoint);
        }

        for cp in matching_height {
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
