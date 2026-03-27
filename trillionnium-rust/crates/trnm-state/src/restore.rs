use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ObjectValue, StateStore, VersionedObject};
use trnm_types::TaskObject;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointMeta {
    pub height: u64,
    pub state_root_hex: String,
    pub wal_entry_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn has_complete_task_metering_snapshot(metering: &trnm_types::TaskMeteringSnapshot) -> bool {
    has_canonical_metadata(&metering.workload_class)
        && has_canonical_metadata(&metering.metering_schema)
        && has_canonical_metadata(&metering.receipt_hash)
}

fn has_complete_task_metadata(metadata: &trnm_types::TaskMetadata) -> bool {
    metadata
        .note
        .as_deref()
        .map(has_canonical_metadata)
        .unwrap_or(true)
        && metadata
            .task_type
            .as_deref()
            .map(has_canonical_metadata)
            .unwrap_or(true)
        && metadata
            .input_hash
            .as_deref()
            .map(has_canonical_metadata)
            .unwrap_or(true)
        && metadata
            .model
            .as_ref()
            .map(|model| {
                model
                    .model_id
                    .as_deref()
                    .map(has_canonical_metadata)
                    .unwrap_or(true)
                    && model
                        .model_digest
                        .as_deref()
                        .map(has_canonical_metadata)
                        .unwrap_or(true)
                    && model
                        .version
                        .as_deref()
                        .map(has_canonical_metadata)
                        .unwrap_or(true)
            })
            .unwrap_or(true)
        && metadata
            .provenance
            .as_ref()
            .map(|provenance| {
                provenance
                    .producer_did
                    .as_deref()
                    .map(has_canonical_metadata)
                    .unwrap_or(true)
                    && provenance
                        .produced_at
                        .as_deref()
                        .map(has_canonical_metadata)
                        .unwrap_or(true)
                    && provenance
                        .provenance_index
                        .as_deref()
                        .map(has_canonical_metadata)
                        .unwrap_or(true)
            })
            .unwrap_or(true)
        && metadata
            .metering
            .as_ref()
            .map(has_complete_task_metering_snapshot)
            .unwrap_or(true)
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
            Some(task)
                if task.task_id == id
                    && task
                        .metadata
                        .as_ref()
                        .map(has_complete_task_metadata)
                        .unwrap_or(true) =>
            {
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
            if e.height != last_height.saturating_add(1) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_meta_rejects_unknown_fields_for_restore_surface() {
        let err = toml::from_str::<CheckpointMeta>(
            r#"
                height = 7
                state_root_hex = "aa"
                wal_entry_hash_hex = "bb"
                forged = true
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );
    }

    #[test]
    fn wal_meta_rejects_unknown_fields_for_restore_surface() {
        let err = toml::from_str::<WalMeta>(
            r#"
                height = 7
                round = 1
                proposal_hash = "proposal-7"
                committed = true
                state_root_hex = "aa"
                prev_hash_hex = "bb"
                forged = true
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );
    }
}
