use crate::{CheckpointMeta, WalMeta};

pub fn verify_wal_and_find_checkpoint(
    checkpoints: &[CheckpointMeta],
    wal_entries: &[WalMeta],
) -> Result<Option<CheckpointMeta>, String> {
    let mut prev_hash: Option<String> = None;
    let mut prev_height: Option<u64> = None;
    let mut best_checkpoint: Option<CheckpointMeta> = None;

    for e in wal_entries {
        if prev_height.is_none() && e.height > 1 {
            // Fail closed: metadata-only recovery cannot start above genesis without
            // a proven lower-height anchor already in the verified prefix.
            return Ok(best_checkpoint);
        }
        if let Some(last_height) = prev_height {
            // Stop at the first non-monotonic height transition and fall back to the
            // latest checkpoint proven by the prefix seen so far.
            if e.height <= last_height {
                return Ok(best_checkpoint);
            }
        }
        if e.prev_hash_hex != prev_hash {
            return Ok(best_checkpoint);
        }
        // Fail closed: uncommitted WAL tail must not advance recovery checkpoint.
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
