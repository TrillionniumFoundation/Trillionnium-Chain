use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_meta_rejects_unknown_fields_for_auditable_surfaces() {
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
    fn wal_meta_rejects_unknown_fields_for_auditable_surfaces() {
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

    #[test]
    fn wal_meta_content_hash_hex_length_frames_adjacent_strings() {
        let left = WalMeta {
            height: 9,
            round: 4,
            proposal_hash: "ab".into(),
            committed: true,
            state_root_hex: "c".into(),
            prev_hash_hex: Some("tail".into()),
        };
        let right = WalMeta {
            height: 9,
            round: 4,
            proposal_hash: "a".into(),
            committed: true,
            state_root_hex: "bc".into(),
            prev_hash_hex: Some("tail".into()),
        };

        assert_ne!(
            left.content_hash_hex(),
            right.content_hash_hex(),
            "WAL metadata hashing must length-frame proposal_hash and state_root_hex so adjacent restore/audit surfaces cannot collide by shifting string boundaries"
        );
    }

    #[test]
    fn wal_meta_content_hash_hex_distinguishes_missing_prev_hash_from_literal_genesis() {
        let missing_prev = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "proposal-genesis".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: None,
        };
        let literal_prev = WalMeta {
            prev_hash_hex: Some("genesis".into()),
            ..missing_prev.clone()
        };

        assert_ne!(
            missing_prev.content_hash_hex(),
            literal_prev.content_hash_hex(),
            "WAL metadata hashing must distinguish missing prev_hash_hex from a literal \"genesis\" string so restore surfaces cannot collapse sentinel-vs-data states"
        );
    }
}
