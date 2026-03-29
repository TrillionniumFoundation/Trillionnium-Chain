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
    fn checkpoint_meta_rejects_duplicate_fields_for_auditable_surfaces() {
        let err = toml::from_str::<CheckpointMeta>(
            r#"
                height = 7
                state_root_hex = "aa"
                state_root_hex = "bb"
                wal_entry_hash_hex = "cc"
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("duplicate") && err.contains("state_root_hex"),
            "unexpected parse error: {err}"
        );
    }

    #[test]
    fn wal_meta_rejects_duplicate_fields_for_auditable_surfaces() {
        let err = toml::from_str::<WalMeta>(
            r#"
                height = 7
                round = 1
                proposal_hash = "proposal-7"
                committed = true
                state_root_hex = "aa"
                prev_hash_hex = "bb"
                prev_hash_hex = "cc"
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("duplicate") && err.contains("prev_hash_hex"),
            "unexpected parse error: {err}"
        );
    }
}
