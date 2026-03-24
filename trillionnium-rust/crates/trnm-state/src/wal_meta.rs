use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
