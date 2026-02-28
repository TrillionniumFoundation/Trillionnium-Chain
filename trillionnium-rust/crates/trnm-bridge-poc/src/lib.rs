pub mod bridge_status {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub enum BridgeStatus {
        Pending,
        Finalized(u64), // block height
        Reverted(String), // reason
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SettlementRequest {
        pub chain_id: u32,
        pub tx_hash: String,
        pub status: BridgeStatus,
    }

    impl SettlementRequest {
        pub fn new(chain_id: u32, tx_hash: String) -> Self {
            SettlementRequest {
                chain_id,
                tx_hash,
                status: BridgeStatus::Pending,
            }
        }

        pub fn settle(&mut self, height: u64) {
            self.status = BridgeStatus::Finalized(height);
        }

        pub fn revert(&mut self, reason: String) {
            self.status = BridgeStatus::Reverted(reason);
        }
    }
}
