pub mod bridge_status {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub enum BridgeStatus {
        Pending,
        Finalized(u64), // block height
        Reverted(String), // reason
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SettlementCapability {
        Finalize,
        Revert,
    }

    #[derive(Debug, Clone)]
    pub struct CapabilityToken {
        pub subject: String,
        pub capabilities: Vec<SettlementCapability>,
    }

    impl CapabilityToken {
        pub fn allows(&self, capability: SettlementCapability) -> bool {
            self.capabilities.contains(&capability)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum SettlementError {
        Unauthorized { subject: String, action: &'static str },
        InvalidTransition { from: &'static str, to: &'static str },
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

        pub fn settle_authorized(
            &mut self,
            token: &CapabilityToken,
            height: u64,
        ) -> Result<(), SettlementError> {
            if !token.allows(SettlementCapability::Finalize) {
                return Err(SettlementError::Unauthorized {
                    subject: token.subject.clone(),
                    action: "finalize",
                });
            }
            self.transition_to_finalized(height)
        }

        pub fn revert_authorized(
            &mut self,
            token: &CapabilityToken,
            reason: String,
        ) -> Result<(), SettlementError> {
            if !token.allows(SettlementCapability::Revert) {
                return Err(SettlementError::Unauthorized {
                    subject: token.subject.clone(),
                    action: "revert",
                });
            }
            self.transition_to_reverted(reason)
        }

        fn transition_to_finalized(&mut self, height: u64) -> Result<(), SettlementError> {
            match self.status {
                BridgeStatus::Pending => {
                    self.status = BridgeStatus::Finalized(height);
                    Ok(())
                }
                BridgeStatus::Finalized(_) => Err(SettlementError::InvalidTransition {
                    from: "finalized",
                    to: "finalized",
                }),
                BridgeStatus::Reverted(_) => Err(SettlementError::InvalidTransition {
                    from: "reverted",
                    to: "finalized",
                }),
            }
        }

        fn transition_to_reverted(&mut self, reason: String) -> Result<(), SettlementError> {
            match self.status {
                BridgeStatus::Pending => {
                    self.status = BridgeStatus::Reverted(reason);
                    Ok(())
                }
                BridgeStatus::Finalized(_) => Err(SettlementError::InvalidTransition {
                    from: "finalized",
                    to: "reverted",
                }),
                BridgeStatus::Reverted(_) => Err(SettlementError::InvalidTransition {
                    from: "reverted",
                    to: "reverted",
                }),
            }
        }
    }
}
