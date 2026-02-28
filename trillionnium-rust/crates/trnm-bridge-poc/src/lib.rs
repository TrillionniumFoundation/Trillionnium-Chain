pub mod bridge_status {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub enum BridgeStatus {
        Pending,
        Finalized(u64),   // block height
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
        Unauthorized {
            subject: String,
            action: &'static str,
        },
        InvalidTransition {
            from: &'static str,
            to: &'static str,
        },
        InvalidHeight {
            height: u64,
        },
        InvalidRevertReason,
        MalformedRequest {
            reason: &'static str,
        },
        MalformedToken {
            reason: &'static str,
        },
    }

    impl SettlementError {
        pub fn is_unauthorized(&self) -> bool {
            matches!(self, SettlementError::Unauthorized { .. })
        }
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

        fn validate_request(&self) -> Result<(), SettlementError> {
            if self.tx_hash.trim().is_empty() {
                return Err(SettlementError::MalformedRequest {
                    reason: "empty tx_hash",
                });
            }
            if self.tx_hash.trim() != self.tx_hash || self.tx_hash.chars().any(char::is_control) {
                return Err(SettlementError::MalformedRequest {
                    reason: "non-canonical tx_hash",
                });
            }
            Ok(())
        }

        fn validate_token(token: &CapabilityToken) -> Result<(), SettlementError> {
            if token.subject.trim().is_empty() {
                return Err(SettlementError::MalformedToken {
                    reason: "empty subject",
                });
            }
            if token.subject.trim() != token.subject || token.subject.chars().any(char::is_control)
            {
                return Err(SettlementError::MalformedToken {
                    reason: "non-canonical subject",
                });
            }
            Ok(())
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
            self.validate_request()?;
            Self::validate_token(token)?;
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
            self.validate_request()?;
            Self::validate_token(token)?;
            if !token.allows(SettlementCapability::Revert) {
                return Err(SettlementError::Unauthorized {
                    subject: token.subject.clone(),
                    action: "revert",
                });
            }
            self.transition_to_reverted(reason)
        }

        fn transition_to_finalized(&mut self, height: u64) -> Result<(), SettlementError> {
            if height == 0 {
                return Err(SettlementError::InvalidHeight { height });
            }
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
            if reason.trim().is_empty() {
                return Err(SettlementError::InvalidRevertReason);
            }
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

pub mod relay_heartbeat;
pub mod x2_settlement_loop;

#[cfg(test)]
mod tests;
