pub mod bridge_status {
    use serde::{Deserialize, Serialize};
    use trnm_types::IdentityRegistry;

    fn has_disallowed_request_char(ch: char) -> bool {
        ch.is_control()
            || matches!(
                ch,
                '\u{00A0}'
                    | '\u{00AD}'
                    | '\u{034F}'
                    | '\u{061C}'
                    | '\u{115F}'
                    | '\u{1160}'
                    | '\u{1680}'
                    | '\u{180B}'
                    | '\u{180C}'
                    | '\u{180D}'
                    | '\u{180E}'
                    | '\u{180F}'
                    | '\u{2800}'
                    | '\u{3164}'
                    | '\u{FFA0}'
                    | '\u{2000}'
                    | '\u{2001}'
                    | '\u{2002}'
                    | '\u{2003}'
                    | '\u{2004}'
                    | '\u{2005}'
                    | '\u{2006}'
                    | '\u{2007}'
                    | '\u{2008}'
                    | '\u{2009}'
                    | '\u{200A}'
                    | '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202C}'
                    | '\u{202D}'
                    | '\u{202E}'
                    | '\u{202F}'
                    | '\u{205F}'
                    | '\u{3000}'
                    | '\u{2060}'
                    | '\u{2061}'
                    | '\u{2062}'
                    | '\u{2063}'
                    | '\u{2064}'
                    | '\u{2065}'
                    | '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
                    | '\u{206A}'
                    | '\u{206B}'
                    | '\u{206C}'
                    | '\u{206D}'
                    | '\u{206E}'
                    | '\u{206F}'
                    | '\u{FEFF}'
                    | '\u{FFF9}'
                    | '\u{FFFA}'
                    | '\u{FFFB}'
            )
            || ('\u{FE00}'..='\u{FE0F}').contains(&ch)
            || ('\u{E0000}'..='\u{E007F}').contains(&ch)
            || ('\u{E0100}'..='\u{E01EF}').contains(&ch)
    }

    fn has_disallowed_subject_char(ch: char) -> bool {
        has_disallowed_request_char(ch)
    }

    fn is_non_canonical_request_field(value: &str) -> bool {
        value.trim() != value
            || value
                .chars()
                .any(|ch| ch.is_whitespace() || has_disallowed_request_char(ch))
    }

    fn is_non_canonical_subject(value: &str) -> bool {
        value.trim() != value
            || value
                .chars()
                .any(|ch| ch.is_whitespace() || has_disallowed_subject_char(ch))
    }

    fn normalize_revert_reason(reason: &str) -> Option<String> {
        let sanitized: String = reason
            .chars()
            .map(|ch| {
                if ch.is_whitespace() || has_disallowed_request_char(ch) {
                    ' '
                } else {
                    ch
                }
            })
            .collect();
        let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.is_empty() {
            return None;
        }

        Some(collapsed)
    }

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
        HeartbeatRetryPending {
            reason: String,
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

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SettlementAuditView {
        pub chain_id: u32,
        pub tx_hash: String,
        pub status: &'static str,
        pub is_terminal: bool,
        pub finalized_height: Option<u64>,
        pub revert_reason: Option<String>,
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
            if self.chain_id == 0 {
                return Err(SettlementError::MalformedRequest {
                    reason: "invalid chain_id",
                });
            }
            if self.tx_hash.trim().is_empty() {
                return Err(SettlementError::MalformedRequest {
                    reason: "empty tx_hash",
                });
            }
            if is_non_canonical_request_field(&self.tx_hash) {
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
            if is_non_canonical_subject(&token.subject) {
                return Err(SettlementError::MalformedToken {
                    reason: "non-canonical subject",
                });
            }
            if !IdentityRegistry::is_canonical_did(&token.subject) {
                return Err(SettlementError::MalformedToken {
                    reason: "non-canonical subject",
                });
            }
            Ok(())
        }

        #[deprecated(note = "direct settlement writes are disabled; use settle_authorized")]
        pub fn settle(&mut self, _height: u64) {
            // SECURITY: keep legacy API surface without allowing authorization bypass.
            // Only *_authorized paths may perform terminal state transitions.
        }

        #[deprecated(note = "direct settlement writes are disabled; use revert_authorized")]
        pub fn revert(&mut self, _reason: String) {
            // SECURITY: keep legacy API surface without allowing authorization bypass.
            // Only *_authorized paths may perform terminal state transitions.
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

        pub fn audit_view(&self) -> SettlementAuditView {
            match &self.status {
                BridgeStatus::Pending => SettlementAuditView {
                    chain_id: self.chain_id,
                    tx_hash: self.tx_hash.clone(),
                    status: "pending",
                    is_terminal: false,
                    finalized_height: None,
                    revert_reason: None,
                },
                BridgeStatus::Finalized(height) => SettlementAuditView {
                    chain_id: self.chain_id,
                    tx_hash: self.tx_hash.clone(),
                    status: "finalized",
                    is_terminal: true,
                    finalized_height: Some(*height),
                    revert_reason: None,
                },
                BridgeStatus::Reverted(reason) => SettlementAuditView {
                    chain_id: self.chain_id,
                    tx_hash: self.tx_hash.clone(),
                    status: "reverted",
                    is_terminal: true,
                    finalized_height: None,
                    revert_reason: normalize_revert_reason(reason),
                },
            }
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
            let Some(reason) = normalize_revert_reason(&reason) else {
                return Err(SettlementError::InvalidRevertReason);
            };
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
