use super::normalize::{canonical_path_segment, normalize_revert_reason};
use super::{Deserialize, InteropIdentityError, Serialize};

/// Chain-pair abstraction for cross-chain bridge settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRoute {
    pub route_id: String,
    pub source_chain: String,
    pub target_chain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SettlementStatus {
    Pending,
    Finalized,
    Reverted,
}

pub const SETTLEMENT_TX_RECEIPT_SUCCESS: u8 = 1;

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SettlementStatus::Pending => "pending",
            SettlementStatus::Finalized => "finalized",
            SettlementStatus::Reverted => "reverted",
        }
    }

    pub fn can_transition_to(self, to: Self) -> bool {
        if self == to {
            return true;
        }

        matches!(
            (self, to),
            (SettlementStatus::Pending, SettlementStatus::Finalized)
                | (SettlementStatus::Pending, SettlementStatus::Reverted)
        )
    }

    pub fn transition(self, to: Self) -> Result<Self, InteropIdentityError> {
        if self.can_transition_to(to) {
            return Ok(to);
        }
        Err(InteropIdentityError::InvalidSettlementTransition { from: self, to })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: u64,
    pub route: BridgeRoute,
    pub status: SettlementStatus,
    pub at_height: u64,
    pub settlement_tx: Option<String>,
    pub revert_reason: Option<String>,
}

impl SettlementRecord {
    /// Stable PoC scaffold path for dual-chain settlement state-machine evidence.
    ///
    /// Format:
    /// `settlements/<route_id>/<source_chain>/<target_chain>/<settlement_id>/<status>@<height>`
    pub fn evidence_path(&self) -> String {
        format!(
            "settlements/{}/{}/{}/{}/{}@{}",
            canonical_path_segment(&self.route.route_id),
            canonical_path_segment(&self.route.source_chain),
            canonical_path_segment(&self.route.target_chain),
            self.settlement_id,
            self.status.as_str(),
            self.at_height
        )
    }

    pub fn apply_status(
        &mut self,
        to: SettlementStatus,
        at_height: u64,
        settlement_tx: Option<String>,
        revert_reason: Option<String>,
    ) -> Result<(), InteropIdentityError> {
        self.apply_status_with_receipt_status(to, at_height, settlement_tx, None, revert_reason)
    }

    pub fn apply_status_with_receipt_status(
        &mut self,
        to: SettlementStatus,
        at_height: u64,
        settlement_tx: Option<String>,
        tx_receipt_status: Option<u8>,
        revert_reason: Option<String>,
    ) -> Result<(), InteropIdentityError> {
        if at_height < self.at_height {
            return Err(InteropIdentityError::InvalidSettlementHeightRegression {
                current_at: self.at_height,
                next_at: at_height,
            });
        }

        let next_status = self.status.transition(to)?;

        let (next_settlement_tx, next_revert_reason) = match to {
            SettlementStatus::Finalized => {
                let expected = SETTLEMENT_TX_RECEIPT_SUCCESS;
                let got = tx_receipt_status.unwrap_or(expected);
                if got != expected {
                    return Err(InteropIdentityError::InvalidSettlementReceiptStatus {
                        expected,
                        got,
                    });
                }

                let provided_tx = settlement_tx
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string);
                if self.status == SettlementStatus::Finalized {
                    if let (Some(existing), Some(provided)) =
                        (self.settlement_tx.as_deref(), provided_tx.as_deref())
                    {
                        if existing != provided {
                            return Err(InteropIdentityError::SettlementTerminalPayloadConflict {
                                status: SettlementStatus::Finalized,
                                existing: existing.to_string(),
                                provided: provided.to_string(),
                            });
                        }
                    }
                }
                let tx = provided_tx
                    .or_else(|| self.settlement_tx.clone())
                    .ok_or(InteropIdentityError::MissingSettlementTx)?;
                (Some(tx), None)
            }
            SettlementStatus::Reverted => {
                let provided_reason = revert_reason
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .map(normalize_revert_reason);
                if self.status == SettlementStatus::Reverted {
                    if let (Some(existing), Some(provided)) =
                        (self.revert_reason.as_deref(), provided_reason.as_deref())
                    {
                        let existing_normalized = normalize_revert_reason(existing.to_string());
                        if existing_normalized != *provided {
                            return Err(InteropIdentityError::SettlementTerminalPayloadConflict {
                                status: SettlementStatus::Reverted,
                                existing: existing.to_string(),
                                provided: provided.to_string(),
                            });
                        }
                    }
                }
                let reason = provided_reason
                    .or_else(|| self.revert_reason.clone().map(normalize_revert_reason))
                    .ok_or(InteropIdentityError::MissingRevertReason)?;
                (None, Some(reason))
            }
            SettlementStatus::Pending => (None, None),
        };

        self.status = next_status;
        self.at_height = at_height;
        self.settlement_tx = next_settlement_tx;
        self.revert_reason = next_revert_reason;

        Ok(())
    }
}
