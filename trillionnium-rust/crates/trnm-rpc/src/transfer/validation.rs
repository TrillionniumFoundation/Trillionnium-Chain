use crate::transfer::helpers::{
    InMemoryTransferLedger, SubmitTransferRequest, SubmitTransferResponse,
};
use trnm_types::{TransferTx, TransferTxValidationError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferApplyError {
    Basic(TransferTxValidationError),
    NonceRollback {
        expected: u64,
        got: u64,
    },
    InsufficientBalance {
        balance: u128,
        needed: u128,
    },
    AmountFeeOverflow {
        amount: u128,
        fee: u128,
    },
    ReceiverBalanceOverflow {
        receiver: String,
        balance: u128,
        amount: u128,
    },
}

impl std::fmt::Display for TransferApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic(e) => write!(f, "{}", e),
            Self::NonceRollback { expected, got } => {
                write!(
                    f,
                    "nonce rollback/replay: expected {}, got {}",
                    expected, got
                )
            }
            Self::InsufficientBalance { balance, needed } => {
                write!(
                    f,
                    "insufficient balance: balance {}, needed {}",
                    balance, needed
                )
            }
            Self::AmountFeeOverflow { amount, fee } => {
                write!(f, "amount+fee overflow: amount {}, fee {}", amount, fee)
            }
            Self::ReceiverBalanceOverflow {
                receiver,
                balance,
                amount,
            } => {
                write!(
                    f,
                    "receiver balance overflow: receiver {}, balance {}, amount {}",
                    receiver, balance, amount
                )
            }
        }
    }
}

impl std::error::Error for TransferApplyError {}

pub fn apply_transfer(
    ledger: &mut InMemoryTransferLedger,
    req: SubmitTransferRequest,
) -> Result<SubmitTransferResponse, TransferApplyError> {
    let tx = req.tx;
    tx.validate_basic().map_err(TransferApplyError::Basic)?;

    let expected_nonce = ledger.next_nonce_of(&tx.from);
    validate_nonce(&tx, expected_nonce)?;

    let needed = required_balance(&tx)?;
    let from_balance = ledger.balance_of(&tx.from);
    ensure_sufficient_balance(from_balance, needed)?;

    let to_balance = ledger.balance_of(&tx.to);
    let new_from = from_balance - needed;
    let new_to = credited_balance(&tx, to_balance)?;

    ledger.balances.insert(tx.from.clone(), new_from);
    ledger.balances.insert(tx.to.clone(), new_to);
    ledger.nonces.insert(tx.from.clone(), expected_nonce + 1);

    Ok(SubmitTransferResponse {
        accepted: true,
        from_balance: new_from,
        to_balance: new_to,
        next_nonce: expected_nonce + 1,
    })
}

fn validate_nonce(tx: &TransferTx, expected_nonce: u64) -> Result<(), TransferApplyError> {
    if tx.nonce != expected_nonce {
        return Err(TransferApplyError::NonceRollback {
            expected: expected_nonce,
            got: tx.nonce,
        });
    }
    Ok(())
}

fn required_balance(tx: &TransferTx) -> Result<u128, TransferApplyError> {
    tx.amount
        .checked_add(tx.fee)
        .ok_or(TransferApplyError::AmountFeeOverflow {
            amount: tx.amount,
            fee: tx.fee,
        })
}

fn ensure_sufficient_balance(from_balance: u128, needed: u128) -> Result<(), TransferApplyError> {
    if from_balance < needed {
        return Err(TransferApplyError::InsufficientBalance {
            balance: from_balance,
            needed,
        });
    }
    Ok(())
}

fn credited_balance(tx: &TransferTx, to_balance: u128) -> Result<u128, TransferApplyError> {
    to_balance
        .checked_add(tx.amount)
        .ok_or_else(|| TransferApplyError::ReceiverBalanceOverflow {
            receiver: tx.to.clone(),
            balance: to_balance,
            amount: tx.amount,
        })
}
