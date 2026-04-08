use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use trnm_types::{TransferTx, TransferTxValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransferRequest {
    pub tx: TransferTx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransferResponse {
    pub accepted: bool,
    pub from_balance: u128,
    pub to_balance: u128,
    pub next_nonce: u64,
}

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

#[derive(Debug, Default)]
pub struct InMemoryTransferLedger {
    balances: BTreeMap<String, u128>,
    nonces: BTreeMap<String, u64>,
}

impl InMemoryTransferLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_account(&mut self, addr: impl Into<String>, balance: u128, next_nonce: u64) {
        let addr = addr.into();
        self.balances.insert(addr.clone(), balance);
        self.nonces.insert(addr, next_nonce);
    }

    pub fn balance_of(&self, addr: &str) -> u128 {
        self.balances.get(addr).copied().unwrap_or(0)
    }

    pub fn next_nonce_of(&self, addr: &str) -> u64 {
        self.nonces.get(addr).copied().unwrap_or(0)
    }

    pub fn apply_transfer(
        &mut self,
        req: SubmitTransferRequest,
    ) -> Result<SubmitTransferResponse, TransferApplyError> {
        let tx = req.tx;
        tx.validate_basic().map_err(TransferApplyError::Basic)?;

        let expected_nonce = self.next_nonce_of(&tx.from);
        if tx.nonce != expected_nonce {
            return Err(TransferApplyError::NonceRollback {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        let needed = checked_total_charge(tx.amount, tx.fee).ok_or(
            TransferApplyError::AmountFeeOverflow {
                amount: tx.amount,
                fee: tx.fee,
            },
        )?;
        let from_balance = self.balance_of(&tx.from);
        if from_balance < needed {
            return Err(TransferApplyError::InsufficientBalance {
                balance: from_balance,
                needed,
            });
        }

        let to_balance = self.balance_of(&tx.to);
        let new_from = from_balance - needed;
        let new_to = to_balance.checked_add(tx.amount).ok_or_else(|| {
            TransferApplyError::ReceiverBalanceOverflow {
                receiver: tx.to.clone(),
                balance: to_balance,
                amount: tx.amount,
            }
        })?;

        self.balances.insert(tx.from.clone(), new_from);
        self.balances.insert(tx.to.clone(), new_to);
        self.nonces.insert(tx.from.clone(), expected_nonce + 1);

        Ok(SubmitTransferResponse {
            accepted: true,
            from_balance: new_from,
            to_balance: new_to,
            next_nonce: expected_nonce + 1,
        })
    }
}

pub fn compute_tx_hash(tx: &TransferTx) -> String {
    let mut h = Sha256::new();
    h.update(tx.from.as_bytes());
    h.update([0]);
    h.update(tx.to.as_bytes());
    h.update([0]);
    h.update(tx.amount.to_le_bytes());
    h.update(tx.fee.to_le_bytes());
    h.update(tx.nonce.to_le_bytes());
    h.update(tx.signature.as_bytes());
    format!("0x{}", hex::encode(h.finalize()))
}

fn tx_status_at_ingress(
    txs: &BTreeMap<String, TxLifecycleRecord>,
    tx_hash: &str,
) -> Option<TxStatus> {
    txs.get(tx_hash).map(|record| record.status.clone())
}

fn checked_total_charge(amount: u128, fee: u128) -> Option<u128> {
    amount.checked_add(fee)
}

fn checked_ingress_fee_boundary_charge(tx: &TransferTx) -> Option<u128> {
    checked_total_charge(tx.amount, tx.fee)
}

fn ingress_fee_boundary_allows(tx: &TransferTx) -> bool {
    checked_ingress_fee_boundary_charge(tx).is_some()
}

#[cfg(test)]
fn is_exact_ingress_fee_boundary_charge(tx: &TransferTx) -> bool {
    checked_ingress_fee_boundary_charge(tx) == Some(u128::MAX)
}

fn has_ingress_accounting_overflow(tx: &TransferTx) -> bool {
    !ingress_fee_boundary_allows(tx)
}

pub fn submit_tx(
    txs: &mut BTreeMap<String, TxLifecycleRecord>,
    tx: TransferTx,
    now_unix_ms: u128,
) -> SendTxResponse {
    let tx_hash = compute_tx_hash(&tx);

    // Ingress hardening: reject obviously invalid txs before entering pending pool.
    if tx.validate_basic().is_err() || has_ingress_accounting_overflow(&tx) {
        return SendTxResponse {
            tx_hash,
            status: TxStatus::Fail,
        };
    }

    if let Some(status) = tx_status_at_ingress(txs, &tx_hash) {
        return SendTxResponse { tx_hash, status };
    }

    txs.insert(
        tx_hash.clone(),
        TxLifecycleRecord {
            tx_hash: tx_hash.clone(),
            tx,
            status: TxStatus::Pending,
            error: None,
            submitted_at_unix_ms: now_unix_ms,
            updated_at_unix_ms: now_unix_ms,
        },
    );

    SendTxResponse {
        tx_hash,
        status: TxStatus::Pending,
    }
}

pub fn get_tx(
    txs: &mut BTreeMap<String, TxLifecycleRecord>,
    ledger: &mut InMemoryTransferLedger,
    tx_hash: &str,
    now_unix_ms: u128,
) -> Result<GetTxResponse, GetTxError> {
    let Some(rec) = txs.get_mut(tx_hash) else {
        return Err(GetTxError::NotFound(tx_hash.to_string()));
    };

    if rec.status == TxStatus::Pending {
        let req = SubmitTransferRequest { tx: rec.tx.clone() };
        match ledger.apply_transfer(req) {
            Ok(_) => {
                rec.status = TxStatus::Committed;
                rec.error = None;
                rec.updated_at_unix_ms = now_unix_ms;
            }
            Err(err) => {
                rec.status = TxStatus::Fail;
                rec.error = Some(err.to_string());
                rec.updated_at_unix_ms = now_unix_ms;
            }
        }
    }

    Ok(GetTxResponse {
        tx_hash: rec.tx_hash.clone(),
        status: rec.status.clone(),
        error: rec.error.clone(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxStatus {
    Pending,
    Committed,
    #[serde(alias = "failed", alias = "error")]
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendTxResponse {
    pub tx_hash: String,
    pub status: TxStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTxResponse {
    pub tx_hash: String,
    pub status: TxStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetTxError {
    NotFound(String),
}

impl std::fmt::Display for GetTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(h) => write!(f, "tx not found: {}", h),
        }
    }
}

impl std::error::Error for GetTxError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxLifecycleRecord {
    pub tx_hash: String,
    pub tx: TransferTx,
    pub status: TxStatus,
    pub error: Option<String>,
    pub submitted_at_unix_ms: u128,
    pub updated_at_unix_ms: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const ALICE_SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const BOB_SK_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn address_from_secret_hex(secret_hex: &str) -> String {
        let bytes = hex::decode(secret_hex).unwrap();
        let key_bytes: [u8; 32] = bytes.as_slice().try_into().unwrap();
        let sk = SigningKey::from_bytes(&key_bytes);
        TransferTx::derive_address_from_ed25519_pubkey(sk.verifying_key().as_bytes())
    }

    fn tx(
        from: &str,
        to: &str,
        amount: u128,
        fee: u128,
        nonce: u64,
        signer_secret_hex: &str,
    ) -> SubmitTransferRequest {
        let mut inner = TransferTx {
            from: from.into(),
            to: to.into(),
            amount,
            fee,
            nonce,
            signature: String::new(),
        };
        inner.signature = inner.sign_with_private_key_hex(signer_secret_hex).unwrap();
        SubmitTransferRequest { tx: inner }
    }

    fn transfer_tx(
        from: &str,
        to: &str,
        amount: u128,
        fee: u128,
        nonce: u64,
        signer_secret_hex: &str,
    ) -> TransferTx {
        tx(from, to, amount, fee, nonce, signer_secret_hex).tx
    }

    #[test]
    fn apply_transfer_success() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 0);
        ledger.set_account(bob.clone(), 5, 0);

        let out = ledger
            .apply_transfer(tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX))
            .unwrap();

        assert!(out.accepted);
        assert_eq!(ledger.balance_of(&alice), 89);
        assert_eq!(ledger.balance_of(&bob), 15);
        assert_eq!(ledger.next_nonce_of(&alice), 1);
    }

    #[test]
    fn reject_nonce_rollback() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 1);

        let err = ledger
            .apply_transfer(tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::NonceRollback {
                expected: 1,
                got: 0
            }
        );
    }

    #[test]
    fn reject_insufficient_balance() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 10, 0);

        let err = ledger
            .apply_transfer(tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::InsufficientBalance {
                balance: 10,
                needed: 11
            }
        );
    }

    #[test]
    fn reject_amount_plus_fee_overflow() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), u128::MAX, 0);
        ledger.set_account(bob.clone(), 0, 0);

        let err = ledger
            .apply_transfer(tx(&alice, &bob, u128::MAX, 1, 0, ALICE_SK_HEX))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::AmountFeeOverflow {
                amount: u128::MAX,
                fee: 1
            }
        );
    }

    #[test]
    fn reject_receiver_credit_overflow() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 20, 0);
        ledger.set_account(bob.clone(), u128::MAX, 0);

        let err = ledger
            .apply_transfer(tx(&alice, &bob, 1, 0, 0, ALICE_SK_HEX))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::ReceiverBalanceOverflow {
                receiver: bob,
                balance: u128::MAX,
                amount: 1
            }
        );
    }

    #[test]
    fn reject_missing_signature() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 0);

        let err = ledger
            .apply_transfer(SubmitTransferRequest {
                tx: TransferTx {
                    from: alice,
                    to: bob,
                    amount: 1,
                    fee: 0,
                    nonce: 0,
                    signature: String::new(),
                },
            })
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::Basic(TransferTxValidationError::MissingSignature)
        );
    }

    #[test]
    fn reject_invalid_signature() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 0);

        let err = ledger
            .apply_transfer(tx(&alice, &bob, 1, 0, 0, BOB_SK_HEX))
            .unwrap_err();
        assert_eq!(
            err,
            TransferApplyError::Basic(TransferTxValidationError::InvalidSignature)
        );
    }

    #[test]
    fn reject_replay_nonce_even_with_valid_signature() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 0);
        ledger.set_account(bob.clone(), 0, 0);

        ledger
            .apply_transfer(tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX))
            .unwrap();

        let replay_err = ledger
            .apply_transfer(tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX))
            .unwrap_err();
        assert_eq!(
            replay_err,
            TransferApplyError::NonceRollback {
                expected: 1,
                got: 0
            }
        );
    }

    #[test]
    fn submit_tx_rejects_invalid_signature_at_ingress() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut txs = BTreeMap::new();
        let out = submit_tx(
            &mut txs,
            TransferTx {
                from: alice,
                to: bob,
                amount: 1,
                fee: 0,
                nonce: 0,
                signature: "not-a-valid-signature".into(),
            },
            100,
        );

        assert_eq!(out.status, TxStatus::Fail);
        assert!(txs.is_empty());
    }

    #[test]
    fn submit_tx_rejects_amount_plus_fee_overflow_at_ingress() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut txs = BTreeMap::new();
        let out = submit_tx(
            &mut txs,
            transfer_tx(&alice, &bob, u128::MAX, 1, 0, ALICE_SK_HEX),
            100,
        );

        assert_eq!(out.status, TxStatus::Fail);
        assert!(txs.is_empty());
    }

    #[test]
    fn submit_tx_accepts_amount_max_boundary_when_fee_is_zero() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut txs = BTreeMap::new();
        let out = submit_tx(
            &mut txs,
            transfer_tx(&alice, &bob, u128::MAX, 0, 0, ALICE_SK_HEX),
            100,
        );

        assert_eq!(out.status, TxStatus::Pending);
        assert_eq!(txs.len(), 1);
    }

    #[test]
    fn submit_tx_rejects_fee_max_boundary_when_amount_is_nonzero() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut txs = BTreeMap::new();
        let out = submit_tx(
            &mut txs,
            transfer_tx(&alice, &bob, 1, u128::MAX, 0, ALICE_SK_HEX),
            100,
        );

        assert_eq!(out.status, TxStatus::Fail);
        assert!(txs.is_empty());
    }

    #[test]
    fn ingress_fee_boundary_allows_fee_max_boundary_when_amount_is_zero() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);
        let zero_amount_boundary_fee = transfer_tx(&alice, &bob, 0, u128::MAX, 0, ALICE_SK_HEX);

        assert!(ingress_fee_boundary_allows(&zero_amount_boundary_fee));
        assert!(!has_ingress_accounting_overflow(&zero_amount_boundary_fee));
    }

    #[test]
    fn submit_tx_reuses_pending_status_for_exact_amount_plus_fee_u128_boundary() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);
        let tx = transfer_tx(&alice, &bob, u128::MAX - 1, 1, 0, ALICE_SK_HEX);

        let mut txs = BTreeMap::new();
        let first = submit_tx(&mut txs, tx.clone(), 100);
        let second = submit_tx(&mut txs, tx, 101);

        assert_eq!(first.status, TxStatus::Pending);
        assert_eq!(second.status, TxStatus::Pending);
        assert_eq!(first.tx_hash, second.tx_hash);
        assert_eq!(txs.len(), 1);
    }

    #[test]
    fn submit_tx_accepts_exact_amount_plus_fee_u128_boundary() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut txs = BTreeMap::new();
        let out = submit_tx(
            &mut txs,
            transfer_tx(&alice, &bob, u128::MAX - 1, 1, 0, ALICE_SK_HEX),
            100,
        );

        assert_eq!(out.status, TxStatus::Pending);
        assert_eq!(txs.len(), 1);
    }

    #[test]
    fn ingress_accounting_overflow_allows_exact_u128_boundary_charge() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        assert!(!has_ingress_accounting_overflow(&transfer_tx(
            &alice,
            &bob,
            u128::MAX - 1,
            1,
            0,
            ALICE_SK_HEX,
        )));
        assert!(has_ingress_accounting_overflow(&transfer_tx(
            &alice,
            &bob,
            u128::MAX,
            1,
            0,
            ALICE_SK_HEX,
        )));
    }

    #[test]
    fn ingress_fee_boundary_marks_exact_u128_charge_without_flagging_overflow() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);
        let exact_boundary = transfer_tx(&alice, &bob, u128::MAX - 1, 1, 0, ALICE_SK_HEX);

        assert!(is_exact_ingress_fee_boundary_charge(&exact_boundary));
        assert!(!has_ingress_accounting_overflow(&exact_boundary));
    }

    #[test]
    fn tx_lifecycle_pending_to_committed() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 0);
        ledger.set_account(bob.clone(), 0, 0);
        let mut txs = BTreeMap::new();

        let submit = submit_tx(
            &mut txs,
            transfer_tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX),
            100,
        );
        assert_eq!(submit.status, TxStatus::Pending);

        let got = get_tx(&mut txs, &mut ledger, &submit.tx_hash, 120).unwrap();
        assert_eq!(got.status, TxStatus::Committed);
        assert!(got.error.is_none());
    }

    #[test]
    fn tx_lifecycle_pending_to_fail_nonce_conflict() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 1);
        ledger.set_account(bob.clone(), 0, 0);
        let mut txs = BTreeMap::new();

        let submit = submit_tx(
            &mut txs,
            transfer_tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX),
            100,
        );
        let got = get_tx(&mut txs, &mut ledger, &submit.tx_hash, 120).unwrap();
        assert_eq!(got.status, TxStatus::Fail);
        assert!(got
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("nonce rollback/replay"));
    }

    #[test]
    fn submit_tx_duplicate_preserves_existing_fail_status() {
        let alice = address_from_secret_hex(ALICE_SK_HEX);
        let bob = address_from_secret_hex(BOB_SK_HEX);

        let mut ledger = InMemoryTransferLedger::new();
        ledger.set_account(alice.clone(), 100, 1);
        ledger.set_account(bob.clone(), 0, 0);
        let mut txs = BTreeMap::new();
        let tx = transfer_tx(&alice, &bob, 10, 1, 0, ALICE_SK_HEX);

        let submit = submit_tx(&mut txs, tx.clone(), 100);
        let failed = get_tx(&mut txs, &mut ledger, &submit.tx_hash, 120).unwrap();
        assert_eq!(failed.status, TxStatus::Fail);

        let duplicate = submit_tx(&mut txs, tx, 130);
        assert_eq!(duplicate.tx_hash, submit.tx_hash);
        assert_eq!(duplicate.status, TxStatus::Fail);
    }

    #[test]
    fn get_tx_not_found() {
        let mut ledger = InMemoryTransferLedger::new();
        let mut txs = BTreeMap::new();
        let err = get_tx(&mut txs, &mut ledger, "0x404", 100).unwrap_err();
        assert_eq!(err, GetTxError::NotFound("0x404".to_string()));
    }

    #[test]
    fn tx_status_parser_accepts_legacy_failed_aliases() {
        let failed: TxStatus = serde_json::from_str("\"failed\"").unwrap();
        let error: TxStatus = serde_json::from_str("\"error\"").unwrap();
        assert_eq!(failed, TxStatus::Fail);
        assert_eq!(error, TxStatus::Fail);
    }
}
