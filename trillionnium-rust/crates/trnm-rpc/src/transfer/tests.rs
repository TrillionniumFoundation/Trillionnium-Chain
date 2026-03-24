use super::*;

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use hex;
use serde_json;
use trnm_types::{TransferTx, TransferTxValidationError};

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
