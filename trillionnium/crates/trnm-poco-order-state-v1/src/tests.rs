use std::{fs, path::Path};

use rusqlite::{params, Connection};
use tempfile::TempDir;
use trnm_poco_order_finality_verifier_v1 as order_finality;

use crate::{
    store::{issue_test_order_state_write_permit_v1, OrderStateWriteFaultV1},
    verify_order_state_membership_proof_v1, OrderStateErrorCodeV1, OrderStateHeadPinV1,
    PocoOrderStateStoreV1, TestOrderStateWritePermitV1,
};

const STORE_ID: [u8; 32] = [0xa1; 32];
const GENESIS_HASH: [u8; 32] = [0x11; 32];
const STACK_PROFILE_HASH: [u8; 32] = [0x22; 32];

fn path(temp: &TempDir) -> std::path::PathBuf {
    temp.path().join("order-state.sqlite")
}

fn initialize(anchor_height: u64) -> (TempDir, PocoOrderStateStoreV1, OrderStateHeadPinV1) {
    let temp = tempfile::tempdir().expect("temporary Order-state directory");
    let store = PocoOrderStateStoreV1::initialize_new(path(&temp), STORE_ID, anchor_height)
        .expect("initialize Order-state store");
    let pin = store.fresh_head_pin_v1().expect("fresh genesis pin");
    (temp, store, pin)
}

#[test]
fn zero_height_anchor_is_rejected_before_file_creation() {
    let temp = tempfile::tempdir().expect("zero-height tempdir");
    assert_eq!(
        PocoOrderStateStoreV1::initialize_new(path(&temp), STORE_ID, 0)
            .expect_err("zero-height anchor rejects")
            .code(),
        OrderStateErrorCodeV1::InvalidContext
    );
    assert!(!path(&temp).exists());
}

fn permit(
    pin: &OrderStateHeadPinV1,
    candidate_height: u64,
    seed: u8,
) -> TestOrderStateWritePermitV1 {
    issue_test_order_state_write_permit_v1(
        STORE_ID,
        pin.height(),
        pin.state_root(),
        pin.history_checksum(),
        "trnm-order-state-test",
        GENESIS_HASH,
        1,
        STACK_PROFILE_HASH,
        candidate_height,
        [seed; 32],
        [seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
        pin.height() + 1,
    )
    .expect("issue test-only terminal-derived permit")
}

#[test]
fn fresh_create_reopen_membership_and_exact_retry() {
    let (temp, store, anchor) = initialize(6);
    let first = permit(&anchor, 6, 0x31);
    let retry = permit(&anchor, 6, 0x31);
    let receipt = store
        .create_test_global_execution_binding_v1(first)
        .expect("create exact tag-50 value");
    assert!(!receipt.is_replay());
    assert_eq!(receipt.pin().height(), 7);
    assert_eq!(receipt.proof().height(), 7);
    assert_eq!(receipt.proof().state_root(), receipt.pin().state_root());
    assert!(verify_order_state_membership_proof_v1(receipt.proof()));

    let reopened =
        PocoOrderStateStoreV1::open_existing_pinned(path(&temp), STORE_ID, receipt.pin())
            .expect("fresh pinned reopen");
    let proof = reopened
        .prove_membership_v1(7, receipt.proof().state_key())
        .expect("fresh historical membership proof");
    assert_eq!(&proof, receipt.proof());
    let replay = reopened
        .create_test_global_execution_binding_v1(retry)
        .expect("exact response-loss retry");
    assert!(replay.is_replay());
    assert_eq!(replay.pin(), receipt.pin());
    assert_eq!(replay.proof(), receipt.proof());
}

#[test]
fn authoritative_receipt_plus_later_finality_issues_exact_binding_carrier() {
    let (_temp, store, anchor) = initialize(6);
    let receipt = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x31))
        .expect("authoritative tag-50 writer creates exact successor");
    let order = order_finality::issue_test_order_finality_with_ancestor_v1(
        "trnm-order-state-test",
        GENESIS_HASH,
        1,
        STACK_PROFILE_HASH,
        1,
        receipt.pin().height(),
        [0xf1; 32],
        receipt.pin().state_root(),
        6,
        [0x31; 32],
    )
    .expect("test-only later finality retains exact candidate ancestry");
    let binding = receipt
        .verify_later_order_finality_v1(&order)
        .expect("writer receipt membership under later finality issues carrier");
    assert_eq!(binding.finalized_height(), receipt.pin().height());
    assert_eq!(
        binding.finalized_post_state_root(),
        receipt.pin().state_root()
    );
    assert_eq!(binding.candidate_height(), 6);
    assert_eq!(binding.candidate_block_id(), [0x31; 32]);
    assert_eq!(binding.candidate_composite_root(), [0x32; 32]);
    assert_eq!(binding.final_execution_root(), [0x33; 32]);
    assert_eq!(binding.binding_state_key(), receipt.proof().state_key());

    let foreign_root = order_finality::issue_test_order_finality_with_ancestor_v1(
        "trnm-order-state-test",
        GENESIS_HASH,
        1,
        STACK_PROFILE_HASH,
        1,
        receipt.pin().height(),
        [0xf1; 32],
        [0xee; 32],
        6,
        [0x31; 32],
    )
    .expect("synthetic foreign-root finality carrier");
    assert!(receipt
        .verify_later_order_finality_v1(&foreign_root)
        .is_err());

    let foreign_ancestor = order_finality::issue_test_order_finality_with_ancestor_v1(
        "trnm-order-state-test",
        GENESIS_HASH,
        1,
        STACK_PROFILE_HASH,
        1,
        receipt.pin().height(),
        [0xf1; 32],
        receipt.pin().state_root(),
        6,
        [0x41; 32],
    )
    .expect("synthetic foreign-ancestry finality carrier");
    assert!(receipt
        .verify_later_order_finality_v1(&foreign_ancestor)
        .is_err());
}

#[test]
fn duplicate_fork_and_stale_parent_fail_closed() {
    let (_temp, store, anchor) = initialize(6);
    let first = permit(&anchor, 6, 0x41);
    let fork = permit(&anchor, 6, 0x51);
    let first_receipt = store
        .create_test_global_execution_binding_v1(first)
        .expect("first branch commits");
    assert_eq!(
        store
            .create_test_global_execution_binding_v1(fork)
            .expect_err("different write at occupied target is a fork")
            .code(),
        OrderStateErrorCodeV1::Fork
    );

    let second = permit(first_receipt.pin(), 7, 0x61);
    let second_receipt = store
        .create_test_global_execution_binding_v1(second)
        .expect("second successor commits");
    let late_replay = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x41))
        .expect("exact retry remains deterministic after a later successor");
    assert!(late_replay.is_replay());
    assert_eq!(late_replay.pin(), first_receipt.pin());
    assert_eq!(late_replay.observed_head_pin(), second_receipt.pin());
    assert_eq!(late_replay.proof(), first_receipt.proof());

    let duplicate = issue_test_order_state_write_permit_v1(
        STORE_ID,
        second_receipt.pin().height(),
        second_receipt.pin().state_root(),
        second_receipt.pin().history_checksum(),
        "trnm-order-state-test",
        GENESIS_HASH,
        1,
        STACK_PROFILE_HASH,
        6,
        [0x41; 32],
        [0x42; 32],
        [0x43; 32],
        second_receipt.pin().height() + 1,
    )
    .expect("same immutable object can derive later inert material");
    assert_eq!(
        store
            .create_test_global_execution_binding_v1(duplicate)
            .expect_err("create-once key cannot be inserted twice")
            .code(),
        OrderStateErrorCodeV1::DuplicateKey
    );

    let stale = issue_test_order_state_write_permit_v1(
        STORE_ID,
        second_receipt.pin().height(),
        [0x99; 32],
        second_receipt.pin().history_checksum(),
        "trnm-order-state-test",
        GENESIS_HASH,
        1,
        STACK_PROFILE_HASH,
        8,
        [0x71; 32],
        [0x72; 32],
        [0x73; 32],
        second_receipt.pin().height() + 1,
    )
    .expect("test permit can name a stale parent root");
    assert_eq!(
        store
            .create_test_global_execution_binding_v1(stale)
            .expect_err("wrong current parent rejects")
            .code(),
        OrderStateErrorCodeV1::StaleParent
    );

    let stale_checksum = issue_test_order_state_write_permit_v1(
        STORE_ID,
        second_receipt.pin().height(),
        second_receipt.pin().state_root(),
        [0x98; 32],
        "trnm-order-state-test",
        GENESIS_HASH,
        1,
        STACK_PROFILE_HASH,
        8,
        [0x81; 32],
        [0x82; 32],
        [0x83; 32],
        second_receipt.pin().height() + 1,
    )
    .expect("test permit can name a stale parent history checksum");
    assert_eq!(
        store
            .create_test_global_execution_binding_v1(stale_checksum)
            .expect_err("wrong current parent history checksum rejects")
            .code(),
        OrderStateErrorCodeV1::StaleParent
    );
}

#[test]
fn precommit_rollback_and_postcommit_response_loss_are_exact() {
    let (_temp, store, anchor) = initialize(6);
    let before = permit(&anchor, 6, 0x21);
    assert_eq!(
        store
            .create_with_fault_v1(before, OrderStateWriteFaultV1::BeforeCommit)
            .expect_err("injected precommit loss")
            .code(),
        OrderStateErrorCodeV1::CommitUncertain
    );
    assert_eq!(
        store.fresh_head_pin_v1().expect("head after rollback"),
        anchor
    );

    let after = permit(&anchor, 6, 0x21);
    assert_eq!(
        store
            .create_with_fault_v1(after, OrderStateWriteFaultV1::AfterCommitBeforeReturn)
            .expect_err("injected postcommit response loss")
            .code(),
        OrderStateErrorCodeV1::CommitUncertain
    );
    let committed = store.fresh_head_pin_v1().expect("committed head survives");
    assert_eq!(committed.height(), 7);
    let replay = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x21))
        .expect("retry reauthenticates exact committed target");
    assert!(replay.is_replay());
    assert_eq!(replay.pin(), &committed);
}

#[test]
fn nested_value_and_leaf_projection_tamper_fail_closed() {
    let (temp, store, anchor) = initialize(6);
    let receipt = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x31))
        .expect("create fixture");
    drop(store);
    let connection = Connection::open(path(&temp)).expect("open raw tamper connection");
    connection
        .execute(
            "UPDATE order_state_leaves_v1 SET value_bytes=x'01' WHERE state_key=?1",
            params![&receipt.proof().state_key()[..]],
        )
        .expect("tamper live value");
    drop(connection);
    let error = PocoOrderStateStoreV1::open_existing_pinned(path(&temp), STORE_ID, receipt.pin())
        .expect_err("fresh reopen rejects leaf projection tamper");
    assert_eq!(error.code(), OrderStateErrorCodeV1::StoreTamper);

    let history_temp = tempfile::tempdir().expect("history tamper tempdir");
    let history_store = PocoOrderStateStoreV1::initialize_new(path(&history_temp), STORE_ID, 6)
        .expect("initialize history fixture");
    let history_anchor = history_store
        .fresh_head_pin_v1()
        .expect("history fixture anchor");
    let history_receipt = history_store
        .create_test_global_execution_binding_v1(permit(&history_anchor, 6, 0x51))
        .expect("create history fixture");
    drop(history_store);
    let connection = Connection::open(path(&history_temp)).expect("open history tamper connection");
    connection
        .execute(
            "UPDATE order_state_history_v1 SET value_bytes=x'01' WHERE height=?1",
            params![&history_receipt.pin().height().to_be_bytes()[..]],
        )
        .expect("tamper canonical history value");
    drop(connection);
    assert_eq!(
        PocoOrderStateStoreV1::open_existing_pinned(
            path(&history_temp),
            STORE_ID,
            history_receipt.pin(),
        )
        .expect_err("fresh reopen rejects nested history value tamper")
        .code(),
        OrderStateErrorCodeV1::StoreTamper
    );
}

#[test]
fn partial_history_row_and_schema_tamper_fail_closed() {
    let (temp, store, anchor) = initialize(6);
    let receipt = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x31))
        .expect("create fixture");
    drop(store);
    let connection = Connection::open(path(&temp)).expect("open raw tamper connection");
    connection
        .execute(
            "DELETE FROM order_state_leaves_v1 WHERE state_key=?1",
            params![&receipt.proof().state_key()[..]],
        )
        .expect("delete one half of atomic projection");
    drop(connection);
    assert_eq!(
        PocoOrderStateStoreV1::open_existing_pinned(path(&temp), STORE_ID, receipt.pin())
            .expect_err("partial history/live projection rejects")
            .code(),
        OrderStateErrorCodeV1::StoreTamper
    );

    let other = tempfile::tempdir().expect("schema tamper tempdir");
    let other_store = PocoOrderStateStoreV1::initialize_new(path(&other), STORE_ID, 6)
        .expect("initialize schema fixture");
    let pin = other_store.fresh_head_pin_v1().expect("schema fixture pin");
    drop(other_store);
    let connection = Connection::open(path(&other)).expect("open schema tamper connection");
    connection
        .execute_batch("CREATE TABLE injected(extra INTEGER) STRICT")
        .expect("inject schema table");
    drop(connection);
    assert_eq!(
        PocoOrderStateStoreV1::open_existing_pinned(path(&other), STORE_ID, &pin)
            .expect_err("schema extension rejects")
            .code(),
        OrderStateErrorCodeV1::SchemaMismatch
    );
}

#[test]
fn coherent_logical_rollback_requires_and_rejects_against_trusted_pin() {
    let (temp, store, anchor) = initialize(6);
    let first = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x31))
        .expect("first write");
    let second = store
        .create_test_global_execution_binding_v1(permit(first.pin(), 7, 0x41))
        .expect("second write");
    let first_at_second = store
        .prove_membership_v1(second.pin().height(), first.proof().state_key())
        .expect("first leaf remains provable in two-leaf tree");
    let second_at_second = store
        .prove_membership_v1(second.pin().height(), second.proof().state_key())
        .expect("second leaf is provable in two-leaf tree");
    assert!(verify_order_state_membership_proof_v1(&first_at_second));
    assert!(verify_order_state_membership_proof_v1(&second_at_second));
    let trusted_terminal = second.pin().clone();
    let first_pin = first.pin().clone();
    let second_key = second.proof().state_key();
    drop(store);

    let connection = Connection::open(path(&temp)).expect("open rollback connection");
    let transaction = connection
        .unchecked_transaction()
        .expect("begin rollback simulation");
    transaction
        .execute(
            "DELETE FROM order_state_leaves_v1 WHERE state_key=?1",
            params![&second_key[..]],
        )
        .expect("remove rolled-back leaf");
    transaction
        .execute(
            "DELETE FROM order_state_history_v1 WHERE height=?1",
            params![&trusted_terminal.height().to_be_bytes()[..]],
        )
        .expect("remove rolled-back history");
    transaction
        .execute(
            "UPDATE order_state_metadata_v1 SET head_height=?1,head_root=?2,head_checksum=?3 WHERE singleton=1",
            params![
                &first_pin.height().to_be_bytes()[..],
                &first_pin.state_root()[..],
                &first_pin.history_checksum()[..],
            ],
        )
        .expect("roll metadata back coherently");
    transaction.commit().expect("commit rollback simulation");
    drop(connection);

    assert_eq!(
        PocoOrderStateStoreV1::open_existing_pinned(path(&temp), STORE_ID, &trusted_terminal,)
            .expect_err("trusted terminal pin rejects coherent store rollback")
            .code(),
        OrderStateErrorCodeV1::StoreRollback
    );
}

#[test]
fn sparse_membership_orientation_mutant_rejects() {
    let (_temp, store, anchor) = initialize(6);
    let receipt = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x31))
        .expect("create proof fixture");
    let mut proof = receipt.proof().clone();
    proof.test_flip_sibling_v1(73);
    assert!(!verify_order_state_membership_proof_v1(&proof));
}

#[test]
fn path_and_store_identity_substitution_fail_closed() {
    let (temp, store, anchor) = initialize(6);
    let receipt = store
        .create_test_global_execution_binding_v1(permit(&anchor, 6, 0x31))
        .expect("create identity fixture");
    assert_eq!(
        PocoOrderStateStoreV1::open_existing_pinned(path(&temp), [0xb2; 32], receipt.pin())
            .expect_err("foreign store ID rejects")
            .code(),
        OrderStateErrorCodeV1::StoreTamper
    );
    drop(store);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = temp.path().join("order-state-link.sqlite");
        symlink(path(&temp), &link).expect("create test symlink");
        assert_eq!(
            PocoOrderStateStoreV1::open_existing_pinned(link, STORE_ID, receipt.pin())
                .expect_err("top-level database symlink rejects")
                .code(),
            OrderStateErrorCodeV1::StoreUnavailable
        );
    }
}

#[test]
fn no_sidecar_is_accepted_on_reopen() {
    let (temp, store, pin) = initialize(6);
    drop(store);
    let sidecar = format!("{}-wal", path(&temp).display());
    fs::write(&sidecar, b"not a sqlite wal").expect("create sidecar control");
    assert_eq!(
        PocoOrderStateStoreV1::open_existing_pinned(path(&temp), STORE_ID, &pin)
            .expect_err("sidecar rejects before immutable read")
            .code(),
        OrderStateErrorCodeV1::StoreUnavailable
    );
    fs::remove_file(sidecar).expect("remove test sidecar");
    assert!(Path::new(&path(&temp)).exists());
}
