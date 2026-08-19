use std::{fs, path::Path};

use rusqlite::Connection;
use tempfile::TempDir;

use crate::*;

const NEGATIVE_CASES: &[&str] = &[
    "wrong-schema-version",
    "wrong-protocol-context",
    "zero-store-id",
    "unsorted-initial-objects",
    "duplicate-initial-object",
    "wrong-resource-class-unit",
    "zero-price-denominator",
    "price-minimum-above-maximum",
    "unsorted-resource-prices",
    "duplicate-fee-destination",
    "fee-splits-do-not-sum-to-one",
    "missing-remainder-destination",
    "fee-destination-object-absent",
    "wrong-transaction-id",
    "wrong-block-id",
    "duplicate-transaction-id",
    "transaction-index-gap",
    "empty-block",
    "too-many-transactions",
    "undeclared-read",
    "undeclared-write",
    "duplicate-read-object",
    "duplicate-write-object",
    "fee-payer-equals-program-object",
    "fee-destination-used-as-payer",
    "stale-parent-height",
    "stale-parent-block-id",
    "stale-parent-state-root",
    "fee-limit-exceeded",
    "fee-payer-insufficient",
    "object-arithmetic-overflow",
    "transfer-source-insufficient",
    "object-version-overflow",
    "state-row-tamper",
    "journal-row-tamper",
    "metadata-root-tamper",
    "schema-drift",
    "sqlite-sidecar-present",
    "foreign-store-receipt",
];

const POSITIVE_CASES: &[&str] = &[
    "independent-transactions-zero-retry",
    "conflicting-read-version-retries-once",
    "canonical-index-order-serial-equivalence",
    "success-receipt-complete",
    "reverted-receipt-complete",
    "out-of-resource-receipt-complete",
    "four-resource-classes-metered",
    "per-transaction-fee-deltas-conserve",
    "block-end-destination-credit-once",
    "exact-block-replay",
    "immutable-reopen-confirms-roots",
    "sorted-object-state-roundtrip",
];

const CRASH_CASES: &[&str] = &[
    "not-applied-ack-lost-preserves-parent",
    "applied-ack-lost-reopens-target",
    "third-state-fences-current-process",
    "third-state-fences-reopen",
    "exact-replay-after-applied-ack-lost",
    "tamper-after-reopen-fails-closed",
];

fn h(byte: u8) -> Hash32V1 {
    Hash32V1([byte; 32])
}
fn oid(kind: u16, byte: u8) -> TypedObjectIdV1 {
    TypedObjectIdV1 {
        object_kind: kind,
        object_id: [byte; 32],
    }
}
fn object(id: TypedObjectIdV1, value: u128) -> ObjectStateV1 {
    ObjectStateV1 {
        schema_version: 1,
        object_id: id,
        version: 0,
        value,
        closed: false,
    }
}

fn genesis(store_byte: u8) -> MvccFeeGenesisV1 {
    let mut initial_objects = vec![
        object(oid(45, 1), 10_000),
        object(oid(45, 2), 10_000),
        object(oid(45, 3), 100),
        object(oid(45, 4), 200),
        object(oid(45, 5), 300),
        object(oid(46, 10), 0),
        object(oid(46, 11), 0),
    ];
    initial_objects.sort_by_key(|value| value.object_id);
    MvccFeeGenesisV1 {
        schema_version: 1,
        context: ProtocolContextV1 {
            chain_id: b"trnm-test".to_vec(),
            genesis_hash: h(200),
            protocol_id: b"trnm-poco-ai-native-v1".to_vec(),
            protocol_version: 1,
            profile_hash: h(201),
        },
        store_id: h(store_byte),
        initial_height: 10,
        initial_block_id: h(202),
        initial_objects,
        resource_prices: vec![
            ResourcePriceV1 {
                resource_class: 0,
                resource_id: vec![],
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            ResourcePriceV1 {
                resource_class: 2,
                resource_id: vec![],
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            ResourcePriceV1 {
                resource_class: 3,
                resource_id: vec![],
                unit: 1,
                price_numerator: 1,
                price_denominator: 128,
                minimum_charge: 1,
                maximum_charge: 100,
            },
            ResourcePriceV1 {
                resource_class: 7,
                resource_id: vec![],
                unit: 3,
                price_numerator: 1,
                price_denominator: 10,
                minimum_charge: 1,
                maximum_charge: 100,
            },
        ],
        destination_splits: vec![
            FeeDestinationSplitV1 {
                destination: oid(46, 10),
                numerator: 3,
                denominator: 4,
            },
            FeeDestinationSplitV1 {
                destination: oid(46, 11),
                numerator: 1,
                denominator: 4,
            },
        ],
        remainder_destination: oid(46, 11),
    }
}

fn add_tx(
    index: u32,
    payer: TypedObjectIdV1,
    target: TypedObjectIdV1,
    amount: u128,
    limit: u128,
) -> MvccTransactionV1 {
    let mut access = vec![payer, target];
    access.sort_unstable();
    let mut transaction = MvccTransactionV1 {
        schema_version: 1,
        transaction_id: h(0),
        transaction_index: index,
        fee_payer: payer,
        declared_reads: access.clone(),
        declared_writes: access,
        compute_unit_limit: limit,
        max_fee: 1_000,
        program: ObjectProgramV1::Add { target, amount },
    };
    transaction.transaction_id = derive_transaction_id_v1(&transaction).unwrap();
    transaction
}

fn revert_tx(index: u32, payer: TypedObjectIdV1) -> MvccTransactionV1 {
    let mut transaction = MvccTransactionV1 {
        schema_version: 1,
        transaction_id: h(0),
        transaction_index: index,
        fee_payer: payer,
        declared_reads: vec![payer],
        declared_writes: vec![payer],
        compute_unit_limit: 10,
        max_fee: 1_000,
        program: ObjectProgramV1::Revert { error_class: 77 },
    };
    transaction.transaction_id = derive_transaction_id_v1(&transaction).unwrap();
    transaction
}

fn block(
    genesis: &MvccFeeGenesisV1,
    transactions: Vec<MvccTransactionV1>,
    height: u64,
    parent_block: Hash32V1,
    parent_root: Hash32V1,
) -> MvccBlockV1 {
    let mut block = MvccBlockV1 {
        schema_version: 1,
        context: genesis.context.clone(),
        block_id: h(0),
        height,
        expected_parent_height: height - 1,
        expected_parent_block_id: parent_block,
        expected_parent_state_root: parent_root,
        transactions,
    };
    block.block_id = derive_block_id_v1(&block).unwrap();
    block
}

fn path(temp: &TempDir) -> std::path::PathBuf {
    temp.path().join("mvcc.sqlite")
}

#[test]
fn conflicts_outcomes_resources_and_fee_reduction_are_deterministic() {
    let g = genesis(210);
    let temp_a = TempDir::new().unwrap();
    let temp_b = TempDir::new().unwrap();
    let parent_root = derive_state_root_v1(&g.initial_objects).unwrap();
    let transactions = vec![
        add_tx(0, oid(45, 1), oid(45, 3), 5, 100),
        add_tx(1, oid(45, 2), oid(45, 3), 7, 100),
        revert_tx(2, oid(45, 1)),
        add_tx(3, oid(45, 2), oid(45, 4), 99, 1),
    ];
    let candidate = block(&g, transactions, 11, g.initial_block_id, parent_root);
    let store_a = MvccFeeStoreV1::open(path(&temp_a), g.clone()).unwrap();
    let store_b = MvccFeeStoreV1::open(path(&temp_b), g.clone()).unwrap();
    let left = store_a.execute_block(&candidate).unwrap();
    let right = store_b.execute_block(&candidate).unwrap();
    assert_eq!(left.confirmed.receipt(), right.confirmed.receipt());
    let receipt = left.confirmed.receipt();
    assert_eq!(
        receipt
            .receipts
            .iter()
            .map(|value| value.status)
            .collect::<Vec<_>>(),
        vec![
            ReceiptStatusV1::Success,
            ReceiptStatusV1::Success,
            ReceiptStatusV1::Reverted,
            ReceiptStatusV1::OutOfResource
        ]
    );
    assert_eq!(receipt.receipts[0].retry_count, 0);
    assert_eq!(receipt.receipts[1].retry_count, 1);
    assert_eq!(receipt.receipts[1].conflict_set, vec![oid(45, 3)]);
    assert!(receipt
        .receipts
        .iter()
        .all(|value| value.resource_usage.len() == 4
            && !value.read_set.is_empty()
            && !value.write_set.is_empty()));
    assert!(receipt.receipts.iter().all(|value| value
        .fee_deltas
        .iter()
        .map(|delta| delta.amount)
        .sum::<u128>()
        == value.fee_charged));
    assert_eq!(receipt.destination_credits.len(), 2);
    assert_eq!(receipt.destination_credits[0].destination, oid(46, 10));
    assert_eq!(receipt.destination_credits[1].destination, oid(46, 11));
    assert_eq!(
        receipt
            .destination_credits
            .iter()
            .map(|value| value.amount)
            .sum::<u128>(),
        receipt
            .receipts
            .iter()
            .map(|value| value.fee_charged)
            .sum::<u128>()
    );
    let objects = store_a.objects().unwrap();
    assert_eq!(
        objects
            .iter()
            .find(|value| value.object_id == oid(45, 3))
            .unwrap()
            .value,
        112
    );
    assert_eq!(
        objects
            .iter()
            .find(|value| value.object_id == oid(45, 4))
            .unwrap()
            .value,
        200
    );
    assert_eq!(
        objects
            .iter()
            .find(|value| value.object_id == oid(46, 10))
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        objects
            .iter()
            .find(|value| value.object_id == oid(46, 11))
            .unwrap()
            .version,
        1
    );
}

#[test]
fn pre_vote_preview_executes_full_fee_path_without_advancing_the_store() {
    let temporary = TempDir::new().expect("temporary directory");
    let genesis = genesis(120);
    let store = MvccFeeStoreV1::open(path(&temporary), genesis.clone()).expect("open store");
    let before = store.fresh_readback().expect("fresh parent");
    let candidate = block(
        &genesis,
        vec![add_tx(0, oid(45, 1), oid(45, 3), 10, 100)],
        11,
        before.block_id(),
        before.durable_state_root(),
    );
    let preview = store
        .preview_before_vote_v1(&before, &candidate)
        .expect("read-only MVCC preview");
    let after = store.fresh_readback().expect("unchanged parent");
    assert_eq!(before, after);
    assert_eq!(preview.source_height(), before.height());
    assert_eq!(preview.source_state_root(), before.durable_state_root());
    assert_eq!(preview.source_journal_root(), before.durable_journal_root());
    assert_eq!(preview.candidate_receipt().transaction_count, 1);
    assert_ne!(
        preview.candidate_post_state_root(),
        before.durable_state_root()
    );
}

#[test]
fn exact_replay_and_parent_identity_are_fail_closed() {
    let g = genesis(211);
    let temp = TempDir::new().unwrap();
    let store = MvccFeeStoreV1::open(path(&temp), g.clone()).unwrap();
    let candidate = block(
        &g,
        vec![add_tx(0, oid(45, 1), oid(45, 3), 1, 100)],
        11,
        g.initial_block_id,
        derive_state_root_v1(&g.initial_objects).unwrap(),
    );
    let first = store.execute_block(&candidate).unwrap();
    let replay = store.execute_block(&candidate).unwrap();
    assert!(!first.replay && replay.replay);
    assert_eq!(first.confirmed.receipt(), replay.confirmed.receipt());
    let mut stale = candidate.clone();
    stale.block_id = h(44);
    assert_eq!(
        store.execute_block(&stale).unwrap_err().code(),
        MvccFeeErrorCodeV1::StaleParent
    );
    let foreign = genesis(212);
    let foreign_store = MvccFeeStoreV1::open(temp.path().join("foreign.sqlite"), foreign).unwrap();
    assert_eq!(
        foreign_store
            .fresh_confirm(first.confirmed.receipt())
            .unwrap_err()
            .code(),
        MvccFeeErrorCodeV1::InvalidContext
    );
}

#[test]
fn static_access_fee_and_arithmetic_mutants_fail_before_commit() {
    let g = genesis(213);
    let temp = TempDir::new().unwrap();
    let store = MvccFeeStoreV1::open(path(&temp), g.clone()).unwrap();
    let root = derive_state_root_v1(&g.initial_objects).unwrap();
    let mut undeclared = add_tx(0, oid(45, 1), oid(45, 3), 1, 100);
    undeclared.declared_writes = vec![oid(45, 1)];
    undeclared.transaction_id = derive_transaction_id_v1(&undeclared).unwrap();
    let bad = block(&g, vec![undeclared], 11, g.initial_block_id, root);
    assert_eq!(
        store.execute_block(&bad).unwrap_err().code(),
        MvccFeeErrorCodeV1::UndeclaredAccess
    );
    let mut fee = add_tx(0, oid(45, 1), oid(45, 3), 1, 100);
    fee.max_fee = 1;
    fee.transaction_id = derive_transaction_id_v1(&fee).unwrap();
    let bad = block(&g, vec![fee], 11, g.initial_block_id, root);
    assert_eq!(
        store.execute_block(&bad).unwrap_err().code(),
        MvccFeeErrorCodeV1::FeeLimitExceeded
    );
    let mut overflow_genesis = g.clone();
    overflow_genesis
        .initial_objects
        .iter_mut()
        .find(|value| value.object_id == oid(45, 3))
        .unwrap()
        .value = u128::MAX;
    let overflow_store = MvccFeeStoreV1::open(
        temp.path().join("overflow.sqlite"),
        overflow_genesis.clone(),
    )
    .unwrap();
    let bad = block(
        &overflow_genesis,
        vec![add_tx(0, oid(45, 1), oid(45, 3), 1, 100)],
        11,
        overflow_genesis.initial_block_id,
        derive_state_root_v1(&overflow_genesis.initial_objects).unwrap(),
    );
    assert_eq!(
        overflow_store.execute_block(&bad).unwrap_err().code(),
        MvccFeeErrorCodeV1::ArithmeticOverflow
    );
}

#[test]
fn crash_outcomes_reopen_to_exact_source_target_or_fence() {
    let g = genesis(214);
    let root = derive_state_root_v1(&g.initial_objects).unwrap();
    let candidate = block(
        &g,
        vec![add_tx(0, oid(45, 1), oid(45, 3), 1, 100)],
        11,
        g.initial_block_id,
        root,
    );
    let not_temp = TempDir::new().unwrap();
    let not_store = MvccFeeStoreV1::open(path(&not_temp), g.clone()).unwrap();
    assert_eq!(
        not_store
            .execute_with_fault(&candidate, MvccCommitFaultV1::NotAppliedAckLost)
            .unwrap_err()
            .code(),
        MvccFeeErrorCodeV1::CommitUncertain
    );
    let reopened = MvccFeeStoreV1::open(path(&not_temp), g.clone()).unwrap();
    assert!(!reopened.execute_block(&candidate).unwrap().replay);
    let applied_temp = TempDir::new().unwrap();
    let applied_store = MvccFeeStoreV1::open(path(&applied_temp), g.clone()).unwrap();
    assert_eq!(
        applied_store
            .execute_with_fault(&candidate, MvccCommitFaultV1::AppliedAckLost)
            .unwrap_err()
            .code(),
        MvccFeeErrorCodeV1::CommitUncertain
    );
    let reopened = MvccFeeStoreV1::open(path(&applied_temp), g.clone()).unwrap();
    assert!(reopened.execute_block(&candidate).unwrap().replay);
    let third_temp = TempDir::new().unwrap();
    let third_store = MvccFeeStoreV1::open(path(&third_temp), g.clone()).unwrap();
    assert_eq!(
        third_store
            .execute_with_fault(&candidate, MvccCommitFaultV1::ThirdState)
            .unwrap_err()
            .code(),
        MvccFeeErrorCodeV1::ThirdStateFenced
    );
    assert_eq!(
        MvccFeeStoreV1::open(path(&third_temp), g)
            .unwrap_err()
            .code(),
        MvccFeeErrorCodeV1::ThirdStateFenced
    );
}

#[test]
fn schema_sidecar_and_self_consistent_row_tamper_fail_closed() {
    let g = genesis(215);
    let temp = TempDir::new().unwrap();
    let store_path = path(&temp);
    let store = MvccFeeStoreV1::open(&store_path, g.clone()).unwrap();
    drop(store);
    let connection = Connection::open(&store_path).unwrap();
    connection.execute("UPDATE objects SET body=zeroblob(length(body)) WHERE rowid=(SELECT MIN(rowid) FROM objects)", []).unwrap();
    drop(connection);
    assert_eq!(
        MvccFeeStoreV1::open(&store_path, g.clone())
            .unwrap_err()
            .code(),
        MvccFeeErrorCodeV1::TamperDetected
    );
    let side_temp = TempDir::new().unwrap();
    let side_path = path(&side_temp);
    let mut sidecar = side_path.as_os_str().to_os_string();
    sidecar.push("-wal");
    fs::write(Path::new(&sidecar), b"x").unwrap();
    assert_eq!(
        MvccFeeStoreV1::open(side_path, g).unwrap_err().code(),
        MvccFeeErrorCodeV1::SidecarPresent
    );
}

#[test]
fn vector_inventory_matches_executable_candidate_assertions() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../docs/protocol/poco-ai-native-v1/vectors/cev1-object-mvcc-fee-kernel-v1.json",
    );
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let strings = |key: &str| {
        value[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(strings("positive_cases"), POSITIVE_CASES);
    assert_eq!(strings("negative_cases"), NEGATIVE_CASES);
    assert_eq!(strings("crash_reopen_cases"), CRASH_CASES);
    assert_eq!(value["counts"]["positive"], POSITIVE_CASES.len());
    assert_eq!(value["counts"]["negative"], NEGATIVE_CASES.len());
    assert_eq!(value["counts"]["crash_reopen"], CRASH_CASES.len());
    assert!(value["global_truth"]
        .as_object()
        .unwrap()
        .values()
        .all(|entry| entry == false));
}

#[test]
fn open_existing_requires_precreated_regular_nonsymlink_store() {
    let temporary = TempDir::new().unwrap();
    let store_path = path(&temporary);
    let g = genesis(216);

    assert_eq!(
        MvccFeeStoreV1::open_existing(&store_path, g.clone())
            .expect_err("missing store")
            .code(),
        MvccFeeErrorCodeV1::StoreFailure
    );
    assert!(!store_path.exists(), "strict open must not create a store");

    drop(MvccFeeStoreV1::open(&store_path, g.clone()).expect("create store"));
    drop(MvccFeeStoreV1::open_existing(&store_path, g.clone()).expect("strict reopen"));

    let directory_path = temporary.path().join("not-a-store-file");
    fs::create_dir(&directory_path).expect("directory object");
    assert_eq!(
        MvccFeeStoreV1::open_existing(&directory_path, g.clone())
            .expect_err("directory store path")
            .code(),
        MvccFeeErrorCodeV1::StoreFailure
    );

    #[cfg(unix)]
    {
        let symlink_path = temporary.path().join("store-link.sqlite");
        std::os::unix::fs::symlink(&store_path, &symlink_path).expect("store symlink");
        assert_eq!(
            MvccFeeStoreV1::open_existing(symlink_path, g)
                .expect_err("symlink store path")
                .code(),
            MvccFeeErrorCodeV1::StoreFailure
        );
    }
}
