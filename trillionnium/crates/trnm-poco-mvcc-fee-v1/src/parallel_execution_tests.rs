use super::*;
use crate::engine::{
    execute_block, execute_block_with_workers, worker_computation_probe_v1, ObjectMapV1,
};
use std::collections::HashSet;

fn parent(g: &MvccFeeGenesisV1) -> ObjectMapV1 {
    g.initial_objects
        .iter()
        .cloned()
        .map(|o| (o.object_id, o))
        .collect()
}

fn candidate(g: &MvccFeeGenesisV1, txs: Vec<MvccTransactionV1>) -> MvccBlockV1 {
    block(
        g,
        txs,
        g.initial_height + 1,
        g.initial_block_id,
        derive_state_root_v1(&g.initial_objects).unwrap(),
    )
}

fn transfer_tx(
    index: u32,
    payer: TypedObjectIdV1,
    source: TypedObjectIdV1,
    destination: TypedObjectIdV1,
    amount: u128,
) -> MvccTransactionV1 {
    let mut tx = add_tx(index, payer, source, amount, 100);
    tx.program = ObjectProgramV1::Transfer {
        source,
        destination,
        amount,
    };
    tx.declared_reads.push(destination);
    tx.declared_reads.sort_unstable();
    tx.declared_writes = tx.declared_reads.clone();
    tx.transaction_id = derive_transaction_id_v1(&tx).unwrap();
    tx
}

#[test]
fn workers_compute_program_meter_fees_and_successors_on_immutable_parent() {
    let mut g = genesis(225);
    let mut txs = Vec::new();
    for index in 0..8u8 {
        let payer = oid(47, index * 2 + 1);
        let target = oid(47, index * 2 + 2);
        g.initial_objects
            .extend([object(payer, 10_000), object(target, 0)]);
        txs.push(add_tx(
            u32::from(index),
            payer,
            target,
            u128::from(index) + 1,
            100,
        ));
    }
    g.initial_objects.sort_by_key(|o| o.object_id);
    let initial = parent(&g);
    let preserved = initial.clone();
    let probes = worker_computation_probe_v1(&g, &initial, &txs, 8).unwrap();
    let threads: HashSet<_> = probes.iter().map(|p| p.thread_id).collect();
    assert_eq!(
        threads.len(),
        8,
        "actual program computation ran on eight workers"
    );
    assert!(!threads.contains(&std::thread::current().id()));
    for (index, probe) in probes.iter().enumerate() {
        let payer = oid(47, (index * 2 + 1) as u8);
        let target = oid(47, (index * 2 + 2) as u8);
        assert_eq!(
            probe.successors.len(),
            2,
            "only transaction-local successors"
        );
        assert_eq!(probe.successors[&target].value, index as u128 + 1);
        assert_eq!(probe.successors[&target].version, 1);
        assert_eq!(probe.successors[&payer].value, 10_000 - probe.fee_charged);
        assert!(probe.fee_charged > 0);
        assert_eq!(probe.resource_usage.len(), 4);
        assert_eq!(probe.resource_usage[3].amount, 10);
    }
    assert_eq!(initial, preserved, "workers cannot mutate the parent");
    let block = candidate(&g, txs);
    let serial = execute_block(&g, &initial, &block).unwrap();
    for workers in [1, 2, 4, 8] {
        let parallel = execute_block_with_workers(&g, &initial, &block, workers).unwrap();
        assert_eq!(
            parallel, serial,
            "all canonical roots and complete receipts"
        );
        assert!(parallel.1.receipts.iter().all(|r| r.retry_count == 0));
    }
}

#[test]
fn hotspot_revert_and_resource_exhaustion_match_sequential_journal_oracle() {
    let g = genesis(226);
    let txs = (0..64)
        .map(|index| match index % 4 {
            0 => add_tx(index, oid(45, 1), oid(45, 3), 2, 100),
            1 => revert_tx(index, oid(45, 1)),
            2 => add_tx(index, oid(45, 1), oid(45, 3), 999, 1),
            _ => transfer_tx(index, oid(45, 1), oid(45, 4), oid(45, 5), 1),
        })
        .collect();
    let block = candidate(&g, txs);
    let initial = parent(&g);
    let serial = execute_block(&g, &initial, &block).unwrap();
    assert_eq!(
        serial.0[&oid(45, 3)].value,
        132,
        "failed work writes no application state"
    );
    assert_eq!(serial.0[&oid(45, 4)].value, 184);
    assert_eq!(serial.0[&oid(45, 5)].value, 316);
    assert_eq!(
        serial
            .1
            .receipts
            .iter()
            .filter(|r| r.retry_count == 1)
            .count(),
        63
    );
    for workers in [1, 2, 4, 8] {
        assert_eq!(
            execute_block_with_workers(&g, &initial, &block, workers).unwrap(),
            serial
        );
    }
}

#[test]
fn speculative_insufficient_funds_is_retried_after_predecessor_funds_payer_or_source() {
    for repair_payer in [true, false] {
        let mut g = genesis(227);
        let funded = if repair_payer { oid(45, 2) } else { oid(45, 4) };
        g.initial_objects
            .iter_mut()
            .find(|o| o.object_id == funded)
            .unwrap()
            .value = 0;
        let second = if repair_payer {
            add_tx(1, oid(45, 2), oid(45, 3), 7, 100)
        } else {
            transfer_tx(1, oid(45, 2), oid(45, 4), oid(45, 5), 80)
        };
        // The second complete computation fails on the parent snapshot.
        assert_eq!(
            worker_computation_probe_v1(&g, &parent(&g), std::slice::from_ref(&second), 1)
                .err()
                .unwrap()
                .code(),
            MvccFeeErrorCodeV1::InsufficientFunds
        );
        let block = candidate(&g, vec![add_tx(0, oid(45, 1), funded, 100, 100), second]);
        let serial = execute_block(&g, &parent(&g), &block).unwrap();
        assert_eq!(serial.1.receipts[1].retry_count, 1);
        assert_eq!(serial.1.receipts[1].status, ReceiptStatusV1::Success);
        for workers in [1, 2, 4, 8] {
            let temp = TempDir::new().unwrap();
            let store =
                MvccFeeStoreV1::open_with_worker_count(path(&temp), g.clone(), workers).unwrap();
            let outcome = store.execute_block(&block).unwrap();
            assert_eq!(outcome.confirmed.receipt(), &serial.1);
            assert_eq!(
                store.objects().unwrap(),
                serial.0.values().cloned().collect::<Vec<_>>()
            );
            drop(store);
            let reopened =
                MvccFeeStoreV1::open_existing_with_worker_count(path(&temp), g.clone(), workers)
                    .unwrap();
            let replay = reopened.execute_block(&block).unwrap();
            assert!(replay.replay);
            assert_eq!(replay.confirmed.receipt(), &serial.1);
        }
    }
}

#[test]
fn stale_speculative_success_cannot_publish_when_canonical_payer_is_exhausted() {
    let mut g = genesis(228);
    let first = add_tx(0, oid(45, 1), oid(45, 3), 1, 100);
    let first_fee = execute_block(&g, &parent(&g), &candidate(&g, vec![first.clone()]))
        .unwrap()
        .1
        .receipts[0]
        .fee_charged;
    g.initial_objects
        .iter_mut()
        .find(|o| o.object_id == oid(45, 1))
        .unwrap()
        .value = first_fee;
    let second = add_tx(1, oid(45, 1), oid(45, 4), 2, 100);
    let block = candidate(&g, vec![first, second]);
    assert_eq!(
        worker_computation_probe_v1(&g, &parent(&g), &block.transactions, 2)
            .unwrap()
            .len(),
        2
    );
    let canonical_error = execute_block(&g, &parent(&g), &block).unwrap_err();
    assert_eq!(
        canonical_error.code(),
        MvccFeeErrorCodeV1::InsufficientFunds
    );
    for workers in [1, 2, 4, 8] {
        assert_eq!(
            execute_block_with_workers(&g, &parent(&g), &block, workers).unwrap_err(),
            canonical_error
        );
        let temp = TempDir::new().unwrap();
        let store =
            MvccFeeStoreV1::open_with_worker_count(path(&temp), g.clone(), workers).unwrap();
        let before = store.fresh_readback().unwrap();
        assert_eq!(store.execute_block(&block).unwrap_err(), canonical_error);
        assert_eq!(store.fresh_readback().unwrap(), before);
        assert_eq!(store.objects().unwrap(), g.initial_objects);
        drop(store);
        let reopened =
            MvccFeeStoreV1::open_existing_with_worker_count(path(&temp), g.clone(), workers)
                .unwrap();
        assert_eq!(reopened.fresh_readback().unwrap(), before);
        assert_eq!(reopened.objects().unwrap(), g.initial_objects);
    }
}

#[test]
fn multiple_speculative_failures_report_the_canonical_transaction_error() {
    let mut g = genesis(229);
    g.initial_objects
        .iter_mut()
        .find(|o| o.object_id == oid(45, 4))
        .unwrap()
        .value = u128::MAX;
    let mut fee_error = add_tx(1, oid(45, 2), oid(45, 3), 1, 100);
    fee_error.max_fee = 1;
    fee_error.transaction_id = derive_transaction_id_v1(&fee_error).unwrap();
    let block = candidate(
        &g,
        vec![
            add_tx(0, oid(45, 1), oid(45, 5), 1, 100),
            fee_error,
            add_tx(2, oid(45, 2), oid(45, 4), 1, 100),
        ],
    );
    let canonical_error = execute_block(&g, &parent(&g), &block).unwrap_err();
    assert_eq!(canonical_error.code(), MvccFeeErrorCodeV1::FeeLimitExceeded);
    for workers in [1, 2, 4, 8] {
        assert_eq!(
            execute_block_with_workers(&g, &parent(&g), &block, workers).unwrap_err(),
            canonical_error
        );
    }
}
