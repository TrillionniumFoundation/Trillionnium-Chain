//! Public Rust archive planner and complete read-only batch verifier.
#[allow(dead_code)]
#[path = "rust_task_archive_singleton_batch_reference.rs"]
mod wire;
#[allow(dead_code)]
#[path = "rust_task_archive_inclusion_fold_reference.rs"]
mod facts;

use std::collections::BTreeSet;
use std::io;
use trnm_task_kernel::{
    plan_task_archive_pruning_v1, Hash32V1, ProtocolContextV1, TaskArchiveBatchV1,
    TaskArchivePolicyV1, TerminalTaskArchiveRecordV1,
};

fn policy(n: u32) -> TaskArchivePolicyV1 {
    TaskArchivePolicyV1 {
        schema_version: 1,
        context: ProtocolContextV1 {
            genesis_hash: Hash32V1([7; 32]),
            chain_id: "多记录\0".repeat((n*6) as usize),
            protocol_version: 1,
            stack_profile_hash: Hash32V1([8; 32]),
        },
        minimum_terminal_retention_blocks: 5,
        maximum_live_terminal_records: 1,
        maximum_live_terminal_bytes: 100,
        maximum_archive_batch_records: n,
        maximum_archive_batch_bytes: u64::from(n) * 100,
        retention_charge_units_per_byte_block: 2,
    }
}

fn records(policy: &TaskArchivePolicyV1) -> Vec<TerminalTaskArchiveRecordV1> {
    (0..=policy.maximum_archive_batch_records)
        .rev()
        .map(|i| {
            let mut record = facts::record(&policy.context, i);
            record.task_id.0[0] = (i+1) as u8;
            record.task_id.0[1] = 255 - i as u8;
            record.terminal_height = 1 + u64::from(i / 2);
            record.retention_paid_through_height = record.terminal_height + 4;
            record
        })
        .collect()
}

fn plan(policy: &TaskArchivePolicyV1, records: &[TerminalTaskArchiveRecordV1]) -> TaskArchiveBatchV1 {
    plan_task_archive_pruning_v1(policy, records, &BTreeSet::new(), 64, 5, Hash32V1([6; 32]))
        .unwrap()
        .archive_batch()
        .unwrap()
        .clone()
}

fn main() {
    let mut w = io::stdout().lock();
    for width in [1, 2, 3, 5, 8] {
        let p = policy(width);
        let source = records(&p);
        let batch = plan(&p, &source);
        assert_eq!(batch.records.len(), width as usize);
        wire::emit(&mut w, &p, &batch);
    }
    // Exact low-limb carry into the high limb in a genuinely planned batch.
    let p = policy(3);
    let mut source = records(&p);
    source.iter_mut().find(|r| r.task_revision == 0).unwrap().retention_charge_paid =
        u128::from(u64::MAX);
    let carried = plan(&p, &source);
    assert_eq!(carried.seal.total_retention_charge, u128::from(u64::MAX)+2000);
    wire::emit(&mut w, &p, &carried);

    let p = policy(5);
    let batch = plan(&p, &records(&p));
    let mut wrong = batch.clone();
    wrong.records.swap(0, 1);
    wire::emit(&mut w, &p, &wrong); // 2, same-height bytewise order.
    wrong.records[1].schema_version = 2;
    wire::emit(&mut w, &p, &wrong); // 22, same bad order but row eligibility first.
    let mut wrong = batch.clone();
    wrong.records.swap(2, 4);
    wire::emit(&mut w, &p, &wrong); // 2, descending terminal height.
    let mut wrong = batch.clone();
    wrong.records[4].task_id = wrong.records[0].task_id;
    wire::emit(&mut w, &p, &wrong); // 2, nonadjacent reused ID at higher height.
    wrong.records[4].retention_charge_paid = 999;
    wire::emit(&mut w, &p, &wrong); // 15, prior eligibility before duplicate.
    let mut wrong = batch.clone();
    // The first bad row rejects before any future row schema.
    wrong.records[1].retention_charge_paid = 999;
    wrong.records[2].schema_version = 2;
    wire::emit(&mut w, &p, &wrong); // 15.
    let mut wrong = batch.clone();
    wrong.records[4].context.chain_id.push('x');
    wire::emit(&mut w, &p, &wrong); // 200.

    let mut wrong = batch.clone();
    wrong.records[0].retention_charge_paid = u128::MAX;
    wire::emit(&mut w, &p, &wrong); // 20, add charge overflow.
    let mut large_policy = p.clone();
    large_policy.maximum_archive_batch_bytes = u64::MAX;
    large_policy.retention_charge_units_per_byte_block = 1;
    let mut wrong = batch.clone();
    wrong.seal.policy_hash = large_policy.policy_hash().unwrap();
    for record in wrong.records.iter_mut().take(2) {
        record.encoded_bytes = 1 << 63;
        record.retention_charge_paid = 5u128 << 63;
    }
    wire::emit(&mut w, &large_policy, &wrong); // 20, add bytes overflow.
    let mut too_small = p.clone();
    too_small.maximum_archive_batch_records = 4;
    wire::emit(&mut w, &too_small, &batch); // 1, actual Vec count before seal hash.
    let mut too_small_bytes = p.clone();
    too_small_bytes.maximum_archive_batch_bytes -= 1;
    let mut wrong = batch.clone();
    wrong.seal.policy_hash = too_small_bytes.policy_hash().unwrap();
    wire::emit(&mut w, &too_small_bytes, &wrong); // 13, max total bytes.
    let mut wrong = batch.clone();
    wrong.seal.record_count = 4;
    wire::emit(&mut w, &p, &wrong); // 13, seal count, not Vec count.
    let mut wrong = batch.clone();
    wrong.seal.records_root.0[17] ^= 1;
    wire::emit(&mut w, &p, &wrong); // 13, odd Merkle root binding.
    let mut wrong = batch.clone();
    wrong.seal.total_retention_charge += 1;
    wire::emit(&mut w, &p, &wrong); // 13, total charge.
    let mut wrong = batch.clone();
    wrong.seal.first_task_id.0[0] ^= 1;
    wire::emit(&mut w, &p, &wrong); // 13, canonical range.
}
