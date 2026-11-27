//! Locked original public archive planner and batch verifier; no store operations.
#[allow(dead_code)]
#[path = "rust_task_archive_inclusion_fold_reference.rs"]
mod shared;

use std::collections::BTreeSet;
use std::io::{self, Write};
use trnm_task_kernel::{
    plan_task_archive_pruning_v1, verify_task_archive_batch_v1, AgentMarketErrorCodeV1,
    Hash32V1, ProtocolContextV1, TaskArchiveBatchV1, TaskArchivePolicyV1,
};

fn emit(out: &mut impl Write, policy: &TaskArchivePolicyV1, batch: &TaskArchiveBatchV1) {
    let status = match verify_task_archive_batch_v1(policy, batch) {
        Ok(()) => 0u32,
        Err(err) => match err.code() {
            AgentMarketErrorCodeV1::InvalidContext => 200,
            AgentMarketErrorCodeV1::InvalidBounds => 1,
            AgentMarketErrorCodeV1::InvalidState => 13,
            AgentMarketErrorCodeV1::ConservationViolation => 15,
            AgentMarketErrorCodeV1::ArithmeticOverflow => 20,
            AgentMarketErrorCodeV1::SchemaMismatch => 22,
            other => panic!("unexpected public batch result: {other:?}"),
        },
    };
    let pol = borsh::to_vec(policy).unwrap();
    let seal = borsh::to_vec(&batch.seal).unwrap();
    let body = borsh::to_vec(batch).unwrap();
    let size = 16+pol.len()+body.len();
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(size as u32).to_le_bytes()).unwrap();
    out.write_all(&(pol.len() as u64).to_le_bytes()).unwrap();
    out.write_all(&(seal.len() as u64).to_le_bytes()).unwrap();
    out.write_all(&pol).unwrap();
    out.write_all(&body).unwrap();
}

fn main() {
    let policy = TaskArchivePolicyV1 {
        schema_version: 1,
        context: ProtocolContextV1 {
            genesis_hash: Hash32V1([4; 32]),
            chain_id: "一\0".repeat(128),
            protocol_version: 64,
            stack_profile_hash: Hash32V1([5; 32]),
        },
        minimum_terminal_retention_blocks: 5,
        maximum_live_terminal_records: 1,
        maximum_live_terminal_bytes: 100,
        maximum_archive_batch_records: 1,
        maximum_archive_batch_bytes: 100,
        retention_charge_units_per_byte_block: 2,
    };
    let records: Vec<_> = (0..2).rev().map(|i| shared::record(&policy.context, i)).collect();
    let plan = plan_task_archive_pruning_v1(
        &policy, &records, &BTreeSet::new(), 20, 1, Hash32V1([0; 32]),
    )
    .unwrap();
    let batch = plan.archive_batch().unwrap();
    let mut out = io::stdout().lock();
    emit(&mut out, &policy, batch);

    let mut large_policy = policy.clone();
    large_policy.maximum_archive_batch_bytes = u64::MAX;
    let mut large = batch.clone();
    large.records[0].encoded_bytes = 1 << 63;
    large.records[0].retention_charge_paid = 5u128 << 64;
    large.seal.policy_hash = large_policy.policy_hash().unwrap();
    large.seal.total_encoded_bytes = 1 << 63;
    large.seal.total_retention_charge = 5u128 << 64;
    large.seal.records_root = large.records[0].record_hash().unwrap();
    emit(&mut out, &large_policy, &large);
    large.records[0].retention_charge_paid -= 1;
    emit(&mut out, &large_policy, &large); // high limb lower, low limb max.
    large_policy.retention_charge_units_per_byte_block = u64::MAX;
    large.seal.policy_hash = large_policy.policy_hash().unwrap();
    large.records[0].encoded_bytes = u64::MAX;
    emit(&mut out, &large_policy, &large); // charge overflow precedes stale seal totals.

    let mut altered = batch.clone();
    altered.records[0].terminal_height = u64::MAX;
    altered.seal.archive_height = u64::MAX;
    emit(&mut out, &policy, &altered); // mandatory retention height overflow.
    altered.records[0].terminal_height = 0;
    altered.records[0].retention_paid_through_height = u64::MAX;
    emit(&mut out, &policy, &altered); // charged-block overflow.
    altered.records[0].terminal_height = 1;
    altered.records[0].encoded_bytes = 1;
    altered.records[0].retention_charge_paid = u128::MAX;
    emit(&mut out, &policy, &altered); // inclusive first-prunable height overflow.

    let mut changed = policy.clone();
    changed.schema_version = 2;
    changed.retention_charge_units_per_byte_block = 0;
    emit(&mut out, &changed, batch);
    changed.schema_version = 1;
    emit(&mut out, &changed, batch);

    let mut alter = batch.clone();
    alter.seal.schema_version = 0;
    alter.records[0].schema_version = 0;
    emit(&mut out, &policy, &alter); // seal row failure before record schema.
    alter.seal.schema_version = 1;
    alter.records[0].context.protocol_version = 9;
    emit(&mut out, &policy, &alter); // original record schema before context.
    alter.records[0].schema_version = 1;
    emit(&mut out, &policy, &alter);

    let mut alter = batch.clone();
    alter.seal.context.chain_id.pop();
    emit(&mut out, &policy, &alter);
    alter.seal.context = policy.context.clone();
    alter.seal.policy_hash.0[0] ^= 1;
    emit(&mut out, &policy, &alter);
    alter.seal.policy_hash = batch.seal.policy_hash;
    alter.seal.batch_sequence = 0;
    emit(&mut out, &policy, &alter);
    alter.seal.batch_sequence = 1;
    alter.seal.record_count = 2;
    emit(&mut out, &policy, &alter);

    let mut changed_record = batch.clone();
    changed_record.records[0].encoded_bytes = 0;
    emit(&mut out, &policy, &changed_record);
    changed_record.records[0].encoded_bytes = 100;
    changed_record.records[0].retention_paid_through_height = 4;
    emit(&mut out, &policy, &changed_record);
    changed_record.records[0].retention_paid_through_height = 5;
    changed_record.records[0].retention_charge_paid = 999;
    emit(&mut out, &policy, &changed_record); // low-limb underfunded.
    changed_record.records[0].retention_charge_paid = 1000;
    changed_record.seal.archive_height = 5;
    emit(&mut out, &policy, &changed_record); // last inclusive paid block.

    let mut mismatch = batch.clone();
    mismatch.seal.total_encoded_bytes += 1;
    emit(&mut out, &policy, &mismatch);
    mismatch = batch.clone();
    mismatch.seal.total_retention_charge += 1;
    emit(&mut out, &policy, &mismatch);
    mismatch = batch.clone();
    mismatch.seal.records_root.0[31] ^= 1;
    emit(&mut out, &policy, &mismatch);
    mismatch = batch.clone();
    mismatch.seal.last_task_id.0[0] ^= 1;
    emit(&mut out, &policy, &mismatch);
}
