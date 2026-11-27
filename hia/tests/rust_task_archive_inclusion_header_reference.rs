//! Complete typed fixtures created and judged by the unchanged public API.
#[allow(dead_code)]
#[path = "rust_task_archive_inclusion_fold_reference.rs"]
mod shared;

use std::collections::BTreeSet;
use std::io::{self, Write};
use trnm_task_kernel::{
    plan_task_archive_pruning_v1, verify_task_archive_inclusion_v1, AgentMarketErrorCodeV1,
    Hash32V1, ProtocolContextV1, TaskArchiveInclusionProofV1, TaskArchivePolicyV1,
    TaskArchiveSealV1, TerminalTaskArchiveRecordV1,
};

fn row(
    w: &mut impl Write,
    seal: &TaskArchiveSealV1,
    record: &TerminalTaskArchiveRecordV1,
    proof: &TaskArchiveInclusionProofV1,
) {
    let status = match verify_task_archive_inclusion_v1(seal, record, proof) {
        Ok(()) => 0u32,
        Err(error) => match error.code() {
            AgentMarketErrorCodeV1::InvalidBounds => 1,
            AgentMarketErrorCodeV1::InvalidState => 13,
            AgentMarketErrorCodeV1::ArithmeticOverflow => 20,
            AgentMarketErrorCodeV1::SchemaMismatch => 22,
            AgentMarketErrorCodeV1::TamperDetected => 23,
            other => panic!("unexpected verifier failure: {other:?}"),
        },
    };
    let seal = borsh::to_vec(seal).unwrap();
    let record = borsh::to_vec(record).unwrap();
    let proof = borsh::to_vec(proof).unwrap();
    for value in [status, seal.len() as u32, record.len() as u32, proof.len() as u32] {
        w.write_all(&value.to_le_bytes()).unwrap();
    }
    for part in [seal, record, proof] {
        w.write_all(&part).unwrap();
    }
}

fn main() {
    let context = ProtocolContextV1 {
        genesis_hash: Hash32V1([4; 32]),
        chain_id: "outer-归档-🔎".to_string(),
        protocol_version: 64,
        stack_profile_hash: Hash32V1([5; 32]),
    };
    let policy = TaskArchivePolicyV1 {
        schema_version: 1,
        context: context.clone(),
        minimum_terminal_retention_blocks: 5,
        maximum_live_terminal_records: 1,
        maximum_live_terminal_bytes: 100,
        maximum_archive_batch_records: 3,
        maximum_archive_batch_bytes: 300,
        retention_charge_units_per_byte_block: 2,
    };
    let records: Vec<_> = (0..4).rev().map(|i| shared::record(&context, i)).collect();
    // Latest selected record (height 3) is exactly one beyond paid-through.
    let plan = plan_task_archive_pruning_v1(
        &policy,
        &records,
        &BTreeSet::new(),
        8,
        1,
        Hash32V1([0; 32]),
    )
    .unwrap();
    let batch = plan.archive_batch().unwrap();
    let seal = &batch.seal;
    let fact = &batch.records[2];
    let proof = batch.inclusion_proof(&policy, fact.task_id).unwrap();
    let mut w = io::stdout().lock();
    row(&mut w, seal, fact, &proof); // 0, inclusive boundary plus one

    let mut altered_proof = proof.clone();
    altered_proof.siblings[0].0[0] ^= 1;
    row(&mut w, seal, fact, &altered_proof); // 23, valid header only
    let mut early = seal.clone();
    early.archive_height = fact.retention_paid_through_height;
    altered_proof.schema_version = 2;
    row(&mut w, &early, fact, &altered_proof); // 13, retention before proof
    let mut invalid_record = fact.clone();
    invalid_record.retention_paid_through_height = u64::MAX;
    row(&mut w, &early, &invalid_record, &altered_proof); // 20, even bad proof/early seal

    let mut empty = seal.clone();
    empty.record_count = 0;
    row(&mut w, &empty, fact, &altered_proof); // 13, proof schema before seal count
    row(&mut w, &empty, fact, &proof); // 22, zero count via seal hash

    let mut bad_seal = seal.clone();
    bad_seal.schema_version = 2;
    bad_seal.record_count = 0;
    row(&mut w, &bad_seal, fact, &proof); // 13, seal schema before zero count

    let mut moved = fact.clone();
    moved.context.chain_id.push('x');
    row(&mut w, seal, &moved, &proof); // 13, length/context
    moved.context = fact.context.clone();
    moved.context.stack_profile_hash.0[0] ^= 1;
    row(&mut w, seal, &moved, &proof); // 13, same-length context mismatch

    let mut bad_hash = proof.clone();
    bad_hash.seal_hash.0[31] ^= 1;
    invalid_record = fact.clone();
    invalid_record.schema_version = 2;
    row(&mut w, seal, &invalid_record, &bad_hash); // 13, proof hash before record schema
    row(&mut w, seal, &invalid_record, &proof); // 22, lower record schema gate

    let mut bad_depth = proof.clone();
    bad_depth.siblings.pop();
    row(&mut w, seal, &invalid_record, &bad_depth); // 13, depth before record schema
    bad_depth.siblings.resize(13, Hash32V1([0; 32]));
    row(&mut w, seal, fact, &bad_depth); // 13, typed oversized proof vector
    let mut too_wide = seal.clone();
    too_wide.record_count = 4097;
    let mut out_of_range = proof.clone();
    out_of_range.seal_hash = too_wide.seal_hash().unwrap();
    row(&mut w, &too_wide, fact, &out_of_range); // 1, count before depth
    out_of_range.leaf_index = too_wide.record_count;
    row(&mut w, &too_wide, fact, &out_of_range); // 13, index before count
}
