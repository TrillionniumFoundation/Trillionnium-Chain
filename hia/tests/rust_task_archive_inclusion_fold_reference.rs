//! Genuine planner, batch proof, hash and public verifier from the original crate.
use std::collections::BTreeSet;
use std::io::{self, Write};
use trnm_task_kernel::{
    plan_task_archive_pruning_v1, verify_task_archive_inclusion_v1, AgentMarketErrorCodeV1,
    Hash32V1, ProtocolContextV1, TaskArchiveInclusionProofV1, TaskArchivePolicyV1,
    TaskArchiveSealV1, TaskIdV1, TerminalTaskArchiveRecordV1,
};

fn record(context: &ProtocolContextV1, i: u32) -> TerminalTaskArchiveRecordV1 {
    let mut name = [0; 32];
    name[..4].copy_from_slice(&i.to_be_bytes());
    let height = u64::from(i) + 1;
    TerminalTaskArchiveRecordV1 {
        schema_version: 1,
        context: context.clone(),
        task_id: TaskIdV1(name),
        terminal_height: height,
        task_revision: u64::from(i),
        terminal_state_digest: Hash32V1([1; 32]),
        terminal_receipt_digest: Hash32V1([2; 32]),
        evidence_root: Hash32V1([3; 32]),
        encoded_bytes: 100,
        retention_paid_through_height: height + 4,
        retention_charge_paid: 1_000,
    }
}

fn emit(
    out: &mut impl Write,
    seal: &TaskArchiveSealV1,
    record: &TerminalTaskArchiveRecordV1,
    proof: &TaskArchiveInclusionProofV1,
) {
    let status = match verify_task_archive_inclusion_v1(seal, record, proof) {
        Ok(()) => 0u32,
        Err(err) => match err.code() {
            AgentMarketErrorCodeV1::InvalidBounds => 1,
            AgentMarketErrorCodeV1::InvalidState => 13,
            AgentMarketErrorCodeV1::TamperDetected => 23,
            other => panic!("unexpected original verifier status: {other:?}"),
        },
    };
    let raw = borsh::to_vec(record).unwrap();
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(raw.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&raw).unwrap();
    out.write_all(&seal.record_count.to_le_bytes()).unwrap();
    out.write_all(&proof.leaf_index.to_le_bytes()).unwrap();
    out.write_all(&(proof.siblings.len() as u64).to_le_bytes()).unwrap();
    out.write_all(&seal.records_root.0).unwrap();
    out.write_all(&record.record_hash().unwrap().0).unwrap();
    for sibling in &proof.siblings {
        out.write_all(&sibling.0).unwrap();
    }
}

fn main() {
    let context = ProtocolContextV1 {
        genesis_hash: Hash32V1([4; 32]),
        chain_id: "archive-fold-测试".to_string(),
        protocol_version: 1,
        stack_profile_hash: Hash32V1([5; 32]),
    };
    let mut out = io::stdout().lock();
    for width in [1u32, 2, 3, 5, 8, 4096] {
        let policy = TaskArchivePolicyV1 {
            schema_version: 1,
            context: context.clone(),
            minimum_terminal_retention_blocks: 5,
            maximum_live_terminal_records: 1,
            maximum_live_terminal_bytes: 100,
            maximum_archive_batch_records: width,
            maximum_archive_batch_bytes: u64::from(width) * 100,
            retention_charge_units_per_byte_block: 2,
        };
        let records: Vec<_> = (0..=width).rev().map(|i| record(&context, i)).collect();
        let plan = plan_task_archive_pruning_v1(
            &policy,
            &records,
            &BTreeSet::new(),
            20_000,
            1,
            Hash32V1([0; 32]),
        )
        .unwrap();
        let batch = plan.archive_batch().unwrap();
        assert_eq!(batch.records.len(), width as usize);
        for index in BTreeSet::from([0, width.min(2) - 1, width - 1]) {
            let record = &batch.records[index as usize];
            let proof = batch.inclusion_proof(&policy, record.task_id).unwrap();
            assert_eq!(proof.leaf_index, index);
            emit(&mut out, &batch.seal, record, &proof);
        }
        if width == 3 {
            let record = &batch.records[2];
            let proof = batch.inclusion_proof(&policy, record.task_id).unwrap();

            let mut tampered = proof.clone();
            tampered.siblings[0].0[0] ^= 1;
            emit(&mut out, &batch.seal, record, &tampered);
            let mut tampered = record.clone();
            tampered.evidence_root.0[0] ^= 1;
            emit(&mut out, &batch.seal, &tampered, &proof);
            let mut wrong = proof.clone();
            wrong.leaf_index = width;
            emit(&mut out, &batch.seal, record, &wrong);
            let mut wrong = proof.clone();
            wrong.siblings.pop();
            emit(&mut out, &batch.seal, record, &wrong);
            let mut too_wide = batch.seal.clone();
            too_wide.record_count = 4097;
            let mut proof = proof.clone();
            proof.seal_hash = too_wide.seal_hash().unwrap();
            emit(&mut out, &too_wide, record, &proof);
        }
    }
}
