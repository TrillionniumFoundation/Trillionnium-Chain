//! Disposable local archive fixture, original complete validation then Borsh path construction.
#[allow(dead_code)]
#[path = "rust_task_archive_inclusion_fold_reference.rs"]
mod facts;

use std::{collections::BTreeSet, io::{self, Write}};
use trnm_task_kernel::{plan_task_archive_pruning_v1, verify_task_archive_inclusion_v1,
    AgentMarketErrorCodeV1, Hash32V1, ProtocolContextV1, TaskArchiveBatchV1,
    TaskArchivePolicyV1, TaskIdV1};

fn emit(out: &mut impl Write, policy: &TaskArchivePolicyV1, batch: &TaskArchiveBatchV1, id: TaskIdV1) {
    let (status, answer) = match batch.inclusion_proof(policy,id) {
        Ok(path) => {
            let terminal = batch.records.iter().find(|r| r.task_id == id).unwrap();
            verify_task_archive_inclusion_v1(&batch.seal,terminal,&path).unwrap();
            (0u32, borsh::to_vec(&path).unwrap())
        }
        Err(e) => (match e.code() {
            AgentMarketErrorCodeV1::InvalidBounds=>1,
            AgentMarketErrorCodeV1::NonCanonical=>2,
            AgentMarketErrorCodeV1::InvalidState=>13,
            AgentMarketErrorCodeV1::NotFound=>19,
            AgentMarketErrorCodeV1::SchemaMismatch=>22,
            c => panic!("Unexpected original response: {c:?}"),
        }, Vec::new()),
    };
    let p = borsh::to_vec(policy).unwrap();
    let seal = borsh::to_vec(&batch.seal).unwrap();
    let b = borsh::to_vec(batch).unwrap();
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&((48+p.len()+b.len()) as u32).to_le_bytes()).unwrap();
    out.write_all(&(answer.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&(p.len() as u64).to_le_bytes()).unwrap();
    out.write_all(&(seal.len() as u64).to_le_bytes()).unwrap();
    out.write_all(&p).unwrap();
    out.write_all(&b).unwrap();
    out.write_all(&id.0).unwrap();
    out.write_all(&answer).unwrap();
}

fn main() {
    let mut out = io::stdout().lock();
    for width in [1u32,2,3,5,8] {
        let policy = TaskArchivePolicyV1 {
            schema_version: 1,
            context: ProtocolContextV1 { genesis_hash: Hash32V1([7;32]),
                chain_id: "Archive\0合".repeat(width as usize),
                protocol_version:23, stack_profile_hash:Hash32V1([8;32]) },
            minimum_terminal_retention_blocks:5, maximum_live_terminal_records:1,
            maximum_live_terminal_bytes:100, maximum_archive_batch_records:width,
            maximum_archive_batch_bytes:u64::from(width)*100,
            retention_charge_units_per_byte_block:2,
        };
        let records = (0..=width).rev().map(|i| facts::record(&policy.context,i)).collect::<Vec<_>>();
        let planned = plan_task_archive_pruning_v1(&policy,&records,&BTreeSet::new(),64,9,Hash32V1([6;32])).unwrap();
        let batch = planned.archive_batch().unwrap();
        assert_eq!(batch.records.len(),width as usize);
        for r in &batch.records { emit(&mut out,&policy,batch,r.task_id); }
        let missing=TaskIdV1([0x91;32]);
        emit(&mut out,&policy,batch,missing);
        if width==5 {
            let mut changed=batch.clone();
            changed.seal.total_encoded_bytes+=1;
            emit(&mut out,&policy,&changed,missing);
            let mut unordered=batch.clone();
            unordered.records.swap(0,1);
            emit(&mut out,&policy,&unordered,batch.records[0].task_id);
            unordered.records[1].schema_version=2;
            emit(&mut out,&policy,&unordered,missing);
        }
    }
}
