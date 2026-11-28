//! Disposable exact original store fixtures. The native verifier never opens or writes these databases.
#[allow(dead_code)]
#[path = "rust_task_archive_inclusion_fold_reference.rs"]
mod shared;

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::path::Path;
use trnm_task_kernel::{
    plan_task_archive_pruning_v1, AgentMarketErrorCodeV1, Hash32V1, ProtocolContextV1,
    TaskArchiveBatchV1, TaskArchivePolicyV1, TaskArchiveStoreV1,
};

fn policy() -> TaskArchivePolicyV1 {
    TaskArchivePolicyV1 {
        schema_version: 1,
        context: ProtocolContextV1 {
            genesis_hash: Hash32V1([4; 32]), chain_id: "封\0".repeat(128),
            protocol_version: 1, stack_profile_hash: Hash32V1([5; 32]),
        },
        minimum_terminal_retention_blocks: 5,
        maximum_live_terminal_records: 1, maximum_live_terminal_bytes: 100,
        maximum_archive_batch_records: 8, maximum_archive_batch_bytes: 800,
        retention_charge_units_per_byte_block: 2,
    }
}

fn create(root: &Path) {
    for n in [0u32, 1, 2, 8] {
        let path = root.join(format!("chain-{n}.sqlite"));
        let p = policy();
        let store = TaskArchiveStoreV1::initialize(path, p.clone()).unwrap();
        let retained: Vec<_> = (0..=n).map(|i| shared::record(&p.context, i)).collect();
        store.install_live_records_v1(&retained, 50).unwrap();
        let mut previous = Hash32V1([0; 32]);
        for i in 0..n {
            // Each actual original planner invocation receives two extant generated
            // facts under the same locked policy, so its selection has one record.
            let sequence = u64::from(i) + 1;
            let plan = plan_task_archive_pruning_v1(&p, &retained[i as usize..i as usize+2],
                    &BTreeSet::new(), 50 + sequence, sequence, previous).unwrap();
            let batch = plan.archive_batch().unwrap();
            let original = store.archive_and_delete_v1(batch).unwrap();
            assert_eq!(original.generation, sequence);
            assert_eq!(original.seal_hash, batch.seal.seal_hash().unwrap());
            assert_eq!(store.read_archive_batch_v1(sequence).unwrap(), *batch);
            previous = original.seal_hash;
        }
    }
}

fn create_inventory(root: &Path) {
    create(root);
    let p = policy();
    TaskArchiveStoreV1::initialize(root.join("inventory-empty.sqlite"), p.clone()).unwrap();
    let store = TaskArchiveStoreV1::initialize(root.join("inventory-full.sqlite"), p.clone()).unwrap();
    let facts: Vec<_> = (0..16).map(|i| shared::record(&p.context, i)).collect();
    store.install_live_records_v1(&facts, 50).unwrap();
    let large = TaskArchiveStoreV1::initialize(root.join("inventory-wide.sqlite"), p.clone()).unwrap();
    large.install_live_records_v1(&facts[..9], 50).unwrap();
    let planned = plan_task_archive_pruning_v1(&p, &facts[..9], &BTreeSet::new(), 51, 1,
             Hash32V1([0;32])).unwrap();
    let saved_batch = planned.archive_batch().unwrap();
    assert_eq!(saved_batch.records.len(),8);
    large.archive_and_delete_v1(saved_batch).unwrap();
    let mut offset = 0;
    let mut previous = Hash32V1([0; 32]);
    for (i, size) in [3, 2, 1, 1, 1, 1, 1, 1].into_iter().enumerate() {
        let seq = i as u64 + 1;
        let plan = plan_task_archive_pruning_v1(&p, &facts[offset..offset+size+1],
                    &BTreeSet::new(), 51+seq, seq, previous).unwrap();
        let batch = plan.archive_batch().unwrap();
        let receipt = store.archive_and_delete_v1(batch).unwrap();
        assert_eq!(receipt.deleted_record_count as usize, size);
        assert_eq!(store.read_archive_batch_v1(seq).unwrap(), *batch);
        previous = receipt.seal_hash;
        offset += size;
    }
}

fn read(path: &Path, count: u64) {
    let mut out = io::stdout().lock();
    match TaskArchiveStoreV1::open_existing(path, policy()) {
        Ok(store) => {
            out.write_all(&0u32.to_le_bytes()).unwrap();
            out.write_all(&store.live_root_v1().unwrap().0).unwrap();
            for seq in 1..=count {
                let batch = store.read_archive_batch_v1(seq).unwrap();
                let seal = borsh::to_vec(&batch.seal).unwrap();
                let raw = borsh::to_vec(&batch).unwrap();
                let digest = batch.seal.seal_hash().unwrap();
                out.write_all(&(seal.len() as u32).to_le_bytes()).unwrap();
                out.write_all(&(raw.len() as u32).to_le_bytes()).unwrap();
                out.write_all(&digest.0).unwrap();
                out.write_all(&raw).unwrap();
            }
        }
        Err(err) => {
            let status: u32 = match err.code() {
                AgentMarketErrorCodeV1::TamperDetected => 23,
                AgentMarketErrorCodeV1::SchemaMismatch => 22,
                AgentMarketErrorCodeV1::InvalidBounds => 1,
                AgentMarketErrorCodeV1::InvalidState => 13,
                AgentMarketErrorCodeV1::NonCanonical => 2,
                other => panic!("unexpected original archive store admission: {other:?}"),
            };
            out.write_all(&status.to_le_bytes()).unwrap();
        }
    }
}

fn wrong_link() {
    // Only the fixture can present an inconsistent retained predecessor.
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    let mut batch: TaskArchiveBatchV1 = borsh::from_slice(&raw).unwrap();
    batch.seal.previous_seal_hash = Hash32V1([11; 32]);
    let mut out = io::stdout().lock();
    out.write_all(&batch.seal.seal_hash().unwrap().0).unwrap();
    out.write_all(&borsh::to_vec(&batch).unwrap()).unwrap();
}

fn revised_value(full_batch: bool) {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    let mut out = io::stdout().lock();
    if full_batch {
        let mut batch: TaskArchiveBatchV1 = borsh::from_slice(&raw).unwrap();
        batch.records[0].task_revision += 1;
        out.write_all(&borsh::to_vec(&batch).unwrap()).unwrap();
    } else {
        let mut record: trnm_task_kernel::TerminalTaskArchiveRecordV1 = borsh::from_slice(&raw).unwrap();
        record.task_revision += 1;
        out.write_all(&record.record_hash().unwrap().0).unwrap();
        out.write_all(&borsh::to_vec(&record).unwrap()).unwrap();
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    match args[1].to_str().unwrap() {
        "policy" => io::stdout().write_all(&borsh::to_vec(&policy()).unwrap()).unwrap(),
        "changed-batch" => revised_value(true),
        "changed-row" => revised_value(false),
        "wrong-link" => wrong_link(),
        "create-inventory" => create_inventory(Path::new(&args[2])),
        "create" => create(Path::new(&args[2])),
        "read" => read(Path::new(&args[2]), args[3].to_str().unwrap().parse().unwrap()),
        _ => unreachable!(),
    }
}
