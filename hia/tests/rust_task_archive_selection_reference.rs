//! Projection of unchanged public Rust archive plans; no store or deletion.
#[allow(dead_code)]
#[path = "rust_task_archive_inclusion_fold_reference.rs"]
mod fixture;
use std::collections::BTreeSet;
use std::io::{self, Write};
use trnm_task_kernel::{
    plan_task_archive_pruning_v1, AgentMarketErrorCodeV1, Hash32V1, ProtocolContextV1,
    TaskArchivePolicyV1, TaskIdV1, TerminalTaskArchiveRecordV1,
};

fn row(w: &mut impl Write, p: &TaskArchivePolicyV1, facts: &[TerminalTaskArchiveRecordV1],
       holds: BTreeSet<TaskIdV1>, height: u64, sequence: u64) {
    let typed = std::env::args_os().nth(1).is_some_and(|v| v == "typed");
    let mut selected_borsh = Vec::new();
    let result = plan_task_archive_pruning_v1(p, facts, &holds, height, sequence, Hash32V1([7;32]));
    let mut output = [u64::MAX;21];
    let status = match result {
        Ok(plan) => {
            let selected = plan.archive_batch().map(|b| b.records.as_slice()).unwrap_or(&[]);
            if typed { selected_borsh = borsh::to_vec(&selected.to_vec()).unwrap(); }
            let sums = selected.iter().map(|x| x.retention_charge_paid).sum::<u128>();
            output[..5].copy_from_slice(&[
                selected.len() as u64, selected.iter().map(|x| x.encoded_bytes).sum(),
                sums as u64, (sums >> 64) as u64, plan.retained_records().len() as u64,
            ]);
            for (base, rows) in [(5, selected), (13, plan.retained_records())] {
                for (i, fact) in rows.iter().enumerate() {
                    output[base+i] = facts.iter().position(|x| x.task_id == fact.task_id).unwrap() as u64;
                }
            }
            0u32
        }
        Err(err) => match err.code() {
            AgentMarketErrorCodeV1::InvalidBounds => 1,
            AgentMarketErrorCodeV1::SchemaMismatch => 22,
            AgentMarketErrorCodeV1::InvalidContext => 200,
            AgentMarketErrorCodeV1::ConservationViolation => 15,
            AgentMarketErrorCodeV1::NonCanonical => 2,
            AgentMarketErrorCodeV1::Conflict => 18,
            AgentMarketErrorCodeV1::NotFound => 19,
            AgentMarketErrorCodeV1::ArithmeticOverflow => 20,
            other => panic!("unexpected projected error {other:?}"),
        },
    };
    let mut raw = Vec::new();
    if typed {
        let policy = borsh::to_vec(p).unwrap();
        for x in [policy.len() as u64, facts.len() as u64, holds.len() as u64, height, sequence] {
            raw.extend(x.to_le_bytes());
        }
        raw.extend(policy);
        for fact in facts { raw.extend(borsh::to_vec(fact).unwrap()); }
    } else {
        for x in [facts.len() as u64, holds.len() as u64, height, sequence,
                  u64::from(p.maximum_live_terminal_records), p.maximum_live_terminal_bytes,
                  u64::from(p.maximum_archive_batch_records), p.maximum_archive_batch_bytes] {
            raw.extend(x.to_le_bytes());
        }
        for fact in facts {
            raw.extend(fact.task_id.0);
            raw.extend(fact.terminal_height.to_le_bytes());
            raw.extend(fact.retention_paid_through_height.to_le_bytes());
            raw.extend(fact.encoded_bytes.to_le_bytes());
            raw.extend(fact.retention_charge_paid.to_le_bytes());
        }
    }
    for id in holds { raw.extend(id.0); }
    w.write_all(&status.to_le_bytes()).unwrap();
    w.write_all(&(raw.len() as u32).to_le_bytes()).unwrap();
    w.write_all(&raw).unwrap();
    for x in output { w.write_all(&x.to_le_bytes()).unwrap(); }
    if typed {
        w.write_all(&(selected_borsh.len() as u64).to_le_bytes()).unwrap();
        w.write_all(&selected_borsh).unwrap();
    }
}

fn main() {
    let context = ProtocolContextV1 {
        genesis_hash: Hash32V1([1;32]), chain_id: "bounded selection".to_owned(),
        protocol_version: 1, stack_profile_hash: Hash32V1([2;32]),
    };
    let mut p = TaskArchivePolicyV1 {
        schema_version: 1, context: context.clone(), minimum_terminal_retention_blocks: 5,
        maximum_live_terminal_records: 8, maximum_live_terminal_bytes: 800,
        maximum_archive_batch_records: 8, maximum_archive_batch_bytes: 800,
        retention_charge_units_per_byte_block: 2,
    };
    let mut facts: Vec<_> = (0..8u32).rev().map(|i| {
        let mut t = fixture::record(&context, i);
        t.terminal_height = 1 + u64::from(i/2);
        t.retention_paid_through_height = t.terminal_height + 4;
        t.task_id.0[0] = i as u8;
        t.task_id.0[1] = 255-i as u8;
        t
    }).collect();
    let mut w = io::stdout().lock();
    row(&mut w,&p,&[],BTreeSet::new(),20,0); // empty, no sequence needed.
    row(&mut w,&p,&facts,BTreeSet::new(),20,0); // native sort + no pressure.
    row(&mut w,&p,&facts,BTreeSet::from([TaskIdV1([0xee;32])]),20,0); // subset before no pressure.
    p.maximum_live_terminal_records = 3;
    row(&mut w,&p,&facts,BTreeSet::new(),20,0);
    row(&mut w,&p,&facts,BTreeSet::new(),20,1);
    row(&mut w,&p,&facts,BTreeSet::from([facts[7].task_id]),20,1);
    row(&mut w,&p,&facts,BTreeSet::new(),6,1); // inclusive hold and unresolved pressure.
    p.maximum_archive_batch_records = 2;
    row(&mut w,&p,&facts,BTreeSet::new(),20,1);
    p.maximum_archive_batch_records = 8;
    p.maximum_live_terminal_records = 8;
    p.maximum_live_terminal_bytes = 400;
    row(&mut w,&p,&facts,BTreeSet::new(),20,1); // byte-only pressure.
    p.maximum_live_terminal_bytes = 500;
    p.maximum_archive_batch_bytes = 300;
    facts[7].encoded_bytes = 401;
    facts[7].retention_charge_paid = 4010;
    p.maximum_live_terminal_bytes = 801;
    row(&mut w,&p,&facts,BTreeSet::new(),20,1); // skips first oversized and reaches exact caps.
    facts[7].encoded_bytes = 100;
    facts[7].retention_charge_paid = 1000;
    p.maximum_live_terminal_bytes = 500;
    facts[7].retention_charge_paid = u128::MAX;
    row(&mut w,&p,&facts,BTreeSet::new(),20,1); // selected charge overflow after resolving pressure.
    p.maximum_archive_batch_records = 1;
    row(&mut w,&p,&facts,BTreeSet::new(),20,1); // count pressure conflict before charge.
    p.maximum_archive_batch_records = 8;
    facts[7].retention_charge_paid = 1000;
    facts[6].task_id = facts[7].task_id;
    row(&mut w,&p,&facts,BTreeSet::from([TaskIdV1([0xef;32])]),20,1); // duplicate first.
    let mut frozen = fixture::record(&context, 17);
    frozen.encoded_bytes = 1;
    frozen.retention_paid_through_height = u64::MAX;
    frozen.retention_charge_paid = u128::MAX;
    p.maximum_live_terminal_records = 1;
    p.maximum_live_terminal_bytes = 100;
    p.retention_charge_units_per_byte_block = 1;
    let mut other = fixture::record(&context, 18);
    other.terminal_height = 2;
    other.retention_paid_through_height = 6;
    frozen.terminal_height = 1;
    let id = frozen.task_id;
    row(&mut w,&p,&[other.clone(),frozen.clone()],BTreeSet::new(),20,1); // expiry overflows.
    row(&mut w,&p,&[other,frozen],BTreeSet::from([id]),20,1); // held row skips expiry.
    if std::env::args_os().nth(1).is_some_and(|v| v == "typed") {
        let canonical = fixture::record(&context, 4);
        let mut earlier = fixture::record(&context, 0);
        let mut later = canonical.clone();
        let mut wrong = p.clone();
        wrong.schema_version = 2;
        wrong.maximum_live_terminal_bytes = 0;
        earlier.schema_version = 2;
        row(&mut w,&wrong,&[canonical.clone(),earlier.clone()],BTreeSet::new(),20,1); // policy version
        wrong.schema_version = 1;
        row(&mut w,&wrong,&[canonical.clone(),earlier.clone()],BTreeSet::new(),20,1); // policy bounds

        later.context.chain_id.push('x');
        row(&mut w,&p,&[later.clone(),earlier.clone()],BTreeSet::new(),20,1); // canonical earlier schema
        earlier.schema_version = 1;
        row(&mut w,&p,&[later,earlier.clone()],BTreeSet::new(),20,1); // full record context
        earlier.encoded_bytes = 0;
        row(&mut w,&p,&[canonical.clone(),earlier.clone()],BTreeSet::new(),20,1);
        earlier.encoded_bytes = 100;
        earlier.retention_charge_paid = 499;
        row(&mut w,&p,&[canonical.clone(),earlier.clone()],BTreeSet::new(),20,1); // original exact charge

        earlier.retention_charge_paid = 500;
        earlier.retention_paid_through_height = 4;
        row(&mut w,&p,&[canonical.clone(),earlier.clone()],BTreeSet::new(),20,1); // < mandatory
        earlier.retention_paid_through_height = 5;
        earlier.context.chain_id = "四\0".repeat(128);
        let mut max_policy = p.clone();
        max_policy.context = earlier.context.clone();
        let mut max_other = canonical;
        max_other.context = max_policy.context.clone();
        row(&mut w,&max_policy,&[max_other,earlier],BTreeSet::new(),20,1); // max 512-byte context
    }
}
