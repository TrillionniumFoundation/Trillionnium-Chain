//! Unchanged original in-memory planner and actual retained Borsh values only.
#[allow(dead_code)]
#[path = "rust_task_archive_inclusion_fold_reference.rs"]
mod shared;

use std::{collections::BTreeSet, io::{self, Write}};
use trnm_task_kernel::{
    plan_task_archive_pruning_v1, AgentMarketErrorCodeV1, Hash32V1, ProtocolContextV1,
    TaskArchivePolicyV1, TaskIdV1, TerminalTaskArchiveRecordV1,
};

fn emit(out: &mut impl Write, p: &TaskArchivePolicyV1, rows: &[TerminalTaskArchiveRecordV1],
        holds: BTreeSet<TaskIdV1>, height: u64, seq: u64) {
    let policy=borsh::to_vec(p).unwrap();
    let mut raw=Vec::new();
    for x in [policy.len() as u64, rows.len() as u64, holds.len() as u64,height,seq] {
        raw.extend_from_slice(&x.to_le_bytes());
    }
    raw.extend_from_slice(&policy);
    for row in rows { raw.extend_from_slice(&borsh::to_vec(row).unwrap()); }
    for id in &holds { raw.extend_from_slice(&id.0); }
    let (status, wire) = match plan_task_archive_pruning_v1(p,rows,&holds,height,seq,Hash32V1([0;32])) {
        Ok(plan) => (0u32,borsh::to_vec(&plan.retained_records().to_vec()).unwrap()),
        Err(e) => (match e.code() {
            AgentMarketErrorCodeV1::InvalidBounds=>1,
            AgentMarketErrorCodeV1::NonCanonical=>2,
            AgentMarketErrorCodeV1::Conflict=>18,
            AgentMarketErrorCodeV1::NotFound=>19,
            c=>panic!("Unexpected original result {c:?}"),
        },Vec::new()),
    };
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(raw.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&(wire.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&raw).unwrap();
    out.write_all(&wire).unwrap();
}

fn main() {
    let p=TaskArchivePolicyV1{schema_version:1,context:ProtocolContextV1{
        genesis_hash:Hash32V1([7;32]),chain_id:"合\0".repeat(128),protocol_version:3,
        stack_profile_hash:Hash32V1([4;32]),
    },minimum_terminal_retention_blocks:5,maximum_live_terminal_records:8,
        maximum_live_terminal_bytes:800,maximum_archive_batch_records:8,
        maximum_archive_batch_bytes:800,retention_charge_units_per_byte_block:2};
    let mut rows=(0..8).rev().map(|i| {
        let mut r=shared::record(&p.context,i);
        r.terminal_height=1+u64::from(i/2);
        r.retention_paid_through_height=r.terminal_height+4;
        r.task_revision=u64::MAX-u64::from(i);
        r.retention_charge_paid=(1u128<<64)+u128::from(i);
        r
    }).collect::<Vec<_>>();
    let mut out=io::stdout().lock();
    emit(&mut out,&p,&[],BTreeSet::new(),25,0);
    emit(&mut out,&p,&rows,BTreeSet::new(),25,0);
    rows.rotate_left(3);
    emit(&mut out,&p,&rows,BTreeSet::new(),25,0);
    let mut pressure=p.clone(); pressure.maximum_live_terminal_records=3;
    emit(&mut out,&pressure,&rows,BTreeSet::new(),25,1);
    emit(&mut out,&pressure,&rows,BTreeSet::from([TaskIdV1([0;32])]),25,1);
    emit(&mut out,&pressure,&rows,BTreeSet::new(),25,0);
    emit(&mut out,&pressure,&rows,BTreeSet::new(),5,1);
    emit(&mut out,&p,&rows,BTreeSet::from([TaskIdV1([99;32])]),25,1);
    let mut all=p.clone(); all.maximum_live_terminal_bytes=1;
    emit(&mut out,&all,&rows,BTreeSet::new(),25,1);
    rows[0].encoded_bytes=0;
    emit(&mut out,&p,&rows,BTreeSet::new(),25,1);
}
