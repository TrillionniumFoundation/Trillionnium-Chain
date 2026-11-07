//! Finite native reorganization cost observation, not original Host qualification.
//! Compare exact source binaries with the same fixture and retain every attempt.
use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Result, Settings};

const BLOCKS: u64 = 512;

fn cpu_ns() -> Result<u64> {
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime))
        .map_err(|_| "COST_CPU_UNAVAILABLE")?;
    let seconds = u64::try_from(value.tv_sec).map_err(|_| "COST_CPU_UNAVAILABLE")?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| "COST_CPU_UNAVAILABLE")?;
    if nanos >= 1_000_000_000 {
        return Err("COST_CPU_UNAVAILABLE".into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or_else(|| "COST_CPU_UNAVAILABLE".into())
}

fn run() -> Result<Value> {
    let entire_started = Instant::now();
    let entire_cpu = cpu_ns()?;
    let directory = tempfile::tempdir()?;
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )?;
    let mut builder = Node::open(&directory.path().join("builder"), settings.clone(), 1)?;
    let receiver_path = directory.path().join("receiver");
    let mut receiver = Node::open(&receiver_path, settings.clone(), 1)?;
    let mut packet_bytes = 0_u64;
    for height in 1..=BLOCKS {
        let packet = builder.make_consensus_maintenance(
            builder.active()?.0,
            vec![],
            development_public(3)?,
            1 + height * 10,
            4096,
        )?;
        packet_bytes = packet_bytes
            .checked_add(packet.encode()?.len() as u64)
            .ok_or("COST_BYTE_OVERFLOW")?;
        let target = builder.admit(&packet, 100_000)?;
        builder.activate_observed(target, 100_000)?;
        if receiver.admit(&packet, 100_000)? != target {
            return Err("COST_PACKET_IDENTITY".into());
        }
    }
    let expected = builder.read_active()?;
    if receiver.active()?.0 != settings.genesis() {
        return Err("COST_RECEIVER_NOT_GENESIS".into());
    }
    let preparation_wall_ns = entire_started.elapsed().as_nanos();
    let preparation_cpu_ns = cpu_ns()?
        .checked_sub(entire_cpu)
        .ok_or("COST_CPU_REGRESSED")?;
    if !receiver.enable_native_legacy_reorg_observation() {
        return Err("COST_OBSERVATION_UNAVAILABLE".into());
    }
    let before = receiver.native_history_arithmetic_observation();
    let started = Instant::now();
    let before_cpu = cpu_ns()?;
    let result = receiver.activate_observed(expected.0, 100_000);
    let activation_cpu_ns = cpu_ns()?
        .checked_sub(before_cpu)
        .ok_or("COST_CPU_REGRESSED")?;
    let activation_wall_ns = started.elapsed().as_nanos();
    let after = receiver.native_history_arithmetic_observation();
    result?;
    let actual = receiver.read_active()?;
    if actual.0 != expected.0 || actual.2 != expected.2 {
        return Err("COST_COMPLETE_STATE_MISMATCH".into());
    }
    drop(receiver);
    let reopened = Node::open(&receiver_path, settings.clone(), 1)?;
    if reopened.read_active()? != actual {
        return Err("COST_COLD_STATE_MISMATCH".into());
    }
    Ok(json!({
        "schema":"native-reorg-query-cost-v1",
        "completed":true,
        "planned_blocks":BLOCKS,
        "admitted_blocks":BLOCKS,
        "packet_bytes":packet_bytes,
        "backend":"legacy",
        "task_profile":continuity_v1::PROFILE,
        "store_source_sha256":hex::encode(Sha256::digest(include_bytes!("../src/store.rs"))),
        "observer_source_sha256":hex::encode(Sha256::digest(include_bytes!("native_reorg_query_cost.rs"))),
        "network":hex::encode(settings.network()),
        "parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),
        "target":hex::encode(actual.0),
        "preparation_wall_ns":preparation_wall_ns,
        "preparation_process_cpu_ns":preparation_cpu_ns,
        "activation_wall_ns":activation_wall_ns,
        "activation_process_cpu_ns":activation_cpu_ns,
        "entire_wall_ns":entire_started.elapsed().as_nanos(),
        "entire_process_cpu_ns":cpu_ns()?.checked_sub(entire_cpu).ok_or("COST_CPU_REGRESSED")?,
        "entire_scope":"from before temporary-store creation through final cold readback, before JSON emission and final owner/directory drops; the external runner must retain whole-process CPU/wall separately",
        "native_observation_before":before,
        "native_observation_after":after,
        "same_native_state":true,
        "cold_reopen_same_state":true,
        "scope":"one process, 512 real maintenance PNW1 packets, unchanged native admission and complete Legacy activation; preparation includes two owners and all W1 generation/replay; local cost only, no paid History or public Host traffic",
        "original_history_4105_accepted":false,
        "original_four_second_accepted":false,
        "public_network_ready":false,
        "production_activation":false
    }))
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            println!(
                "{}",
                json!({"schema":"native-reorg-query-cost-v1","completed":false,"planned_blocks":BLOCKS,"error":error.to_string(),"public_network_ready":false,"production_activation":false})
            );
            std::process::exit(1);
        }
    }
}
