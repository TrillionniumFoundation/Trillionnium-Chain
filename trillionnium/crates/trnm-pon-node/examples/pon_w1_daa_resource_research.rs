//! Bounded native DAA/time legality vectors, not a physical mining-cost campaign.
//! Original parameters, proof generator, Node admission and activation are used.
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_pon_node::{
    consensus::{self, Work},
    development_public, Node, Packet, Settings,
};
use trnm_protocol::pon_wire::Hash;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-native-daa-resource-v2";
const NON_GENESIS_BLOCKS: usize = 36;

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn emit(output: &mut impl Write, value: Value) -> Result<()> {
    serde_json::to_writer(&mut *output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn small_work(value: u64) -> Work {
    let mut bytes = [0; 64];
    bytes[56..].copy_from_slice(&value.to_be_bytes());
    Work::from_bytes(bytes)
}
fn assert_profile() -> Result<Hash> {
    // Read the existing public configuration owner. No Settings visibility or
    // runtime rule is changed to support this research example.
    let config = trnm_mvcc_fee::pon_executor::Config::installed()?;
    for (name, expected) in [
        ("retarget_interval", 16),
        ("target_spacing_seconds", 10),
        ("median_time_width", 11),
        ("retarget_factor", 4),
        ("future_skew_seconds", 120),
    ] {
        require(
            config.params[name].as_u64() == Some(expected),
            "PROFILE_CHANGED",
        )?;
    }
    let mut limit = [255; 32];
    limit[0] = 127;
    require(
        config.params["initial_target_hex"].as_str() == Some(hex::encode(limit).as_str())
            && config.params["pow_limit_hex"].as_str() == Some(hex::encode(limit).as_str()),
        "TARGET_PROFILE_CHANGED",
    )?;
    Ok(limit)
}

struct Built {
    packet: Packet,
    id: Hash,
    chainwork: Work,
    attempts: u64,
}
struct Context<'a> {
    node: &'a mut Node,
    output: &'a mut io::BufWriter<io::Stdout>,
    max_attempts: u64,
    ordinal: usize,
}
impl Context<'_> {
    fn block(
        &mut self,
        label: &str,
        parent: Hash,
        parent_work: Work,
        timestamp: u64,
        expected_work: u64,
    ) -> Result<Built> {
        let target = self.node.expected_target(parent)?;
        let delta = consensus::required_work(target)?;
        require(delta == small_work(expected_work), "EXPECTED_NATIVE_WORK")?;
        // Original sequential nonce search; no faster producer or forged proof.
        let packet = self.node.make(
            parent,
            Vec::new(),
            development_public(3)?,
            timestamp,
            self.max_attempts,
        )?;
        let observed_now = now()?;
        let id = self.node.admit(&packet, observed_now)?;
        require(id == packet.id()?, "NATIVE_PACKET_ID")?;
        require(packet.header.target == target, "NATIVE_TARGET")?;
        require(
            self.node.parent_height(id)? == packet.header.height,
            "NATIVE_HEIGHT",
        )?;
        let chainwork = parent_work.checked_add(delta)?;
        let observation = self.node.exact_packet_observation(&packet)?;
        require(
            observation["stored_exact"] == json!(true)
                && observation["block_chainwork_hex"] == json!(hex::encode(chainwork.bytes())),
            "NATIVE_CHAINWORK_READBACK",
        )?;
        let attempts = packet.header.nonce.checked_add(1).ok_or("NONCE")?;
        self.ordinal += 1;
        emit(
            self.output,
            json!({
                "schema":SCHEMA,"kind":"admitted-block","ordinal":self.ordinal,
                "label":label,"block":hex::encode(id),"parent":hex::encode(parent),
                "height":packet.header.height,"timestamp":packet.header.timestamp,
                "observed_now":observed_now,"target":hex::encode(target),
                "work":expected_work,"chainwork_hex":hex::encode(chainwork.bytes()),
                "native_search_attempts":attempts,"nonce":packet.header.nonce,
                "unsuccessful_proof_bytes_retained":false,
                "packet_hex":hex::encode(packet.encode()?),"observation":observation,
                "performance_claim":false,"production_activation":false
            }),
        )?;
        Ok(Built {
            packet,
            id,
            chainwork,
            attempts,
        })
    }
    fn activate(&mut self, built: &Built, label: &str) -> Result<()> {
        let observed_now = now()?;
        require(
            self.node.activate_observed(built.id, observed_now)? == built.id,
            "NATIVE_GREATER_WORK_ACTIVATION",
        )?;
        let stats = self.node.stats()?;
        require(
            stats["tip"] == json!(hex::encode(built.id))
                && stats["chainwork_hex"] == json!(hex::encode(built.chainwork.bytes())),
            "ACTIVATION_READBACK",
        )?;
        emit(
            self.output,
            json!({"schema":SCHEMA,"kind":"activation","label":label,
                "observed_now":observed_now,"stats":stats,"production_activation":false}),
        )
    }
}

fn pure_time_controls(observed_now: u64) -> Result<Value> {
    let ancestors = [600, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5];
    consensus::check_time(12, &ancestors, observed_now, 120)?;
    let median_error = consensus::check_time(10, &ancestors, observed_now, 120)
        .expect_err("strict median boundary")
        .to_string();
    let inclusive = observed_now.checked_add(120).ok_or("TIME_OVERFLOW")?;
    let future = observed_now.checked_add(121).ok_or("TIME_OVERFLOW")?;
    consensus::check_time(inclusive, &[1], observed_now, 120)?;
    let future_error = consensus::check_time(future, &[1], observed_now, 120)
        .expect_err("future boundary")
        .to_string();
    require(
        median_error == "TIME" && future_error == "TIME_DEFERRED",
        "NATIVE_TIME_ERRORS",
    )?;
    Ok(
        json!({"native_arithmetic_only":true,"observed_now":observed_now,
        "median_rejection":median_error,"future_rejection":future_error,
        "inclusive_future_timestamp":inclusive,"rejected_future_timestamp":future,
        "backdated_candidate":12,"parent_timestamp":600}),
    )
}

fn options() -> Result<(bool, u64)> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok((false, 4096)),
        [flag] if flag == "--pure-controls" => Ok((true, 4096)),
        [flag, value] if flag == "--max-attempts" => {
            let attempts = value.parse::<u64>()?;
            require((1..=4096).contains(&attempts), "WORK_BUDGET")?;
            Ok((false, attempts))
        }
        _ => Err("USAGE: [--pure-controls | --max-attempts 1..4096]".into()),
    }
}
fn run(output: &mut io::BufWriter<io::Stdout>) -> Result<()> {
    let (pure_only, max_attempts) = options()?;
    let started_at = now()?;
    emit(
        output,
        json!({"schema":SCHEMA,"kind":"native-time-controls",
        "controls":pure_time_controls(started_at)?}),
    )?;
    if pure_only {
        return Ok(());
    }
    let genesis_time = started_at.checked_sub(1200).ok_or("GENESIS_TIME")?;
    let settings = Settings::development(Some(genesis_time))?;
    let limit = assert_profile()?;
    emit(
        output,
        json!({"schema":SCHEMA,"kind":"start",
        "source_scope":"bounded-native-rule-legality-not-production-qualification",
        "started_at":started_at,"genesis_time":genesis_time,
        "genesis":hex::encode(settings.genesis()),"network":hex::encode(settings.network()),
        "parameters":hex::encode(settings.parameters()),"retarget_interval":16,
        "spacing_seconds":10,"median_width":11,"future_skew_seconds":120,
        "max_attempts_per_block":max_attempts,"planned_non_genesis_blocks":NON_GENESIS_BLOCKS,
        "new_valueless_development_namespace":true,"production_activation":false,
        "complete_failure_proofs_retained":false,"performance_claim":false}),
    )?;
    let directory = tempfile::tempdir()?;
    let mut node = Node::open(directory.path(), settings.clone(), 1)?;
    require(
        node.expected_target(settings.genesis())? == limit,
        "NATIVE_INITIAL_TARGET",
    )?;
    let mut context = Context {
        node: &mut node,
        output,
        max_attempts,
        ordinal: 0,
    };
    let mut parent = settings.genesis();
    let mut cumulative = Work::default();
    let mut attempts = 0_u64;
    for height in 1..=30 {
        let offset = if height == 16 { 11 } else { height };
        let expected_work = if height < 16 { 2 } else { 7 };
        let built = context.block(
            "common",
            parent,
            cumulative,
            genesis_time.checked_add(offset).ok_or("TIME_OVERFLOW")?,
            expected_work,
        )?;
        attempts = attempts.checked_add(built.attempts).ok_or("ATTEMPTS")?;
        context.activate(&built, "common")?;
        parent = built.id;
        cumulative = built.chainwork;
    }
    require(cumulative == small_work(135), "COMMON_WORK")?;
    let mut branches = Vec::new();
    let mut forest_work = cumulative;
    for (name, offset, expected_work, expected_chainwork) in [
        ("tighten", 31, 31, 173),
        ("unchanged", 161, 7, 149),
        ("ease", 611, 2, 144),
    ] {
        let first = context.block(
            name,
            parent,
            cumulative,
            genesis_time.checked_add(offset).ok_or("TIME_OVERFLOW")?,
            7,
        )?;
        let second = context.block(
            name,
            first.id,
            first.chainwork,
            genesis_time.checked_add(32).ok_or("TIME_OVERFLOW")?,
            expected_work,
        )?;
        require(
            second.chainwork == small_work(expected_chainwork),
            "BRANCH_WORK",
        )?;
        attempts = attempts
            .checked_add(first.attempts)
            .and_then(|n| n.checked_add(second.attempts))
            .ok_or("ATTEMPTS")?;
        forest_work = forest_work.checked_add(small_work(7 + expected_work))?;
        branches.push((name, second));
    }
    require(context.ordinal == NON_GENESIS_BLOCKS, "BLOCK_COUNT")?;
    require(forest_work == small_work(196), "FOREST_WORK")?;
    for (name, built) in branches.iter().rev() {
        context.activate(built, name)?;
    }
    let strongest = &branches[0].1;
    let before = context.node.stats()?;
    let replay_now = now()?;
    require(
        context.node.admit(&strongest.packet, replay_now)? == strongest.id,
        "REPLAY_ID",
    )?;
    require(
        context.node.activate_observed(strongest.id, replay_now)? == strongest.id,
        "REPLAY_TIP",
    )?;
    require(
        context.node.stats()? == before,
        "REPLAY_CHANGED_NATIVE_STATE",
    )?;
    // A weaker legal branch is still stored; activation must retain the heavier tip.
    require(
        context.node.activate_observed(branches[2].1.id, now()?)? == strongest.id,
        "WEAKER_BRANCH_REPLACED_TIP",
    )?;
    let final_stats = context.node.stats()?;
    emit(
        context.output,
        json!({"schema":SCHEMA,"kind":"complete",
        "admitted_non_genesis_blocks":context.ordinal,"native_search_attempts":attempts,
        "common_chainwork":135,"forest_work":196,"active_chainwork":173,
        "branch_work32":{"tighten":31,"unchanged":7,"ease":2},
        "branch_chainwork32":{"tighten":173,"unchanged":149,"ease":144},
        "replay_changed_state":false,"weaker_branch_replaced_tip":false,
        "retained_packet_count":context.ordinal,"stats":final_stats,
        "node_admission_and_activation_executed":true,"native_clock_parameter_relaxed":false,
        "proof_cost_campaign":false,"common_prefix_established":false,
        "O03_closed":false,"production_activation":false}),
    )
}
fn main() {
    let mut output = io::BufWriter::new(io::stdout());
    if let Err(error) = run(&mut output) {
        let _ = emit(
            &mut output,
            json!({"schema":SCHEMA,"kind":"failure",
            "error":error.to_string(),"successful_completion":false,
            "production_activation":false}),
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_native_timestamp_controls() {
        let result = pure_time_controls(1201).unwrap();
        assert_eq!(result["median_rejection"], json!("TIME"));
        assert_eq!(result["future_rejection"], json!("TIME_DEFERRED"));
    }

    #[test]
    fn actual_native_two_retarget_bookends() {
        let limit = assert_profile().unwrap();
        let first = consensus::retarget(limit, 1, 16, 16, 10, limit).unwrap();
        assert_eq!(consensus::required_work(first).unwrap(), small_work(7));
        for (last, expected) in [(32, 31), (162, 7), (612, 2)] {
            let second = consensus::retarget(first, 12, last, 16, 10, limit).unwrap();
            assert_eq!(
                consensus::required_work(second).unwrap(),
                small_work(expected)
            );
        }
    }
}
