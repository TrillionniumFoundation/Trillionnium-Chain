//! Finite native W1 experiment: identical trace, eager versus winner-only PNW1.
//! Full setup/miner/receiver/audit CPU is observed. No consensus rule changes.
#[path = "support/w1_deferred_producer.rs"]
mod producer;

use producer::DeferredPrepared;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{self, Hash};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::Header;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-late-assembly-research-v1";
const NOW: u64 = 100_000;
const MAKE_LIMIT: u64 = 64;

#[derive(Clone, Debug, Serialize)]
struct Options {
    setup_budget_ns: u64,
    miner_budget_ns: u64,
    max_attempts: u64,
    seed: u64,
    mode: String,
}
impl Options {
    fn read() -> Result<Self> {
        let mut out = Self {
            setup_budget_ns: 1_000_000_000,
            miner_budget_ns: 128_000_000,
            max_attempts: 4096,
            seed: 1,
            mode: "eager".into(),
        };
        let args: Vec<_> = std::env::args().skip(1).collect();
        if !args.len().is_multiple_of(2) {
            return Err("OPTION_PAIRS".into());
        }
        let mut used = std::collections::BTreeSet::new();
        for pair in args.chunks_exact(2) {
            if !used.insert(&pair[0]) {
                return Err("DUPLICATE_OPTION".into());
            }
            match pair[0].as_str() {
                "--setup-budget-ns" => out.setup_budget_ns = pair[1].parse()?,
                "--miner-budget-ns" => out.miner_budget_ns = pair[1].parse()?,
                "--max-attempts" => out.max_attempts = pair[1].parse()?,
                "--seed" => out.seed = pair[1].parse()?,
                "--mode" => out.mode.clone_from(&pair[1]),
                _ => return Err("UNKNOWN_OPTION".into()),
            }
        }
        if !(1..=4096).contains(&out.max_attempts)
            || out.seed > u64::from(u32::MAX)
            || !["eager", "deferred"].contains(&out.mode.as_str())
        {
            return Err("OPTION_BOUNDS".into());
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Stamp {
    process_cpu_ns: u64,
    wall_ns: u64,
}
#[cfg(target_os = "linux")]
fn cpu() -> Result<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime))?;
    let nanos = u64::try_from(t.tv_nsec)?;
    if nanos >= 1_000_000_000 {
        return Err("CPU_NANOS".into());
    }
    u64::try_from(t.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .ok_or_else(|| "CPU_OVERFLOW".into())
}
#[cfg(not(target_os = "linux"))]
fn cpu() -> Result<u64> {
    Err("LINUX_PROCESS_CLOCK_REQUIRED".into())
}
struct Journal {
    cpu_origin: u64,
    wall_origin: Instant,
    phase: &'static str,
    start: Stamp,
    sequence: u64,
}
impl Journal {
    fn new() -> Result<Self> {
        Ok(Self {
            cpu_origin: cpu()?,
            wall_origin: Instant::now(),
            phase: "setup",
            start: Stamp {
                process_cpu_ns: 0,
                wall_ns: 0,
            },
            sequence: 0,
        })
    }
    fn stamp(&self) -> Result<Stamp> {
        Ok(Stamp {
            process_cpu_ns: cpu()?.checked_sub(self.cpu_origin).ok_or("CPU_REVERSED")?,
            wall_ns: self.wall_origin.elapsed().as_nanos().try_into()?,
        })
    }
    fn elapsed(&self, stamp: Stamp) -> u64 {
        stamp.process_cpu_ns - self.start.process_cpu_ns
    }
    fn emit(&mut self, mut value: Value) -> Result<()> {
        let row = value.as_object_mut().ok_or("RECORD_OBJECT")?;
        row.insert("schema".into(), json!(SCHEMA));
        row.insert("sequence".into(), json!(self.sequence));
        row.insert("phase".into(), json!(self.phase));
        row.insert("observed".into(), json!(self.stamp()?));
        let mut out = std::io::stdout().lock();
        serde_json::to_writer(&mut out, &value)?;
        out.write_all(b"\n")?;
        out.flush()?;
        self.sequence += 1;
        Ok(())
    }
    fn transition(&mut self, next: &'static str) -> Result<u64> {
        let end = self.stamp()?;
        let elapsed = self.elapsed(end);
        let old = self.phase;
        let start = self.start;
        self.phase = next;
        self.start = end;
        self.emit(json!({"kind":"boundary", "from":old,"to":next,
            "begin":start,"end":end,"elapsed_cpu_ns":elapsed,
            "boundary_encoding_charged_to_next_phase":true}))?;
        Ok(elapsed)
    }
}
fn relation<T>(v: std::result::Result<T, pon_work::WorkError>) -> Result<T> {
    v.map_err(|e| format!("WORK:{e:?}").into())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn identity(header: &Header, trace: Hash) -> (Hash, Hash) {
    let challenge = header.challenge();
    let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
    (
        ticket,
        pon_work::hash(
            b"w1-cost-game-semantic-ticket-v1",
            &[&header.work_task, &challenge, &ticket],
        ),
    )
}
fn proof_value(proof: &[u8]) -> Value {
    json!({"hex":hex::encode(proof),"bytes":proof.len(),"sha256":sha(proof)})
}
fn statement(header: &Header, trace: Hash) -> Value {
    let (ticket, semantic) = identity(header, trace);
    json!({"header_hex":hex::encode(header.encode()),"trace":hex::encode(trace),
        "challenge":hex::encode(header.challenge()),"ticket":hex::encode(ticket),
        "semantic_id":hex::encode(semantic),"block_id":hex::encode(header.block_id(trace)),
        "target_hit":header.target != [0;32] && ticket<=header.target})
}
struct Attempt {
    header: Header,
    trace: Hash,
    proof: Option<Vec<u8>>,
    hit: bool,
    within: bool,
}

// Intentionally no Node, verifier, receiver result or mutable target input.
fn mine(
    j: &mut Journal,
    o: &Options,
    prepared: &DeferredPrepared,
    template: &Header,
) -> Result<Vec<Attempt>> {
    let mut attempts = Vec::new();
    while (attempts.len() as u64) < o.max_attempts {
        let begin = j.stamp()?;
        if j.elapsed(begin) >= o.miner_budget_ns {
            break;
        }
        let ordinal = attempts.len() as u64;
        let mut header = template.clone();
        header.nonce = (1_u64 << 63) + o.seed * 4096 + ordinal;
        let trace = relation(prepared.trace(header.challenge()))?;
        let trace_done = j.stamp()?;
        let (ticket, _) = identity(&header, trace);
        let hit = header.target != [0; 32] && ticket <= header.target;
        let proof = (o.mode == "eager" || hit).then(|| prepared.assemble(trace));
        let proof_ready = j.stamp()?;
        j.emit(
            json!({"kind":"attempt","ordinal":ordinal,"begin":begin,"trace_done":trace_done,
            "proof_ready":proof_ready,"statement":statement(&header,trace),
            "proof":proof.as_ref().map(|p| proof_value(p)),"node_or_verifier_called":false}),
        )?;
        // Availability follows the original byte record's successful write AND flush.
        let available = j.stamp()?;
        let within = j.elapsed(available) <= o.miner_budget_ns;
        j.emit(
            json!({"kind":"available","ordinal":ordinal,"available":available,
            "elapsed_cpu_ns":j.elapsed(available),"within_miner_budget":within,
            "full_proof_flushed":proof.is_some(),"original_trace_flushed":true}),
        )?;
        attempts.push(Attempt {
            header,
            trace,
            proof,
            hit,
            within,
        });
    }
    Ok(attempts)
}

fn run(o: Options) -> Result<()> {
    let mut j = Journal::new()?;
    j.emit(
        json!({"kind":"start","options":o,"phase_order":["setup","miner","receiver","audit","done"],
        "cpu_scope":"process-CPU-with-all-original-output-until-flush",
        "physical_cost_lower_bound":false,"production_activation":false,
        "same_trace_kernel_in_both_modes":true,"proof_compression":false}),
    )?;
    let mut context = None;
    let mut setup_packet = None;
    let mut prepared = None;
    let begin = j.stamp()?;
    if j.elapsed(begin) < o.setup_budget_ns {
        let directory = tempfile::tempdir()?;
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )?;
        let (model, input, a, b) = settings.consensus_maintenance_material()?;
        let node = Node::open(directory.path(), settings, 2)?;
        let genesis = node.active()?.0;
        j.emit(json!({"kind":"context","begin":begin,"genesis":hex::encode(genesis),"model_hex":hex::encode(model),
            "input_hex":hex::encode(input),"task":hex::encode(relation(pon_work::task_id(&a,&b))?),
            "observed_now":NOW,"maintenance_is_real_training":false}))?;
        context = Some((node, directory, a, b, genesis));
    }
    let begin = j.stamp()?;
    if j.elapsed(begin) < o.setup_budget_ns {
        if let Some((node, _, _, _, genesis)) = context.as_mut() {
            let packet = node.make_consensus_maintenance(
                *genesis,
                vec![],
                development_public(0)?,
                11,
                MAKE_LIMIT,
            )?;
            let trace: Hash = packet.proof[pon_work::PROOF_BYTES - 32..].try_into()?;
            let id = node.admit(&packet, NOW)?;
            if node.active()?.0 != *genesis
                || packet.header.target != node.expected_target(*genesis)?
            {
                return Err("SETUP_NATIVE_CONTEXT".into());
            }
            j.emit(json!({"kind":"setup-proof","begin":begin,"statement":statement(&packet.header,trace),"proof":proof_value(&packet.proof),
                "native_block_id":hex::encode(id),"original_completed_attempts":packet.header.nonce+1,
                "original_miss_bytes_retained":false,"setup_credit_is_separate":true,"research_activation":false}))?;
            setup_packet = Some(packet);
        }
    }
    let begin = j.stamp()?;
    if j.elapsed(begin) < o.setup_budget_ns && setup_packet.is_some() {
        let (_, _, a, b, _) = context.as_ref().ok_or("MISSING_CONTEXT")?;
        prepared = Some(relation(DeferredPrepared::new(a, b))?);
        j.emit(json!({"kind":"prepared","begin":begin,"original_AB_and_prefix_paid_in_setup":true,"arm":"integer-paired-general"}))?;
    }
    let setup_completed_at = j.stamp()?;
    let setup_complete = prepared.is_some() && j.elapsed(setup_completed_at) <= o.setup_budget_ns;
    let setup_cpu = j.transition("miner")?;
    let attempts = if setup_complete {
        mine(
            &mut j,
            &o,
            prepared.as_ref().ok_or("MISSING_PREPARED")?,
            &setup_packet.as_ref().ok_or("MISSING_TEMPLATE")?.header,
        )?
    } else {
        Vec::new()
    };
    let miner_cpu = j.transition("receiver")?;
    let mut native_accepted = 0;
    let mut native_accepted_from_b = 0;
    if let Some((node, _, _, _, genesis)) = context.as_mut() {
        for (ordinal, a) in attempts.iter().enumerate().filter(|(_, a)| a.hit) {
            let packet = Packet {
                header: a.header.clone(),
                transactions: vec![],
                proof: a.proof.clone().ok_or("WINNER_PROOF_REQUIRED")?,
            };
            let id = node.admit(&packet, NOW)?;
            if id != packet.id()? || node.active()?.0 != *genesis {
                return Err("RECEIVER_NATIVE_CONTEXT".into());
            }
            native_accepted += 1;
            native_accepted_from_b += u64::from(a.within);
            j.emit(json!({"kind":"receiver","ordinal":ordinal,"native_block_id":hex::encode(id),
                "within_miner_budget":a.within,"active_unchanged":true,"mature_reward_claim":false}))?;
        }
    }
    // State owner and temporary directory teardown are charged to receiver.
    drop(context);
    let receiver_cpu = j.transition("audit")?;
    for (ordinal, a) in attempts.iter().enumerate() {
        let proof = match &a.proof {
            Some(p) => p.clone(),
            None => prepared
                .as_ref()
                .ok_or("MISSING_PREPARED")?
                .assemble(a.trace),
        };
        relation(pon_work::verify(
            a.header.challenge(),
            a.header.work_task,
            [255; 32],
            &proof,
        ))?;
        relation(pon_work::verify_reference(
            a.header.challenge(),
            a.header.work_task,
            [255; 32],
            &proof,
        ))?;
        let actual = pon_work::verify(
            a.header.challenge(),
            a.header.work_task,
            a.header.target,
            &proof,
        );
        if a.hit != actual.is_ok()
            || (!a.hit && !matches!(actual, Err(pon_work::WorkError::Target)))
        {
            return Err("TARGET_AUDIT".into());
        }
        j.emit(json!({"kind":"audit","ordinal":ordinal,"posthoc_proof":a.proof.is_none().then(|| proof_value(&proof)),
            "full_relation":true,"reference_relation":true,"actual_target_hit":a.hit,
            "posthoc_new_credit":0,"provides_miner_feedback":false}))?;
    }
    if let Some(packet) = &setup_packet {
        // Include all acquisition attempts in audit. Original misses were paid in P,
        // but these reconstructed bytes cannot attest when the original bytes existed.
        let p = if let Some(p) = prepared {
            p
        } else {
            let settings = Settings::development_with_profiles(
                Some(1),
                "native-public-evaluation-dev-v1",
                continuity_v1::PROFILE,
            )?;
            let (_, _, a, b) = settings.consensus_maintenance_material()?;
            relation(DeferredPrepared::new(&a, &b))?
        };
        for nonce in 0..=packet.header.nonce {
            let mut header = packet.header.clone();
            header.nonce = nonce;
            let proof = p.assemble(relation(p.trace(header.challenge()))?);
            let trace: Hash = proof[pon_work::PROOF_BYTES - 32..].try_into()?;
            relation(pon_work::verify_reference(
                header.challenge(),
                header.work_task,
                [255; 32],
                &proof,
            ))?;
            let hit = identity(&header, trace).0 <= header.target;
            let original_winner = nonce == packet.header.nonce;
            if hit != original_winner || (original_winner && proof != packet.proof) {
                return Err("ACQUISITION_RECONSTRUCTION".into());
            }
            j.emit(json!({"kind":"setup-reconstruction","nonce":nonce,"statement":statement(&header,trace),"proof":proof_value(&proof),
                "original_winner":original_winner,"original_bytes_observed":original_winner,"new_work_credit":0}))?;
        }
    }
    let audit_cpu = j.transition("done")?;
    let complete = attempts.iter().filter(|a| a.within).count();
    let full = attempts
        .iter()
        .filter(|a| a.within && a.proof.is_some())
        .count();
    let wins = attempts.iter().filter(|a| a.within && a.hit).count();
    j.emit(json!({"kind":"end","status":"PASS","setup_complete":setup_complete,"setup_completed_at":setup_completed_at,
        "attempts":attempts.len(),"traces_available_by_B":complete,"full_proofs_available_by_B":full,
        "full_winners_available_by_B":wins,"native_accepted":native_accepted,
        "native_accepted_from_B":native_accepted_from_b,"censored_by_attempt_cap":attempts.len() as u64==o.max_attempts,
        "phase_cpu_ns":{"setup":setup_cpu,"miner":miner_cpu,"receiver":receiver_cpu,"audit":audit_cpu},
        "native_total_endpoint":j.stamp()?,"candidate_chain_activation":false,
        "minimum_attacker_cost_established":false,"production_activation":false}))?;
    Ok(())
}
fn main() {
    if let Err(e) = Options::read().and_then(run) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deferred_and_eager_equal_original_relation_for_distinct_materials() {
        use pon_work::{CELLS, Q};
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap();
        let (_, _, a, b) = settings.consensus_maintenance_material().unwrap();
        for (a, b) in [
            (a, b),
            (vec![0; CELLS], vec![(Q - 1) as u32; CELLS]),
            (vec![(Q - 1) as u32; CELLS], vec![(Q - 1) as u32; CELLS]),
        ] {
            let p = DeferredPrepared::new(&a, &b).unwrap();
            for challenge in [[0; 32], [17; 32]] {
                let trace = p.trace(challenge).unwrap();
                let assembled = p.assemble(trace);
                assert_eq!(assembled, pon_work::prove(challenge, &a, &b).unwrap());
                let task = pon_work::task_id(&a, &b).unwrap();
                assert!(pon_work::verify_reference(challenge, task, [255; 32], &assembled).is_ok());
                let mut wrong = assembled;
                wrong[pon_work::PROOF_BYTES - 1] ^= 1;
                assert!(matches!(
                    pon_work::verify(challenge, task, [255; 32], &wrong),
                    Err(pon_work::WorkError::Transcript)
                ));
            }
        }
    }
}
