//! Native W1 component observations for cold, reused and discarded cache state.
//! This executes the existing verifiers and the existing from-zero constructor.
//! It is not a Node, network, hard resource-isolation or task-fairness experiment.
#[path = "../../trnm-pon-node/examples/support/w1_from_zero.rs"]
mod w1_from_zero;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, time::Duration, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self, arithmetic_facts::ArithmeticFactCache, arithmetic_facts::ArithmeticObservation,
    facts::FactError, rejection_cache::RejectionCache, Hash, VerificationError,
    VerificationProgress, VerifiedWork, CELLS, PROOF_BYTES,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-work-expensive-verifier-v1";
const SELECTOR: &str = "--work-expensive-verifier-v1";
const PATHS: [&str; 3] = ["native-raw", "negative-cache", "arithmetic-facts"];
const SCENARIOS: [&str; 9] = [
    "distinct-material-cold",
    "exact-retransmission",
    "same-input-new-forgeries",
    "new-challenge",
    "one-slot-eviction",
    "owner-restart",
    "negative-ttl-expiry",
    "legal-cold-warm",
    "cheap-malformed",
];
const SAMPLES: usize = 8;
const SEARCH_LIMIT: u64 = 4096;

fn cpu() -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
        let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime))?;
        let seconds = u64::try_from(stamp.tv_sec)?;
        let nanos = u64::try_from(stamp.tv_nsec)?;
        if nanos >= 1_000_000_000 {
            return Err("VERIFIER_CLOCK_RANGE".into());
        }
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(nanos))
            .ok_or_else(|| "VERIFIER_CLOCK_RANGE".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("VERIFIER_ACTUAL_LINUX_THREAD_CLOCK_REQUIRED".into())
    }
}
struct Clock {
    cpu: u64,
    wall: Instant,
}
impl Clock {
    fn start() -> Result<Self> {
        Ok(Self {
            cpu: cpu()?,
            wall: Instant::now(),
        })
    }
    fn snapshot(&self) -> Result<Value> {
        Ok(json!({
            "cpu_ns": cpu()?.checked_sub(self.cpu).ok_or("VERIFIER_CLOCK_REWIND")?,
            "wall_ns": u64::try_from(self.wall.elapsed().as_nanos())?
        }))
    }
    fn finish(self) -> Result<Value> {
        self.snapshot()
    }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn emit(kind: &str, mut row: Value) -> Result<()> {
    let map = row.as_object_mut().ok_or("VERIFIER_RECORD_OBJECT")?;
    map.insert("schema".into(), SCHEMA.into());
    map.insert("kind".into(), kind.into());
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &row)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn target() -> Hash {
    let mut value = [255; 32];
    value[0] = 127;
    value
}
fn challenge(scenario: &str, index: usize) -> Hash {
    pon_work::hash(
        b"work-expensive-verifier-challenge-v1",
        &[scenario.as_bytes(), &(index as u64).to_le_bytes()],
    )
}

struct Material {
    a: Vec<u32>,
    b: Vec<u32>,
    task: Hash,
    prefix: Vec<u8>,
}
fn material(index: usize) -> Result<Material> {
    // Explicit synthetic public fixtures, not learned Hepta input claims.
    let mut a = vec![0_u32; CELLS];
    let mut b = vec![0_u32; CELLS];
    for i in 0..CELLS {
        a[i] = ((i * 17 + index * 13) % 251) as u32;
        b[i] = ((i * 29 + index * 31) % 241) as u32;
    }
    a[0] = index as u32;
    let task = pon_work::task_id(&a, &b).map_err(|e| format!("{e:?}"))?;
    let prefix = w1_from_zero::proof_prefix(&a, &b).map_err(|e| format!("{e:?}"))?;
    Ok(Material { a, b, task, prefix })
}
struct Candidate {
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: Vec<u8>,
    expected: &'static str,
}
fn candidate(
    scenario: &str,
    index: usize,
    material: &Material,
    prior: Option<&Candidate>,
) -> Result<(Candidate, Value)> {
    let started = Clock::start()?;
    let mut trials = Vec::new();
    let mut repeat_of = None;
    let mut method = "from-zero";
    let context_index = if scenario == "new-challenge" {
        index
    } else {
        0
    };
    let context = challenge(scenario, context_index);
    let mut value = if let Some(prior) = prior {
        method = "exact-byte-reuse";
        repeat_of = Some(if scenario == "one-slot-eviction" {
            index % 2
        } else {
            0
        });
        Candidate {
            challenge: prior.challenge,
            task: prior.task,
            target: prior.target,
            proof: prior.proof.clone(),
            expected: prior.expected,
        }
    } else if scenario == "cheap-malformed" {
        method = "malformed-encoding";
        Candidate {
            challenge: context,
            task: material.task,
            target: target(),
            proof: material.prefix.clone(),
            expected: "unused",
        }
    } else {
        let mut selected = None;
        let nonce_start = index as u64 * SEARCH_LIMIT;
        for nonce in nonce_start..nonce_start + SEARCH_LIMIT {
            let (trial_context, trace, proof) = if scenario == "legal-cold-warm" {
                method = "legal-native-prove";
                let fresh = challenge(scenario, nonce as usize);
                let proof = pon_work::prove(fresh, &material.a, &material.b)
                    .map_err(|e| format!("{e:?}"))?;
                let trace: Hash = proof[PROOF_BYTES - 32..].try_into()?;
                (fresh, trace, Some(proof))
            } else {
                let (trace, _) = w1_from_zero::trial(context, nonce);
                (context, trace, None)
            };
            let ticket = pon_work::hash(b"ticket", &[&trial_context, &trace]);
            let hit = ticket <= target();
            trials.push(
                json!({"nonce": nonce, "challenge": hex::encode(trial_context),
                "trace": hex::encode(trace), "ticket": hex::encode(ticket), "target_hit": hit}),
            );
            if hit {
                let mut proof = proof.unwrap_or_else(|| material.prefix.clone());
                proof[PROOF_BYTES - 32..].copy_from_slice(&trace);
                selected = Some(Candidate {
                    challenge: trial_context,
                    task: material.task,
                    target: target(),
                    proof,
                    expected: if scenario == "legal-cold-warm" {
                        "Accepted"
                    } else {
                        "Transcript"
                    },
                });
                break;
            }
        }
        match selected {
            Some(value) => value,
            None => {
                // A fixed budget miss is retained and fails the planned grid;
                // it is never replaced with a fresh seed until a winner appears.
                emit(
                    "exhausted",
                    json!({"scenario": scenario, "index": index,
                    "method": method, "trials": trials, "timing": started.finish()?}),
                )?;
                return Err("VERIFIER_FIXED_SEARCH_EXHAUSTED".into());
            }
        }
    };
    if scenario == "cheap-malformed" {
        match index {
            0 => {
                value.proof.pop();
                value.expected = "Length";
            }
            1 => {
                value.proof[0] = b'X';
                value.expected = "Version";
            }
            2 => {
                value.target = [0; 32];
                value.expected = "Target";
            }
            3..=5 => {
                let start = 4 + (index - 3) * CELLS * 4;
                value.proof[start..start + 4].copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
                value.expected = "Field";
            }
            6 => {
                value.task[0] ^= 1;
                value.expected = "Task";
            }
            _ => {
                value.target = [0; 32];
                value.target[31] = 1;
                value.expected = "Target";
            }
        }
    }
    // Preserve the actual algorithm interval before proof hex/hash diagnostics.
    // Every completed losing trial, nonce search, and actual proof clone remains
    // charged. The enclosing timer also retains diagnostic overhead separately;
    // logging cannot make an attacker look expensive in the operation ratio.
    let operation_timing = started.snapshot()?;
    let record = json!({"scenario": scenario, "index": index, "method": method,
        "repeat_of": repeat_of, "challenge_index": context_index,
        "challenge": hex::encode(value.challenge), "task": hex::encode(value.task),
        "target": hex::encode(value.target), "expected_outcome": value.expected,
        "proof_hex": hex::encode(&value.proof), "proof_sha256": sha(&value.proof),
        "trial_limit": SEARCH_LIMIT, "trials": trials, "operation_timing": operation_timing});
    let mut record = record;
    record
        .as_object_mut()
        .unwrap()
        .insert("timing".into(), started.finish()?);
    Ok((value, record))
}

struct Owners {
    negative: RejectionCache,
    arithmetic: ArithmeticFactCache,
    epoch: usize,
    capacity: usize,
    created: Instant,
}
impl Owners {
    fn new(scenario: &str, epoch: usize) -> Result<Self> {
        let created = Instant::now();
        let capacity = if scenario == "one-slot-eviction" {
            1
        } else {
            64
        };
        let ttl_ms = if scenario == "negative-ttl-expiry" {
            5
        } else {
            30_000
        };
        let clock = Clock::start()?;
        let negative = RejectionCache::new(capacity, Duration::from_millis(ttl_ms))
            .ok_or("VERIFIER_NEGATIVE_CONFIGURATION")?;
        let negative_timing = clock.finish()?;
        let clock = Clock::start()?;
        let arithmetic = ArithmeticFactCache::new(capacity)?;
        let arithmetic_timing = clock.finish()?;
        emit(
            "owner",
            json!({"scenario": scenario, "epoch": epoch, "capacity": capacity,
            "negative_ttl_ms": ttl_ms, "negative_setup": negative_timing,
            "arithmetic_setup": arithmetic_timing,
            "arithmetic_software_bytes": arithmetic.software_bytes()}),
        )?;
        Ok(Self {
            negative,
            arithmetic,
            epoch,
            capacity,
            created,
        })
    }
}
fn verdict<E>(result: std::result::Result<VerifiedWork, VerificationError<E>>) -> String {
    match black_box(result) {
        Ok(work) => {
            drop(work);
            "Accepted".into()
        }
        Err(VerificationError::Relation(e)) => format!("{e:?}"),
        Err(VerificationError::Cancelled(_)) => "Cancelled".into(),
    }
}
fn verify(
    scenario: &str,
    index: usize,
    path: usize,
    value: &Candidate,
    owners: &Owners,
) -> Result<bool> {
    let started = Clock::start()?;
    let mut tiles = 0;
    let mut before_replay = 0;
    let mut before_product = 0;
    let mut before_verified = 0;
    let mut progress = |point| {
        match point {
            VerificationProgress::TranscriptTile { .. } => tiles += 1,
            VerificationProgress::BeforeReplay => before_replay += 1,
            VerificationProgress::BeforeProduct => before_product += 1,
            VerificationProgress::BeforeVerifiedWork => before_verified += 1,
            _ => {}
        }
        Ok::<(), ()>(())
    };
    let mut arithmetic = ArithmeticObservation::default();
    let outcome = match path {
        0 => verdict(pon_work::verify_with_progress(
            value.challenge,
            value.task,
            value.target,
            &value.proof,
            &mut progress,
        )),
        1 => verdict(owners.negative.verify_with_progress(
            value.challenge,
            value.task,
            value.target,
            &value.proof,
            &mut progress,
        )),
        _ => match black_box(owners.arithmetic.verify_with_observation(
            value.challenge,
            value.task,
            value.target,
            &value.proof,
            &mut progress,
            &mut arithmetic,
        )) {
            Ok(work) => {
                drop(work);
                "Accepted".into()
            }
            Err(FactError::Relation(e)) => format!("{e:?}"),
            Err(FactError::Cancelled(_)) => "Cancelled".into(),
            Err(FactError::Unavailable) => "Unavailable".into(),
        },
    };
    let timing = started.finish()?;
    emit(
        "verification",
        json!({"scenario": scenario, "index": index, "path": PATHS[path],
            "epoch": owners.epoch, "capacity": owners.capacity, "outcome": outcome,
            "owner_age_wall_ns": u64::try_from(owners.created.elapsed().as_nanos())?,
        "timing": timing, "tiles": tiles, "before_replay": before_replay,
        "before_product": before_product, "before_verified": before_verified,
        "arithmetic": if path == 2 { Some(json!({
            "exact_fact_found": arithmetic.exact_fact_found,
            "trace_reused": arithmetic.trace_reused,
            "product_reused": arithmetic.product_reused,
            "transcript_entered": arithmetic.transcript_entered,
            "transcript_completed": arithmetic.transcript_completed,
            "lookup_probes": arithmetic.lookup_probes,
            "publication_probes": arithmetic.publication_probes,
        })) } else { None }}),
    )?;
    Ok(outcome == value.expected)
}
fn run() -> Result<()> {
    if std::env::args().skip(1).collect::<Vec<_>>().as_slice() != [SELECTOR] {
        return Err("VERIFIER_FIXED_SELECTOR_REQUIRED".into());
    }
    let total = Clock::start()?;
    emit(
        "header",
        json!({"profile": pon_work::PROFILE, "scenarios": SCENARIOS,
        "samples": SAMPLES, "paths": PATHS, "proof_bytes": PROOF_BYTES,
        "native_component_execution": true, "synthetic_public_material": true,
        "node_runtime_measured": false, "resource_fairness_qualified": false,
        "work_hardness_qualified": false, "production_activation": false}),
    )?;
    let mut all_expected = true;
    for scenario in SCENARIOS {
        let material_count = match scenario {
            "distinct-material-cold" => SAMPLES,
            "one-slot-eviction" => 2,
            _ => 1,
        };
        let setup = Clock::start()?;
        let materials = (0..material_count)
            .map(material)
            .collect::<Result<Vec<_>>>()?;
        emit(
            "preparation",
            json!({"scenario": scenario, "material_count": material_count,
            "tasks": materials.iter().map(|m| hex::encode(m.task)).collect::<Vec<_>>(),
            "timing": setup.finish()?}),
        )?;
        // Construct the complete attacker stream first. Verifier work never
        // appears in attacker preparation/search timing or cache amortization.
        let mut candidates: Vec<Candidate> = Vec::new();
        for index in 0..SAMPLES {
            let material_index = match scenario {
                "distinct-material-cold" => index,
                "one-slot-eviction" => index % 2,
                _ => 0,
            };
            let reused = match scenario {
                "exact-retransmission"
                | "owner-restart"
                | "negative-ttl-expiry"
                | "legal-cold-warm"
                    if index > 0 =>
                {
                    candidates.first()
                }
                "one-slot-eviction" if index >= 2 => candidates.get(index % 2),
                _ => None,
            };
            let (value, mut record) =
                candidate(scenario, index, &materials[material_index], reused)?;
            record
                .as_object_mut()
                .unwrap()
                .insert("material_index".into(), material_index.into());
            emit("candidate", record)?;
            candidates.push(value);
        }
        let mut owners = Owners::new(scenario, 0)?;
        for (index, value) in candidates.iter().enumerate() {
            if scenario == "owner-restart" && index > 0 && index % 2 == 0 {
                owners = Owners::new(scenario, owners.epoch + 1)?;
            }
            if scenario == "negative-ttl-expiry" && index > 0 {
                let waiting = Clock::start()?;
                std::thread::sleep(Duration::from_millis(20));
                emit(
                    "lifecycle-wait",
                    json!({"scenario": scenario, "index": index,
                    "reason": "expire-negative-cache", "timing": waiting.finish()?}),
                )?;
            }
            for order in 0..PATHS.len() {
                let path = (index + order) % PATHS.len();
                all_expected &= verify(scenario, index, path, value, &owners)?;
            }
        }
    }
    emit(
        "footer",
        json!({"scenarios_completed": SCENARIOS.len(),
        "candidates_completed": SCENARIOS.len() * SAMPLES,
        "verifications_completed": SCENARIOS.len() * SAMPLES * PATHS.len(),
        "all_expected_outcomes": all_expected, "total_including_diagnostics": total.finish()?}),
    )?;
    if !all_expected {
        return Err("VERIFIER_NATIVE_OUTCOME_DISAGREEMENT".into());
    }
    Ok(())
}
fn main() -> Result<()> {
    run()
}
