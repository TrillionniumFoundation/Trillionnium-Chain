//! Fixed native component experiment: no valid proof is acquired by the forgery arm.
//! No JSON/hex formatting or output occurs inside construction/verification clocks.
//! This does not measure Node admission, network service, or a cheapest strategy.
#[path = "../../trnm-pon-node/examples/support/w1_from_zero.rs"]
mod w1_from_zero;
#[path = "support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self,
    arithmetic_facts::ArithmeticFactCache,
    facts::FactError,
    legal_attempt::{Arithmetic, Materialization, Task},
    Hash, VerificationError, VerificationProgress, PROOF_BYTES,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-from-zero-filter-cost-v1";
const SELECTOR: &str = "--from-zero-filter-cost-v1";
const CLASSES: [&str; 2] = ["zero", "full-rank-field"];
const BITS: [u8; 3] = [1, 4, 8];
const SAMPLES: u64 = 8;
const LIMIT: u64 = 4096;
const PATHS: [&str; 6] = [
    "precheck",
    "raw-first",
    "raw-repeat",
    "arithmetic-cold",
    "arithmetic-hot",
    "scalar-reference",
];

fn cpu() -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
        let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime))?;
        let seconds = u64::try_from(stamp.tv_sec)?;
        let nanos = u64::try_from(stamp.tv_nsec)?;
        if nanos >= 1_000_000_000 {
            return Err("FILTER_CLOCK_RANGE".into());
        }
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(nanos))
            .ok_or_else(|| "FILTER_CLOCK_RANGE".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("FILTER_LINUX_THREAD_CLOCK_REQUIRED".into())
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
    fn finish(self) -> Result<Value> {
        let cpu_ns = cpu()?.checked_sub(self.cpu).ok_or("FILTER_CLOCK_REWIND")?;
        let wall_ns = u64::try_from(self.wall.elapsed().as_nanos())?;
        Ok(json!({"cpu_ns": cpu_ns, "wall_ns": wall_ns}))
    }
}
fn emit(kind: &str, mut row: Value) -> Result<()> {
    let map = row.as_object_mut().ok_or("FILTER_RECORD_OBJECT")?;
    map.insert("schema".into(), SCHEMA.into());
    map.insert("kind".into(), kind.into());
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &row)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn target(bits: u8) -> Hash {
    let mut value = [255; 32];
    value[0] = (u16::from(u8::MAX) >> bits) as u8;
    value
}
fn context(task: Hash, sample: u64, bits: u8, nonce: u64) -> Hash {
    pon_work::hash(
        b"pon-from-zero-filter-challenge-v1",
        &[&task, &sample.to_le_bytes(), &[bits], &nonce.to_le_bytes()],
    )
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Trial {
    nonce: u64,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
    hit: bool,
}
impl Trial {
    fn record(&self) -> Value {
        json!({"nonce": self.nonce, "challenge": hex::encode(self.challenge),
            "trace": hex::encode(self.trace), "ticket": hex::encode(self.ticket),
            "target_hit": self.hit})
    }
}
struct Search {
    trials: Vec<Trial>,
    winner: Option<(Hash, Vec<u8>)>,
}

fn false_search(prefix: &[u8], challenge: Hash, limit: Hash) -> Search {
    // Allocation and every retained binary trial record are part of this interval.
    // The shared constructor computes trace AND ticket once per attempted nonce.
    let mut trials = Vec::new();
    for nonce in 0..LIMIT {
        let (trace, ticket) = w1_from_zero::trial(challenge, nonce);
        let hit = ticket <= limit;
        trials.push(Trial {
            nonce,
            challenge,
            trace,
            ticket,
            hit,
        });
        if hit {
            let mut proof = prefix.to_vec();
            proof[PROOF_BYTES - 32..].copy_from_slice(&trace);
            return Search {
                trials,
                winner: Some((challenge, proof)),
            };
        }
    }
    Search {
        trials,
        winner: None,
    }
}
fn legal_search(prepared: &Task, task: Hash, sample: u64, bits: u8) -> Result<Search> {
    let mut trials = Vec::new();
    for nonce in 0..LIMIT {
        let challenge = context(task, sample, bits, nonce);
        let attempt = prepared
            .attempt(challenge, target(bits), Materialization::TargetHit)
            .map_err(|error| format!("FILTER_LEGAL_ATTEMPT:{error:?}"))?;
        trials.push(Trial {
            nonce,
            challenge,
            trace: attempt.trace,
            ticket: attempt.ticket,
            hit: attempt.target_hit,
        });
        if attempt.target_hit {
            let proof = attempt.proof.ok_or("FILTER_WINNER_WITHOUT_BYTES")?;
            return Ok(Search {
                trials,
                winner: Some((challenge, proof)),
            });
        }
        if attempt.proof.is_some() {
            return Err("FILTER_LAZY_MISS_HAS_BYTES".into());
        }
    }
    Ok(Search {
        trials,
        winner: None,
    })
}

#[derive(Default)]
struct Progress {
    tiles: usize,
    before_product: usize,
    before_verified: usize,
}
impl Progress {
    fn see(&mut self, point: VerificationProgress) -> std::result::Result<(), ()> {
        match point {
            VerificationProgress::TranscriptTile { .. } => self.tiles += 1,
            VerificationProgress::BeforeProduct => self.before_product += 1,
            VerificationProgress::BeforeVerifiedWork => self.before_verified += 1,
            _ => {}
        }
        Ok(())
    }
}
fn verify_paths(
    key: &Value,
    challenge: Hash,
    task: Hash,
    limit: Hash,
    proof: &[u8],
    expected: &str,
) -> Result<bool> {
    let started = Clock::start()?;
    let cache = ArithmeticFactCache::new(1)?;
    let setup = started.finish()?;
    emit(
        "receiver-setup",
        json!({"key": key, "timing": setup,
        "capacity": 1, "software_bytes": cache.software_bytes()}),
    )?;
    let mut all_expected = true;
    for path in PATHS {
        let mut progress = Progress::default();
        let started = Clock::start()?;
        // Formatting and output happen after finish, including enum error names.
        let outcome = match path {
            "precheck" => match black_box(pon_work::precheck_proof_statement(
                challenge, task, limit, proof,
            )) {
                Ok(()) => Ok(None),
                Err(error) => Err(error),
            },
            "arithmetic-cold" | "arithmetic-hot" => {
                match cache
                    .verify_with_progress(challenge, task, limit, proof, &mut |p| progress.see(p))
                {
                    Ok(work) => Ok(Some(work)),
                    Err(FactError::Relation(error)) => Err(error),
                    Err(FactError::Cancelled(())) => return Err("FILTER_UNEXPECTED_CANCEL".into()),
                    Err(FactError::Unavailable) => return Err("FILTER_CACHE_UNAVAILABLE".into()),
                }
            }
            _ => {
                let result = if path == "scalar-reference" {
                    pon_work::verify_reference_with_progress(
                        challenge,
                        task,
                        limit,
                        proof,
                        &mut |p| progress.see(p),
                    )
                } else {
                    pon_work::verify_with_progress(challenge, task, limit, proof, &mut |p| {
                        progress.see(p)
                    })
                };
                match result {
                    Ok(work) => Ok(Some(work)),
                    Err(VerificationError::Relation(error)) => Err(error),
                    Err(VerificationError::Cancelled(())) => {
                        return Err("FILTER_UNEXPECTED_CANCEL".into());
                    }
                }
            }
        };
        // Drop the returned product before stopping this actual call interval.
        let result = black_box(outcome).map(|work| {
            drop(work);
        });
        let timing = started.finish()?;
        let label = match result {
            Ok(()) => {
                if path == "precheck" {
                    "PrecheckPass".into()
                } else {
                    "Accepted".into()
                }
            }
            Err(error) => format!("{error:?}"),
        };
        let wanted = if path == "precheck" {
            "PrecheckPass"
        } else {
            expected
        };
        all_expected &= label == wanted;
        emit(
            "verification",
            json!({"key": key, "path": path, "outcome": label,
            "timing": timing, "transcript_tiles": progress.tiles,
            "before_product": progress.before_product, "before_verified": progress.before_verified}),
        )?;
    }
    Ok(all_expected)
}

fn run() -> Result<()> {
    if std::env::args().skip(1).collect::<Vec<_>>().as_slice() != [SELECTOR] {
        return Err("FILTER_FIXED_SELECTOR_REQUIRED".into());
    }
    let total = Clock::start()?;
    emit(
        "header",
        json!({"selector": SELECTOR, "profile": pon_work::PROFILE,
        "classes": CLASSES, "target_leading_zero_bits": BITS, "samples": SAMPLES,
        "attempt_limit": LIMIT, "paths": PATHS, "proof_bytes": PROOF_BYTES,
        "legal_producer": "full-limb-dense-preparation-lazy-winner",
        "algorithm_timing_scope": "all-attempts-binary-bookkeeping-no-json-no-hex-no-output",
        "precheck_is_separate_invocation": true, "synthetic_material": true,
        "native_header_admission": false, "node_service_measured": false,
        "work_cost_lower_bound_proved": false, "production_activation": false}),
    )?;
    let clock = Clock::start()?;
    // The exact existing generator also prepares five unused public recipes.
    // Its whole cost is retained separately, never hidden in one attack interval.
    let materials = w1_material::materials(None, None)?;
    emit(
        "fixtures",
        json!({"timing": clock.finish()?, "generated_classes": materials.len(),
        "retained_classes": CLASSES, "scope": "all-existing-public-diagnostic-recipes"}),
    )?;
    let mut samples = 0;
    let mut all_expected = true;
    for name in CLASSES {
        let material = materials
            .iter()
            .find(|m| m.name == name)
            .ok_or("FILTER_MATERIAL")?;
        let started = Clock::start()?;
        let task = pon_work::task_id(&material.a, &material.b).map_err(|e| format!("{e:?}"))?;
        let timing = started.finish()?;
        emit(
            "material",
            json!({"class": name, "source": material.source, "task": hex::encode(task), "timing": timing}),
        )?;
        for bits in BITS {
            for sample in 0..SAMPLES {
                // Rotate construction/verification arm order. Forgery code never
                // receives, reads or copies the independently produced legal proof.
                let arms = if sample % 2 == 0 {
                    ["from-zero", "legal"]
                } else {
                    ["legal", "from-zero"]
                };
                for arm in arms {
                    let key = json!({"class": name, "bits": bits, "sample": sample, "arm": arm});
                    emit(
                        "sample-start",
                        json!({"key": key, "target": hex::encode(target(bits))}),
                    )?;
                    let setup_clock = Clock::start()?;
                    let (prefix, legal) = if arm == "from-zero" {
                        (
                            Some(
                                w1_from_zero::proof_prefix(&material.a, &material.b)
                                    .map_err(|e| format!("FILTER_PREFIX:{e:?}"))?,
                            ),
                            None,
                        )
                    } else {
                        (
                            None,
                            Some(
                                Task::new(&material.a, &material.b, Arithmetic::FullLimb)
                                    .map_err(|e| format!("FILTER_PREPARATION:{e:?}"))?,
                            ),
                        )
                    };
                    let setup = setup_clock.finish()?;
                    let started = Clock::start()?;
                    let result = if let Some(prefix) = prefix {
                        false_search(&prefix, context(task, sample, bits, 0), target(bits))
                    } else {
                        legal_search(legal.as_ref().ok_or("FILTER_PRODUCER")?, task, sample, bits)?
                    };
                    drop(legal);
                    let search_timing = started.finish()?;
                    let (status, winner) = match &result.winner {
                        Some((challenge, proof)) => (
                            "target-hit",
                            Some(json!({
                            "challenge": hex::encode(challenge), "proof_hex": hex::encode(proof),
                            "proof_sha256": sha(proof)})),
                        ),
                        None => ("exhausted", None),
                    };
                    emit(
                        "construction",
                        json!({"key": key, "setup": setup, "search": search_timing,
                        "target": hex::encode(target(bits)), "status": status,
                        "trials": result.trials.iter().map(Trial::record).collect::<Vec<_>>(), "winner": winner}),
                    )?;
                    let (challenge, proof) =
                        result.winner.ok_or("FILTER_FIXED_SEARCH_EXHAUSTED")?;
                    let expected = if arm == "from-zero" {
                        "Transcript"
                    } else {
                        "Accepted"
                    };
                    all_expected &=
                        verify_paths(&key, challenge, task, target(bits), &proof, expected)?;
                    emit("sample-end", json!({"key": key}))?;
                    samples += 1;
                }
            }
        }
    }
    emit(
        "end",
        json!({"samples_completed": samples, "verifications_completed": samples * PATHS.len(),
        "all_expected_outcomes": all_expected, "work_cost_lower_bound_proved": false,
        "node_service_measured": false, "production_activation": false,
        "total_before_terminal": total.finish()?}),
    )?;
    if !all_expected {
        return Err("FILTER_NATIVE_OUTCOME_DISAGREEMENT".into());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(
            "failure",
            json!({"reason": error.to_string(), "unfinished_cost": null,
            "complete": false, "production_activation": false}),
        );
        eprintln!("{error}");
        std::process::exit(1);
    }
}
