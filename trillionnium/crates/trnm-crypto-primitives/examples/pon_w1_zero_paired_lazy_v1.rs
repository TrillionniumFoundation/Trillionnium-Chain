//! Registered zero-material factorial comparison. Every begin is flushed before
//! native work; no observation or locally generated proof grants chain credit.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self,
    blocked_zero_paired::BlockedZeroPairedPreparedTask,
    legal_attempt::{Arithmetic, Attempt, Materialization, Preparation, Task},
    Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-zero-paired-lazy-v1";
const ARMS: [&str; 5] = [
    "full-limb-sparse-eager",
    "full-limb-sparse-lazy",
    "zero-paired-legacy",
    "zero-paired-eager",
    "zero-paired-lazy",
];
const SAMPLES: usize = 8;

struct Clock {
    wall: Instant,
    cpu: Option<u64>,
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu(),
        }
    }
    fn finish(self) -> Value {
        json!({
            "cpu_ns":self.cpu.and_then(|before| cpu()?.checked_sub(before)),
            "wall_ns":u64::try_from(self.wall.elapsed().as_nanos()).ok()
        })
    }
}
#[cfg(target_os = "linux")]
fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime)).ok()?;
    let ns = u64::try_from(t.tv_nsec).ok()?;
    (ns < 1_000_000_000).then_some(())?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(ns)
}
#[cfg(not(target_os = "linux"))]
fn cpu() -> Option<u64> {
    None
}

struct Journal<W: Write> {
    sink: W,
    seq: u64,
}
impl<W: Write> Journal<W> {
    fn emit(&mut self, event: &str, mut record: Value) -> Result<()> {
        let object = record.as_object_mut().ok_or("JOURNAL_OBJECT")?;
        object.insert("schema".into(), json!(SCHEMA));
        object.insert("seq".into(), json!(self.seq));
        object.insert("event".into(), json!(event));
        serde_json::to_writer(&mut self.sink, &record)?;
        self.sink.write_all(b"\n")?;
        self.sink.flush()?;
        self.seq += 1;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Shard {
    target_index: usize,
    horizon: usize,
}
impl Shard {
    fn parse(args: &[String]) -> Result<Self> {
        if args.len() != 5
            || args[0] != "--zero-paired-lazy-v1"
            || args[1] != "--target-index"
            || args[3] != "--reuse-searches"
        {
            return Err("FIXED_ZERO_PAIRED_LAZY_SHARD_REQUIRED".into());
        }
        let target_index = match args[2].as_str() {
            "0" => 0,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            _ => return Err("ZERO_PAIRED_LAZY_TARGET".into()),
        };
        let horizon = match args[4].as_str() {
            "1" => 1,
            "8" => 8,
            _ => return Err("ZERO_PAIRED_LAZY_HORIZON".into()),
        };
        if target_index >= 2 && horizon != 1 {
            return Err("ZERO_PAIRED_LAZY_CONTROL_HORIZON".into());
        }
        Ok(Self {
            target_index,
            horizon,
        })
    }
    fn target(self) -> Hash {
        let mut target = [255; 32];
        match self.target_index {
            0 => target[0] = 127,
            1 => target[0] = 7,
            2 => {
                target.fill(0);
                target[31] = 1;
            }
            3 => (),
            _ => unreachable!(),
        }
        target
    }
    fn limit(self) -> u64 {
        if self.target_index < 2 {
            4096
        } else {
            3
        }
    }
}

enum Producer {
    Full(Task, Materialization),
    Old(BlockedZeroPairedPreparedTask),
    Paired(BlockedZeroPairedPreparedTask, Materialization),
}
impl Producer {
    fn new(arm: usize, zero: &[u32]) -> Result<Self> {
        let mode = if arm == 1 || arm == 4 {
            Materialization::TargetHit
        } else {
            Materialization::EveryAttempt
        };
        if arm < 2 {
            Ok(Self::Full(
                Task::with_preparation(zero, zero, Arithmetic::FullLimb, Preparation::Sparse)
                    .map_err(|e| format!("PREPARE_FULL:{e:?}"))?,
                mode,
            ))
        } else {
            let prepared = BlockedZeroPairedPreparedTask::new(zero, zero)
                .map_err(|e| format!("PREPARE_PAIRED:{e:?}"))?
                .ok_or("ZERO_SPECIALIST_UNEXPECTED_UNSUPPORTED")?;
            if arm == 2 {
                Ok(Self::Old(prepared))
            } else {
                Ok(Self::Paired(prepared, mode))
            }
        }
    }
    fn prefix(&self) -> &[u8] {
        match self {
            Self::Full(task, _) => task.proof_prefix(),
            Self::Old(task) | Self::Paired(task, _) => task.proof_prefix(),
        }
    }
    fn attempt(&self, challenge: Hash, target: Hash) -> Result<Attempt> {
        match self {
            Self::Full(task, mode) => task
                .attempt(challenge, target, *mode)
                .map_err(|e| format!("FULL_ATTEMPT:{e:?}").into()),
            Self::Paired(task, mode) => task
                .attempt(challenge, target, *mode)
                .map_err(|e| format!("PAIRED_ATTEMPT:{e:?}").into()),
            Self::Old(task) => {
                let proof = task
                    .prove(challenge)
                    .map_err(|e| format!("LEGACY_PROVE:{e:?}"))?;
                if proof.len() != PROOF_BYTES {
                    return Err("LEGACY_PROOF_LENGTH".into());
                }
                let trace: Hash = proof[PROOF_BYTES - 32..].try_into()?;
                let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
                Ok(Attempt {
                    challenge,
                    trace,
                    ticket,
                    target_hit: ticket <= target,
                    proof: Some(proof),
                })
            }
        }
    }
}

fn challenge(task: Hash, target: Hash, sample: usize, search: usize, nonce: u64) -> Hash {
    // No arm, horizon or completion-order dependency. Nested horizon prefixes
    // are deliberate matched observations, not extra independent samples.
    pon_work::hash(
        b"pon-w1-zero-paired-lazy-challenge-v1",
        &[
            &task,
            &target,
            &(sample as u64).to_le_bytes(),
            &(search as u64).to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

#[derive(Default)]
struct Counts {
    cohorts: u64,
    searches: u64,
    attempts: u64,
    hits: u64,
    misses: u64,
    exhausted: u64,
    materialized: u64,
    verification_calls: u64,
}
impl Counts {
    fn value(&self) -> Value {
        json!({"cohorts":self.cohorts,"setup_calls":self.cohorts,
            "searches":self.searches,"attempts":self.attempts,"hits":self.hits,
            "misses":self.misses,"exhausted":self.exhausted,
            "materialized":self.materialized,"verification_calls":self.verification_calls})
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Trial {
    nonce: u64,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
    proof_sha256: Hash,
}
#[derive(Clone, Copy)]
struct Position {
    sample: usize,
    arm: usize,
    search: usize,
}

fn verify<W: Write>(
    journal: &mut Journal<W>,
    position: Position,
    trial: &Trial,
    task: Hash,
    target: Hash,
    proof: &[u8],
    kind: &str,
) -> Result<u64> {
    type Verifier = fn(Hash, Hash, Hash, &[u8]) -> std::result::Result<VerifiedWork, WorkError>;
    for (name, checker) in [
        ("production", pon_work::verify as Verifier),
        ("reference", pon_work::verify_reference as Verifier),
    ] {
        let mut row = json!({"sample":position.sample,"arm":position.arm,
            "search":position.search,"nonce":trial.nonce,"kind":kind,"verifier":name,
            "target":hex::encode(target),"proof_sha256":hex::encode(Sha256::digest(proof))});
        journal.emit("verify_begin", row.clone())?;
        let clock = Clock::start();
        let outcome = checker(trial.challenge, task, target, black_box(proof));
        let timing = clock.finish();
        let correct = match &outcome {
            Ok(value) => {
                kind != "product-last"
                    && value.challenge() == trial.challenge
                    && value.task() == task
                    && value.ticket() == trial.ticket
                    && value.product().iter().all(|word| *word == 0)
            }
            Err(error) => kind == "product-last" && *error == WorkError::Product,
        };
        row["accepted"] = json!(outcome.is_ok());
        row["error"] = json!(outcome.as_ref().err().map(|e| format!("{e:?}")));
        row["timing"] = timing;
        journal.emit("verify_finish", row)?;
        if !correct {
            return Err("COMPLETE_VERIFIER_DISAGREEMENT".into());
        }
    }
    Ok(2)
}

fn run<W: Write>(journal: &mut Journal<W>, shard: Shard) -> Result<()> {
    let material_clock = Clock::start();
    let zero = vec![0; CELLS];
    let task = pon_work::task_id(&zero, &zero).map_err(|e| format!("TASK:{e:?}"))?;
    let mut prefix = vec![0; PROOF_BYTES - 32];
    prefix[..4].copy_from_slice(b"PNW1");
    let material_timing = material_clock.finish();
    let target = shard.target();
    journal.emit("header", json!({
        "arms":ARMS,"samples":SAMPLES,"target_index":shard.target_index,
        "target":hex::encode(target),"horizon":shard.horizon,"max_attempts":shard.limit(),
        "task":hex::encode(task),"material":"zero","proof_bytes":PROOF_BYTES,
        "prefix_sha256":hex::encode(Sha256::digest(&prefix)),
        "a_sha256":hex::encode(Sha256::digest(vec![0; CELLS*4])),
        "b_sha256":hex::encode(Sha256::digest(vec![0; CELLS*4])),
        "material_timing":material_timing,"clock":"process-cpu-monotonic-wall",
        "rotation":"arm=(position+sample)%5","complete_trace_tiles":512,
        "shared_preparation":"one-actual-constructor-per-cohort",
        "producer_scope":"setup+attempts+losing-proof-disposal+winner-cleanup+task-teardown",
        "inclusive_scope":"cohort-total-includes-observation-streaming-and-verification-before-end-record",
        "ideal_uniform_ticket_assumption":match shard.target_index {0=>Some("1/2"),1=>Some("1/32"),_=>None},
        "consensus_credit":0,"production_activation":false,"cheapest_strategy_proven":false
    }))?;
    let mut counts = Counts::default();
    for sample in 0..SAMPLES {
        let mut expected: Vec<Option<Vec<Trial>>> = vec![None; shard.horizon];
        for position in 0..ARMS.len() {
            let arm = (position + sample) % ARMS.len();
            journal.emit(
                "cohort_begin",
                json!({"sample":sample,"position":position,"arm":arm}),
            )?;
            let cohort_clock = Clock::start();
            let setup = Clock::start();
            let producer = Producer::new(black_box(arm), black_box(&zero))?;
            black_box(&producer);
            let setup = setup.finish();
            journal.emit(
                "setup_finish",
                json!({"sample":sample,"arm":arm,"setup_calls":1,"timing":setup}),
            )?;
            counts.cohorts += 1;
            if producer.prefix() != prefix {
                return Err("PREPARATION_PREFIX_DISAGREEMENT".into());
            }
            for (search, expected) in expected.iter_mut().enumerate() {
                let at = Position {
                    sample,
                    arm,
                    search,
                };
                let identity = json!({"sample":sample,"arm":arm,"search":search});
                journal.emit("search_begin", identity.clone())?;
                let search_clock = Clock::start();
                let mut trials = Vec::new();
                let mut winner: Option<Vec<u8>> = None;
                let mut first_hit = None;
                for nonce in 0..shard.limit() {
                    let mut row = identity.clone();
                    row["nonce"] = json!(nonce);
                    journal.emit("attempt_begin", row.clone())?;
                    let clock = Clock::start();
                    let context = challenge(task, target, sample, search, nonce);
                    let mut attempt = producer.attempt(black_box(context), black_box(target))?;
                    if let Some(proof) = &attempt.proof {
                        black_box(proof.as_slice());
                    }
                    black_box(&attempt);
                    let production = clock.finish();
                    let clock = Clock::start();
                    let materialized = attempt.proof.is_some();
                    if attempt.challenge != context
                        || attempt.ticket != pon_work::hash(b"ticket", &[&context, &attempt.trace])
                        || attempt.target_hit != (attempt.ticket <= target)
                        || materialized != (arm == 0 || arm == 2 || arm == 3 || attempt.target_hit)
                    {
                        return Err("ATTEMPT_IDENTITY_DISAGREEMENT".into());
                    }
                    let proof_sha256: Hash = if let Some(proof) = &attempt.proof {
                        if proof.len() != PROOF_BYTES
                            || proof[..PROOF_BYTES - 32] != prefix
                            || proof[PROOF_BYTES - 32..] != attempt.trace
                        {
                            return Err("MATERIALIZED_PROOF_DISAGREEMENT".into());
                        }
                        Sha256::digest(proof).into()
                    } else {
                        let mut hash = Sha256::new();
                        hash.update(&prefix);
                        hash.update(attempt.trace);
                        hash.finalize().into()
                    };
                    let evidence = clock.finish();
                    let clock = Clock::start();
                    if attempt.target_hit {
                        first_hit = Some(nonce);
                        winner = attempt.proof.take();
                    } else {
                        drop(attempt.proof.take());
                    }
                    let disposal = clock.finish();
                    row["challenge"] = json!(hex::encode(context));
                    row["trace"] = json!(hex::encode(attempt.trace));
                    row["ticket"] = json!(hex::encode(attempt.ticket));
                    row["proof_sha256"] = json!(hex::encode(proof_sha256));
                    row["hit"] = json!(attempt.target_hit);
                    row["materialized"] = json!(materialized);
                    row["producer"] = production;
                    row["evidence"] = evidence;
                    row["disposal"] = disposal;
                    journal.emit("attempt_finish", row)?;
                    counts.attempts += 1;
                    counts.hits += u64::from(attempt.target_hit);
                    counts.misses += u64::from(!attempt.target_hit);
                    counts.materialized += u64::from(materialized);
                    trials.push(Trial {
                        nonce,
                        challenge: context,
                        trace: attempt.trace,
                        ticket: attempt.ticket,
                        proof_sha256,
                    });
                    if first_hit.is_some() {
                        break;
                    }
                }
                let mut row = identity.clone();
                row["attempts"] = json!(trials.len());
                row["first_hit_nonce"] = json!(first_hit);
                row["timing"] = search_clock.finish();
                journal.emit("search_finish", row)?;
                counts.searches += 1;
                counts.exhausted += u64::from(first_hit.is_none());
                if let Some(previous) = expected {
                    if *previous != trials {
                        return Err("MATCHED_ARM_STREAM_DISAGREEMENT".into());
                    }
                } else {
                    *expected = Some(trials.clone());
                }
                if let Some(proof) = &winner {
                    let trial = trials.last().ok_or("MISSING_HIT")?;
                    counts.verification_calls +=
                        verify(journal, at, trial, task, target, proof, "winner")?;
                    let mut mutant = proof.clone();
                    mutant[4 + 3 * CELLS * 4 - 4] = 1;
                    counts.verification_calls +=
                        verify(journal, at, trial, task, target, &mutant, "product-last")?;
                } else if shard.target_index == 2 {
                    // Full independent replay of *every* exhaustion control miss.
                    // Max-target acceptance here never changes the original miss.
                    for trial in &trials {
                        let mut proof = prefix.clone();
                        proof.extend_from_slice(&trial.trace);
                        counts.verification_calls += verify(
                            journal,
                            at,
                            trial,
                            task,
                            [255; 32],
                            &proof,
                            "exhausted-replay",
                        )?;
                    }
                }
                journal.emit("cleanup_begin", identity.clone())?;
                let clock = Clock::start();
                drop(winner);
                let mut row = identity;
                row["timing"] = clock.finish();
                journal.emit("cleanup_finish", row)?;
            }
            let clock = Clock::start();
            drop(producer);
            let teardown = clock.finish();
            journal.emit("cohort_end", json!({"sample":sample,"arm":arm,"teardown":teardown,"total":cohort_clock.finish()}))?;
        }
    }
    journal.emit(
        "footer",
        json!({"counts":counts.value(),"complete":true,
        "consensus_credit":0,"production_activation":false,"cheapest_strategy_proven":false}),
    )
}

fn main() -> Result<()> {
    let shard = Shard::parse(&std::env::args().skip(1).collect::<Vec<_>>())?;
    let stdout = std::io::stdout();
    let mut journal = Journal {
        sink: stdout.lock(),
        seq: 0,
    };
    let result = run(&mut journal, shard);
    if let Err(error) = &result {
        let _ = journal.emit("failure", json!({"error":error.to_string()}));
    }
    result
}
