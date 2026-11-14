//! Fixed complete-search comparisons for paid exact low-rank preparation and
//! four-worker speculative batches. This diagnostic grants no work authority.
#[path = "support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, thread, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self,
    blocked_one_zero::BlockedOneZeroRankOnePreparedTask,
    blocked_zero::BlockedZeroPreparedTask,
    blocked_zero_paired::BlockedZeroPairedPreparedTask,
    legal_attempt::{Arithmetic, Attempt, Materialization, Preparation, PreparationUsed, Task},
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{StructuredPreparedTask, TileKernel, TiledPreparedTask},
    Hash, PreparedTask, VerifiedWork, WorkError, CELLS, N, PROOF_BYTES, Q,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-rank-batch-v5";
const SELECTOR: &str = "--rank-batch-v5";
const SAMPLES: u64 = 8;
const LIMIT: u64 = 4096;
const BATCH: usize = 4;
const HORIZONS: [usize; 2] = [1, 8];
const CLASSES: [&str; 11] = [
    "zero",
    "rank-one",
    "rank-two-left",
    "rank-four-left",
    "rank-eight-left",
    "rank-four-right",
    "rank-nine-left",
    "full-rank-field",
    "sparse-diagonal",
    "one-zero-rank-one",
    "continuity-maintenance-v1",
];
const ARMS: [&str; 17] = [
    "full-limb-dense-lazy",
    "full-limb-sparse-lazy",
    "full-limb-rank8-lazy",
    "full-limb-rank8-batch4-lazy",
    "scalar-original",
    "prepared-generic",
    "prepared-structured",
    "tiled-classical",
    "tiled-strassen-one-level",
    "paired-product",
    "blocked-zero",
    "blocked-zero-integer-paired",
    "blocked-one-zero-rank-one",
    "maintenance-periodic",
    "maintenance-integer-paired",
    "maintenance-prefix",
    "maintenance-limb",
];

#[derive(Clone, Copy)]
struct Timing {
    cpu_ns: Option<u64>,
    wall_ns: Option<u64>,
}
impl Timing {
    fn zero() -> Self {
        Self {
            cpu_ns: Some(0),
            wall_ns: Some(0),
        }
    }
    fn add(&mut self, other: Self) {
        self.cpu_ns = self
            .cpu_ns
            .zip(other.cpu_ns)
            .and_then(|(a, b)| a.checked_add(b));
        self.wall_ns = self
            .wall_ns
            .zip(other.wall_ns)
            .and_then(|(a, b)| a.checked_add(b));
    }
    fn value(self) -> Value {
        json!({"cpu_ns":self.cpu_ns,"wall_ns":self.wall_ns})
    }
}
struct Clock {
    wall: Instant,
    cpu: Option<u64>,
    owner: thread::ThreadId,
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu(),
            owner: thread::current().id(),
        }
    }
    fn finish(self) -> Timing {
        Timing {
            wall_ns: u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            cpu_ns: if self.owner == thread::current().id() {
                self.cpu.and_then(|n| cpu()?.checked_sub(n))
            } else {
                None
            },
        }
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
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn raw(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|v| v.to_le_bytes()).collect()
}

struct Shard {
    class: String,
    target_index: usize,
    horizon: usize,
}
impl Shard {
    fn parse(args: &[String]) -> Result<Self> {
        if args.len() != 7
            || args[0] != SELECTOR
            || args[1] != "--class"
            || args[3] != "--target-index"
            || args[5] != "--reuse-winners"
        {
            return Err("RANK_BATCH_FIXED_SHARD_REQUIRED".into());
        }
        if !CLASSES.contains(&args[2].as_str()) {
            return Err("RANK_BATCH_CLASS".into());
        }
        let target_index = match args[4].as_str() {
            "0" => 0,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            _ => return Err("RANK_BATCH_TARGET".into()),
        };
        let horizon = match args[6].as_str() {
            "1" => 1,
            "8" => 8,
            _ => return Err("RANK_BATCH_HORIZON".into()),
        };
        if target_index >= 2 && horizon != 1 {
            return Err("RANK_BATCH_CONTROL_HORIZON".into());
        }
        Ok(Self {
            class: args[2].clone(),
            target_index,
            horizon,
        })
    }
    fn target(&self) -> Hash {
        let mut t = [255; 32];
        match self.target_index {
            0 => t[0] = 127,
            1 => t[0] = 7,
            2 => {
                t.fill(0);
                t[31] = 1;
            }
            3 => (),
            _ => unreachable!(),
        }
        t
    }
    fn limit(&self) -> u64 {
        if self.target_index < 2 {
            LIMIT
        } else {
            3
        }
    }
    fn purpose(&self) -> &'static str {
        match self.target_index {
            0 | 1 => "search-cost",
            2 => "exhaustion-control",
            3 => "first-hit-control",
            _ => unreachable!(),
        }
    }
}

fn ranked(rank: usize, shift: usize) -> Vec<u32> {
    // The leading identity minor makes the finite-field rank exact before
    // row/column permutations. This uses remainder arithmetic independently
    // of the new preparation kernel's specialized reducer.
    let left: Vec<u32> = (0..N * rank)
        .map(|p| {
            let (i, k) = (p / rank, p % rank);
            if i < rank {
                u32::from(i == k)
            } else {
                ((Q - 1 - (i * 101 + k * 17) as u128) % Q) as u32
            }
        })
        .collect();
    let right: Vec<u32> = (0..rank * N)
        .map(|p| {
            let (k, j) = (p / N, p % N);
            if j < rank {
                u32::from(j == k)
            } else {
                ((Q - 1 - (j * 73 + k * 31) as u128) % Q) as u32
            }
        })
        .collect();
    (0..CELLS)
        .map(|p| {
            let i = (p / N + shift) % N;
            let j = (p % N + 2 * shift) % N;
            ((0..rank)
                .map(|k| u128::from(left[i * rank + k]) * u128::from(right[k * N + j]))
                .sum::<u128>()
                % Q) as u32
        })
        .collect()
}
fn material(class: &str) -> Result<w1_material::Material> {
    let mut original = w1_material::materials(None, None)?;
    if let Some(i) = original.iter().position(|m| m.name == class) {
        return Ok(original.swap_remove(i));
    }
    let dense = original
        .iter()
        .find(|m| m.name == "full-rank-field")
        .ok_or("RANK_BATCH_MATERIAL")?;
    let (a, b) = match class {
        "rank-two-left" => (ranked(2, 7), dense.b.clone()),
        "rank-four-left" => (ranked(4, 7), dense.b.clone()),
        "rank-eight-left" => (ranked(8, 7), dense.b.clone()),
        "rank-four-right" => (dense.a.clone(), ranked(4, 11)),
        "rank-nine-left" => (ranked(9, 7), dense.b.clone()),
        "one-zero-rank-one" => (ranked(1, 7), vec![0; CELLS]),
        _ => return Err("RANK_BATCH_MATERIAL_CLASS".into()),
    };
    Ok(w1_material::Material {
        name: "rank-batch-fixture",
        source: "synthetic-exact-rank-fixture",
        a,
        b,
    })
}

// These are the same thirteen existing native constructors used by the prior
// legal-strategy campaigns. No arithmetic is copied or replaced by a stub.
enum Legacy {
    Scalar(Vec<u32>, Vec<u32>),
    Generic(Box<PreparedTask>),
    Structured(Box<StructuredPreparedTask>),
    Tiled(Box<TiledPreparedTask>),
    Paired(Box<PairedPreparedTask>),
    Zero(Box<BlockedZeroPreparedTask>),
    ZeroPaired(Box<BlockedZeroPairedPreparedTask>),
    OneZero(Box<BlockedOneZeroRankOnePreparedTask>),
    Periodic(Box<MaintenancePeriodicPreparedTask>),
    Integer(Box<MaintenanceIntegerPairedPreparedTask>),
    Prefix(Box<MaintenancePrefixPreparedTask>),
    Limb(Box<MaintenanceLimbPreparedTask>),
}
impl Legacy {
    fn new(index: usize, a: &[u32], b: &[u32]) -> std::result::Result<Option<Self>, WorkError> {
        Ok(match index {
            0 => {
                pon_work::task_id(a, b)?;
                Some(Self::Scalar(a.to_vec(), b.to_vec()))
            }
            1 => Some(Self::Generic(Box::new(PreparedTask::new(a, b)?))),
            2 => StructuredPreparedTask::new(a, b)?.map(|t| Self::Structured(Box::new(t))),
            3 | 4 => Some(Self::Tiled(Box::new(TiledPreparedTask::new(
                a,
                b,
                if index == 3 {
                    TileKernel::Classical
                } else {
                    TileKernel::StrassenOneLevel
                },
            )?))),
            5 => Some(Self::Paired(Box::new(PairedPreparedTask::new(a, b)?))),
            6 => BlockedZeroPreparedTask::new(a, b)?.map(|t| Self::Zero(Box::new(t))),
            7 => BlockedZeroPairedPreparedTask::new(a, b)?.map(|t| Self::ZeroPaired(Box::new(t))),
            8 => BlockedOneZeroRankOnePreparedTask::new(a, b)?.map(|t| Self::OneZero(Box::new(t))),
            9 => MaintenancePeriodicPreparedTask::new(a, b)?.map(|t| Self::Periodic(Box::new(t))),
            10 => {
                MaintenanceIntegerPairedPreparedTask::new(a, b)?.map(|t| Self::Integer(Box::new(t)))
            }
            11 => MaintenancePrefixPreparedTask::new(a, b)?.map(|t| Self::Prefix(Box::new(t))),
            12 => MaintenanceLimbPreparedTask::new(a, b)?.map(|t| Self::Limb(Box::new(t))),
            _ => return Err(WorkError::Task),
        })
    }
    fn prove(&self, challenge: Hash) -> std::result::Result<Vec<u8>, WorkError> {
        match self {
            Self::Scalar(a, b) => pon_work::prove(challenge, a, b),
            Self::Generic(t) => t.prove(challenge),
            Self::Structured(t) => t.prove(challenge),
            Self::Tiled(t) => t.prove(challenge),
            Self::Paired(t) => t.prove(challenge),
            Self::Zero(t) => t.prove(challenge),
            Self::ZeroPaired(t) => t.prove(challenge),
            Self::OneZero(t) => t.prove(challenge),
            Self::Periodic(t) => t.prove(challenge),
            Self::Integer(t) => t.prove(challenge),
            Self::Prefix(t) => t.prove(challenge),
            Self::Limb(t) => t.prove(challenge),
        }
    }
}
enum Producer {
    Full(Box<Task>),
    Legacy(Legacy),
}
impl Producer {
    fn new(index: usize, a: &[u32], b: &[u32]) -> Result<Option<Self>> {
        if index < 4 {
            let task = match index {
                0 => Task::new(a, b, Arithmetic::FullLimb),
                1 => Task::with_preparation(a, b, Arithmetic::FullLimb, Preparation::Sparse),
                _ => Task::with_rank_preparation(a, b, Arithmetic::FullLimb),
            };
            Ok(Some(Self::Full(Box::new(
                task.map_err(|e| format!("RANK_BATCH_SETUP:{e:?}"))?,
            ))))
        } else {
            Ok(Legacy::new(index - 4, a, b)
                .map_err(|e| format!("RANK_BATCH_SETUP:{e:?}"))?
                .map(Self::Legacy))
        }
    }
    fn description(&self) -> Value {
        match self {
            Self::Legacy(_) => {
                json!({"preparation_used":"existing-legacy-constructor","rank_bound":null})
            }
            Self::Full(t) => match t.preparation_used() {
                PreparationUsed::Dense => json!({"preparation_used":"dense","rank_bound":null}),
                PreparationUsed::Sparse => json!({"preparation_used":"sparse","rank_bound":null}),
                // The frozen V5 arms never select the separately measured
                // specialized constructor. Do not label it as a generic probe.
                PreparationUsed::CheckedRankOne => {
                    json!({"preparation_used":"checked-rank-one","rank_bound":1})
                }
                PreparationUsed::LeftLowRank { rank } => {
                    json!({"preparation_used":"left-low-rank","rank_bound":8,"rank":rank,"right_probe":false,"dense_fallback":false})
                }
                PreparationUsed::RightLowRank { rank } => {
                    json!({"preparation_used":"right-low-rank","rank_bound":8,"rank":rank,"left_above_bound":true,"right_probe":true,"dense_fallback":false})
                }
                PreparationUsed::DenseAfterRankBound => {
                    json!({"preparation_used":"dense-after-two-rank-probes","rank_bound":8,"left_above_bound":true,"right_above_bound":true,"dense_fallback":true})
                }
            },
        }
    }
    fn attempt(&self, challenge: Hash, target: Hash) -> std::result::Result<Attempt, String> {
        match self {
            Self::Full(t) => t
                .attempt(challenge, target, Materialization::TargetHit)
                .map_err(|e| format!("ATTEMPT:{e:?}")),
            Self::Legacy(t) => {
                if target == [0; 32] {
                    return Err("ATTEMPT:Target".into());
                }
                let proof = t.prove(challenge).map_err(|e| format!("ATTEMPT:{e:?}"))?;
                if proof.len() != PROOF_BYTES {
                    return Err("ATTEMPT:ProofLength".into());
                }
                let trace: Hash = proof[PROOF_BYTES - 32..].try_into().unwrap();
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

fn challenge(task: Hash, target: Hash, sample: u64, search: usize, nonce: u64) -> Hash {
    // Horizon, arm, worker and completion order are deliberately absent.
    pon_work::hash(
        b"pon-w1-rank-batch-challenge-v5",
        &[
            &task,
            &target,
            &sample.to_le_bytes(),
            &(search as u64).to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

fn parallel_map<T: Send>(
    values: &[Hash],
    worker: impl Fn(usize, Hash) -> std::result::Result<T, String> + Sync,
) -> Vec<std::result::Result<T, String>> {
    thread::scope(|scope| {
        let handles: Vec<_> = values
            .iter()
            .copied()
            .enumerate()
            .map(|(index, value)| {
                let work = &worker;
                thread::Builder::new()
                    .name("w1-rank-batch-v5".into())
                    .spawn_scoped(scope, move || work(index, value))
            })
            .collect();
        // Join every successfully spawned worker, including after a failure or
        // early ticket hit. Output follows declared nonce order, never fastest
        // completion. Scope owns and reaps every actual thread.
        handles
            .into_iter()
            .map(|handle| match handle {
                Ok(handle) => handle.join().unwrap_or_else(|_| Err("WORKER_PANIC".into())),
                Err(error) => Err(format!("WORKER_SPAWN:{:?}", error.kind())),
            })
            .collect()
    })
}

#[derive(Clone, PartialEq, Eq)]
struct Commitment {
    nonce: u64,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
}
struct Search {
    attempts: Vec<Value>,
    commitments: Vec<Commitment>,
    winner: Option<(Hash, Vec<u8>)>,
    first_hit: Option<u64>,
    speculative: Vec<Commitment>,
    errors: usize,
    proof_buffers: usize,
    producer: Timing,
    observation: Timing,
    disposal: Timing,
    batches: usize,
}
#[derive(Clone, Copy)]
struct Position {
    sample: u64,
    index: usize,
    search_index: usize,
}
fn search(
    producer: &Producer,
    prefix: &[u8],
    task: Hash,
    target: Hash,
    position: Position,
    limit: u64,
) -> Result<Search> {
    let Position {
        sample,
        index,
        search_index,
    } = position;
    if limit == 0 || limit > LIMIT || target == [0; 32] {
        return Err("RANK_BATCH_SEARCH_BUDGET_OR_TARGET".into());
    }
    let width = if index == 3 { BATCH } else { 1 };
    let mut result = Search {
        attempts: vec![],
        commitments: vec![],
        winner: None,
        first_hit: None,
        speculative: vec![],
        errors: 0,
        proof_buffers: 0,
        producer: Timing::zero(),
        observation: Timing::zero(),
        disposal: Timing::zero(),
        batches: 0,
    };
    let mut nonce = 0;
    while nonce < limit && result.first_hit.is_none() && result.errors == 0 {
        let started = Clock::start();
        let count = width.min((limit - nonce) as usize);
        let contexts: Vec<_> = (0..count)
            .map(|n| challenge(task, target, sample, search_index, nonce + n as u64))
            .collect();
        let mut outcomes = if width == 1 {
            vec![producer.attempt(contexts[0], target)]
        } else {
            let Producer::Full(task) = producer else {
                return Err("RANK_BATCH_PARALLEL_TASK_REQUIRED".into());
            };
            parallel_map(&contexts, |_, context| {
                task.attempt(context, target, Materialization::TargetHit)
                    .map_err(|e| format!("ATTEMPT:{e:?}"))
            })
        };
        black_box(&outcomes);
        result.producer.add(started.finish());
        result.batches += 1;
        let observed = Clock::start();
        let mut winner_index = None;
        for (offset, outcome) in outcomes.iter().enumerate() {
            let n = nonce + offset as u64;
            let expected = contexts[offset];
            let attempt = match outcome {
                Ok(a) => a,
                Err(error) => {
                    result.errors += 1;
                    result.attempts.push(json!({"nonce":n,"challenge":hex::encode(expected),"error":error,"complete":false}));
                    continue;
                }
            };
            let correct = attempt.challenge == expected
                && attempt.ticket == pon_work::hash(b"ticket", &[&expected, &attempt.trace])
                && attempt.target_hit == (attempt.ticket <= target)
                && attempt.proof.is_some() == (index >= 4 || attempt.target_hit)
                && attempt.proof.as_ref().is_none_or(|p| {
                    p.len() == PROOF_BYTES
                        && p[..PROOF_BYTES - 32] == *prefix
                        && p[PROOF_BYTES - 32..] == attempt.trace
                });
            if !correct {
                result.errors += 1;
                result.attempts.push(json!({"nonce":n,"challenge":hex::encode(expected),"error":"ATTEMPT_IDENTITY","complete":false}));
                continue;
            }
            let proof_sha = if let Some(proof) = &attempt.proof {
                result.proof_buffers += 1;
                sha(proof)
            } else {
                let mut hash = Sha256::new();
                hash.update(prefix);
                hash.update(attempt.trace);
                hex::encode(hash.finalize())
            };
            if attempt.target_hit && result.first_hit.is_none() {
                result.first_hit = Some(n);
                winner_index = Some(offset);
            }
            let after = result.first_hit.is_some_and(|first| n > first);
            let commitment = Commitment {
                nonce: n,
                challenge: expected,
                trace: attempt.trace,
                ticket: attempt.ticket,
            };
            if after {
                result.speculative.push(commitment.clone());
            }
            result.commitments.push(commitment);
            result.attempts.push(json!({"nonce":n,"challenge":hex::encode(expected),"trace":hex::encode(attempt.trace),
                "ticket":hex::encode(attempt.ticket),"target_hit":attempt.target_hit,"proof_materialized":attempt.proof.is_some(),
                "proof_sha256":proof_sha,"after_first_hit":after,"complete":true}));
        }
        result.observation.add(observed.finish());
        let disposal = Clock::start();
        if result.errors == 0 {
            if let Some(winner_index) = winner_index {
                let proof = outcomes[winner_index]
                    .as_mut()
                    .unwrap()
                    .proof
                    .take()
                    .ok_or("RANK_BATCH_WINNER_PROOF")?;
                result.winner = Some((contexts[winner_index], proof));
            }
        }
        // All losing and speculative proof buffers are destroyed in this
        // separately charged producer-disposal interval; none leaks to a later
        // cohort's cost. Observation hashing is separately reported.
        drop(outcomes);
        drop(contexts);
        result.disposal.add(disposal.finish());
        nonce += count as u64;
    }
    Ok(result)
}

fn signature(search: &Search) -> Vec<Commitment> {
    search
        .commitments
        .iter()
        .take_while(|v| search.first_hit.is_none_or(|n| v.nonce <= n))
        .cloned()
        .collect()
}
fn emit(kind: &str, mut value: Value) -> Result<()> {
    let object = value.as_object_mut().ok_or("RANK_BATCH_RECORD")?;
    object.insert("schema".into(), SCHEMA.into());
    object.insert("kind".into(), kind.into());
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn verdict(
    result: std::result::Result<VerifiedWork, WorkError>,
    context: Hash,
    task: Hash,
    proof: &[u8],
) -> String {
    match result {
        Ok(v)
            if v.challenge() == context
                && v.task() == task
                && v.ticket()
                    == pon_work::hash(b"ticket", &[&context, &proof[PROOF_BYTES - 32..]]) =>
        {
            "ACCEPT".into()
        }
        Ok(_) => "BAD_VERIFIED_BINDING".into(),
        Err(e) => format!("{e:?}"),
    }
}
fn verify(
    context: Hash,
    task: Hash,
    target: Hash,
    proof: &[u8],
    case: &str,
    position: Position,
    nonce: u64,
) -> Result<usize> {
    let Position {
        sample,
        index,
        search_index: search,
    } = position;
    for path in ["production", "reference"] {
        let started = Clock::start();
        let result = if path == "production" {
            pon_work::verify(context, task, target, proof)
        } else {
            pon_work::verify_reference(context, task, target, proof)
        };
        let timing = started.finish();
        let outcome = verdict(result, context, task, proof);
        emit(
            "verifier",
            json!({"sample":sample,"strategy_index":index,"search_index":search,"nonce":nonce,"path":path,"case":case,
            "target":hex::encode(target),"challenge":hex::encode(context),"proof_sha256":sha(proof),"result":outcome,"timing":timing.value()}),
        )?;
        if outcome
            != if case == "product-last" {
                "Product"
            } else {
                "ACCEPT"
            }
        {
            return Err("RANK_BATCH_VERIFIER_DISAGREEMENT".into());
        }
    }
    Ok(2)
}

#[derive(Default)]
struct Counts {
    setups: usize,
    unsupported: usize,
    searches: usize,
    attempts: usize,
    hits: usize,
    misses: usize,
    exhausted: usize,
    speculative: usize,
    proof_buffers: usize,
    verifier_calls: usize,
}
fn run(shard: Shard) -> Result<()> {
    let started = Clock::start();
    let input = material(&shard.class)?;
    let task =
        pon_work::task_id(&input.a, &input.b).map_err(|e| format!("RANK_BATCH_TASK:{e:?}"))?;
    let ranks = (w1_material::rank(&input.a), w1_material::rank(&input.b));
    let material_setup = started.finish();
    let reference = Clock::start();
    let canonical = Task::new(&input.a, &input.b, Arithmetic::FullLimb)
        .map_err(|e| format!("RANK_BATCH_REFERENCE_SETUP:{e:?}"))?;
    let prefix = canonical.proof_prefix();
    let reference_setup = reference.finish();
    let target = shard.target();
    emit(
        "header",
        json!({"class":shard.class,"target_index":shard.target_index,"target":hex::encode(target),"horizon":shard.horizon,
        "purpose":shard.purpose(),"samples":SAMPLES,"attempt_limit":shard.limit(),"horizons":HORIZONS,"classes":CLASSES,"strategies":ARMS,
        "task":hex::encode(task),"a_hex":hex::encode(raw(&input.a)),"b_hex":hex::encode(raw(&input.b)),"c_hex":hex::encode(&prefix[4+2*CELLS*4..]),
        "rank_a":ranks.0,"rank_b":ranks.1,"material_setup":material_setup.value(),"reference_setup":reference_setup.value(),
        "material_source":input.source,"feature_provenance_verified":false,"batch_workers":BATCH,"rank_bound":8,
        "rank_probe_order":"left-then-right-then-explicit-dense-fallback","complete_trace_tiles":512,
        "clock":"process-cpu-and-monotonic-wall","producer_clock_includes_threads":true,"worker_policy":"fixed-at-most-four-scoped-workers-per-batch-join-all-in-nonce-order",
        "batch_winner_policy":"first-hit-in-declared-nonce-order-after-completing-entire-batch","post_winner_attempts_charged":true,
        "producer_cost":"paid-setup-plus-complete-attempts-including-misses-speculation-thread-spawn-join-all-proof-buffer-disposal-and-task-teardown",
        "observation_cost":"separate-full-proof-identity-digest-and-JSON-value-work-including-losing-attempts",
        "verification_cost":"separate-both-winner-verifiers-product-mutants-and-both-replays-of-every-post-winner-attempt",
        "reuse_scope":"same-fixed-A-B-preparation-only-no-cross-challenge-trace-cache","horizon_prefixes_correlated":true,
        "ideal_uniform_ticket_probability_assumption":if shard.target_index==0 {Some("1/2")}else if shard.target_index==1 {Some("1/32")}else{None},
        "sampling_rotation":"strategy=(position+sample)%17","consensus_default_changed":false,"cheapest_strategy_proven":false,"activation":false}),
    )?;
    let mut counts = Counts::default();
    for sample in 0..SAMPLES {
        let mut expected: Vec<Option<Vec<Commitment>>> = vec![None; shard.horizon];
        for position in 0..ARMS.len() {
            let index = (position + sample as usize) % ARMS.len();
            let total = Clock::start();
            let setup = Clock::start();
            let producer = Producer::new(index, &input.a, &input.b)?;
            let setup = setup.finish();
            counts.setups += 1;
            let supported = producer.is_some();
            emit(
                "cohort",
                json!({"sample":sample,"position":position,"strategy_index":index,"strategy":ARMS[index],"setup_calls":1,"supported":supported,
                "setup":setup.value(),"selection":producer.as_ref().map(Producer::description),"searches_planned":if supported {shard.horizon}else{0}}),
            )?;
            let teardown = if let Some(producer) = producer {
                if let Producer::Full(t) = &producer {
                    if t.proof_prefix() != prefix {
                        return Err("RANK_BATCH_PREPARED_PRODUCT".into());
                    }
                }
                for (search_index, expected) in expected.iter_mut().enumerate() {
                    let position = Position {
                        sample,
                        index,
                        search_index,
                    };
                    let mut observed =
                        search(&producer, prefix, task, target, position, shard.limit())?;
                    counts.searches += 1;
                    counts.attempts += observed.attempts.len();
                    counts.proof_buffers += observed.proof_buffers;
                    counts.speculative += observed.speculative.len();
                    for row in &observed.attempts {
                        if row.get("target_hit") == Some(&Value::Bool(true)) {
                            counts.hits += 1;
                        } else if row.get("complete") == Some(&Value::Bool(true)) {
                            counts.misses += 1;
                        }
                    }
                    counts.exhausted += usize::from(observed.first_hit.is_none());
                    emit(
                        "search",
                        json!({"sample":sample,"strategy_index":index,"search_index":search_index,"setup_calls":0,"batch_width":if index==3 {BATCH}else{1},
                        "batches":observed.batches,"attempt_count":observed.attempts.len(),"complete":observed.errors==0,"errors":observed.errors,
                        "first_hit_nonce":observed.first_hit,"speculative_attempts":observed.speculative.len(),"proof_buffers":observed.proof_buffers,
                        "producer":observed.producer.value(),"observation":observed.observation.value(),"disposal":observed.disposal.value(),"attempts":observed.attempts}),
                    )?;
                    if observed.errors != 0 {
                        return Err("RANK_BATCH_RECORDED_PRODUCER_FAILURE".into());
                    }
                    let identity = signature(&observed);
                    if let Some(previous) = expected {
                        if *previous != identity {
                            return Err("RANK_BATCH_LEGAL_PREFIX_DISAGREEMENT".into());
                        }
                    } else {
                        *expected = Some(identity);
                    }
                    if let Some((context, proof)) = &observed.winner {
                        let nonce = observed.first_hit.unwrap();
                        counts.verifier_calls +=
                            verify(*context, task, target, proof, "winner", position, nonce)?;
                        let mut mutant = proof.clone();
                        let offset = 4 + 3 * CELLS * 4 - 4;
                        let value =
                            u32::from_le_bytes(mutant[offset..offset + 4].try_into().unwrap());
                        mutant[offset..offset + 4]
                            .copy_from_slice(&(((u128::from(value) + 1) % Q) as u32).to_le_bytes());
                        counts.verifier_calls += verify(
                            *context,
                            task,
                            target,
                            &mutant,
                            "product-last",
                            position,
                            nonce,
                        )?;
                    }
                    for extra in &observed.speculative {
                        let mut proof = prefix.to_vec();
                        proof.extend_from_slice(&extra.trace);
                        counts.verifier_calls += verify(
                            extra.challenge,
                            task,
                            [255; 32],
                            &proof,
                            "post-winner-full-replay",
                            position,
                            extra.nonce,
                        )?;
                    }
                    let cleanup = Clock::start();
                    drop(observed.winner.take());
                    let cleanup = cleanup.finish();
                    emit(
                        "search-cleanup",
                        json!({"sample":sample,"strategy_index":index,
                        "search_index":search_index,"scope":"winning-proof-buffer-only","timing":cleanup.value()}),
                    )?;
                }
                let cleanup = Clock::start();
                drop(producer);
                cleanup.finish()
            } else {
                counts.unsupported += 1;
                Timing::zero()
            };
            emit(
                "cohort-end",
                json!({"sample":sample,"strategy_index":index,"teardown":teardown.value(),"total":total.finish().value()}),
            )?;
        }
    }
    emit(
        "footer",
        json!({"setup_calls":counts.setups,"unsupported_setups":counts.unsupported,"search_count":counts.searches,"attempt_count":counts.attempts,
        "hit_count":counts.hits,"miss_count":counts.misses,"exhausted_searches":counts.exhausted,"speculative_attempts":counts.speculative,"proof_buffers":counts.proof_buffers,
        "verifier_calls":counts.verifier_calls,"all_declared_cohorts_completed":true,"status":"COMPONENT_OBSERVATION","activation":false}),
    )
}
fn main() -> Result<()> {
    run(Shard::parse(&std::env::args().skip(1).collect::<Vec<_>>())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };

    fn first(index: usize) -> Position {
        Position {
            sample: 0,
            index,
            search_index: 0,
        }
    }

    #[test]
    fn declaration_is_fixed_and_rejects_resource_or_domain_overrides() {
        let good: Vec<String> = [
            SELECTOR,
            "--class",
            "rank-four-left",
            "--target-index",
            "0",
            "--reuse-winners",
            "8",
        ]
        .map(str::to_owned)
        .into();
        assert_eq!(Shard::parse(&good).unwrap().horizon, 8);
        for (index, value) in [(2, "fake"), (4, "4"), (6, "64"), (6, "0")] {
            let mut bad = good.clone();
            bad[index] = value.into();
            assert!(Shard::parse(&bad).is_err());
        }
        let mut bad = good.clone();
        bad.extend(["--workers".into(), "8".into()]);
        assert!(Shard::parse(&bad).is_err());
        let mut bad = good;
        bad[4] = "2".into();
        assert!(Shard::parse(&bad).is_err());
    }

    #[test]
    fn rank_materials_have_exact_field_ranks_and_preserve_full_rank_partners() {
        for (name, left, right) in [
            ("rank-two-left", 2, 64),
            ("rank-four-left", 4, 64),
            ("rank-eight-left", 8, 64),
            ("rank-four-right", 64, 4),
            ("rank-nine-left", 9, 64),
            ("one-zero-rank-one", 1, 0),
        ] {
            let m = material(name).unwrap();
            assert_eq!(
                (w1_material::rank(&m.a), w1_material::rank(&m.b)),
                (left, right)
            );
        }
    }

    #[test]
    fn parallel_workers_really_overlap_and_keep_declared_order_after_error_or_panic() {
        let barrier = Barrier::new(BATCH);
        let entered = AtomicUsize::new(0);
        let finished = AtomicUsize::new(0);
        let output = parallel_map(&[[0; 32]; BATCH], |index, _| {
            entered.fetch_add(1, Ordering::SeqCst);
            barrier.wait();
            assert_eq!(entered.load(Ordering::SeqCst), BATCH);
            if index == 1 {
                return Err("CONTROLLED_FAILURE".into());
            }
            if index == 2 {
                panic!("controlled worker panic");
            }
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(index)
        });
        assert_eq!(
            output,
            [
                Ok(0),
                Err("CONTROLLED_FAILURE".into()),
                Err("WORKER_PANIC".into()),
                Ok(3)
            ]
        );
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn batch_retains_every_post_winner_attempt_and_every_materialized_buffer() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let producer = Producer::new(3, &zero, &zero).unwrap().unwrap();
        let canonical = Task::new(&zero, &zero, Arithmetic::FullLimb).unwrap();
        let found = search(
            &producer,
            canonical.proof_prefix(),
            task,
            [255; 32],
            first(3),
            8,
        )
        .unwrap();
        assert_eq!(found.first_hit, Some(0));
        assert_eq!(found.attempts.len(), 4);
        assert_eq!(found.speculative.len(), 3);
        assert_eq!(found.proof_buffers, 4);
        assert_eq!(found.batches, 1);
        let sequential = search(
            &producer,
            canonical.proof_prefix(),
            task,
            [255; 32],
            first(2),
            8,
        )
        .unwrap();
        assert_eq!(sequential.attempts.len(), 1);
        assert!(signature(&found) == signature(&sequential));
        assert_eq!(found.winner, sequential.winner);
        for extra in found.speculative {
            let proof = pon_work::prove(extra.challenge, &zero, &zero).unwrap();
            assert_eq!(extra.trace.as_slice(), &proof[PROOF_BYTES - 32..]);
        }
    }

    #[test]
    fn partial_last_batch_obeys_total_attempt_limit_and_never_skips_complete_misses() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let producer = Producer::new(3, &zero, &zero).unwrap().unwrap();
        let canonical = Task::new(&zero, &zero, Arithmetic::FullLimb).unwrap();
        let mut target = [0; 32];
        target[31] = 1;
        let missed = search(
            &producer,
            canonical.proof_prefix(),
            task,
            target,
            first(3),
            3,
        )
        .unwrap();
        assert_eq!(missed.attempts.len(), 3);
        assert!(missed.first_hit.is_none());
        assert_eq!(missed.proof_buffers, 0);
        assert_eq!(missed.batches, 1);
        for (n, row) in missed.attempts.iter().enumerate() {
            assert_eq!(row["nonce"], n);
            assert_eq!(row["complete"], true);
            assert_eq!(row["target_hit"], false);
        }
        for limit in [0, LIMIT + 1] {
            assert!(search(
                &producer,
                canonical.proof_prefix(),
                task,
                target,
                first(3),
                limit
            )
            .is_err());
        }
        assert!(search(
            &producer,
            canonical.proof_prefix(),
            task,
            [0; 32],
            first(3),
            3
        )
        .is_err());
    }

    #[test]
    fn all_existing_producers_keep_the_same_complete_legal_proof_and_prefix() {
        for class in [
            "zero",
            "rank-one",
            "rank-four-left",
            "continuity-maintenance-v1",
        ] {
            let m = material(class).unwrap();
            let task = pon_work::task_id(&m.a, &m.b).unwrap();
            let canonical = Task::new(&m.a, &m.b, Arithmetic::FullLimb).unwrap();
            let baseline = search(
                &Producer::new(0, &m.a, &m.b).unwrap().unwrap(),
                canonical.proof_prefix(),
                task,
                [255; 32],
                first(0),
                1,
            )
            .unwrap();
            for index in 1..ARMS.len() {
                if let Some(p) = Producer::new(index, &m.a, &m.b).unwrap() {
                    let compared = search(
                        &p,
                        canonical.proof_prefix(),
                        task,
                        [255; 32],
                        first(index),
                        1,
                    )
                    .unwrap();
                    assert_eq!(compared.errors, 0);
                    assert!(signature(&compared) == signature(&baseline));
                    assert_eq!(compared.winner, baseline.winner);
                }
            }
        }
    }

    #[test]
    fn changed_task_and_challenge_are_not_a_cross_challenge_trace_cache() {
        let m = material("rank-four-left").unwrap();
        let task = pon_work::task_id(&m.a, &m.b).unwrap();
        let p = Producer::new(2, &m.a, &m.b).unwrap().unwrap();
        let a = challenge(task, [255; 32], 0, 0, 0);
        let b = challenge(task, [255; 32], 0, 1, 0);
        let first = p.attempt(a, [255; 32]).unwrap();
        let second = p.attempt(b, [255; 32]).unwrap();
        assert_ne!(first.trace, second.trace);
        assert_eq!(
            pon_work::verify(b, task, [255; 32], first.proof.as_ref().unwrap()).unwrap_err(),
            WorkError::Transcript
        );
        assert_eq!(
            pon_work::verify(a, [0; 32], [255; 32], first.proof.as_ref().unwrap()).unwrap_err(),
            WorkError::Task
        );
    }
}
