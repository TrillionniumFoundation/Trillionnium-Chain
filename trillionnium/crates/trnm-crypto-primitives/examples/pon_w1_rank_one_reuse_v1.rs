//! Checked rank-one AB preparation and paid cross-challenge reuse.
//! All six arms execute the same FullLimb transcript and lazy materialization.
//! This is a finite primitive diagnostic, not mining policy or a hardness bound.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, thread, time::Instant};
use trnm_crypto_primitives::pon_work::legal_attempt::{
    Arithmetic, Materialization, Preparation, Task,
};
use trnm_crypto_primitives::pon_work::{
    self, Hash, VerifiedWork, WorkError, CELLS, N, PROOF_BYTES, Q,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-rank-one-reuse-v1";
const SELECTOR: &str = "--rank-one-reuse-v1";
const SAMPLES: usize = 6;
const LIMIT: u64 = 4096;
const CLASSES: [&str; 2] = ["rank-one-field", "rank-one-sparse"];
const HORIZONS: [usize; 3] = [1, 8, 64];
const ARMS: [&str; 6] = [
    "dense-per-search",
    "dense-warm-horizon",
    "sparse-per-search",
    "sparse-warm-horizon",
    "rank-one-per-search",
    "rank-one-warm-horizon",
];
const PREPARATIONS: [&str; 3] = ["dense", "sparse", "checked-rank-one"];
const LIFETIMES: [&str; 2] = ["per-search", "warm-horizon"];
const PATHS: [&str; 2] = ["production", "scalar-reference"];
const CASES: [&str; 3] = ["legal", "product-last", "transcript-max-target"];
const PRODUCER_SCOPE: &str = "all-actual-setups-complete-attempts-tickets-lazy-proof-materializations-binary-trial-retention-one-prefix-copy-and-task-destructions-excludes-evidence-verification-json-and-retained-search-buffer-destruction";
const ATTEMPT_SCOPE: &str =
    "challenge-construction-and-complete-FullLimb-attempt-including-ticket-and-hit-proof-bytes";
const VERIFY_SCOPE: &str =
    "native-full-verifier-call-return-only-no-fact-cache-excludes-returned-work-destruction";

#[derive(Clone, Copy)]
struct Timing {
    cpu_ns: Option<u64>,
    wall_ns: Option<u64>,
}
impl Timing {
    fn json(self) -> Value {
        json!({"cpu_ns":self.cpu_ns,"wall_ns":self.wall_ns})
    }
}
struct Clock {
    cpu: Option<u64>,
    wall: Instant,
    owner: thread::ThreadId,
}
impl Clock {
    fn start() -> Self {
        Self {
            cpu: cpu(),
            wall: Instant::now(),
            owner: thread::current().id(),
        }
    }
    fn finish(self) -> Timing {
        Timing {
            cpu_ns: if self.owner == thread::current().id() {
                self.cpu.and_then(|before| cpu()?.checked_sub(before))
            } else {
                None
            },
            wall_ns: u64::try_from(self.wall.elapsed().as_nanos()).ok(),
        }
    }
}
#[cfg(target_os = "linux")]
fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let nanos = u64::try_from(value.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
#[cfg(not(target_os = "linux"))]
fn cpu() -> Option<u64> {
    None
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn raw(matrix: &[u32]) -> Vec<u8> {
    matrix.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn emit(kind: &str, mut value: Value) -> Result<()> {
    let map = value
        .as_object_mut()
        .ok_or("RANK_ONE_REUSE_RECORD_OBJECT")?;
    map.insert("schema".into(), json!(SCHEMA));
    map.insert("kind".into(), json!(kind));
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
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
            || args[5] != "--reuse-searches"
            || !CLASSES.contains(&args[2].as_str())
        {
            return Err("RANK_ONE_REUSE_FIXED_SHARD_REQUIRED".into());
        }
        let target_index = match args[4].as_str() {
            "0" => 0,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            _ => return Err("RANK_ONE_REUSE_TARGET".into()),
        };
        let horizon = match args[6].as_str() {
            "1" => 1,
            "8" => 8,
            "64" => 64,
            _ => return Err("RANK_ONE_REUSE_HORIZON".into()),
        };
        if target_index >= 2 && horizon != 1 {
            return Err("RANK_ONE_REUSE_CONTROL_HORIZON".into());
        }
        Ok(Self {
            class: args[2].clone(),
            target_index,
            horizon,
        })
    }
    fn target(&self) -> Hash {
        let mut target = [255; 32];
        match self.target_index {
            0 => target[0] = 127,
            1 => target[0] = 7,
            2 => {
                target.fill(0);
                target[31] = 1;
            }
            3 => (),
            _ => unreachable!("validated target"),
        }
        target
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
            _ => unreachable!("validated target"),
        }
    }
}
fn factor(label: u8, index: usize) -> u32 {
    let bytes = pon_work::hash(
        b"pon-w1-rank-one-reuse-factor-v1",
        &[&[label], &(index as u64).to_le_bytes()],
    );
    let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    (u64::from(word) % (Q as u64 - 1) + 1) as u32
}
fn material(class: &str) -> (Vec<u32>, Vec<u32>) {
    let factors: [Vec<u32>; 4] = std::array::from_fn(|label| {
        (0..N)
            .map(|i| {
                let keep = class != "rank-one-sparse"
                    || match label {
                        0 => i % 5 == 2,
                        1 | 2 => i % 7 == 3,
                        _ => i % 11 == 4,
                    };
                if keep {
                    factor(label as u8, i)
                } else {
                    0
                }
            })
            .collect()
    });
    let outer = |left: &[u32], right: &[u32]| -> Vec<u32> {
        left.iter()
            .flat_map(|x| {
                right
                    .iter()
                    .map(|y| ((u128::from(*x) * u128::from(*y)) % Q) as u32)
            })
            .collect()
    };
    (
        outer(&factors[0], &factors[1]),
        outer(&factors[2], &factors[3]),
    )
}
fn challenge(task: Hash, target: Hash, sample: usize, search: usize, nonce: u64) -> Hash {
    // No arm, lifetime or horizon: all arms and overlapping horizons see the
    // same complete search stream, not independent extra mining samples.
    pon_work::hash(
        b"pon-w1-rank-one-reuse-challenge-v1",
        &[
            &task,
            &target,
            &(sample as u64).to_le_bytes(),
            &(search as u64).to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}
fn prepare(arm: usize, a: &[u32], b: &[u32]) -> Result<Task> {
    match arm / 2 {
        0 => Task::with_preparation(a, b, Arithmetic::FullLimb, Preparation::Dense),
        1 => Task::with_preparation(a, b, Arithmetic::FullLimb, Preparation::Sparse),
        2 => {
            return Task::with_rank_one_preparation(a, b, Arithmetic::FullLimb)
                .map_err(|e| format!("RANK_ONE_REUSE_PREPARATION:{e:?}").into())
                .and_then(|value| {
                    value.ok_or_else(|| "RANK_ONE_REUSE_UNSUPPORTED_NO_FALLBACK".into())
                })
        }
        _ => return Err("RANK_ONE_REUSE_ARM".into()),
    }
    .map_err(|e| format!("RANK_ONE_REUSE_PREPARATION:{e:?}").into())
}

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    nonce: u64,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
    hit: bool,
}
struct Trial {
    identity: Identity,
    timing: Timing,
}
struct Search {
    trials: Vec<Trial>,
    winner: Option<Vec<u8>>,
    timing: Timing,
}
fn search(
    producer: &Task,
    shard: &Shard,
    task: Hash,
    sample: usize,
    index: usize,
) -> Result<Search> {
    let total = Clock::start();
    let mut trials = Vec::new();
    let mut winner = None;
    for nonce in 0..shard.limit() {
        let started = Clock::start();
        let context = challenge(task, shard.target(), sample, index, nonce);
        let attempt = black_box(
            producer
                .attempt(context, shard.target(), Materialization::TargetHit)
                .map_err(|e| format!("RANK_ONE_REUSE_ATTEMPT:{e:?}"))?,
        );
        black_box(&attempt);
        let timing = started.finish();
        if attempt.challenge != context
            || attempt.target_hit != (attempt.ticket <= shard.target())
            || attempt.proof.is_some() != attempt.target_hit
        {
            return Err("RANK_ONE_REUSE_ATTEMPT_IDENTITY".into());
        }
        let hit = attempt.target_hit;
        trials.push(Trial {
            identity: Identity {
                nonce,
                challenge: context,
                trace: attempt.trace,
                ticket: attempt.ticket,
                hit,
            },
            timing,
        });
        if hit {
            winner = attempt.proof;
            break;
        }
    }
    Ok(Search {
        trials,
        winner,
        timing: total.finish(),
    })
}
struct Phase {
    search_index: usize,
    timing: Timing,
}
impl Phase {
    fn json(&self) -> Value {
        json!({"search_index":self.search_index,"timing":self.timing.json()})
    }
}
struct Cohort {
    prefix: Vec<u8>,
    setups: Vec<Phase>,
    destructions: Vec<Phase>,
    searches: Vec<Search>,
    timing: Timing,
}
fn cohort(
    shard: &Shard,
    a: &[u32],
    b: &[u32],
    task: Hash,
    sample: usize,
    arm: usize,
) -> Result<Cohort> {
    let total = Clock::start();
    let warm = arm % 2 == 1;
    let mut producer = None;
    let mut prefix = Vec::new();
    let mut setups = Vec::new();
    let mut destructions = Vec::new();
    let mut searches = Vec::new();
    for index in 0..shard.horizon {
        if producer.is_none() {
            let started = Clock::start();
            producer = Some(black_box(prepare(arm, a, b)?));
            setups.push(Phase {
                search_index: index,
                timing: started.finish(),
            });
            // Exactly one retained prefix copy in EVERY arm, in its paid total.
            if prefix.is_empty() {
                prefix = producer.as_ref().unwrap().proof_prefix().to_vec();
            }
        }
        searches.push(search(
            producer.as_ref().unwrap(),
            shard,
            task,
            sample,
            index,
        )?);
        if !warm || index + 1 == shard.horizon {
            let started = Clock::start();
            drop(producer.take());
            destructions.push(Phase {
                search_index: index,
                timing: started.finish(),
            });
        }
    }
    Ok(Cohort {
        prefix,
        setups,
        destructions,
        searches,
        timing: total.finish(),
    })
}
fn same_stream(left: &[Search], right: &[Search]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            a.winner == b.winner
                && a.trials.len() == b.trials.len()
                && a.trials
                    .iter()
                    .zip(&b.trials)
                    .all(|(x, y)| x.identity == y.identity)
        })
}
fn outcome(value: std::result::Result<VerifiedWork, WorkError>) -> Value {
    match value {
        Ok(work) => json!({"result":"Accepted","challenge":hex::encode(work.challenge()),
            "task":hex::encode(work.task()),"ticket":hex::encode(work.ticket()),"product_sha256":sha(&raw(work.product()))}),
        Err(error) => json!({"result":format!("{error:?}")}),
    }
}
fn checks(
    shard: &Shard,
    task: Hash,
    searched: &Search,
    rotation: usize,
) -> Result<(Vec<Value>, usize)> {
    let Some(proof) = searched.winner.as_ref() else {
        return Ok((Vec::new(), 0));
    };
    let last = &searched
        .trials
        .last()
        .ok_or("RANK_ONE_REUSE_EMPTY_SEARCH")?
        .identity;
    let mut values = Vec::new();
    let mut failures = 0;
    for (case, name) in CASES.iter().enumerate() {
        let mut mutation = None;
        let changed;
        let candidate = if case == 0 {
            proof.as_slice()
        } else {
            let started = Clock::start();
            let mut bytes = proof.clone();
            if case == 1 {
                let offset = PROOF_BYTES - 36;
                let before = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                bytes[offset..offset + 4].copy_from_slice(&((before + 1) % Q as u32).to_le_bytes());
            } else {
                bytes[PROOF_BYTES - 1] ^= 1;
            }
            mutation = Some(started.finish().json());
            changed = bytes;
            &changed
        };
        // Transcript mutation uses an explicit MAX-target negative control,
        // not a fabricated ticket hit at the cost population's target.
        let target = if case == 2 { [255; 32] } else { shard.target() };
        let mut verifiers = Vec::new();
        for order in 0..PATHS.len() {
            let path = (rotation + order) % PATHS.len();
            let started = Clock::start();
            let observed = black_box(if path == 0 {
                pon_work::verify(last.challenge, task, target, candidate)
            } else {
                pon_work::verify_reference(last.challenge, task, target, candidate)
            });
            let timing = started.finish();
            let actual = outcome(observed);
            let expected = match case {
                0 => json!({"result":"Accepted","challenge":hex::encode(last.challenge),
                    "task":hex::encode(task),"ticket":hex::encode(last.ticket),
                    "product_sha256":sha(&proof[4+2*CELLS*4..PROOF_BYTES-32])}),
                1 => json!({"result":"Product"}),
                _ => json!({"result":"Transcript"}),
            };
            failures += usize::from(actual != expected);
            verifiers.push(json!({"path":PATHS[path],"invocation_order":order,
                "timing":timing.json(),"outcome":actual}));
        }
        values.push(
            json!({"case":name,"target":hex::encode(target),"proof_sha256":sha(candidate),
            "mutation_timing":mutation,"verifiers":verifiers}),
        );
    }
    Ok((values, failures))
}
fn report_search(
    shard: &Shard,
    task: Hash,
    prefix: &[u8],
    (sample, arm, order, index): (usize, usize, usize, usize),
    searched: &Search,
) -> Result<usize> {
    let started = Clock::start();
    let mut digest = Sha256::new();
    digest.update(prefix);
    let attempts: Vec<_> = searched.trials.iter().map(|trial| {
        let id = &trial.identity;
        let mut full = digest.clone();
        full.update(id.trace);
        json!({"nonce":id.nonce,"challenge":hex::encode(id.challenge),"trace":hex::encode(id.trace),
            "ticket":hex::encode(id.ticket),"hit":id.hit,"proof_materialized":id.hit,
            "complete_proof_sha256":hex::encode(full.finalize()),"timing":trial.timing.json()})
    }).collect();
    let winner = searched
        .winner
        .as_ref()
        .map(|proof| json!({"proof_sha256":sha(proof)}));
    if let Some(proof) = &searched.winner {
        if proof.len() != PROOF_BYTES
            || proof[..PROOF_BYTES - 32] != *prefix
            || proof[PROOF_BYTES - 32..] != searched.trials.last().unwrap().identity.trace
        {
            return Err("RANK_ONE_REUSE_WINNER_BYTES".into());
        }
    }
    let evidence_timing = started.finish();
    let (verification, failures) = checks(shard, task, searched, sample + order + index)?;
    emit(
        "search",
        json!({"sample":sample,"arm":ARMS[arm],"search_index":index,
        "timing":searched.timing.json(),"attempts":attempts,"winner":winner,
        "status":if searched.winner.is_some(){"target-hit-unverified"}else{"exhausted"},
        "evidence_timing":evidence_timing.json(),"checks":verification}),
    )?;
    Ok(failures)
}
fn run() -> Result<()> {
    let shard = Shard::parse(&std::env::args().skip(1).collect::<Vec<_>>())?;
    let started = Clock::start();
    let (a, b) = material(&shard.class);
    let task = pon_work::task_id(&a, &b).map_err(|e| format!("RANK_ONE_REUSE_MATERIAL:{e:?}"))?;
    let material_timing = started.finish();
    emit(
        "campaign",
        json!({"selector":SELECTOR,"class":shard.class,"target_index":shard.target_index,
        "target":hex::encode(shard.target()),"reuse_searches":shard.horizon,"samples":SAMPLES,
        "attempt_budget":shard.limit(),"purpose":shard.purpose(),"classes":CLASSES,"horizons":HORIZONS,
        "arms":ARMS,"preparations":PREPARATIONS,"lifetimes":LIFETIMES,"paths":PATHS,"cases":CASES,
        "arithmetic":"full-limb","materialization":"target-hit","clock":"thread-cpu-and-monotonic-wall-ns",
        "producer_timing_scope":PRODUCER_SCOPE,"attempt_timing_scope":ATTEMPT_SCOPE,"verifier_timing_scope":VERIFY_SCOPE,
        "cross_horizon_challenges":"same-prefix-not-independent","proof_bytes_encoding":"shared-exact-prefix-plus-32-byte-trace",
        "material_timing":material_timing.json(),"cheapest_legal_strategy_lower_bound_established":false,
        "public_service_measured":false,"batching_measured":false,"persistent_cache_measured":false,
        "hardware_fairness_qualified":false,"production_activation":false}),
    )?;
    emit(
        "material",
        json!({"class":shard.class,"task":hex::encode(task),"a_hex":hex::encode(raw(&a)),
        "b_hex":hex::encode(raw(&b)),"source":"deterministic-synthetic-rank-one-v1","provenance_verified":false}),
    )?;
    let mut retained_prefix: Option<Vec<u8>> = None;
    let mut cohort_count = 0;
    let mut search_count = 0;
    let mut semantic_failures = 0;
    for sample in 0..SAMPLES {
        let mut canonical: Option<Vec<Search>> = None;
        for order in 0..ARMS.len() {
            let arm = (sample + order) % ARMS.len();
            let observed = cohort(&shard, &a, &b, task, sample, arm)?;
            if let Some(prefix) = &retained_prefix {
                if prefix != &observed.prefix {
                    return Err("RANK_ONE_REUSE_PREFIX_MISMATCH".into());
                }
            } else {
                emit(
                    "proof_prefix",
                    json!({"bytes_hex":hex::encode(&observed.prefix),"sha256":sha(&observed.prefix)}),
                )?;
                retained_prefix = Some(observed.prefix.clone());
            }
            if canonical
                .as_ref()
                .is_some_and(|earlier| !same_stream(earlier, &observed.searches))
            {
                return Err("RANK_ONE_REUSE_CHANGED_STREAM".into());
            }
            emit(
                "cohort",
                json!({"sample":sample,"arm":ARMS[arm],"invocation_order":order,
                "preparation":PREPARATIONS[arm/2],"lifetime":LIFETIMES[arm%2],"prefix_sha256":sha(&observed.prefix),
                "timing":observed.timing.json(),"setups":observed.setups.iter().map(Phase::json).collect::<Vec<_>>(),
                "destructions":observed.destructions.iter().map(Phase::json).collect::<Vec<_>>(),"searches":shard.horizon}),
            )?;
            cohort_count += 1;
            for (index, searched) in observed.searches.iter().enumerate() {
                semantic_failures += report_search(
                    &shard,
                    task,
                    &observed.prefix,
                    (sample, arm, order, index),
                    searched,
                )?;
                search_count += 1;
            }
            if canonical.is_none() {
                canonical = Some(observed.searches);
            }
        }
    }
    emit(
        "end",
        json!({"cohort_count":cohort_count,"search_count":search_count,
        "semantic_failures":semantic_failures,"complete":true}),
    )?;
    if semantic_failures != 0 {
        return Err("RANK_ONE_REUSE_VERIFIER_SEMANTICS".into());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
