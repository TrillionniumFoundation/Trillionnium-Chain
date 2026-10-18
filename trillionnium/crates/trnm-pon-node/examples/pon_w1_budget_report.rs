//! Bounded same-task/target producer, direct false-trace and receiver CPU report.
//! Raw full-verifier diagnostics and cooperative receiver outcomes are separate.
//! Example only: no W1, signed-domain, target or fork-choice rule is replaced.
#[path = "support/w1_from_zero.rs"]
mod w1_from_zero;

use serde_json::{json, Value};
use std::{
    io::{self, Write},
    thread,
    time::Instant,
};
use trnm_crypto_primitives::pon_work::{
    self, blocked_zero::BlockedZeroPreparedTask, structured::StructuredPreparedTask, PreparedTask,
    VerificationError, VerificationProgress, VerifiedWork,
};
use trnm_pon_node::ingress::public_v3::ServiceMutationCpuDomain;
use trnm_protocol::pon_wire::{hash, Hash};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-same-target-budget-v1";
const CLASSES: [&str; 4] = ["dense", "zero", "rank-one", "sparse"];

struct Options {
    samples: u64,
    attempts: u64,
    receiver_replays: u64,
    target: Hash,
    seed: u64,
}
impl Options {
    fn parse() -> Result<Self> {
        let mut target = [255; 32];
        target[0] = 127;
        let mut options = Self {
            samples: 1,
            attempts: 8,
            receiver_replays: 1,
            target,
            seed: 1,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--help" {
                println!("pon_w1_budget_report [--samples 1..16] [--attempts 1..4096] [--receiver-replays 1..64] [--target 64hex] [--seed u64]\nJSONL retains every attempt, unsupported arms, exhaustion, raw relation outcomes and separate shared receiver-budget outcomes.");
                std::process::exit(0);
            }
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for {arg}"))?;
            match arg.as_str() {
                "--samples" => options.samples = value.parse()?,
                "--attempts" => options.attempts = value.parse()?,
                "--receiver-replays" => options.receiver_replays = value.parse()?,
                "--seed" => options.seed = value.parse()?,
                "--target" => {
                    options.target = hex::decode(value)?
                        .try_into()
                        .map_err(|_| "target must be 32 bytes")?
                }
                _ => return Err(format!("unknown option {arg}").into()),
            }
        }
        if !(1..=16).contains(&options.samples)
            || !(1..=4096).contains(&options.attempts)
            || !(1..=64).contains(&options.receiver_replays)
        {
            return Err("samples/attempts/receiver-replays outside bounded range".into());
        }
        Ok(options)
    }
}

// Match the original receiver's checked calling-thread CPU semantics. Wall
// time never fills a missing CPU value; a moved/reversed interval stays null.
struct Clock {
    wall: Instant,
    cpu: Option<u64>,
    owner: thread::ThreadId,
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: thread_cpu_ns(),
            owner: thread::current().id(),
        }
    }
    fn finish(self) -> Timing {
        Timing {
            wall_ns: u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            cpu_ns: if self.owner == thread::current().id() {
                self.cpu
                    .and_then(|start| thread_cpu_ns()?.checked_sub(start))
            } else {
                None
            },
        }
    }
}
#[derive(serde::Serialize)]
struct Timing {
    wall_ns: Option<u64>,
    cpu_ns: Option<u64>,
}
#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u64::try_from(stamp.tv_sec).ok()?;
    let nanos = u64::try_from(stamp.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}
#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> Option<u64> {
    None
}
fn emit(value: Value) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn challenge(options: &Options, class: &str, sample: u64, nonce: u64) -> Hash {
    hash(
        b"pon-w1-budget-challenge-v1",
        &[
            &options.seed.to_le_bytes(),
            class.as_bytes(),
            &sample.to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}
fn material(options: &Options, class: &str) -> (Vec<u32>, Vec<u32>) {
    let mut a = vec![0; pon_work::CELLS];
    let mut b = a.clone();
    for index in 0..pon_work::CELLS {
        let random = hash(
            b"pon-w1-budget-material-v1",
            &[
                &options.seed.to_le_bytes(),
                class.as_bytes(),
                &(index as u64).to_le_bytes(),
            ],
        );
        let field = |offset| {
            (u128::from(u32::from_le_bytes(
                random[offset..offset + 4].try_into().unwrap(),
            )) % pon_work::Q) as u32
        };
        match class {
            "dense" => {
                a[index] = field(0);
                b[index] = field(4);
            }
            "zero" => {}
            "rank-one" => {
                a[index] = ((index / pon_work::N + 1) * (index % pon_work::N + 1)) as u32;
                b[index] = ((index / pon_work::N + 3) * (index % pon_work::N + 2)) as u32;
            }
            "sparse" => {
                if index.is_multiple_of(17) {
                    a[index] = field(0);
                }
                if index.is_multiple_of(19) {
                    b[index] = field(4);
                }
            }
            _ => unreachable!(),
        }
    }
    (a, b)
}

enum Producer {
    Generic(PreparedTask),
    Structured(StructuredPreparedTask),
    BlockedZero(BlockedZeroPreparedTask),
    FalseTrace(Vec<u8>),
}
impl Producer {
    fn prepare(
        arm: &str,
        a: &[u32],
        b: &[u32],
    ) -> std::result::Result<Option<Self>, pon_work::WorkError> {
        match arm {
            "generic" => PreparedTask::new(a, b).map(|task| Some(Self::Generic(task))),
            "structured" => {
                StructuredPreparedTask::new(a, b).map(|task| task.map(Self::Structured))
            }
            "blocked-zero" => {
                BlockedZeroPreparedTask::new(a, b).map(|task| task.map(Self::BlockedZero))
            }
            "from-zero-false-trace" => {
                w1_from_zero::proof_prefix(a, b).map(|proof| Some(Self::FalseTrace(proof)))
            }
            _ => unreachable!(),
        }
    }
    fn proof(&self, challenge: Hash) -> std::result::Result<Vec<u8>, pon_work::WorkError> {
        match self {
            Self::Generic(task) => task.prove(challenge),
            Self::Structured(task) => task.prove(challenge),
            Self::BlockedZero(task) => task.prove(challenge),
            Self::FalseTrace(_) => unreachable!(),
        }
    }
}
struct Candidate {
    case: String,
    challenge: Hash,
    task: Hash,
    proof: Vec<u8>,
    producer_cpu_ns: Option<u64>,
}

fn generate(
    options: &Options,
    class: &str,
    sample: u64,
    arm: &str,
    a: &[u32],
    b: &[u32],
    task: Hash,
) -> Result<Option<Candidate>> {
    let case = format!("{class}/{sample}/{arm}");
    let total = Clock::start();
    let setup = Clock::start();
    let prepared = Producer::prepare(arm, a, b).map_err(|e| format!("prepare {case}: {e:?}"))?;
    let setup = setup.finish();
    let Some(prepared) = prepared else {
        return emit(json!({"schema":SCHEMA,"kind":"producer","case":case,"task":hex::encode(task),
            "target":hex::encode(options.target),"status":"unsupported","setup":setup,"total":total.finish(),"attempts":[]})).map(|()| None);
    };
    let method = match &prepared {
        Producer::Structured(task) => task.method(),
        Producer::FalseTrace(_) => "claimed-zero-C-and-hash-only-trace-search",
        Producer::BlockedZero(_) => "blocked-zero-full-transcript",
        Producer::Generic(_) => "generic-prepared-full-transcript",
    };
    let mut trials = Vec::new();
    let mut candidate = None;
    let search = Clock::start();
    for nonce in 0..options.attempts {
        let measured = Clock::start();
        let context = challenge(
            options,
            class,
            sample,
            if matches!(prepared, Producer::FalseTrace(_)) {
                0
            } else {
                nonce
            },
        );
        let (trace, ticket, proof) = if let Producer::FalseTrace(prefix) = &prepared {
            let (trace, ticket) = w1_from_zero::trial(context, nonce);
            let proof = if options.target != [0; 32] && ticket <= options.target {
                let mut bytes = prefix.clone();
                bytes[pon_work::PROOF_BYTES - 32..].copy_from_slice(&trace);
                Some(bytes)
            } else {
                None
            };
            (trace, ticket, proof)
        } else {
            let proof = prepared
                .proof(context)
                .map_err(|e| format!("prove {case}: {e:?}"))?;
            let trace: Hash = proof[pon_work::PROOF_BYTES - 32..].try_into().unwrap();
            (trace, hash(b"ticket", &[&context, &trace]), Some(proof))
        };
        let hit = options.target != [0; 32] && ticket <= options.target;
        let timing = measured.finish();
        trials.push(
            json!({"nonce":nonce,"challenge":hex::encode(context),"trace":hex::encode(trace),
            "ticket":hex::encode(ticket),"target_hit_unverified":hit,"timing":timing}),
        );
        if hit {
            candidate = Some(Candidate {
                case: case.clone(),
                challenge: context,
                task,
                proof: proof.ok_or("missing winning bytes")?,
                producer_cpu_ns: None,
            });
            break;
        }
    }
    let search = search.finish();
    let total = total.finish();
    if let Some(candidate) = &mut candidate {
        candidate.producer_cpu_ns = total.cpu_ns;
    }
    emit(
        json!({"schema":SCHEMA,"kind":"producer","case":case,"task":hex::encode(task),"target":hex::encode(options.target),
        "method":method,"status":if candidate.is_some(){"target-hit-unverified"}else{"exhausted"},"attempt_budget":options.attempts,
        "attempts_executed":trials.len(),"attempts":trials,"setup":setup,"search":search,"total":total,
        "candidate_proof_digest":candidate.as_ref().map(|c|hex::encode(hash(b"proof", &[&c.proof]))),
        "scope":"setup plus every failed/successful trial and in-memory trial records; excludes final JSONL serialization and public task material construction",
        "phase_intervals_nested_in_total":true,"valid_proof_acquisition_used":arm!="from-zero-false-trace"}),
    )?;
    Ok(candidate)
}

fn verdict<E: std::fmt::Display>(
    result: std::result::Result<VerifiedWork, VerificationError<E>>,
) -> Value {
    match result {
        Ok(_) => json!({"kind":"verified-work","error":null}),
        Err(VerificationError::Relation(error)) => {
            json!({"kind":"relation-error","error":format!("{error:?}")})
        }
        Err(VerificationError::Cancelled(error)) => {
            json!({"kind":"local-cancellation","error":error.to_string()})
        }
    }
}
fn raw_diagnostic(options: &Options, candidate: &Candidate) -> Result<()> {
    for kernel in ["production", "scalar-reference", "limb"] {
        let mut checkpoints = 0u64;
        let measured = Clock::start();
        let mut progress =
            |_: VerificationProgress| -> std::result::Result<(), std::convert::Infallible> {
                checkpoints += 1;
                Ok(())
            };
        let result = match kernel {
            "production" => pon_work::verify_with_progress(
                candidate.challenge,
                candidate.task,
                options.target,
                &candidate.proof,
                &mut progress,
            ),
            "scalar-reference" => pon_work::verify_reference_with_progress(
                candidate.challenge,
                candidate.task,
                options.target,
                &candidate.proof,
                &mut progress,
            ),
            "limb" => pon_work::verify_limb_with_progress(
                candidate.challenge,
                candidate.task,
                options.target,
                &candidate.proof,
                &mut progress,
            ),
            _ => unreachable!(),
        };
        let timing = measured.finish();
        let result = verdict(result);
        let ratio =
            timing
                .cpu_ns
                .zip(candidate.producer_cpu_ns)
                .and_then(|(receiver, producer)| {
                    (producer > 0).then_some(receiver as f64 / producer as f64)
                });
        emit(
            json!({"schema":SCHEMA,"kind":"raw-verifier-diagnostic","case":candidate.case,"kernel":kernel,
            "target":hex::encode(options.target),"task":hex::encode(candidate.task),"outcome":result,"timing":timing,
            "checkpoints":checkpoints,"receiver_cpu_over_full_producer_search_cpu":ratio,
            "ratio_denominator":"same arm full setup + all trials CPU, including failed trials; not winning trial only",
            "scope":"full primitive replay, no service budget; excludes packet/p2p/signature/M06/SQLite and JSONL serialization"}),
        )?;
    }
    Ok(())
}
fn receiver_campaign(options: &Options, candidates: &[Candidate]) -> Result<()> {
    let domain = ServiceMutationCpuDomain::standalone();
    emit(
        json!({"schema":SCHEMA,"kind":"receiver-domain-start","domain_count":1,"state":domain.observe()?,
        "scope":"one explicit local domain for the entire receiver phase; original reserve/refill/debit semantics; no per-case or per-key reset"}),
    )?;
    let wall = Instant::now();
    let mut attempts = 0u64;
    let mut starts = 0u64;
    let mut verified = 0u64;
    let mut relation_errors = 0u64;
    let mut cancellations = 0u64;
    let mut start_refusals = 0u64;
    for round in 0..options.receiver_replays {
        for candidate in candidates {
            attempts += 1;
            let before = domain.observe()?;
            let operation = match domain.begin() {
                Ok(operation) => operation,
                Err(error) => {
                    start_refusals += 1;
                    emit(
                        json!({"schema":SCHEMA,"kind":"receiver","case":candidate.case,"round":round,
                        "status":"not-started","error":error.to_string(),"before":before,"after":domain.observe()?}),
                    )?;
                    continue;
                }
            };
            starts += 1;
            let mut checkpoints = 0u64;
            let result = pon_work::verify_with_progress(
                candidate.challenge,
                candidate.task,
                options.target,
                &candidate.proof,
                &mut |_| {
                    checkpoints += 1;
                    operation.checkpoint()
                },
            );
            match &result {
                Ok(_) => verified += 1,
                Err(VerificationError::Relation(_)) => relation_errors += 1,
                Err(VerificationError::Cancelled(_)) => cancellations += 1,
            }
            let result = verdict(result);
            let settlement = operation.finish();
            emit(
                json!({"schema":SCHEMA,"kind":"receiver","case":candidate.case,"round":round,"status":"started",
                "outcome":result,"checkpoints":checkpoints,"settlement":settlement,"before":before,"after":domain.observe()?,
                "scope":"production W1 verifier plus cooperative checkpoint accounting; original live + residual charge once; no block admission claim"}),
            )?;
        }
    }
    emit(
        json!({"schema":SCHEMA,"kind":"receiver-summary","receiver_replays":options.receiver_replays,
        "candidate_count":candidates.len(),"requested_replays":attempts,"started_replays":starts,"verified_work":verified,
        "relation_errors":relation_errors,"local_cancellations":cancellations,"start_refusals":start_refusals,
        "wall_ns":u64::try_from(wall.elapsed().as_nanos()).ok(),"actual_flow":domain.observe_actual_flow()?,"final_state":domain.observe()?,
        "denominator":"all requested replays, including start refusal and local cancellation; distinct successful blocks and business confirmations are not measured",
        "source_proves_w1_hardness":false,"independent_operators":false,"production_qualification":false}),
    )
}
fn main() -> Result<()> {
    let options = Options::parse()?;
    emit(
        json!({"schema":SCHEMA,"kind":"campaign","work_profile":pon_work::PROFILE,"target":hex::encode(options.target),
        "samples":options.samples,"attempt_budget_per_arm":options.attempts,"seed":options.seed,"receiver_replays":options.receiver_replays,
        "classes":CLASSES,"cpu_clock":"actual calling-thread CPU; unavailable/reversed remains null","w1_changed":false,
        "scope":"same task/target bounded diagnostic; generic/structured legal streams match; false-trace search holds the first challenge fixed and never acquires a valid proof"}),
    )?;
    let mut candidates = Vec::new();
    for class in CLASSES {
        let measured = Clock::start();
        let (a, b) = material(&options, class);
        let task = pon_work::task_id(&a, &b).map_err(|e| format!("task {class}: {e:?}"))?;
        let timing = measured.finish();
        emit(
            json!({"schema":SCHEMA,"kind":"public-task-material","class":class,"task":hex::encode(task),"timing":timing,
            "generation":"pon-w1-budget-material-v1 with reported seed; construction outside all per-arm search denominators"}),
        )?;
        for sample in 0..options.samples {
            for arm in [
                "generic",
                "structured",
                "blocked-zero",
                "from-zero-false-trace",
            ] {
                if let Some(candidate) = generate(&options, class, sample, arm, &a, &b, task)? {
                    raw_diagnostic(&options, &candidate)?;
                    candidates.push(candidate);
                }
            }
        }
    }
    receiver_campaign(&options, &candidates)
}
