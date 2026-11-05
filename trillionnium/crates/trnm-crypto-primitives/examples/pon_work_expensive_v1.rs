//! Fixed-attempt finite legal-strategy census, never an attacker lower bound.
//!
//! All paid attempts, including misses, remain in the output. A preparation is
//! amortized only over its actual lifetime, and every hit runs both complete W1
//! verifiers. These primitive challenges grant no live task/branch eligibility.
//! The v2 record schema adds sparse preparation as a separate fifteenth arm;
//! the historical --work-expensive-v1 execution selector remains unchanged.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    hint::black_box,
    io::{self, Read, Write},
    path::PathBuf,
    thread,
    time::Instant,
};
use trnm_crypto_primitives::pon_work::{
    self,
    blocked_one_zero::BlockedOneZeroRankOnePreparedTask,
    blocked_zero::BlockedZeroPreparedTask,
    blocked_zero_paired::BlockedZeroPairedPreparedTask,
    legal_attempt::{Arithmetic, Materialization, Preparation, Task},
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{StructuredPreparedTask, TileKernel, TiledPreparedTask},
    Hash, PreparedTask, WorkError, CELLS, N, PROFILE, PROOF_BYTES,
};
#[path = "support/w1_material.rs"]
mod material;

const SCHEMA: &str = "pon-work-expensive-native-v2";
const ARMS: [&str; 15] = [
    "lazy-full-limb",
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
    "scalar-original",
    "lazy-full-limb-sparse",
];
type Result<T> = std::result::Result<T, String>;

#[derive(Debug, PartialEq, Eq)]
struct Options {
    attempts: u64,
    samples: u64,
    reuse: u64,
    target_index: usize,
    seed: Hash,
    material: Option<PathBuf>,
}
impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut args = args.into_iter();
        if args.next().as_deref() != Some("--work-expensive-v1") {
            return Err("SELECTOR".into());
        }
        let mut out = Self {
            attempts: 32,
            samples: 3,
            reuse: 32,
            target_index: 1,
            seed: [0; 32],
            material: None,
        };
        let mut seen = [false; 6];
        while let Some(key) = args.next() {
            let i = match key.as_str() {
                "--attempts" => 0,
                "--samples" => 1,
                "--reuse" => 2,
                "--target-index" => 3,
                "--seed" => 4,
                "--material" => 5,
                _ => return Err("OPTION".into()),
            };
            if std::mem::replace(&mut seen[i], true) {
                return Err("DUPLICATE_OPTION".into());
            }
            let value = args.next().ok_or("OPTION_VALUE")?;
            match i {
                0..=2 => {
                    let n = value.parse::<u64>().map_err(|_| "COUNT")?;
                    if n == 0 || n > if i == 1 { 16 } else { 1024 } || n.to_string() != value {
                        return Err("COUNT".into());
                    }
                    match i {
                        0 => out.attempts = n,
                        1 => out.samples = n,
                        _ => out.reuse = n,
                    }
                }
                3 => {
                    out.target_index = match value.as_str() {
                        "0" => 0,
                        "1" => 1,
                        _ => return Err("TARGET".into()),
                    }
                }
                4 => {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err("SEED".into());
                    }
                    hex::decode_to_slice(value, &mut out.seed).map_err(|_| "SEED")?;
                }
                5 => out.material = Some(value.into()),
                _ => unreachable!(),
            }
        }
        Ok(out)
    }
    fn target(&self) -> Hash {
        let mut target = [255; 32];
        target[0] = [127, 7][self.target_index];
        target
    }
}

#[cfg(target_os = "linux")]
fn cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let s = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let nanos = u64::try_from(s.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    u64::try_from(s.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}
#[cfg(not(target_os = "linux"))]
fn cpu_ns() -> Option<u64> {
    None
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
            cpu: cpu_ns(),
            owner: thread::current().id(),
        }
    }
    fn observe(&self) -> Timing {
        Timing {
            wall: u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            cpu: if self.owner == thread::current().id() {
                self.cpu.and_then(|v| cpu_ns()?.checked_sub(v))
            } else {
                None
            },
        }
    }
    fn finish(self) -> Timing {
        self.observe()
    }
}
#[derive(Clone, Copy)]
struct Timing {
    cpu: Option<u64>,
    wall: Option<u64>,
}
impl Timing {
    fn zero() -> Self {
        Self {
            cpu: Some(0),
            wall: Some(0),
        }
    }
    fn add(&mut self, v: Self) {
        self.cpu = self.cpu.and_then(|n| n.checked_add(v.cpu?));
        self.wall = self.wall.and_then(|n| n.checked_add(v.wall?));
    }
    fn value(self) -> Value {
        json!({"cpu_ns":self.cpu,"wall_ns":self.wall})
    }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn raw(matrix: &[u32]) -> Vec<u8> {
    matrix.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn challenge(task: Hash, seed: Hash, sample: u64, index: u64) -> Hash {
    pon_work::hash(
        b"pon-work-expensive-challenge-v1",
        &[&task, &seed, &sample.to_le_bytes(), &index.to_le_bytes()],
    )
}
// A statement gets one credit regardless of proof encoding, output choice or
// randomness. The v2 domain deliberately does not reuse the initial development
// trace-bearing v1 key. This is still only a research identifier: native branch
// admission, profile registration and fork-choice authority are absent.
fn work_id(challenge: Hash, task: Hash, target: Hash) -> Hash {
    pon_work::hash(b"pon-work-expensive-work-v2", &[&challenge, &task, &target])
}
fn emit(out: &mut impl Write, mut value: Value) -> Result<()> {
    value["schema"] = json!(SCHEMA);
    serde_json::to_writer(&mut *out, &value).map_err(|e| e.to_string())?;
    out.write_all(b"\n").map_err(|e| e.to_string())
}

// Thin dispatch only: all arithmetic is the repository's existing executable
// producer code, with no successful fallback for an unsupported structure.
enum Producer {
    Limb(Box<Task>),
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
    MaintenanceLimb(Box<MaintenanceLimbPreparedTask>),
    Scalar(Vec<u32>, Vec<u32>),
}
struct Trial {
    trace: Hash,
    ticket: Hash,
    hit: bool,
    proof: Option<Vec<u8>>,
}
impl Producer {
    fn new(index: usize, a: &[u32], b: &[u32]) -> std::result::Result<Option<Self>, WorkError> {
        Ok(match index {
            0 => Some(Self::Limb(Box::new(Task::new(a, b, Arithmetic::FullLimb)?))),
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
            12 => {
                MaintenanceLimbPreparedTask::new(a, b)?.map(|t| Self::MaintenanceLimb(Box::new(t)))
            }
            13 => {
                pon_work::task_id(a, b)?;
                Some(Self::Scalar(a.to_vec(), b.to_vec()))
            }
            14 => Some(Self::Limb(Box::new(Task::with_preparation(
                a,
                b,
                Arithmetic::FullLimb,
                Preparation::Sparse,
            )?))),
            _ => return Err(WorkError::Task),
        })
    }
    fn attempt(&self, c: Hash, target: Hash) -> std::result::Result<Trial, WorkError> {
        if let Self::Limb(t) = self {
            let a = t.attempt(c, target, Materialization::TargetHit)?;
            return Ok(Trial {
                trace: a.trace,
                ticket: a.ticket,
                hit: a.target_hit,
                proof: a.proof,
            });
        }
        let proof = match self {
            Self::Generic(t) => t.prove(c),
            Self::Structured(t) => t.prove(c),
            Self::Tiled(t) => t.prove(c),
            Self::Paired(t) => t.prove(c),
            Self::Zero(t) => t.prove(c),
            Self::ZeroPaired(t) => t.prove(c),
            Self::OneZero(t) => t.prove(c),
            Self::Periodic(t) => t.prove(c),
            Self::Integer(t) => t.prove(c),
            Self::Prefix(t) => t.prove(c),
            Self::MaintenanceLimb(t) => t.prove(c),
            Self::Scalar(a, b) => pon_work::prove(c, a, b),
            Self::Limb(_) => unreachable!(),
        }?;
        if proof.len() != PROOF_BYTES {
            return Err(WorkError::Length);
        }
        let trace: Hash = proof[PROOF_BYTES - 32..]
            .try_into()
            .map_err(|_| WorkError::Length)?;
        let ticket = pon_work::hash(b"ticket", &[&c, &trace]);
        Ok(Trial {
            trace,
            ticket,
            hit: ticket <= target,
            proof: Some(proof),
        })
    }
}

fn read_material(bytes: &[u8]) -> Result<(Vec<u32>, Vec<u32>)> {
    if bytes.len() != 2 * CELLS * 4 {
        return Err("MATERIAL_LENGTH".into());
    }
    let v: Vec<_> = bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("fixed word")))
        .collect();
    let (a, b) = v.split_at(CELLS);
    pon_work::task_id(a, b).map_err(|_| "MATERIAL_FIELD")?;
    Ok((a.to_vec(), b.to_vec()))
}
fn materials(options: &Options) -> Result<Vec<material::Material>> {
    if let Some(path) = &options.material {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|e| e.to_string())?
            .take((2 * CELLS * 4 + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let (a, b) = read_material(&bytes)?;
        return Ok(vec![material::Material {
            name: "supplied-material",
            source: "caller-supplied-provenance-not-verified",
            a,
            b,
        }]);
    }
    let mut cases = material::materials(None, None).map_err(|e| e.to_string())?;
    let rank: Vec<_> = (0..CELLS)
        .map(|i| ((i / N + 1) * (i % N + 3)) as u32)
        .collect();
    cases.push(material::Material {
        name: "left-zero-right-rank-one",
        source: "synthetic-fixture",
        a: vec![0; CELLS],
        b: rank.clone(),
    });
    cases.push(material::Material {
        name: "right-zero-left-rank-one",
        source: "synthetic-fixture",
        a: rank,
        b: vec![0; CELLS],
    });
    Ok(cases)
}

struct Totals {
    setup: Timing,
    attempt: Timing,
    cleanup: Timing,
    teardown: Timing,
    verification: Timing,
    attempts: u64,
    hits: u64,
    verified: u64,
    setups: u64,
    unsupported: u64,
    errors: u64,
}
impl Totals {
    fn new() -> Self {
        Self {
            setup: Timing::zero(),
            attempt: Timing::zero(),
            cleanup: Timing::zero(),
            teardown: Timing::zero(),
            verification: Timing::zero(),
            attempts: 0,
            hits: 0,
            verified: 0,
            setups: 0,
            unsupported: 0,
            errors: 0,
        }
    }
    fn producer(&self) -> Timing {
        let mut t = self.setup;
        t.add(self.attempt);
        t.add(self.cleanup);
        t.add(self.teardown);
        t
    }
}
fn execute_cell(
    out: &mut impl Write,
    options: &Options,
    case: &material::Material,
    task: Hash,
    sample: u64,
    arm: usize,
    expected: &mut [Option<(Hash, Hash)>],
) -> Result<Totals> {
    // A continuous instrumentation clock is separate from the disjoint producer
    // components below. It includes intervening verifier/audit/output work and
    // must never be summed with any overlapping component or cache lifetime.
    let cell_clock = Clock::start();
    let mut totals = Totals::new();
    let target = options.target();
    let mut index = 0;
    while index < options.attempts {
        let epoch = index / options.reuse;
        let start_index = index;
        let intended = (options.attempts - index).min(options.reuse);
        let setup_clock = Clock::start();
        let prepared = Producer::new(arm, &case.a, &case.b);
        let setup = setup_clock.finish();
        // Start before the setup record is built/emitted: the retained prepared
        // object already exists through that I/O, and its life is not forgiven.
        let lifetime = Clock::start();
        totals.setup.add(setup);
        totals.setups += 1;
        let (status, error) = match &prepared {
            Ok(Some(_)) => ("prepared", None),
            Ok(None) => ("unsupported", None),
            Err(e) => ("error", Some(format!("{e:?}"))),
        };
        emit(
            out,
            json!({"kind":"setup","class":case.name,"sample":sample,"arm":ARMS[arm],"epoch":epoch,"start_attempt":index,"status":status,"error":error,"timing":setup.value(),"setup_generation":epoch,"cache_key":hex::encode(task),"intended_reuse_attempts":intended}),
        )?;
        let producer = match prepared {
            Ok(Some(p)) => p,
            Ok(None) => {
                totals.unsupported += 1;
                break;
            }
            Err(_) => {
                totals.errors += 1;
                break;
            }
        };
        let mut epoch_hits = 0;
        for _ in 0..intended {
            let before = Clock::start();
            let c = challenge(task, options.seed, sample, index);
            let generated = producer.attempt(c, target);
            black_box(&generated);
            let timing = before.finish();
            totals.attempt.add(timing);
            totals.attempts += 1;
            match generated {
                Err(error) => {
                    totals.errors += 1;
                    let observed_cell = cell_clock.observe();
                    emit(
                        out,
                        json!({"kind":"attempt","class":case.name,"sample":sample,"arm":ARMS[arm],"epoch":epoch,"index":index,"challenge":hex::encode(c),"trace":null,"ticket":null,"target_hit":false,"proof_materialized":false,"proof_sha256":null,"outcome":"error","error":format!("{error:?}"),"timing":timing.value(),"cleanup_timing":Timing::zero().value(),"verification":null,"producer_cumulative_cpu_ns":totals.producer().cpu,"producer_cumulative_wall_ns":totals.producer().wall,"work_id":null,"stream_equal":null,"observed_cell_cumulative_cpu_ns":observed_cell.cpu,"observed_cell_cumulative_wall_ns":observed_cell.wall}),
                    )?;
                }
                Ok(trial) => {
                    let stream_equal = match expected[index as usize] {
                        Some((trace, ticket)) => trace == trial.trace && ticket == trial.ticket,
                        None => {
                            expected[index as usize] = Some((trial.trace, trial.ticket));
                            true
                        }
                    };
                    if !stream_equal {
                        totals.errors += 1;
                    }
                    let mut verification = Value::Null;
                    let proof_sha = trial.proof.as_ref().map(|p| sha(p));
                    let materialized = trial.proof.is_some();
                    if trial.hit {
                        totals.hits += 1;
                        epoch_hits += 1;
                        if let Some(proof) = &trial.proof {
                            let start = Clock::start();
                            let native = pon_work::verify(c, task, target, proof);
                            let nt = start.finish();
                            let start = Clock::start();
                            let scalar = pon_work::verify_reference(c, task, target, proof);
                            let st = start.finish();
                            let equal = match (&native, &scalar) {
                                (Ok(a), Ok(b)) => {
                                    a.product() == b.product()
                                        && a.task() == task
                                        && b.task() == task
                                        && a.challenge() == c
                                        && b.challenge() == c
                                        && a.ticket() == trial.ticket
                                        && b.ticket() == trial.ticket
                                }
                                _ => false,
                            };
                            let native_outcome = match &native {
                                Ok(_) => "Accepted".to_string(),
                                Err(e) => format!("{e:?}"),
                            };
                            let scalar_outcome = match &scalar {
                                Ok(_) => "Accepted".to_string(),
                                Err(e) => format!("{e:?}"),
                            };
                            let start = Clock::start();
                            drop(native);
                            drop(scalar);
                            let cleanup = start.finish();
                            totals.verification.add(nt);
                            totals.verification.add(st);
                            totals.verification.add(cleanup);
                            if equal && stream_equal {
                                totals.verified += 1;
                            } else {
                                totals.errors += 1;
                            }
                            verification = json!({"native":{"outcome":native_outcome,"timing":nt.value()},"scalar":{"outcome":scalar_outcome,"timing":st.value()},"products_equal":equal,"cleanup_timing":cleanup.value()});
                        } else {
                            totals.errors += 1;
                            verification = json!({"error":"MISSING_HIT_PROOF"});
                        }
                    }
                    let (trace, ticket, hit) = (trial.trace, trial.ticket, trial.hit);
                    let start = Clock::start();
                    drop(trial);
                    let cleanup = start.finish();
                    totals.cleanup.add(cleanup);
                    let observed_cell = cell_clock.observe();
                    emit(
                        out,
                        json!({"kind":"attempt","class":case.name,"sample":sample,"arm":ARMS[arm],"epoch":epoch,"index":index,"challenge":hex::encode(c),"trace":hex::encode(trace),"ticket":hex::encode(ticket),"target_hit":hit,"proof_materialized":materialized,"proof_sha256":proof_sha,"outcome":"complete","error":null,"timing":timing.value(),"cleanup_timing":cleanup.value(),"verification":verification,"producer_cumulative_cpu_ns":totals.producer().cpu,"producer_cumulative_wall_ns":totals.producer().wall,"work_id":hex::encode(work_id(c,task,target)),"stream_equal":stream_equal,"observed_cell_cumulative_cpu_ns":observed_cell.cpu,"observed_cell_cumulative_wall_ns":observed_cell.wall}),
                    )?;
                }
            }
            index += 1;
        }
        let before = Clock::start();
        drop(producer);
        let teardown = before.finish();
        let cached_lifetime = lifetime.finish();
        totals.teardown.add(teardown);
        // This is an actually completed cache lifetime, not a counterfactual
        // early-stop estimate. The reader can budget only these closed epochs.
        let observed_cell = cell_clock.observe();
        emit(
            out,
            json!({"kind":"teardown","class":case.name,"sample":sample,"arm":ARMS[arm],"epoch":epoch,"actual_attempts":index-start_index,"actual_hits":epoch_hits,"timing":teardown.value(),"cached_lifetime":cached_lifetime.value(),"lifetime_includes_audit_and_output":true,"observed_cell_cumulative_cpu_ns":observed_cell.cpu,"observed_cell_cumulative_wall_ns":observed_cell.wall}),
        )?;
    }
    let status = if totals.errors > 0 {
        "failed"
    } else if totals.unsupported > 0 {
        "unsupported"
    } else {
        "complete"
    };
    let observed_cell_timing = cell_clock.finish();
    emit(
        out,
        json!({"kind":"cell_summary","class":case.name,"sample":sample,"arm":ARMS[arm],"status":status,"attempts":totals.attempts,"hits":totals.hits,"verified_hits":totals.verified,"setup_count":totals.setups,"unsupported_count":totals.unsupported,"error_count":totals.errors,"setup_timing":totals.setup.value(),"attempt_timing":totals.attempt.value(),"cleanup_timing":totals.cleanup.value(),"teardown_timing":totals.teardown.value(),"producer_timing":totals.producer().value(),"verification_timing":totals.verification.value(),"sequence_complete":index==options.attempts,"distinct_application_results":u64::from(totals.verified>0),"native_branch_accepted_work":null,"observed_cell_timing":observed_cell_timing.value()}),
    )?;
    Ok(totals)
}

fn run(options: Options, out: &mut impl Write) -> Result<bool> {
    let whole = Clock::start();
    let creation = Clock::start();
    let cases = materials(&options)?;
    let creation = creation.finish();
    emit(
        out,
        json!({"kind":"run","profile":PROFILE,"seed":hex::encode(options.seed),"attempts_per_arm":options.attempts,"samples":options.samples,"reuse_attempts":options.reuse,"target":hex::encode(options.target()),"target_index":options.target_index,"arms":ARMS,"class_count":cases.len(),"source_provenance":"caller-must-bind","production_activation":false,"material_creation_timing":creation.value(),"budget_semantics":"complete fixed attempt sequence; prefix CPU budgets are postprocessed with actual setup and cleanup","timing_scope":"producer sums disjoint observed setup, challenge/attempt, proof cleanup and teardown components; excludes material acquisition, audit, output and verifier; run_timing stops before run_summary emission and final flush","challenge_domain":"pon-work-expensive-challenge-v1","work_domain":"pon-work-expensive-work-v2","work_identity_revision":2,"work_identity_fields":["challenge","task","target"],"replaced_development_identity":"v1 also included trace; never interpret it as v2","target_shared_challenge_stream":true,"challenge_is_native_header":false,"observed_cell_clock_scope":"continuous before first setup through final teardown record emission, before cell_summary construction; attempt clocks stop before their own record construction; includes intervening verifier, audit and output; overlaps component clocks and must not be added to them","startup_scope":"material_creation_timing is one whole-run input acquisition; each material identity_timing includes task/raw conversion/rank observation; neither is in cell clocks, no allocation across future reuse"}),
    )?;
    let (mut completed, mut unsupported, mut failed, mut attempts, mut hits, mut verified) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for case in &cases {
        let clock = Clock::start();
        let task = pon_work::task_id(&case.a, &case.b).map_err(|e| format!("MATERIAL_{e:?}"))?;
        let a = raw(&case.a);
        let b = raw(&case.b);
        let ra = material::rank(&case.a);
        let rb = material::rank(&case.b);
        let identity = clock.finish();
        emit(
            out,
            json!({"kind":"material","class":case.name,"source":case.source,"task":hex::encode(task),"a_hex":hex::encode(&a),"b_hex":hex::encode(&b),"a_sha256":sha(&a),"b_sha256":sha(&b),"rank_a":ra,"rank_b":rb,"nonzero_a":case.a.iter().filter(|v|**v!=0).count(),"nonzero_b":case.b.iter().filter(|v|**v!=0).count(),"identity_timing":identity.value()}),
        )?;
        for sample in 0..options.samples {
            let mut expected = vec![None; options.attempts as usize];
            for offset in 0..ARMS.len() {
                let arm = (offset + sample as usize) % ARMS.len();
                let totals = execute_cell(out, &options, case, task, sample, arm, &mut expected)?;
                if totals.errors > 0 {
                    failed += 1;
                } else if totals.unsupported > 0 {
                    unsupported += 1;
                } else {
                    completed += 1;
                }
                attempts += totals.attempts;
                hits += totals.hits;
                verified += totals.verified;
            }
        }
    }
    let timing = whole.finish();
    emit(
        out,
        json!({"kind":"run_summary","status":if failed==0{"complete"}else{"failed"},"requested_cells":cases.len()as u64*options.samples*ARMS.len()as u64,"completed_cells":completed,"unsupported_cells":unsupported,"failed_cells":failed,"attempts":attempts,"hits":hits,"verified_hits":verified,"all_attempts_retained":true,"qualification":false,"run_timing":timing.value(),"native_branch_accepted_work":null,"distinct_application_results_are_not_chain_weight":true}),
    )?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(failed == 0)
}
fn main() {
    let result = Options::parse(std::env::args().skip(1))
        .and_then(|o| run(o, &mut io::BufWriter::new(io::stdout().lock())));
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(e) => {
            eprintln!("{SCHEMA}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_reject_ambiguous_unbounded_or_noncanonical_counts() {
        for args in [
            vec!["--work-expensive-v1", "--attempts", "0"],
            vec!["--work-expensive-v1", "--samples", "17"],
            vec!["--work-expensive-v1", "--attempts", "01"],
            vec!["--work-expensive-v1", "--reuse", "2", "--reuse", "3"],
            vec!["--work-expensive-v1", "--target-index", "2"],
        ] {
            assert!(Options::parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }
    #[test]
    fn external_material_refuses_length_and_noncanonical_words() {
        assert!(read_material(&vec![0; 2 * CELLS * 4 - 1]).is_err());
        assert!(read_material(&vec![0; 2 * CELLS * 4 + 1]).is_err());
        assert!(read_material(&vec![255; 2 * CELLS * 4]).is_err());
        assert!(read_material(&vec![0; 2 * CELLS * 4]).is_ok());
    }
    #[test]
    fn fixed_attempt_census_keeps_misses_and_actual_cache_recreation() {
        let case = material::Material {
            name: "zero",
            source: "test",
            a: vec![0; CELLS],
            b: vec![0; CELLS],
        };
        let task = pon_work::task_id(&case.a, &case.b).unwrap();
        let o = Options {
            attempts: 7,
            samples: 1,
            reuse: 3,
            target_index: 1,
            seed: [3; 32],
            material: None,
        };
        let mut output = Vec::new();
        let mut expected = vec![None; 7];
        let t = execute_cell(&mut output, &o, &case, task, 0, 0, &mut expected).unwrap();
        assert_eq!(t.attempts, 7);
        assert_eq!(t.setups, 3);
        assert!(t.hits < 7);
        assert_eq!(t.hits, t.verified);
        assert_eq!(t.errors, 0);
        let rows: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let trials: Vec<_> = rows.iter().filter(|r| r["kind"] == "attempt").collect();
        assert_eq!(trials.len(), 7);
        let teardown: Vec<_> = rows
            .iter()
            .filter(|r| r["kind"] == "teardown")
            .map(|r| r["actual_attempts"].as_u64().unwrap())
            .collect();
        assert_eq!(teardown, [3, 3, 1]);
        for (i, row) in trials.iter().enumerate() {
            assert_eq!(row["index"], i as u64);
            assert_eq!(row["proof_materialized"], row["target_hit"]);
        }
        // Recompute the exact completed-prefix debit from disjoint raw rows,
        // including each actual epoch teardown before the next setup.
        for (field, cumulative) in [
            ("cpu_ns", "producer_cumulative_cpu_ns"),
            ("wall_ns", "producer_cumulative_wall_ns"),
        ] {
            let mut paid = Some(0_u64);
            let mut last_observed = None;
            for row in &rows {
                match row["kind"].as_str().unwrap() {
                    "setup" | "teardown" => {
                        paid = paid.and_then(|v| v.checked_add(row["timing"][field].as_u64()?));
                        if row["kind"] == "teardown" {
                            let observed_key = if field == "cpu_ns" {
                                "observed_cell_cumulative_cpu_ns"
                            } else {
                                "observed_cell_cumulative_wall_ns"
                            };
                            if let (Some(before), Some(after)) =
                                (last_observed, row[observed_key].as_u64())
                            {
                                assert!(after >= before);
                            }
                            last_observed = row[observed_key].as_u64();
                        }
                    }
                    "attempt" => {
                        for stage in ["timing", "cleanup_timing"] {
                            paid = paid.and_then(|v| v.checked_add(row[stage][field].as_u64()?));
                        }
                        assert_eq!(row[cumulative].as_u64(), paid);
                        let observed_key = if field == "cpu_ns" {
                            "observed_cell_cumulative_cpu_ns"
                        } else {
                            "observed_cell_cumulative_wall_ns"
                        };
                        if let (Some(before), Some(after)) =
                            (last_observed, row[observed_key].as_u64())
                        {
                            assert!(after >= before);
                        }
                        last_observed = row[observed_key].as_u64();
                    }
                    "cell_summary" => {
                        assert_eq!(row["producer_timing"][field].as_u64(), paid);
                        if let (Some(before), Some(after)) =
                            (last_observed, row["observed_cell_timing"][field].as_u64())
                        {
                            assert!(after >= before);
                        }
                    }
                    _ => panic!("unexpected cell row"),
                }
            }
        }
    }
    #[test]
    fn one_zero_optimized_and_full_limb_keep_identical_complete_streams() {
        let case = material::Material {
            name: "one-zero",
            source: "test",
            a: vec![0; CELLS],
            b: (0..CELLS)
                .map(|i| ((i / N + 1) * (i % N + 3)) as u32)
                .collect(),
        };
        let task = pon_work::task_id(&case.a, &case.b).unwrap();
        let target = [255; 32];
        let reference = Producer::new(0, &case.a, &case.b).unwrap().unwrap();
        let alternative = Producer::new(8, &case.a, &case.b).unwrap().unwrap();
        for i in 0..3 {
            let c = challenge(task, [5; 32], 0, i);
            let a = reference.attempt(c, target).unwrap();
            let b = alternative.attempt(c, target).unwrap();
            assert_eq!((a.trace, a.ticket), (b.trace, b.ticket));
            assert_eq!(a.proof, b.proof);
            assert!(pon_work::verify_reference(c, task, target, b.proof.as_ref().unwrap()).is_ok());
        }
    }
    #[test]
    fn sparse_dispatch_matches_dense_and_independent_complete_proofs() {
        let options =
            Options::parse(["--work-expensive-v1"].into_iter().map(str::to_owned)).unwrap();
        let cases = materials(&options).unwrap();
        assert_eq!(cases.len(), 9);
        for case in cases {
            let task = pon_work::task_id(&case.a, &case.b).unwrap();
            let c = challenge(task, [71; 32], 0, 0);
            let dense = Producer::new(0, &case.a, &case.b).unwrap().unwrap();
            let sparse = Producer::new(14, &case.a, &case.b).unwrap().unwrap();
            let expected = pon_work::prove(c, &case.a, &case.b).unwrap();
            let mut miss_target = [0; 32];
            miss_target[31] = 1;
            for (target, hit) in [([255; 32], true), (miss_target, false)] {
                let a = dense.attempt(c, target).unwrap();
                let b = sparse.attempt(c, target).unwrap();
                assert_eq!((a.trace, a.ticket, a.hit), (b.trace, b.ticket, b.hit));
                assert_eq!(a.proof, b.proof);
                assert_eq!(b.hit, hit, "{}", case.name);
                assert_eq!(b.proof.is_some(), hit);
                if let Some(proof) = b.proof {
                    assert_eq!(proof, expected);
                    let native = pon_work::verify(c, task, target, &proof).unwrap();
                    let scalar = pon_work::verify_reference(c, task, target, &proof).unwrap();
                    assert_eq!(native.product(), scalar.product());
                }
            }
        }
        // Zero multiplication partners do not hide malformed padded words.
        let zero = vec![0; CELLS];
        let mut malformed = zero.clone();
        malformed[CELLS - 1] = pon_work::Q as u32;
        for (a, b) in [(&zero, &malformed), (&malformed, &zero)] {
            assert!(matches!(Producer::new(14, a, b), Err(WorkError::Field)));
        }
    }
    #[test]
    fn sparse_v2_cell_retains_every_hit_miss_and_closed_epoch() {
        assert_eq!(SCHEMA, "pon-work-expensive-native-v2");
        assert_eq!(ARMS[0], "lazy-full-limb");
        assert_eq!(ARMS[13], "scalar-original");
        assert_eq!(ARMS[14], "lazy-full-limb-sparse");
        let case = material::Material {
            name: "zero",
            source: "test",
            a: vec![0; CELLS],
            b: vec![0; CELLS],
        };
        let task = pon_work::task_id(&case.a, &case.b).unwrap();
        let options = Options {
            attempts: 7,
            samples: 1,
            reuse: 3,
            target_index: 0,
            seed: [3; 32],
            material: None,
        };
        let mut expected = vec![None; 7];
        let mut streams = Vec::new();
        for arm in [0, 14] {
            let mut output = Vec::new();
            let totals =
                execute_cell(&mut output, &options, &case, task, 0, arm, &mut expected).unwrap();
            assert_eq!((totals.attempts, totals.setups, totals.errors), (7, 3, 0));
            assert!(totals.hits > 0 && totals.hits < totals.attempts);
            assert_eq!(totals.hits, totals.verified);
            let rows: Vec<Value> = String::from_utf8(output)
                .unwrap()
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
            assert!(rows.iter().all(|row| row["schema"] == SCHEMA));
            let epochs: Vec<_> = rows
                .iter()
                .filter(|row| row["kind"] == "teardown")
                .map(|row| row["actual_attempts"].as_u64().unwrap())
                .collect();
            assert_eq!(epochs, [3, 3, 1]);
            let attempts: Vec<_> = rows
                .into_iter()
                .filter(|row| row["kind"] == "attempt")
                .collect();
            assert_eq!(attempts.len(), 7);
            for row in &attempts {
                assert_eq!(row["proof_materialized"], row["target_hit"]);
                if row["target_hit"] == true {
                    for backend in ["native", "scalar"] {
                        assert_eq!(row["verification"][backend]["outcome"], "Accepted");
                    }
                } else {
                    assert!(row["verification"].is_null());
                }
            }
            streams.push(attempts);
        }
        for (dense, sparse) in streams[0].iter().zip(&streams[1]) {
            for field in [
                "challenge",
                "trace",
                "ticket",
                "target_hit",
                "proof_materialized",
                "proof_sha256",
                "work_id",
                "stream_equal",
                "outcome",
            ] {
                assert_eq!(dense[field], sparse[field]);
            }
        }
    }
    #[test]
    fn work_identity_binds_only_the_versioned_statement() {
        let c = [1; 32];
        let task = [2; 32];
        let target = [3; 32];
        let identity = work_id(c, task, target);
        assert_eq!(
            identity,
            pon_work::hash(b"pon-work-expensive-work-v2", &[&c, &task, &target])
        );
        assert_ne!(identity, work_id([4; 32], task, target));
        assert_ne!(identity, work_id(c, [4; 32], target));
        assert_ne!(identity, work_id(c, task, [4; 32]));
        for arbitrary_trace in [[0; 32], [255; 32]] {
            assert_ne!(
                identity,
                pon_work::hash(
                    b"pon-work-expensive-work-v1",
                    &[&c, &task, &target, &arbitrary_trace]
                )
            );
        }
    }

    #[test]
    fn unsupported_optimization_is_not_silently_counted_as_an_executed_cell() {
        let rank: Vec<_> = (0..CELLS)
            .map(|i| ((i / N + 1) * (i % N + 3)) as u32)
            .collect();
        let case = material::Material {
            name: "rank",
            source: "test",
            a: rank.clone(),
            b: rank,
        };
        let task = pon_work::task_id(&case.a, &case.b).unwrap();
        let o = Options {
            attempts: 3,
            samples: 1,
            reuse: 3,
            target_index: 0,
            seed: [0; 32],
            material: None,
        };
        let t = execute_cell(&mut Vec::new(), &o, &case, task, 0, 6, &mut [None; 3]).unwrap();
        assert_eq!((t.attempts, t.unsupported, t.setups), (0, 1, 1));
    }
}
