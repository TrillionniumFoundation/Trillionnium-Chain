//! Same-stream, complete-certificate comparison of a genuine four-challenge
//! SIMD kernel and the original sequential PreparedTask producer.
//! Diagnostic Header values confer no parent eligibility or native admission.
#[path = "support/w1_joint_challenge.rs"]
mod joint;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{self, Hash, PreparedTask, CELLS, N, PROOF_BYTES, Q};
use trnm_protocol::pon_wire::Header;
use w1_material::Material;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-joint-challenge-v1";
const FAMILIES: [&str; 10] = [
    "periodic-dense-fixture",
    "full-rank-field",
    "zero",
    "identity",
    "rank-one",
    "sparse-diagonal",
    "continuity-maintenance-v1",
    "zero-left-rank-one",
    "zero-right-rank-one",
    "near-q-full-rank",
];

#[derive(Clone, Debug, Serialize)]
struct Options {
    producer: String,
    family: String,
    mode: String,
    attempts: u64,
    width: usize,
    seed: u64,
    sample: u64,
    target: Hash,
    cpu_budget_ns: Option<u64>,
    nonce_space: u64,
}
fn parse_options(args: impl IntoIterator<Item = String>) -> Result<Options> {
    let mut out = Options {
        producer: "avx2-joint".into(),
        family: "full-rank-field".into(),
        mode: "hot".into(),
        attempts: 4,
        width: 4,
        seed: 1,
        sample: 0,
        target: [255; 32],
        cpu_budget_ns: None,
        nonce_space: 0,
    };
    out.target[0] = 127;
    let mut supplied = BTreeSet::new();
    let mut args = args.into_iter();
    while let Some(key) = args.next() {
        if !supplied.insert(key.clone()) {
            return Err(format!("DUPLICATE_OPTION:{key}").into());
        }
        let value = args.next().ok_or_else(|| format!("MISSING_VALUE:{key}"))?;
        match key.as_str() {
            "--producer" => out.producer = value,
            "--family" => out.family = value,
            "--mode" => out.mode = value,
            "--attempts" => out.attempts = value.parse()?,
            "--width" => out.width = value.parse()?,
            "--seed" => out.seed = value.parse()?,
            "--sample" => out.sample = value.parse()?,
            "--target" => {
                out.target = hex::decode(value)?
                    .try_into()
                    .map_err(|_| "TARGET_LENGTH")?;
            }
            "--cpu-budget-ns" => out.cpu_budget_ns = Some(value.parse()?),
            "--nonce-space" => out.nonce_space = value.parse()?,
            _ => return Err(format!("UNKNOWN_OPTION:{key}").into()),
        }
    }
    if !["avx2-joint", "prepared-sequential"].contains(&out.producer.as_str())
        || !["hot", "cold"].contains(&out.mode.as_str())
        || !FAMILIES.contains(&out.family.as_str())
        || !(1..=4096).contains(&out.attempts)
        || !(1..=joint::SIMD_LANES).contains(&out.width)
    {
        return Err("OPTION_BOUNDS".into());
    }
    if supplied.contains("--nonce-space") && out.nonce_space == 0 {
        return Err("NONCE_SPACE_BOUNDS".into());
    }
    if out.nonce_space == 0 {
        out.nonce_space = out.attempts;
    }
    if out.nonce_space > 4096 {
        return Err("NONCE_SPACE_BOUNDS".into());
    }
    Ok(out)
}

fn material(family: &str) -> Result<Material> {
    match family {
        "near-q-full-rank" => Ok(Material {
            name: "near-q-full-rank",
            source: "canonical-near-q-full-rank-boundary",
            // -(J+I) and -(J+P), with P a cyclic permutation. Both are
            // invertible over Fq: 65 != 0, and P is invertible. These are
            // structured matrices with small signed representations, used
            // only as canonical-word boundaries, never as hardness evidence.
            a: (0..CELLS)
                .map(|p| Q as u32 - 1 - u32::from(p / N == p % N))
                .collect(),
            b: (0..CELLS)
                .map(|p| Q as u32 - 1 - u32::from((p / N + 1) % N == p % N))
                .collect(),
        }),
        "zero-left-rank-one" => Ok(Material {
            name: "zero-left-rank-one",
            source: "synthetic-fixture",
            a: vec![0; CELLS],
            b: (0..CELLS)
                .map(|i| ((i / N + 2) * (i % N + 1)) as u32)
                .collect(),
        }),
        "zero-right-rank-one" => Ok(Material {
            name: "zero-right-rank-one",
            source: "synthetic-fixture",
            a: (0..CELLS)
                .map(|i| ((i / N + 1) * (i % N + 1)) as u32)
                .collect(),
            b: vec![0; CELLS],
        }),
        _ => w1_material::materials(None, None)?
            .into_iter()
            .find(|m| m.name == family)
            .ok_or_else(|| "UNKNOWN_FAMILY".into()),
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct Timing {
    cpu_ns: u64,
    wall_ns: u64,
}
struct Clock {
    cpu: u64,
    wall: Instant,
}
impl Clock {
    fn start() -> Result<Self> {
        Ok(Self {
            cpu: cpu_ns()?,
            wall: Instant::now(),
        })
    }
    fn elapsed(&self) -> Result<Timing> {
        Ok(Timing {
            cpu_ns: cpu_ns()?
                .checked_sub(self.cpu)
                .ok_or("CPU_CLOCK_REVERSED")?,
            wall_ns: self.wall.elapsed().as_nanos().try_into()?,
        })
    }
}
#[cfg(target_os = "linux")]
fn cpu_ns() -> Result<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime))?;
    let seconds = u64::try_from(value.tv_sec)?;
    let nanos = u64::try_from(value.tv_nsec)?;
    if nanos >= 1_000_000_000 {
        return Err("CPU_CLOCK_NANOSECONDS".into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or_else(|| "CPU_CLOCK_OVERFLOW".into())
}
#[cfg(not(target_os = "linux"))]
fn cpu_ns() -> Result<u64> {
    Err("PROCESS_CPU_CLOCK_UNAVAILABLE".into())
}

fn emit(mut row: Value) -> Result<()> {
    row.as_object_mut()
        .ok_or("RECORD_OBJECT")?
        .insert("schema".into(), SCHEMA.into());
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &row)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn matrix_hex(words: &[u32]) -> String {
    hex::encode(
        words
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}

fn diagnostic_header(options: &Options, task: Hash, index: u64) -> Header {
    let context = pon_work::hash(
        b"w1-joint-research-context-v1",
        &[&options.seed.to_le_bytes(), &options.sample.to_le_bytes()],
    );
    Header {
        network: pon_work::hash(b"w1-joint-research-network-v1", &[]),
        parameters: pon_work::hash(b"w1-joint-research-parameters-v1", &[]),
        parent: context,
        height: 1,
        timestamp: 1,
        target: options.target,
        miner: pon_work::hash(b"w1-joint-research-miner-v1", &[&context]),
        transactions: [0; 32],
        state: [0; 32],
        receipts: [0; 32],
        work_task: task,
        nonce: index % options.nonce_space,
    }
}

enum Producer {
    Sequential(PreparedTask),
    Joint(joint::JointPreparedTask),
}
impl Producer {
    fn new(options: &Options, material: &Material) -> Result<Self> {
        Ok(if options.producer == "avx2-joint" {
            Self::Joint(joint::JointPreparedTask::new(&material.a, &material.b)?)
        } else {
            Self::Sequential(
                PreparedTask::new(&material.a, &material.b).map_err(|e| format!("{e:?}"))?,
            )
        })
    }
    fn prove(&self, challenges: &[Hash]) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::Sequential(prepared) => challenges
                .iter()
                .map(|challenge| {
                    prepared
                        .prove(*challenge)
                        .map_err(|e| format!("{e:?}").into())
                })
                .collect(),
            Self::Joint(prepared) => Ok(prepared.prove_batch(challenges)?),
        }
    }
}

#[derive(Default)]
struct Ledger {
    charged: Timing,
    observer: Timing,
    charges: u64,
    batches: u64,
    attempts: u64,
    target_hits: u64,
    unique_opportunities: u64,
    unique_target_hits: u64,
    inclusive_budget_unique_opportunities: u64,
    inclusive_budget_unique_target_hits: u64,
    seen: BTreeSet<Hash>,
}
impl Ledger {
    fn charge(&mut self, stage: &str, batch_index: Option<u64>, duration: Timing) -> Result<()> {
        self.charged.cpu_ns = self
            .charged
            .cpu_ns
            .checked_add(duration.cpu_ns)
            .ok_or("CPU_OVERFLOW")?;
        self.charged.wall_ns = self
            .charged
            .wall_ns
            .checked_add(duration.wall_ns)
            .ok_or("WALL_OVERFLOW")?;
        let seq = self.charges;
        self.charges += 1;
        emit(json!({
            "kind": "charge", "seq": seq, "stage": stage, "batch_index": batch_index,
            "cpu_ns": duration.cpu_ns, "wall_ns": duration.wall_ns,
            "cumulative_charged_cpu_ns": self.charged.cpu_ns,
            "cumulative_charged_wall_ns": self.charged.wall_ns
        }))
    }
    fn inclusive(&self, elapsed: Timing) -> Result<u64> {
        elapsed
            .cpu_ns
            .checked_sub(self.observer.cpu_ns)
            .ok_or_else(|| "OBSERVER_EXCEEDS_ELAPSED".into())
    }
    fn exhausted(&self, epoch: &Clock, budget: Option<u64>) -> Result<bool> {
        Ok(match budget {
            Some(limit) => self.inclusive(epoch.elapsed()?)? >= limit,
            None => false,
        })
    }
}

struct Completion {
    header: Header,
    challenge: Hash,
    proof: Vec<u8>,
    proof_sha256: String,
    trace: Hash,
    ticket: Hash,
    semantic_id: Hash,
    block_id: Hash,
    target_hit: bool,
}
fn generate(
    producer: &Producer,
    options: &Options,
    task: Hash,
    begin: u64,
    count: usize,
) -> Result<Vec<Completion>> {
    let headers: Vec<_> = (begin..begin + count as u64)
        .map(|index| diagnostic_header(options, task, index))
        .collect();
    let challenges: Vec<_> = headers.iter().map(Header::challenge).collect();
    let proofs = producer.prove(&challenges)?;
    if proofs.len() != count {
        return Err("PROOF_COUNT".into());
    }
    headers
        .into_iter()
        .zip(challenges)
        .zip(proofs)
        .map(|((header, challenge), proof)| {
            if proof.len() != PROOF_BYTES {
                return Err("PROOF_LENGTH".into());
            }
            let trace: Hash = proof[PROOF_BYTES - 32..].try_into()?;
            let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
            let semantic_id = pon_work::hash(
                b"w1-cost-game-semantic-ticket-v1",
                &[&task, &challenge, &ticket],
            );
            Ok(Completion {
                block_id: header.block_id(trace),
                header,
                challenge,
                proof_sha256: sha(&proof),
                proof,
                trace,
                ticket,
                semantic_id,
                target_hit: options.target != [0; 32] && ticket <= options.target,
            })
        })
        .collect()
}
fn verify_complete(completion: &Completion, task: Hash) -> Result<()> {
    let production = pon_work::verify(completion.challenge, task, [255; 32], &completion.proof)
        .map_err(|e| format!("PRODUCTION_FULL_VERIFY:{e:?}"))?;
    let reference =
        pon_work::verify_reference(completion.challenge, task, [255; 32], &completion.proof)
            .map_err(|e| format!("REFERENCE_FULL_VERIFY:{e:?}"))?;
    if production.ticket() != completion.ticket
        || reference.ticket() != completion.ticket
        || production.product() != reference.product()
    {
        return Err("VERIFIER_DISAGREEMENT".into());
    }
    Ok(())
}

fn run(epoch: Clock, options: Options) -> Result<()> {
    let mut ledger = Ledger::default();
    emit(json!({
        "kind": "start", "options": options,
        "qualification_level": "relation-only-diagnostic-context", "native_admitted": false,
        "avx2_available": joint::available(), "hardware_attested": false,
        "simd_lanes": if options.producer == "avx2-joint" { joint::SIMD_LANES } else { 1 },
        "clock": "linux-process-cpu-time", "budget_stop": "inclusive-before-prepare-or-batch",
        "completion_policy": "all-active-proofs-return-to-caller-together-before-raw-emission",
        "cold_policy": "actual-prepare-per-batch-not-cache-flush",
        "warm_policy": "one-actual-prepare-per-invocation",
        "accounting_excludes": ["process-startup-before-main-clock", "final-end-row-construction-serialization-and-write", "post-end-options-and-framework-teardown"],
        "observer_exclusion": "both-complete-original-native-verifiers-and-their-local-allocation-destruction",
        "material_setup_policy": "all-fixture-construction-performed-in-this-invocation-is-charged"
    }))?;
    if options.producer == "avx2-joint" && !joint::available() {
        return Err("UNSUPPORTED_AVX2_NO_FALLBACK".into());
    }

    let timer = Clock::start()?;
    let created = material(&options.family);
    let material_duration = timer.elapsed()?;
    ledger.charge("material", None, material_duration)?;
    let material = created?;
    let task = pon_work::task_id(&material.a, &material.b).map_err(|e| format!("{e:?}"))?;
    let material_complete = epoch.elapsed()?;
    emit(json!({
        "kind": "material", "family": material.name, "source": material.source,
        "task": hex::encode(task), "a_hex": matrix_hex(&material.a), "b_hex": matrix_hex(&material.b),
        "setup_complete_elapsed_cpu_ns": material_complete.cpu_ns,
        "setup_complete_inclusive_cpu_ns": ledger.inclusive(material_complete)?,
        "material_cpu_ns": material_duration.cpu_ns, "material_wall_ns": material_duration.wall_ns
    }))?;

    let mut hot = None;
    if options.mode == "hot" && !ledger.exhausted(&epoch, options.cpu_budget_ns)? {
        let timer = Clock::start()?;
        let created = Producer::new(&options, &material);
        ledger.charge("prepare", None, timer.elapsed()?)?;
        hot = Some(created?);
    }
    while ledger.attempts < options.attempts {
        if ledger.exhausted(&epoch, options.cpu_budget_ns)? {
            break;
        }
        let batch = ledger.batches;
        let mut cold = None;
        if options.mode == "cold" {
            let timer = Clock::start()?;
            let created = Producer::new(&options, &material);
            ledger.charge("prepare", Some(batch), timer.elapsed()?)?;
            cold = Some(created?);
            if ledger.exhausted(&epoch, options.cpu_budget_ns)? {
                drop(cold);
                break;
            }
        }
        let producer = hot
            .as_ref()
            .or(cold.as_ref())
            .ok_or("MISSING_PREPARED_PRODUCER")?;
        let count = options
            .width
            .min((options.attempts - ledger.attempts) as usize);
        let begin = ledger.attempts;
        let timer = Clock::start()?;
        let results = generate(producer, &options, task, begin, count);
        // In cold mode the actual cache destructor belongs to this paid batch.
        drop(cold);
        let generation_duration = timer.elapsed()?;
        let complete_elapsed = epoch.elapsed()?;
        let complete_inclusive = ledger.inclusive(complete_elapsed)?;
        let within_budget = options
            .cpu_budget_ns
            .is_none_or(|limit| complete_inclusive <= limit);
        ledger.charge("generate", Some(batch), generation_duration)?;
        let results = results?;
        emit(json!({
            "kind": "batch", "batch_index": batch, "attempt_start": begin,
            "active_lanes": count,
            "padded_lanes": if options.producer == "avx2-joint" { joint::SIMD_LANES - count } else { 0 },
            "completion_elapsed_cpu_ns": complete_elapsed.cpu_ns,
            "completion_elapsed_wall_ns": complete_elapsed.wall_ns,
            "observer_before_cpu_ns": ledger.observer.cpu_ns,
            "inclusive_producer_cpu_ns": complete_inclusive,
            "inclusive_within_cpu_budget": within_budget,
            "cumulative_charged_cpu_ns": ledger.charged.cpu_ns
        }))?;
        for (lane, completion) in results.into_iter().enumerate() {
            let timer = Clock::start()?;
            let verdict = verify_complete(&completion, task);
            let observer = timer.elapsed()?;
            ledger.observer.cpu_ns = ledger
                .observer
                .cpu_ns
                .checked_add(observer.cpu_ns)
                .ok_or("CPU_OVERFLOW")?;
            ledger.observer.wall_ns = ledger
                .observer
                .wall_ns
                .checked_add(observer.wall_ns)
                .ok_or("WALL_OVERFLOW")?;
            verdict?;
            let unique = ledger.seen.insert(completion.semantic_id);
            ledger.attempts += 1;
            ledger.target_hits += u64::from(completion.target_hit);
            ledger.unique_opportunities += u64::from(unique);
            ledger.unique_target_hits += u64::from(unique && completion.target_hit);
            ledger.inclusive_budget_unique_opportunities += u64::from(unique && within_budget);
            ledger.inclusive_budget_unique_target_hits +=
                u64::from(unique && within_budget && completion.target_hit);
            emit(json!({
                "kind": "attempt", "index": begin + lane as u64, "batch_index": batch, "lane": lane,
                "header_hex": hex::encode(completion.header.encode()),
                "challenge": hex::encode(completion.challenge), "task": hex::encode(task),
                "target": hex::encode(options.target), "trace": hex::encode(completion.trace),
                "ticket": hex::encode(completion.ticket), "block_id": hex::encode(completion.block_id),
                "semantic_id": hex::encode(completion.semantic_id),
                "proof_hex": hex::encode(&completion.proof), "proof_sha256": completion.proof_sha256,
                "proof_bytes": completion.proof.len(),
                "target_hit": completion.target_hit, "unique": unique,
                "qualification_level": "relation-valid", "native_admitted": false,
                "production_full_verify": true, "reference_full_verify": true,
                "relation_verification_target": hex::encode([255; 32]),
                "observer_cpu_ns": observer.cpu_ns, "observer_wall_ns": observer.wall_ns,
                "cumulative_observer_cpu_ns": ledger.observer.cpu_ns,
                "completion_elapsed_cpu_ns": complete_elapsed.cpu_ns,
                "inclusive_producer_cpu_ns": complete_inclusive,
                "inclusive_within_cpu_budget": within_budget
            }))?;
        }
        ledger.batches += 1;
    }
    drop(hot);
    drop(material);
    // Dedup bookkeeping is no longer needed. Destruction belongs to the total
    // producer measurement, as do earlier proof-hex conversion and logging.
    ledger.seen.clear();
    let elapsed = epoch.elapsed()?;
    let inclusive = ledger.inclusive(elapsed)?;
    let status = if ledger.attempts == options.attempts {
        "attempt-cap-complete"
    } else {
        "inclusive-cpu-budget-exhausted"
    };
    emit(json!({
        "kind": "end", "status": status, "complete": true,
        "attempts": ledger.attempts, "batches": ledger.batches, "charges": ledger.charges,
        "target_hits": ledger.target_hits, "target_misses": ledger.attempts - ledger.target_hits,
        "unique_opportunities": ledger.unique_opportunities,
        "unique_target_hits": ledger.unique_target_hits,
        "inclusive_budget_unique_opportunities": ledger.inclusive_budget_unique_opportunities,
        "inclusive_budget_unique_target_hits": ledger.inclusive_budget_unique_target_hits,
        "native_admitted": 0, "production_full_verified": ledger.attempts,
        "reference_full_verified": ledger.attempts,
        "charged_core_cpu_ns": ledger.charged.cpu_ns,
        "charged_core_wall_ns": ledger.charged.wall_ns,
        "observer_cpu_ns": ledger.observer.cpu_ns, "observer_wall_ns": ledger.observer.wall_ns,
        "elapsed_cpu_ns": elapsed.cpu_ns, "elapsed_wall_ns": elapsed.wall_ns,
        "inclusive_producer_cpu_ns": inclusive,
        "inclusive_noncore_cpu_ns": inclusive.checked_sub(ledger.charged.cpu_ns).ok_or("CORE_EXCEEDS_INCLUSIVE")?,
        "budget_stop": "inclusive-before-prepare-or-batch",
        "overrun_cost_refunded": false, "cache_and_material_teardown_included": true,
        "final_end_emission_included": false
    }))
}

fn main() {
    let result = (|| {
        let epoch = Clock::start()?;
        if std::env::args().any(|arg| arg == "--help") {
            println!("pon_w1_joint_research --producer avx2-joint|prepared-sequential --family FAMILY --mode hot|cold --attempts 1..4096 --width 1..4 --seed U64 --sample U64 --target HEX64 --cpu-budget-ns U64 --nonce-space 1..4096");
            return Ok(());
        }
        run(epoch, parse_options(std::env::args().skip(1))?)
    })();
    if let Err(error) = result {
        let _ = emit(json!({"kind": "failure", "complete": false, "error": error.to_string()}));
        eprintln!("W1_JOINT_RESEARCH_FAILED: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(args: &[&str]) -> Options {
        parse_options(args.iter().map(|v| (*v).to_owned())).unwrap()
    }
    #[test]
    fn diagnostic_stream_is_identical_across_producer_mode_and_width() {
        let task = [27; 32];
        let mut left = options(&[]);
        let mut right = left.clone();
        right.producer = "prepared-sequential".into();
        right.mode = "cold".into();
        right.width = 1;
        for index in 0..left.attempts {
            assert_eq!(
                diagnostic_header(&left, task, index).encode(),
                diagnostic_header(&right, task, index).encode()
            );
        }
        let old = diagnostic_header(&left, task, 0).challenge();
        left.seed += 1;
        assert_ne!(diagnostic_header(&left, task, 0).challenge(), old);
        left.seed -= 1;
        left.sample += 1;
        assert_ne!(diagnostic_header(&left, task, 0).challenge(), old);
        left.sample -= 1;
        left.target[0] -= 1;
        assert_ne!(diagnostic_header(&left, task, 0).challenge(), old);
    }
    #[test]
    fn duplicate_nonce_has_one_semantic_identity_and_zero_target_has_no_hits() {
        let o = options(&[
            "--producer",
            "prepared-sequential",
            "--family",
            "zero",
            "--nonce-space",
            "1",
            "--target",
            &"00".repeat(32),
        ]);
        let material = material(&o.family).unwrap();
        let task = pon_work::task_id(&material.a, &material.b).unwrap();
        let producer = Producer::new(&o, &material).unwrap();
        let results = generate(&producer, &o, task, 0, 2).unwrap();
        assert_eq!(results[0].semantic_id, results[1].semantic_id);
        assert_eq!(results[0].block_id, results[1].block_id);
        assert!(!results[0].target_hit && !results[1].target_hit);
        verify_complete(&results[0], task).unwrap();
    }
    #[test]
    fn options_reject_unsupported_width_duplicate_flags_and_unbounded_attempts() {
        for args in [
            vec!["--width", "0"],
            vec!["--width", "5"],
            vec!["--attempts", "4097"],
            vec!["--attempts", "0"],
            vec!["--nonce-space", "0"],
            vec!["--producer", "fake-simd"],
            vec!["--family", "invented"],
            vec!["--width", "1", "--width", "2"],
        ] {
            assert!(parse_options(args.into_iter().map(str::to_owned)).is_err());
        }
        assert_eq!(options(&["--cpu-budget-ns", "0"]).cpu_budget_ns, Some(0));
    }
    #[test]
    fn canonical_full_rank_boundary_only() {
        let material = material("near-q-full-rank").unwrap();
        assert_eq!(w1_material::rank(&material.a), N);
        assert_eq!(w1_material::rank(&material.b), N);
        assert!(material
            .a
            .iter()
            .chain(&material.b)
            .all(|v| u128::from(*v) >= Q - 2));
    }
}
