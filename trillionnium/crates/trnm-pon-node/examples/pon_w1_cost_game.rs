//! Finite, fully valid W1 cost games. This example changes no production rule.
//! Charge records cover producer work; independent full verification and actual
//! Node admission are observer intervals, never cheap invalid-proof attacks.
#[path = "support/w1_cost_game_context.rs"]
mod native_context;
#[path = "support/w1_cost_game_producers.rs"]
mod producers;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use native_context::NativeContext;
use producers::{Producer, ARMS};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, hint::black_box, io::Write, thread, time::Instant};
use trnm_crypto_primitives::pon_work::{self, Hash, CELLS, PROOF_BYTES};
use trnm_protocol::pon_wire::Header;
use w1_material::Material;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-valid-cost-game-v1";
const FAMILIES: [&str; 9] = [
    "periodic-dense-fixture",
    "full-rank-field",
    "zero",
    "identity",
    "rank-one",
    "sparse-diagonal",
    "continuity-maintenance-v1",
    "zero-left-rank-one",
    "zero-right-rank-one",
];

#[derive(Clone, Debug, Serialize)]
struct Options {
    samples: u64,
    attempts: u64,
    seed: u64,
    mode: String,
    scope: String,
    families: Vec<String>,
    arms: Vec<usize>,
    training_attempts: u64,
    batch_size: usize,
    cpu_budget_ns: Option<u64>,
    target: Hash,
    nonce_space: u64,
}

fn choices(value: &str, allowed: &[&str]) -> Result<Vec<String>> {
    let values: Vec<_> = if value == "all" {
        allowed.iter().map(|s| (*s).to_owned()).collect()
    } else {
        value.split(',').map(str::to_owned).collect()
    };
    let unique: BTreeSet<_> = values.iter().collect();
    if values.is_empty()
        || unique.len() != values.len()
        || values.iter().any(|s| !allowed.contains(&s.as_str()))
    {
        return Err(format!("UNKNOWN_OR_DUPLICATE_CHOICE:{value}").into());
    }
    Ok(values)
}

fn options() -> Result<Options> {
    let mut o = Options {
        samples: 1,
        attempts: 8,
        seed: 1,
        mode: "hot".into(),
        scope: "relation".into(),
        families: vec![
            "full-rank-field".into(),
            "zero".into(),
            "continuity-maintenance-v1".into(),
        ],
        arms: vec![1, 5, 13],
        training_attempts: 2,
        batch_size: 4,
        cpu_budget_ns: None,
        target: [255; 32],
        nonce_space: 0,
    };
    o.target[0] = 127;
    let mut args = std::env::args().skip(1);
    let mut target_supplied = false;
    let mut families_supplied = false;
    let mut nonce_space_supplied = false;
    while let Some(key) = args.next() {
        if key == "--help" {
            println!("pon_w1_cost_game --samples 1..64 --attempts 1..4096 --seed U64 --mode cold|hot|batch|adaptive --scope relation|maintenance-parent --families all|CSV --arms all|CSV --training-attempts 1..64 --batch-size 1..64 --cpu-budget-ns U64 --target HEX64 --nonce-space 1..4096");
            std::process::exit(0);
        }
        let value = args.next().ok_or_else(|| format!("MISSING_VALUE:{key}"))?;
        match key.as_str() {
            "--samples" => o.samples = value.parse()?,
            "--attempts" => o.attempts = value.parse()?,
            "--seed" => o.seed = value.parse()?,
            "--mode" => o.mode = value,
            "--scope" => o.scope = value,
            "--families" => {
                o.families = choices(&value, &FAMILIES)?;
                families_supplied = true;
            }
            "--arms" => {
                o.arms = choices(&value, &ARMS)?
                    .iter()
                    .map(|s| ARMS.iter().position(|a| a == s).expect("validated arm"))
                    .collect()
            }
            "--training-attempts" => o.training_attempts = value.parse()?,
            "--batch-size" => o.batch_size = value.parse()?,
            "--cpu-budget-ns" => o.cpu_budget_ns = Some(value.parse()?),
            "--target" => {
                o.target = hex::decode(value)?
                    .try_into()
                    .map_err(|_| "TARGET_LENGTH")?;
                target_supplied = true;
            }
            "--nonce-space" => {
                o.nonce_space = value.parse()?;
                nonce_space_supplied = true;
            }
            _ => return Err(format!("UNKNOWN_OPTION:{key}").into()),
        }
    }
    if !(1..=64).contains(&o.samples)
        || !(1..=4096).contains(&o.attempts)
        || !(1..=64).contains(&o.training_attempts)
        || !(1..=64).contains(&o.batch_size)
        || !["cold", "hot", "batch", "adaptive"].contains(&o.mode.as_str())
        || !["relation", "maintenance-parent"].contains(&o.scope.as_str())
    {
        return Err("OPTION_BOUNDS".into());
    }
    if nonce_space_supplied && o.nonce_space == 0 {
        return Err("NONCE_SPACE_BOUNDS".into());
    }
    if o.nonce_space == 0 {
        o.nonce_space = o.attempts.max(o.training_attempts);
    }
    if o.nonce_space > 4096 {
        return Err("NONCE_SPACE_BOUNDS".into());
    }
    if o.scope == "maintenance-parent" {
        if target_supplied {
            return Err("NATIVE_TARGET_MUST_COME_FROM_NODE".into());
        }
        if families_supplied && o.families != ["continuity-maintenance-v1"] {
            return Err("NATIVE_SCOPE_SUPPORTS_ONLY_ORIGINAL_MAINTENANCE".into());
        }
        o.families = vec!["continuity-maintenance-v1".into()];
    }
    Ok(o)
}

#[derive(Clone, Copy, Debug, Serialize)]
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
    fn add(self, other: Self) -> Self {
        Self {
            cpu_ns: self.cpu_ns.and_then(|a| a.checked_add(other.cpu_ns?)),
            wall_ns: self.wall_ns.and_then(|a| a.checked_add(other.wall_ns?)),
        }
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
    fn snapshot(&self) -> Timing {
        Timing {
            wall_ns: u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            cpu_ns: if self.owner == thread::current().id() {
                self.cpu.and_then(|start| cpu()?.checked_sub(start))
            } else {
                None
            },
        }
    }
    fn finish(self) -> Timing {
        self.snapshot()
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
fn emit(mut row: Value) -> Result<()> {
    row.as_object_mut()
        .ok_or("RECORD_OBJECT")?
        .insert("schema".into(), SCHEMA.into());
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &row)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

struct Ledger {
    cohort: String,
    total: Timing,
    observer: Timing,
    limit: Option<u64>,
    seq: u64,
    attempts: u64,
    evaluation_attempts: u64,
    training_attempts: u64,
    wins: u64,
    unique_wins: u64,
    budget_unique_wins: u64,
    evaluation_budget_unique_wins: u64,
    native_admitted: u64,
    seen: BTreeSet<Hash>,
    auxiliary_work: u64,
    inclusive_budget_unique_wins: u64,
    all_work_seen: BTreeSet<Hash>,
    all_work_inclusive_budget_seen: BTreeSet<Hash>,
}
impl Ledger {
    fn new(cohort: String, limit: Option<u64>) -> Self {
        Self {
            cohort,
            total: Timing::zero(),
            observer: Timing::zero(),
            limit,
            seq: 0,
            attempts: 0,
            evaluation_attempts: 0,
            training_attempts: 0,
            wins: 0,
            unique_wins: 0,
            budget_unique_wins: 0,
            evaluation_budget_unique_wins: 0,
            native_admitted: 0,
            seen: BTreeSet::new(),
            auxiliary_work: 0,
            inclusive_budget_unique_wins: 0,
            all_work_seen: BTreeSet::new(),
            all_work_inclusive_budget_seen: BTreeSet::new(),
        }
    }
    fn within(&self) -> Option<bool> {
        match self.limit {
            None => Some(true),
            Some(limit) => self.total.cpu_ns.map(|n| n <= limit),
        }
    }
    fn can_start(&self) -> bool {
        match self.limit {
            None => true,
            Some(limit) => self.total.cpu_ns.is_some_and(|n| n < limit),
        }
    }
    fn charge(
        &mut self,
        stage: &str,
        arm: Option<usize>,
        timing: Timing,
        detail: Value,
    ) -> Result<()> {
        self.total = self.total.add(timing);
        emit(json!({"kind":"charge","cohort":self.cohort,"seq":self.seq,
            "stage":stage,"arm":arm.map(|i| ARMS[i]),"timing":timing,"cumulative":self.total,
            "within_cpu_budget":self.within(),"overrun_cpu_ns":self.limit.and_then(|b| self.total.cpu_ns.map(|n| n.saturating_sub(b))),
            "detail":detail}))?;
        self.seq += 1;
        Ok(())
    }
}

struct RawTrial {
    phase: &'static str,
    ordinal: u64,
    arm: usize,
    nonce: u64,
    challenge: Hash,
    target: Hash,
    trace: Hash,
    ticket: Hash,
    proof: Vec<u8>,
    proof_sha256: String,
    semantic: Hash,
    unique: bool,
    hit: bool,
    header: Option<Header>,
    timing: Timing,
    charged_cpu: Option<u64>,
    inclusive_cpu: Option<u64>,
    inclusive_within: Option<bool>,
    charge_seq: u64,
    within: Option<bool>,
}

fn semantic_id(task: Hash, challenge: Hash, ticket: Hash) -> Hash {
    // Encodings/proof hashes are deliberately absent from the work identity.
    pon_work::hash(
        b"w1-cost-game-semantic-ticket-v1",
        &[&task, &challenge, &ticket],
    )
}

fn target_hit(target: Hash, ticket: Hash) -> bool {
    target != [0; 32] && ticket <= target
}

struct Game<'a> {
    o: &'a Options,
    material: &'a Material,
    sample: u64,
    task: Hash,
    native: Option<NativeContext>,
    ledger: Ledger,
    epoch: Clock,
}
impl Game<'_> {
    fn prepare(&mut self, arm: usize) -> Result<Option<Producer>> {
        let started = Clock::start();
        let prepared = Producer::new(
            arm,
            black_box(&self.material.a),
            black_box(&self.material.b),
        );
        let timing = started.finish();
        self.ledger.charge(
            "prepare",
            Some(arm),
            timing,
            json!({"supported":prepared.as_ref().is_ok_and(Option::is_some)}),
        )?;
        prepared.map_err(|e| format!("PREPARE:{e:?}").into())
    }

    fn generate(
        &mut self,
        producer: &Producer,
        arm: usize,
        phase: &'static str,
        ordinal: u64,
    ) -> Result<RawTrial> {
        let started = Clock::start();
        let logical_nonce = ordinal % self.o.nonce_space;
        let header = self
            .native
            .as_ref()
            .map(|native| native.header(self.o.seed, self.sample, phase, logical_nonce));
        let challenge = header.as_ref().map_or_else(
            || {
                pon_work::hash(
                    b"w1-cost-game-challenge-v1",
                    &[
                        &self.task,
                        &self.o.seed.to_le_bytes(),
                        &self.sample.to_le_bytes(),
                        phase.as_bytes(),
                        &logical_nonce.to_le_bytes(),
                    ],
                )
            },
            Header::challenge,
        );
        let target = header.as_ref().map_or(self.o.target, |h| h.target);
        let nonce = header.as_ref().map_or(logical_nonce, |h| h.nonce);
        let made = producer.prove(black_box(challenge));
        let proof = match made {
            Ok(proof) => proof,
            Err(error) => {
                let timing = started.finish();
                self.ledger.charge(
                    "generate",
                    Some(arm),
                    timing,
                    json!({"phase":phase,"ordinal":ordinal,"error":format!("{error:?}")}),
                )?;
                return Err(format!("GENERATION:{error:?}").into());
            }
        };
        if proof.len() != PROOF_BYTES {
            let timing = started.finish();
            self.ledger.charge("generate", Some(arm), timing,
                json!({"phase":phase,"ordinal":ordinal,"error":"PROOF_LENGTH","actual_bytes":proof.len()}))?;
            return Err("PROOF_LENGTH".into());
        }
        let trace: Hash = proof[PROOF_BYTES - 32..]
            .try_into()
            .expect("complete trace");
        let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
        let hit = target_hit(target, ticket);
        let proof_sha256 = sha(&proof);
        let semantic = semantic_id(self.task, challenge, ticket);
        let unique = self.ledger.seen.insert(semantic);
        let timing = started.finish();
        // Completion fence before this trial's logging or observer replay.
        // Prior bookkeeping, dispatch, construction and logging remain in the
        // inclusive CPU; only already measured full observer calls are removed.
        let inclusive_cpu = self
            .epoch
            .snapshot()
            .cpu_ns
            .and_then(|n| n.checked_sub(self.ledger.observer.cpu_ns?));
        let inclusive_within = match self.o.cpu_budget_ns {
            Some(limit) => inclusive_cpu.map(|n| n <= limit),
            None => Some(true),
        };
        self.ledger.charge(
            "generate",
            Some(arm),
            timing,
            json!({"phase":phase,"ordinal":ordinal}),
        )?;
        Ok(RawTrial {
            phase,
            ordinal,
            arm,
            nonce,
            challenge,
            target,
            trace,
            ticket,
            proof,
            proof_sha256,
            semantic,
            unique,
            hit,
            header,
            timing,
            charged_cpu: self.ledger.total.cpu_ns,
            inclusive_cpu,
            inclusive_within,
            charge_seq: self.ledger.seq - 1,
            within: self.ledger.within(),
        })
    }

    fn observe(&mut self, trial: RawTrial, examples: &mut BTreeSet<String>) -> Result<()> {
        // All complete proofs, including target misses and overrun proofs, are
        // verified by both original independent paths, outside producer costs.
        let started = Clock::start();
        let production = pon_work::verify(trial.challenge, self.task, [255; 32], &trial.proof);
        let production_timing = started.finish();
        let started = Clock::start();
        let reference =
            pon_work::verify_reference(trial.challenge, self.task, [255; 32], &trial.proof);
        let reference_timing = started.finish();
        self.ledger.observer = self
            .ledger
            .observer
            .add(production_timing)
            .add(reference_timing);
        let relation_valid = production
            .as_ref()
            .is_ok_and(|w| w.ticket() == trial.ticket)
            && reference.as_ref().is_ok_and(|w| w.ticket() == trial.ticket)
            && production
                .as_ref()
                .ok()
                .zip(reference.as_ref().ok())
                .is_some_and(|(a, b)| a.product() == b.product());
        let product_sha256 = production.as_ref().ok().map(|w| {
            let bytes: Vec<_> = w.product().iter().flat_map(|v| v.to_le_bytes()).collect();
            sha(&bytes)
        });
        let mut admission = Value::Null;
        let mut admission_timing = Timing::zero();
        if relation_valid && trial.hit {
            if let (Some(native), Some(header)) = (&mut self.native, &trial.header) {
                let started = Clock::start();
                let admitted = native.admit(header.clone(), trial.proof.clone());
                admission_timing = started.finish();
                self.ledger.observer = self.ledger.observer.add(admission_timing);
                admission = match admitted {
                    Ok(value) => value,
                    Err(error) => json!({"admitted":false,"error":error.to_string()}),
                };
            }
        }
        let native_ok = self.native.is_none() || !trial.hit || admission["admitted"] == true;
        let qualification = if admission["admitted"] == true {
            "native-admitted-maintenance"
        } else if self.native.is_some() {
            "parent-eligible-maintenance-relation"
        } else {
            "relation-valid-only"
        };
        let proof_hex =
            if relation_valid && trial.hit && examples.insert(self.material.name.to_owned()) {
                Some(hex::encode(&trial.proof))
            } else {
                None
            };
        self.ledger.attempts += 1;
        if trial.phase == "training" {
            self.ledger.training_attempts += 1;
        } else {
            self.ledger.evaluation_attempts += 1;
        }
        if relation_valid && trial.hit {
            self.ledger.wins += 1;
            if native_ok {
                self.ledger.all_work_seen.insert(trial.semantic);
                if trial.inclusive_within == Some(true) {
                    self.ledger
                        .all_work_inclusive_budget_seen
                        .insert(trial.semantic);
                }
            }
            if trial.unique {
                self.ledger.unique_wins += 1;
                if trial.inclusive_within == Some(true) && native_ok {
                    self.ledger.inclusive_budget_unique_wins += 1;
                }
                if admission["admitted"] == true {
                    self.ledger.native_admitted += 1;
                }
                if trial.within == Some(true) && native_ok {
                    self.ledger.budget_unique_wins += 1;
                    if trial.phase == "evaluation" {
                        self.ledger.evaluation_budget_unique_wins += 1;
                    }
                }
            }
        }
        emit(json!({"kind":"attempt","cohort":self.ledger.cohort,
            "attempt_index":self.ledger.attempts-1,"phase":trial.phase,"ordinal":trial.ordinal,
            "arm":ARMS[trial.arm],"nonce":trial.nonce,"challenge":hex::encode(trial.challenge),
            "task":hex::encode(self.task),"target":hex::encode(trial.target),"trace":hex::encode(trial.trace),
            "ticket":hex::encode(trial.ticket),"proof_sha256":trial.proof_sha256,"proof_bytes":trial.proof.len(),
            "proof_hex":proof_hex,"product_sha256":product_sha256,"target_hit":trial.hit,
            "semantic_id":hex::encode(trial.semantic),"unique_ticket":trial.unique,
            "within_cpu_budget":trial.within,"cumulative_charged_cpu_ns":trial.charged_cpu,
            "inclusive_producer_cpu_ns":trial.inclusive_cpu,
            "inclusive_within_cpu_budget":trial.inclusive_within,
            "charge_seq":trial.charge_seq,"generation_timing":trial.timing,
            "relation_valid":relation_valid,"qualification_level":qualification,
            "production_verifier":{"accepted":production.is_ok(),"timing":production_timing,
                "target_used":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "error":production.err().map(|e| format!("{e:?}"))},
            "reference_verifier":{"accepted":reference.is_ok(),"timing":reference_timing,
                "error":reference.err().map(|e| format!("{e:?}"))},
            "parent":trial.header.as_ref().map(|h| hex::encode(h.parent)),
            "header_hex":trial.header.as_ref().map(|h| hex::encode(h.encode())),
            "block_id":trial.header.as_ref().map(|h| hex::encode(h.block_id(trial.trace))),
            "native_admission":admission,"native_admission_timing":admission_timing}))?;
        if !relation_valid {
            return Err("FULL_RELATION_VERIFICATION_FAILED".into());
        }
        if !native_ok {
            return Err("ORIGINAL_NODE_ADMISSION_FAILED".into());
        }
        Ok(())
    }

    fn evaluate(
        &mut self,
        producer: &Producer,
        arm: usize,
        examples: &mut BTreeSet<String>,
    ) -> Result<()> {
        if !self.ledger.can_start() {
            return Ok(());
        }
        if self.o.mode != "batch" {
            for ordinal in 0..self.o.attempts {
                if !self.ledger.can_start() {
                    break;
                }
                let trial = self.generate(producer, arm, "evaluation", ordinal)?;
                self.observe(trial, examples)?;
            }
            return Ok(());
        }
        // Actual bounded queue: generate a batch of distinct complete proofs
        // before observer replays. This is sequential batching, not SIMD/GPU.
        let started = Clock::start();
        let mut pending = Vec::with_capacity(self.o.batch_size);
        let timing = started.finish();
        self.ledger.charge(
            "batch-buffer",
            Some(arm),
            timing,
            json!({"capacity":self.o.batch_size}),
        )?;
        for ordinal in 0..self.o.attempts {
            if !self.ledger.can_start() {
                break;
            }
            pending.push(self.generate(producer, arm, "evaluation", ordinal)?);
            if pending.len() == self.o.batch_size {
                for trial in pending.drain(..) {
                    self.observe(trial, examples)?;
                }
            }
        }
        for trial in pending {
            self.observe(trial, examples)?;
        }
        Ok(())
    }

    fn adaptive(&mut self, examples: &mut BTreeSet<String>) -> Result<Option<usize>> {
        let mut candidates = Vec::new();
        for offset in 0..self.o.arms.len() {
            if !self.ledger.can_start() {
                break;
            }
            let arm = self.o.arms[(offset + self.sample as usize) % self.o.arms.len()];
            let Some(producer) = self.prepare(arm)? else {
                continue;
            };
            let mut timing = Timing::zero();
            let mut count = 0u64;
            for ordinal in 0..self.o.training_attempts {
                if !self.ledger.can_start() {
                    break;
                }
                let trial = self.generate(&producer, arm, "training", ordinal)?;
                timing = timing.add(trial.timing);
                count += 1;
                self.observe(trial, examples)?;
            }
            if count == self.o.training_attempts {
                candidates.push((arm, producer, timing, count));
            }
        }
        if !self.ledger.can_start() || candidates.is_empty() {
            return Ok(None);
        }
        let started = Clock::start();
        let selected = candidates
            .iter()
            .enumerate()
            .filter_map(|(i, (arm, _, timing, count))| {
                timing.cpu_ns.map(|cpu| (i, cpu / count, *arm))
            })
            .min_by_key(|(_, mean, arm)| (*mean, *arm))
            .map(|v| v.0);
        let timing = started.finish();
        self.ledger.charge(
            "select",
            None,
            timing,
            json!({"policy":"minimum-measured-training-generation-cpu-mean; arm-order-tie-break"}),
        )?;
        let Some(selected) = selected else {
            return Err("ADAPTIVE_CPU_CLOCK_UNAVAILABLE".into());
        };
        let scores: Vec<_> = candidates
            .iter()
            .map(|(arm, _, timing, count)| {
                json!({"arm":ARMS[*arm],
            "training_attempts":count,"training_generation_timing":timing,
            "training_mean_cpu_ns":timing.cpu_ns.map(|n| n / count)})
            })
            .collect();
        let (arm, producer, _, _) = candidates.swap_remove(selected);
        emit(
            json!({"kind":"selection","cohort":self.ledger.cohort,"selected_arm":ARMS[arm],
            "scores":scores,"policy_frozen_before_evaluation":true,"training_stream_disjoint":true,
            "training_and_all_candidate_preparation_charged":true,"training_unique_wins_counted":true}),
        )?;
        if self.ledger.can_start() {
            self.evaluate(&producer, arm, examples)?;
        }
        Ok(Some(arm))
    }
}

fn materials() -> Result<Vec<Material>> {
    let mut cases = w1_material::materials(None, None)?;
    let rank_one = cases
        .iter()
        .find(|m| m.name == "rank-one")
        .expect("rank-one fixture");
    let a = rank_one.a.clone();
    let b = rank_one.b.clone();
    cases.push(Material {
        name: "zero-left-rank-one",
        source: "synthetic-fixture",
        a: vec![0; CELLS],
        b,
    });
    cases.push(Material {
        name: "zero-right-rank-one",
        source: "synthetic-fixture",
        a,
        b: vec![0; CELLS],
    });
    Ok(cases)
}

fn run_cohort(
    o: &Options,
    material: &Material,
    task: Hash,
    sample: u64,
    arm: Option<usize>,
    examples: &mut BTreeSet<String>,
) -> Result<()> {
    let label = arm.map_or("adaptive-dispatcher", |i| ARMS[i]);
    let cohort = format!(
        "{}/{}/{}/{}/{}",
        o.scope, material.name, o.mode, label, sample
    );
    let elapsed = Clock::start();
    let mut game = Game {
        o,
        material,
        sample,
        task,
        native: None,
        ledger: Ledger::new(cohort.clone(), o.cpu_budget_ns),
        epoch: elapsed,
    };
    emit(
        json!({"kind":"cohort-start","cohort":cohort,"family":material.name,"sample":sample,
        "mode":o.mode,"scope":o.scope,"arm":label,"task":hex::encode(task),
        "cpu_budget_ns":o.cpu_budget_ns,"attempt_cap":o.attempts,
        "qualification_level":if o.scope == "relation" {"relation-only-public-input"} else {"pending-original-parent-acquisition"},
        "semantic_dedup_scope":"one-cohort; alternatives are counterfactual and must not be aggregated",
        "cold_definition":"actual-prepare-before-every-evaluation-attempt",
        "hot_definition":"one-actual-prepare-reused-for-observed-attempts"}),
    )?;
    if o.scope == "maintenance-parent" && game.ledger.can_start() {
        let started = Clock::start();
        let native = NativeContext::new(sample, || {
            game.epoch
                .snapshot()
                .cpu_ns
                .and_then(|n| n.checked_sub(game.ledger.observer.cpu_ns?))
        });
        let timing = started.finish();
        let native = match native {
            Ok(native) => native,
            Err(error) => {
                game.ledger
                    .charge("context", None, timing, json!({"error":error.to_string()}))?;
                return Err(error);
            }
        };
        if native.task() != task {
            return Err("NATIVE_MATERIAL_TASK_MISMATCH".into());
        }
        game.ledger
            .charge("context", None, timing, native.receipt.clone())?;
        for work in &native.auxiliary {
            game.ledger.auxiliary_work += 1;
            game.ledger.all_work_seen.insert(work.semantic);
            let within = match o.cpu_budget_ns {
                Some(limit) => work.completion_cpu_ns.is_some_and(|n| n <= limit),
                None => true,
            };
            if within {
                game.ledger
                    .all_work_inclusive_budget_seen
                    .insert(work.semantic);
            }
        }
        game.native = Some(native);
    }
    let mut selected = arm;
    let mut unsupported = false;
    if o.mode == "adaptive" {
        selected = game.adaptive(examples)?;
    } else if game.ledger.can_start() {
        let arm = arm.ok_or("MISSING_FIXED_ARM")?;
        if o.mode == "cold" {
            for ordinal in 0..o.attempts {
                if !game.ledger.can_start() {
                    break;
                }
                let Some(producer) = game.prepare(arm)? else {
                    unsupported = true;
                    break;
                };
                if !game.ledger.can_start() {
                    break;
                }
                let trial = game.generate(&producer, arm, "evaluation", ordinal)?;
                game.observe(trial, examples)?;
            }
        } else if let Some(producer) = game.prepare(arm)? {
            game.evaluate(&producer, arm, examples)?;
        } else {
            unsupported = true;
        }
    }
    let elapsed = game.epoch.snapshot();
    let inclusive = Timing {
        cpu_ns: elapsed
            .cpu_ns
            .and_then(|n| n.checked_sub(game.ledger.observer.cpu_ns?)),
        wall_ns: elapsed
            .wall_ns
            .and_then(|n| n.checked_sub(game.ledger.observer.wall_ns?)),
    };
    let remaining = Timing {
        cpu_ns: elapsed.cpu_ns.and_then(|n| {
            n.checked_sub(game.ledger.total.cpu_ns?)
                .and_then(|n| n.checked_sub(game.ledger.observer.cpu_ns?))
        }),
        wall_ns: elapsed.wall_ns.and_then(|n| {
            n.checked_sub(game.ledger.total.wall_ns?)
                .and_then(|n| n.checked_sub(game.ledger.observer.wall_ns?))
        }),
    };
    emit(
        json!({"kind":"cohort-end","cohort":cohort,"selected_arm":selected.map(|i| ARMS[i]),
        "status":if unsupported {"unsupported"} else if !game.ledger.can_start() {"core-cpu-budget-stopped"} else if selected.is_none() {"no-supported-candidate"} else {"attempt-cap-complete"},
        "charge_records":game.ledger.seq,"charged":game.ledger.total,"observer_verification_and_admission":game.ledger.observer,
        "cohort_elapsed":elapsed,"observer_logging_and_unattributed_overhead":remaining,
        "inclusive_producer_timing":inclusive,
        "inclusive_budget_excludes_global_public_material_construction":true,
        "attempts":game.ledger.attempts,"evaluation_attempts":game.ledger.evaluation_attempts,
        "training_attempts":game.ledger.training_attempts,"target_hits":game.ledger.wins,
        "target_misses":game.ledger.attempts-game.ledger.wins,
        "unique_target_hits":game.ledger.unique_wins,"budget_unique_target_hits":game.ledger.budget_unique_wins,
        "evaluation_budget_unique_target_hits":game.ledger.evaluation_budget_unique_wins,
        "inclusive_budget_unique_target_hits":game.ledger.inclusive_budget_unique_wins,
        "unique_native_admitted":game.ledger.native_admitted,
        "auxiliary_original_node_work":game.ledger.auxiliary_work,
        "all_work_target_hits":game.ledger.auxiliary_work+game.ledger.wins,
        "all_work_unique_target_hits":game.ledger.all_work_seen.len(),
        "all_work_inclusive_budget_unique_target_hits":game.ledger.all_work_inclusive_budget_seen.len(),
        "all_work_is_distinct_candidates_not_additive_chainweight":true,
        "cpu_budget_ns":o.cpu_budget_ns,"overrun_cpu_ns":o.cpu_budget_ns.and_then(|b| game.ledger.total.cpu_ns.map(|n| n.saturating_sub(b))),
        "zero_wins_retained":true,"successful_work_lower_bound_claimed":false,"production_activation":false}),
    )
}

fn main() -> Result<()> {
    let o = options()?;
    if o.cpu_budget_ns.is_some() && cpu().is_none() {
        return Err("CPU_BUDGET_REQUIRES_ACTUAL_THREAD_CPU_CLOCK".into());
    }
    emit(
        json!({"kind":"campaign","options":o,"arm_names":o.arms.iter().map(|i| ARMS[*i]).collect::<Vec<_>>(),
        "profile":pon_work::PROFILE,"proof_bytes":PROOF_BYTES,"clock":"Linux calling-thread CPU; monotonic wall separately",
        "budget_semantics":"main loop stops on core-stage CPU sum; separate inclusive completion fence subtracts only full observer calls from cohort CPU; proof finishing after the applicable B has no corresponding in-budget credit; no refund",
        "charged_generation_includes":"challenge, complete proof, ticket predicate, proof SHA256 and semantic dedup",
        "observer_excluded":"both complete verifiers, native admission, JSONL and explicit uncharged overhead",
        "batch_semantics":"bounded sequential complete-proof queue; no SIMD or parallel speedup claimed",
        "material_is_public_input":true,"energy_and_hardware_cost_measured":false,
        "invalid_rejection_paths_used":false,"hardness_accepted":false,"production_activation":false}),
    )?;
    let started = Clock::start();
    let cases = materials()?;
    let material_timing = started.finish();
    emit(
        json!({"kind":"material-construction","timing":material_timing,
        "charged_per_producer":false,"reason":"same public diagnostic operands; no prepared product or proof supplied to producers"}),
    )?;
    let mut examples = BTreeSet::new();
    let mut cohorts = 0u64;
    for material in cases
        .iter()
        .filter(|m| o.families.iter().any(|f| f == m.name))
    {
        let task =
            pon_work::task_id(&material.a, &material.b).map_err(|e| format!("TASK:{e:?}"))?;
        let a: Vec<_> = material.a.iter().flat_map(|v| v.to_le_bytes()).collect();
        let b: Vec<_> = material.b.iter().flat_map(|v| v.to_le_bytes()).collect();
        emit(
            json!({"kind":"material","family":material.name,"source":material.source,
            "task":hex::encode(task),"a_hex":hex::encode(&a),"b_hex":hex::encode(&b),
            "a_sha256":sha(&a),"b_sha256":sha(&b),"a_rank":w1_material::rank(&material.a),"b_rank":w1_material::rank(&material.b),
            "parent_eligibility_claimed":false}),
        )?;
        for sample in 0..o.samples {
            if o.mode == "adaptive" {
                run_cohort(&o, material, task, sample, None, &mut examples)?;
                cohorts += 1;
            } else {
                for offset in 0..o.arms.len() {
                    let arm = o.arms[(offset + sample as usize) % o.arms.len()];
                    run_cohort(&o, material, task, sample, Some(arm), &mut examples)?;
                    cohorts += 1;
                }
            }
        }
    }
    emit(
        json!({"kind":"end","cohorts":cohorts,"complete":true,"hardness_accepted":false,"production_activation":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semantic_work_does_not_depend_on_serialized_proof_or_encoding_hash() {
        let task = [1; 32];
        let challenge = [2; 32];
        let ticket = [3; 32];
        let mut seen = BTreeSet::new();
        assert!(seen.insert(semantic_id(task, challenge, ticket)));
        assert!(!seen.insert(semantic_id(task, challenge, ticket)));
        assert!(seen.insert(semantic_id(task, [4; 32], ticket)));
        assert!(seen.insert(semantic_id([4; 32], challenge, ticket)));
    }
    #[test]
    fn budget_completion_fence_is_inclusive_and_never_refunds_overrun() {
        let mut ledger = Ledger::new("test".into(), Some(10));
        ledger.total.cpu_ns = Some(10);
        assert_eq!(ledger.within(), Some(true));
        assert!(!ledger.can_start());
        ledger.total.cpu_ns = Some(11);
        assert_eq!(ledger.within(), Some(false));
        assert!(!ledger.can_start());
        ledger.total.cpu_ns = None;
        assert_eq!(ledger.within(), None);
        assert!(!ledger.can_start());
    }
    #[test]
    fn zero_target_is_rejected_even_for_an_all_zero_ticket() {
        assert!(!target_hit([0; 32], [0; 32]));
        let mut one = [0; 32];
        one[31] = 1;
        assert!(target_hit(one, one));
        assert!(!target_hit(one, [255; 32]));
    }
}
