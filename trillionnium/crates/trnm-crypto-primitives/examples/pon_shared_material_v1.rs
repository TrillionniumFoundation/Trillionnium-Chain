//! Fixed-material offline W1 experiment and typed product handoff.
//!
//! The caller supplies exactly one canonical A/B pair. One real preparation is
//! reused across every requested challenge search. This has its own evidence
//! namespace and does not alter the historical V3 grid or any consensus rule.
//! Full native AND scalar-reference verification precede every product handoff.
//! No input provenance, node service, physical recovery or useful demand follows.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    hint::black_box,
    io::{self, Read, Write},
    thread,
    time::Instant,
};
use trnm_crypto_primitives::pon_work::{
    self,
    arithmetic_facts::{ArithmeticFactCache, ArithmeticObservation},
    legal_attempt::{Arithmetic, Materialization, Task},
    Hash, VerifiedWork, WorkError, CELLS, PROFILE, PROOF_BYTES,
};

const SCHEMA: &str = "pon-shared-material-v1";
const INPUT_BYTES: usize = 2 * CELLS * 4;
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const CHALLENGE_DOMAIN: &[u8] = b"pon-shared-material-challenge-v1";
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Options {
    target_index: usize,
    seed: Hash,
    max_attempts: u64,
    cycles: u64,
    arithmetic: Arithmetic,
    attack_controls: bool,
}
impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut args = args.into_iter();
        if args.next().as_deref() != Some("--shared-material-v1") {
            return Err("SHARED_MATERIAL_SELECTOR".into());
        }
        let mut options = Self {
            target_index: 0,
            seed: [0; 32],
            max_attempts: 4096,
            cycles: 1,
            arithmetic: Arithmetic::FullLimb,
            attack_controls: false,
        };
        let mut seen = [false; 6];
        while let Some(flag) = args.next() {
            let index = match flag.as_str() {
                "--target-index" => 0,
                "--seed" => 1,
                "--max-attempts" => 2,
                "--cycles" => 3,
                "--arithmetic" => 4,
                "--attack-controls" => 5,
                _ => return Err("SHARED_MATERIAL_OPTION".into()),
            };
            if std::mem::replace(&mut seen[index], true) {
                return Err("SHARED_MATERIAL_DUPLICATE_OPTION".into());
            }
            if index == 5 {
                options.attack_controls = true;
                continue;
            }
            let value = args.next().ok_or("SHARED_MATERIAL_OPTION_VALUE")?;
            match index {
                0 => {
                    options.target_index = match value.as_str() {
                        "0" => 0,
                        "1" => 1,
                        _ => return Err("SHARED_MATERIAL_TARGET".into()),
                    };
                }
                1 => {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err("SHARED_MATERIAL_SEED".into());
                    }
                    hex::decode_to_slice(value, &mut options.seed)
                        .map_err(|_| "SHARED_MATERIAL_SEED")?;
                }
                2 | 3 => {
                    let number = value.parse::<u64>().map_err(|_| "SHARED_MATERIAL_COUNT")?;
                    if value != number.to_string()
                        || number == 0
                        || number > if index == 2 { 4096 } else { 64 }
                    {
                        return Err("SHARED_MATERIAL_COUNT".into());
                    }
                    if index == 2 {
                        options.max_attempts = number;
                    } else {
                        options.cycles = number;
                    }
                }
                4 => {
                    options.arithmetic = match value.as_str() {
                        "full-limb" => Arithmetic::FullLimb,
                        "transposed" => Arithmetic::Transposed,
                        _ => return Err("SHARED_MATERIAL_ARITHMETIC".into()),
                    };
                }
                _ => unreachable!("fixed option"),
            }
        }
        if !seen[0] || !seen[1] {
            return Err("SHARED_MATERIAL_EXPLICIT_TARGET_AND_SEED".into());
        }
        Ok(options)
    }
    fn target(&self) -> Hash {
        let mut target = [255; 32];
        target[0] = [127, 7][self.target_index];
        target
    }
    fn arithmetic_name(&self) -> &'static str {
        match self.arithmetic {
            Arithmetic::FullLimb => "full-limb",
            Arithmetic::Transposed => "transposed",
        }
    }
}

// Same safe clock semantics as the existing Node cost examples. Unsupported or
// failed CPU observations stay null, never fabricated from wall time or ticks.
#[cfg(target_os = "linux")]
fn cpu_ns() -> Option<u64> {
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
    fn finish(self) -> Timing {
        Timing {
            wall_ns: u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            cpu_ns: if self.owner == thread::current().id() {
                self.cpu.and_then(|start| cpu_ns()?.checked_sub(start))
            } else {
                None
            },
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct Timing {
    wall_ns: Option<u64>,
    cpu_ns: Option<u64>,
}
impl Timing {
    fn value(self) -> Value {
        json!({"wall_ns":self.wall_ns,"cpu_ns":self.cpu_ns})
    }
    fn known(self) -> bool {
        self.wall_ns.is_some() && self.cpu_ns.is_some()
    }
}
impl Default for Timing {
    fn default() -> Self {
        Self {
            wall_ns: Some(0),
            cpu_ns: Some(0),
        }
    }
}
fn add(total: &mut Timing, value: Timing) {
    total.wall_ns = total
        .wall_ns
        .and_then(|old| old.checked_add(value.wall_ns?));
    total.cpu_ns = total.cpu_ns.and_then(|old| old.checked_add(value.cpu_ns?));
}
fn retain_unknown_time(
    incomplete: &mut Vec<String>,
    label: impl FnOnce() -> String,
    value: Timing,
) {
    if !value.known() {
        incomplete.push(label());
    }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn raw(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn decode(bytes: &[u8]) -> Result<(Vec<u32>, Vec<u32>)> {
    if bytes.len() != INPUT_BYTES {
        return Err("SHARED_MATERIAL_EXACT_INPUT_BYTES".into());
    }
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("four-byte word")))
        .collect();
    let (a, b) = words.split_at(CELLS);
    pon_work::task_id(a, b).map_err(|e| format!("SHARED_MATERIAL_CANONICAL:{e:?}"))?;
    Ok((a.to_vec(), b.to_vec()))
}
fn challenge(task: Hash, options: &Options, cycle: u64, nonce: u64) -> Hash {
    // Arithmetic and reuse length are deliberately absent from this identity.
    pon_work::hash(
        CHALLENGE_DOMAIN,
        &[
            &task,
            &options.target(),
            &options.seed,
            &cycle.to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

struct Emitter<W> {
    output: W,
    rows: u64,
    bytes: u64,
    record_build: Timing,
    serialization_output: Timing,
}
impl<W: Write> Emitter<W> {
    fn new(output: W) -> Self {
        Self {
            output,
            rows: 0,
            bytes: 0,
            record_build: Timing::default(),
            serialization_output: Timing::default(),
        }
    }
    fn emit(&mut self, kind: &str, build: impl FnOnce() -> Value) -> Result<()> {
        let started = Clock::start();
        let mut row = build();
        let object = row.as_object_mut().ok_or("SHARED_MATERIAL_RECORD")?;
        object.insert("schema".into(), SCHEMA.into());
        object.insert("kind".into(), kind.into());
        let timing = started.finish();
        add(&mut self.record_build, timing);
        object.insert("record_build_timing".into(), timing.value());
        let started = Clock::start();
        let bytes = serde_json::to_vec(&row).map_err(|e| format!("SHARED_MATERIAL_JSON:{e}"))?;
        if bytes.len() > MAX_LINE_BYTES {
            return Err("SHARED_MATERIAL_RECORD_LIMIT".into());
        }
        self.output
            .write_all(&bytes)
            .and_then(|()| self.output.write_all(b"\n"))
            .and_then(|()| self.output.flush())
            .map_err(|e| format!("SHARED_MATERIAL_OUTPUT:{e}"))?;
        add(&mut self.serialization_output, started.finish());
        self.rows += 1;
        self.bytes += bytes.len() as u64 + 1;
        Ok(())
    }
}

struct Trial {
    nonce: u64,
    challenge: Hash,
    trace: Option<Hash>,
    ticket: Option<Hash>,
    hit: bool,
    materialized: bool,
    timing: Timing,
    error: Option<String>,
}
impl Trial {
    fn value(&self) -> Value {
        json!({"nonce":self.nonce,"challenge":hex::encode(self.challenge),
            "trace":self.trace.map(hex::encode),"ticket":self.ticket.map(hex::encode),
            "target_hit":self.hit,"proof_materialized":self.materialized,"timing":self.timing.value(),
            "error":self.error})
    }
}
struct Winner {
    challenge: Hash,
    ticket: Hash,
    proof: Vec<u8>,
}
struct Search {
    trials: Vec<Trial>,
    winner: Option<Winner>,
    timing: Timing,
    error: Option<String>,
}
fn search(producer: &Task, task: Hash, options: &Options, cycle: u64) -> Search {
    let started = Clock::start();
    let mut result = Search {
        trials: Vec::new(),
        winner: None,
        timing: Timing::default(),
        error: None,
    };
    for nonce in 0..options.max_attempts {
        let attempt_started = Clock::start();
        let context = challenge(task, options, cycle, nonce);
        let attempt =
            black_box(producer.attempt(context, options.target(), Materialization::TargetHit));
        let timing = attempt_started.finish();
        match attempt {
            Ok(attempt) => {
                result.trials.push(Trial {
                    nonce,
                    challenge: context,
                    trace: Some(attempt.trace),
                    ticket: Some(attempt.ticket),
                    hit: attempt.target_hit,
                    materialized: attempt.proof.is_some(),
                    timing,
                    error: None,
                });
                if attempt.challenge != context
                    || attempt.target_hit != (attempt.ticket <= options.target())
                    || attempt.proof.is_some() != attempt.target_hit
                    || attempt
                        .proof
                        .as_ref()
                        .is_some_and(|p| p.len() != PROOF_BYTES)
                {
                    result.error = Some("SHARED_MATERIAL_ATTEMPT_IDENTITY".into());
                    break;
                }
                if let Some(proof) = attempt.proof {
                    result.winner = Some(Winner {
                        challenge: context,
                        ticket: attempt.ticket,
                        proof,
                    });
                    break;
                }
            }
            Err(error) => {
                // Retain the failed attempt and its clock even though no trace or
                // ticket exists. The surrounding search remains unsuccessful.
                result.trials.push(Trial {
                    nonce,
                    challenge: context,
                    trace: None,
                    ticket: None,
                    hit: false,
                    materialized: false,
                    timing,
                    error: Some(format!("{error:?}")),
                });
                result.error = Some(format!("SHARED_MATERIAL_ATTEMPT:{nonce}:{error:?}"));
                break;
            }
        }
    }
    result.timing = started.finish();
    result
}

fn outcome(result: &std::result::Result<VerifiedWork, WorkError>) -> String {
    match result {
        Ok(_) => "Accepted".into(),
        Err(error) => format!("{error:?}"),
    }
}
fn typed_match(work: &VerifiedWork, winner: &Winner, task: Hash) -> bool {
    work.challenge() == winner.challenge
        && work.task() == task
        && work.ticket() == winner.ticket
        && work.product().len() == CELLS
}

#[derive(Default)]
struct Summary {
    searches: u64,
    attempts: u64,
    winners: u64,
    exhausted: u64,
    failed: u64,
    control_campaigns: u64,
    controls_failed: u64,
    measurement_incomplete: Vec<String>,
    producer: Timing,
    native_verifier: Timing,
    reference_verifier: Timing,
    typed_copy: Timing,
}

fn run<W: Write>(options: &Options, input: impl Read, emitter: &mut Emitter<W>) -> Result<Summary> {
    let input_started = Clock::start();
    let mut bytes = Vec::new();
    input
        .take(INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("SHARED_MATERIAL_INPUT:{e}"))?;
    let (a, b) = decode(&bytes)?;
    let task = pon_work::task_id(&a, &b).map_err(|e| format!("SHARED_MATERIAL_TASK:{e:?}"))?;
    let input_timing = input_started.finish();
    emitter.emit("material", || json!({"profile":PROFILE,"matrix_width":pon_work::N,
        "field_modulus":pon_work::Q as u64,"input_bytes":bytes.len(),"input_hex":hex::encode(&bytes),
        "input_sha256":sha(&bytes),"matrix_a_sha256":sha(&bytes[..CELLS*4]),
        "matrix_b_sha256":sha(&bytes[CELLS*4..]),"task":hex::encode(task),
        "target":hex::encode(options.target()),"target_index":options.target_index,
        "seed":hex::encode(options.seed),"challenge_domain":String::from_utf8_lossy(CHALLENGE_DOMAIN),
        "arithmetic":options.arithmetic_name(),"materialization":"target-hit",
        "cycles":options.cycles,"max_attempts":options.max_attempts,"attack_controls":options.attack_controls,
        "input_timing":input_timing.value(),"input_provenance_verified":false,
        "scope":"offline complete W1; no task eligibility, native service or useful demand",
        "timing_scope":"search includes challenge, all complete attempts and binary trial retention; hex/JSON/output separately observed; outer process costs require caller supervisor",
        "max_line_bytes":MAX_LINE_BYTES}))?;
    let setup_started = Clock::start();
    let producer = Task::new(&a, &b, options.arithmetic);
    let setup = setup_started.finish();
    emitter.emit("setup", || {
        json!({"task":hex::encode(task),"arithmetic":options.arithmetic_name(),
        "calls":1,"reuse_searches":options.cycles,"timing":setup.value(),
        "outcome":match &producer { Ok(_) => "Prepared".into(), Err(e) => format!("{e:?}") }})
    })?;
    let producer = producer.map_err(|e| format!("SHARED_MATERIAL_SETUP:{e:?}"))?;
    let mut summary = Summary::default();
    retain_unknown_time(
        &mut summary.measurement_incomplete,
        || "input".into(),
        input_timing,
    );
    retain_unknown_time(
        &mut summary.measurement_incomplete,
        || "setup".into(),
        setup,
    );
    add(&mut summary.producer, setup);
    for cycle in 0..options.cycles {
        let searched = search(&producer, task, options, cycle);
        summary.searches += 1;
        summary.attempts += searched.trials.len() as u64;
        add(&mut summary.producer, searched.timing);
        retain_unknown_time(
            &mut summary.measurement_incomplete,
            || format!("search[{cycle}]"),
            searched.timing,
        );
        for trial in &searched.trials {
            retain_unknown_time(
                &mut summary.measurement_incomplete,
                || format!("search[{cycle}].attempt[{}]", trial.nonce),
                trial.timing,
            );
        }
        emitter.emit("search", || json!({"cycle":cycle,"task":hex::encode(task),
            "target":hex::encode(options.target()),"arithmetic":options.arithmetic_name(),
            "setup_calls":0,"timing":searched.timing.value(),"error":searched.error,
            "status":if searched.error.is_some(){"failed"}else if searched.winner.is_some(){"target-hit-unverified"}else{"exhausted"},
            "attempts":searched.trials.iter().map(Trial::value).collect::<Vec<_>>()}))?;
        // Controls have their own attempts and denominator; a legal search that
        // exhausts never silently removes a planned adversarial observation.
        if options.attack_controls {
            summary.control_campaigns += 1;
            summary.controls_failed += attack_controls(
                &a,
                &b,
                task,
                options,
                cycle,
                emitter,
                &mut summary.measurement_incomplete,
            )?;
        }
        if searched.error.is_some() {
            summary.failed += 1;
            continue;
        }
        let Some(winner) = searched.winner else {
            summary.exhausted += 1;
            continue;
        };
        emitter.emit("candidate", || {
            json!({"cycle":cycle,"challenge":hex::encode(winner.challenge),
            "task":hex::encode(task),"target":hex::encode(options.target()),
            "ticket":hex::encode(winner.ticket),"proof_sha256":sha(&winner.proof),
            "proof_hex":hex::encode(&winner.proof),"verified":false})
        })?;
        let started = Clock::start();
        let native = black_box(pon_work::verify(
            winner.challenge,
            task,
            options.target(),
            &winner.proof,
        ));
        let native_timing = started.finish();
        let started = Clock::start();
        let reference = black_box(pon_work::verify_reference(
            winner.challenge,
            task,
            options.target(),
            &winner.proof,
        ));
        let reference_timing = started.finish();
        add(&mut summary.native_verifier, native_timing);
        add(&mut summary.reference_verifier, reference_timing);
        retain_unknown_time(
            &mut summary.measurement_incomplete,
            || format!("native_verifier[{cycle}]"),
            native_timing,
        );
        retain_unknown_time(
            &mut summary.measurement_incomplete,
            || format!("reference_verifier[{cycle}]"),
            reference_timing,
        );
        let verified = match (&native, &reference) {
            (Ok(a), Ok(b)) => {
                typed_match(a, &winner, task)
                    && typed_match(b, &winner, task)
                    && a.product() == b.product()
            }
            _ => false,
        };
        emitter.emit("verification", || {
            json!({"cycle":cycle,"proof_sha256":sha(&winner.proof),
            "native":{"outcome":outcome(&native),"timing":native_timing.value()},
            "scalar_reference":{"outcome":outcome(&reference),"timing":reference_timing.value()},
            "typed_products_equal":verified})
        })?;
        if !verified {
            summary.failed += 1;
            continue;
        }
        let native = native.map_err(|e| format!("SHARED_MATERIAL_VERIFIER:{e:?}"))?;
        let started = Clock::start();
        // This is the only output handoff. Never decode C from unverified bytes.
        let product = raw(native.product());
        let copy_timing = started.finish();
        add(&mut summary.typed_copy, copy_timing);
        retain_unknown_time(
            &mut summary.measurement_incomplete,
            || format!("typed_copy[{cycle}]"),
            copy_timing,
        );
        summary.winners += 1;
        emitter.emit("winner", || {
            json!({"cycle":cycle,"challenge":hex::encode(native.challenge()),
            "task":hex::encode(native.task()),"target":hex::encode(options.target()),
            "ticket":hex::encode(native.ticket()),"proof_sha256":sha(&winner.proof),
            "proof_hex":hex::encode(&winner.proof),"product_sha256":sha(&product),
            "product_hex":hex::encode(&product),"product_source":"VerifiedWork.product",
            "scalar_reference_equal":true,"typed_copy_timing":copy_timing.value()})
        })?;
    }
    Ok(summary)
}

fn arithmetic_observation(value: &ArithmeticObservation) -> Value {
    json!({"lookup_probes":value.lookup_probes,"lookup_contended":value.lookup_contended,
        "exact_fact_found":value.exact_fact_found,"trace_reused":value.trace_reused,
        "product_reused":value.product_reused,"transcript_entered":value.transcript_entered,
        "transcript_completed":value.transcript_completed,"product_entered":value.product_entered,
        "product_completed":value.product_completed,"publication_probes":value.publication_probes,
        "publication":format!("{:?}",value.publication)})
}

// Explicitly selected, finite arithmetic-cache controls. The forged prefix is
// built directly from public A/B with zero C; no valid proof is acquired for it.
// Owner recreation below is volatile state loss, not a node/service restart.
fn attack_controls<W: Write>(
    a: &[u32],
    b: &[u32],
    task: Hash,
    options: &Options,
    cycle: u64,
    emitter: &mut Emitter<W>,
    measurement_incomplete: &mut Vec<String>,
) -> Result<u64> {
    let started = Clock::start();
    if pon_work::task_id(a, b).map_err(|e| format!("SHARED_MATERIAL_ATTACK_INPUT:{e:?}"))? != task {
        return Err("SHARED_MATERIAL_ATTACK_TASK".into());
    }
    let mut prefix = b"PNW1".to_vec();
    prefix.extend_from_slice(&raw(a));
    prefix.extend_from_slice(&raw(b));
    prefix.resize(PROOF_BYTES, 0);
    let setup = started.finish();
    retain_unknown_time(
        measurement_incomplete,
        || format!("attack[{cycle}].setup"),
        setup,
    );
    emitter.emit("attack_setup", || json!({"cycle":cycle,"task":hex::encode(task),
        "setup_calls":1,"reuse_searches":2,"timing":setup.value(),"valid_proof_acquired":false,
        "scope":"attacker-only constructor uses public A/B, zero C and no legal producer or proof input"}))?;
    let mut candidates = Vec::new();
    let mut failures = 0;
    for index in 0u64..2 {
        let context = challenge(task, options, cycle, index);
        let started = Clock::start();
        let mut trials = Vec::new();
        let mut winner = None;
        for nonce in 0..options.max_attempts {
            let attempt_started = Clock::start();
            let trace = pon_work::hash(
                b"pon-shared-material-false-trace-v1",
                &[&context, &nonce.to_le_bytes()],
            );
            let ticket = pon_work::hash(b"ticket", &[&context, &trace]);
            let hit = ticket <= options.target();
            if hit {
                let mut proof = prefix.clone();
                proof[PROOF_BYTES - 32..].copy_from_slice(&trace);
                winner = Some(Winner {
                    challenge: context,
                    ticket,
                    proof,
                });
            }
            trials.push(Trial {
                nonce,
                challenge: context,
                trace: Some(trace),
                ticket: Some(ticket),
                hit,
                materialized: hit,
                timing: attempt_started.finish(),
                error: None,
            });
            if hit {
                break;
            }
        }
        let timing = started.finish();
        retain_unknown_time(
            measurement_incomplete,
            || format!("attack[{cycle}].search[{index}]"),
            timing,
        );
        for trial in &trials {
            retain_unknown_time(
                measurement_incomplete,
                || format!("attack[{cycle}].search[{index}].attempt[{}]", trial.nonce),
                trial.timing,
            );
        }
        emitter.emit("attack_search", || json!({"cycle":cycle,"attack_index":index,
            "task":hex::encode(task),"target":hex::encode(options.target()),"timing":timing.value(),
            "status":if winner.is_some(){"target-hit-unverified"}else{"exhausted"},
            "attempts":trials.iter().map(Trial::value).collect::<Vec<_>>(),
            "candidate":winner.as_ref().map(|w|json!({"challenge":hex::encode(w.challenge),
                "ticket":hex::encode(w.ticket),"proof_sha256":sha(&w.proof),"proof_hex":hex::encode(&w.proof)}))}))?;
        if let Some(winner) = winner {
            candidates.push((index, winner));
        } else {
            failures += 1;
        }
    }
    for (index, candidate) in &candidates {
        for path in ["native", "scalar-reference"] {
            let started = Clock::start();
            let result = black_box(if path == "native" {
                pon_work::verify(
                    candidate.challenge,
                    task,
                    options.target(),
                    &candidate.proof,
                )
            } else {
                pon_work::verify_reference(
                    candidate.challenge,
                    task,
                    options.target(),
                    &candidate.proof,
                )
            });
            let timing = started.finish();
            retain_unknown_time(
                measurement_incomplete,
                || format!("attack[{cycle}].search[{index}].{path}"),
                timing,
            );
            let matches = matches!(result, Err(WorkError::Transcript));
            if !matches {
                failures += 1;
            }
            emitter.emit("attack_native_verifier", || json!({"cycle":cycle,"attack_index":index,
                "path":path,"challenge":hex::encode(candidate.challenge),"task":hex::encode(task),
                "target":hex::encode(options.target()),"proof_sha256":sha(&candidate.proof),
                "outcome":outcome(&result),"timing":timing.value(),"expected_refusal_observed":matches,
                "unexpected_product_sha256":result.as_ref().ok().map(|work|sha(&raw(work.product())))}))?;
        }
    }
    if candidates.len() != 2 {
        emitter.emit("attack_cache_unavailable", || json!({"cycle":cycle,
            "reason":"two independently searched target-hit candidates required for the declared churn sequence",
            "candidate_indices":candidates.iter().map(|(index,_)|*index).collect::<Vec<_>>()}))?;
        return Ok(failures);
    }
    let started = Clock::start();
    let mut cache = ArithmeticFactCache::new(1).map_err(str::to_owned)?;
    let cache_setup = started.finish();
    retain_unknown_time(
        measurement_incomplete,
        || format!("attack[{cycle}].cache_setup"),
        cache_setup,
    );
    emitter.emit("attack_cache_setup", || {
        json!({"cycle":cycle,"capacity":cache.capacity(),
        "software_bytes":cache.software_bytes(),"timing":cache_setup.value()})
    })?;
    for (label, index, warm) in [
        ("cold", 0, false),
        ("warm", 0, true),
        ("churn-other", 1, false),
        ("after-churn", 0, false),
        ("after-owner-recreation", 0, false),
    ] {
        if label == "after-owner-recreation" {
            let started = Clock::start();
            drop(cache);
            cache = ArithmeticFactCache::new(1).map_err(str::to_owned)?;
            let timing = started.finish();
            retain_unknown_time(
                measurement_incomplete,
                || format!("attack[{cycle}].cache_reset"),
                timing,
            );
            emitter.emit("attack_cache_reset", || json!({"cycle":cycle,"timing":timing.value(),
                "scope":"in-process volatile owner destruction/recreation; no node or durable recovery"}))?;
        }
        let candidate = &candidates[index].1;
        let mut observation = ArithmeticObservation::default();
        let started = Clock::start();
        let result = black_box(cache.verify_with_observation(
            candidate.challenge,
            task,
            options.target(),
            &candidate.proof,
            &mut |_| Ok::<_, std::convert::Infallible>(()),
            &mut observation,
        ));
        let timing = started.finish();
        retain_unknown_time(
            measurement_incomplete,
            || format!("attack[{cycle}].cache.{label}"),
            timing,
        );
        let outcome = match result {
            Err(pon_work::facts::FactError::Relation(error)) => format!("{error:?}"),
            Err(error) => format!("{error:?}"),
            Ok(_) => "AcceptedUnexpectedly".into(),
        };
        let matches = outcome == "Transcript"
            && observation.exact_fact_found == warm
            && observation.trace_reused == warm
            && observation.transcript_completed != warm;
        if !matches {
            failures += 1;
        }
        emitter.emit("attack_cache_verifier", || json!({"cycle":cycle,"path":label,
            "challenge":hex::encode(candidate.challenge),"task":hex::encode(task),
            "target":hex::encode(options.target()),"proof_sha256":sha(&candidate.proof),
            "outcome":outcome,"timing":timing.value(),"observation":arithmetic_observation(&observation),
            "expected_path_observed":matches}))?;
    }
    Ok(failures)
}

fn execute<W: Write>(args: impl IntoIterator<Item = String>, input: impl Read, output: W) -> i32 {
    let started = Clock::start();
    let mut emitter = Emitter::new(output);
    let result = Options::parse(args)
        .and_then(|options| run(&options, input, &mut emitter).map(|r| (options, r)));
    let run_timing = started.finish();
    let build = emitter.record_build;
    let output = emitter.serialization_output;
    let rows = emitter.rows;
    let bytes = emitter.bytes;
    let (status, result) = match result {
        Ok((options, mut summary)) => {
            retain_unknown_time(
                &mut summary.measurement_incomplete,
                || "run_through_before_summary".into(),
                run_timing,
            );
            retain_unknown_time(
                &mut summary.measurement_incomplete,
                || "record_build_subtotal".into(),
                build,
            );
            retain_unknown_time(
                &mut summary.measurement_incomplete,
                || "serialization_output_subtotal".into(),
                output,
            );
            let complete = summary.winners == options.cycles
                && summary.failed == 0
                && summary.exhausted == 0
                && summary.controls_failed == 0
                && summary.measurement_incomplete.is_empty()
                && summary.producer.known()
                && summary.native_verifier.known()
                && summary.reference_verifier.known()
                && summary.typed_copy.known()
                && run_timing.known();
            (
                if complete { 0 } else { 2 },
                json!({
                "status":if complete{"complete"}else{"failed"},"requested_cycles":options.cycles,
                "searches":summary.searches,"attempts":summary.attempts,"winners":summary.winners,
                "exhausted":summary.exhausted,"failed_searches":summary.failed,"control_failures":summary.controls_failed,
                "requested_control_campaigns":if options.attack_controls{options.cycles}else{0},
                "control_campaigns":summary.control_campaigns,
                "measurement_incomplete":summary.measurement_incomplete,
                "producer_subtotal":summary.producer.value(),"native_verifier_subtotal":summary.native_verifier.value(),
                "reference_verifier_subtotal":summary.reference_verifier.value(),"typed_copy_subtotal":summary.typed_copy.value(),
                "run_through_before_summary":run_timing.value(),"record_build_subtotal":build.value(),
                "serialization_output_subtotal":output.value(),"rows_before_summary":rows,"bytes_before_summary":bytes,
                "source_hardware_verified":false,"cheapest_work_qualified":false,"public_service_measured":false,
                "model_utility_qualified":false,"production_activation":false,
                "scope":"finite offline observation; run total overlaps subtotals and excludes final summary/exit; physical process resources require external supervisor"}),
            )
        }
        Err(error) => (
            2,
            json!({"status":"failed","error":error,
            "run_through_before_summary":run_timing.value(),"rows_before_summary":rows,"bytes_before_summary":bytes,
            "source_hardware_verified":false,"cheapest_work_qualified":false,"public_service_measured":false,
            "model_utility_qualified":false,"production_activation":false}),
        ),
    };
    if let Err(error) = emitter.emit("summary", || result) {
        eprintln!("{error}");
        return 2;
    }
    status
}

fn main() {
    std::process::exit(execute(
        std::env::args().skip(1),
        io::stdin().lock(),
        io::stdout().lock(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        vec![
            "--shared-material-v1".into(),
            "--target-index".into(),
            "0".into(),
            "--seed".into(),
            "07".repeat(32),
        ]
    }
    #[test]
    fn explicit_canonical_controls_are_bounded() {
        assert!(Options::parse(args()).is_ok());
        for extension in [
            vec!["--cycles", "0"],
            vec!["--cycles", "65"],
            vec!["--cycles", "01"],
            vec!["--max-attempts", "4097"],
            vec!["--seed", "00"],
            vec!["--target-index", "1"],
        ] {
            let mut values = args();
            values.extend(extension.into_iter().map(str::to_owned));
            assert!(Options::parse(values).is_err());
        }
        let mut values = args();
        values[4] = "FF".repeat(32);
        assert!(Options::parse(values).is_err());
        assert!(Options::parse(["--shared-material-v1".into()]).is_err());
    }
    #[test]
    fn raw_material_is_exact_and_is_never_reduced() {
        assert!(decode(&vec![0; INPUT_BYTES]).is_ok());
        assert!(decode(&vec![0; INPUT_BYTES - 1]).is_err());
        assert!(decode(&vec![0; INPUT_BYTES + 1]).is_err());
        let mut bytes = vec![0; INPUT_BYTES];
        bytes[..4].copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
        assert!(decode(&bytes).is_err());
    }
    #[test]
    fn matched_challenges_bind_task_target_seed_cycle_nonce_but_not_arm_or_reuse() {
        let original = Options::parse(args()).unwrap();
        let task = [4; 32];
        let expected = challenge(task, &original, 0, 0);
        let mut arm = original.clone();
        arm.arithmetic = Arithmetic::Transposed;
        arm.cycles = 64;
        assert_eq!(expected, challenge(task, &arm, 0, 0));
        arm.target_index = 1;
        assert_ne!(expected, challenge(task, &arm, 0, 0));
        arm = original.clone();
        arm.seed[0] ^= 1;
        assert_ne!(expected, challenge(task, &arm, 0, 0));
        assert_ne!(expected, challenge([5; 32], &original, 0, 0));
        assert_ne!(expected, challenge(task, &original, 1, 0));
        assert_ne!(expected, challenge(task, &original, 0, 1));
    }
    #[test]
    fn native_and_reference_handoff_reuses_one_setup_and_keeps_all_attempts() {
        let mut values = args();
        values.extend(["--cycles".into(), "2".into()]);
        let bytes = vec![0; INPUT_BYTES];
        let mut output = Vec::new();
        let code = execute(values, bytes.as_slice(), &mut output);
        #[cfg(target_os = "linux")]
        assert_eq!(code, 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(code, 2);
        let rows: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(rows.iter().filter(|r| r["kind"] == "setup").count(), 1);
        assert_eq!(rows.iter().filter(|r| r["kind"] == "winner").count(), 2);
        for row in rows.iter().filter(|r| r["kind"] == "search") {
            let trials = row["attempts"].as_array().unwrap();
            assert!(!trials.is_empty());
            for (index, trial) in trials.iter().enumerate() {
                assert_eq!(trial["nonce"], index);
                assert_eq!(trial["target_hit"], index + 1 == trials.len());
                assert_eq!(trial["proof_materialized"], index + 1 == trials.len());
            }
        }
        for row in rows.iter().filter(|r| r["kind"] == "winner") {
            assert_eq!(row["product_hex"], "00".repeat(CELLS * 4));
            assert_eq!(row["product_source"], "VerifiedWork.product");
            assert_eq!(row["scalar_reference_equal"], true);
        }
    }
    #[test]
    fn malformed_material_has_failed_summary_and_no_winner() {
        let mut output = Vec::new();
        assert_eq!(execute(args(), &[0u8; 5][..], &mut output), 2);
        let rows: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["status"], "failed");
        assert_eq!(rows[0]["error"], "SHARED_MATERIAL_EXACT_INPUT_BYTES");
    }
    #[test]
    fn forged_same_material_keeps_cold_warm_churn_and_owner_loss_distinct() {
        let options = Options::parse(args()).unwrap();
        let a = vec![0; CELLS];
        let b = vec![0; CELLS];
        let task = pon_work::task_id(&a, &b).unwrap();
        let mut output = Vec::new();
        let mut emitter = Emitter::new(&mut output);
        let mut measurement_incomplete = Vec::new();
        assert_eq!(
            attack_controls(
                &a,
                &b,
                task,
                &options,
                0,
                &mut emitter,
                &mut measurement_incomplete
            )
            .unwrap(),
            0
        );
        #[cfg(target_os = "linux")]
        assert!(measurement_incomplete.is_empty());
        #[cfg(not(target_os = "linux"))]
        assert!(!measurement_incomplete.is_empty());
        let rows: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let checks: Vec<_> = rows
            .iter()
            .filter(|r| r["kind"] == "attack_cache_verifier")
            .collect();
        assert_eq!(checks.len(), 5);
        for row in checks {
            assert_eq!(row["outcome"], "Transcript");
            assert_eq!(row["expected_path_observed"], true);
        }
        assert!(!rows.iter().any(|r| r["kind"] == "winner"));
    }
}
