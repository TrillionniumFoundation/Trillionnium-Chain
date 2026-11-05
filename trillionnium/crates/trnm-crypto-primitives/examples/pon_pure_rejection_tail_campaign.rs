//! Finite rejection-tail observations; no worst-case CPU or hardness theorem.
//! Digest byte positions are not internal transcript tiles: PNW1 carries only
//! the final digest, so even a first-byte mismatch follows complete replay.
use sha2::{Digest, Sha256};
use std::{convert::Infallible, error::Error, hint::black_box, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{public_product::PublicProduct, *};
use trnm_protocol::pon_wire::Header;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA: &str = "pon-pure-rejection-tail-campaign-v1";
const ROUNDS: usize = 9;
const PATHS: [&str; 4] = [
    "valid-control-full",
    "mutated-full",
    "filter-only",
    "filter-then-full",
];

fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn array(rows: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", rows.into_iter().collect::<Vec<_>>().join(","))
}
macro_rules! object {
    ($($key:literal => $value:expr),* $(,)?) => {
        format!("{{{}}}", [$(format!("{}:{}", quoted($key), $value)),*].join(","))
    };
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn optional(value: Option<u64>) -> String {
    value.map_or("null".to_owned(), |v| v.to_string())
}

// Diagnostic-only clock, with no new dependency or consensus use. Linux's
// CLOCK_THREAD_CPUTIME_ID is 3; unsupported hosts retain unknown observations.
#[cfg(target_os = "linux")]
fn thread_cpu() -> Option<u64> {
    #[repr(C)]
    struct Timespec {
        seconds: std::ffi::c_long,
        nanos: std::ffi::c_long,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: std::ffi::c_int, value: *mut Timespec) -> std::ffi::c_int;
    }
    let mut value = Timespec {
        seconds: 0,
        nanos: 0,
    };
    // SAFETY: exact Linux timespec ABI, writable initialized storage, no retained
    // pointers. Failure and invalid/overflowing observations remain unknown.
    if unsafe { clock_gettime(3, &mut value) } != 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return None;
    }
    u64::try_from(value.seconds)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(value.nanos).ok()?)
}
#[cfg(not(target_os = "linux"))]
fn thread_cpu() -> Option<u64> {
    None
}

struct Timing {
    wall: u128,
    before: Option<u64>,
    after: Option<u64>,
}
impl Timing {
    fn json(&self) -> String {
        let cpu = self
            .before
            .zip(self.after)
            .and_then(|(a, b)| b.checked_sub(a));
        object! {"wall_ns"=>self.wall, "thread_cpu_ns"=>optional(cpu),
        "thread_cpu_before_ns"=>optional(self.before), "thread_cpu_after_ns"=>optional(self.after),
        "cpu_unknown"=>cpu.is_none()}
    }
}
fn measured<T>(call: impl FnOnce() -> T) -> (T, Timing) {
    let before = thread_cpu();
    let start = Instant::now();
    let value = black_box(call());
    let wall = start.elapsed().as_nanos();
    let after = thread_cpu();
    (
        value,
        Timing {
            wall,
            before,
            after,
        },
    )
}
struct Report {
    written: usize,
}
impl Report {
    fn emit(&mut self, kind: &str, fields: String) -> Result<()> {
        let row = format!(
            "{{\"schema\":{},\"kind\":{},{}\n",
            quoted(SCHEMA),
            quoted(kind),
            &fields[1..]
        );
        if row.len() > 256 * 1024
            || self.written + row.len()
                > 8 * 1024 * 1024 - if kind == "terminal" { 0 } else { 4096 }
        {
            return Err("bounded diagnostic report exceeded".into());
        }
        self.written += row.len();
        let mut output = std::io::stdout().lock();
        output.write_all(row.as_bytes())?;
        output.flush()?;
        Ok(())
    }
}
fn work<T>(result: std::result::Result<T, WorkError>) -> Result<T> {
    result.map_err(|e| format!("W1:{e:?}").into())
}
fn name(error: WorkError) -> &'static str {
    match error {
        WorkError::Length => "Length",
        WorkError::Version => "Version",
        WorkError::Field => "Field",
        WorkError::Task => "Task",
        WorkError::Transcript => "Transcript",
        WorkError::Product => "Product",
        WorkError::Target => "Target",
        WorkError::NoiseBudget => "NoiseBudget",
    }
}
fn full(header: &Header, bytes: &[u8]) -> &'static str {
    match verify(
        black_box(header.challenge()),
        header.work_task,
        header.target,
        black_box(bytes),
    ) {
        Ok(value) => {
            black_box(value.product());
            "Accepted"
        }
        Err(e) => name(e),
    }
}
fn filtered(
    fact: &PublicProduct,
    header: &Header,
    bytes: &[u8],
    continue_full: bool,
) -> &'static str {
    match fact.precheck(
        header.challenge(),
        header.work_task,
        header.target,
        black_box(bytes),
    ) {
        Ok(_) if continue_full => full(header, bytes),
        Ok(true) => "FactMatchOnly",
        Ok(false) => "UnknownFactOnly",
        Err(e) => name(e),
    }
}
fn progress(header: &Header, bytes: &[u8]) -> (String, &'static str) {
    let (mut calls, mut tiles, mut noise, mut rows) = (0, 0, 0, 0);
    let (mut replay, mut product, mut verified) = (false, false, false);
    let mut last = None;
    let result = verify_with_progress(
        header.challenge(),
        header.work_task,
        header.target,
        bytes,
        &mut |point| {
            calls += 1;
            last = Some(point);
            match point {
                VerificationProgress::BeforeReplay => replay = true,
                VerificationProgress::Noise { .. } => noise += 1,
                VerificationProgress::MatrixRow { .. } => rows += 1,
                VerificationProgress::TranscriptTile { .. } => tiles += 1,
                VerificationProgress::BeforeProduct => product = true,
                VerificationProgress::BeforeVerifiedWork => verified = true,
            }
            Ok::<_, Infallible>(())
        },
    );
    let outcome = match result {
        Ok(_) => "Accepted",
        Err(VerificationError::Relation(e)) => name(e),
        Err(VerificationError::Cancelled(impossible)) => match impossible {},
    };
    (
        object! {"calls"=>calls,"transcript_tiles"=>tiles,"noise_calls"=>noise,"matrix_rows"=>rows,
        "before_replay"=>replay,"before_product"=>product,"before_verified_work"=>verified,
        "last_progress"=>last.map_or("null".to_owned(),|p|quoted(&format!("{p:?}"))),
        "result"=>quoted(outcome),"timed_with_samples"=>false},
        outcome,
    )
}
struct Case {
    id: String,
    family: &'static str,
    proof: Vec<u8>,
    expected: WorkError,
    index: Option<usize>,
}
impl Case {
    fn new(
        id: String,
        family: &'static str,
        proof: Vec<u8>,
        expected: WorkError,
        index: Option<usize>,
    ) -> Self {
        Self {
            id,
            family,
            proof,
            expected,
            index,
        }
    }
}
fn change_word(proof: &mut [u8], word: usize, invalid_field: bool) {
    let at = 4 + word * 4;
    let old = u32::from_le_bytes(proof[at..at + 4].try_into().expect("fixed word"));
    let next = if invalid_field {
        Q as u32
    } else {
        ((u128::from(old) + 1) % Q) as u32
    };
    proof[at..at + 4].copy_from_slice(&next.to_le_bytes());
}
fn ticket(header: &Header, proof: &[u8]) -> Hash {
    hash(
        b"ticket",
        &[&header.challenge(), &proof[PROOF_BYTES - 32..]],
    )
}

fn trace_case(
    report: &mut Report,
    header: &Header,
    valid: &[u8],
    index: usize,
    eligible: bool,
) -> Result<Case> {
    let id = format!(
        "trace-byte-{index}-{}",
        if eligible {
            "passing-ticket"
        } else {
            "failing-ticket"
        }
    );
    let (search, total) = measured(|| {
        let mut attempts = Vec::new();
        let mut selected = None;
        for delta in 1u16..=255 {
            let ((proof, claim), cost) = measured(|| {
                let mut proof = valid.to_vec();
                let at = PROOF_BYTES - 32 + index;
                proof[at] = proof[at].wrapping_add(delta as u8);
                let claim = ticket(header, &proof);
                (proof, claim)
            });
            let passes = claim <= header.target;
            attempts.push(object! {"delta"=>delta,"trace"=>quoted(&hex::encode(&proof[PROOF_BYTES-32..])),
                "claimed_ticket"=>quoted(&hex::encode(claim)),"target_passes"=>passes,"timing"=>cost.json()});
            if passes == eligible {
                selected = Some(proof);
                break;
            }
        }
        (attempts, selected)
    });
    let (attempts, selected) = search;
    report.emit(
        "trace_preparation",
        object! {"case"=>quoted(&id),"digest_byte_index"=>index,
        "internal_tile_index"=>"null","target_eligible_required"=>eligible,
        "attempts"=>array(attempts),"total_timing"=>total.json(),"found"=>selected.is_some()},
    )?;
    let proof = selected.ok_or("bounded single-byte trace mutation search exhausted")?;
    Ok(Case::new(
        id,
        if eligible { "false-trace" } else { "target" },
        proof,
        if eligible {
            WorkError::Transcript
        } else {
            WorkError::Target
        },
        Some(index),
    ))
}

fn run(report: &mut Report) -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--header" {
        return Err("requires exact --header PNH1 hex from retained native capture".into());
    }
    let raw = hex::decode(&args[1])?;
    let header = Header::decode(&raw).map_err(|e| format!("header:{e:?}"))?;
    let mut native = [255; 32];
    native[0] = 127;
    if header.target != native {
        return Err("expected the original native development target 7f..ff".into());
    }
    let a: Vec<_> = (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect();
    let b: Vec<_> = (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect();
    if work(task_id(&a, &b))? != header.work_task {
        return Err("header task differs from fixed public maintenance mathematics".into());
    }
    let (prepared, prepare) = measured(|| PreparedTask::new(&a, &b));
    let prepared = work(prepared)?;
    let (valid, acquire) = measured(|| prepared.prove(header.challenge()));
    let valid = work(valid)?;
    if full(&header, &valid) != "Accepted" || ticket(&header, &valid) > header.target {
        return Err("original header did not produce real native-target-winning W1".into());
    }
    let (fact, fact_setup) = measured(|| PublicProduct::new(&a, &b));
    let fact = work(fact)?;
    let (valid_progress, _) = progress(&header, &valid);
    report.emit("begin",object! {"rounds"=>ROUNDS,"seed"=>1,"header_hex"=>quoted(&args[1]),
        "challenge"=>quoted(&hex::encode(header.challenge())),"task"=>quoted(&hex::encode(header.work_task)),
        "native_target"=>quoted(&hex::encode(native)),"valid_proof_hex"=>quoted(&hex::encode(&valid)),
        "valid_proof_sha256"=>quoted(&sha(&valid)),"valid_ticket"=>quoted(&hex::encode(ticket(&header,&valid))),
        "material"=>quoted("exact public maintenance A[i]=(13i+17)%257, B[i]=(29i+31)%263"),
        "prepared_setup"=>prepare.json(),"valid_acquisition"=>acquire.json(),"fact_setup"=>fact_setup.json(),
        "fact_software_bytes"=>fact.software_bytes(),"valid_progress"=>valid_progress,
        "cpu_clock"=>quoted("Linux CLOCK_THREAD_CPUTIME_ID; unsupported/failure/overflow=>null"),
        "cpu_interval"=>quoted("includes surrounding wall timer and CPU clock observation overhead; no subtraction"),
        "warmup"=>quoted("none; every fixed round retained"),"native_admission_attempted"=>false,
        "hardness_proved"=>false,"global_upper_bound_proved"=>false,"production_qualified"=>false})?;
    let mut cases = Vec::new();
    for ordinal in 0..64 {
        let index = ordinal * (CELLS - 1) / 63;
        let mut proof = valid.clone();
        change_word(&mut proof, 2 * CELLS + index, false);
        cases.push(Case::new(
            format!("product-cell-{index}"),
            "wrong-product",
            proof,
            WorkError::Product,
            Some(index),
        ));
    }
    for index in [0, 16, 31] {
        cases.push(trace_case(report, &header, &valid, index, true)?);
    }
    for matrix in 0..3 {
        for index in [0, CELLS / 2, CELLS - 1] {
            let word = matrix * CELLS + index;
            let mut proof = valid.clone();
            change_word(&mut proof, word, true);
            cases.push(Case::new(
                format!("invalid-field-word-{word}"),
                "field",
                proof,
                WorkError::Field,
                Some(word),
            ));
        }
    }
    for len in [0, 3, PROOF_BYTES - 1, PROOF_BYTES + 1] {
        let mut proof = valid.clone();
        proof.resize(len, 0);
        cases.push(Case::new(
            format!("invalid-length-{len}"),
            "length",
            proof,
            WorkError::Length,
            None,
        ));
    }
    let mut proof = valid.clone();
    proof[3] = b'0';
    cases.push(Case::new(
        "invalid-version".into(),
        "version",
        proof,
        WorkError::Version,
        None,
    ));
    let mut proof = valid.clone();
    change_word(&mut proof, 0, false);
    cases.push(Case::new(
        "wrong-task".into(),
        "task",
        proof,
        WorkError::Task,
        Some(0),
    ));
    cases.push(trace_case(report, &header, &valid, 0, false)?);
    if cases.len() != 83 {
        return Err("fixed case coverage differs".into());
    }
    for case in &cases {
        let (observed, outcome) = progress(&header, &case.proof);
        if outcome != name(case.expected) {
            return Err(format!(
                "unexpected observed progress outcome for {}: {outcome}",
                case.id
            )
            .into());
        }
        let encoding = precheck_proof_encoding(&case.proof).map_or_else(name, |_| "EncodingOnly");
        let statement = precheck_proof_statement(
            header.challenge(),
            header.work_task,
            header.target,
            &case.proof,
        )
        .map_or_else(name, |_| "StatementOnly");
        let fact_only = filtered(&fact, &header, &case.proof, false);
        report.emit("case",object! {"case"=>quoted(&case.id),"family"=>quoted(case.family),
            "index"=>case.index.map_or("null".to_owned(),|i|i.to_string()),"proof_length"=>case.proof.len(),
            "proof_sha256"=>quoted(&sha(&case.proof)),"expected_full"=>quoted(name(case.expected)),
            "claimed_ticket"=>if case.proof.len()==PROOF_BYTES {quoted(&hex::encode(ticket(&header,&case.proof)))} else {"null".to_owned()},
            "encoding_stage"=>quoted(encoding),"statement_stage"=>quoted(statement),"filter_only"=>quoted(fact_only),
            "progress"=>observed,"filter_success_is_verified_work"=>false})?;
    }
    let start = Instant::now();
    let mut samples = 0;
    for round in 0..ROUNDS {
        for step in 0..cases.len() {
            let position = (step + round * 13) % cases.len();
            let case = &cases[position];
            let mut rows = Vec::new();
            for order in 0..PATHS.len() {
                let path = (order + round + position) % PATHS.len();
                let (outcome, timing) = measured(|| match path {
                    0 => full(&header, &valid),
                    1 => full(&header, &case.proof),
                    2 => filtered(&fact, &header, &case.proof, false),
                    3 => filtered(&fact, &header, &case.proof, true),
                    _ => unreachable!("fixed paths"),
                });
                let expected = if path == 0 {
                    "Accepted"
                } else if path == 2 && case.family == "false-trace" {
                    "FactMatchOnly"
                } else {
                    name(case.expected)
                };
                rows.push(
                    object! {"path"=>quoted(PATHS[path]),"order"=>order,"outcome"=>quoted(outcome),
                    "expected"=>quoted(expected),"timing"=>timing.json()},
                );
                if outcome != expected {
                    report.emit("failed_sample",object! {"round"=>round,"case"=>quoted(&case.id),"measurements"=>array(rows)})?;
                    return Err("measured path differed from fixed expected result".into());
                }
            }
            report.emit(
                "sample",
                object! {"round"=>round,"step"=>step,"case"=>quoted(&case.id),
                "family"=>quoted(case.family),"measurements"=>array(rows)},
            )?;
            samples += 1;
        }
    }
    report.emit("terminal",object! {"status"=>quoted("complete"),"cases"=>cases.len(),"samples"=>samples,
        "measured_calls"=>samples*PATHS.len(),"sample_campaign_wall_ns"=>start.elapsed().as_nanos(),
        "p99_and_max_scope"=>quoted("finite configured samples only; neither a global worst case nor a hard bound"),
        "global_upper_bound_proved"=>false,"production_qualified"=>false,"hardness_proved"=>false})
}
fn main() {
    let mut report = Report { written: 0 };
    if let Err(error) = run(&mut report) {
        let _=report.emit("terminal",object! {"status"=>quoted("failed"),"reason"=>quoted(&error.to_string()),
            "global_upper_bound_proved"=>false,"production_qualified"=>false,"hardness_proved"=>false});
        eprintln!("rejection-tail campaign failed: {error}");
        std::process::exit(1);
    }
}
