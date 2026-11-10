//! From-scratch false-transcript acquisition and complete native rejection.
//! No honest proof, product computation, preparation cache or winner is acquired.
//! Fixed diagnostic only; external source/binary receipts remain mandatory.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, process::ExitCode, time::Instant};
use trnm_crypto_primitives::pon_work::{
    hash, precheck_proof_statement, task_id, verify, verify_reference,
    verify_reference_with_progress, verify_with_progress, Hash, VerificationError,
    VerificationProgress, VerifiedWork, WorkError, CELLS, N, PROFILE, PROOF_BYTES,
};

const LIMIT: usize = 4096;
const SAMPLES: usize = 8;
const CLASSES: [&str; 4] = ["dense", "zero", "rank-one", "sparse"];
const KERNELS: [&str; 2] = ["production-full-limb", "scalar-reference"];

fn ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).expect("bounded diagnostic duration")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn error_name(error: WorkError) -> &'static str {
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
fn result_name(result: Result<VerifiedWork, WorkError>) -> &'static str {
    match result {
        Ok(_) => "Accepted",
        Err(error) => error_name(error),
    }
}
fn material(class: &str) -> (Vec<u32>, Vec<u32>) {
    let operand = |right: bool| {
        (0..CELLS)
            .map(|i| match class {
                "zero" => 0,
                "sparse" => u32::from(i / N == i % N),
                "rank-one" => ((i / N + if right { 2 } else { 1 }) * (i % N + 1)) as u32,
                "dense" if right => ((i * 7) % 37) as u32,
                "dense" => (i % 31) as u32,
                _ => unreachable!("fixed input class"),
            })
            .collect()
    };
    (operand(false), operand(true))
}
fn challenge_for(class: &str, target: Hash, sample: usize) -> Hash {
    hash(
        b"fresh-rejection-challenge-v1",
        &[class.as_bytes(), &target, &(sample as u64).to_le_bytes()],
    )
}
fn trace_for(challenge: Hash, nonce: usize) -> Hash {
    hash(
        b"fresh-rejection-fake-trace-v1",
        &[&challenge, &(nonce as u64).to_le_bytes()],
    )
}

// Only public canonical inputs and an arbitrary zero product claim are encoded.
// The caller must not replace this with a prefix from a computed/valid witness.
fn zero_claim_prefix(a: &[u32], b: &[u32]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(PROOF_BYTES);
    prefix.extend_from_slice(b"PNW1");
    for value in a.iter().chain(b.iter()) {
        prefix.extend_from_slice(&value.to_le_bytes());
    }
    prefix.resize(PROOF_BYTES - 32, 0);
    prefix
}

struct Search {
    winner: Option<Hash>,
    attempts: Vec<Value>,
    wall_ns: u64,
    trace_ns: u64,
    ticket_ns: u64,
}
fn search(challenge: Hash, target: Hash, limit: usize) -> Search {
    let started = Instant::now();
    let mut attempts = Vec::new();
    let (mut winner, mut trace_ns, mut ticket_ns) = (None, 0, 0);
    for nonce in 0..limit {
        let start = Instant::now();
        let trace = black_box(trace_for(challenge, nonce));
        let candidate_ns = ns(start);
        let start = Instant::now();
        let ticket = black_box(hash(b"ticket", &[&challenge, &trace]));
        let selected = ticket <= target;
        let hash_ns = ns(start);
        trace_ns += candidate_ns;
        ticket_ns += hash_ns;
        // Record allocation and hex serialization stay in the enclosing timer.
        attempts.push(json!({"nonce": nonce, "trace": hex::encode(trace),
            "ticket": hex::encode(ticket), "selected": selected,
            "trace_ns": candidate_ns, "ticket_ns": hash_ns}));
        if selected {
            winner = Some(trace);
            break;
        }
    }
    Search {
        winner,
        attempts,
        wall_ns: ns(started),
        trace_ns,
        ticket_ns,
    }
}

fn progress_probe(kernel: usize, challenge: Hash, task: Hash, target: Hash, proof: &[u8]) -> Value {
    let mut sequence = Vec::new();
    let mut counts = [0usize; 4];
    let (mut replay, mut rows, mut tiles, mut product, mut verified) = (0, 0, 0, 0, 0);
    let mut observe = |point| {
        match point {
            VerificationProgress::BeforeReplay => {
                sequence.push(0);
                replay += 1;
            }
            VerificationProgress::Noise { label, counter } => {
                sequence.extend([1, label]);
                sequence.extend(counter.to_le_bytes());
                counts[usize::from(label)] += 1;
            }
            VerificationProgress::MatrixRow { row } => {
                sequence.push(2);
                sequence.extend((row as u32).to_le_bytes());
                rows += 1;
            }
            VerificationProgress::TranscriptTile { row, column, inner } => {
                sequence.push(3);
                for value in [row, column, inner] {
                    sequence.extend((value as u32).to_le_bytes());
                }
                tiles += 1;
            }
            VerificationProgress::BeforeProduct => {
                sequence.push(4);
                product += 1;
            }
            VerificationProgress::BeforeVerifiedWork => {
                sequence.push(5);
                verified += 1;
            }
        }
        Ok::<(), std::convert::Infallible>(())
    };
    let result = if kernel == 0 {
        verify_with_progress(challenge, task, target, proof, &mut observe)
    } else {
        verify_reference_with_progress(challenge, task, target, proof, &mut observe)
    };
    let result = match result {
        Ok(value) => Ok(value),
        Err(VerificationError::Relation(error)) => Err(error),
        Err(VerificationError::Cancelled(impossible)) => match impossible {},
    };
    json!({"timed": false, "actual_result": result_name(result),
        "sequence_sha256": digest(&sequence), "noise_counts": counts,
        "before_replay": replay, "matrix_rows": rows, "transcript_tiles": tiles,
        "before_product": product, "before_verified_work": verified})
}

fn sample(class: &str, target: Hash, index: usize, limit: usize) -> (Value, bool) {
    let acquisition_start = Instant::now();
    let setup_start = Instant::now();
    let start = Instant::now();
    let (a, b) = material(class);
    let material_ns = ns(start);
    let start = Instant::now();
    let task = task_id(&a, &b).expect("fixed canonical public input");
    let task_ns = ns(start);
    let start = Instant::now();
    let challenge = challenge_for(class, target, index);
    let challenge_ns = ns(start);
    let start = Instant::now();
    let prefix = zero_claim_prefix(&a, &b);
    let prefix_ns = ns(start);
    let setup_ns = ns(setup_start);
    let searched = search(challenge, target, limit);
    let mut encoding_ns = 0;
    let proof = searched.winner.map(|trace| {
        let start = Instant::now();
        let mut proof = prefix.clone();
        proof.extend_from_slice(&trace);
        encoding_ns = ns(start);
        proof
    });
    let acquisition_wall_ns = ns(acquisition_start);
    let accounted_ns = setup_ns + searched.wall_ns + encoding_ns;
    // Identity hashes, receiver work and probes are outside attacker timing.
    let mut precheck = Value::Null;
    let mut measurements = Vec::new();
    let mut expected = false;
    if let Some(bytes) = &proof {
        let start = Instant::now();
        let result = black_box(precheck_proof_statement(challenge, task, target, bytes));
        let precheck_ns = ns(start);
        let result = match result {
            Ok(()) => "FilterPassed",
            Err(error) => error_name(error),
        };
        precheck = json!({"actual_result": result, "elapsed_ns": precheck_ns});
        expected = result == "FilterPassed";
        for position in 0..KERNELS.len() {
            let kernel = (position + index) % KERNELS.len();
            let start = Instant::now();
            let result = black_box(if kernel == 0 {
                verify(challenge, task, target, bytes)
            } else {
                verify_reference(challenge, task, target, bytes)
            });
            let elapsed_ns = ns(start);
            let result = result_name(result);
            expected &= result == "Transcript";
            measurements.push(json!({"position": position, "kernel": KERNELS[kernel],
                "elapsed_ns": elapsed_ns, "actual_result": result}));
        }
        // Run observations after all timed receiver arms, never inside a timer.
        for measurement in &mut measurements {
            let kernel = if measurement["kernel"] == KERNELS[0] {
                0
            } else {
                1
            };
            let probe = progress_probe(kernel, challenge, task, target, bytes);
            expected &= probe["actual_result"] == "Transcript";
            measurement["probe"] = probe;
        }
    }
    (
        json!({"class": class, "sample": index, "target": hex::encode(target),
        "task": hex::encode(task), "challenge": hex::encode(challenge),
        "prefix_sha256": digest(&prefix),
        "setup": {"material_ns": material_ns, "task_ns": task_ns,
            "challenge_ns": challenge_ns, "prefix_ns": prefix_ns, "wall_ns": setup_ns,
            "overhead_ns": setup_ns - material_ns - task_ns - challenge_ns - prefix_ns},
        "search": {"outcome": if proof.is_some() { "ticket-found" } else { "search-exhausted" },
            "attempt_limit": limit, "wall_ns": searched.wall_ns,
            "trace_ns": searched.trace_ns, "ticket_ns": searched.ticket_ns,
            "overhead_ns": searched.wall_ns - searched.trace_ns - searched.ticket_ns,
            "attempts": searched.attempts},
        "proof": proof.as_ref().map(|bytes| json!({"bytes": bytes.len(),
            "sha256": digest(bytes), "encoding_ns": encoding_ns})),
        "acquisition": {"wall_ns": acquisition_wall_ns, "accounted_ns": accounted_ns,
            "overhead_ns": acquisition_wall_ns - accounted_ns},
        "precheck": precheck, "measurements": measurements}),
        expected,
    )
}

fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("fixed from-scratch diagnostic has no argument overrides");
        return ExitCode::from(2);
    }
    let mut samples = Vec::new();
    let mut expected = true;
    for class in CLASSES {
        for top in [127, 7] {
            let mut target = [255; 32];
            target[0] = top;
            for index in 0..SAMPLES {
                let (row, valid) = sample(class, target, index, LIMIT);
                samples.push(row);
                expected &= valid;
            }
        }
    }
    println!(
        "{}",
        json!({"schema": "pon-fresh-rejection-cost-v1", "profile": PROFILE,
        "construction": "public-inputs-zero-product-claim-fake-trace",
        "valid_proof_preacquired": false, "attempt_limit": LIMIT,
        "samples_per_group": SAMPLES, "kernels": KERNELS,
        "metadata": {"arch": std::env::consts::ARCH, "os": std::env::consts::OS,
            "pointer_bits": usize::BITS, "process_id": std::process::id(),
            "debug_assertions": cfg!(debug_assertions),
            "clock": "std::time::Instant-wall-nanoseconds",
            "identity_scope": "external-source-binary-resource-receipt-required"},
        "samples": samples, "hardness_qualified": false,
        "worst_case_rejection_qualified": false, "public_service_measured": false,
        "production_activation": false})
    );
    if expected {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_honest_proof_is_needed_for_same_target_full_rejection() {
        let mut target = [255; 32];
        target[0] = 127;
        for class in CLASSES {
            let (row, expected) = sample(class, target, 0, LIMIT);
            assert!(expected);
            assert_eq!(row["precheck"]["actual_result"], "FilterPassed");
            for measured in row["measurements"].as_array().unwrap() {
                assert_eq!(measured["actual_result"], "Transcript");
                assert_eq!(measured["probe"]["transcript_tiles"], 512);
                assert_eq!(measured["probe"]["before_product"], 0);
                assert_eq!(measured["probe"]["before_verified_work"], 0);
            }
        }
    }
    #[test]
    fn exhausted_search_retains_failed_attempts_and_has_no_receiver_success() {
        // Local branch control, not an admissible campaign target.
        let (row, expected) = sample("zero", [0; 32], 0, 2);
        assert!(!expected);
        assert_eq!(row["search"]["outcome"], "search-exhausted");
        assert_eq!(row["search"]["attempts"].as_array().unwrap().len(), 2);
        assert!(row["proof"].is_null());
        assert!(row["precheck"].is_null());
        assert!(row["measurements"].as_array().unwrap().is_empty());
        assert_eq!(
            row["acquisition"]["accounted_ns"].as_u64().unwrap(),
            row["setup"]["wall_ns"].as_u64().unwrap() + row["search"]["wall_ns"].as_u64().unwrap()
        );
    }
    #[test]
    fn claim_encoding_never_computes_the_dense_product() {
        let (a, b) = material("dense");
        let prefix = zero_claim_prefix(&a, &b);
        assert_eq!(prefix.len(), PROOF_BYTES - 32);
        assert!(prefix[4 + 8 * CELLS..].iter().all(|v| *v == 0));
        assert!(a.iter().any(|v| *v != 0));
        assert!(b.iter().any(|v| *v != 0));
    }
}
