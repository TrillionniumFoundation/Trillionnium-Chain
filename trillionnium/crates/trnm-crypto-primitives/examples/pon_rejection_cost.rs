//! Same-target late rejection measurements with explicit acquisition and reuse costs.
//! This diagnostic does not qualify worst-case cost, hardness or a default kernel change.
use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};
use trnm_crypto_primitives::pon_work::*;

const LIMIT: usize = 4096;
const SAMPLES: usize = 9;
const KERNELS: [&str; 3] = [
    "production-transposed",
    "scalar-reference",
    "limb-transcript",
];
const VARIANTS: [&str; 3] = ["legal", "transcript", "product-last-cell"];

// Only diagnostic serialization. None of these labels is a wire error code.
fn quoted(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
    output
}
fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}
macro_rules! object {
    ($($key:literal => $value:expr),* $(,)?) => {
        format!("{{{}}}", [$(format!("{}:{}", quoted($key), $value)),*].join(","))
    };
}
fn sha256(bytes: &[u8]) -> String {
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
fn actual_result(result: Result<VerifiedWork, WorkError>) -> (&'static str, Option<String>) {
    match result {
        Ok(work) => {
            let bytes: Vec<_> = work
                .product()
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            ("Accepted", Some(sha256(&bytes)))
        }
        Err(error) => (error_name(error), None),
    }
}
fn verifier(
    kernel: usize,
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: &[u8],
) -> Result<VerifiedWork, WorkError> {
    match kernel {
        0 => verify(challenge, task, target, proof),
        1 => verify_reference(challenge, task, target, proof),
        2 => verify_limb(challenge, task, target, proof),
        _ => unreachable!("fixed verifier kernel"),
    }
}

#[derive(Clone)]
struct Attempt {
    nonce: usize,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
    proof_sha256: String,
    selected: bool,
    challenge_ns: u128,
    proof_construction_ns: u128,
    ticket_ns: u128,
}
impl Attempt {
    fn json(&self) -> String {
        object! {
            "nonce" => self.nonce,
            "challenge" => quoted(&hex::encode(self.challenge)),
            "trace" => quoted(&hex::encode(self.trace)),
            "ticket" => quoted(&hex::encode(self.ticket)),
            "proof_sha256" => quoted(&self.proof_sha256),
            "selected" => self.selected,
            "challenge_ns" => self.challenge_ns,
            "proof_construction_ns" => self.proof_construction_ns,
            "ticket_ns" => self.ticket_ns,
        }
    }
}
struct Search {
    attempts: Vec<Attempt>,
    prefix: Vec<u8>,
    winner: Option<(Hash, Vec<u8>)>,
    wall_ns: u128,
}
impl Search {
    fn json(&self, limit: usize) -> String {
        let challenge_ns: u128 = self.attempts.iter().map(|a| a.challenge_ns).sum();
        let proof_ns: u128 = self.attempts.iter().map(|a| a.proof_construction_ns).sum();
        let ticket_ns: u128 = self.attempts.iter().map(|a| a.ticket_ns).sum();
        object! {
            "outcome" => quoted(if self.winner.is_some() { "winner" } else { "exhausted" }),
            "attempt_limit" => limit,
            "wall_ns" => self.wall_ns,
            "challenge_ns" => challenge_ns,
            "proof_construction_ns" => proof_ns,
            "ticket_ns" => ticket_ns,
            "diagnostic_overhead_ns" => self.wall_ns - challenge_ns - proof_ns - ticket_ns,
            "attempts" => array(self.attempts.iter().map(Attempt::json)),
        }
    }
}

fn search(
    prepared: &PreparedTask,
    class: &str,
    target: Hash,
    sample: usize,
    limit: usize,
) -> Search {
    let started = Instant::now();
    let mut attempts = Vec::new();
    let mut prefix = Vec::new();
    let mut winner = None;
    for nonce in 0..limit {
        let start = Instant::now();
        let challenge = hash(
            b"rejection-cost-challenge-v1",
            &[
                class.as_bytes(),
                &target,
                &(sample as u64).to_le_bytes(),
                &(nonce as u64).to_le_bytes(),
            ],
        );
        let challenge_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        let proof = black_box(prepared.prove(challenge).expect("valid fixed task"));
        let proof_construction_ns = start.elapsed().as_nanos();
        let trace: Hash = proof[PROOF_BYTES - 32..].try_into().unwrap();
        let start = Instant::now();
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        let selected = ticket <= target;
        let ticket_ns = start.elapsed().as_nanos();
        if prefix.is_empty() {
            prefix.extend_from_slice(&proof[..PROOF_BYTES - 32]);
        }
        assert_eq!(
            prefix,
            proof[..PROOF_BYTES - 32],
            "fixed task product/prefix"
        );
        // These audit hashes and retained records are outside the phase timers.
        // Their cost remains charged in the enclosing search wall measurement.
        attempts.push(Attempt {
            nonce,
            challenge,
            trace,
            ticket,
            proof_sha256: sha256(&proof),
            selected,
            challenge_ns,
            proof_construction_ns,
            ticket_ns,
        });
        if selected {
            winner = Some((challenge, proof));
            break;
        }
    }
    Search {
        attempts,
        prefix,
        winner,
        wall_ns: started.elapsed().as_nanos(),
    }
}

#[derive(Clone)]
struct FakeAttempt {
    nonce: usize,
    trace: Hash,
    ticket: Hash,
    selected: bool,
    candidate_ns: u128,
    ticket_ns: u128,
}
impl FakeAttempt {
    fn json(&self) -> String {
        object! {
            "nonce" => self.nonce,
            "trace" => quoted(&hex::encode(self.trace)),
            "ticket" => quoted(&hex::encode(self.ticket)),
            "selected" => self.selected,
            "candidate_ns" => self.candidate_ns,
            "ticket_ns" => self.ticket_ns,
        }
    }
}
struct Mutation {
    id: &'static str,
    proof: Option<Vec<u8>>,
    clone_ns: u128,
    mutation_ns: u128,
    ticket_search_wall_ns: u128,
    construction_ns: u128,
    attempts: Vec<FakeAttempt>,
    product_cell: Option<(u32, u32)>,
}
impl Mutation {
    fn json(&self, source_proof: &[u8], challenge: Hash) -> String {
        let candidate_ns: u128 = self.attempts.iter().map(|a| a.candidate_ns).sum();
        let ticket_ns: u128 = self.attempts.iter().map(|a| a.ticket_ns).sum();
        object! {
            "id" => quoted(self.id),
            "outcome" => quoted(if self.proof.is_some() { "ready" } else { "search-exhausted" }),
            "source_proof_sha256" => quoted(&sha256(source_proof)),
            "proof_sha256" => self.proof.as_ref().map_or("null".into(), |p| quoted(&sha256(p))),
            "trace" => self.proof.as_ref().map_or("null".into(), |p| quoted(&hex::encode(&p[PROOF_BYTES - 32..]))),
            "ticket" => self.proof.as_ref().map_or("null".into(), |p| quoted(&hex::encode(hash(b"ticket", &[&challenge, &p[PROOF_BYTES - 32..]])))),
            "clone_ns" => self.clone_ns,
            "mutation_ns" => self.mutation_ns,
            "ticket_search_wall_ns" => self.ticket_search_wall_ns,
            "ticket_candidate_ns" => candidate_ns,
            "ticket_hash_ns" => ticket_ns,
            "ticket_recording_overhead_ns" => self.ticket_search_wall_ns - candidate_ns - ticket_ns,
            "construction_ns" => self.construction_ns,
            "construction_overhead_ns" => self.construction_ns - self.clone_ns - self.mutation_ns - self.ticket_search_wall_ns,
            "ticket_origin" => quoted(if self.id == "transcript" { "new-fake-trace-search" } else { "honest-winner" }),
            "ticket_attempts" => array(self.attempts.iter().map(FakeAttempt::json)),
            "product_cell" => self.product_cell.map_or("null".into(), |(before, after)| object! {
                "index" => CELLS - 1, "before" => before, "after" => after,
            }),
        }
    }
}
fn changed_cell(value: u32) -> u32 {
    assert!(u128::from(value) < Q);
    if u128::from(value) == Q - 1 {
        0
    } else {
        value + 1
    }
}
fn product_mutation(proof: &[u8]) -> Mutation {
    let started = Instant::now();
    let start = Instant::now();
    let mut changed = proof.to_vec();
    let clone_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let offset = PROOF_BYTES - 36;
    let before = u32::from_le_bytes(changed[offset..offset + 4].try_into().unwrap());
    let after = changed_cell(before);
    changed[offset..offset + 4].copy_from_slice(&after.to_le_bytes());
    let mutation_ns = start.elapsed().as_nanos();
    Mutation {
        id: "product-last-cell",
        proof: Some(changed),
        clone_ns,
        mutation_ns,
        ticket_search_wall_ns: 0,
        construction_ns: started.elapsed().as_nanos(),
        attempts: Vec::new(),
        product_cell: Some((before, after)),
    }
}
fn transcript_mutation(proof: &[u8], challenge: Hash, target: Hash, limit: usize) -> Mutation {
    let started = Instant::now();
    let start = Instant::now();
    let mut changed = proof.to_vec();
    let clone_ns = start.elapsed().as_nanos();
    let mut attempts = Vec::new();
    let mut fake = None;
    let start_search = Instant::now();
    for nonce in 0..limit {
        let start = Instant::now();
        let trace = hash(
            b"rejection-cost-fake-trace-v1",
            &[&challenge, &(nonce as u64).to_le_bytes()],
        );
        let candidate_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        let selected = ticket <= target && trace.as_slice() != &proof[PROOF_BYTES - 32..];
        let ticket_ns = start.elapsed().as_nanos();
        attempts.push(FakeAttempt {
            nonce,
            trace,
            ticket,
            selected,
            candidate_ns,
            ticket_ns,
        });
        if selected {
            fake = Some(trace);
            break;
        }
    }
    let ticket_search_wall_ns = start_search.elapsed().as_nanos();
    let start = Instant::now();
    let output = fake.map(|trace| {
        changed[PROOF_BYTES - 32..].copy_from_slice(&trace);
        changed
    });
    let mutation_ns = start.elapsed().as_nanos();
    Mutation {
        id: "transcript",
        proof: output,
        clone_ns,
        mutation_ns,
        ticket_search_wall_ns,
        construction_ns: started.elapsed().as_nanos(),
        attempts,
        product_cell: None,
    }
}

fn progress_bytes(points: &[VerificationProgress]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for point in points {
        match *point {
            VerificationProgress::BeforeReplay => bytes.push(0),
            VerificationProgress::Noise { label, counter } => {
                bytes.extend([1, label]);
                bytes.extend(counter.to_le_bytes());
            }
            VerificationProgress::MatrixRow { row } => {
                bytes.push(2);
                bytes.extend((row as u32).to_le_bytes());
            }
            VerificationProgress::TranscriptTile { row, column, inner } => {
                bytes.push(3);
                for value in [row, column, inner] {
                    bytes.extend((value as u32).to_le_bytes());
                }
            }
            VerificationProgress::BeforeProduct => bytes.push(4),
            VerificationProgress::BeforeVerifiedWork => bytes.push(5),
        }
    }
    bytes
}
fn probe(
    kernel: usize,
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: &[u8],
) -> (&'static str, Option<String>, Vec<VerificationProgress>) {
    let mut points = Vec::new();
    let mut observe = |point| {
        points.push(point);
        Ok::<(), std::convert::Infallible>(())
    };
    let result = match kernel {
        0 => verify_with_progress(challenge, task, target, proof, &mut observe),
        1 => verify_reference_with_progress(challenge, task, target, proof, &mut observe),
        2 => verify_limb_with_progress(challenge, task, target, proof, &mut observe),
        _ => unreachable!("fixed probe kernel"),
    };
    let result = match result {
        Ok(work) => Ok(work),
        Err(VerificationError::Relation(error)) => Err(error),
        Err(VerificationError::Cancelled(impossible)) => match impossible {},
    };
    let (name, product) = actual_result(result);
    (name, product, points)
}
fn probe_json(points: &[VerificationProgress], result: &str) -> String {
    let mut noise = [0_usize; 4];
    let (mut replay, mut rows, mut tiles, mut product, mut verified) = (0, 0, 0, 0, 0);
    for point in points {
        match *point {
            VerificationProgress::BeforeReplay => replay += 1,
            VerificationProgress::Noise { label, .. } => noise[usize::from(label)] += 1,
            VerificationProgress::MatrixRow { .. } => rows += 1,
            VerificationProgress::TranscriptTile { .. } => tiles += 1,
            VerificationProgress::BeforeProduct => product += 1,
            VerificationProgress::BeforeVerifiedWork => verified += 1,
        }
    }
    object! {
        "timed" => false,
        "actual_result" => quoted(result),
        "sequence_sha256" => quoted(&sha256(&progress_bytes(points))),
        "events" => points.len(),
        "noise_counts" => array(noise.map(|v| v.to_string())),
        "before_replay" => replay,
        "matrix_rows" => rows,
        "transcript_tiles" => tiles,
        "before_product" => product,
        "before_verified_work" => verified,
    }
}
struct Measurement {
    position: usize,
    variant: usize,
    kernel: usize,
    elapsed_ns: u128,
    result: &'static str,
    product: Option<String>,
}

fn material(class: &str) -> (Vec<u32>, Vec<u32>) {
    let a = (0..CELLS)
        .map(|i| match class {
            "zero" => 0,
            "rank-one" => ((i / N + 1) * (i % N + 1)) as u32,
            "sparse" => u32::from(i / N == i % N),
            "dense" => (i % 31) as u32,
            _ => unreachable!("fixed diagnostic task class"),
        })
        .collect();
    let b = (0..CELLS)
        .map(|i| match class {
            "zero" => 0,
            "rank-one" => ((i / N + 2) * (i % N + 1)) as u32,
            "sparse" => u32::from(i / N == i % N),
            "dense" => ((i * 7) % 37) as u32,
            _ => unreachable!("fixed diagnostic task class"),
        })
        .collect();
    (a, b)
}
fn sample_json(class: &str, target: Hash, sample: usize) -> String {
    let start = Instant::now();
    let (a, b) = material(class);
    let material_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let task = task_id(&a, &b).expect("fixed material");
    let task_binding_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let prepared = PreparedTask::new(&a, &b).expect("fixed material preparation");
    let reusable_preprocessing_ns = start.elapsed().as_nanos();
    let setup_ns = material_ns + task_binding_ns + reusable_preprocessing_ns;
    let searched = search(&prepared, class, target, sample, LIMIT);
    let mut mutations = Vec::new();
    let mut measurements_json = Vec::new();
    let mut mutation_json = Vec::new();
    if let Some((challenge, proof)) = &searched.winner {
        // A separate allocation supplies each mutation. Neither construction
        // claims to begin without the charged full honest winner above.
        mutations.push(transcript_mutation(proof, *challenge, target, LIMIT));
        mutations.push(product_mutation(proof));
        let proofs = [
            Some(proof.as_slice()),
            mutations[0].proof.as_deref(),
            mutations[1].proof.as_deref(),
        ];
        let mut measurements = Vec::new();
        for position in 0..9 {
            let arm = (position + sample) % 9;
            let (variant, kernel) = (arm / 3, arm % 3);
            if let Some(bytes) = proofs[variant] {
                let start = Instant::now();
                let result = black_box(verifier(kernel, *challenge, task, target, bytes));
                let elapsed_ns = start.elapsed().as_nanos();
                let (result, product) = actual_result(result);
                assert_eq!(result, ["Accepted", "Transcript", "Product"][variant]);
                measurements.push(Measurement {
                    position,
                    variant,
                    kernel,
                    elapsed_ns,
                    result,
                    product,
                });
            }
        }
        // Observation instrumentation is deliberately executed only after every
        // timed arm. Each probe is bound to the same complete input bytes.
        let mut canonical_sequences: [Option<Vec<VerificationProgress>>; 3] = [None, None, None];
        for measured in measurements {
            let bytes = proofs[measured.variant].unwrap();
            let (result, product, points) = probe(measured.kernel, *challenge, task, target, bytes);
            assert_eq!((result, &product), (measured.result, &measured.product));
            if let Some(reference) = &canonical_sequences[measured.variant] {
                assert_eq!(&points, reference, "kernel observation sequence");
            } else {
                canonical_sequences[measured.variant] = Some(points.clone());
            }
            measurements_json.push(object! {
                "position" => measured.position,
                "variant" => quoted(VARIANTS[measured.variant]),
                "kernel" => quoted(KERNELS[measured.kernel]),
                "proof_sha256" => quoted(&sha256(bytes)),
                "elapsed_ns" => measured.elapsed_ns,
                "actual_result" => quoted(measured.result),
                "returned_product_sha256" => measured.product.map_or("null".into(), |v| quoted(&v)),
                "probe" => probe_json(&points, result),
            });
        }
        let accepted = canonical_sequences[0].as_ref().unwrap();
        let product_points = canonical_sequences[2].as_ref().unwrap();
        assert_eq!(
            accepted.last(),
            Some(&VerificationProgress::BeforeVerifiedWork)
        );
        assert_eq!(product_points, &accepted[..accepted.len() - 1]);
        if let Some(transcript_points) = &canonical_sequences[1] {
            let before_product = accepted
                .iter()
                .position(|p| *p == VerificationProgress::BeforeProduct)
                .unwrap();
            assert_eq!(transcript_points, &accepted[..before_product]);
        }
        mutation_json.extend(mutations.iter().map(|m| m.json(proof, *challenge)));
    }
    object! {
        "class" => quoted(class),
        "sample" => sample,
        "target" => quoted(&hex::encode(target)),
        "task" => quoted(&hex::encode(task)),
        "proof_prefix_hex" => quoted(&hex::encode(&searched.prefix)),
        "setup" => object! {
            "material_ns" => material_ns,
            "task_binding_ns" => task_binding_ns,
            "reusable_preprocessing_ns" => reusable_preprocessing_ns,
            "total_ns" => setup_ns,
        },
        "honest_search" => searched.json(LIMIT),
        "honest_acquisition_ns" => setup_ns + searched.wall_ns,
        "mutations" => array(mutation_json),
        "measurements" => array(measurements_json),
    }
}

fn main() {
    assert_eq!(
        std::env::args_os().count(),
        1,
        "fixed diagnostic has no argument overrides"
    );
    print!("{{\"schema\":\"pon-work-rejection-cost-v1\",\"profile\":{},\"attempt_limit\":{LIMIT},\"samples_per_group\":{SAMPLES},\"producer\":\"prepared-task-full-transcript\",\"kernels\":{},\"samples\":[", quoted(PROFILE), array(KERNELS.map(quoted)));
    let mut first = true;
    for class in ["dense", "zero", "rank-one", "sparse"] {
        for top in [127, 7] {
            let mut target = [255; 32];
            target[0] = top;
            for sample in 0..SAMPLES {
                let row = sample_json(class, target, sample);
                if !first {
                    print!(",");
                }
                first = false;
                print!("{row}");
            }
        }
    }
    println!("],\"fastest_adversary_qualified\":false,\"work_hardness_accepted\":false,\"worst_case_rejection_qualified\":false,\"public_service_measured\":false,\"production_activation\":false}}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_last_cell_mutation_is_canonical_even_at_modulus_boundary() {
        assert_eq!(changed_cell(0), 1);
        assert_eq!(changed_cell(Q as u32 - 1), 0);
        let (a, b) = material("dense");
        let prepared = PreparedTask::new(&a, &b).unwrap();
        let task = task_id(&a, &b).unwrap();
        let challenge = [19; 32];
        let proof = prepared.prove(challenge).unwrap();
        let mutated = product_mutation(&proof).proof.unwrap();
        let offset = PROOF_BYTES - 36;
        assert_eq!(&mutated[..offset], &proof[..offset]);
        assert_eq!(&mutated[offset + 4..], &proof[offset + 4..]);
        assert_ne!(&mutated[offset..offset + 4], &proof[offset..offset + 4]);
        for kernel in 0..3 {
            assert_eq!(
                verifier(kernel, challenge, task, [255; 32], &mutated).unwrap_err(),
                WorkError::Product
            );
            let mut both = mutated.clone();
            both[PROOF_BYTES - 1] ^= 1;
            assert_eq!(
                verifier(kernel, challenge, task, [255; 32], &both).unwrap_err(),
                WorkError::Transcript
            );
            both[offset..offset + 4].copy_from_slice(&(Q as u32).to_le_bytes());
            assert_eq!(
                verifier(kernel, challenge, [0; 32], [255; 32], &both).unwrap_err(),
                WorkError::Field
            );
        }
    }

    #[test]
    fn bounded_search_and_fake_ticket_exhaustion_keep_every_attempt() {
        let (a, b) = material("zero");
        let prepared = PreparedTask::new(&a, &b).unwrap();
        let exhausted = search(&prepared, "zero", [0; 32], 0, 2);
        assert!(exhausted.winner.is_none());
        assert_eq!(exhausted.attempts.len(), 2);
        assert!(exhausted.attempts.iter().all(|a| !a.selected));
        let challenge = [17; 32];
        let proof = prepared.prove(challenge).unwrap();
        let fake = transcript_mutation(&proof, challenge, [0; 32], 2);
        assert!(fake.proof.is_none());
        assert_eq!(fake.attempts.len(), 2);
        assert!(fake.attempts.iter().all(|a| !a.selected));
    }

    #[test]
    fn actual_late_rejection_stage_matches_scalar_and_keeps_cancellation_distinct() {
        let (a, b) = material("rank-one");
        let prepared = PreparedTask::new(&a, &b).unwrap();
        let challenge = [27; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prepared.prove(challenge).unwrap();
        let product = product_mutation(&proof).proof.unwrap();
        let transcript = transcript_mutation(&proof, challenge, [255; 32], 2)
            .proof
            .unwrap();
        let accepted = probe(1, challenge, task, [255; 32], &proof).2;
        let before_product = accepted
            .iter()
            .position(|p| *p == VerificationProgress::BeforeProduct)
            .unwrap();
        for kernel in 0..3 {
            let (result, _, points) = probe(kernel, challenge, task, [255; 32], &product);
            assert_eq!(result, "Product");
            assert_eq!(points, accepted[..accepted.len() - 1]);
            let (result, _, points) = probe(kernel, challenge, task, [255; 32], &transcript);
            assert_eq!(result, "Transcript");
            assert_eq!(points, accepted[..before_product]);
        }
        // Every product-correction row boundary remains cancellable before the
        // relation can return Product. This is not represented as a rejection timing.
        for cut in (before_product..accepted.len() - 1).filter(|&index| {
            matches!(
                accepted[index],
                VerificationProgress::BeforeProduct
                    | VerificationProgress::MatrixRow { row: 0 | 7 | 63 }
            )
        }) {
            let mut observed = 0;
            let result =
                verify_limb_with_progress(challenge, task, [255; 32], &product, &mut |_| {
                    let index = observed;
                    observed += 1;
                    if index == cut {
                        Err(cut)
                    } else {
                        Ok(())
                    }
                });
            assert_eq!(result.unwrap_err(), VerificationError::Cancelled(cut));
            assert_eq!(observed, cut + 1);
        }
    }
}
