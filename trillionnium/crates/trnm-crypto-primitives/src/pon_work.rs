//! Executable experimental PoN relation. No production-hardness or mining-network claim.
//! Full-transcript work on challenge-encoded matrices; verification recomputes it.
use sha2::{Digest, Sha256};

pub const PROFILE: &str = "pon-matmul-transcript-64-v1";
pub const N: usize = 64;
pub const R: usize = 8;
pub const Q: u128 = 4_294_967_291;
pub const CELLS: usize = N * N;
pub const PROOF_BYTES: usize = 4 + 3 * CELLS * 4 + 32;
pub type Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkError {
    Length,
    Version,
    Field,
    Task,
    Transcript,
    Product,
    Target,
    NoiseBudget,
}

/// A successful relation check for an exact caller-supplied statement, not a capability.
#[derive(Debug)]
pub struct VerifiedWork {
    challenge: Hash,
    task: Hash,
    ticket: Hash,
    product: Vec<u32>,
}
impl VerifiedWork {
    pub fn challenge(&self) -> Hash {
        self.challenge
    }
    pub fn task(&self) -> Hash {
        self.task
    }
    pub fn ticket(&self) -> Hash {
        self.ticket
    }
    pub fn product(&self) -> &[u32] {
        &self.product
    }
}

pub fn hash(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"TRNM-PON1\0");
    h.update((tag.len() as u16).to_le_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}
fn field_bytes(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn validate(values: &[u32]) -> Result<(), WorkError> {
    if values.len() != CELLS {
        return Err(WorkError::Length);
    }
    if values.iter().any(|v| u128::from(*v) >= Q) {
        return Err(WorkError::Field);
    }
    Ok(())
}
pub fn task_id(a: &[u32], b: &[u32]) -> Result<Hash, WorkError> {
    validate(a)?;
    validate(b)?;
    Ok(hash(b"task", &[&field_bytes(a), &field_bytes(b)]))
}
fn expand(challenge: Hash, label: u8, len: usize) -> Result<Vec<u32>, WorkError> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u32;
    while out.len() < len {
        if counter >= 128 {
            return Err(WorkError::NoiseBudget);
        }
        let bytes = hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
        for pair in bytes.chunks_exact(4) {
            let v = u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]);
            if u128::from(v) < Q {
                out.push(v);
                if out.len() == len {
                    break;
                }
            }
        }
        counter += 1;
    }
    Ok(out)
}
fn mul(a: &[u32], b: &[u32], rows: usize, inner: usize, cols: usize) -> Vec<u32> {
    let mut out = vec![0; rows * cols];
    for i in 0..rows {
        for j in 0..cols {
            let mut sum = 0_u128;
            for k in 0..inner {
                sum += u128::from(a[i * inner + k]) * u128::from(b[k * cols + j]);
            }
            out[i * cols + j] = (sum % Q) as u32;
        }
    }
    out
}
// Operation-local arithmetic intermediates, never a verified-work capability or cache.
struct TranscriptEvaluation {
    cp: Vec<u32>,
    el: Vec<u32>,
    er: Vec<u32>,
    fl: Vec<u32>,
    fr: Vec<u32>,
    bp: Vec<u32>,
    trace: Hash,
}

fn evaluate_transcript(
    challenge: Hash,
    a: &[u32],
    b: &[u32],
) -> Result<TranscriptEvaluation, WorkError> {
    validate(a)?;
    validate(b)?;
    let el = expand(challenge, 0, N * R)?;
    let er = expand(challenge, 1, R * N)?;
    let fl = expand(challenge, 2, N * R)?;
    let fr = expand(challenge, 3, R * N)?;
    let e = mul(&el, &er, N, R, N);
    let f = mul(&fl, &fr, N, R, N);
    let ap: Vec<u32> = a
        .iter()
        .zip(e)
        .map(|(x, y)| ((u128::from(*x) + u128::from(y)) % Q) as u32)
        .collect();
    let bp: Vec<u32> = b
        .iter()
        .zip(f)
        .map(|(x, y)| ((u128::from(*x) + u128::from(y)) % Q) as u32)
        .collect();
    let mut cp = vec![0_u32; CELLS];
    let mut transcript = Sha256::new();
    transcript.update(b"TRNM-PON-TRACE1\0");
    transcript.update(challenge);
    for bi in 0..N / R {
        for bj in 0..N / R {
            for bk in 0..N / R {
                for i in bi * R..(bi + 1) * R {
                    for j in bj * R..(bj + 1) * R {
                        let mut sum = u128::from(cp[i * N + j]);
                        for k in bk * R..(bk + 1) * R {
                            sum += u128::from(ap[i * N + k]) * u128::from(bp[k * N + j]);
                        }
                        cp[i * N + j] = (sum % Q) as u32;
                        transcript.update(cp[i * N + j].to_le_bytes());
                    }
                }
            }
        }
    }
    Ok(TranscriptEvaluation {
        cp,
        el,
        er,
        fl,
        fr,
        bp,
        trace: transcript.finalize().into(),
    })
}

#[cfg(test)]
thread_local! {
    static PRODUCT_RECONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn finish_product(a: &[u32], evaluated: TranscriptEvaluation) -> Vec<u32> {
    #[cfg(test)]
    PRODUCT_RECONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let correction1 = mul(&mul(a, &evaluated.fl, N, N, R), &evaluated.fr, N, R, N);
    let correction2 = mul(
        &evaluated.el,
        &mul(&evaluated.er, &evaluated.bp, R, N, N),
        N,
        R,
        N,
    );
    evaluated
        .cp
        .iter()
        .zip(correction1)
        .zip(correction2)
        .map(|((x, y), z)| ((u128::from(*x) + 2 * Q - u128::from(y) - u128::from(z)) % Q) as u32)
        .collect()
}

/// Exact useful matrix product plus the bound transcript digest.
/// The entire fixed-size job is evaluated; no proof-randomness lottery is offered.
pub fn evaluate(challenge: Hash, a: &[u32], b: &[u32]) -> Result<(Vec<u32>, Hash), WorkError> {
    let evaluated = evaluate_transcript(challenge, a, b)?;
    let trace = evaluated.trace;
    Ok((finish_product(a, evaluated), trace))
}
pub fn prove(challenge: Hash, a: &[u32], b: &[u32]) -> Result<Vec<u8>, WorkError> {
    let (product, trace) = evaluate(challenge, a, b)?;
    let mut out = Vec::with_capacity(PROOF_BYTES);
    out.extend_from_slice(b"PNW1");
    for matrix in [a, b, &product] {
        out.extend_from_slice(&field_bytes(matrix));
    }
    out.extend_from_slice(&trace);
    Ok(out)
}
pub fn verify(
    challenge: Hash,
    expected_task: Hash,
    target: Hash,
    bytes: &[u8],
) -> Result<VerifiedWork, WorkError> {
    if bytes.len() != PROOF_BYTES {
        return Err(WorkError::Length);
    }
    if &bytes[..4] != b"PNW1" {
        return Err(WorkError::Version);
    }
    if target == [0; 32] {
        return Err(WorkError::Target);
    }
    let matrices: Vec<u32> = bytes[4..4 + 3 * CELLS * 4]
        .chunks_exact(4)
        .map(|p| u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
        .collect();
    let (a, tail) = matrices.split_at(CELLS);
    let (b, claimed) = tail.split_at(CELLS);
    validate(claimed)?;
    let actual_task = task_id(a, b)?;
    if actual_task != expected_task {
        return Err(WorkError::Task);
    }
    let trace_claim: &[u8] = &bytes[4 + 3 * CELLS * 4..];
    // Cheap ticket rejection before expensive transcript verification is only an admission filter.
    // A passing filter alone never constructs VerifiedWork.
    let ticket = hash(b"ticket", &[&challenge, trace_claim]);
    if ticket > target {
        return Err(WorkError::Target);
    }
    let evaluated = evaluate_transcript(challenge, a, b)?;
    // PNW1 submits only a final digest: every transcript update is still replayed.
    // A mismatch skips product corrections; a matching digest is not yet VerifiedWork.
    if evaluated.trace.as_slice() != trace_claim {
        return Err(WorkError::Transcript);
    }
    let product = finish_product(a, evaluated);
    if product != claimed {
        return Err(WorkError::Product);
    }
    Ok(VerifiedWork {
        challenge,
        task: actual_task,
        ticket,
        product,
    })
}

// q = 2^32 - 5. A transcript sum is below 2^70; two folds followed by
// one subtraction are exact. Only the producer uses this alternative arithmetic;
// the independent verifier retains u128 remainder and full recomputation.
fn producer_reduce(x: u128) -> u32 {
    debug_assert!(x < (1_u128 << 70));
    let first = (x as u32 as u64) + 5 * ((x >> 32) as u64);
    let second = (first as u32 as u64) + 5 * (first >> 32);
    if second >= Q as u64 {
        (second - Q as u64) as u32
    } else {
        second as u32
    }
}
fn producer_mul(a: &[u32], b: &[u32], rows: usize, inner: usize, cols: usize) -> Vec<u32> {
    debug_assert!(inner <= N);
    let mut transposed = vec![0; b.len()];
    for k in 0..inner {
        for j in 0..cols {
            transposed[j * inner + k] = b[k * cols + j];
        }
    }
    let mut out = vec![0; rows * cols];
    for i in 0..rows {
        for j in 0..cols {
            let mut sum = 0_u128;
            for k in 0..inner {
                sum += u128::from(a[i * inner + k]) * u128::from(transposed[j * inner + k]);
            }
            out[i * cols + j] = producer_reduce(sum);
        }
    }
    out
}

/// Bounded producer cache for one exact task. It carries no verification authority.
/// The useful product is fixed across challenges; every challenge still hashes every tile.
pub struct PreparedTask {
    a: Vec<u32>,
    b: Vec<u32>,
    prefix: Vec<u8>,
}
impl PreparedTask {
    /// Cached mathematical result bytes for producer root planning. This is not
    /// a verified-work capability; admission still replays the original relation.
    pub fn product_bytes(&self) -> &[u8] {
        &self.prefix[4 + 2 * CELLS * 4..4 + 3 * CELLS * 4]
    }
    pub fn new(a: &[u32], b: &[u32]) -> Result<Self, WorkError> {
        validate(a)?;
        validate(b)?;
        let product = producer_mul(a, b, N, N, N);
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for matrix in [a, b, product.as_slice()] {
            prefix.extend_from_slice(&field_bytes(matrix));
        }
        Ok(Self {
            a: a.to_vec(),
            b: b.to_vec(),
            prefix,
        })
    }
    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        let el = expand(challenge, 0, N * R)?;
        let er = expand(challenge, 1, N * R)?;
        let fl = expand(challenge, 2, N * R)?;
        let fr = expand(challenge, 3, N * R)?;
        let ap: Vec<u32> = self
            .a
            .iter()
            .zip(producer_mul(&el, &er, N, R, N))
            .map(|(x, y)| ((u128::from(*x) + u128::from(y)) % Q) as u32)
            .collect();
        let bp: Vec<u32> = self
            .b
            .iter()
            .zip(producer_mul(&fl, &fr, N, R, N))
            .map(|(x, y)| ((u128::from(*x) + u128::from(y)) % Q) as u32)
            .collect();
        let mut bt = vec![0u32; CELLS];
        for k in 0..N {
            for j in 0..N {
                bt[j * N + k] = bp[k * N + j];
            }
        }
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        for bi in 0..N / R {
            for bj in 0..N / R {
                let mut cells = [0u32; R * R];
                let mut bytes = [0u8; R * R * 4];
                for bk in 0..N / R {
                    for i in 0..R {
                        for j in 0..R {
                            let pos = i * R + j;
                            let mut sum = u128::from(cells[pos]);
                            for k in bk * R..(bk + 1) * R {
                                sum += u128::from(ap[(bi * R + i) * N + k])
                                    * u128::from(bt[(bj * R + j) * N + k]);
                            }
                            cells[pos] = producer_reduce(sum);
                            bytes[pos * 4..pos * 4 + 4].copy_from_slice(&cells[pos].to_le_bytes());
                        }
                    }
                    transcript.update(bytes);
                }
            }
        }
        let mut out = self.prefix.clone();
        out.extend_from_slice(&transcript.finalize());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_reduction_matches_remainder_at_boundaries_and_deterministic_samples() {
        let limit = 1_u128 << 70;
        let bounds = [
            0,
            1,
            Q - 1,
            Q,
            Q + 1,
            Q * Q - 1,
            64 * (Q - 1) * (Q - 1) + Q - 1,
            limit - 1,
        ];
        for x in bounds {
            assert_eq!(producer_reduce(x), (x % Q) as u32);
        }
        let mut seed = 19u128;
        for _ in 0..8192 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let x = seed % limit;
            assert_eq!(producer_reduce(x), (x % Q) as u32);
        }
    }
    #[test]
    fn optimized_producer_matches_full_verifier_for_structures_and_extreme_fields() {
        let shapes = [
            vec![0; CELLS],
            vec![(Q - 1) as u32; CELLS],
            (0..CELLS)
                .map(|i| ((i / N + 1) * (i % N + 1)) as u32)
                .collect(),
            (0..CELLS)
                .map(|i| if i % 71 == 0 { (Q - 2) as u32 } else { 0 })
                .collect(),
        ];
        for (index, a) in shapes.iter().enumerate() {
            let b = &shapes[(index + 1) % shapes.len()];
            let prepared = PreparedTask::new(a, b).unwrap();
            for c in [[0; 32], [7; 32], [255; 32]] {
                let proof = prepared.prove(c).unwrap();
                assert_eq!(proof, prove(c, a, b).unwrap());
                verify(c, task_id(a, b).unwrap(), [255; 32], &proof).unwrap();
            }
        }
    }
    fn matrices() -> (Vec<u32>, Vec<u32>) {
        (
            (0..CELLS).map(|i| (i % 31) as u32).collect(),
            (0..CELLS).map(|i| ((i * 7) % 37) as u32).collect(),
        )
    }
    #[test]
    fn decoded_output_is_the_real_matrix_product() {
        let (a, b) = matrices();
        let (p, _) = evaluate([7; 32], &a, &b).unwrap();
        assert_eq!(p, mul(&a, &b, N, N, N));
    }
    #[test]
    fn work_binds_challenge_and_inputs() {
        let (a, b) = matrices();
        let proof = prove([7; 32], &a, &b).unwrap();
        let task = task_id(&a, &b).unwrap();
        let v = verify([7; 32], task, [255; 32], &proof).unwrap();
        assert_eq!(v.challenge(), [7; 32]);
        assert_eq!(v.task(), task);
        assert_eq!(
            verify([8; 32], task, [255; 32], &proof).unwrap_err(),
            WorkError::Transcript
        );
        assert_eq!(
            verify([7; 32], [9; 32], [255; 32], &proof).unwrap_err(),
            WorkError::Task
        );
    }
    #[test]
    fn bad_proof_never_gains_a_verified_type() {
        let (a, b) = matrices();
        let mut proof = prove([3; 32], &a, &b).unwrap();
        let task = task_id(&a, &b).unwrap();
        proof[4 + 8 * CELLS] ^= 1;
        assert_eq!(
            verify([3; 32], task, [255; 32], &proof).unwrap_err(),
            WorkError::Product
        );
        proof[4 + 8 * CELLS] ^= 1;
        let last = proof.len() - 1;
        proof[last] ^= 1;
        assert_eq!(
            verify([3; 32], task, [255; 32], &proof).unwrap_err(),
            WorkError::Transcript
        );
        assert_eq!(
            verify([3; 32], task, [0; 32], &proof).unwrap_err(),
            WorkError::Target
        );
    }
    fn assert_verification_error(
        challenge: Hash,
        task: Hash,
        target: Hash,
        proof: &[u8],
        expected: WorkError,
        product_reconstructions: usize,
    ) {
        PRODUCT_RECONSTRUCTIONS.with(|count| count.set(0));
        assert_eq!(
            verify(challenge, task, target, proof).unwrap_err(),
            expected
        );
        PRODUCT_RECONSTRUCTIONS.with(|count| {
            assert_eq!(count.get(), product_reconstructions);
        });
    }
    #[test]
    fn transcript_mismatch_skips_corrections_but_matching_digest_requires_product() {
        let (a, b) = matrices();
        let challenge = [3; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        let mut bad_product = proof.clone();
        bad_product[4 + 8 * CELLS] ^= 1;
        let mut bad_both = bad_product.clone();
        bad_both[PROOF_BYTES - 1] ^= 1;
        assert_verification_error(
            challenge,
            task,
            [255; 32],
            &bad_both,
            WorkError::Transcript,
            0,
        );
        assert_verification_error([4; 32], task, [255; 32], &proof, WorkError::Transcript, 0);
        assert_verification_error(
            challenge,
            task,
            [255; 32],
            &bad_product,
            WorkError::Product,
            1,
        );
        PRODUCT_RECONSTRUCTIONS.with(|count| count.set(0));
        let verified = verify(challenge, task, [255; 32], &proof).unwrap();
        assert_eq!(verified.product(), mul(&a, &b, N, N, N));
        PRODUCT_RECONSTRUCTIONS.with(|count| assert_eq!(count.get(), 1));
    }
    #[test]
    fn verifier_error_precedence_is_preserved_before_deferred_product() {
        let (a, b) = matrices();
        let challenge = [11; 32];
        let task = task_id(&a, &b).unwrap();
        let wrong_task = [0; 32];
        assert_ne!(task, wrong_task);
        let proof = prove(challenge, &a, &b).unwrap();
        let mut bad_fields = proof.clone();
        for pos in [4, 4 + 4 * CELLS, 4 + 8 * CELLS] {
            bad_fields[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        bad_fields[0] = b'X';
        assert_verification_error(
            challenge,
            wrong_task,
            [0; 32],
            &bad_fields[..PROOF_BYTES - 1],
            WorkError::Length,
            0,
        );
        assert_verification_error(
            challenge,
            wrong_task,
            [0; 32],
            &bad_fields,
            WorkError::Version,
            0,
        );
        bad_fields[0] = b'P';
        assert_verification_error(
            challenge,
            wrong_task,
            [0; 32],
            &bad_fields,
            WorkError::Target,
            0,
        );
        assert_verification_error(
            challenge,
            wrong_task,
            [255; 32],
            &bad_fields,
            WorkError::Field,
            0,
        );
        for pos in [4, 4 + 4 * CELLS] {
            let mut bad_input = proof.clone();
            bad_input[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert_verification_error(
                challenge,
                wrong_task,
                [255; 32],
                &bad_input,
                WorkError::Field,
                0,
            );
        }
        let mut bad_both = proof.clone();
        bad_both[4 + 8 * CELLS] ^= 1;
        bad_both[PROOF_BYTES - 1] ^= 1;
        let ticket = hash(b"ticket", &[&challenge, &bad_both[PROOF_BYTES - 32..]]);
        let mut lower_target = ticket;
        for byte in lower_target.iter_mut().rev() {
            if *byte != 0 {
                *byte -= 1;
                break;
            }
            *byte = 255;
        }
        assert_ne!(lower_target, [0; 32]);
        assert!(lower_target < ticket);
        assert_verification_error(
            challenge,
            wrong_task,
            lower_target,
            &bad_both,
            WorkError::Task,
            0,
        );
        assert_verification_error(
            challenge,
            task,
            lower_target,
            &bad_both,
            WorkError::Target,
            0,
        );
        assert_eq!(evaluate(challenge, &[], &b), Err(WorkError::Length));
        assert_eq!(
            evaluate(challenge, &vec![u32::MAX; CELLS], &[]),
            Err(WorkError::Field)
        );
    }
    #[test]
    fn final_output_only_shortcut_is_not_a_transcript_proof() {
        let zeros = vec![0; CELLS];
        let mut proof = prove([4; 32], &zeros, &zeros).unwrap();
        assert_eq!(&proof[4 + 8 * CELLS..4 + 12 * CELLS], &vec![0; 4 * CELLS]);
        let length = proof.len();
        proof[length - 32..].fill(0);
        assert_eq!(
            verify([4; 32], task_id(&zeros, &zeros).unwrap(), [255; 32], &proof).unwrap_err(),
            WorkError::Transcript
        );
    }
    #[test]
    fn expansion_cannot_exceed_fixed_hash_budget() {
        assert_eq!(
            expand([0; 32], 0, 1025).unwrap_err(),
            WorkError::NoiseBudget
        );
    }
    #[test]
    fn exact_length_and_field_are_required() {
        assert_eq!(
            verify([0; 32], [0; 32], [255; 32], &[]).unwrap_err(),
            WorkError::Length
        );
        let mut a = vec![0; CELLS];
        a[0] = u32::MAX;
        assert_eq!(prove([0; 32], &a, &a).unwrap_err(), WorkError::Field);
    }
    #[test]
    fn fixed_task_preparation_is_byte_identical_across_challenges_and_shapes() {
        for class in 0..4 {
            let a: Vec<u32> = (0..CELLS)
                .map(|i| match class {
                    0 => 0,
                    1 => u32::from(i / N == i % N),
                    2 => ((i / N + 1) * (i % N + 1)) as u32,
                    _ => (i % 31) as u32,
                })
                .collect();
            let b: Vec<u32> = (0..CELLS)
                .map(|i| match class {
                    0 => 0,
                    1 => u32::from(i / N == i % N),
                    2 => ((i / N + 2) * (i % N + 1)) as u32,
                    _ => ((i * 7) % 37) as u32,
                })
                .collect();
            let prepared = PreparedTask::new(&a, &b).unwrap();
            let task = task_id(&a, &b).unwrap();
            for challenge in [[0; 32], [255; 32], [7; 32]] {
                let actual = prepared.prove(challenge).unwrap();
                assert_eq!(actual, prove(challenge, &a, &b).unwrap());
                verify(challenge, task, [255; 32], &actual).unwrap();
            }
        }
        assert!(PreparedTask::new(&[], &[]).is_err());
        assert!(PreparedTask::new(&vec![u32::MAX; CELLS], &vec![0; CELLS]).is_err());
    }
}
