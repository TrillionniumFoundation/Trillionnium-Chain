//! Executable experimental PoN relation. No production-hardness or mining-network claim.
//! Full-transcript work on challenge-encoded matrices; verification recomputes it.
use sha2::{Digest, Sha256};

pub mod blocked_one_zero;
pub mod blocked_zero;
pub mod maintenance_periodic;
pub mod paired_product;
pub mod structured;

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

/// Local observation boundaries; these are neither proof bytes nor consensus input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationProgress {
    BeforeReplay,
    Noise {
        label: u8,
        counter: u32,
    },
    MatrixRow {
        row: usize,
    },
    TranscriptTile {
        row: usize,
        column: usize,
        inner: usize,
    },
    BeforeProduct,
    BeforeVerifiedWork,
}

/// An abandoned local computation does not assert that the relation is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError<E> {
    Relation(WorkError),
    Cancelled(E),
}
impl<E> From<WorkError> for VerificationError<E> {
    fn from(error: WorkError) -> Self {
        Self::Relation(error)
    }
}
fn relation_only<T>(
    result: Result<T, VerificationError<std::convert::Infallible>>,
) -> Result<T, WorkError> {
    match result {
        Ok(value) => Ok(value),
        Err(VerificationError::Relation(error)) => Err(error),
        Err(VerificationError::Cancelled(impossible)) => match impossible {},
    }
}
fn no_cancellation(_: VerificationProgress) -> Result<(), std::convert::Infallible> {
    Ok(())
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
    relation_only(expand_with_progress(
        challenge,
        label,
        len,
        &mut no_cancellation,
    ))
}
fn expand_with_progress<E>(
    challenge: Hash,
    label: u8,
    len: usize,
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, VerificationError<E>> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u32;
    while out.len() < len {
        if counter >= 128 {
            return Err(WorkError::NoiseBudget.into());
        }
        progress(VerificationProgress::Noise { label, counter })
            .map_err(VerificationError::Cancelled)?;
        let bytes = hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
        for pair in bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| chunk.as_slice())
        {
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
#[cfg(test)]
fn mul(a: &[u32], b: &[u32], rows: usize, inner: usize, cols: usize) -> Vec<u32> {
    match mul_with_progress(a, b, rows, inner, cols, &mut no_cancellation) {
        Ok(product) => product,
        Err(impossible) => match impossible {},
    }
}
fn mul_with_progress<E>(
    a: &[u32],
    b: &[u32],
    rows: usize,
    inner: usize,
    cols: usize,
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, E> {
    let mut out = vec![0; rows * cols];
    for i in 0..rows {
        progress(VerificationProgress::MatrixRow { row: i })?;
        for j in 0..cols {
            let mut sum = 0_u128;
            for k in 0..inner {
                sum += u128::from(a[i * inner + k]) * u128::from(b[k * cols + j]);
            }
            out[i * cols + j] = (sum % Q) as u32;
        }
    }
    Ok(out)
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
    relation_only(evaluate_transcript_with_progress(
        challenge,
        a,
        b,
        &mut no_cancellation,
    ))
}
fn evaluate_transcript_with_progress<E>(
    challenge: Hash,
    a: &[u32],
    b: &[u32],
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<TranscriptEvaluation, VerificationError<E>> {
    validate(a)?;
    validate(b)?;
    let el = expand_with_progress(challenge, 0, N * R, progress)?;
    let er = expand_with_progress(challenge, 1, R * N, progress)?;
    let fl = expand_with_progress(challenge, 2, N * R, progress)?;
    let fr = expand_with_progress(challenge, 3, R * N, progress)?;
    let e = mul_with_progress(&el, &er, N, R, N, progress).map_err(VerificationError::Cancelled)?;
    let f = mul_with_progress(&fl, &fr, N, R, N, progress).map_err(VerificationError::Cancelled)?;
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
                progress(VerificationProgress::TranscriptTile {
                    row: bi,
                    column: bj,
                    inner: bk,
                })
                .map_err(VerificationError::Cancelled)?;
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
    match finish_product_with_progress(a, evaluated, &mut no_cancellation) {
        Ok(product) => product,
        Err(impossible) => match impossible {},
    }
}
fn finish_product_with_progress<E>(
    a: &[u32],
    evaluated: TranscriptEvaluation,
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, E> {
    progress(VerificationProgress::BeforeProduct)?;
    #[cfg(test)]
    PRODUCT_RECONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let left = mul_with_progress(a, &evaluated.fl, N, N, R, progress)?;
    let correction1 = mul_with_progress(&left, &evaluated.fr, N, R, N, progress)?;
    let right = mul_with_progress(&evaluated.er, &evaluated.bp, R, N, N, progress)?;
    let correction2 = mul_with_progress(&evaluated.el, &right, N, R, N, progress)?;
    Ok(evaluated
        .cp
        .iter()
        .zip(correction1)
        .zip(correction2)
        .map(|((x, y), z)| ((u128::from(*x) + 2 * Q - u128::from(y) - u128::from(z)) % Q) as u32)
        .collect())
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
    relation_only(verify_with_progress(
        challenge,
        expected_task,
        target,
        bytes,
        &mut no_cancellation,
    ))
}
/// Full PNW1 replay with caller-local cooperative cancellation.
/// A callback error drops all intermediates; only complete success creates VerifiedWork.
/// Checkpoints bound arithmetic between observations, not physical CPU time or preemption.
pub fn verify_with_progress<E>(
    challenge: Hash,
    expected_task: Hash,
    target: Hash,
    bytes: &[u8],
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<VerifiedWork, VerificationError<E>> {
    verify_with_kernel(
        challenge,
        expected_task,
        target,
        bytes,
        progress,
        VerificationKernel::Transposed,
    )
}

/// Retained scalar verifier for differential checks and explicitly named cost baselines.
/// This follows the same admission grammar but uses the original u128 remainder,
/// row-major multiplication and per-cell transcript updates for the full relation.
pub fn verify_reference(
    challenge: Hash,
    expected_task: Hash,
    target: Hash,
    bytes: &[u8],
) -> Result<VerifiedWork, WorkError> {
    relation_only(verify_reference_with_progress(
        challenge,
        expected_task,
        target,
        bytes,
        &mut no_cancellation,
    ))
}

pub fn verify_reference_with_progress<E>(
    challenge: Hash,
    expected_task: Hash,
    target: Hash,
    bytes: &[u8],
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<VerifiedWork, VerificationError<E>> {
    verify_with_kernel(
        challenge,
        expected_task,
        target,
        bytes,
        progress,
        VerificationKernel::ScalarReference,
    )
}

#[derive(Clone, Copy)]
enum VerificationKernel {
    ScalarReference,
    Transposed,
}

fn verify_with_kernel<E>(
    challenge: Hash,
    expected_task: Hash,
    target: Hash,
    bytes: &[u8],
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
    kernel: VerificationKernel,
) -> Result<VerifiedWork, VerificationError<E>> {
    if bytes.len() != PROOF_BYTES {
        return Err(WorkError::Length.into());
    }
    if &bytes[..4] != b"PNW1" {
        return Err(WorkError::Version.into());
    }
    if target == [0; 32] {
        return Err(WorkError::Target.into());
    }
    let matrices: Vec<u32> = bytes[4..4 + 3 * CELLS * 4]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .map(|p| u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
        .collect();
    let (a, tail) = matrices.split_at(CELLS);
    let (b, claimed) = tail.split_at(CELLS);
    validate(claimed)?;
    let actual_task = task_id(a, b)?;
    if actual_task != expected_task {
        return Err(WorkError::Task.into());
    }
    let trace_claim: &[u8] = &bytes[4 + 3 * CELLS * 4..];
    // Cheap ticket rejection before expensive transcript verification is only an admission filter.
    // A passing filter alone never constructs VerifiedWork.
    let ticket = hash(b"ticket", &[&challenge, trace_claim]);
    if ticket > target {
        return Err(WorkError::Target.into());
    }
    progress(VerificationProgress::BeforeReplay).map_err(VerificationError::Cancelled)?;
    let evaluated = match kernel {
        VerificationKernel::ScalarReference => {
            evaluate_transcript_with_progress(challenge, a, b, progress)?
        }
        VerificationKernel::Transposed => {
            evaluate_transposed_with_progress(challenge, a, b, progress)?
        }
    };
    // PNW1 submits only a final digest: every transcript update is still replayed.
    // A mismatch skips product corrections; a matching digest is not yet VerifiedWork.
    if evaluated.trace.as_slice() != trace_claim {
        return Err(WorkError::Transcript.into());
    }
    let product = match kernel {
        VerificationKernel::ScalarReference => finish_product_with_progress(a, evaluated, progress),
        VerificationKernel::Transposed => finish_transposed_with_progress(a, evaluated, progress),
    }
    .map_err(VerificationError::Cancelled)?;
    if product != claimed {
        return Err(WorkError::Product.into());
    }
    progress(VerificationProgress::BeforeVerifiedWork).map_err(VerificationError::Cancelled)?;
    Ok(VerifiedWork {
        challenge,
        task: actual_task,
        ticket,
        product,
    })
}

// q = 2^32 - 5. A transcript sum is below 2^70; two folds followed by
// one subtraction are exact. The prepared producer and production verifier use
// this arithmetic; the separately retained scalar reference uses u128 remainder.
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
    match transposed_mul_with_progress(a, b, rows, inner, cols, &mut no_cancellation) {
        Ok(product) => product,
        Err(impossible) => match impossible {},
    }
}
fn transposed_mul_with_progress<E>(
    a: &[u32],
    b: &[u32],
    rows: usize,
    inner: usize,
    cols: usize,
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, E> {
    debug_assert!(inner <= N);
    let mut transposed = vec![0; b.len()];
    for k in 0..inner {
        for j in 0..cols {
            transposed[j * inner + k] = b[k * cols + j];
        }
    }
    let mut out = vec![0; rows * cols];
    for i in 0..rows {
        progress(VerificationProgress::MatrixRow { row: i })?;
        for j in 0..cols {
            let mut sum = 0_u128;
            for k in 0..inner {
                sum += u128::from(a[i * inner + k]) * u128::from(transposed[j * inner + k]);
            }
            out[i * cols + j] = producer_reduce(sum);
        }
    }
    Ok(out)
}

// Exact full replay. Transposition and batched hashing change neither transcript
// order nor the original noise/row/tile observation sequence. Nothing is trusted
// from the producer, a prior task, the claimed product or an earlier callback.
fn evaluate_transposed_with_progress<E>(
    challenge: Hash,
    a: &[u32],
    b: &[u32],
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<TranscriptEvaluation, VerificationError<E>> {
    validate(a)?;
    validate(b)?;
    let el = expand_with_progress(challenge, 0, N * R, progress)?;
    let er = expand_with_progress(challenge, 1, R * N, progress)?;
    let fl = expand_with_progress(challenge, 2, N * R, progress)?;
    let fr = expand_with_progress(challenge, 3, R * N, progress)?;
    let e = transposed_mul_with_progress(&el, &er, N, R, N, progress)
        .map_err(VerificationError::Cancelled)?;
    let f = transposed_mul_with_progress(&fl, &fr, N, R, N, progress)
        .map_err(VerificationError::Cancelled)?;
    let ap: Vec<u32> = a
        .iter()
        .zip(e)
        .map(|(x, y)| producer_reduce(u128::from(*x) + u128::from(y)))
        .collect();
    let bp: Vec<u32> = b
        .iter()
        .zip(f)
        .map(|(x, y)| producer_reduce(u128::from(*x) + u128::from(y)))
        .collect();
    let mut bt = vec![0u32; CELLS];
    for k in 0..N {
        for j in 0..N {
            bt[j * N + k] = bp[k * N + j];
        }
    }
    let mut cp = vec![0u32; CELLS];
    let mut transcript = Sha256::new();
    transcript.update(b"TRNM-PON-TRACE1\0");
    transcript.update(challenge);
    for bi in 0..N / R {
        for bj in 0..N / R {
            let mut cells = [0u32; R * R];
            let mut bytes = [0u8; R * R * 4];
            for bk in 0..N / R {
                progress(VerificationProgress::TranscriptTile {
                    row: bi,
                    column: bj,
                    inner: bk,
                })
                .map_err(VerificationError::Cancelled)?;
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
            for i in 0..R {
                cp[(bi * R + i) * N + bj * R..(bi * R + i) * N + (bj + 1) * R]
                    .copy_from_slice(&cells[i * R..(i + 1) * R]);
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

fn finish_transposed_with_progress<E>(
    a: &[u32],
    evaluated: TranscriptEvaluation,
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, E> {
    progress(VerificationProgress::BeforeProduct)?;
    #[cfg(test)]
    PRODUCT_RECONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let left = transposed_mul_with_progress(a, &evaluated.fl, N, N, R, progress)?;
    let correction1 = transposed_mul_with_progress(&left, &evaluated.fr, N, R, N, progress)?;
    let right = transposed_mul_with_progress(&evaluated.er, &evaluated.bp, R, N, N, progress)?;
    let correction2 = transposed_mul_with_progress(&evaluated.el, &right, N, R, N, progress)?;
    Ok(evaluated
        .cp
        .iter()
        .zip(correction1)
        .zip(correction2)
        .map(|((x, y), z)| producer_reduce(u128::from(*x) + 2 * Q - u128::from(y) - u128::from(z)))
        .collect())
}

/// Bounded producer cache for one exact task. It carries no verification authority.
/// The useful product is fixed across challenges; every challenge still hashes every tile.
pub struct PreparedTask {
    a: Vec<u32>,
    b: Vec<u32>,
    prefix: Vec<u8>,
}

/// Local generation checkpoints, with no proof field or verification capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedGenerationProgress {
    BeforeReplay,
    Noise {
        label: u8,
        counter: u32,
    },
    NoiseRow {
        operand: u8,
        row: usize,
    },
    TranscriptTile {
        row: usize,
        column: usize,
        inner: usize,
    },
    BeforeProof,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PreparedGenerationError<E> {
    Relation(WorkError),
    Cancelled(E),
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
        match self.prove_with_progress(challenge, |_| Ok::<_, std::convert::Infallible>(())) {
            Ok(proof) => Ok(proof),
            Err(PreparedGenerationError::Relation(error)) => Err(error),
            Err(PreparedGenerationError::Cancelled(impossible)) => match impossible {},
        }
    }

    /// Same complete arithmetic and byte order as ordinary production. Each
    /// observation precedes its bounded work; cancellation returns no proof and
    /// leaves this exact mathematical cache available for a later fresh call.
    pub fn prove_with_progress<E>(
        &self,
        challenge: Hash,
        mut progress: impl FnMut(PreparedGenerationProgress) -> Result<(), E>,
    ) -> Result<Vec<u8>, PreparedGenerationError<E>> {
        progress(PreparedGenerationProgress::BeforeReplay)
            .map_err(PreparedGenerationError::Cancelled)?;
        let mut noise = |label| {
            expand_with_progress(challenge, label, N * R, &mut |point| {
                let VerificationProgress::Noise { label, counter } = point else {
                    unreachable!("noise expansion emits only noise observations")
                };
                progress(PreparedGenerationProgress::Noise { label, counter })
            })
            .map_err(|error| match error {
                VerificationError::Relation(error) => PreparedGenerationError::Relation(error),
                VerificationError::Cancelled(error) => PreparedGenerationError::Cancelled(error),
            })
        };
        let el = noise(0)?;
        let er = noise(1)?;
        let fl = noise(2)?;
        let fr = noise(3)?;
        let e = transposed_mul_with_progress(&el, &er, N, R, N, &mut |point| {
            let VerificationProgress::MatrixRow { row } = point else {
                unreachable!("matrix multiplication emits only row observations")
            };
            progress(PreparedGenerationProgress::NoiseRow { operand: 0, row })
        })
        .map_err(PreparedGenerationError::Cancelled)?;
        let ap: Vec<u32> = self
            .a
            .iter()
            .zip(e)
            .map(|(x, y)| ((u128::from(*x) + u128::from(y)) % Q) as u32)
            .collect();
        let f = transposed_mul_with_progress(&fl, &fr, N, R, N, &mut |point| {
            let VerificationProgress::MatrixRow { row } = point else {
                unreachable!("matrix multiplication emits only row observations")
            };
            progress(PreparedGenerationProgress::NoiseRow { operand: 1, row })
        })
        .map_err(PreparedGenerationError::Cancelled)?;
        let bp: Vec<u32> = self
            .b
            .iter()
            .zip(f)
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
                    progress(PreparedGenerationProgress::TranscriptTile {
                        row: bi,
                        column: bj,
                        inner: bk,
                    })
                    .map_err(PreparedGenerationError::Cancelled)?;
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
        progress(PreparedGenerationProgress::BeforeProof)
            .map_err(PreparedGenerationError::Cancelled)?;
        let mut out = self.prefix.clone();
        out.extend_from_slice(&transcript.finalize());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked_value(
        result: Result<VerifiedWork, WorkError>,
    ) -> Result<(Hash, Hash, Hash, Vec<u32>), WorkError> {
        result.map(|work| (work.challenge(), work.task(), work.ticket(), work.product))
    }

    #[test]
    fn fast_and_scalar_verifiers_match_extreme_products_and_error_precedence() {
        let a: Vec<_> = (0..CELLS)
            .map(|i| if i % 2 == 0 { (Q - 1) as u32 } else { 0 })
            .collect();
        let b: Vec<_> = (0..CELLS)
            .map(|i| (Q - 1 - (i % 19) as u128) as u32)
            .collect();
        let challenge = [255; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        let mut cases = vec![(challenge, task, [255; 32], proof.clone())];
        cases.push(([7; 32], task, [255; 32], proof.clone()));
        cases.push((challenge, [0; 32], [255; 32], proof.clone()));
        cases.push((challenge, task, [0; 32], proof.clone()));
        for length in [0, 4, PROOF_BYTES - 1] {
            cases.push((challenge, task, [255; 32], proof[..length].to_vec()));
        }
        let mut extra = proof.clone();
        extra.push(0);
        cases.push((challenge, task, [255; 32], extra));
        for pos in [4, 4 + CELLS * 4, 4 + CELLS * 8] {
            let mut bad = proof.clone();
            bad[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            cases.push((challenge, [0; 32], [255; 32], bad));
        }
        let mut wrong_product = proof.clone();
        wrong_product[4 + CELLS * 8..4 + CELLS * 8 + 4].copy_from_slice(&0u32.to_le_bytes());
        // Use a guaranteed different canonical value even if the true cell is zero.
        if wrong_product == proof {
            wrong_product[4 + CELLS * 8] = 1;
        }
        cases.push((challenge, task, [255; 32], wrong_product.clone()));
        wrong_product[PROOF_BYTES - 1] ^= 1;
        cases.push((challenge, task, [255; 32], wrong_product));
        let mut wrong_magic = proof.clone();
        wrong_magic[0] ^= 1;
        cases.push((challenge, [0; 32], [0; 32], wrong_magic));
        for (c, t, target, bytes) in cases {
            assert_eq!(
                checked_value(verify(c, t, target, &bytes)),
                checked_value(verify_reference(c, t, target, &bytes))
            );
        }
    }

    #[test]
    fn fast_and_scalar_verifiers_preserve_observation_order_and_cancelled_results() {
        let (a, b) = matrices();
        let challenge = [23; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        let mut fast_points = Vec::new();
        let fast = verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
            fast_points.push(point);
            Ok::<(), usize>(())
        })
        .unwrap();
        let mut scalar_points = Vec::new();
        let scalar =
            verify_reference_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
                scalar_points.push(point);
                Ok::<(), usize>(())
            })
            .unwrap();
        assert_eq!(fast_points, scalar_points);
        assert_eq!(fast.product(), scalar.product());
        let cuts: Vec<_> = scalar_points
            .iter()
            .enumerate()
            .filter_map(|(index, point)| {
                let selected = match point {
                    VerificationProgress::BeforeReplay
                    | VerificationProgress::BeforeProduct
                    | VerificationProgress::BeforeVerifiedWork => true,
                    VerificationProgress::Noise { counter, .. } => *counter == 0 || *counter == 63,
                    VerificationProgress::MatrixRow { row } => [0, 7, 63].contains(row),
                    VerificationProgress::TranscriptTile { row, column, inner } => {
                        (*row, *column, *inner) == (0, 0, 0)
                            || (*row, *column, *inner) == (4, 4, 4)
                            || (*row, *column, *inner) == (7, 7, 7)
                    }
                };
                selected.then_some(index)
            })
            .collect();
        for cut in cuts {
            let mut observed = 0;
            let mut stop = |_| {
                let current = observed;
                observed += 1;
                if current == cut {
                    Err(cut)
                } else {
                    Ok(())
                }
            };
            let fast_error =
                verify_with_progress(challenge, task, [255; 32], &proof, &mut stop).unwrap_err();
            assert_eq!(observed, cut + 1);
            observed = 0;
            let scalar_error =
                verify_reference_with_progress(challenge, task, [255; 32], &proof, &mut |_| {
                    let current = observed;
                    observed += 1;
                    if current == cut {
                        Err(cut)
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert_eq!(observed, cut + 1);
            assert_eq!(fast_error, VerificationError::Cancelled(cut));
            assert_eq!(fast_error, scalar_error);
        }
    }
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
    fn controlled_verification_preserves_full_success_and_late_relation_errors() {
        let (a, b) = matrices();
        let challenge = [17; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        let ordinary = verify(challenge, task, [255; 32], &proof).unwrap();
        let controlled = verify_with_progress(challenge, task, [255; 32], &proof, &mut |_| {
            Ok::<(), &str>(())
        })
        .unwrap();
        assert_eq!(controlled.challenge(), ordinary.challenge());
        assert_eq!(controlled.task(), ordinary.task());
        assert_eq!(controlled.ticket(), ordinary.ticket());
        assert_eq!(
            field_bytes(controlled.product()),
            field_bytes(ordinary.product())
        );
        let mut bad_product = proof.clone();
        bad_product[4 + 8 * CELLS] ^= 1;
        let mut bad_trace = bad_product.clone();
        bad_trace[PROOF_BYTES - 1] ^= 1;
        for (bad, expected) in [
            (&bad_product, WorkError::Product),
            (&bad_trace, WorkError::Transcript),
        ] {
            assert_eq!(
                verify(challenge, task, [255; 32], bad).unwrap_err(),
                expected
            );
            assert_eq!(
                verify_with_progress(challenge, task, [255; 32], bad, &mut |_| Ok::<(), &str>(()))
                    .unwrap_err(),
                VerificationError::Relation(expected)
            );
        }
    }
    #[test]
    fn cancellation_on_last_transcript_tile_never_starts_product_reconstruction() {
        let (a, b) = matrices();
        let challenge = [18; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        PRODUCT_RECONSTRUCTIONS.with(|count| count.set(0));
        let mut tiles = 0;
        let error = verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
            if let VerificationProgress::TranscriptTile { row, column, inner } = point {
                tiles += 1;
                if (row, column, inner) == (N / R - 1, N / R - 1, N / R - 1) {
                    return Err("local deadline");
                }
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error, VerificationError::Cancelled("local deadline"));
        assert_eq!(tiles, (N / R).pow(3));
        PRODUCT_RECONSTRUCTIONS.with(|count| assert_eq!(count.get(), 0));
    }
    #[test]
    fn product_row_and_final_cancellation_never_yield_verified_work() {
        let (a, b) = matrices();
        let challenge = [19; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        for final_boundary in [false, true] {
            PRODUCT_RECONSTRUCTIONS.with(|count| count.set(0));
            let mut correcting = false;
            let error = verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
                if point == VerificationProgress::BeforeProduct {
                    correcting = true;
                }
                if (final_boundary && point == VerificationProgress::BeforeVerifiedWork)
                    || (!final_boundary
                        && correcting
                        && point == (VerificationProgress::MatrixRow { row: 16 }))
                {
                    return Err("local stop");
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(error, VerificationError::Cancelled("local stop"));
            PRODUCT_RECONSTRUCTIONS.with(|count| assert_eq!(count.get(), 1));
        }
    }
    #[test]
    fn cheap_rejection_precedes_progress_and_noise_cancellation_is_local() {
        let (a, b) = matrices();
        let challenge = [20; 32];
        let task = task_id(&a, &b).unwrap();
        let proof = prove(challenge, &a, &b).unwrap();
        let mut observations = 0;
        let mut deny = |_| {
            observations += 1;
            Err("cancelled")
        };
        for (bytes, expected_task, target, expected) in [
            (&[][..], task, [255; 32], WorkError::Length),
            (&proof[..], [0; 32], [255; 32], WorkError::Task),
            (&proof[..], task, [0; 32], WorkError::Target),
        ] {
            assert_eq!(
                verify_with_progress(challenge, expected_task, target, bytes, &mut deny)
                    .unwrap_err(),
                VerificationError::Relation(expected)
            );
        }
        assert_eq!(observations, 0);
        assert_eq!(
            verify_with_progress(challenge, task, [255; 32], &proof, &mut |point| {
                if point
                    == (VerificationProgress::Noise {
                        label: 0,
                        counter: 1,
                    })
                {
                    Err("cancelled")
                } else {
                    Ok(())
                }
            })
            .unwrap_err(),
            VerificationError::Cancelled("cancelled")
        );
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
