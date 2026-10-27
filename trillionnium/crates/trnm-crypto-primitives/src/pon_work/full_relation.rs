//! Bounded, deterministic complete W1 relation for a future computation-proof guest.
//!
//! This module performs the full computation locally. It implements no succinct
//! proof system, accepts no cryptographic certificate, and cannot construct
//! `VerifiedWork`. Its output is an execution observation, never admission,
//! chainwork, signature, release or consensus authority. No node calls this path.
//!
//! The arithmetic below is intentionally independent of the three native W1
//! kernels. Only their public constants/error vocabulary are shared. A future
//! proof verifier must pin the actual guest image and proof parameters in
//! addition to this relation's version; a profile hash is not a proof.

use sha2::{Digest, Sha256};

use super::{Hash, WorkError, CELLS, N, PROOF_BYTES, Q, R};

pub const PROFILE: &str = "pon-complete-w1-relation-v1";
pub const HEADER_BYTES: usize = 318;
pub const STATEMENT_BYTES: usize = 4 + 2 + 32 + HEADER_BYTES + 3 * 32;
pub const INPUT_BYTES: usize = STATEMENT_BYTES + PROOF_BYTES;
const TARGET_OFFSET: usize = 118;
const TASK_OFFSET: usize = 278;
const MATRIX_BYTES: usize = CELLS * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationError {
    StatementLength,
    StatementVersion,
    Profile,
    HeaderEncoding,
    HeaderTask,
    HeaderTarget,
    WitnessCommitment,
    Work(WorkError),
}

impl From<WorkError> for RelationError {
    fn from(value: WorkError) -> Self {
        Self::Work(value)
    }
}

/// Exact public statement, not authenticated chain context.
///
/// The consensus caller must independently establish the parent, network,
/// parameters, expected target and task authorization. This local relation only
/// proves consistency with the values it is given. All 318 header bytes bind the
/// challenge, including miner, parent, roots, time, height and nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicStatement {
    header: [u8; HEADER_BYTES],
    expected_task: Hash,
    expected_target: Hash,
    witness_commitment: Hash,
}

impl PublicStatement {
    pub fn bind(
        header: &[u8],
        expected_task: Hash,
        expected_target: Hash,
        canonical_pnw1: &[u8],
    ) -> Result<Self, RelationError> {
        let header = parse_header(header)?;
        if canonical_pnw1.len() != PROOF_BYTES {
            return Err(WorkError::Length.into());
        }
        Ok(Self {
            header,
            expected_task,
            expected_target,
            witness_commitment: witness_commitment(canonical_pnw1),
        })
    }

    pub fn encode(&self) -> [u8; STATEMENT_BYTES] {
        let mut bytes = [0; STATEMENT_BYTES];
        bytes[..4].copy_from_slice(b"PWG1");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6..38].copy_from_slice(&profile_id());
        bytes[38..38 + HEADER_BYTES].copy_from_slice(&self.header);
        let offset = 38 + HEADER_BYTES;
        bytes[offset..offset + 32].copy_from_slice(&self.expected_task);
        bytes[offset + 32..offset + 64].copy_from_slice(&self.expected_target);
        bytes[offset + 64..].copy_from_slice(&self.witness_commitment);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelationError> {
        if bytes.len() != STATEMENT_BYTES {
            return Err(RelationError::StatementLength);
        }
        if &bytes[..4] != b"PWG1" || bytes[4..6] != 1u16.to_le_bytes() {
            return Err(RelationError::StatementVersion);
        }
        if bytes[6..38] != profile_id() {
            return Err(RelationError::Profile);
        }
        let header = parse_header(&bytes[38..38 + HEADER_BYTES])?;
        let offset = 38 + HEADER_BYTES;
        Ok(Self {
            header,
            expected_task: array(&bytes[offset..offset + 32]),
            expected_target: array(&bytes[offset + 32..offset + 64]),
            witness_commitment: array(&bytes[offset + 64..]),
        })
    }

    pub fn header_bytes(&self) -> &[u8; HEADER_BYTES] {
        &self.header
    }

    pub fn expected_task(&self) -> Hash {
        self.expected_task
    }

    pub fn expected_target(&self) -> Hash {
        self.expected_target
    }

    pub fn witness_commitment(&self) -> Hash {
        self.witness_commitment
    }

    pub fn statement_id(&self) -> Hash {
        domain_hash(b"w1-complete-statement-v1", &[&self.encode()])
    }
}

/// Result of real local recomputation, explicitly not a transferable proof.
///
/// There is deliberately no conversion to the native `VerifiedWork` type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalExecution {
    statement_id: Hash,
    challenge: Hash,
    task: Hash,
    ticket: Hash,
    trace: Hash,
    block_id: Hash,
    product: Vec<u32>,
}

impl LocalExecution {
    pub fn statement_id(&self) -> Hash {
        self.statement_id
    }
    pub fn challenge(&self) -> Hash {
        self.challenge
    }
    pub fn task(&self) -> Hash {
        self.task
    }
    pub fn ticket(&self) -> Hash {
        self.ticket
    }
    pub fn trace(&self) -> Hash {
        self.trace
    }
    pub fn block_id(&self) -> Hash {
        self.block_id
    }
    pub fn product(&self) -> &[u32] {
        &self.product
    }

    /// Deterministic public execution journal for backend integration research.
    /// These bytes have no authenticity until a real, pinned proof verifies them.
    /// No proof randomness or proof encoding is included in the work/block ID.
    pub fn journal(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 7 * 32);
        out.extend_from_slice(b"PWJ1");
        for value in [
            self.statement_id,
            self.challenge,
            self.task,
            self.ticket,
            self.trace,
            self.block_id,
            domain_hash(b"w1-complete-product-v1", &[&field_bytes(&self.product)]),
        ] {
            out.extend_from_slice(&value);
        }
        out
    }
}

pub fn profile_id() -> Hash {
    domain_hash(b"w1-complete-profile-v1", &[PROFILE.as_bytes()])
}

pub fn witness_commitment(bytes: &[u8]) -> Hash {
    domain_hash(b"w1-complete-witness-v1", &[bytes])
}

/// Execute the exact fixed-size guest input. This is a native full replay, not
/// succinct verification. Missing/trailing bytes cannot select another relation.
pub fn execute_input(input: &[u8]) -> Result<LocalExecution, RelationError> {
    if input.len() != INPUT_BYTES {
        return Err(RelationError::StatementLength);
    }
    let statement = PublicStatement::decode(&input[..STATEMENT_BYTES])?;
    execute(&statement, &input[STATEMENT_BYTES..])
}

/// Construct the public journal *claimed* by a fixed input, without executing
/// W1. This deliberately accepts arithmetically false claims. Its sole purpose
/// is to give a real cryptographic verifier the expected public output cheaply;
/// callers must never treat these bytes as verified computation or chainwork.
pub fn unverified_claimed_journal(input: &[u8]) -> Result<Vec<u8>, RelationError> {
    if input.len() != INPUT_BYTES {
        return Err(RelationError::StatementLength);
    }
    let statement = PublicStatement::decode(&input[..STATEMENT_BYTES])?;
    let bytes = &input[STATEMENT_BYTES..];
    if witness_commitment(bytes) != statement.witness_commitment {
        return Err(RelationError::WitnessCommitment);
    }
    let challenge = domain_hash(b"challenge", &[&statement.header]);
    let trace: Hash = array(&bytes[PROOF_BYTES - 32..]);
    let mut out = Vec::with_capacity(4 + 7 * 32);
    out.extend_from_slice(b"PWJ1");
    for value in [
        statement.statement_id(),
        challenge,
        statement.expected_task,
        domain_hash(b"ticket", &[&challenge, &trace]),
        trace,
        domain_hash(b"block", &[&statement.header, &trace]),
        domain_hash(
            b"w1-complete-product-v1",
            &[&bytes[4 + 2 * MATRIX_BYTES..4 + 3 * MATRIX_BYTES]],
        ),
    ] {
        out.extend_from_slice(&value);
    }
    Ok(out)
}

/// Independently recompute every part of the existing W1 relation.
///
/// This entry point has no filesystem, clock, network, RNG, signatures, free
/// proof nonce or independent hashcash. The statement fixes all work inputs.
pub fn execute(statement: &PublicStatement, bytes: &[u8]) -> Result<LocalExecution, RelationError> {
    if statement.header[TASK_OFFSET..TASK_OFFSET + 32] != statement.expected_task {
        return Err(RelationError::HeaderTask);
    }
    if statement.header[TARGET_OFFSET..TARGET_OFFSET + 32] != statement.expected_target {
        return Err(RelationError::HeaderTarget);
    }
    if bytes.len() != PROOF_BYTES {
        return Err(WorkError::Length.into());
    }
    if witness_commitment(bytes) != statement.witness_commitment {
        return Err(RelationError::WitnessCommitment);
    }
    if &bytes[..4] != b"PNW1" {
        return Err(WorkError::Version.into());
    }
    if statement.expected_target == [0; 32] {
        return Err(WorkError::Target.into());
    }
    // Preserve native W1's C, then A/B field-validation order.
    let claimed = decode_field(&bytes[4 + 2 * MATRIX_BYTES..4 + 3 * MATRIX_BYTES])?;
    let a = decode_field(&bytes[4..4 + MATRIX_BYTES])?;
    let b = decode_field(&bytes[4 + MATRIX_BYTES..4 + 2 * MATRIX_BYTES])?;
    let task = domain_hash(
        b"task",
        &[
            &bytes[4..4 + MATRIX_BYTES],
            &bytes[4 + MATRIX_BYTES..4 + 2 * MATRIX_BYTES],
        ],
    );
    if task != statement.expected_task {
        return Err(WorkError::Task.into());
    }
    let challenge = domain_hash(b"challenge", &[&statement.header]);
    let trace: Hash = array(&bytes[4 + 3 * MATRIX_BYTES..]);
    let ticket = domain_hash(b"ticket", &[&challenge, &trace]);
    if ticket > statement.expected_target {
        return Err(WorkError::Target.into());
    }
    let replay = replay(challenge, &a, &b, |_, _| {})?;
    if replay.trace != trace {
        return Err(WorkError::Transcript.into());
    }
    let left = matrix_product(&a, &replay.fl, N, N, R);
    let correction1 = matrix_product(&left, &replay.fr, N, R, N);
    let right = matrix_product(&replay.er, &replay.bp, R, N, N);
    let correction2 = matrix_product(&replay.el, &right, N, R, N);
    let product: Vec<_> = replay
        .cp
        .iter()
        .zip(correction1)
        .zip(correction2)
        .map(|((x, y), z)| reduce_bounded(u128::from(*x) + 2 * Q - u128::from(y) - u128::from(z)))
        .collect();
    if product != claimed {
        return Err(WorkError::Product.into());
    }
    Ok(LocalExecution {
        statement_id: statement.statement_id(),
        challenge,
        task,
        ticket,
        trace,
        block_id: domain_hash(b"block", &[&statement.header, &trace]),
        product,
    })
}

fn parse_header(bytes: &[u8]) -> Result<[u8; HEADER_BYTES], RelationError> {
    if bytes.len() != HEADER_BYTES || &bytes[..4] != b"PNH1" || bytes[4..6] != [1, 0] {
        return Err(RelationError::HeaderEncoding);
    }
    let mut out = [0; HEADER_BYTES];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn array(bytes: &[u8]) -> Hash {
    let mut value = [0; 32];
    value.copy_from_slice(bytes);
    value
}

fn domain_hash(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"TRNM-PON1\0");
    h.update((tag.len() as u16).to_le_bytes());
    h.update(tag);
    for part in parts {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

fn field_bytes(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn decode_field(bytes: &[u8]) -> Result<Vec<u32>, WorkError> {
    let mut values = Vec::with_capacity(CELLS);
    for word in bytes.chunks_exact(4) {
        let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        if u128::from(value) >= Q {
            return Err(WorkError::Field);
        }
        values.push(value);
    }
    Ok(values)
}

fn expand(challenge: Hash, label: u8) -> Result<Vec<u32>, WorkError> {
    let mut values = Vec::with_capacity(N * R);
    for counter in 0..128u32 {
        let block = domain_hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
        for word in block.chunks_exact(4) {
            let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            if u128::from(value) < Q {
                values.push(value);
                if values.len() == N * R {
                    return Ok(values);
                }
            }
        }
    }
    Err(WorkError::NoiseBudget)
}

/// Exact reduction for this fixed relation's bounded accumulators.
///
/// Every canonical word is below q = 2^32 - 5 and each dot product has at most
/// 64 terms, so its sum is strictly below 2^70. Since 2^32 = 5 (mod q), two
/// folds yield a value below 2q; one conditional subtraction is sufficient.
/// The bound is checked in release builds too: an internal range regression
/// must fail instead of truncating high bits and changing the proved relation.
fn reduce_bounded(value: u128) -> u32 {
    assert!(value < (1u128 << 70), "complete W1 reduction range");
    let first = u64::from(value as u32) + 5 * ((value >> 32) as u64);
    let second = u64::from(first as u32) + 5 * (first >> 32);
    if second >= Q as u64 {
        (second - Q as u64) as u32
    } else {
        second as u32
    }
}

fn wide_product(a: u32, b: u32) -> u128 {
    // A 32-by-32 product fits in u64, including noncanonical u32 values. Avoid
    // compiling an unnecessarily general 128-by-128 multiplication in RV32.
    u128::from(u64::from(a) * u64::from(b))
}

fn matrix_product(a: &[u32], b: &[u32], rows: usize, inner: usize, columns: usize) -> Vec<u32> {
    let mut output = vec![0; rows * columns];
    for i in 0..rows {
        for j in 0..columns {
            let total: u128 = (0..inner)
                .map(|k| wide_product(a[i * inner + k], b[k * columns + j]))
                .sum();
            output[i * columns + j] = reduce_bounded(total);
        }
    }
    output
}

struct Replay {
    cp: Vec<u32>,
    el: Vec<u32>,
    er: Vec<u32>,
    fl: Vec<u32>,
    fr: Vec<u32>,
    bp: Vec<u32>,
    trace: Hash,
}

// Observation cannot alter the trace. Production passes a no-op; unit tests
// collect every prefix to build independently committed malicious witnesses.
fn replay(
    challenge: Hash,
    a: &[u32],
    b: &[u32],
    mut observe: impl FnMut(usize, u32),
) -> Result<Replay, WorkError> {
    let el = expand(challenge, 0)?;
    let er = expand(challenge, 1)?;
    let fl = expand(challenge, 2)?;
    let fr = expand(challenge, 3)?;
    let e = matrix_product(&el, &er, N, R, N);
    let f = matrix_product(&fl, &fr, N, R, N);
    let ap: Vec<_> = a
        .iter()
        .zip(e)
        .map(|(x, y)| reduce_bounded(u128::from(*x) + u128::from(y)))
        .collect();
    let bp: Vec<_> = b
        .iter()
        .zip(f)
        .map(|(x, y)| reduce_bounded(u128::from(*x) + u128::from(y)))
        .collect();
    let mut cp = vec![0u32; CELLS];
    let mut transcript = Sha256::new();
    transcript.update(b"TRNM-PON-TRACE1\0");
    transcript.update(challenge);
    let mut position = 0;
    for bi in 0..N / R {
        for bj in 0..N / R {
            for bk in 0..N / R {
                let mut tile_bytes = [0u8; R * R * 4];
                let mut tile_offset = 0;
                for i in bi * R..(bi + 1) * R {
                    for j in bj * R..(bj + 1) * R {
                        let mut total = u128::from(cp[i * N + j]);
                        for k in bk * R..(bk + 1) * R {
                            total += wide_product(ap[i * N + k], bp[k * N + j]);
                        }
                        let value = reduce_bounded(total);
                        cp[i * N + j] = value;
                        tile_bytes[tile_offset..tile_offset + 4]
                            .copy_from_slice(&value.to_le_bytes());
                        tile_offset += 4;
                        observe(position, value);
                        position += 1;
                    }
                }
                // Exactly the original 64 ordered little-endian words; only
                // the API call boundary changes, not any hashed byte.
                transcript.update(tile_bytes);
            }
        }
    }
    Ok(Replay {
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
#[path = "full_relation_tests.rs"]
mod tests;
