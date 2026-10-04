//! Concrete alternative producers for legal structured W1 inputs. Their returned
//! bytes carry no authority and must pass the ordinary complete verifier. This is
//! an implemented algorithm comparison, not a fastest-adversary or hardness claim.
use super::{
    expand, field_bytes, producer_mul, producer_reduce, validate, Hash, PreparedTask, WorkError,
    CELLS, N, PROOF_BYTES, Q, R,
};
use sha2::{Digest, Sha256};

enum Kernel {
    Zero {
        prefix: Vec<u8>,
    },
    Product {
        name: &'static str,
        task: PreparedTask,
    },
}

/// A fixed-task preparation with an explicit, checked structure. Unsupported
/// matrices return None; this interface never silently charges a generic producer
/// as a successful structured optimization.
pub struct StructuredPreparedTask {
    kernel: Kernel,
}
impl StructuredPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        validate(a)?;
        validate(b)?;
        let a_zero = a.iter().all(|value| *value == 0);
        let b_zero = b.iter().all(|value| *value == 0);
        if a_zero && b_zero {
            let mut prefix = Vec::with_capacity(PROOF_BYTES);
            prefix.extend_from_slice(b"PNW1");
            prefix.resize(PROOF_BYTES - 32, 0);
            return Ok(Some(Self {
                kernel: Kernel::Zero { prefix },
            }));
        }
        let (name, product) = if a_zero || b_zero {
            ("zero-product-full-transcript", vec![0; CELLS])
        } else if is_identity(a) {
            ("left-identity-full-transcript", b.to_vec())
        } else if is_identity(b) {
            ("right-identity-full-transcript", a.to_vec())
        } else if is_diagonal(a) && is_diagonal(b) {
            let mut product = vec![0; CELLS];
            for i in 0..N {
                product[i * N + i] =
                    producer_reduce(u128::from(a[i * N + i]) * u128::from(b[i * N + i]));
            }
            ("diagonal-product-full-transcript", product)
        } else if let (Some((left_a, right_a)), Some((left_b, right_b))) =
            (rank_one(a), rank_one(b))
        {
            let scale = producer_reduce(
                right_a
                    .iter()
                    .zip(left_b)
                    .map(|(x, y)| u128::from(*x) * u128::from(y))
                    .sum(),
            );
            let scaled_left: Vec<_> = left_a
                .iter()
                .map(|value| producer_reduce(u128::from(*value) * u128::from(scale)))
                .collect();
            let product = scaled_left
                .iter()
                .flat_map(|left| {
                    right_b
                        .iter()
                        .map(|right| producer_reduce(u128::from(*left) * u128::from(*right)))
                })
                .collect();
            ("rank-one-product-full-transcript", product)
        } else {
            return Ok(None);
        };
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for matrix in [a, b, product.as_slice()] {
            prefix.extend_from_slice(&field_bytes(matrix));
        }
        Ok(Some(Self {
            kernel: Kernel::Product {
                name,
                task: PreparedTask {
                    a: a.to_vec(),
                    b: b.to_vec(),
                    prefix,
                },
            },
        }))
    }

    pub fn method(&self) -> &'static str {
        match &self.kernel {
            Kernel::Zero { .. } => "zero-reassociated-transcript",
            Kernel::Product { name, .. } => name,
        }
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match &self.kernel {
            Kernel::Product { task, .. } => task.prove(challenge),
            Kernel::Zero { prefix } => zero_proof(challenge, prefix),
        }
    }
}

fn is_identity(matrix: &[u32]) -> bool {
    matrix
        .iter()
        .enumerate()
        .all(|(i, value)| *value == u32::from(i / N == i % N))
}
fn is_diagonal(matrix: &[u32]) -> bool {
    matrix
        .iter()
        .enumerate()
        .all(|(i, value)| i / N == i % N || *value == 0)
}
fn inverse(value: u32) -> u32 {
    debug_assert!(value != 0);
    let mut exponent = (Q - 2) as u64;
    let mut power = value;
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = producer_reduce(u128::from(result) * u128::from(power));
        }
        power = producer_reduce(u128::from(power) * u128::from(power));
        exponent >>= 1;
    }
    result
}
fn rank_one(matrix: &[u32]) -> Option<(Vec<u32>, Vec<u32>)> {
    let pivot = matrix.iter().position(|value| *value != 0)?;
    let row = pivot / N;
    let column = pivot % N;
    let reciprocal = inverse(matrix[pivot]);
    let left: Vec<_> = (0..N).map(|i| matrix[i * N + column]).collect();
    let right: Vec<_> = (0..N)
        .map(|j| producer_reduce(u128::from(matrix[row * N + j]) * u128::from(reciprocal)))
        .collect();
    for i in 0..N {
        for j in 0..N {
            if producer_reduce(u128::from(left[i]) * u128::from(right[j])) != matrix[i * N + j] {
                return None;
            }
        }
    }
    Some((left, right))
}

fn zero_proof(challenge: Hash, prefix: &[u8]) -> Result<Vec<u8>, WorkError> {
    let el = expand(challenge, 0, N * R)?;
    let er = expand(challenge, 1, R * N)?;
    let fl = expand(challenge, 2, N * R)?;
    let fr = expand(challenge, 3, R * N)?;
    let mut middle = vec![0u32; R * R];
    let mut partials = Vec::with_capacity(N / R);
    for block in 0..N / R {
        let er_block: Vec<_> = (0..R)
            .flat_map(|i| {
                er[i * N + block * R..i * N + (block + 1) * R]
                    .iter()
                    .copied()
            })
            .collect();
        let fl_block = &fl[block * R * R..(block + 1) * R * R];
        let increment = producer_mul(&er_block, fl_block, R, R, R);
        for (value, delta) in middle.iter_mut().zip(increment) {
            *value = producer_reduce(u128::from(*value) + u128::from(delta));
        }
        partials.push(producer_mul(
            &producer_mul(&el, &middle, N, R, R),
            &fr,
            N,
            R,
            N,
        ));
    }
    let mut trace = Sha256::new();
    trace.update(b"TRNM-PON-TRACE1\0");
    trace.update(challenge);
    for bi in 0..N / R {
        for bj in 0..N / R {
            for partial in &partials {
                let mut bytes = [0u8; R * R * 4];
                for i in 0..R {
                    for j in 0..R {
                        let value = partial[(bi * R + i) * N + bj * R + j];
                        let pos = (i * R + j) * 4;
                        bytes[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
                    }
                }
                trace.update(bytes);
            }
        }
    }
    let mut proof = prefix.to_vec();
    proof.extend_from_slice(&trace.finalize());
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{prove, task_id, verify, verify_reference};

    #[test]
    fn zero_reassociation_matches_the_retained_python_oracle_bytes() {
        // Complete-proof hashes obtained from the independently coded scalar
        // work_oracle.py, not generated by the structured Rust implementation.
        let zero = vec![0; CELLS];
        let task = StructuredPreparedTask::new(&zero, &zero).unwrap().unwrap();
        for (byte, expected) in [
            (
                0,
                "d8111b2ad64c3dbd1fcab46e07507b6e071aa9608356a4b577b9c4e2182433a4",
            ),
            (
                7,
                "ba5e30e124e397a90f78f01ffcef19b408a4be9939be972cb0895a42a8679bb3",
            ),
            (
                255,
                "41917a90d1927ba85213f2ffdba37d1abb99ba462ff71be6d5a824fa28b4f78c",
            ),
        ] {
            let proof = task.prove([byte; 32]).unwrap();
            assert_eq!(hex::encode(Sha256::digest(proof)), expected);
        }
    }

    #[test]
    fn structure_specific_products_and_transcripts_match_both_verifiers() {
        let zero = vec![0; CELLS];
        let identity: Vec<_> = (0..CELLS).map(|i| u32::from(i / N == i % N)).collect();
        let diagonal: Vec<_> = (0..CELLS)
            .map(|i| {
                if i / N == i % N {
                    (Q - 1 - (i / N) as u128) as u32
                } else {
                    0
                }
            })
            .collect();
        let rank_a: Vec<_> = (0..CELLS)
            .map(|i| producer_reduce((Q - 1 - (i / N) as u128) * (i % N) as u128))
            .collect();
        let rank_b: Vec<_> = (0..CELLS)
            .map(|i| producer_reduce((i / N + 1) as u128 * (Q - 1 - (i % N) as u128)))
            .collect();
        for (a, b) in [
            (&zero, &zero),
            (&zero, &rank_a),
            (&rank_a, &zero),
            (&identity, &rank_a),
            (&rank_a, &identity),
            (&diagonal, &diagonal),
            (&rank_a, &rank_b),
        ] {
            let prepared = StructuredPreparedTask::new(a, b).unwrap().unwrap();
            for challenge in [[0; 32], [7; 32], [255; 32]] {
                let proof = prepared.prove(challenge).unwrap();
                assert_eq!(proof, prove(challenge, a, b).unwrap());
                let task = task_id(a, b).unwrap();
                let fast = verify(challenge, task, [255; 32], &proof).unwrap();
                let reference = verify_reference(challenge, task, [255; 32], &proof).unwrap();
                assert_eq!(fast.product(), reference.product());
            }
        }
    }

    #[test]
    fn invalid_or_nearly_structured_material_cannot_create_a_shortcut() {
        assert!(StructuredPreparedTask::new(&[], &[]).is_err());
        assert!(StructuredPreparedTask::new(&vec![u32::MAX; CELLS], &vec![0; CELLS]).is_err());
        let mut matrix = vec![1; CELLS];
        matrix[CELLS - 1] = 2;
        assert!(StructuredPreparedTask::new(&matrix, &matrix)
            .unwrap()
            .is_none());
        let mut diagonal = vec![0; CELLS];
        for i in 0..N {
            diagonal[i * N + i] = 2;
        }
        diagonal[1] = 1;
        assert!(StructuredPreparedTask::new(&diagonal, &diagonal)
            .unwrap()
            .is_none());
    }
}
