//! Concrete alternative producers for legal structured W1 inputs. Their returned
//! bytes carry no authority and must pass the ordinary complete verifier. This is
//! an implemented algorithm comparison, not a fastest-adversary or hardness claim.
use super::{
    expand, field_bytes, producer_mul, producer_reduce, validate, Hash, PreparedTask, WorkError,
    CELLS, N, PROOF_BYTES, Q, R,
};
use sha2::{Digest, Sha256};

/// Locally selected diagnostic arithmetic. Neither variant changes W1 bytes or
/// constructs verification authority; native mining keeps its existing kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TileKernel {
    Classical,
    StrassenOneLevel,
}

/// Complete alternative prepared producers, including the actual fixed product
/// setup. A multiplication-count saving is not a promised speedup.
pub struct TiledPreparedTask {
    task: PreparedTask,
    kernel: TileKernel,
}
impl TiledPreparedTask {
    pub fn new(a: &[u32], b: &[u32], kernel: TileKernel) -> Result<Self, WorkError> {
        validate(a)?;
        validate(b)?;
        let product = tiled_mul(a, b, N, N, N, kernel);
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for matrix in [a, b, product.as_slice()] {
            prefix.extend_from_slice(&field_bytes(matrix));
        }
        Ok(Self {
            task: PreparedTask {
                a: a.to_vec(),
                b: b.to_vec(),
                prefix,
            },
            kernel,
        })
    }

    pub fn method(&self) -> &'static str {
        match self.kernel {
            TileKernel::Classical => "tiled-classical-full-transcript",
            TileKernel::StrassenOneLevel => "tiled-strassen-one-level-full-transcript",
        }
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        let el = expand(challenge, 0, N * R)?;
        let er = expand(challenge, 1, N * R)?;
        let fl = expand(challenge, 2, N * R)?;
        let fr = expand(challenge, 3, N * R)?;
        let ap: Vec<_> = self
            .task
            .a
            .iter()
            .zip(tiled_mul(&el, &er, N, R, N, self.kernel))
            .map(|(a, e)| producer_reduce(u128::from(*a) + u128::from(e)))
            .collect();
        let bp: Vec<_> = self
            .task
            .b
            .iter()
            .zip(tiled_mul(&fl, &fr, N, R, N, self.kernel))
            .map(|(b, f)| producer_reduce(u128::from(*b) + u128::from(f)))
            .collect();
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        for bi in 0..N / R {
            for bj in 0..N / R {
                let mut cells = [0u32; R * R];
                let mut bytes = [0u8; R * R * 4];
                for bk in 0..N / R {
                    let increment = tile_product(
                        &tile(&ap, N, bi * R, bk * R),
                        &tile(&bp, N, bk * R, bj * R),
                        self.kernel,
                    );
                    for (pos, (value, delta)) in cells.iter_mut().zip(increment).enumerate() {
                        *value = producer_reduce(u128::from(*value) + delta);
                        bytes[pos * 4..pos * 4 + 4].copy_from_slice(&value.to_le_bytes());
                    }
                    transcript.update(bytes);
                }
            }
        }
        let mut proof = self.task.prefix.clone();
        proof.extend_from_slice(&transcript.finalize());
        Ok(proof)
    }
}

fn tile(matrix: &[u32], width: usize, row: usize, column: usize) -> [u32; R * R] {
    let mut result = [0; R * R];
    for i in 0..R {
        result[i * R..(i + 1) * R]
            .copy_from_slice(&matrix[(row + i) * width + column..(row + i) * width + column + R]);
    }
    result
}

fn tiled_mul(
    a: &[u32],
    b: &[u32],
    rows: usize,
    inner: usize,
    cols: usize,
    kernel: TileKernel,
) -> Vec<u32> {
    debug_assert!(rows.is_multiple_of(R) && inner.is_multiple_of(R) && cols.is_multiple_of(R));
    let mut result = vec![0; rows * cols];
    for row in (0..rows).step_by(R) {
        for column in (0..cols).step_by(R) {
            let mut cells = [0u32; R * R];
            for k in (0..inner).step_by(R) {
                let increment =
                    tile_product(&tile(a, inner, row, k), &tile(b, cols, k, column), kernel);
                for (value, delta) in cells.iter_mut().zip(increment) {
                    *value = producer_reduce(u128::from(*value) + delta);
                }
            }
            for i in 0..R {
                result[(row + i) * cols + column..(row + i) * cols + column + R]
                    .copy_from_slice(&cells[i * R..(i + 1) * R]);
            }
        }
    }
    result
}

// Return the exact nonnegative integer 8x8 product, before field reduction. All
// input cells are canonical. Even signed Strassen intermediates are below 2^71;
// i128 has ample headroom and final dot products are below 8*q^2 < 2^67.
fn tile_product(a: &[u32; R * R], b: &[u32; R * R], kernel: TileKernel) -> [u128; R * R] {
    if kernel == TileKernel::Classical {
        let mut result = [0; R * R];
        for i in 0..R {
            for j in 0..R {
                for k in 0..R {
                    result[i * R + j] += u128::from(a[i * R + k]) * u128::from(b[k * R + j]);
                }
            }
        }
        return result;
    }
    const H: usize = R / 2;
    type Half = [i64; H * H];
    let quadrant = |matrix: &[u32; R * R], row: usize, column: usize| -> Half {
        std::array::from_fn(|i| i64::from(matrix[(row + i / H) * R + column + i % H]))
    };
    let combine = |left: &Half, right: &Half, sign: i64| -> Half {
        std::array::from_fn(|i| left[i] + sign * right[i])
    };
    let multiply = |left: &Half, right: &Half| -> [i128; H * H] {
        std::array::from_fn(|index| {
            (0..H)
                .map(|k| i128::from(left[index / H * H + k]) * i128::from(right[k * H + index % H]))
                .sum()
        })
    };
    let [a11, a12, a21, a22] = [
        quadrant(a, 0, 0),
        quadrant(a, 0, H),
        quadrant(a, H, 0),
        quadrant(a, H, H),
    ];
    let [b11, b12, b21, b22] = [
        quadrant(b, 0, 0),
        quadrant(b, 0, H),
        quadrant(b, H, 0),
        quadrant(b, H, H),
    ];
    let m1 = multiply(&combine(&a11, &a22, 1), &combine(&b11, &b22, 1));
    let m2 = multiply(&combine(&a21, &a22, 1), &b11);
    let m3 = multiply(&a11, &combine(&b12, &b22, -1));
    let m4 = multiply(&a22, &combine(&b21, &b11, -1));
    let m5 = multiply(&combine(&a11, &a12, 1), &b22);
    let m6 = multiply(&combine(&a21, &a11, -1), &combine(&b11, &b12, 1));
    let m7 = multiply(&combine(&a12, &a22, -1), &combine(&b21, &b22, 1));
    std::array::from_fn(|index| {
        let i = (index / R % H) * H + index % H;
        let value = match (index / R < H, index % R < H) {
            (true, true) => m1[i] + m4[i] - m5[i] + m7[i],
            (true, false) => m3[i] + m5[i],
            (false, true) => m2[i] + m4[i],
            (false, false) => m1[i] - m2[i] + m3[i] + m6[i],
        };
        debug_assert!((0..(1i128 << 67)).contains(&value));
        value as u128
    })
}

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
    fn strassen_tiles_equal_exact_integer_products_with_signed_extremes() {
        let highest = (Q - 1) as u32;
        let mut random = 0x916a_71ce_2403_ebd5u64;
        for case in 0..68 {
            let mut next = || {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                (u128::from(random) % Q) as u32
            };
            let a = std::array::from_fn(|i| match case {
                0 => 0,
                1 => highest,
                2 => {
                    if i / R < R / 2 {
                        highest
                    } else {
                        0
                    }
                }
                3 => {
                    if i % R < R / 2 {
                        0
                    } else {
                        highest
                    }
                }
                _ => next(),
            });
            let b = std::array::from_fn(|i| match case {
                0 => highest,
                1 => highest,
                2 => {
                    if i % R < R / 2 {
                        0
                    } else {
                        highest
                    }
                }
                3 => {
                    if i / R < R / 2 {
                        highest
                    } else {
                        0
                    }
                }
                _ => next(),
            });
            let actual = tile_product(&a, &b, TileKernel::StrassenOneLevel);
            let expected = tile_product(&a, &b, TileKernel::Classical);
            assert_eq!(actual, expected, "exact unreduced product, case {case}");
        }
    }

    #[test]
    fn tiled_complete_proofs_match_scalar_and_independent_python_extreme_vectors() {
        // Complete-certificate SHA256 values from the retained independent
        // formal/pon-nakamoto-v1/work_oracle.py, not either tiled implementation.
        let extreme_a: Vec<_> = (0..CELLS)
            .map(|i| (Q - 1 - (i % 17) as u128) as u32)
            .collect();
        let extreme_b: Vec<_> = (0..CELLS)
            .map(|i| {
                if i % 3 == 0 {
                    0
                } else {
                    (Q - 1 - (i % 23) as u128) as u32
                }
            })
            .collect();
        let continuity_a: Vec<_> = (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect();
        let continuity_b: Vec<_> = (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect();
        for (a, b, hashes) in [
            (
                &extreme_a,
                &extreme_b,
                [
                    "8aeb4a492cebefcbe5f190cc6d14cdf0a9c751f721955250ce677dbeea3552f2",
                    "6c9742a75455b810c5da89a79b05b28605d5c3bb3858db45addb58983aadc3b4",
                    "bbbf557425acb688e4d5f7691d34f486b05cf7e3e320db87938889b7706a6dc9",
                ],
            ),
            (
                &continuity_a,
                &continuity_b,
                [
                    "5d38a10d4e33648a96277f6faef92c46a82427f50ffb3912b147d06b593a9e3d",
                    "2c52d83c0677ce783d7b13d6f6a8f61ac416671b51c5ef9fe142655b37a5148b",
                    "7b695584cf386a9be3c8218f3f42759df2bd1c885b41d1b0d68f9c54ebf557c9",
                ],
            ),
        ] {
            let classical = TiledPreparedTask::new(a, b, TileKernel::Classical).unwrap();
            let strassen = TiledPreparedTask::new(a, b, TileKernel::StrassenOneLevel).unwrap();
            let task = task_id(a, b).unwrap();
            for (challenge_byte, expected_hash) in [0, 7, 255].into_iter().zip(hashes) {
                let challenge = [challenge_byte; 32];
                let expected = prove(challenge, a, b).unwrap();
                assert_eq!(hex::encode(Sha256::digest(&expected)), expected_hash);
                for producer in [&classical, &strassen] {
                    let proof = producer.prove(challenge).unwrap();
                    assert_eq!(proof, expected);
                    assert_eq!(
                        verify(challenge, task, [255; 32], &proof)
                            .unwrap()
                            .product(),
                        verify_reference(challenge, task, [255; 32], &proof)
                            .unwrap()
                            .product()
                    );
                }
            }
        }
    }

    #[test]
    fn tiled_task_validation_and_reuse_never_depend_on_a_previous_challenge() {
        let zero = vec![0; CELLS];
        for kernel in [TileKernel::Classical, TileKernel::StrassenOneLevel] {
            assert!(matches!(
                TiledPreparedTask::new(&[], &zero, kernel),
                Err(WorkError::Length)
            ));
            assert!(matches!(
                TiledPreparedTask::new(&zero, &vec![u32::MAX; CELLS], kernel),
                Err(WorkError::Field)
            ));
            let prepared = TiledPreparedTask::new(&zero, &zero, kernel).unwrap();
            let first = prepared.prove([7; 32]).unwrap();
            let different = prepared.prove([8; 32]).unwrap();
            assert_ne!(&first[PROOF_BYTES - 32..], &different[PROOF_BYTES - 32..]);
            assert_eq!(first, prepared.prove([7; 32]).unwrap());
            assert_eq!(different, prove([8; 32], &zero, &zero).unwrap());
        }
    }

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
