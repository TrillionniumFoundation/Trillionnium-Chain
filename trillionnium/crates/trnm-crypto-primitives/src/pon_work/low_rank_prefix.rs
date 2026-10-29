//! A legal adversarial producer for arbitrary rank <= 8 task matrices.
//!
//! For A = U V and B = X Y, form thin factorizations of the challenged inputs:
//! A' = [U EL] [V; ER], B' = [X FL] [Y; FR].  Every required cumulative prefix
//! is L (sum_{k < prefix} R[:, k] S[k, :]) T.  This computes ALL original
//! prefix values and hashes them in the original bi,bj,bk,i,j order.
//!
//! Factor discovery, exact reconstruction, and the useful product are charged
//! setup.  No claim is made that this is cheaper than all existing producers.
//! This module cannot construct upstream VerifiedWork or alter its verifier.
use crate::pon_work::{hash, task_id, Hash, WorkError, CELLS, N, PROOF_BYTES, Q, R};
use sha2::{Digest, Sha256};

pub const MAX_TASK_RANK: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kernel {
    Scalar,
    Paired,
}

fn reduce(x: u128) -> u32 {
    // All private callers have inner <= 64. Even the paired identity is below
    // 32*(2*q)^2 + q^2 < 2^72. Since 2^32 == 5 mod q, two folds preserve the
    // residue. The first fits u64; the second is below 2*q, so one subtraction
    // gives the canonical field value. No high bits are discarded.
    debug_assert!(x < (1_u128 << 72));
    let first = u64::from(x as u32) + 5 * ((x >> 32) as u64);
    let second = u64::from(first as u32) + 5 * (first >> 32);
    if second >= Q as u64 {
        (second - Q as u64) as u32
    } else {
        second as u32
    }
}

fn inverse(value: u32) -> u32 {
    let mut x = u128::from(value);
    let mut result = 1_u128;
    let mut exponent = Q - 2;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = u128::from(reduce(result * x));
        }
        x = u128::from(reduce(x * x));
        exponent >>= 1;
    }
    result as u32
}

/// Exact rank factorization from input bytes, not a trusted rank claim.
fn factor(matrix: &[u32]) -> Option<(Vec<u32>, Vec<u32>, usize)> {
    let mut reduced = matrix.to_vec();
    let mut columns = Vec::new();
    for col in 0..N {
        let row = columns.len();
        let Some(pivot) = (row..N).find(|i| reduced[*i * N + col] != 0) else {
            continue;
        };
        if row == MAX_TASK_RANK {
            return None;
        }
        for j in 0..N {
            reduced.swap(row * N + j, pivot * N + j);
        }
        let reciprocal = inverse(reduced[row * N + col]);
        for j in col..N {
            reduced[row * N + j] =
                reduce(u128::from(reduced[row * N + j]) * u128::from(reciprocal));
        }
        for i in 0..N {
            if i == row {
                continue;
            }
            let scale = u128::from(reduced[i * N + col]);
            if scale == 0 {
                continue;
            }
            for j in col..N {
                let subtract = u128::from(reduce(scale * u128::from(reduced[row * N + j])));
                reduced[i * N + j] = reduce(u128::from(reduced[i * N + j]) + Q - subtract);
            }
        }
        columns.push(col);
    }
    let rank = columns.len();
    let left: Vec<_> = (0..N)
        .flat_map(|i| columns.iter().map(move |j| matrix[i * N + *j]))
        .collect();
    let right = reduced[..rank * N].to_vec();
    // A failed factorization is not silently accepted or sent to a fallback.
    if multiply(&left, &right, N, rank, N, Kernel::Scalar) != matrix {
        return None;
    }
    Some((left, right, rank))
}

fn multiply(
    a: &[u32],
    b: &[u32],
    rows: usize,
    inner: usize,
    cols: usize,
    kernel: Kernel,
) -> Vec<u32> {
    let mut out = vec![0; rows * cols];
    assert_eq!(a.len(), rows * inner);
    assert_eq!(b.len(), inner * cols);
    if inner == 0 {
        return out;
    }
    let mut transposed = vec![0; b.len()];
    for k in 0..inner {
        for j in 0..cols {
            transposed[j * inner + k] = b[k * cols + j];
        }
    }
    let mut row_corrections = vec![0_u32; rows];
    let mut column_corrections = vec![0_u32; cols];
    if kernel == Kernel::Paired {
        for i in 0..rows {
            row_corrections[i] = reduce(
                (0..inner / 2)
                    .map(|k| {
                        u128::from(a[i * inner + 2 * k]) * u128::from(a[i * inner + 2 * k + 1])
                    })
                    .sum(),
            );
        }
        for j in 0..cols {
            column_corrections[j] = reduce(
                (0..inner / 2)
                    .map(|k| {
                        u128::from(transposed[j * inner + 2 * k])
                            * u128::from(transposed[j * inner + 2 * k + 1])
                    })
                    .sum(),
            );
        }
    }
    for i in 0..rows {
        let left = &a[i * inner..(i + 1) * inner];
        for j in 0..cols {
            let right = &transposed[j * inner..(j + 1) * inner];
            let value = if kernel == Kernel::Scalar {
                reduce(
                    left.iter()
                        .zip(right)
                        .map(|(x, y)| u128::from(*x) * u128::from(*y))
                        .sum(),
                )
            } else {
                let paired: u128 = (0..inner / 2)
                    .map(|k| {
                        (u128::from(left[2 * k]) + u128::from(right[2 * k + 1]))
                            * (u128::from(left[2 * k + 1]) + u128::from(right[2 * k]))
                    })
                    .sum();
                let odd = if inner % 2 == 1 {
                    u128::from(left[inner - 1]) * u128::from(right[inner - 1])
                } else {
                    0
                };
                reduce(
                    u128::from(reduce(paired + odd)) + 2 * Q
                        - u128::from(row_corrections[i])
                        - u128::from(column_corrections[j]),
                )
            };
            out[i * cols + j] = value;
        }
    }
    out
}

fn expand(challenge: Hash, label: u8) -> Result<Vec<u32>, WorkError> {
    let mut values = Vec::with_capacity(N * R);
    for counter in 0_u32..128 {
        let digest = hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
        for bytes in digest.chunks_exact(4) {
            let x = u32::from_le_bytes(bytes.try_into().unwrap());
            if u128::from(x) < Q {
                values.push(x);
                if values.len() == N * R {
                    return Ok(values);
                }
            }
        }
    }
    Err(WorkError::NoiseBudget)
}

pub struct LowRankPrefixPrepared {
    a_left: Vec<u32>,
    a_right: Vec<u32>,
    b_left: Vec<u32>,
    b_right: Vec<u32>,
    rank_a: usize,
    rank_b: usize,
    prefix: Vec<u8>,
    kernel: Kernel,
}

impl LowRankPrefixPrepared {
    pub fn new(a: &[u32], b: &[u32], kernel: Kernel) -> Result<Option<Self>, WorkError> {
        task_id(a, b)?;
        let Some((a_left, a_right, rank_a)) = factor(a) else {
            return Ok(None);
        };
        let Some((b_left, b_right, rank_b)) = factor(b) else {
            return Ok(None);
        };
        let middle = multiply(&a_right, &b_left, rank_a, N, rank_b, kernel);
        let left = multiply(&a_left, &middle, N, rank_a, rank_b, kernel);
        let product = multiply(&left, &b_right, N, rank_b, N, kernel);
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for values in [a, b, product.as_slice()] {
            for value in values {
                prefix.extend_from_slice(&value.to_le_bytes());
            }
        }
        Ok(Some(Self {
            a_left,
            a_right,
            b_left,
            b_right,
            rank_a,
            rank_b,
            prefix,
            kernel,
        }))
    }

    pub fn ranks(&self) -> (usize, usize) {
        (self.rank_a, self.rank_b)
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        let el = expand(challenge, 0)?;
        let er = expand(challenge, 1)?;
        let fl = expand(challenge, 2)?;
        let fr = expand(challenge, 3)?;
        let ra = self.rank_a + R;
        let rb = self.rank_b + R;
        let mut left = Vec::with_capacity(N * ra);
        let mut right = self.a_right.clone();
        right.extend_from_slice(&er);
        let mut second_left = Vec::with_capacity(N * rb);
        let mut second_right = self.b_right.clone();
        second_right.extend_from_slice(&fr);
        for i in 0..N {
            left.extend_from_slice(&self.a_left[i * self.rank_a..(i + 1) * self.rank_a]);
            left.extend_from_slice(&el[i * R..(i + 1) * R]);
            second_left.extend_from_slice(&self.b_left[i * self.rank_b..(i + 1) * self.rank_b]);
            second_left.extend_from_slice(&fl[i * R..(i + 1) * R]);
        }
        let mut middle = vec![0; ra * rb];
        let mut prefixes = Vec::with_capacity(N / R);
        for bk in 0..N / R {
            for i in 0..ra {
                for j in 0..rb {
                    middle[i * rb + j] = reduce(
                        u128::from(middle[i * rb + j])
                            + (bk * R..(bk + 1) * R)
                                .map(|k| {
                                    u128::from(right[i * N + k])
                                        * u128::from(second_left[k * rb + j])
                                })
                                .sum::<u128>(),
                    );
                }
            }
            let mixed = multiply(&left, &middle, N, ra, rb, self.kernel);
            prefixes.push(multiply(&mixed, &second_right, N, rb, N, self.kernel));
        }
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        let mut tile = [0_u8; R * R * 4];
        for bi in 0..N / R {
            for bj in 0..N / R {
                for prefix in &prefixes {
                    for i in 0..R {
                        for j in 0..R {
                            let value = prefix[(bi * R + i) * N + bj * R + j];
                            tile[(i * R + j) * 4..(i * R + j + 1) * 4]
                                .copy_from_slice(&value.to_le_bytes());
                        }
                    }
                    transcript.update(tile);
                }
            }
        }
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&transcript.finalize());
        debug_assert_eq!(proof.len(), 4 + CELLS * 12 + 32);
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work;

    #[test]
    fn folded_reduction_matches_remainder_at_carries_and_full_private_bound() {
        for x in [
            0,
            1,
            Q - 1,
            Q,
            Q + 1,
            2 * Q - 1,
            (1_u128 << 32) - 1,
            1_u128 << 32,
            (1_u128 << 64) - 1,
            1_u128 << 64,
            (1_u128 << 70) - 1,
            (1_u128 << 71) - 1,
            (1_u128 << 72) - 1,
        ] {
            assert_eq!(u128::from(reduce(x)), x % Q);
        }
        let mut seed = 0x76543210fedcba98_u128;
        for _ in 0..10000 {
            seed = seed
                .wrapping_mul(0x27bb2ee687b0b0fd)
                .wrapping_add(0xb504f32d);
            let x = seed & ((1_u128 << 72) - 1);
            assert_eq!(u128::from(reduce(x)), x % Q);
        }
    }

    fn low_rank(rank: usize, seed: u32) -> Vec<u32> {
        let l: Vec<_> = (0..N * rank)
            .map(|i| reduce(Q - 1 - (i as u128 * 17 + u128::from(seed)) % 997))
            .collect();
        let r: Vec<_> = (0..rank * N)
            .map(|i| reduce(Q - 1 - (i as u128 * 29 + u128::from(seed) * 7) % 991))
            .collect();
        multiply(&l, &r, N, rank, N, Kernel::Scalar)
    }

    #[test]
    fn paired_product_handles_odd_even_zero_and_high_words() {
        for inner in 0..=16 {
            let a: Vec<_> = (0..5 * inner).map(|i| (Q - 1 - i as u128) as u32).collect();
            let b: Vec<_> = (0..7 * inner)
                .map(|i| (Q - 1 - 3 * i as u128) as u32)
                .collect();
            assert_eq!(
                multiply(&a, &b, 5, inner, 7, Kernel::Paired),
                multiply(&a, &b, 5, inner, 7, Kernel::Scalar)
            );
        }
    }

    #[test]
    fn every_low_rank_prefix_matches_full_upstream_transcript() {
        for (ra, rb) in [(0, 0), (0, 1), (1, 0), (1, 1), (2, 4), (4, 8), (8, 8)] {
            let a = low_rank(ra, 1);
            let b = low_rank(rb, 3);
            for kernel in [Kernel::Scalar, Kernel::Paired] {
                let prepared = LowRankPrefixPrepared::new(&a, &b, kernel).unwrap().unwrap();
                for challenge in [[0; 32], [255; 32], [7; 32]] {
                    let actual = prepared.prove(challenge).unwrap();
                    assert_eq!(
                        actual,
                        pon_work::prove(challenge, &a, &b).unwrap(),
                        "rank {ra}/{rb} kernel {kernel:?}"
                    );
                    pon_work::verify(challenge, task_id(&a, &b).unwrap(), [255; 32], &actual)
                        .unwrap();
                }
            }
        }
    }

    #[test]
    fn unsupported_or_noncanonical_material_never_silently_falls_back() {
        let identity: Vec<_> = (0..CELLS).map(|i| u32::from(i / N == i % N)).collect();
        assert!(
            LowRankPrefixPrepared::new(&identity, &identity, Kernel::Paired)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            LowRankPrefixPrepared::new(&[0; 3], &identity, Kernel::Paired),
            Err(WorkError::Length)
        ));
        let mut bad = vec![0; CELLS];
        bad[7] = Q as u32;
        assert!(matches!(
            LowRankPrefixPrepared::new(&bad, &bad, Kernel::Paired),
            Err(WorkError::Field)
        ));
    }
}
