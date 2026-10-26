//! Research-only zero W1 producer: blocked reassociation, two Strassen levels,
//! then exact integer-paired leaves. Every canonical prefix is still hashed.
//! This changes no verifier, task eligibility, challenge, target or work credit.
//! Scalar products fall from 152,832 to 126,864; additions/reductions increase.
//! That count is not a CPU-speed, energy or minimum-work claim.
use sha2::{Digest, Sha256};
use trnm_crypto_primitives::pon_work::{self, Hash, WorkError, CELLS, N, PROOF_BYTES, Q, R};

const BLOCKS: usize = N / R;
const LEAVES: usize = 49;
type Tile = [u32; R * R];
type Four = [u32; 16];
type Two = [u32; 4];

#[derive(Clone, Copy, Default)]
struct Leaf {
    // Left: two rows. Right: two transposed columns.
    words: Two,
    factors: [u128; 2],
}

#[derive(Clone, Copy)]
struct Prepared {
    leaves: [Leaf; LEAVES],
}

/// The constructor checks both complete operands. Unsupported canonical
/// nonzero operands return None; there is no hidden generic fallback.
pub struct ZeroStrassen {
    prefix: Vec<u8>,
}

impl ZeroStrassen {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        if a.len() != CELLS || b.len() != CELLS {
            return Err(WorkError::Length);
        }
        if a.iter().chain(b).any(|value| u128::from(*value) >= Q) {
            return Err(WorkError::Field);
        }
        if a.iter().chain(b).any(|value| *value != 0) {
            return Ok(None);
        }
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        prefix.resize(PROOF_BYTES - 32, 0);
        Ok(Some(Self { prefix }))
    }

    /// This one complete generation is atomic to the caller. It has no parent
    /// authority or budget bypass; the caller must exclude late delivered work.
    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        let el = expand(challenge, 0)?;
        let er = expand(challenge, 1)?;
        let fl = expand(challenge, 2)?;
        let fr = expand(challenge, 3)?;
        let mut trace = Sha256::new();
        trace.update(b"TRNM-PON-TRACE1\0");
        trace.update(challenge);
        transcript(&el, &er, &fl, &fr, |tile| {
            let mut bytes = [0; R * R * 4];
            for (word, encoded) in tile.iter().zip(bytes.chunks_exact_mut(4)) {
                encoded.copy_from_slice(&word.to_le_bytes());
            }
            trace.update(bytes);
        });
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&trace.finalize());
        Ok(proof)
    }
}

fn expand(challenge: Hash, label: u8) -> Result<Vec<u32>, WorkError> {
    let mut output = Vec::with_capacity(N * R);
    for counter in 0_u32..128 {
        let digest = pon_work::hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
        for encoded in digest.chunks_exact(4) {
            let value = u32::from_le_bytes(encoded.try_into().expect("four bytes"));
            if u128::from(value) < Q {
                output.push(value);
                if output.len() == N * R {
                    return Ok(output);
                }
            }
        }
    }
    Err(WorkError::NoiseBudget)
}

// After exact factor subtraction, at most eight canonical products remain:
// x <= 8(q-1)^2 < 2^67. This two-fold reduction also accepts x < 2^70.
fn reduce(x: u128) -> u32 {
    debug_assert!(x < (1_u128 << 70));
    let first = (x as u32 as u64) + 5 * ((x >> 32) as u64);
    let second = (first as u32 as u64) + 5 * (first >> 32);
    if second >= Q as u64 {
        (second - Q as u64) as u32
    } else {
        second as u32
    }
}

fn add(a: u32, b: u32) -> u32 {
    let sum = u64::from(a) + u64::from(b);
    if sum >= Q as u64 {
        (sum - Q as u64) as u32
    } else {
        sum as u32
    }
}

fn sub(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        Q as u32 - (b - a)
    }
}

fn factor(values: &[u32]) -> u128 {
    values
        .chunks_exact(2)
        .map(|pair| u128::from(pair[0]) * u128::from(pair[1]))
        .sum()
}

fn dot(left: &[u32], right: &[u32], lf: u128, rf: u128) -> u32 {
    debug_assert_eq!(left.len(), right.len());
    debug_assert!(left.len() <= R && left.len().is_multiple_of(2));
    let sum: u128 = left
        .chunks_exact(2)
        .zip(right.chunks_exact(2))
        .map(|(a, b)| (u128::from(a[0]) + u128::from(b[1])) * (u128::from(a[1]) + u128::from(b[0])))
        .sum();
    debug_assert!(sum >= lf + rf);
    reduce(sum - lf - rf)
}

fn split8(input: &Tile) -> [Four; 4] {
    std::array::from_fn(|quadrant| {
        std::array::from_fn(|position| {
            let row = (quadrant / 2) * 4 + position / 4;
            let column = (quadrant % 2) * 4 + position % 4;
            input[row * R + column]
        })
    })
}

fn split4(input: &Four) -> [Two; 4] {
    std::array::from_fn(|quadrant| {
        std::array::from_fn(|position| {
            let row = (quadrant / 2) * 2 + position / 2;
            let column = (quadrant % 2) * 2 + position % 2;
            input[row * 4 + column]
        })
    })
}

fn operands<const SIZE: usize>(q: &[[u32; SIZE]; 4], right: bool) -> [[u32; SIZE]; 7] {
    let plus = |a: usize, b: usize| std::array::from_fn(|i| add(q[a][i], q[b][i]));
    let minus = |a: usize, b: usize| std::array::from_fn(|i| sub(q[a][i], q[b][i]));
    if right {
        [
            plus(0, 3),
            q[0],
            minus(1, 3),
            minus(2, 0),
            q[3],
            plus(0, 1),
            plus(2, 3),
        ]
    } else {
        [
            plus(0, 3),
            plus(2, 3),
            q[0],
            q[3],
            plus(0, 1),
            minus(2, 0),
            minus(1, 3),
        ]
    }
}

fn prepare(input: &Tile, right: bool) -> Prepared {
    let mut leaves = [Leaf::default(); LEAVES];
    for (outer, four) in operands(&split8(input), right).iter().enumerate() {
        for (inner, two) in operands(&split4(four), right).iter().enumerate() {
            let words = if right {
                [two[0], two[2], two[1], two[3]]
            } else {
                *two
            };
            leaves[outer * 7 + inner] = Leaf {
                words,
                factors: [
                    u128::from(words[0]) * u128::from(words[1]),
                    u128::from(words[2]) * u128::from(words[3]),
                ],
            };
        }
    }
    Prepared { leaves }
}

fn combine<const SMALL: usize, const LARGE: usize>(
    products: &[[u32; SMALL]; 7],
    half: usize,
) -> [u32; LARGE] {
    debug_assert_eq!(SMALL, half * half);
    debug_assert_eq!(LARGE, 4 * SMALL);
    let mut output = [0; LARGE];
    for position in 0..SMALL {
        let [p1, p2, p3, p4, p5, p6, p7] = products.map(|p| p[position]);
        let quadrants = [
            add(sub(add(p1, p4), p5), p7),
            add(p3, p5),
            add(p2, p4),
            add(add(sub(p1, p2), p3), p6),
        ];
        for (quadrant, value) in quadrants.into_iter().enumerate() {
            let row = (quadrant / 2) * half + position / half;
            let column = (quadrant % 2) * half + position % half;
            output[row * (2 * half) + column] = value;
        }
    }
    output
}

fn prepared_product(a: &Prepared, b: &Prepared) -> Tile {
    let mut fours = [[0; 16]; 7];
    for (outer, four) in fours.iter_mut().enumerate() {
        let twos: [Two; 7] = std::array::from_fn(|inner| {
            let left = a.leaves[outer * 7 + inner];
            let right = b.leaves[outer * 7 + inner];
            std::array::from_fn(|position| {
                let row = position / 2;
                let column = position % 2;
                dot(
                    &left.words[row * 2..row * 2 + 2],
                    &right.words[column * 2..column * 2 + 2],
                    left.factors[row],
                    right.factors[column],
                )
            })
        });
        *four = combine(&twos, 2);
    }
    combine(&fours, 4)
}

// Same S and L integer-pair schedule as blocked_zero_paired. Only the output
// L_tile*FR_tile stage changes; right leaf factors are reused across bi,bk and
// left leaf factors across bj. Holding one bi's eight left preparations preserves
// canonical bi,bj,bk,i,j order without retaining the 131,072 prefix bytes.
fn transcript(el: &[u32], er: &[u32], fl: &[u32], fr: &[u32], mut emit: impl FnMut(&Tile)) {
    let mut middles = [[0; R * R]; BLOCKS];
    let mut current = [0; R * R];
    for (bk, middle) in middles.iter_mut().enumerate() {
        let right: Tile = std::array::from_fn(|position| {
            let column = position / R;
            let k = position % R;
            fl[(bk * R + k) * R + column]
        });
        let left_factors: [u128; R] =
            std::array::from_fn(|row| factor(&er[row * N + bk * R..row * N + (bk + 1) * R]));
        let right_factors: [u128; R] =
            std::array::from_fn(|column| factor(&right[column * R..(column + 1) * R]));
        for row in 0..R {
            for column in 0..R {
                current[row * R + column] = add(
                    current[row * R + column],
                    dot(
                        &er[row * N + bk * R..row * N + (bk + 1) * R],
                        &right[column * R..(column + 1) * R],
                        left_factors[row],
                        right_factors[column],
                    ),
                );
                middle[column * R + row] = current[row * R + column];
            }
        }
    }
    let el_factors: [u128; N] = std::array::from_fn(|row| factor(&el[row * R..(row + 1) * R]));
    let middle_factors: [[u128; R]; BLOCKS] = std::array::from_fn(|bk| {
        std::array::from_fn(|column| factor(&middles[bk][column * R..(column + 1) * R]))
    });
    let rights: [Prepared; BLOCKS] = std::array::from_fn(|bj| {
        let tile = std::array::from_fn(|position| fr[(position / R) * N + bj * R + position % R]);
        prepare(&tile, true)
    });
    for bi in 0..BLOCKS {
        let lefts: [Prepared; BLOCKS] = std::array::from_fn(|bk| {
            let tile = std::array::from_fn(|position| {
                let row = bi * R + position / R;
                let column = position % R;
                dot(
                    &el[row * R..(row + 1) * R],
                    &middles[bk][column * R..(column + 1) * R],
                    el_factors[row],
                    middle_factors[bk][column],
                )
            });
            prepare(&tile, false)
        });
        for right in &rights {
            for left in &lefts {
                emit(&prepared_product(left, right));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(a: &Tile, b: &Tile) -> Tile {
        std::array::from_fn(|position| {
            let row = position / R;
            let column = position % R;
            let value: u128 = (0..R)
                .map(|k| u128::from(a[row * R + k]) * u128::from(b[k * R + column]))
                .sum();
            (value % Q) as u32
        })
    }

    #[test]
    fn paired_strassen_matches_naive_near_q_and_degenerate_tiles() {
        for mode in 0_u32..4 {
            let a: Tile = std::array::from_fn(|i| match mode {
                0 => 0,
                1 => Q as u32 - 1,
                _ => Q as u32 - 1 - (17 * i as u32 + mode),
            });
            let b: Tile = std::array::from_fn(|i| match mode {
                0 => 1,
                1 => u32::from(i / R == i % R),
                _ => (13 * i as u32 + mode) % Q as u32,
            });
            assert_eq!(
                prepared_product(&prepare(&a, false), &prepare(&b, true)),
                naive(&a, &b)
            );
        }
    }

    #[test]
    fn every_prefix_matches_direct_perturbed_zero_multiplication() {
        let el = expand([7; 32], 0).unwrap();
        let er = expand([7; 32], 1).unwrap();
        let fl = expand([7; 32], 2).unwrap();
        let fr = expand([7; 32], 3).unwrap();
        let e: Vec<u32> = (0..CELLS)
            .map(|position| {
                (0..R)
                    .map(|k| {
                        u128::from(el[(position / N) * R + k])
                            * u128::from(er[k * N + position % N])
                    })
                    .sum::<u128>()
                    % Q
            })
            .map(|x| x as u32)
            .collect();
        let f: Vec<u32> = (0..CELLS)
            .map(|position| {
                (0..R)
                    .map(|k| {
                        u128::from(fl[(position / N) * R + k])
                            * u128::from(fr[k * N + position % N])
                    })
                    .sum::<u128>()
                    % Q
            })
            .map(|x| x as u32)
            .collect();
        let mut expected = Vec::new();
        for bi in 0..BLOCKS {
            for bj in 0..BLOCKS {
                for bk in 0..BLOCKS {
                    for i in bi * R..(bi + 1) * R {
                        for j in bj * R..(bj + 1) * R {
                            expected.push(
                                ((0..(bk + 1) * R)
                                    .map(|k| u128::from(e[i * N + k]) * u128::from(f[k * N + j]))
                                    .sum::<u128>()
                                    % Q) as u32,
                            );
                        }
                    }
                }
            }
        }
        let mut actual = Vec::new();
        transcript(&el, &er, &fl, &fr, |tile| actual.extend_from_slice(tile));
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 32768);
    }

    #[test]
    fn full_proof_matches_original_and_zero_eligibility_is_strict() {
        let zero = vec![0; CELLS];
        let prepared = ZeroStrassen::new(&zero, &zero).unwrap().unwrap();
        for challenge in [[0; 32], [7; 32], [255; 32]] {
            let proof = prepared.prove(challenge).unwrap();
            assert_eq!(proof, pon_work::prove(challenge, &zero, &zero).unwrap());
            assert_eq!(proof.len(), PROOF_BYTES);
            pon_work::verify(
                challenge,
                pon_work::task_id(&zero, &zero).unwrap(),
                [255; 32],
                &proof,
            )
            .unwrap();
        }
        let mut nonzero = zero.clone();
        nonzero[CELLS - 1] = 1;
        assert!(ZeroStrassen::new(&nonzero, &zero).unwrap().is_none());
        assert!(ZeroStrassen::new(&zero, &nonzero).unwrap().is_none());
        nonzero[CELLS - 1] = Q as u32;
        assert!(matches!(
            ZeroStrassen::new(&nonzero, &zero),
            Err(WorkError::Field)
        ));
        assert!(matches!(
            ZeroStrassen::new(&zero[..CELLS - 1], &zero),
            Err(WorkError::Length)
        ));
    }
}
