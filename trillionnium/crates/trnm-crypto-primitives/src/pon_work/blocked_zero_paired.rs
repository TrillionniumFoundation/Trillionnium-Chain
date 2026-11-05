//! Complete zero/zero W1 production by blocked reassociation and integer pairs.
//! Every original transcript word remains; this separate research producer owns
//! no current-parent admission or verification authority and changes no default.
use super::{
    expand_with_progress, integer_paired, validate, Hash, VerificationError, VerificationProgress,
    WorkError, N, PROOF_BYTES, R,
};
use sha2::{Digest, Sha256};

const BLOCKS: usize = N / R;
type Tile = [u32; R * R];
type Prefixes = [Tile; BLOCKS];
type Factors = [[u128; R]; BLOCKS];

/// Observations precede bounded local work. They are not fields of a proof and
/// do not promise the checkpoint order of a different generation algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationProgress {
    BeforeReplay,
    Noise {
        label: u8,
        counter: u32,
    },
    MiddleBlock {
        inner: usize,
    },
    OuterFactor {
        operand: u8,
        row: usize,
    },
    LeftTile {
        row: usize,
        inner: usize,
    },
    TranscriptTile {
        row: usize,
        column: usize,
        inner: usize,
    },
    BeforeProof,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GenerationError<E> {
    Relation(WorkError),
    Cancelled(E),
}

/// Exact A=B=0 preparation. Both complete canonical operands are checked inside
/// the constructor. Unsupported material returns None without a generic fallback.
pub struct BlockedZeroPairedPreparedTask {
    prefix: Vec<u8>,
}

impl BlockedZeroPairedPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        validate(a)?;
        validate(b)?;
        if a.iter().chain(b).any(|value| *value != 0) {
            return Ok(None);
        }
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        prefix.resize(PROOF_BYTES - 32, 0);
        Ok(Some(Self { prefix }))
    }

    pub fn method(&self) -> &'static str {
        "blocked-zero-integer-paired-full-prefix-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self.prove_with_progress(challenge, |_| Ok::<_, std::convert::Infallible>(())) {
            Ok(proof) => Ok(proof),
            Err(GenerationError::Relation(error)) => Err(error),
            Err(GenerationError::Cancelled(impossible)) => match impossible {},
        }
    }

    /// Recomputes every noise array, middle prefix and paired factor. Cancellation
    /// returns no proof and leaves only exact zero material for a fresh call.
    /// Construction, transposes, allocation and work between calls are bounded
    /// but not asynchronously preempted; this is not a wall-time cancellation SLA.
    pub fn prove_with_progress<E>(
        &self,
        challenge: Hash,
        mut progress: impl FnMut(GenerationProgress) -> Result<(), E>,
    ) -> Result<Vec<u8>, GenerationError<E>> {
        progress(GenerationProgress::BeforeReplay).map_err(GenerationError::Cancelled)?;
        let mut noise = |label| {
            expand_with_progress(challenge, label, N * R, &mut |point| {
                let VerificationProgress::Noise { label, counter } = point else {
                    unreachable!("noise expansion emits only noise observations")
                };
                progress(GenerationProgress::Noise { label, counter })
            })
            .map_err(|error| match error {
                VerificationError::Relation(error) => GenerationError::Relation(error),
                VerificationError::Cancelled(error) => GenerationError::Cancelled(error),
            })
        };
        let el = noise(0)?;
        let er = noise(1)?;
        let fl = noise(2)?;
        let fr = noise(3)?;
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        transcript_tiles(&el, &er, &fl, &fr, &mut progress, |bytes| {
            transcript.update(bytes)
        })?;
        progress(GenerationProgress::BeforeProof).map_err(GenerationError::Cancelled)?;
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&transcript.finalize());
        Ok(proof)
    }
}

// S_k=ER[:,0:8k]*FL[0:8k,:]. Retain eight transposed 8x8 S matrices (2 KiB)
// and their column factors (1 KiB). The integer-pair helper widens before each
// sum, subtracts exact factors, then reduces the nonnegative result below 2^67.
// Per challenge: eight times (64*4 cross products + 16*4 input-factor products)
// is 2,560. S column factors below belong to the subsequent L multiplication.
fn middle_prefixes<E>(
    er: &[u32],
    fl: &[u32],
    progress: &mut impl FnMut(GenerationProgress) -> Result<(), E>,
) -> Result<(Prefixes, Factors), GenerationError<E>> {
    let mut prefixes = [[0; R * R]; BLOCKS];
    let mut factors = [[0; R]; BLOCKS];
    let mut middle = [0; R * R];
    for block in 0..BLOCKS {
        progress(GenerationProgress::MiddleBlock { inner: block })
            .map_err(GenerationError::Cancelled)?;
        let mut right = [0; R * R];
        for row in 0..R {
            for column in 0..R {
                right[column * R + row] = fl[(block * R + row) * R + column];
            }
        }
        let left_factors: [u128; R] = std::array::from_fn(|row| {
            integer_paired::factor(&er[row * N + block * R..row * N + (block + 1) * R])
        });
        let right_factors: [u128; R] = std::array::from_fn(|column| {
            integer_paired::factor(&right[column * R..(column + 1) * R])
        });
        for row in 0..R {
            for column in 0..R {
                let position = row * R + column;
                middle[position] = integer_paired::dot(
                    &er[row * N + block * R..row * N + (block + 1) * R],
                    &right[column * R..(column + 1) * R],
                    left_factors[row],
                    right_factors[column],
                    middle[position],
                );
                prefixes[block][column * R + row] = middle[position];
            }
        }
        for column in 0..R {
            factors[block][column] =
                integer_paired::factor(&prefixes[block][column * R..(column + 1) * R]);
        }
    }
    Ok((prefixes, factors))
}

// L_k=EL*S_k, retaining only the current eight output rows. Its eight 8x8
// matrices occupy another 2 KiB and row factors 1 KiB. EL factors are reused
// across k, S factors across output rows, all inside this one challenge.
// L costs 8*64*8*4 + 64*4 + 8*8*4 =16,896 products including those input factors.
fn left_prefixes<E>(
    el: &[u32],
    el_factors: &[u128; N],
    middle: &Prefixes,
    middle_factors: &Factors,
    row_tile: usize,
    progress: &mut impl FnMut(GenerationProgress) -> Result<(), E>,
) -> Result<(Prefixes, Factors), GenerationError<E>> {
    let mut left = [[0; R * R]; BLOCKS];
    let mut factors = [[0; R]; BLOCKS];
    for block in 0..BLOCKS {
        progress(GenerationProgress::LeftTile {
            row: row_tile,
            inner: block,
        })
        .map_err(GenerationError::Cancelled)?;
        for local_row in 0..R {
            let row = row_tile * R + local_row;
            for column in 0..R {
                left[block][local_row * R + column] = integer_paired::dot(
                    &el[row * R..(row + 1) * R],
                    &middle[block][column * R..(column + 1) * R],
                    el_factors[row],
                    middle_factors[block][column],
                    0,
                );
            }
            // These factors belong to the following L_k*FR output operation.
            factors[block][local_row] =
                integer_paired::factor(&left[block][local_row * R..(local_row + 1) * R]);
        }
    }
    Ok((left, factors))
}

// Emit every original bi,bj,bk,i,j word immediately. A test may retain all
// bytes independently; proof production feeds SHA256 and stores no output array.
// Output costs 8*64*64*4 + 8*64*4 + 64*4 =133,376 products. Together with S and L
// the schedule is 152,832, excluding noise hashing, additions, reduction and I/O.
fn transcript_tiles<E>(
    el: &[u32],
    er: &[u32],
    fl: &[u32],
    fr: &[u32],
    progress: &mut impl FnMut(GenerationProgress) -> Result<(), E>,
    mut emit: impl FnMut(&[u8; R * R * 4]),
) -> Result<(), GenerationError<E>> {
    let (middle, middle_factors) = middle_prefixes(er, fl, progress)?;
    let mut right = [0; N * R];
    for row in 0..R {
        for column in 0..N {
            right[column * R + row] = fr[row * N + column];
        }
    }
    let mut el_factors = [0; N];
    let mut fr_factors = [0; N];
    for (operand, (matrix, factors)) in [(el, &mut el_factors), (right.as_slice(), &mut fr_factors)]
        .into_iter()
        .enumerate()
    {
        for (row, factor) in factors.iter_mut().enumerate() {
            progress(GenerationProgress::OuterFactor {
                operand: operand as u8,
                row,
            })
            .map_err(GenerationError::Cancelled)?;
            *factor = integer_paired::factor(&matrix[row * R..(row + 1) * R]);
        }
    }
    for bi in 0..BLOCKS {
        let (left, left_factors) =
            left_prefixes(el, &el_factors, &middle, &middle_factors, bi, progress)?;
        for bj in 0..BLOCKS {
            for bk in 0..BLOCKS {
                progress(GenerationProgress::TranscriptTile {
                    row: bi,
                    column: bj,
                    inner: bk,
                })
                .map_err(GenerationError::Cancelled)?;
                let mut bytes = [0; R * R * 4];
                for i in 0..R {
                    for j in 0..R {
                        let column = bj * R + j;
                        let value = integer_paired::dot(
                            &left[bk][i * R..(i + 1) * R],
                            &right[column * R..(column + 1) * R],
                            left_factors[bk][i],
                            fr_factors[column],
                            0,
                        );
                        let position = (i * R + j) * 4;
                        bytes[position..position + 4].copy_from_slice(&value.to_le_bytes());
                    }
                }
                emit(&bytes);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{
        blocked_zero::BlockedZeroPreparedTask, hash, mul, paired_product::PairedPreparedTask,
        prove, structured::StructuredPreparedTask, task_id, verify, verify_reference, PreparedTask,
        CELLS, Q,
    };

    #[test]
    fn complete_canonical_zero_detection_never_substitutes_another_material() {
        let zero = vec![0; CELLS];
        for (left, right) in [
            (&zero[..CELLS - 1], zero.as_slice()),
            (zero.as_slice(), &zero[..1]),
        ] {
            assert!(matches!(
                BlockedZeroPairedPreparedTask::new(left, right),
                Err(WorkError::Length)
            ));
        }
        for position in [0, CELLS / 2, CELLS - 1] {
            let mut nonzero = zero.clone();
            nonzero[position] = 1;
            for (left, right) in [(&nonzero, &zero), (&zero, &nonzero), (&nonzero, &nonzero)] {
                assert!(BlockedZeroPairedPreparedTask::new(left, right)
                    .unwrap()
                    .is_none());
            }
            nonzero[position] = Q as u32;
            for (left, right) in [(&nonzero, &zero), (&zero, &nonzero)] {
                assert!(matches!(
                    BlockedZeroPairedPreparedTask::new(left, right),
                    Err(WorkError::Field)
                ));
            }
        }
    }

    #[test]
    fn full_proof_and_ticket_match_scalar_generic_zero_and_paired_across_reuse() {
        let mut zero = vec![0; CELLS];
        let candidate = BlockedZeroPairedPreparedTask::new(&zero, &zero)
            .unwrap()
            .unwrap();
        let blocked = BlockedZeroPreparedTask::new(&zero, &zero).unwrap().unwrap();
        let old = StructuredPreparedTask::new(&zero, &zero).unwrap().unwrap();
        let generic = PreparedTask::new(&zero, &zero).unwrap();
        let paired = PairedPreparedTask::new(&zero, &zero).unwrap();
        let task = task_id(&zero, &zero).unwrap();
        for challenge in [
            [0; 32],
            [7; 32],
            [255; 32],
            hash(b"zero-paired-reuse-v1", &[&task]),
            [7; 32],
        ] {
            let actual = candidate.prove(challenge).unwrap();
            assert_eq!(actual.len(), PROOF_BYTES);
            for expected in [
                prove(challenge, &zero, &zero).unwrap(),
                generic.prove(challenge).unwrap(),
                blocked.prove(challenge).unwrap(),
                old.prove(challenge).unwrap(),
                paired.prove(challenge).unwrap(),
            ] {
                assert_eq!(actual, expected);
            }
            let ordinary = verify(challenge, task, [255; 32], &actual).unwrap();
            let scalar = verify_reference(challenge, task, [255; 32], &actual).unwrap();
            assert_eq!(ordinary.ticket(), scalar.ticket());
            assert_eq!(ordinary.product(), zero);
        }
        let before = candidate.prove([7; 32]).unwrap();
        zero[CELLS - 1] = 1;
        assert_eq!(candidate.prove([7; 32]).unwrap(), before);
        for checker in [verify, verify_reference] {
            assert_eq!(
                checker([7; 32], task_id(&zero, &zero).unwrap(), [255; 32], &before).unwrap_err(),
                WorkError::Task
            );
            let mut changed = before.clone();
            changed[4 + 2 * CELLS * 4] = 1;
            assert_eq!(
                checker([7; 32], task, [255; 32], &changed).unwrap_err(),
                WorkError::Product
            );
            changed = before.clone();
            changed[PROOF_BYTES - 1] ^= 1;
            assert_eq!(
                checker([7; 32], task, [255; 32], &changed).unwrap_err(),
                WorkError::Transcript
            );
        }
    }

    #[test]
    fn every_extreme_prefix_word_matches_the_original_scalar_relation() {
        let destination =
            std::env::var_os("TRNM_ZERO_PAIRED_PREFIX_OUTPUT").map(std::path::PathBuf::from);
        if let Some(path) = &destination {
            std::fs::create_dir(path).expect("prefix evidence destination must be fresh");
        }
        for case in 0..4_u8 {
            let matrices: Vec<Vec<u32>> = (0..4_u8)
                .map(|label| {
                    (0..N * R)
                        .map(|index| match case {
                            0 => (Q - 1) as u32,
                            1 => {
                                if (index + usize::from(label)) % 3 == 0 {
                                    0
                                } else {
                                    (Q - 1 - (index % 17) as u128) as u32
                                }
                            }
                            2 => {
                                if label == 0 || label == 3 {
                                    0
                                } else {
                                    (Q - 1) as u32
                                }
                            }
                            _ => {
                                u32::from_le_bytes(
                                    hash(
                                        b"zero-paired-prefix-values-v1",
                                        &[&[label], &(index as u64).to_le_bytes()],
                                    )[..4]
                                        .try_into()
                                        .unwrap(),
                                ) % Q as u32
                            }
                        })
                        .collect()
                })
                .collect();
            let [el, er, fl, fr] = matrices.as_slice() else {
                unreachable!()
            };
            // Ordinary-remainder full noisy operands and the original scalar
            // bi,bj,bk loops do not use reassociation or integer-pair helpers.
            let a = mul(el, er, N, R, N);
            let b = mul(fl, fr, N, R, N);
            let mut expected = Vec::new();
            for bi in 0..BLOCKS {
                for bj in 0..BLOCKS {
                    let mut cells = [0_u32; R * R];
                    for bk in 0..BLOCKS {
                        for i in 0..R {
                            for j in 0..R {
                                let position = i * R + j;
                                let value = (u128::from(cells[position])
                                    + (bk * R..(bk + 1) * R)
                                        .map(|k| {
                                            u128::from(a[(bi * R + i) * N + k])
                                                * u128::from(b[k * N + bj * R + j])
                                        })
                                        .sum::<u128>())
                                    % Q;
                                cells[position] = value as u32;
                                expected.extend_from_slice(&cells[position].to_le_bytes());
                            }
                        }
                    }
                }
            }
            let mut actual = Vec::new();
            transcript_tiles(el, er, fl, fr, &mut |_| Ok::<_, ()>(()), |bytes| {
                actual.extend_from_slice(bytes)
            })
            .unwrap();
            assert_eq!(actual.len(), BLOCKS * BLOCKS * BLOCKS * R * R * 4);
            if let Some(path) = &destination {
                let path = path.join(format!("case-{case}"));
                std::fs::create_dir(&path).unwrap();
                let input: Vec<u8> = matrices
                    .iter()
                    .flatten()
                    .flat_map(|value| value.to_le_bytes())
                    .collect();
                std::fs::write(path.join("noise-input.bin"), &input).unwrap();
                std::fs::write(path.join("scalar-prefixes.bin"), &expected).unwrap();
                std::fs::write(path.join("native-prefixes.bin"), &actual).unwrap();
                let record = format!("{{\"schema\":\"pon-w1-blocked-zero-paired-prefix-observation-v1\",\"case\":{case},\"result\":\"{}\",\"prefix_words\":32768,\"input_sha256\":\"{}\",\"scalar_sha256\":\"{}\",\"native_sha256\":\"{}\",\"synthetic_noise_control_only\":true,\"not_a_work_proof\":true}}\n", if actual == expected { "PASS" } else { "FAIL" }, hex::encode(Sha256::digest(&input)), hex::encode(Sha256::digest(&expected)), hex::encode(Sha256::digest(&actual)));
                std::fs::write(path.join("receipt.json"), record).unwrap();
            }
            assert_eq!(
                actual, expected,
                "original scalar words differ for case {case}"
            );
        }
    }

    #[test]
    fn actual_checkpoint_order_cancels_without_retaining_challenge_state() {
        let zero = vec![0; CELLS];
        let task = BlockedZeroPairedPreparedTask::new(&zero, &zero)
            .unwrap()
            .unwrap();
        let mut observed = Vec::new();
        let proof = task
            .prove_with_progress([7; 32], |point| {
                observed.push(point);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(proof, prove([7; 32], &zero, &zero).unwrap());
        assert_eq!(observed.first(), Some(&GenerationProgress::BeforeReplay));
        assert_eq!(observed.last(), Some(&GenerationProgress::BeforeProof));
        let tiles: Vec<_> = observed
            .iter()
            .filter_map(|point| match *point {
                GenerationProgress::TranscriptTile { row, column, inner } => {
                    Some((row, column, inner))
                }
                _ => None,
            })
            .collect();
        let expected: Vec<_> = (0..BLOCKS)
            .flat_map(|row| {
                (0..BLOCKS)
                    .flat_map(move |column| (0..BLOCKS).map(move |inner| (row, column, inner)))
            })
            .collect();
        assert_eq!(tiles, expected);
        for refusal in [
            GenerationProgress::BeforeReplay,
            GenerationProgress::Noise {
                label: 0,
                counter: 0,
            },
            GenerationProgress::Noise {
                label: 3,
                counter: 63,
            },
            GenerationProgress::MiddleBlock { inner: 0 },
            GenerationProgress::MiddleBlock { inner: 7 },
            GenerationProgress::OuterFactor { operand: 0, row: 0 },
            GenerationProgress::OuterFactor {
                operand: 1,
                row: 63,
            },
            GenerationProgress::LeftTile { row: 0, inner: 0 },
            GenerationProgress::LeftTile { row: 7, inner: 7 },
            GenerationProgress::TranscriptTile {
                row: 0,
                column: 0,
                inner: 0,
            },
            GenerationProgress::TranscriptTile {
                row: 3,
                column: 4,
                inner: 5,
            },
            GenerationProgress::TranscriptTile {
                row: 7,
                column: 7,
                inner: 7,
            },
            GenerationProgress::BeforeProof,
        ] {
            assert!(observed.contains(&refusal));
            let mut called = Vec::new();
            let result = task.prove_with_progress([7; 32], |point| {
                called.push(point);
                if point == refusal {
                    Err(refusal)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Err(GenerationError::Cancelled(refusal)));
            assert_eq!(called.last(), Some(&refusal));
            assert_eq!(called, observed[..called.len()]);
        }
        assert_eq!(
            task.prove([255; 32]).unwrap(),
            prove([255; 32], &zero, &zero).unwrap()
        );
        assert_eq!(task.prove([7; 32]).unwrap(), proof);
    }
}
