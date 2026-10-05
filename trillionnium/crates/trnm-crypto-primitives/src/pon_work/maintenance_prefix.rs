//! Complete maintenance producers using exact integer paired products. The
//! prefix producer exploits periodic B inside EACH challenge, not just fixed AB.
//! Both constructors charge the same complete material checks and periodic AB
//! preparation. No challenge result or verification capability is cached.
use super::{
    expand_with_progress,
    integer_paired::{self, ProductProgress},
    maintenance_periodic::{ColumnPlan, MaintenancePeriodicPreparedTask},
    producer_reduce, Hash, PreparedTask, VerificationError, VerificationProgress, WorkError, N, R,
};
use sha2::{Digest, Sha256};

const BLOCKS: usize = N / R;

/// New local observations at real work boundaries. The two algorithms have
/// different sequences; neither sequence replaces an older callback contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationProgress {
    BeforeReplay,
    Noise {
        label: u8,
        counter: u32,
    },
    NoiseFactor {
        operand: u8,
        side: u8,
        row: usize,
    },
    NoiseRow {
        operand: u8,
        row: usize,
    },
    TranscriptFactors {
        operand: u8,
        row: usize,
    },
    PrefixRow {
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
pub enum GenerationError<E> {
    Relation(WorkError),
    Cancelled(E),
}

fn expand<E>(
    challenge: Hash,
    label: u8,
    progress: &mut impl FnMut(GenerationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, GenerationError<E>> {
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
}

fn noise_product<E>(
    left: &[u32],
    right: &[u32],
    operand: u8,
    progress: &mut impl FnMut(GenerationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, GenerationError<E>> {
    integer_paired::mul(left, right, N, R, N, |point| {
        progress(match point {
            ProductProgress::Factor { operand: side, row } => {
                GenerationProgress::NoiseFactor { operand, side, row }
            }
            ProductProgress::Row { row } => GenerationProgress::NoiseRow { operand, row },
        })
    })
    .map_err(GenerationError::Cancelled)
}

fn without_cancellation(
    value: Result<Vec<u8>, GenerationError<std::convert::Infallible>>,
) -> Result<Vec<u8>, WorkError> {
    match value {
        Ok(proof) => Ok(proof),
        Err(GenerationError::Relation(error)) => Err(error),
        Err(GenerationError::Cancelled(impossible)) => match impossible {},
    }
}

/// Necessary direct-transcript competitor: the same fixed maintenance setup and
/// integer paired kernel as the prefix strategy, without its factorization.
pub struct MaintenanceIntegerPairedPreparedTask {
    inner: PreparedTask,
}

impl MaintenanceIntegerPairedPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        Ok(MaintenancePeriodicPreparedTask::new(a, b)?.map(|task| Self { inner: task.inner }))
    }

    pub fn method(&self) -> &'static str {
        "maintenance-integer-paired-full-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        without_cancellation(self.prove_with_progress(challenge, |_| Ok(())))
    }

    pub fn prove_with_progress<E>(
        &self,
        challenge: Hash,
        mut progress: impl FnMut(GenerationProgress) -> Result<(), E>,
    ) -> Result<Vec<u8>, GenerationError<E>> {
        progress(GenerationProgress::BeforeReplay).map_err(GenerationError::Cancelled)?;
        let el = expand(challenge, 0, &mut progress)?;
        let er = expand(challenge, 1, &mut progress)?;
        let fl = expand(challenge, 2, &mut progress)?;
        let fr = expand(challenge, 3, &mut progress)?;
        let e = noise_product(&el, &er, 0, &mut progress)?;
        let f = noise_product(&fl, &fr, 1, &mut progress)?;
        let ap: Vec<_> = self
            .inner
            .a
            .iter()
            .zip(e)
            .map(|(&a, e)| producer_reduce(u128::from(a) + u128::from(e)))
            .collect();
        let bp: Vec<_> = self
            .inner
            .b
            .iter()
            .zip(f)
            .map(|(&b, f)| producer_reduce(u128::from(b) + u128::from(f)))
            .collect();
        let bt = integer_paired::transpose(&bp, N, N);
        let mut row_factors = [[0; BLOCKS]; N];
        let mut column_factors = [[0; BLOCKS]; N];
        for (operand, (matrix, factors)) in [(&ap, &mut row_factors), (&bt, &mut column_factors)]
            .into_iter()
            .enumerate()
        {
            for row in 0..N {
                progress(GenerationProgress::TranscriptFactors {
                    operand: operand as u8,
                    row,
                })
                .map_err(GenerationError::Cancelled)?;
                for block in 0..BLOCKS {
                    factors[row][block] = integer_paired::factor(
                        &matrix[row * N + block * R..row * N + (block + 1) * R],
                    );
                }
            }
        }
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        for bi in 0..BLOCKS {
            for bj in 0..BLOCKS {
                let mut cells = [0; R * R];
                let mut bytes = [0; R * R * 4];
                for bk in 0..BLOCKS {
                    progress(GenerationProgress::TranscriptTile {
                        row: bi,
                        column: bj,
                        inner: bk,
                    })
                    .map_err(GenerationError::Cancelled)?;
                    for i in 0..R {
                        let row = bi * R + i;
                        for j in 0..R {
                            let column = bj * R + j;
                            let position = i * R + j;
                            cells[position] = integer_paired::dot(
                                &ap[row * N + bk * R..row * N + (bk + 1) * R],
                                &bt[column * N + bk * R..column * N + (bk + 1) * R],
                                row_factors[row][bk],
                                column_factors[column][bk],
                                cells[position],
                            );
                            bytes[position * 4..position * 4 + 4]
                                .copy_from_slice(&cells[position].to_le_bytes());
                        }
                    }
                    transcript.update(bytes);
                }
            }
        }
        progress(GenerationProgress::BeforeProof).map_err(GenerationError::Cancelled)?;
        let mut proof = self.inner.prefix.clone();
        proof.extend_from_slice(&transcript.finalize());
        Ok(proof)
    }
}

/// Exact fixed-maintenance prefix decomposition. It does not form F or AP*BP;
/// instead each required prefix is AP*B + (AP*FL)*FR in the same field.
pub struct MaintenancePrefixPreparedTask {
    inner: PreparedTask,
    plans: [ColumnPlan; N],
}

impl MaintenancePrefixPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        Ok(
            MaintenancePeriodicPreparedTask::new(a, b)?.map(|task| Self {
                inner: task.inner,
                // This additional plan construction remains inside charged setup.
                plans: std::array::from_fn(|column| ColumnPlan::new(b[column])),
            }),
        )
    }

    pub fn method(&self) -> &'static str {
        "maintenance-periodic-prefix-integer-paired-full-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        without_cancellation(self.prove_with_progress(challenge, |_| Ok(())))
    }

    pub fn prove_with_progress<E>(
        &self,
        challenge: Hash,
        mut progress: impl FnMut(GenerationProgress) -> Result<(), E>,
    ) -> Result<Vec<u8>, GenerationError<E>> {
        progress(GenerationProgress::BeforeReplay).map_err(GenerationError::Cancelled)?;
        let el = expand(challenge, 0, &mut progress)?;
        let er = expand(challenge, 1, &mut progress)?;
        let fl = expand(challenge, 2, &mut progress)?;
        let fr = expand(challenge, 3, &mut progress)?;
        let e = noise_product(&el, &er, 0, &mut progress)?;
        let ap: Vec<_> = self
            .inner
            .a
            .iter()
            .zip(e)
            .map(|(&a, e)| producer_reduce(u128::from(a) + u128::from(e)))
            .collect();
        let flt = integer_paired::transpose(&fl, N, R);
        let frt = integer_paired::transpose(&fr, R, N);
        let mut fl_factors = [[0; BLOCKS]; R];
        for (rank, factors) in fl_factors.iter_mut().enumerate() {
            progress(GenerationProgress::TranscriptFactors {
                operand: 0,
                row: rank,
            })
            .map_err(GenerationError::Cancelled)?;
            for (block, factor) in factors.iter_mut().enumerate() {
                *factor =
                    integer_paired::factor(&flt[rank * N + block * R..rank * N + (block + 1) * R]);
            }
        }
        let mut fr_factors = [0; N];
        for (column, factor) in fr_factors.iter_mut().enumerate() {
            progress(GenerationProgress::TranscriptFactors {
                operand: 1,
                row: column,
            })
            .map_err(GenerationError::Cancelled)?;
            *factor = integer_paired::factor(&frt[column * R..(column + 1) * R]);
        }
        // All these are fresh challenge-local values. For canonical AP, prefix
        // sums <=64*(q-1) and weighted sums <=2016*(q-1). The largest positive
        // periodic expression is <=47008*(q-1)<2^48, safely inside u64.
        let mut sums = vec![[0_u64; N + 1]; N];
        let mut weighted = vec![[0_u64; BLOCKS]; N];
        let mut products = vec![[0_u32; R]; N * BLOCKS];
        let mut product_factors = vec![0_u128; N * BLOCKS];
        for row in 0..N {
            progress(GenerationProgress::PrefixRow { row }).map_err(GenerationError::Cancelled)?;
            let values = &ap[row * N..(row + 1) * N];
            let mut weight = 0;
            for (k, &value) in values.iter().enumerate() {
                sums[row][k + 1] = sums[row][k] + u64::from(value);
                weight += k as u64 * u64::from(value);
                if (k + 1) % R == 0 {
                    weighted[row][k / R] = weight;
                }
            }
            let mut current = [0; R];
            for block in 0..BLOCKS {
                let left = &values[block * R..(block + 1) * R];
                let left_factor = integer_paired::factor(left);
                for rank in 0..R {
                    current[rank] = integer_paired::dot(
                        left,
                        &flt[rank * N + block * R..rank * N + (block + 1) * R],
                        left_factor,
                        fl_factors[rank][block],
                        current[rank],
                    );
                }
                products[row * BLOCKS + block] = current;
                // A different canonical H vector and factor at every prefix.
                product_factors[row * BLOCKS + block] = integer_paired::factor(&current);
            }
        }
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        for bi in 0..BLOCKS {
            for bj in 0..BLOCKS {
                let mut bytes = [0; R * R * 4];
                for bk in 0..BLOCKS {
                    progress(GenerationProgress::TranscriptTile {
                        row: bi,
                        column: bj,
                        inner: bk,
                    })
                    .map_err(GenerationError::Cancelled)?;
                    for i in 0..R {
                        let row = bi * R + i;
                        for j in 0..R {
                            let column = bj * R + j;
                            let mixed = integer_paired::dot(
                                &products[row * BLOCKS + bk],
                                &frt[column * R..(column + 1) * R],
                                product_factors[row * BLOCKS + bk],
                                fr_factors[column],
                                0,
                            );
                            // Exact integer AP*B prefix is nonnegative. Reduction
                            // only here gives the original field prefix, NOT the
                            // last tile alone and NOT an arbitrary claimed C.
                            let fixed =
                                self.plans[column].dot(&sums[row], weighted[row][bk], (bk + 1) * R);
                            let cell = producer_reduce(u128::from(fixed) + u128::from(mixed));
                            let position = i * R + j;
                            bytes[position * 4..position * 4 + 4]
                                .copy_from_slice(&cell.to_le_bytes());
                        }
                    }
                    transcript.update(bytes);
                }
            }
        }
        progress(GenerationProgress::BeforeProof).map_err(GenerationError::Cancelled)?;
        let mut proof = self.inner.prefix.clone();
        proof.extend_from_slice(&transcript.finalize());
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{prove, task_id, verify, verify_reference, CELLS, PROOF_BYTES, Q};

    fn maintenance() -> (Vec<u32>, Vec<u32>) {
        (
            (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
            (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
        )
    }

    #[test]
    fn periodic_challenge_prefix_bounds_cover_all_intercepts_and_lengths() {
        // Unlike fixed-AB setup checks, AP is any canonical field element.
        for values in [
            vec![0; N],
            vec![Q as u32 - 1; N],
            (0..N)
                .map(|k| if k % 2 == 0 { Q as u32 - 1 } else { 0 })
                .collect(),
        ] {
            let mut sums = [0; N + 1];
            let mut weighted = [0; N + 1];
            for (k, &value) in values.iter().enumerate() {
                sums[k + 1] = sums[k] + u64::from(value);
                weighted[k + 1] = weighted[k] + k as u64 * u64::from(value);
            }
            for base in 0..263 {
                let plan = ColumnPlan::new(base);
                let mut expected = 0;
                for length in 0..=N {
                    if length != 0 {
                        let k = length - 1;
                        expected +=
                            u64::from(values[k]) * ((u64::from(base) + 15 * k as u64) % 263);
                    }
                    assert_eq!(plan.dot(&sums, weighted[length], length), expected);
                    assert!(expected <= 64 * 262 * (Q as u64 - 1));
                }
            }
        }
    }

    #[test]
    fn periodic_factorization_matches_every_prefix_word_with_extreme_noise() {
        let (_, b) = maintenance();
        for salt in [0, 7] {
            let ap: Vec<_> = (0..CELLS)
                .map(|index| {
                    if salt == 0 {
                        Q as u32 - 1
                    } else if index % 3 == 0 {
                        0
                    } else {
                        (Q - 1 - (index * salt % 257) as u128) as u32
                    }
                })
                .collect();
            let fl: Vec<_> = (0..N * R)
                .map(|index| (Q - 1 - (index % 17) as u128) as u32)
                .collect();
            let fr: Vec<_> = (0..N * R)
                .map(|index| (Q - 1 - (index % 19) as u128) as u32)
                .collect();
            let mut bp = vec![0; CELLS];
            for row in 0..N {
                for column in 0..N {
                    let f: u128 = (0..R)
                        .map(|rank| {
                            u128::from(fl[row * R + rank]) * u128::from(fr[rank * N + column])
                        })
                        .sum();
                    bp[row * N + column] = ((f + u128::from(b[row * N + column])) % Q) as u32;
                }
            }
            for row in 0..N {
                let values = &ap[row * N..(row + 1) * N];
                let mut sums = [0; N + 1];
                let mut weighted = [0; BLOCKS];
                let mut weight = 0;
                let mut h = [[0; R]; BLOCKS];
                for (k, &value) in values.iter().enumerate() {
                    sums[k + 1] = sums[k] + u64::from(value);
                    weight += k as u64 * u64::from(value);
                    if (k + 1) % R == 0 {
                        weighted[k / R] = weight;
                    }
                }
                // Independent u128 remainder sums, not production incremental H.
                for (block, vector) in h.iter_mut().enumerate() {
                    for (rank, entry) in vector.iter_mut().enumerate() {
                        *entry = ((0..(block + 1) * R)
                            .map(|k| u128::from(values[k]) * u128::from(fl[k * R + rank]))
                            .sum::<u128>()
                            % Q) as u32;
                    }
                }
                for column in 0..N {
                    let plan = ColumnPlan::new(b[column]);
                    let right: Vec<_> = (0..R).map(|rank| fr[rank * N + column]).collect();
                    let right_factor = integer_paired::factor(&right);
                    let mut expected = 0_u128;
                    for block in 0..BLOCKS {
                        for k in block * R..(block + 1) * R {
                            expected += u128::from(values[k]) * u128::from(bp[k * N + column]);
                        }
                        expected %= Q;
                        let mixed = integer_paired::dot(
                            &h[block],
                            &right,
                            integer_paired::factor(&h[block]),
                            right_factor,
                            0,
                        );
                        let fixed = plan.dot(&sums, weighted[block], (block + 1) * R);
                        assert_eq!(
                            producer_reduce(u128::from(fixed) + u128::from(mixed)),
                            expected as u32,
                            "salt={salt}, row={row}, column={column}, prefix={block}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn both_maintenance_prefix_constructors_reject_unsupported_and_malformed_inputs() {
        let (a, b) = maintenance();
        for position in [0, CELLS / 2, CELLS - 1] {
            for operand in 0..2 {
                let mut left = a.clone();
                let mut right = b.clone();
                if operand == 0 {
                    left[position] ^= 1;
                } else {
                    right[position] ^= 1;
                }
                assert!(MaintenancePrefixPreparedTask::new(&left, &right)
                    .unwrap()
                    .is_none());
                assert!(MaintenanceIntegerPairedPreparedTask::new(&left, &right)
                    .unwrap()
                    .is_none());
            }
        }
        for (left, right, expected) in [
            (&a[..CELLS - 1], b.as_slice(), WorkError::Length),
            (a.as_slice(), &b[..CELLS - 1], WorkError::Length),
        ] {
            assert!(
                matches!(MaintenancePrefixPreparedTask::new(left, right), Err(error) if error == expected)
            );
            assert!(
                matches!(MaintenanceIntegerPairedPreparedTask::new(left, right), Err(error) if error == expected)
            );
        }
        let mut invalid = a.clone();
        invalid[CELLS - 1] = Q as u32;
        for (left, right) in [(&invalid, &b), (&a, &invalid)] {
            assert!(matches!(
                MaintenancePrefixPreparedTask::new(left, right),
                Err(WorkError::Field)
            ));
            assert!(matches!(
                MaintenanceIntegerPairedPreparedTask::new(left, right),
                Err(WorkError::Field)
            ));
        }
        let zero = vec![0; CELLS];
        for (left, right) in [(&zero, &zero), (&a, &zero), (&zero, &b), (&b, &a)] {
            assert!(MaintenancePrefixPreparedTask::new(left, right)
                .unwrap()
                .is_none());
            assert!(MaintenanceIntegerPairedPreparedTask::new(left, right)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn periodic_and_integer_paired_complete_proofs_match_scalar_and_verifier_errors() {
        let (mut a, mut b) = maintenance();
        let prefix = MaintenancePrefixPreparedTask::new(&a, &b).unwrap().unwrap();
        let direct = MaintenanceIntegerPairedPreparedTask::new(&a, &b)
            .unwrap()
            .unwrap();
        let generic = PreparedTask::new(&a, &b).unwrap();
        let task = task_id(&a, &b).unwrap();
        for challenge in [[0; 32], [255; 32], [7; 32], [0; 32]] {
            let proof = prefix.prove(challenge).unwrap();
            assert_eq!(proof.len(), PROOF_BYTES);
            assert_eq!(proof, direct.prove(challenge).unwrap());
            assert_eq!(proof, generic.prove(challenge).unwrap());
            assert_eq!(proof, prove(challenge, &a, &b).unwrap());
            assert_eq!(
                verify(challenge, task, [255; 32], &proof).unwrap().ticket(),
                verify_reference(challenge, task, [255; 32], &proof)
                    .unwrap()
                    .ticket()
            );
            assert!(matches!(
                verify(challenge, task, [0; 32], &proof),
                Err(WorkError::Target)
            ));
            let mut wrong_product = proof.clone();
            wrong_product[4 + 2 * CELLS * 4] ^= 1;
            let mut wrong_trace = proof.clone();
            wrong_trace[PROOF_BYTES - 1] ^= 1;
            for (invalid, expected) in [
                (&wrong_product, WorkError::Product),
                (&wrong_trace, WorkError::Transcript),
            ] {
                assert_eq!(
                    verify(challenge, task, [255; 32], invalid).unwrap_err(),
                    expected
                );
                assert_eq!(
                    verify_reference(challenge, task, [255; 32], invalid).unwrap_err(),
                    expected
                );
            }
        }
        let expected = prefix.prove([19; 32]).unwrap();
        a[0] ^= 1;
        b[CELLS - 1] ^= 1;
        assert_eq!(prefix.prove([19; 32]).unwrap(), expected);
        assert_eq!(direct.prove([19; 32]).unwrap(), expected);
    }

    fn check_cancellation(
        mut run: impl FnMut(
            &mut dyn FnMut(GenerationProgress) -> Result<(), usize>,
        ) -> Result<Vec<u8>, GenerationError<usize>>,
    ) {
        let mut observed = Vec::new();
        let proof = run(&mut |point| {
            observed.push(point);
            Ok(())
        })
        .unwrap();
        assert_eq!(observed.first(), Some(&GenerationProgress::BeforeReplay));
        assert_eq!(observed.last(), Some(&GenerationProgress::BeforeProof));
        let tiles: Vec<_> = observed
            .iter()
            .filter_map(|point| match point {
                GenerationProgress::TranscriptTile { row, column, inner } => {
                    Some((*row, *column, *inner))
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
        for (cut, point) in observed.iter().enumerate() {
            let boundary = match point {
                GenerationProgress::BeforeReplay | GenerationProgress::BeforeProof => true,
                GenerationProgress::Noise { counter, .. } => *counter == 0 || *counter == 63,
                GenerationProgress::NoiseFactor { row, .. }
                | GenerationProgress::NoiseRow { row, .. }
                | GenerationProgress::TranscriptFactors { row, .. }
                | GenerationProgress::PrefixRow { row } => *row == 0 || *row == 7 || *row == 63,
                GenerationProgress::TranscriptTile { row, column, inner } => {
                    [0, 7].contains(row) && [0, 7].contains(column) && [0, 7].contains(inner)
                }
            };
            if !boundary {
                continue;
            }
            let mut visited = Vec::new();
            assert_eq!(
                run(&mut |point| {
                    visited.push(point);
                    if visited.len() - 1 == cut {
                        Err(cut)
                    } else {
                        Ok(())
                    }
                }),
                Err(GenerationError::Cancelled(cut))
            );
            assert_eq!(visited, observed[..=cut]);
        }
        assert_eq!(run(&mut |_| Ok(())).unwrap(), proof);
    }

    #[test]
    fn both_prefix_generators_cancel_at_real_boundaries_and_reuse_no_challenge_state() {
        let (a, b) = maintenance();
        let prefix = MaintenancePrefixPreparedTask::new(&a, &b).unwrap().unwrap();
        let direct = MaintenanceIntegerPairedPreparedTask::new(&a, &b)
            .unwrap()
            .unwrap();
        check_cancellation(|progress| prefix.prove_with_progress([31; 32], progress));
        check_cancellation(|progress| direct.prove_with_progress([31; 32], progress));
    }
}
