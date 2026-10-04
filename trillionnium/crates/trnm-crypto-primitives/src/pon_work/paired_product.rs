//! Complete experimental W1 production by the paired-product identity.
//! All original prefixes and bytes remain. This local producer grants no task
//! admission or verification authority and does not change the native selection.
use super::{
    expand_with_progress, field_bytes, producer_reduce, validate, Hash, VerificationError,
    VerificationProgress, WorkError, N, PROOF_BYTES, Q, R,
};
use sha2::{Digest, Sha256};

/// Local cancellation observations; these are not proof fields or consensus input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationProgress {
    BeforeReplay,
    Noise {
        label: u8,
        counter: u32,
    },
    NoiseRow {
        operand: u8,
        row: usize,
    },
    TranscriptFactors {
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
pub enum GenerationError<E> {
    Relation(WorkError),
    Cancelled(E),
}

/// One exact mathematical task, with a genuinely computed fixed product. No
/// challenge-dependent factor or trace survives a call, and the cache has no
/// parent, lease, source statement, current-admission or VerifiedWork capability.
pub struct PairedPreparedTask {
    a: Vec<u32>,
    b: Vec<u32>,
    prefix: Vec<u8>,
}
impl PairedPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Self, WorkError> {
        validate(a)?;
        validate(b)?;
        let product = paired_mul(a, b, N, N, N, |_| Ok::<_, std::convert::Infallible>(()))
            .unwrap_or_else(|impossible| match impossible {});
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

    pub fn method(&self) -> &'static str {
        "paired-field-products-full-prefix-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self.prove_with_progress(challenge, |_| Ok::<_, std::convert::Infallible>(())) {
            Ok(proof) => Ok(proof),
            Err(GenerationError::Relation(error)) => Err(error),
            Err(GenerationError::Cancelled(impossible)) => match impossible {},
        }
    }

    pub fn prove_with_progress<E>(
        &self,
        challenge: Hash,
        mut progress: impl FnMut(GenerationProgress) -> Result<(), E>,
    ) -> Result<Vec<u8>, GenerationError<E>> {
        progress(GenerationProgress::BeforeReplay).map_err(GenerationError::Cancelled)?;
        let mut noise = |label| {
            expand_with_progress(challenge, label, N * R, &mut |observation| {
                let VerificationProgress::Noise { label, counter } = observation else {
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
        let e = paired_mul(&el, &er, N, R, N, |row| {
            progress(GenerationProgress::NoiseRow { operand: 0, row })
        })
        .map_err(GenerationError::Cancelled)?;
        let f = paired_mul(&fl, &fr, N, R, N, |row| {
            progress(GenerationProgress::NoiseRow { operand: 1, row })
        })
        .map_err(GenerationError::Cancelled)?;
        let ap: Vec<_> = self.a.iter().zip(e).map(|(a, e)| add(*a, e)).collect();
        let bp: Vec<_> = self.b.iter().zip(f).map(|(b, f)| add(*b, f)).collect();
        let bt = transpose(&bp, N, N);
        let mut row_factors = [[0; N / R]; N];
        let mut column_factors = [[0; N / R]; N];
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
                for block in 0..N / R {
                    factors[row][block] =
                        factor(&matrix[row * N + block * R..row * N + (block + 1) * R]);
                }
            }
        }
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        for bi in 0..N / R {
            for bj in 0..N / R {
                let mut cells = [0; R * R];
                let mut bytes = [0; R * R * 4];
                for bk in 0..N / R {
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
                            let pos = i * R + j;
                            cells[pos] = paired_dot(
                                &ap[row * N + bk * R..row * N + (bk + 1) * R],
                                &bt[column * N + bk * R..column * N + (bk + 1) * R],
                                row_factors[row][bk],
                                column_factors[column][bk],
                                cells[pos],
                            );
                            bytes[pos * 4..pos * 4 + 4].copy_from_slice(&cells[pos].to_le_bytes());
                        }
                    }
                    transcript.update(bytes);
                }
            }
        }
        progress(GenerationProgress::BeforeProof).map_err(GenerationError::Cancelled)?;
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&transcript.finalize());
        Ok(proof)
    }
}

// Each input is in [0,q); one conditional subtraction canonicalizes their sum.
fn add(a: u32, b: u32) -> u32 {
    let sum = u64::from(a) + u64::from(b);
    if sum >= Q as u64 {
        (sum - Q as u64) as u32
    } else {
        sum as u32
    }
}

fn factor(values: &[u32]) -> u32 {
    debug_assert!(values.len() <= N && values.len().is_multiple_of(2));
    producer_reduce(
        values
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| chunk.as_slice())
            .map(|pair| u128::from(pair[0]) * u128::from(pair[1]))
            .sum(),
    )
}

// x0*y0+x1*y1 = (x0+y1)*(x1+y0)-x0*x1-y0*y1 in Fq.
// Both sums are canonical before multiplication. A full setup dot has at most
// 32 products: 32*(q-1)^2 + 3*q < 2^69. A transcript increment has only four.
// The +2q makes subtracting the two canonical factors nonnegative, including
// zero inputs and any canonical prior prefix. Both fit producer_reduce's <2^70.
fn paired_dot(a: &[u32], bt: &[u32], row_factor: u32, column_factor: u32, prior: u32) -> u32 {
    debug_assert_eq!(a.len(), bt.len());
    let mut sum = u128::from(prior) + 2 * Q - u128::from(row_factor) - u128::from(column_factor);
    for (x, y) in a
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .zip(bt.as_chunks::<2>().0.iter().map(|chunk| chunk.as_slice()))
    {
        sum += u128::from(add(x[0], y[1])) * u128::from(add(x[1], y[0]));
    }
    producer_reduce(sum)
}

fn transpose(matrix: &[u32], rows: usize, columns: usize) -> Vec<u32> {
    let mut output = vec![0; matrix.len()];
    for row in 0..rows {
        for column in 0..columns {
            output[column * rows + row] = matrix[row * columns + column];
        }
    }
    output
}

fn paired_mul<E>(
    a: &[u32],
    b: &[u32],
    rows: usize,
    inner: usize,
    columns: usize,
    mut row_progress: impl FnMut(usize) -> Result<(), E>,
) -> Result<Vec<u32>, E> {
    debug_assert!(inner <= N && inner.is_multiple_of(2));
    let bt = transpose(b, inner, columns);
    let row_factors: Vec<_> = a.chunks_exact(inner).map(factor).collect();
    let column_factors: Vec<_> = bt.chunks_exact(inner).map(factor).collect();
    let mut output = vec![0; rows * columns];
    for row in 0..rows {
        row_progress(row)?;
        for column in 0..columns {
            output[row * columns + column] = paired_dot(
                &a[row * inner..(row + 1) * inner],
                &bt[column * inner..(column + 1) * inner],
                row_factors[row],
                column_factors[column],
                0,
            );
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{prove, task_id, verify, verify_reference, PreparedTask, CELLS};

    fn maintenance() -> (Vec<u32>, Vec<u32>) {
        (
            (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
            (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
        )
    }

    #[test]
    fn paired_field_identity_covers_canonical_extremes_and_prefixes() {
        let values = [0, 1, 2, Q as u32 - 2, Q as u32 - 1];
        for a0 in values {
            for a1 in values {
                for b0 in values {
                    for b1 in values {
                        let a = [a0, a1];
                        let b = [b0, b1];
                        for prior in values {
                            assert_eq!(
                                paired_dot(&a, &b, factor(&a), factor(&b), prior),
                                ((u128::from(prior)
                                    + u128::from(a0) * u128::from(b0)
                                    + u128::from(a1) * u128::from(b1))
                                    % Q) as u32
                            );
                        }
                    }
                }
            }
        }
        for inner in [R, N] {
            let a = vec![Q as u32 - 1; inner];
            assert_eq!(
                paired_dot(&a, &a, factor(&a), factor(&a), Q as u32 - 1),
                (inner - 1) as u32
            );
        }
    }

    #[test]
    fn paired_complete_proofs_match_scalar_on_maintenance_and_extreme_materials() {
        let (a, b) = maintenance();
        let cases = [
            (a, b),
            (
                vec![Q as u32 - 1; CELLS],
                (0..CELLS)
                    .map(|i| (Q - 1 - (i % 257) as u128) as u32)
                    .collect(),
            ),
            (
                vec![0; CELLS],
                (0..CELLS).map(|i| (i % 263) as u32).collect(),
            ),
            (
                (0..CELLS)
                    .map(|i| ((i / N + 1) * (i % N + 3)) as u32)
                    .collect(),
                vec![1; CELLS],
            ),
        ];
        for (mut a, mut b) in cases {
            let task = task_id(&a, &b).unwrap();
            let paired = PairedPreparedTask::new(&a, &b).unwrap();
            let generic = PreparedTask::new(&a, &b).unwrap();
            for challenge in [[0; 32], [7; 32], [255; 32], [7; 32]] {
                let proof = paired.prove(challenge).unwrap();
                assert_eq!(proof.len(), PROOF_BYTES);
                assert_eq!(proof, prove(challenge, &a, &b).unwrap());
                assert_eq!(proof, generic.prove(challenge).unwrap());
                assert_eq!(
                    verify(challenge, task, [255; 32], &proof).unwrap().ticket(),
                    verify_reference(challenge, task, [255; 32], &proof)
                        .unwrap()
                        .ticket()
                );
            }
            let original = paired.prove([19; 32]).unwrap();
            a[0] = ((u64::from(a[0]) + 1) % Q as u64) as u32;
            b[CELLS - 1] = ((u64::from(b[CELLS - 1]) + 1) % Q as u64) as u32;
            assert_eq!(paired.prove([19; 32]).unwrap(), original);
            assert_ne!(
                PairedPreparedTask::new(&a, &b)
                    .unwrap()
                    .prove([19; 32])
                    .unwrap(),
                original
            );
        }
    }

    #[test]
    fn paired_cancellation_discards_complete_or_partial_work_and_reuse_stays_exact() {
        let (a, b) = maintenance();
        let prepared = PairedPreparedTask::new(&a, &b).unwrap();
        let mut observations = Vec::new();
        let full = prepared
            .prove_with_progress([31; 32], |point| {
                observations.push(point);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(
            observations.first(),
            Some(&GenerationProgress::BeforeReplay)
        );
        assert_eq!(observations.last(), Some(&GenerationProgress::BeforeProof));
        assert_eq!(
            observations
                .iter()
                .filter(|p| matches!(p, GenerationProgress::TranscriptTile { .. }))
                .count(),
            512
        );
        let cuts: Vec<_> = observations
            .iter()
            .enumerate()
            .filter_map(|(index, point)| {
                matches!(
                    point,
                    GenerationProgress::BeforeReplay
                        | GenerationProgress::BeforeProof
                        | GenerationProgress::Noise {
                            counter: 0 | 63,
                            ..
                        }
                        | GenerationProgress::NoiseRow { row: 0 | 63, .. }
                        | GenerationProgress::TranscriptFactors { row: 0 | 63, .. }
                        | GenerationProgress::TranscriptTile {
                            row: 0 | 7,
                            column: 0 | 7,
                            inner: 0 | 7
                        }
                )
                .then_some(index)
            })
            .collect();
        for cut in cuts {
            let mut visited = Vec::new();
            let result = prepared.prove_with_progress([31; 32], |point| {
                visited.push(point);
                if visited.len() - 1 == cut {
                    Err(cut)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Err(GenerationError::Cancelled(cut)));
            assert_eq!(visited, observations[..=cut]);
        }
        assert_eq!(prepared.prove([31; 32]).unwrap(), full);
        assert_eq!(full, prove([31; 32], &a, &b).unwrap());
        assert_ne!(prepared.prove([32; 32]).unwrap(), full);
    }

    #[test]
    fn paired_constructors_validate_complete_material_without_substitution() {
        let (a, mut b) = maintenance();
        assert!(matches!(
            PairedPreparedTask::new(&a[..CELLS - 1], &b),
            Err(WorkError::Length)
        ));
        b[CELLS - 1] = Q as u32;
        assert!(matches!(
            PairedPreparedTask::new(&a, &b),
            Err(WorkError::Field)
        ));
    }
}
