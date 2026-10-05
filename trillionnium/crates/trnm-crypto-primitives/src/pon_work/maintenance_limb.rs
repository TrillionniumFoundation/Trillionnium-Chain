//! Separate complete maintenance producer using bounded split-limb accumulation.
//! The number of scalar products and the complete W1 relation are unchanged.
//! This arithmetic experiment is not selected by the native producer or verifier.
use super::{
    expand_with_progress, maintenance_periodic::MaintenancePeriodicPreparedTask, Hash,
    PreparedGenerationError, PreparedGenerationProgress, PreparedTask, VerificationError,
    VerificationProgress, WorkError, CELLS, N, Q, R,
};
use sha2::{Digest, Sha256};

// For eight canonical u32 products p, use p=lo+2^32*hi and 2^32=5 (mod q).
// Including the canonical prior, low<9*2^32, high<8*2^32 and s<49*2^32.
// Hence folded<2^32+240<2q: one conditional subtraction suffices. Every
// product and accumulator fits u64. No overflowing or wrapping sum is used.
#[inline]
fn dot8(left: &[u32], right: &[u32], prior: u32) -> u32 {
    debug_assert_eq!(left.len(), R);
    debug_assert_eq!(right.len(), R);
    let mut low = u64::from(prior);
    let mut high = 0_u64;
    for k in 0..R {
        let product = u64::from(left[k]) * u64::from(right[k]);
        low += u64::from(product as u32);
        high += product >> 32;
    }
    let sum = low + 5 * high;
    let folded = u64::from(sum as u32) + 5 * (sum >> 32);
    if folded >= Q as u64 {
        (folded - Q as u64) as u32
    } else {
        folded as u32
    }
}

fn add(left: u32, right: u32) -> u32 {
    let sum = u64::from(left) + u64::from(right);
    if sum >= Q as u64 {
        (sum - Q as u64) as u32
    } else {
        sum as u32
    }
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

fn noise_product<E>(
    left: &[u32],
    right: &[u32],
    operand: u8,
    progress: &mut impl FnMut(PreparedGenerationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, PreparedGenerationError<E>> {
    let right = transpose(right, R, N);
    let mut product = vec![0; CELLS];
    for row in 0..N {
        progress(PreparedGenerationProgress::NoiseRow { operand, row })
            .map_err(PreparedGenerationError::Cancelled)?;
        for column in 0..N {
            product[row * N + column] = dot8(
                &left[row * R..(row + 1) * R],
                &right[column * R..(column + 1) * R],
                0,
            );
        }
    }
    Ok(product)
}

// A test can retain each emitted tile and compare its individual words with
// independent ordinary-remainder arithmetic. A real proof streams each tile
// straight into SHA256 and retains no prefix-output cache.
fn transcript_tiles<E>(
    left: &[u32],
    right: &[u32],
    progress: &mut impl FnMut(PreparedGenerationProgress) -> Result<(), E>,
    mut emit: impl FnMut(&[u8; R * R * 4]),
) -> Result<(), PreparedGenerationError<E>> {
    let right = transpose(right, N, N);
    for bi in 0..N / R {
        for bj in 0..N / R {
            let mut cells = [0_u32; R * R];
            let mut bytes = [0_u8; R * R * 4];
            for bk in 0..N / R {
                progress(PreparedGenerationProgress::TranscriptTile {
                    row: bi,
                    column: bj,
                    inner: bk,
                })
                .map_err(PreparedGenerationError::Cancelled)?;
                for i in 0..R {
                    let row = bi * R + i;
                    for j in 0..R {
                        let column = bj * R + j;
                        let position = i * R + j;
                        cells[position] = dot8(
                            &left[row * N + bk * R..row * N + (bk + 1) * R],
                            &right[column * N + bk * R..column * N + (bk + 1) * R],
                            cells[position],
                        );
                        bytes[position * 4..position * 4 + 4]
                            .copy_from_slice(&cells[position].to_le_bytes());
                    }
                }
                emit(&bytes);
            }
        }
    }
    Ok(())
}

/// An exact fixed-material cache, without source, lease, parent or verified-work
/// authority. Its constructor computes the complete fixed product and prefix.
/// Every challenge recomputes all noise, both products and all original tiles.
pub struct MaintenanceLimbPreparedTask {
    inner: PreparedTask,
}

impl MaintenanceLimbPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        Ok(MaintenancePeriodicPreparedTask::new(a, b)?.map(|task| Self { inner: task.inner }))
    }

    pub fn method(&self) -> &'static str {
        "maintenance-split-limb-full-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self.prove_with_progress(challenge, |_| Ok::<_, std::convert::Infallible>(())) {
            Ok(proof) => Ok(proof),
            Err(PreparedGenerationError::Relation(error)) => Err(error),
            Err(PreparedGenerationError::Cancelled(impossible)) => match impossible {},
        }
    }

    /// Uses the original PreparedTask observation sequence. Each cancellation
    /// discards this call's state and returns no proof. Setup, allocation and
    /// bounded work between observations are not asynchronously preempted.
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
        let e = noise_product(&el, &er, 0, &mut progress)?;
        let ap: Vec<_> = self
            .inner
            .a
            .iter()
            .zip(e)
            .map(|(&a, e)| add(a, e))
            .collect();
        let f = noise_product(&fl, &fr, 1, &mut progress)?;
        let bp: Vec<_> = self
            .inner
            .b
            .iter()
            .zip(f)
            .map(|(&b, f)| add(b, f))
            .collect();
        let mut transcript = Sha256::new();
        transcript.update(b"TRNM-PON-TRACE1\0");
        transcript.update(challenge);
        transcript_tiles(&ap, &bp, &mut progress, |bytes| transcript.update(bytes))?;
        progress(PreparedGenerationProgress::BeforeProof)
            .map_err(PreparedGenerationError::Cancelled)?;
        let mut proof = self.inner.prefix.clone();
        proof.extend_from_slice(&transcript.finalize());
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{hash, prove, task_id, verify, verify_reference, PROOF_BYTES};

    fn material() -> (Vec<u32>, Vec<u32>) {
        (
            (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
            (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
        )
    }

    fn scalar(left: &[u32], right: &[u32], prior: u32) -> u32 {
        ((u128::from(prior)
            + left
                .iter()
                .zip(right)
                .map(|(&a, &b)| u128::from(a) * u128::from(b))
                .sum::<u128>())
            % Q) as u32
    }

    #[test]
    fn split_limb_extremes_and_field_carries_match_independent_remainder() {
        let values = [0, 1, 2, 1 << 16, 1 << 31, Q as u32 - 2, Q as u32 - 1];
        for a in values {
            for b in values {
                for prior in values {
                    assert_eq!(
                        dot8(&[a; R], &[b; R], prior),
                        scalar(&[a; R], &[b; R], prior)
                    );
                    assert_eq!(add(a, b), ((u128::from(a) + u128::from(b)) % Q) as u32);
                }
            }
        }
        for index in 0_u64..1024 {
            let left_hash = hash(b"split-limb-left-control-v1", &[&index.to_le_bytes()]);
            let right_hash = hash(b"split-limb-right-control-v1", &[&index.to_le_bytes()]);
            let unpack = |bytes: Hash| -> [u32; R] {
                std::array::from_fn(|i| {
                    (u64::from(u32::from_le_bytes(
                        bytes[i * 4..i * 4 + 4].try_into().unwrap(),
                    )) % Q as u64) as u32
                })
            };
            let left = unpack(left_hash);
            let right = unpack(right_hash);
            for prior in values {
                assert_eq!(dot8(&left, &right, prior), scalar(&left, &right, prior));
            }
        }
    }

    #[test]
    fn every_prefix_word_matches_independent_scalar_at_maximum_and_mixed_fields() {
        for maximum in [true, false] {
            let left: Vec<_> = (0..CELLS)
                .map(|i| {
                    if maximum {
                        Q as u32 - 1
                    } else {
                        [0, 1, Q as u32 - 1, 1 << 31][i % 4]
                    }
                })
                .collect();
            let right: Vec<_> = (0..CELLS)
                .map(|i| {
                    if maximum {
                        Q as u32 - 1
                    } else {
                        [Q as u32 - 2, 0, 17, Q as u32 - 1, 3][i % 5]
                    }
                })
                .collect();
            let mut actual = Vec::new();
            transcript_tiles(&left, &right, &mut |_| Ok::<_, ()>(()), |bytes| {
                actual.extend(
                    bytes
                        .chunks_exact(4)
                        .map(|word| u32::from_le_bytes(word.try_into().unwrap())),
                );
            })
            .unwrap();
            let mut expected = Vec::new();
            for bi in 0..N / R {
                for bj in 0..N / R {
                    for bk in 0..N / R {
                        for i in bi * R..(bi + 1) * R {
                            for j in bj * R..(bj + 1) * R {
                                let value: u128 = (0..(bk + 1) * R)
                                    .map(|k| {
                                        u128::from(left[i * N + k]) * u128::from(right[k * N + j])
                                    })
                                    .sum();
                                expected.push((value % Q) as u32);
                            }
                        }
                    }
                }
            }
            assert_eq!(actual.len(), 32_768);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn exact_material_full_proofs_tickets_and_ordered_rejections_remain_equal() {
        let (mut a, mut b) = material();
        let task = task_id(&a, &b).unwrap();
        let limb = MaintenanceLimbPreparedTask::new(&a, &b).unwrap().unwrap();
        let generic = PreparedTask::new(&a, &b).unwrap();
        for challenge in [[0; 32], [7; 32], [255; 32], [0; 32]] {
            let actual = limb.prove(challenge).unwrap();
            assert_eq!(actual.len(), PROOF_BYTES);
            assert_eq!(actual, prove(challenge, &a, &b).unwrap());
            assert_eq!(actual, generic.prove(challenge).unwrap());
            assert_eq!(
                verify(challenge, task, [255; 32], &actual)
                    .unwrap()
                    .ticket(),
                verify_reference(challenge, task, [255; 32], &actual)
                    .unwrap()
                    .ticket()
            );
            let mut product = actual.clone();
            product[4 + 2 * CELLS * 4] ^= 1;
            let mut trace = actual.clone();
            trace[PROOF_BYTES - 1] ^= 1;
            let mut field = actual.clone();
            field[4..8].copy_from_slice(&(Q as u32).to_le_bytes());
            for (proof, expected) in [
                (&product, WorkError::Product),
                (&trace, WorkError::Transcript),
                (&field, WorkError::Field),
            ] {
                assert_eq!(
                    verify(challenge, task, [255; 32], proof).unwrap_err(),
                    expected
                );
                assert_eq!(
                    verify_reference(challenge, task, [255; 32], proof).unwrap_err(),
                    expected
                );
            }
            for verify_fn in [verify, verify_reference] {
                assert_eq!(
                    verify_fn(challenge, task, [0; 32], &actual).unwrap_err(),
                    WorkError::Target
                );
                assert_eq!(
                    verify_fn(challenge, [0; 32], [255; 32], &actual).unwrap_err(),
                    WorkError::Task
                );
                let mut other = challenge;
                other[0] ^= 1;
                assert_eq!(
                    verify_fn(other, task, [255; 32], &actual).unwrap_err(),
                    WorkError::Transcript
                );
                assert_eq!(
                    verify_fn(challenge, task, [255; 32], &actual[..PROOF_BYTES - 1]).unwrap_err(),
                    WorkError::Length
                );
            }
        }
        let before = limb.prove([7; 32]).unwrap();
        a.fill(0);
        b.fill(0);
        assert_eq!(limb.prove([7; 32]).unwrap(), before);
        assert!(MaintenanceLimbPreparedTask::new(&a, &b).unwrap().is_none());
        for malformed in [vec![0; CELLS - 1], vec![Q as u32; CELLS]] {
            assert!(matches!(
                MaintenanceLimbPreparedTask::new(&malformed, &b),
                Err(WorkError::Length | WorkError::Field)
            ));
            assert!(matches!(
                MaintenanceLimbPreparedTask::new(&a, &malformed),
                Err(WorkError::Length | WorkError::Field)
            ));
        }
        let (a, b) = material();
        for position in [0, CELLS / 2, CELLS - 1] {
            let mut changed_a = a.clone();
            let mut changed_b = b.clone();
            changed_a[position] ^= 1;
            changed_b[position] ^= 1;
            assert!(MaintenanceLimbPreparedTask::new(&changed_a, &b)
                .unwrap()
                .is_none());
            assert!(MaintenanceLimbPreparedTask::new(&a, &changed_b)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn original_observation_order_and_cancelled_call_isolation_are_preserved() {
        let (a, b) = material();
        let generic = PreparedTask::new(&a, &b).unwrap();
        let limb = MaintenanceLimbPreparedTask::new(&a, &b).unwrap().unwrap();
        let challenge = [93; 32];
        let mut expected = Vec::new();
        let proof = generic
            .prove_with_progress(challenge, |point| {
                expected.push(point);
                Ok::<_, ()>(())
            })
            .unwrap();
        let mut actual = Vec::new();
        assert_eq!(
            limb.prove_with_progress(challenge, |point| {
                actual.push(point);
                Ok::<_, ()>(())
            })
            .unwrap(),
            proof
        );
        assert_eq!(actual, expected);
        assert_eq!(
            actual
                .iter()
                .filter(|p| matches!(p, PreparedGenerationProgress::TranscriptTile { .. }))
                .count(),
            512
        );
        for (cut, point) in expected.iter().enumerate() {
            let selected = match point {
                PreparedGenerationProgress::BeforeReplay
                | PreparedGenerationProgress::BeforeProof => true,
                PreparedGenerationProgress::Noise { counter, .. } => [0, 31, 63].contains(counter),
                PreparedGenerationProgress::NoiseRow { row, .. } => [0, 31, 63].contains(row),
                PreparedGenerationProgress::TranscriptTile { row, column, inner } => {
                    [0, 7].contains(row) && [0, 7].contains(column) && [0, 7].contains(inner)
                }
            };
            if selected {
                let mut calls = Vec::new();
                let cancelled = limb.prove_with_progress(challenge, |point| {
                    calls.push(point);
                    if calls.len() - 1 == cut {
                        Err(cut)
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(cancelled, Err(PreparedGenerationError::Cancelled(cut)));
                assert_eq!(calls, expected[..=cut]);
                assert_eq!(
                    limb.prove([18; 32]).unwrap(),
                    generic.prove([18; 32]).unwrap()
                );
                assert_eq!(limb.prove(challenge).unwrap(), proof);
            }
        }
    }
}
