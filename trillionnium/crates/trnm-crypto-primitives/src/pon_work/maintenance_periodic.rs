//! Exact setup specialization for the fixed genesis maintenance material.
//! Every challenge uses the ordinary complete PreparedTask replay. This cache
//! contains no parent, source statement, lease, trace or verification authority.
use super::{
    field_bytes, validate, Hash, PreparedGenerationError, PreparedGenerationProgress, PreparedTask,
    WorkError, CELLS, N, PROOF_BYTES,
};

const RIGHT_MODULUS: u64 = 263;
const RIGHT_ROW_STEP: u64 = 15; // 29 * 64 mod 263.
const MAX_PRODUCT: u64 = N as u64 * 256 * 262;

#[derive(Clone, Copy)]
struct ColumnPlan {
    base: u64,
    thresholds: [usize; 4],
    count: usize,
}

impl ColumnPlan {
    fn new(base: u32) -> Self {
        let base = u64::from(base);
        debug_assert!(base < RIGHT_MODULUS);
        let count = ((base + RIGHT_ROW_STEP * (N as u64 - 1)) / RIGHT_MODULUS) as usize;
        let mut thresholds = [0; 4];
        for (index, threshold) in thresholds.iter_mut().take(count).enumerate() {
            *threshold =
                (((index + 1) as u64 * RIGHT_MODULUS - base).div_ceil(RIGHT_ROW_STEP)) as usize;
        }
        Self {
            base,
            thresholds,
            count,
        }
    }

    // B[k,j] = base + 15*k - 263*sum_l 1{k >= threshold_l}.
    // The expression is an exact nonnegative integer, before field reduction.
    fn dot(self, prefix: &[u64; N + 1], weighted: u64, length: usize) -> u64 {
        let correction: u64 = self.thresholds[..self.count]
            .iter()
            .filter(|&&threshold| threshold < length)
            .map(|&threshold| prefix[length] - prefix[threshold])
            .sum();
        self.base * prefix[length] + RIGHT_ROW_STEP * weighted - RIGHT_MODULUS * correction
    }
}

/// A complete W1 producer for exactly the public maintenance A/B. Unsupported
/// canonical material returns None; malformed operands retain Length/Field errors.
/// No arbitrary supplied product or factor can enter this constructor.
pub struct MaintenancePeriodicPreparedTask {
    inner: PreparedTask,
}

impl MaintenancePeriodicPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        validate(a)?;
        validate(b)?;
        if !a
            .iter()
            .enumerate()
            .all(|(index, &value)| value == ((13 * index + 17) % 257) as u32)
            || !b
                .iter()
                .enumerate()
                .all(|(index, &value)| value == ((29 * index + 31) % 263) as u32)
        {
            return Ok(None);
        }
        // All plan construction, row prefixes, weighted sums and the actual
        // product execute inside each constructor and therefore its setup timer.
        let plans: [ColumnPlan; N] = std::array::from_fn(|column| ColumnPlan::new(b[column]));
        let mut product = Vec::with_capacity(CELLS);
        for row in a.chunks_exact(N) {
            let mut prefix = [0; N + 1];
            let mut weighted = 0;
            for (index, &value) in row.iter().enumerate() {
                prefix[index + 1] = prefix[index] + u64::from(value);
                weighted += index as u64 * u64::from(value);
            }
            for &plan in &plans {
                let cell = plan.dot(&prefix, weighted, N);
                // Exact material guarantees AB <=64*256*262=4,292,608<q.
                // The positive pre-subtraction bound is only 12,034,048.
                debug_assert!(cell <= MAX_PRODUCT);
                product.push(cell as u32);
            }
        }
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for matrix in [a, b, product.as_slice()] {
            prefix.extend_from_slice(&field_bytes(matrix));
        }
        Ok(Some(Self {
            inner: PreparedTask {
                a: a.to_vec(),
                b: b.to_vec(),
                prefix,
            },
        }))
    }

    pub fn method(&self) -> &'static str {
        "maintenance-periodic-setup-full-transcript"
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        self.inner.prove(challenge)
    }

    pub fn prove_with_progress<E>(
        &self,
        challenge: Hash,
        progress: impl FnMut(PreparedGenerationProgress) -> Result<(), E>,
    ) -> Result<Vec<u8>, PreparedGenerationError<E>> {
        self.inner.prove_with_progress(challenge, progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{
        paired_product::PairedPreparedTask, prove, task_id, verify, verify_reference, Q, R,
    };

    fn maintenance() -> (Vec<u32>, Vec<u32>) {
        (
            (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
            (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
        )
    }

    #[test]
    fn periodic_integer_product_and_all_wrap_prefixes_match_direct_sums() {
        let (a, b) = maintenance();
        let task = MaintenancePeriodicPreparedTask::new(&a, &b)
            .unwrap()
            .unwrap();
        assert_eq!(
            task.inner.product_bytes(),
            PreparedTask::new(&a, &b).unwrap().product_bytes()
        );
        // All intercepts and prefix lengths include empty, exact-wrap and final
        // boundaries. Both zero and maximal policy-sized coefficients are used.
        for row in [vec![0; N], vec![256; N], a[..N].to_vec()] {
            let mut prefix = [0; N + 1];
            let mut weighted = [0; N + 1];
            for (index, &value) in row.iter().enumerate() {
                prefix[index + 1] = prefix[index] + u64::from(value);
                weighted[index + 1] = weighted[index] + index as u64 * u64::from(value);
            }
            for base in 0..RIGHT_MODULUS {
                let plan = ColumnPlan::new(base as u32);
                let mut expected = 0;
                for (length, &weighted_prefix) in weighted.iter().enumerate() {
                    if length != 0 {
                        let k = length - 1;
                        expected += u64::from(row[k])
                            * ((base + RIGHT_ROW_STEP * k as u64) % RIGHT_MODULUS);
                    }
                    assert_eq!(plan.dot(&prefix, weighted_prefix, length), expected);
                }
            }
        }
    }

    #[test]
    fn exact_maintenance_constructor_rejects_other_material_without_fallback() {
        let (a, b) = maintenance();
        for position in [0, CELLS / 2, CELLS - 1] {
            let mut changed_a = a.clone();
            let mut changed_b = b.clone();
            changed_a[position] ^= 1;
            changed_b[position] ^= 1;
            for (left, right) in [(&changed_a, &b), (&a, &changed_b)] {
                assert!(MaintenancePeriodicPreparedTask::new(left, right)
                    .unwrap()
                    .is_none());
            }
        }
        let zero = vec![0; CELLS];
        for (left, right) in [(&zero, &zero), (&a, &zero), (&zero, &b), (&b, &a)] {
            assert!(MaintenancePeriodicPreparedTask::new(left, right)
                .unwrap()
                .is_none());
        }
        assert!(matches!(
            MaintenancePeriodicPreparedTask::new(&a[..CELLS - 1], &b),
            Err(WorkError::Length)
        ));
        assert!(matches!(
            MaintenancePeriodicPreparedTask::new(&a, &b[..CELLS - 1]),
            Err(WorkError::Length)
        ));
        let mut invalid = a.clone();
        invalid[CELLS - 1] = Q as u32;
        assert!(matches!(
            MaintenancePeriodicPreparedTask::new(&invalid, &b),
            Err(WorkError::Field)
        ));
        assert!(matches!(
            MaintenancePeriodicPreparedTask::new(&a, &invalid),
            Err(WorkError::Field)
        ));
    }

    #[test]
    fn maintenance_setup_preserves_full_proofs_tickets_and_reject_paths() {
        let (mut a, mut b) = maintenance();
        let periodic = MaintenancePeriodicPreparedTask::new(&a, &b)
            .unwrap()
            .unwrap();
        let generic = PreparedTask::new(&a, &b).unwrap();
        let paired = PairedPreparedTask::new(&a, &b).unwrap();
        let task = task_id(&a, &b).unwrap();
        for challenge in [[0; 32], [255; 32], [7; 32], [0; 32]] {
            let proof = periodic.prove(challenge).unwrap();
            assert_eq!(proof.len(), PROOF_BYTES);
            assert_eq!(proof, generic.prove(challenge).unwrap());
            assert_eq!(proof, paired.prove(challenge).unwrap());
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
        let before = periodic.prove([19; 32]).unwrap();
        a[0] ^= 1;
        b[CELLS - 1] ^= 1;
        assert_eq!(periodic.prove([19; 32]).unwrap(), before);
        assert!(MaintenancePeriodicPreparedTask::new(&a, &b)
            .unwrap()
            .is_none());
    }

    #[test]
    fn shared_prepared_cancellation_stops_before_proof_and_cache_reuse_is_exact() {
        let (a, b) = maintenance();
        let periodic = MaintenancePeriodicPreparedTask::new(&a, &b)
            .unwrap()
            .unwrap();
        let generic = PreparedTask::new(&a, &b).unwrap();
        let challenge = [31; 32];
        let mut observed = Vec::new();
        let proof = periodic
            .prove_with_progress(challenge, |point| {
                observed.push(point);
                Ok::<_, ()>(())
            })
            .unwrap();
        let mut ordinary_points = Vec::new();
        assert_eq!(
            generic
                .prove_with_progress(challenge, |point| {
                    ordinary_points.push(point);
                    Ok::<_, ()>(())
                })
                .unwrap(),
            proof
        );
        assert_eq!(ordinary_points, observed);
        assert_eq!(
            observed.first(),
            Some(&PreparedGenerationProgress::BeforeReplay)
        );
        assert_eq!(
            observed.last(),
            Some(&PreparedGenerationProgress::BeforeProof)
        );
        assert_eq!(
            observed
                .iter()
                .filter(|point| matches!(point, PreparedGenerationProgress::TranscriptTile { .. }))
                .count(),
            (N / R).pow(3)
        );
        for (cut, point) in observed.iter().enumerate() {
            if !matches!(
                point,
                PreparedGenerationProgress::BeforeReplay
                    | PreparedGenerationProgress::BeforeProof
                    | PreparedGenerationProgress::Noise {
                        counter: 0 | 63,
                        ..
                    }
                    | PreparedGenerationProgress::NoiseRow { row: 0 | 63, .. }
                    | PreparedGenerationProgress::TranscriptTile {
                        row: 0 | 7,
                        column: 0 | 7,
                        inner: 0 | 7
                    }
            ) {
                continue;
            }
            let mut visited = Vec::new();
            let result = periodic.prove_with_progress(challenge, |point| {
                visited.push(point);
                if visited.len() - 1 == cut {
                    Err(cut)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Err(PreparedGenerationError::Cancelled(cut)));
            assert_eq!(visited, observed[..=cut]);
            assert_eq!(periodic.prove(challenge).unwrap(), proof);
        }
    }
}
