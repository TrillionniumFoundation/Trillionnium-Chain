//! Research-only, four-challenge AVX2 producer for the unchanged W1 relation.
//! Each 64-bit SIMD lane belongs to a different challenge. Noise products and
//! every transcript dot product execute jointly; SHA-256 state remains per lane.
//! No partial proof, verification capability, cost lower bound or fallback is supplied.
#[cfg(target_arch = "x86_64")]
use sha2::{Digest, Sha256};
use std::fmt;
use trnm_crypto_primitives::pon_work::{
    self, Hash, PreparedTask, WorkError, CELLS, N, PROOF_BYTES, Q, R,
};

pub const SIMD_LANES: usize = 4;
type Lanes = [u64; SIMD_LANES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JointError {
    Work(WorkError),
    UnsupportedAvx2,
    BatchWidth,
}
impl From<WorkError> for JointError {
    fn from(value: WorkError) -> Self {
        Self::Work(value)
    }
}
impl fmt::Display for JointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for JointError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JointProgress {
    BeforeBatch {
        active_lanes: usize,
    },
    Noise {
        lane: usize,
        label: u8,
        counter: u32,
    },
    NoiseRow {
        operand: u8,
        row: usize,
    },
    TranscriptTile {
        row: usize,
        column: usize,
        inner: usize,
    },
    BeforeDelivery,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JointGenerationError<E> {
    Relation(JointError),
    Cancelled(E),
}
impl<E> From<JointError> for JointGenerationError<E> {
    fn from(value: JointError) -> Self {
        Self::Relation(value)
    }
}

pub fn available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// One exact task's ordinary AB prefix. It has no verifier or admission authority.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub struct JointPreparedTask {
    a: Vec<u32>,
    b: Vec<u32>,
    prefix: Vec<u8>,
}
impl JointPreparedTask {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Self, JointError> {
        pon_work::task_id(a, b)?;
        if !available() {
            return Err(JointError::UnsupportedAvx2);
        }
        // Share the established exact preparation algorithm, not an uncharged
        // supplied result. Its construction, copying and destruction are paid.
        let prepared = PreparedTask::new(a, b)?;
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for value in a.iter().chain(b) {
            prefix.extend_from_slice(&value.to_le_bytes());
        }
        prefix.extend_from_slice(prepared.product_bytes());
        Ok(Self {
            a: a.to_vec(),
            b: b.to_vec(),
            prefix,
        })
    }

    pub fn prove_batch(&self, challenges: &[Hash]) -> Result<Vec<Vec<u8>>, JointError> {
        match self.prove_batch_with_progress(challenges, |_| Ok::<_, std::convert::Infallible>(()))
        {
            Ok(proofs) => Ok(proofs),
            Err(JointGenerationError::Relation(error)) => Err(error),
            Err(JointGenerationError::Cancelled(impossible)) => match impossible {},
        }
    }

    /// A cancellation discards the entire batch, including any complete local
    /// certificates at BeforeDelivery. No partial proof is returned to a caller.
    pub fn prove_batch_with_progress<E>(
        &self,
        challenges: &[Hash],
        mut progress: impl FnMut(JointProgress) -> Result<(), E>,
    ) -> Result<Vec<Vec<u8>>, JointGenerationError<E>> {
        if !(1..=SIMD_LANES).contains(&challenges.len()) {
            return Err(JointError::BatchWidth.into());
        }
        if !available() {
            return Err(JointError::UnsupportedAvx2.into());
        }
        progress(JointProgress::BeforeBatch {
            active_lanes: challenges.len(),
        })
        .map_err(JointGenerationError::Cancelled)?;
        let el = expand(challenges, 0, &mut progress)?;
        let er = expand(challenges, 1, &mut progress)?;
        let fl = expand(challenges, 2, &mut progress)?;
        let fr = expand(challenges, 3, &mut progress)?;
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: the runtime AVX2 check precedes this call. Validated
            // private buffers contain canonical words, and every load/store
            // addresses one complete [u64; 4], using unaligned intrinsics.
            unsafe { vector::complete(self, challenges, &el, &er, &fl, &fr, &mut progress) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (el, er, fl, fr);
            Err(JointError::UnsupportedAvx2.into())
        }
    }
}

fn expand<E>(
    challenges: &[Hash],
    label: u8,
    progress: &mut impl FnMut(JointProgress) -> Result<(), E>,
) -> Result<Vec<Lanes>, JointGenerationError<E>> {
    // Inactive lanes are zero. They still occupy actual SIMD arithmetic lanes;
    // neither proof output nor SHA work is invented for them.
    let mut words = vec![[0; SIMD_LANES]; N * R];
    for (lane, challenge) in challenges.iter().enumerate() {
        let mut accepted = 0;
        for counter in 0u32..128 {
            progress(JointProgress::Noise {
                lane,
                label,
                counter,
            })
            .map_err(JointGenerationError::Cancelled)?;
            let bytes = pon_work::hash(b"noise", &[challenge, &[label], &counter.to_le_bytes()]);
            for word in bytes.chunks_exact(4) {
                let value = u32::from_le_bytes(word.try_into().expect("four-byte word"));
                if u128::from(value) < Q {
                    words[accepted][lane] = u64::from(value);
                    accepted += 1;
                    if accepted == N * R {
                        break;
                    }
                }
            }
            if accepted == N * R {
                break;
            }
        }
        if accepted != N * R {
            return Err(JointError::Work(WorkError::NoiseBudget).into());
        }
    }
    Ok(words)
}

#[cfg(target_arch = "x86_64")]
mod vector {
    use super::*;
    use std::arch::x86_64::*;

    /// Exact dot products in four independent lanes. Canonical operands are
    /// below 2^32. Never accumulate their full 64-bit products in one u64:
    /// already eight near-q products would overflow.
    ///
    /// For m <= 64, low <= (m+1)(2^32-1), high <= m(2^32-1).
    /// Thus y=low+5*high < (6m+1)2^32 <= 385*2^32 < 2^41.
    /// z=(y mod 2^32)+5*floor(y/2^32) < 2^32+1925 < 2q.
    /// One conditional subtraction yields the exact canonical remainder.
    /// All comparisons are signed-safe because these values are below 2^63.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn dot(left: &[Lanes], right: &[Lanes], prior: Lanes) -> Lanes {
        assert_eq!(left.len(), right.len());
        assert!(left.len() <= N);
        // SAFETY: caller checked AVX2 and passes full four-lane words. loadu and
        // storeu impose no extra alignment requirement on [u64; 4].
        unsafe {
            let mask = _mm256_set1_epi64x(u32::MAX as i64);
            let mut low = _mm256_loadu_si256(prior.as_ptr().cast());
            let mut high = _mm256_setzero_si256();
            for (a, b) in left.iter().zip(right) {
                let product = _mm256_mul_epu32(
                    _mm256_loadu_si256(a.as_ptr().cast()),
                    _mm256_loadu_si256(b.as_ptr().cast()),
                );
                low = _mm256_add_epi64(low, _mm256_and_si256(product, mask));
                high = _mm256_add_epi64(high, _mm256_srli_epi64::<32>(product));
            }
            let y = _mm256_add_epi64(low, _mm256_add_epi64(high, _mm256_slli_epi64::<2>(high)));
            let top = _mm256_srli_epi64::<32>(y);
            let z = _mm256_add_epi64(
                _mm256_and_si256(y, mask),
                _mm256_add_epi64(top, _mm256_slli_epi64::<2>(top)),
            );
            let q = _mm256_set1_epi64x(Q as i64);
            let subtract =
                _mm256_and_si256(_mm256_cmpgt_epi64(z, _mm256_set1_epi64x(Q as i64 - 1)), q);
            let result = _mm256_sub_epi64(z, subtract);
            let mut out = [0; SIMD_LANES];
            _mm256_storeu_si256(out.as_mut_ptr().cast(), result);
            out
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn encode<E>(
        base: &[u32],
        left: &[Lanes],
        right: &[Lanes],
        operand: u8,
        progress: &mut impl FnMut(JointProgress) -> Result<(), E>,
    ) -> Result<Vec<Lanes>, JointGenerationError<E>> {
        let mut transposed = vec![[0; SIMD_LANES]; N * R];
        for k in 0..R {
            for j in 0..N {
                transposed[j * R + k] = right[k * N + j];
            }
        }
        let mut out = vec![[0; SIMD_LANES]; CELLS];
        for i in 0..N {
            progress(JointProgress::NoiseRow { operand, row: i })
                .map_err(JointGenerationError::Cancelled)?;
            for j in 0..N {
                // Adding canonical A/B as the prior performs the encoding and
                // reduction in the same bounded exact dot operation.
                // SAFETY: canonical private buffers, m=R, checked AVX2.
                out[i * N + j] = unsafe {
                    dot(
                        &left[i * R..(i + 1) * R],
                        &transposed[j * R..(j + 1) * R],
                        [u64::from(base[i * N + j]); SIMD_LANES],
                    )
                };
            }
        }
        Ok(out)
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn complete<E>(
        prepared: &JointPreparedTask,
        challenges: &[Hash],
        el: &[Lanes],
        er: &[Lanes],
        fl: &[Lanes],
        fr: &[Lanes],
        progress: &mut impl FnMut(JointProgress) -> Result<(), E>,
    ) -> Result<Vec<Vec<u8>>, JointGenerationError<E>> {
        // SAFETY: every caller enters through the runtime AVX2 dispatch.
        let ap = unsafe { encode(&prepared.a, el, er, 0, progress)? };
        let bp = unsafe { encode(&prepared.b, fl, fr, 1, progress)? };
        let mut bt = vec![[0; SIMD_LANES]; CELLS];
        for k in 0..N {
            for j in 0..N {
                bt[j * N + k] = bp[k * N + j];
            }
        }
        let mut traces: Vec<_> = challenges
            .iter()
            .map(|challenge| {
                let mut trace = Sha256::new();
                trace.update(b"TRNM-PON-TRACE1\0");
                trace.update(challenge);
                trace
            })
            .collect();
        for bi in 0..N / R {
            for bj in 0..N / R {
                let mut cells = [[0; SIMD_LANES]; R * R];
                let mut bytes = [[0; R * R * 4]; SIMD_LANES];
                for bk in 0..N / R {
                    progress(JointProgress::TranscriptTile {
                        row: bi,
                        column: bj,
                        inner: bk,
                    })
                    .map_err(JointGenerationError::Cancelled)?;
                    for i in 0..R {
                        let row = bi * R + i;
                        for j in 0..R {
                            let column = bj * R + j;
                            let pos = i * R + j;
                            // SAFETY: m=R, complete canonical SIMD words and
                            // runtime-checked target feature.
                            cells[pos] = unsafe {
                                dot(
                                    &ap[row * N + bk * R..row * N + (bk + 1) * R],
                                    &bt[column * N + bk * R..column * N + (bk + 1) * R],
                                    cells[pos],
                                )
                            };
                            for lane in 0..challenges.len() {
                                bytes[lane][pos * 4..pos * 4 + 4]
                                    .copy_from_slice(&(cells[pos][lane] as u32).to_le_bytes());
                            }
                        }
                    }
                    for (trace, words) in traces.iter_mut().zip(&bytes) {
                        trace.update(words);
                    }
                }
            }
        }
        let proofs = traces
            .into_iter()
            .map(|trace| {
                let mut proof = prepared.prefix.clone();
                proof.extend_from_slice(&trace.finalize());
                proof
            })
            .collect();
        progress(JointProgress::BeforeDelivery).map_err(JointGenerationError::Cancelled)?;
        Ok(proofs)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn simd_limb_dots_match_u128_even_when_u64_sum_would_overflow() {
            if !available() {
                return;
            }
            let q = Q as u64;
            for inner in [0, 1, R, N] {
                let mut left = vec![[0; SIMD_LANES]; inner];
                let mut right = left.clone();
                for k in 0..inner {
                    left[k] = [q - 1, q - 2, (k as u64 * 1_000_000_007) % q, 0];
                    right[k] = [q - 1, 1, (k as u64 * 2_000_000_033 + 7) % q, q - 1];
                }
                for prior in [[0; SIMD_LANES], [q - 1; SIMD_LANES]] {
                    // SAFETY: this test checks the runtime feature and all
                    // inputs obey the private canonical-word contract.
                    let actual = unsafe { dot(&left, &right, prior) };
                    for lane in 0..SIMD_LANES {
                        let expected = (u128::from(prior[lane])
                            + (0..inner)
                                .map(|k| u128::from(left[k][lane]) * u128::from(right[k][lane]))
                                .sum::<u128>())
                            % Q;
                        assert_eq!(u128::from(actual[lane]), expected);
                    }
                }
            }
            assert!(8 * (Q - 1) * (Q - 1) > u128::from(u64::MAX));
            // Mixed, independently populated lanes exercise carry patterns
            // beyond the deliberately structured extreme-word examples.
            let mut state = 0x8129_ef34_a50b_671du64;
            let mut next = || {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 32) % q
            };
            for sample in 0..32 {
                let inner = if sample % 2 == 0 { R } else { N };
                let left: Vec<Lanes> = (0..inner)
                    .map(|_| std::array::from_fn(|_| next()))
                    .collect();
                let right: Vec<Lanes> = (0..inner)
                    .map(|_| std::array::from_fn(|_| next()))
                    .collect();
                let prior = std::array::from_fn(|_| next());
                // SAFETY: AVX2 was checked above; all generated words are
                // canonical and each operand contains at most N entries.
                let actual = unsafe { dot(&left, &right, prior) };
                for lane in 0..SIMD_LANES {
                    let exact = (u128::from(prior[lane])
                        + left
                            .iter()
                            .zip(&right)
                            .map(|(a, b)| u128::from(a[lane]) * u128::from(b[lane]))
                            .sum::<u128>())
                        % Q;
                    assert_eq!(
                        u128::from(actual[lane]),
                        exact,
                        "sample={sample},lane={lane}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_material_cannot_become_a_prepared_task() {
        assert!(matches!(
            JointPreparedTask::new(&[0], &vec![0; CELLS]),
            Err(JointError::Work(WorkError::Length))
        ));
        assert!(matches!(
            JointPreparedTask::new(&vec![Q as u32; CELLS], &vec![0; CELLS]),
            Err(JointError::Work(WorkError::Field))
        ));
    }

    #[test]
    fn all_families_and_partial_lane_widths_match_original_bytes_and_full_verifiers() {
        if !available() {
            return;
        }
        for family in crate::FAMILIES {
            let material = crate::material(family).unwrap();
            let joint = JointPreparedTask::new(&material.a, &material.b).unwrap();
            let generic = PreparedTask::new(&material.a, &material.b).unwrap();
            let task = pon_work::task_id(&material.a, &material.b).unwrap();
            let challenges: Vec<_> = (0u64..SIMD_LANES as u64)
                .map(|n| {
                    pon_work::hash(
                        b"joint-functional-challenge-v1",
                        &[family.as_bytes(), &n.to_le_bytes()],
                    )
                })
                .collect();
            let all = joint.prove_batch(&challenges).unwrap();
            for lane in 0..SIMD_LANES {
                let proof = &all[lane];
                assert_eq!(proof.len(), PROOF_BYTES);
                assert_eq!(
                    *proof,
                    pon_work::prove(challenges[lane], &material.a, &material.b).unwrap()
                );
                assert_eq!(*proof, generic.prove(challenges[lane]).unwrap());
                let fast = pon_work::verify(challenges[lane], task, [255; 32], proof).unwrap();
                let reference =
                    pon_work::verify_reference(challenges[lane], task, [255; 32], proof).unwrap();
                assert_eq!(fast.ticket(), reference.ticket());
                assert_eq!(fast.product(), reference.product());
            }
            if family == "near-q-full-rank" {
                for width in 1..SIMD_LANES {
                    assert_eq!(
                        joint.prove_batch(&challenges[..width]).unwrap(),
                        all[..width]
                    );
                }
                let permuted = [challenges[3], challenges[1], challenges[1], challenges[0]];
                assert_eq!(
                    joint.prove_batch(&permuted).unwrap(),
                    vec![
                        all[3].clone(),
                        all[1].clone(),
                        all[1].clone(),
                        all[0].clone()
                    ]
                );
            }
        }
    }

    #[test]
    fn cancellation_at_each_phase_and_after_complete_construction_returns_no_proofs() {
        if !available() {
            return;
        }
        let prepared = JointPreparedTask::new(&vec![0; CELLS], &vec![0; CELLS]).unwrap();
        let challenges = [[1; 32], [2; 32], [3; 32], [4; 32]];
        for phase in 0..5 {
            let result = prepared.prove_batch_with_progress(&challenges, |point| {
                let cancel = match phase {
                    0 => matches!(point, JointProgress::BeforeBatch { .. }),
                    1 => matches!(
                        point,
                        JointProgress::Noise {
                            lane: 3,
                            label: 3,
                            counter: 0
                        }
                    ),
                    2 => matches!(point, JointProgress::NoiseRow { operand: 1, row: 1 }),
                    3 => matches!(
                        point,
                        JointProgress::TranscriptTile {
                            row: 7,
                            column: 7,
                            inner: 7
                        }
                    ),
                    _ => matches!(point, JointProgress::BeforeDelivery),
                };
                if cancel {
                    Err(phase)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Err(JointGenerationError::Cancelled(phase)));
        }
        let after = prepared.prove_batch(&challenges).unwrap();
        for (challenge, proof) in challenges.iter().zip(after) {
            pon_work::verify_reference(
                *challenge,
                pon_work::task_id(&vec![0; CELLS], &vec![0; CELLS]).unwrap(),
                [255; 32],
                &proof,
            )
            .unwrap();
        }
        assert_eq!(prepared.prove_batch(&[]), Err(JointError::BatchWidth));
        assert_eq!(
            prepared.prove_batch(&[[1; 32]; 5]),
            Err(JointError::BatchWidth)
        );
    }
}
