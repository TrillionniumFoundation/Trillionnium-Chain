//! Per-expansion byte framing only: no hash state, result or authority is cached.
use super::{Hash, Q, VerificationError, VerificationProgress, WorkError};
use sha2::{Digest, Sha256};

fn frame(challenge: Hash, label: u8) -> [u8; 66] {
    // Exact hash(b"noise", &[challenge, [label], counter.to_le_bytes()])
    // domain and length prefixes. The changing four-byte counter is last.
    let mut bytes = [0; 66];
    bytes[..10].copy_from_slice(b"TRNM-PON1\0");
    bytes[10..12].copy_from_slice(&5_u16.to_le_bytes());
    bytes[12..17].copy_from_slice(b"noise");
    bytes[17..21].copy_from_slice(&32_u32.to_le_bytes());
    bytes[21..53].copy_from_slice(&challenge);
    bytes[53..57].copy_from_slice(&1_u32.to_le_bytes());
    bytes[57] = label;
    bytes[58..62].copy_from_slice(&4_u32.to_le_bytes());
    bytes
}

pub(super) fn expand_with_progress<E>(
    challenge: Hash,
    label: u8,
    len: usize,
    progress: &mut impl FnMut(VerificationProgress) -> Result<(), E>,
) -> Result<Vec<u32>, VerificationError<E>> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u32;
    let mut input = frame(challenge, label);
    while out.len() < len {
        if counter >= 128 {
            return Err(WorkError::NoiseBudget.into());
        }
        progress(VerificationProgress::Noise { label, counter })
            .map_err(VerificationError::Cancelled)?;
        input[62..66].copy_from_slice(&counter.to_le_bytes());
        // Still hash all 66 current bytes after each original boundary. Only
        // repeated assembly and fragmented updates are removed, not SHA work.
        let bytes: Hash = Sha256::digest(input.as_slice()).into();
        for pair in bytes.chunks_exact(4) {
            let value = u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]);
            if u128::from(value) < Q {
                out.push(value);
                if out.len() == len {
                    break;
                }
            }
        }
        counter += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{expand_with_progress as reference, hash};

    #[test]
    fn framing_matches_original_domain_and_all_part_lengths() {
        for challenge in [[0; 32], [255; 32], std::array::from_fn(|i| i as u8)] {
            for label in [0, 1, 2, 3, 255] {
                let mut input = frame(challenge, label);
                for counter in [0_u32, 1, 127, 128, u32::MAX] {
                    input[62..66].copy_from_slice(&counter.to_le_bytes());
                    let expected = hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
                    let actual: Hash = Sha256::digest(input.as_slice()).into();
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn words_callbacks_and_fixed_noise_budget_match_reference() {
        for challenge in [[0; 32], [19; 32], [255; 32]] {
            for label in [0, 1, 2, 3] {
                for len in [0, 1, 7, 8, 9, 511, 512, 1023, 1024, 1025] {
                    let mut expected_points = Vec::new();
                    let expected = reference(challenge, label, len, &mut |point| {
                        expected_points.push(point);
                        Ok::<_, usize>(())
                    });
                    let mut actual_points = Vec::new();
                    let actual = expand_with_progress(challenge, label, len, &mut |point| {
                        actual_points.push(point);
                        Ok::<_, usize>(())
                    });
                    assert_eq!(actual, expected, "label {label}, len {len}");
                    assert_eq!(actual_points, expected_points);
                    if len == 1025 {
                        assert_eq!(
                            actual,
                            Err(VerificationError::Relation(WorkError::NoiseBudget))
                        );
                        assert_eq!(actual_points.len(), 128);
                    }
                }
            }
        }
    }

    #[test]
    fn each_cancelled_noise_boundary_stops_and_retry_has_fresh_framing() {
        for label in 0..4 {
            let challenge = [31 + label; 32];
            let mut expected_points = Vec::new();
            let expected = reference(challenge, label, 512, &mut |point| {
                expected_points.push(point);
                Ok::<_, usize>(())
            })
            .unwrap();
            for cut in 0..expected_points.len() {
                let mut observed = Vec::new();
                let result = expand_with_progress(challenge, label, 512, &mut |point| {
                    observed.push(point);
                    if observed.len() - 1 == cut {
                        Err(cut)
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(result, Err(VerificationError::Cancelled(cut)));
                assert_eq!(observed, expected_points[..=cut]);
            }
            let retried =
                expand_with_progress(challenge, label, 512, &mut |_| Ok::<_, usize>(())).unwrap();
            assert_eq!(retried, expected);
            let changed = [challenge[0] ^ 0xff; 32];
            assert_eq!(
                expand_with_progress(changed, label, 512, &mut |_| Ok::<_, usize>(())),
                reference(changed, label, 512, &mut |_| Ok::<_, usize>(())),
            );
        }
    }
}
