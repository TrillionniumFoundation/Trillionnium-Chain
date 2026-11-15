//! Version 2 adds the original raw A/B artifact commitments to the complete W1
//! statement. It reuses v1's full native replay and preserves the lottery ID.
//!
//! A proof of this guest still does not prove current-parent task eligibility,
//! signatures, registration, expiry, execution, or commit authority. Those
//! remain the original Node's checks. Only after verifying the distinct v2
//! guest image may a caller bind these public hashes to its trusted manifest.
use super::RelationError;
use trnm_crypto_primitives::pon_work;
pub use trnm_crypto_primitives::pon_work::artifacts::ArtifactCommitments;
pub use trnm_protocol::pon_wire::HEADER_BYTES;

pub const DOMAIN: &[u8] = b"TRNM-W1-ZK-JOURNAL2\0";
pub const INPUT_BYTES: usize = super::INPUT_BYTES;
pub const MODEL_OFFSET: usize = DOMAIN.len() + HEADER_BYTES + 3 * 32;
pub const INPUT_OFFSET: usize = MODEL_OFFSET + 32;
pub const PRODUCT_OFFSET: usize = INPUT_OFFSET + 32;
pub const JOURNAL_BYTES: usize = PRODUCT_OFFSET + pon_work::CELLS * 4;

/// Full original W1 replay plus original A/B commitments. Proof randomness,
/// receipt encodings, guest image and statement version do not enter work_id.
pub fn check_complete_relation(input: &[u8]) -> Result<Vec<u8>, RelationError> {
    let v1 = super::check_complete_relation(input)?;
    let artifacts =
        pon_work::artifacts::commitments(&input[HEADER_BYTES..]).map_err(RelationError::Work)?;
    let v1_product = super::DOMAIN.len() + HEADER_BYTES + 3 * 32;
    let mut out = Vec::with_capacity(JOURNAL_BYTES);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&v1[super::DOMAIN.len()..v1_product]);
    out.extend_from_slice(&artifacts.model);
    out.extend_from_slice(&artifacts.input);
    out.extend_from_slice(&v1[v1_product..]);
    debug_assert_eq!(out.len(), JOURNAL_BYTES);
    Ok(out)
}

/// Check expected public data AFTER cryptographic verification of the v2 guest
/// image. `expected_artifacts` must come from the caller's independently checked
/// current-parent task manifest/material, never from this untrusted journal.
/// This function neither verifies a receipt nor grants Node admission authority.
pub fn check_public_journal(
    expected_header: &[u8],
    expected_artifacts: &ArtifactCommitments,
    journal: &[u8],
) -> Result<[u8; 32], RelationError> {
    if journal.len() != JOURNAL_BYTES || !journal.starts_with(DOMAIN) {
        return Err(RelationError::Journal);
    }
    if journal[MODEL_OFFSET..INPUT_OFFSET] != expected_artifacts.model
        || journal[INPUT_OFFSET..PRODUCT_OFFSET] != expected_artifacts.input
    {
        return Err(RelationError::PublicStatement);
    }
    // The complete original public-byte checks remain one implementation. This
    // projection is local parsing only; it never re-labels a v1 receipt as v2.
    let mut v1 = Vec::with_capacity(super::JOURNAL_BYTES);
    v1.extend_from_slice(super::DOMAIN);
    v1.extend_from_slice(&journal[DOMAIN.len()..MODEL_OFFSET]);
    v1.extend_from_slice(&journal[PRODUCT_OFFSET..]);
    super::check_public_journal(expected_header, &v1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_protocol::pon_wire::{hash, Header};

    fn artifacts(input: &[u8]) -> ArtifactCommitments {
        let proof = &input[HEADER_BYTES..];
        // Retain the original Node expressions independently of the shared
        // helper, so a changed range or hash domain cannot move both controls.
        ArtifactCommitments {
            model: hash(b"artifact", &[&proof[4..4 + pon_work::CELLS * 4]]),
            input: hash(
                b"qualified-task-input-v1",
                &[&proof[4 + pon_work::CELLS * 4..4 + 2 * pon_work::CELLS * 4]],
            ),
        }
    }

    #[test]
    fn original_native_scalar_artifact_and_v1_identity_controls_agree() {
        for seed in [0, 1, u32::MAX] {
            let input = super::super::fixture(seed);
            let header = Header::decode(&input[..HEADER_BYTES]).unwrap();
            let proof = &input[HEADER_BYTES..];
            let scalar = pon_work::verify_reference(
                header.challenge(),
                header.work_task,
                header.target,
                proof,
            )
            .unwrap();
            let journal = check_complete_relation(&input).unwrap();
            assert_eq!(journal.len(), 16_882);
            assert_eq!(INPUT_BYTES, 49_506);
            let expected = artifacts(&input);
            assert_eq!(pon_work::artifacts::commitments(proof), Ok(expected));
            assert_eq!(&journal[MODEL_OFFSET..INPUT_OFFSET], &expected.model);
            assert_eq!(&journal[INPUT_OFFSET..PRODUCT_OFFSET], &expected.input);
            let product: Vec<_> = scalar
                .product()
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            assert_eq!(&journal[PRODUCT_OFFSET..], &product);
            let trace = proof[proof.len() - 32..].try_into().unwrap();
            let v2_id = check_public_journal(&header.encode(), &expected, &journal).unwrap();
            let v1_journal = super::super::check_complete_relation(&input).unwrap();
            let v1_id = super::super::check_public_journal(&header.encode(), &v1_journal).unwrap();
            assert_eq!(v2_id, v1_id);
            assert_eq!(v2_id, header.block_id(trace));
            assert_eq!(
                &journal[DOMAIN.len() + HEADER_BYTES + 32..MODEL_OFFSET - 32],
                scalar.ticket().as_slice()
            );
            assert_eq!(journal, check_complete_relation(&input).unwrap());
        }
    }

    #[test]
    fn wrong_manifest_commitments_and_cross_task_artifacts_are_rejected() {
        let input = super::super::fixture(7);
        let journal = check_complete_relation(&input).unwrap();
        let expected = artifacts(&input);
        let mut wrong_model = expected;
        wrong_model.model[0] ^= 1;
        let mut wrong_input = expected;
        wrong_input.input[31] ^= 1;
        let swapped = ArtifactCommitments {
            model: expected.input,
            input: expected.model,
        };
        let other = artifacts(&super::super::fixture(8));
        for wrong in [wrong_model, wrong_input, swapped, other] {
            assert_eq!(
                check_public_journal(&input[..HEADER_BYTES], &wrong, &journal),
                Err(RelationError::PublicStatement)
            );
        }
        for offset in [
            MODEL_OFFSET,
            INPUT_OFFSET - 1,
            INPUT_OFFSET,
            PRODUCT_OFFSET - 1,
        ] {
            let mut changed = journal.clone();
            changed[offset] ^= 1;
            assert_eq!(
                check_public_journal(&input[..HEADER_BYTES], &expected, &changed),
                Err(RelationError::PublicStatement)
            );
        }
    }

    #[test]
    fn v1_and_v2_domains_lengths_and_headers_cannot_be_substituted() {
        let input = super::super::fixture(9);
        let expected = artifacts(&input);
        let v1 = super::super::check_complete_relation(&input).unwrap();
        let v2 = check_complete_relation(&input).unwrap();
        assert_eq!(
            check_public_journal(&input[..HEADER_BYTES], &expected, &v1),
            Err(RelationError::Journal)
        );
        assert_eq!(
            super::super::check_public_journal(&input[..HEADER_BYTES], &v2),
            Err(RelationError::Journal)
        );
        let mut wrong_domain = v2.clone();
        wrong_domain[..DOMAIN.len()].copy_from_slice(super::super::DOMAIN);
        assert_eq!(
            check_public_journal(&input[..HEADER_BYTES], &expected, &wrong_domain),
            Err(RelationError::Journal)
        );
        for length in [0, JOURNAL_BYTES - 1, JOURNAL_BYTES + 1] {
            let mut changed = v2.clone();
            changed.resize(length, 0);
            assert_eq!(
                check_public_journal(&input[..HEADER_BYTES], &expected, &changed),
                Err(RelationError::Journal)
            );
        }
        let other = super::super::fixture(10);
        assert!(check_public_journal(&other[..HEADER_BYTES], &expected, &v2).is_err());
        for offset in [
            DOMAIN.len(),
            DOMAIN.len() + HEADER_BYTES,
            DOMAIN.len() + HEADER_BYTES + 32,
            DOMAIN.len() + HEADER_BYTES + 64,
        ] {
            let mut changed = v2.clone();
            changed[offset] ^= 1;
            assert!(check_public_journal(&input[..HEADER_BYTES], &expected, &changed).is_err());
        }
        let mut changed = v2;
        changed[PRODUCT_OFFSET..PRODUCT_OFFSET + 4]
            .copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
        assert!(check_public_journal(&input[..HEADER_BYTES], &expected, &changed).is_err());
    }

    #[test]
    fn full_native_replay_rejects_each_matrix_transcript_and_noncanonical_material() {
        let input = super::super::fixture(11);
        let header = Header::decode(&input[..HEADER_BYTES]).unwrap();
        let mut cases = Vec::new();
        for (matrix, error) in [
            (0, pon_work::WorkError::Task),
            (1, pon_work::WorkError::Task),
            (2, pon_work::WorkError::Product),
        ] {
            let mut changed = input.clone();
            let offset = HEADER_BYTES + 4 + matrix * pon_work::CELLS * 4;
            let old = u32::from_le_bytes(changed[offset..offset + 4].try_into().unwrap());
            changed[offset..offset + 4].copy_from_slice(&u32::from(old == 0).to_le_bytes());
            cases.push((changed, error));
        }
        let mut changed = input.clone();
        *changed.last_mut().unwrap() ^= 1;
        cases.push((changed, pon_work::WorkError::Transcript));
        for matrix in 0..3 {
            for word in pon_work::Q as u32..=u32::MAX {
                let mut changed = input.clone();
                let offset = HEADER_BYTES + 4 + matrix * pon_work::CELLS * 4;
                changed[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
                cases.push((changed, pon_work::WorkError::Field));
            }
        }
        for (changed, error) in cases {
            assert_eq!(
                check_complete_relation(&changed),
                Err(RelationError::Work(error))
            );
            assert_eq!(
                pon_work::verify_reference(
                    header.challenge(),
                    header.work_task,
                    header.target,
                    &changed[HEADER_BYTES..],
                )
                .unwrap_err(),
                error
            );
        }
        for length in [0, INPUT_BYTES - 1, INPUT_BYTES + 1] {
            let mut changed = input.clone();
            changed.resize(length, 0);
            assert_eq!(
                check_complete_relation(&changed),
                Err(RelationError::InputLength)
            );
        }
        let mut zero_target = input;
        zero_target[118..150].fill(0);
        assert_eq!(
            check_complete_relation(&zero_target),
            Err(RelationError::Work(pon_work::WorkError::Target))
        );
    }
}
