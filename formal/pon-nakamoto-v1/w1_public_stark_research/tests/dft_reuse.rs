//! Small genuine PCS proofs check cache transparency, not full W1 performance.

use bincode::Options;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha2::{Digest, Sha256};
use w1_full_public_stark_research::arith_air::{Dot8Row, Q};
use w1_full_public_stark_research::arith_carry_air::Dot8PackedCarryAir;
use w1_full_public_stark_research::proof_config::{
    CARRY_COMPONENT, Dft, PACKED_CARRY_COMPONENT, SCHEDULE_SHA_COMPONENT, W1Proof, config,
    config_with_dft,
};
use w1_full_public_stark_research::sha_plan::{HashMessage, ShaPlan};
use w1_full_public_stark_research::sha_schedule_air::ScheduledShaAir;

fn encode(proof: &W1Proof) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(64 * 1024 * 1024)
        .serialize(proof)
        .unwrap()
}

#[test]
fn shared_dft_preserves_both_components_across_distinct_transform_shapes() {
    let dft = Dft::default();
    let bytes: Vec<_> = (0u8..120).collect();
    let plan = ShaPlan::for_public_messages(vec![HashMessage {
        name: "dft-cache-transparency".into(),
        expected_digest: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap();
    let sha = ScheduledShaAir::new(&plan);
    assert_eq!(sha.trace_height(), 4);
    let original_config = config(SCHEDULE_SHA_COMPONENT);
    let shared_config = config_with_dft(SCHEDULE_SHA_COMPONENT, dft.clone());
    let (original_pp, original_vk) = setup_preprocessed(&original_config, &sha, 2)
        .unwrap()
        .unwrap();
    let (shared_pp, shared_vk) = setup_preprocessed(&shared_config, &sha, 2)
        .unwrap()
        .unwrap();
    assert_eq!(original_vk.commitment, shared_vk.commitment);
    let original_proof = prove_with_preprocessed(
        &original_config,
        &sha,
        sha.generate_trace(),
        &[],
        Some(&original_pp),
    )
    .unwrap();
    let shared_proof = prove_with_preprocessed(
        &shared_config,
        &sha,
        sha.generate_trace(),
        &[],
        Some(&shared_pp),
    )
    .unwrap();
    assert_eq!(encode(&original_proof), encode(&shared_proof));
    let public_sha = ScheduledShaAir::public_only(&plan);
    let fresh_config = config_with_dft(SCHEDULE_SHA_COMPONENT, dft.clone());
    let (_, fresh_vk) = setup_preprocessed(&fresh_config, &public_sha, 2)
        .unwrap()
        .unwrap();
    assert!(
        verify_with_preprocessed(
            &fresh_config,
            &public_sha,
            &original_proof,
            &[],
            Some(&fresh_vk),
        )
        .is_ok()
    );
    assert!(
        verify_with_preprocessed(
            &original_config,
            &public_sha,
            &shared_proof,
            &[],
            Some(&original_vk),
        )
        .is_ok()
    );

    // Use nonconstant public rows. A constant fixture is not a general test
    // that every proof must reject every alternative transcript component.
    let rows = (0u32..40)
        .map(|i| {
            let left = [65_537 + i; 8];
            let right = [1_048_579 + 2 * i; 8];
            let total = u128::from(i) + 8 * u128::from(left[0]) * u128::from(right[0]);
            Dot8Row {
                left,
                right,
                start: i,
                goal: (total % u128::from(Q)) as u32,
            }
        })
        .collect();
    let arithmetic = Dot8PackedCarryAir::new(rows).unwrap();
    assert_eq!(arithmetic.trace_height(), 8);
    let original_config = config(PACKED_CARRY_COMPONENT);
    let shared_config = config_with_dft(PACKED_CARRY_COMPONENT, dft.clone());
    let (original_pp, original_vk) = setup_preprocessed(&original_config, &arithmetic, 3)
        .unwrap()
        .unwrap();
    let (shared_pp, shared_vk) = setup_preprocessed(&shared_config, &arithmetic, 3)
        .unwrap()
        .unwrap();
    assert_eq!(original_vk.commitment, shared_vk.commitment);
    let original_proof = prove_with_preprocessed(
        &original_config,
        &arithmetic,
        arithmetic.generate_trace(),
        &[],
        Some(&original_pp),
    )
    .unwrap();
    let shared_proof = prove_with_preprocessed(
        &shared_config,
        &arithmetic,
        arithmetic.generate_trace(),
        &[],
        Some(&shared_pp),
    )
    .unwrap();
    assert_eq!(encode(&original_proof), encode(&shared_proof));
    let fresh_config = config_with_dft(PACKED_CARRY_COMPONENT, dft.clone());
    let (_, fresh_vk) = setup_preprocessed(&fresh_config, &arithmetic, 3)
        .unwrap()
        .unwrap();
    assert!(
        verify_with_preprocessed(
            &fresh_config,
            &arithmetic,
            &original_proof,
            &[],
            Some(&fresh_vk),
        )
        .is_ok()
    );
    assert!(
        verify_with_preprocessed(
            &original_config,
            &arithmetic,
            &shared_proof,
            &[],
            Some(&original_vk),
        )
        .is_ok()
    );
    let wrong_domain = config_with_dft(CARRY_COMPONENT, dft.clone());
    assert!(
        verify_with_preprocessed(
            &wrong_domain,
            &arithmetic,
            &shared_proof,
            &[],
            Some(&shared_vk),
        )
        .is_err()
    );
    let mut changed_rows = arithmetic.rows().to_vec();
    changed_rows[0].goal += 1;
    let changed = Dot8PackedCarryAir::new(changed_rows).unwrap();
    let (_, changed_vk) = setup_preprocessed(&fresh_config, &changed, 3)
        .unwrap()
        .unwrap();
    assert_ne!(shared_vk.commitment, changed_vk.commitment);
    assert!(
        verify_with_preprocessed(
            &fresh_config,
            &changed,
            &shared_proof,
            &[],
            Some(&changed_vk),
        )
        .is_err()
    );
}
