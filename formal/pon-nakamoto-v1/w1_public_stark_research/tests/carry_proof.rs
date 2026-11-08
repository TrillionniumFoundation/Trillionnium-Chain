//! Real PCS/FRI tests for the new carry transcript component.

use bincode::Options;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use w1_full_public_stark_research::arith_air::Dot8Row;
use w1_full_public_stark_research::arith_carry_air::{Dot8CarryAir, Dot8PackedCarryAir};
use w1_full_public_stark_research::proof_config::{
    ARITH_COMPONENT, CARRY_COMPONENT, Challenge, PACKED_CARRY_COMPONENT, W1Proof,
    carry_security_metadata, config, packed_carry_security_metadata,
};
use w1_full_public_stark_research::public::{Expected, PublicStatement};
use w1_full_public_stark_research::sha_air::W1ShaAir;

fn encode(proof: &W1Proof) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(proof)
        .unwrap()
}
fn decode(bytes: &[u8]) -> W1Proof {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(1 << 20)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .unwrap()
}

#[test]
fn carry_proof_rejects_changed_goal_vk_opening_and_old_domain() {
    let cfg = config(CARRY_COMPONENT);
    let prover_air = Dot8CarryAir::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let (pp, _) = setup_preprocessed(&cfg, &prover_air, 2).unwrap().unwrap();
    let proof = prove_with_preprocessed(
        &cfg,
        &prover_air,
        prover_air.generate_trace(),
        &[],
        Some(&pp),
    )
    .unwrap();
    let wire = encode(&proof);
    drop(pp);

    let verifier_air = Dot8CarryAir::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let (verifier_pp, vk) = setup_preprocessed(&cfg, &verifier_air, 2).unwrap().unwrap();
    drop(verifier_pp);
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], Some(&vk)).is_ok());

    let changed_air = Dot8CarryAir::new(vec![Dot8Row::addition(7, 9, 17)]).unwrap();
    let (other_pp, other_vk) = setup_preprocessed(&cfg, &changed_air, 2).unwrap().unwrap();
    drop(other_pp);
    assert!(
        verify_with_preprocessed(&cfg, &changed_air, &decode(&wire), &[], Some(&other_vk)).is_err()
    );
    assert!(
        verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], Some(&other_vk))
            .is_err()
    );

    let mut changed = decode(&wire);
    changed.opened_values.trace_local[0] += Challenge::ONE;
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &changed, &[], Some(&vk)).is_err());
    let mut changed = decode(&wire);
    changed.degree_bits += 1;
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &changed, &[], Some(&vk)).is_err());
    assert!(
        verify_with_preprocessed(
            &config(ARITH_COMPONENT),
            &verifier_air,
            &decode(&wire),
            &[],
            Some(&vk)
        )
        .is_err()
    );
}

#[test]
fn packed_carry_proof_rejects_changed_goal_vk_opening_and_old_domain() {
    let cfg = config(PACKED_CARRY_COMPONENT);
    let prover_air = Dot8PackedCarryAir::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let (pp, _) = setup_preprocessed(&cfg, &prover_air, 2).unwrap().unwrap();
    let proof = prove_with_preprocessed(
        &cfg,
        &prover_air,
        prover_air.generate_trace(),
        &[],
        Some(&pp),
    )
    .unwrap();
    let wire = encode(&proof);
    drop(pp);

    let verifier_air = Dot8PackedCarryAir::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let (verifier_pp, vk) = setup_preprocessed(&cfg, &verifier_air, 2).unwrap().unwrap();
    drop(verifier_pp);
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], Some(&vk)).is_ok());

    let changed_air = Dot8PackedCarryAir::new(vec![Dot8Row::addition(7, 9, 17)]).unwrap();
    let (other_pp, other_vk) = setup_preprocessed(&cfg, &changed_air, 2).unwrap().unwrap();
    drop(other_pp);
    assert!(
        verify_with_preprocessed(&cfg, &changed_air, &decode(&wire), &[], Some(&other_vk)).is_err()
    );
    assert!(
        verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], Some(&other_vk))
            .is_err()
    );

    let mut changed = decode(&wire);
    changed.opened_values.trace_local[0] += Challenge::ONE;
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &changed, &[], Some(&vk)).is_err());
    let mut changed = decode(&wire);
    changed.degree_bits += 1;
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &changed, &[], Some(&vk)).is_err());
    assert!(
        verify_with_preprocessed(
            &config(ARITH_COMPONENT),
            &verifier_air,
            &decode(&wire),
            &[],
            Some(&vk)
        )
        .is_err()
    );
}

#[test]
fn complete_retained_statement_preserves_every_original_arithmetic_row() {
    let expected = Expected::from_bytes(
        include_bytes!("../fixtures/retained.expected-header.bin"),
        include_bytes!("../fixtures/retained.artifacts.bin"),
    )
    .unwrap();
    let statement = PublicStatement::honest(
        include_bytes!("../fixtures/retained.input.bin").to_vec(),
        include_bytes!("../fixtures/retained.prefix.bin").to_vec(),
    )
    .unwrap();
    let (sha_plan, original) = statement.plans(&expected).unwrap();
    let carry = Dot8CarryAir::new(original.rows().to_vec()).unwrap();
    assert_eq!(carry.rows(), original.rows());
    assert_eq!(carry.real_rows(), 81_920);
    assert_eq!(carry.trace_height(), 131_072);
    let sha = W1ShaAir::public_only(&sha_plan);
    let report = carry_security_metadata(&sha, &carry);
    assert_eq!(report["component_domains"]["arithmetic"], CARRY_COMPONENT);
    assert_eq!(report["arithmetic"]["main_width"], 74);
    assert_eq!(report["arithmetic"]["preprocessed_width"], 36);
    assert_eq!(report["arithmetic"]["num_constraints"], 77);
    assert_eq!(
        report["arithmetic"]["is_complete_noninteractive_bound"],
        false
    );
    assert_eq!(report["arithmetic"]["is_quantum_security_bound"], false);
    let packed = Dot8PackedCarryAir::new(original.rows().to_vec()).unwrap();
    assert_eq!(packed.rows(), original.rows());
    assert_eq!(packed.trace_height(), 16_384);
    let packed_report = packed_carry_security_metadata(&sha, &packed);
    assert_eq!(
        packed_report["component_domains"]["arithmetic"],
        PACKED_CARRY_COMPONENT
    );
    assert_eq!(packed_report["arithmetic"]["main_width"], 370);
    assert_eq!(packed_report["arithmetic"]["preprocessed_width"], 180);
    assert_eq!(packed_report["arithmetic"]["num_constraints"], 385);
    assert_eq!(
        packed_report["arithmetic"]["is_complete_noninteractive_bound"],
        false
    );
}
