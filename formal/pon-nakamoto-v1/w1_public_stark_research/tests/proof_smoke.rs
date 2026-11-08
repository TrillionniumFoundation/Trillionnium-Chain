//! Actual small PCS/FRI integration proofs. These are not full W1 proofs.

use bincode::Options;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha2::{Digest, Sha256};
use w1_full_public_stark_research::arith_air::{Dot8Air, Dot8Row};
use w1_full_public_stark_research::proof_config::{
    ARITH_COMPONENT, Challenge, SHA_COMPONENT, W1Proof, config, security_metadata,
};
use w1_full_public_stark_research::sha_air::W1ShaAir;
use w1_full_public_stark_research::sha_plan::{HashMessage, ShaPlan};

const TEST_PROOF_CAP: u64 = 64 * 1024 * 1024;

fn proof_codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(TEST_PROOF_CAP)
}

fn encode(proof: &W1Proof) -> Vec<u8> {
    proof_codec()
        .serialize(proof)
        .expect("bounded proof encoding")
}

fn decode(bytes: &[u8]) -> W1Proof {
    assert!((bytes.len() as u64) <= TEST_PROOF_CAP);
    proof_codec()
        .deserialize(bytes)
        .expect("bounded proof decoding")
}

fn sha_messages() -> Vec<HashMessage> {
    [b"abc".to_vec(), (0u8..120).collect::<Vec<_>>()]
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| HashMessage {
            name: format!("proof-smoke-{i}"),
            expected_digest: Sha256::digest(&bytes).into(),
            bytes,
        })
        .collect()
}

fn sha_plan(messages: Vec<HashMessage>) -> ShaPlan {
    ShaPlan::for_public_messages(messages).unwrap()
}

#[test]
fn tiny_sha_real_proof_rejects_changed_public_vk_opening_and_domain() {
    let cfg = config(SHA_COMPONENT);
    let plan = sha_plan(sha_messages());
    let prover_air = W1ShaAir::new(&plan);
    assert_eq!(prover_air.trace_height(), 4);
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
    drop(prover_air);

    // Verification uses a separately reconstructed public-only AIR and VK.
    let verifier_air = W1ShaAir::public_only(&plan);
    let (verifier_pp, vk) = setup_preprocessed(&cfg, &verifier_air, 2).unwrap().unwrap();
    drop(verifier_pp);
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], Some(&vk)).is_ok());

    let mut messages = sha_messages();
    messages[1].expected_digest[31] ^= 1;
    let changed_digest_air = W1ShaAir::public_only(&sha_plan(messages));
    let (other_pp, other_vk) = setup_preprocessed(&cfg, &changed_digest_air, 2)
        .unwrap()
        .unwrap();
    drop(other_pp);
    assert!(
        verify_with_preprocessed(
            &cfg,
            &changed_digest_air,
            &decode(&wire),
            &[],
            Some(&other_vk)
        )
        .is_err()
    );
    // Supplying a different canonical public table's key is also rejected.
    assert!(
        verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], Some(&other_vk))
            .is_err()
    );

    let mut messages = sha_messages();
    messages[1].bytes[0] ^= 1;
    messages[1].expected_digest = Sha256::digest(&messages[1].bytes).into();
    let changed_message_air = W1ShaAir::public_only(&sha_plan(messages));
    let (other_pp, changed_vk) = setup_preprocessed(&cfg, &changed_message_air, 2)
        .unwrap()
        .unwrap();
    drop(other_pp);
    assert!(
        verify_with_preprocessed(
            &cfg,
            &changed_message_air,
            &decode(&wire),
            &[],
            Some(&changed_vk)
        )
        .is_err()
    );

    let mut changed = decode(&wire);
    changed.opened_values.trace_local[0] += Challenge::ONE;
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &changed, &[], Some(&vk)).is_err());
    let mut changed = decode(&wire);
    changed.commitments.trace = changed.commitments.quotient_chunks.clone();
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
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], None).is_err());

    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(proof_codec().deserialize::<W1Proof>(&trailing).is_err());
    assert!(
        proof_codec()
            .deserialize::<W1Proof>(&wire[..wire.len() - 1])
            .is_err()
    );
}

#[test]
fn tiny_arithmetic_real_proof_rejects_changed_goal_vk_and_opening() {
    let cfg = config(ARITH_COMPONENT);
    let prover_air = Dot8Air::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
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

    let verifier_air = Dot8Air::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let (verifier_pp, vk) = setup_preprocessed(&cfg, &verifier_air, 2).unwrap().unwrap();
    drop(verifier_pp);
    assert!(verify_with_preprocessed(&cfg, &verifier_air, &decode(&wire), &[], Some(&vk)).is_ok());

    let changed_air = Dot8Air::new(vec![Dot8Row::addition(7, 9, 17)]).unwrap();
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
            &config(SHA_COMPONENT),
            &verifier_air,
            &decode(&wire),
            &[],
            Some(&vk)
        )
        .is_err()
    );
}

#[test]
fn metadata_uses_actual_widths_and_keeps_noninteractive_bound_open() {
    let sha = W1ShaAir::public_only(&sha_plan(sha_messages()));
    let arithmetic = Dot8Air::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let meta = security_metadata(&sha, &arithmetic);
    assert_eq!(meta["qualification"], "HOLD_NO_GO");
    assert_eq!(meta["sha"]["preprocessed_width"], 27);
    assert_eq!(meta["arithmetic"]["preprocessed_width"], 18);
    assert_eq!(meta["sha"]["num_batched_functions"], 15487);
    assert_eq!(meta["arithmetic"]["num_batched_functions"], 536);
    assert_eq!(meta["sha"]["is_complete_noninteractive_bound"], false);
    assert_eq!(meta["arithmetic"]["is_quantum_security_bound"], false);
}
