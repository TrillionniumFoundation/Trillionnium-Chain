//! Cross-language W1/W2-B/W2-C RESEARCH vector checks only.
//! This module exists solely under #[cfg(test)]; it cannot grant chainwork,
//! activate a new profile, or replace full transcript verification.
use super::{hash, prove, task_id, verify, WorkError, CELLS, PROOF_BYTES};
use sha2::{Digest, Sha256};

#[test]
fn canonical_w2b_research_statement_matches_external_python_vector_bytes() {
    let challenge: [u8; 32] = std::array::from_fn(|i| i as u8);
    let a: Vec<u32> = (0..CELLS).map(|i| (i % 97) as u32).collect();
    let b: Vec<u32> = (0..CELLS).map(|i| (i % 83) as u32).collect();
    let task = task_id(&a, &b).expect("canonical a/b");
    assert_eq!(
        hex::encode(task),
        "cac3c5379382194f355a87a5625a46d86241f0d491305a21c95a5d1c795e90da"
    );
    let proof = prove(challenge, &a, &b).expect("canonical research proof");
    assert_eq!(proof.len(), PROOF_BYTES);
    assert_eq!(
        hex::encode(Sha256::digest(&proof)),
        "b6d53b8205e0f9c1054541722fd517b73dab3235810fa65195b8074f153ffb04"
    );
    assert_eq!(
        hex::encode(&proof[PROOF_BYTES - 32..]),
        "01c964f77a54e08bf174888a15c25ed0aea7756ced4b90bb8bebc26745b0d46e"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&proof[4 + 2 * CELLS * 4..PROOF_BYTES - 32])),
        "32d788ca02e1244ec9378419999bab2aac3856d65a826982be4397af762459fd"
    );
    let target = [255; 32];
    let statement = hash(
        b"w2b-statement",
        &[
            b"pon-w2b-exact-w1-relation-research-v0",
            &challenge,
            &task,
            &target,
            &proof,
        ],
    );
    assert_eq!(
        hex::encode(statement),
        "1aa3ba12f447b66a2a9b3bea15786493eff62cd97fbfdb968067683bf78039d7"
    );
    assert!(verify(challenge, task, target, &proof).is_ok());
}

#[test]
fn canonical_w2c_separated_security_vectors_preserve_real_w1_refusal() {
    let header_seed = hash(b"w2c-research-header", &[b"A"]);
    let mut header = Vec::with_capacity(318);
    for _ in 0..9 {
        header.extend_from_slice(&header_seed);
    }
    header.extend_from_slice(&[0u8; 30]);
    assert_eq!(header.len(), 318);
    assert_eq!(
        hex::encode(Sha256::digest(&header)),
        "bf9f9e1a7443cae2f2b2da449f197d10dc9eab89d7426886c81e142df41a6d37"
    );
    let challenge = hash(b"challenge", &[&header]);
    let zero_field = vec![0u8; CELLS * 4];
    let mut fake_proof = Vec::with_capacity(PROOF_BYTES);
    fake_proof.extend_from_slice(b"PNW1");
    for _ in 0..3 {
        fake_proof.extend_from_slice(&zero_field);
    }
    fake_proof.extend_from_slice(&hash(b"w2c-false-trace", &[&challenge]));
    assert_eq!(fake_proof.len(), PROOF_BYTES);
    assert_eq!(
        hex::encode(Sha256::digest(&fake_proof)),
        "3d24f79389c76cd71ad16455709878a740f18af1da851498288ef2001dd6cd49"
    );
    let commitment = hash(
        b"w2c-proposal",
        &[b"w2c-research-security-v0", &header, &fake_proof],
    );
    assert_eq!(
        hex::encode(commitment),
        "4068356fd3bc37585ad640e23e1040cd96c2b60a9ed3b987854f0f2469637589"
    );
    for (nonce, expected) in [
        (0u64, "b2a270922619282e262ca045856a413f0b33ac0400d91045bdc1ec8a40a79fb6"),
        (1u64, "51edd0c15496b7e132cbb30e4111d32d33c9407482cfa4432b5c92fe4616bee1"),
    ] {
        let ticket = hash(
            b"w2c-security",
            &[b"w2c-research-security-v0", &commitment, &nonce.to_le_bytes()],
        );
        assert_eq!(hex::encode(ticket), expected);
    }
    let task = hash(b"task", &[&zero_field, &zero_field]);
    assert_eq!(
        verify(challenge, task, [255; 32], &fake_proof),
        Err(WorkError::Transcript)
    );
}
