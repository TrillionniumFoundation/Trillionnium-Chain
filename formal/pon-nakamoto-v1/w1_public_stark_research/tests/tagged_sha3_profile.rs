//! Encoding/known-vector checks and actual small STARK proofs, not security bounds.

use bincode::Options;
use p3_challenger::{CanObserve, CanSample, HashChallenger, SerializingChallenger64};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use sha2::Sha256;
use sha3::{Digest, Sha3_512};
use std::collections::VecDeque;
use w1_full_public_stark_research::arith_air::Dot8Row;
use w1_full_public_stark_research::arith_carry_air::Dot8PackedCarryAir;
use w1_full_public_stark_research::proof_config::{
    Compressor as OldCompressor, GOLDILOCKS_ORDER, Val,
};
use w1_full_public_stark_research::sha_air::W1ShaAir;
use w1_full_public_stark_research::sha_plan::{HashMessage, ShaPlan};
use w1_full_public_stark_research::tagged_sha3::{
    BranchCompressor, Challenge, Component, Context, LeafHasher, Role, TranscriptHasher, W1Proof,
    config, digest_bytes, digest_words, frame_header, profile_metadata, statement_context,
};

fn roundtrip(proof: &W1Proof) -> W1Proof {
    let codec = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
        .reject_trailing_bytes();
    let bytes = codec.serialize(proof).unwrap();
    codec.deserialize(&bytes).unwrap()
}

fn framed_reference(
    component: Component,
    role: Role,
    context: &Context,
    payload: &[u8],
) -> Context {
    let mut bytes = frame_header(component as u32, role, context);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    Sha3_512::digest(&bytes).into()
}

#[test]
fn sha3_standard_vector_and_full_digest_word_roundtrip() {
    assert_eq!(
        hex::encode(Sha3_512::digest([])),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );
    let bytes = core::array::from_fn(|i| (i * 37) as u8);
    assert_eq!(digest_bytes(digest_words(bytes)), bytes);
    assert_eq!(digest_bytes([u64::MAX; 8]), [255; 64]);
}

#[test]
fn actual_streaming_hashes_match_the_exact_framed_encoding() {
    let context = [42; 64];
    let fields = [Val::ZERO, Val::ONE, Val::from_u64(GOLDILOCKS_ORDER - 1)];
    let payload: Vec<_> = [0u64, 1, GOLDILOCKS_ORDER - 1]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let leaf = LeafHasher::new(Component::Sha, context);
    assert_eq!(
        digest_bytes(leaf.hash_slice(&fields)),
        framed_reference(Component::Sha, Role::Leaf, &context, &payload)
    );
    let aliased_zero = Val::from_u64(GOLDILOCKS_ORDER);
    assert_eq!(
        leaf.hash_slice(&[aliased_zero]),
        leaf.hash_slice(&[Val::ZERO])
    );
    assert_ne!(
        leaf.hash_slice(&[Val::ONE]),
        leaf.hash_slice(&[Val::ONE, Val::ZERO])
    );
    assert_ne!(leaf.hash_slice(&[]), leaf.hash_slice(&[Val::ZERO]));
    let pair = [[0x123456789abcdef0u64; 8], [u64::MAX; 8]];
    let payload: Vec<_> = pair
        .into_iter()
        .flatten()
        .flat_map(u64::to_le_bytes)
        .collect();
    assert_eq!(
        digest_bytes(BranchCompressor::new(Component::Sha, context).compress(pair)),
        framed_reference(Component::Sha, Role::Branch, &context, &payload)
    );
    for n in [0, 1, 71, 72, 73, 144, 201] {
        let payload: Vec<_> = (0..n).map(|i| i as u8).collect();
        let transcript = TranscriptHasher::new(Component::Sha, context);
        assert_eq!(
            transcript.hash_slice(&payload),
            framed_reference(Component::Sha, Role::Transcript, &context, &payload)
        );
    }
}

#[test]
fn domain_bytes_and_typed_statement_context_are_unambiguous_for_test_cases() {
    // This proves tested encodings differ, not hash collision resistance or oracle independence.
    let context = [0; 64];
    for a in [
        Role::Leaf,
        Role::Branch,
        Role::Transcript,
        Role::StatementContext,
    ] {
        for b in [
            Role::Leaf,
            Role::Branch,
            Role::Transcript,
            Role::StatementContext,
        ] {
            if a != b {
                assert_ne!(frame_header(1, a, &context), frame_header(1, b, &context));
            }
        }
    }
    assert_ne!(
        frame_header(1, Role::Leaf, &context),
        frame_header(4, Role::Leaf, &context)
    );
    assert_ne!(
        frame_header(1, Role::Leaf, &context),
        frame_header(1, Role::Leaf, &[1; 64])
    );
    assert_ne!(
        statement_context(b"a", b"bc", b"d"),
        statement_context(b"ab", b"c", b"d")
    );
    assert_ne!(
        statement_context(b"a", b"b", b"c"),
        statement_context(b"b", b"a", b"c")
    );
    assert!(Component::try_from(0).is_err());
    assert!(Component::try_from(2).is_err());
    assert!(Component::try_from(u32::MAX).is_err());
}

#[derive(Clone)]
struct ScriptedBytes(VecDeque<u8>);
impl CanObserve<u8> for ScriptedBytes {
    fn observe(&mut self, _value: u8) {}
}
impl CanSample<u8> for ScriptedBytes {
    fn sample(&mut self) -> u8 {
        self.0.pop_front().unwrap()
    }
}
#[test]
fn upstream_serializing_challenger_rejects_modulus_before_sampling_extension() {
    let bytes: VecDeque<_> = [GOLDILOCKS_ORDER, 7, 11]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let mut challenger = SerializingChallenger64::<Val, _>::new(ScriptedBytes(bytes));
    let value: Challenge = challenger.sample();
    assert_eq!(
        <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&value),
        &[Val::from_u8(7), Val::from_u8(11)]
    );
}

#[test]
fn known_raw_inverse_witness_does_not_repeat_under_explicit_new_digest_embedding() {
    let a = [
        895525109234590730u64,
        2513871637543481359,
        6866580664439037727,
        12213085372619991112,
        5421210880553664044,
        10404719342431952033,
        758541627951963262,
        6961099732014900331,
    ];
    let b = [
        18007219444761515550u64,
        15576305404914934757,
        6343815722533953670,
        5593369638671632307,
        524455038159463593,
        15550145857063644192,
        3791585759269295459,
        6656745112379943842,
    ];
    let old = OldCompressor::new(p3_goldilocks::default_goldilocks_poseidon2_8());
    let old_pair = |values: [u64; 8]| {
        core::array::from_fn(|i| core::array::from_fn(|j| Val::from_u64(values[4 * i + j])))
    };
    assert_eq!(old.compress(old_pair(a)), old.compress(old_pair(b)));
    // Explicitly pad each old four-word child to eight raw words. This one
    // regression observation does not establish arbitrary-input collision resistance.
    let embed = |values: [u64; 8]| {
        core::array::from_fn(|i| {
            core::array::from_fn(|j| if j < 4 { values[4 * i + j] } else { 0 })
        })
    };
    let new = BranchCompressor::new(Component::Sha, [0; 64]);
    assert_ne!(new.compress(embed(a)), new.compress(embed(b)));
}

fn sha_plan() -> ShaPlan {
    let messages = [b"abc".to_vec(), (0u8..120).collect()]
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| HashMessage {
            name: format!("tagged-sha3-{i}"),
            expected_digest: Sha256::digest(&bytes).into(),
            bytes,
        })
        .collect();
    ShaPlan::for_public_messages(messages).unwrap()
}

#[test]
fn tiny_sha_proof_independent_verify_rejects_context_component_statement_and_opening() {
    let context = [7; 64];
    let cfg = config(Component::Sha, context);
    let plan = sha_plan();
    let prover = W1ShaAir::new(&plan);
    let (pp, _) = setup_preprocessed(&cfg, &prover, 2).unwrap().unwrap();
    let proof =
        prove_with_preprocessed(&cfg, &prover, prover.generate_trace(), &[], Some(&pp)).unwrap();
    drop(pp);
    drop(prover);
    let verifier = W1ShaAir::public_only(&plan);
    let (pp, vk) = setup_preprocessed(&cfg, &verifier, 2).unwrap().unwrap();
    drop(pp);
    assert!(verify_with_preprocessed(&cfg, &verifier, &roundtrip(&proof), &[], Some(&vk)).is_ok());
    assert!(
        verify_with_preprocessed(
            &config(Component::Sha, [8; 64]),
            &verifier,
            &roundtrip(&proof),
            &[],
            Some(&vk)
        )
        .is_err()
    );
    assert!(
        verify_with_preprocessed(
            &config(Component::PackedCarry, context),
            &verifier,
            &roundtrip(&proof),
            &[],
            Some(&vk)
        )
        .is_err()
    );
    let mut changed = roundtrip(&proof);
    changed.opened_values.trace_local[0] += Challenge::ONE;
    assert!(verify_with_preprocessed(&cfg, &verifier, &changed, &[], Some(&vk)).is_err());
    let bytes = b"different canonical public hash message".to_vec();
    let changed_plan = ShaPlan::for_public_messages(vec![HashMessage {
        name: "changed".into(),
        expected_digest: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap();
    let changed_air = W1ShaAir::public_only(&changed_plan);
    let (pp, other_vk) = setup_preprocessed(
        &cfg,
        &changed_air,
        changed_air.trace_height().ilog2() as usize,
    )
    .unwrap()
    .unwrap();
    drop(pp);
    assert!(
        verify_with_preprocessed(&cfg, &changed_air, &roundtrip(&proof), &[], Some(&other_vk))
            .is_err()
    );
}

#[test]
fn tiny_packed_carry_proof_independent_verify_rejects_changed_goal_and_opening() {
    let cfg = config(Component::PackedCarry, [9; 64]);
    let prover = Dot8PackedCarryAir::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let (pp, _) = setup_preprocessed(&cfg, &prover, 2).unwrap().unwrap();
    let proof =
        prove_with_preprocessed(&cfg, &prover, prover.generate_trace(), &[], Some(&pp)).unwrap();
    drop(pp);
    drop(prover);
    let verifier = Dot8PackedCarryAir::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
    let (pp, vk) = setup_preprocessed(&cfg, &verifier, 2).unwrap().unwrap();
    drop(pp);
    assert!(verify_with_preprocessed(&cfg, &verifier, &roundtrip(&proof), &[], Some(&vk)).is_ok());
    let changed_air = Dot8PackedCarryAir::new(vec![Dot8Row::addition(7, 9, 17)]).unwrap();
    let (pp, other_vk) = setup_preprocessed(&cfg, &changed_air, 2).unwrap().unwrap();
    drop(pp);
    assert!(
        verify_with_preprocessed(&cfg, &changed_air, &roundtrip(&proof), &[], Some(&other_vk))
            .is_err()
    );
    let mut changed = roundtrip(&proof);
    changed.opened_values.trace_local[0] += Challenge::ONE;
    assert!(verify_with_preprocessed(&cfg, &verifier, &changed, &[], Some(&vk)).is_err());
}

#[test]
fn research_metadata_carries_no_security_bit_qualification() {
    let value = profile_metadata(&[0; 64]);
    for field in [
        "concrete_binding_bits",
        "complete_noninteractive_security_bits",
        "quantum_security_bits",
        "lifecycle_security_bits",
    ] {
        assert!(value[field].is_null());
    }
    assert_eq!(value["new_recursive_sha3_air"], false);
    assert_eq!(value["independent_role_oracle_claim"], false);
}

#[test]
fn inherited_hash_challenger_history_alias_is_recorded_not_hidden() {
    let h = TranscriptHasher::new(Component::Sha, [17; 64]);
    let mut a = HashChallenger::<u8, _, 64>::new(vec![1, 2, 3], h.clone());
    let mut b = a.clone();
    let _: u8 = a.sample();
    let _: u8 = b.sample();
    let _: u8 = b.sample();
    a.observe(99);
    b.observe(99);
    let out_a: [u8; 64] = a.sample_array();
    let out_b: [u8; 64] = b.sample_array();
    assert_eq!(out_a, out_b);
    let mut a = HashChallenger::<u8, _, 64>::new(Vec::new(), h.clone());
    let mut b = HashChallenger::<u8, _, 64>::new(Vec::new(), h);
    a.observe_slice(&[1, 2]);
    a.observe_slice(&[3]);
    b.observe_slice(&[1]);
    b.observe_slice(&[2, 3]);
    let out_a: [u8; 64] = a.sample_array();
    let out_b: [u8; 64] = b.sample_array();
    assert_eq!(out_a, out_b);
    // The frozen P3 transcript schedule must supply its own protocol argument.
    // These states alias without a SHA3 collision; this is no full-W1 forgery.
}

#[test]
fn frozen_profile_descriptor_constants_match_actual_configuration() {
    use w1_full_public_stark_research::tagged_sha3::{
        LOG_BLOWUP, LOG_FINAL_POLY_LEN, MAX_LOG_ARITY, NUM_QUERIES,
    };
    assert_eq!(
        (LOG_BLOWUP, LOG_FINAL_POLY_LEN, MAX_LOG_ARITY, NUM_QUERIES),
        (2, 0, 1, 64)
    );
    let generator =
        Challenge::from_basis_coefficients_fn(|i| if i == 1 { Val::ONE } else { Val::ZERO });
    assert_eq!(generator.square(), Challenge::from_u8(7));
}

#[test]
fn independent_python_hashlib_vectors_match_actual_hash_roles() {
    // Fixed external vectors were independently encoded with Python struct/hashlib.
    // This is interoperability evidence; it is not a collision/security proof.
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("tagged_sha3_reference_vectors.json")).unwrap();
    assert_eq!(
        reference["descriptor"].as_str().unwrap().as_bytes(),
        w1_full_public_stark_research::tagged_sha3::DESCRIPTOR
    );
    assert_eq!(
        reference["profile_id"].as_str().unwrap().as_bytes(),
        w1_full_public_stark_research::tagged_sha3::PROFILE_ID
    );
    let cases = reference["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 31);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let decode = |key: &str| hex::decode(case[key].as_str().unwrap()).unwrap();
        let context: Context = decode("context_hex").try_into().unwrap();
        let payload = decode("payload_hex");
        let role = case["role"].as_str().unwrap();
        let actual = if role == "statement_context" {
            assert_eq!(case["component"].as_u64().unwrap(), 0);
            statement_context(
                &decode("public_hex"),
                &decode("expected_header_hex"),
                &decode("expected_artifacts_hex"),
            )
        } else {
            let component =
                Component::try_from(u32::try_from(case["component"].as_u64().unwrap()).unwrap())
                    .unwrap();
            match role {
                "leaf" => {
                    assert_eq!(payload.len() % 8, 0);
                    let values: Vec<Val> = payload
                        .chunks_exact(8)
                        .map(|bytes| {
                            let word = u64::from_le_bytes(bytes.try_into().unwrap());
                            assert!(word < GOLDILOCKS_ORDER);
                            Val::from_u64(word)
                        })
                        .collect();
                    digest_bytes(LeafHasher::new(component, context).hash_slice(&values))
                }
                "branch" => {
                    assert_eq!(payload.len(), 128);
                    let pair: [[u64; 8]; 2] = core::array::from_fn(|side| {
                        core::array::from_fn(|word| {
                            let i = (side * 8 + word) * 8;
                            u64::from_le_bytes(payload[i..i + 8].try_into().unwrap())
                        })
                    });
                    digest_bytes(BranchCompressor::new(component, context).compress(pair))
                }
                "transcript" => TranscriptHasher::new(component, context).hash_slice(&payload),
                other => panic!("unknown external vector role {other}"),
            }
        };
        assert_eq!(
            hex::encode(actual),
            case["sha3_512_hex"].as_str().unwrap(),
            "{name}"
        );
    }
}
