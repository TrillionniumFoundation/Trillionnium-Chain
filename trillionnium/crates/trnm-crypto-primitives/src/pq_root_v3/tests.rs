//! Public structural fixtures and feature-gated RustCrypto key-cache controls.
//! Complete real dual-family signatures are tested by pq_root_v3_native.
use super::*;

fn public(suite: RootSuiteV3, fill: u8) -> RootPublicKeyV3 {
    let mut spki = suite.spki_prefix().to_vec();
    spki.extend(vec![fill; suite.public_key_bytes()]);
    RootPublicKeyV3 { suite, spki }
}
fn roster() -> DualFamilyRosterV3 {
    DualFamilyRosterV3::from_keys(
        RootSuiteV3::ALL
            .into_iter()
            .flat_map(|suite| (1..=3).map(move |fill| public(suite, fill)))
            .collect(),
    )
    .unwrap()
}

#[test]
fn exact_spki_lengths_and_suite_identity_are_bound() {
    // Independently computed SHA512 vectors pin the fresh domain, exact suite
    // names, big-endian framing and complete DER rather than just a round trip.
    for (suite, spki_len, sig_len, key_id) in [
        (
            RootSuiteV3::MlDsa87,
            2_614,
            4_627,
            "cfea464f6bdd4296c933df29790d2ee5f6e943f5e33bbe1bd8b8720c394d01ce2e6cef19543620161331240cc7992092ea084bd2a2eb3a3c4c5cf5801b9aaf7c",
        ),
        (
            RootSuiteV3::SlhDsaSha2_256s,
            82,
            29_792,
            "3bd49cf8531cf7121306ecc54c7ce3c89d3351f7f6037ab0e7e102175b78549010f194de8ef42dba589d361694c40f4899a8dacc3dbf836f45d164448d8f317e",
        ),
    ] {
        let key = public(suite, 1);
        assert_eq!(key.spki.len(), spki_len);
        assert_eq!(suite.signature_bytes(), sig_len);
        assert_eq!(hex::encode(key.id().unwrap()), key_id);
        assert_ne!(key.id().unwrap(), public(suite, 2).id().unwrap());
        assert_ne!(
            key.id().unwrap(),
            commitment(
                b"TRNM/RootRecoveryNativeKey/v2\0",
                &[suite.name().as_bytes(), &key.spki]
            )
        );
        for offset in 0..suite.spki_prefix().len() {
            let mut bad = key.clone();
            bad.spki[offset] ^= 1;
            assert_eq!(bad.id(), Err(RootCryptoErrorV3::PublicKeyEncoding));
        }
        let mut trailing = key.clone();
        trailing.spki.push(0);
        assert!(trailing.id().is_err());
        let mut short = key;
        short.spki.pop();
        assert!(short.id().is_err());
    }
}

#[test]
fn same_length_shake_oid_and_weaker_mldsa_cannot_be_mislabeled() {
    let mut shake = public(RootSuiteV3::SlhDsaSha2_256s, 1);
    shake.spki[14] = 0x1e;
    assert_eq!(shake.spki.len(), 82);
    assert_eq!(shake.id(), Err(RootCryptoErrorV3::PublicKeyEncoding));
    let mut weaker = public(RootSuiteV3::MlDsa87, 1);
    weaker.spki[16] = 0x12;
    assert_eq!(weaker.id(), Err(RootCryptoErrorV3::PublicKeyEncoding));
    assert_eq!(RootSuiteV3::from_wire_tag(0), Err(RootCryptoErrorV3::Suite));
    assert_eq!(RootSuiteV3::from_wire_tag(3), Err(RootCryptoErrorV3::Suite));
}

#[test]
fn entire_roster_is_exact_distinct_and_immutable_including_unused_keys() {
    let original = roster();
    let mut reversed = original.keys().to_vec();
    reversed.reverse();
    assert_eq!(DualFamilyRosterV3::from_keys(reversed).unwrap(), original);
    let mut missing = original.keys().to_vec();
    missing.pop();
    assert_eq!(
        DualFamilyRosterV3::from_keys(missing),
        Err(RootCryptoErrorV3::RosterSize)
    );
    let mut extra = original.keys().to_vec();
    extra.push(public(RootSuiteV3::MlDsa87, 4));
    assert_eq!(
        DualFamilyRosterV3::from_keys(extra),
        Err(RootCryptoErrorV3::RosterSize)
    );
    let mut duplicate = original.keys().to_vec();
    duplicate[2] = duplicate[0].clone();
    assert_eq!(
        DualFamilyRosterV3::from_keys(duplicate),
        Err(RootCryptoErrorV3::DuplicateKey)
    );
    let mut single_family = original.keys().to_vec();
    single_family[5] = public(RootSuiteV3::MlDsa87, 4);
    assert_eq!(
        DualFamilyRosterV3::from_keys(single_family),
        Err(RootCryptoErrorV3::RosterFamilies)
    );
    let mut unused = original.keys().to_vec();
    unused[5].spki[14] = 0x1e;
    assert_eq!(
        DualFamilyRosterV3::from_keys(unused),
        Err(RootCryptoErrorV3::PublicKeyEncoding)
    );
    let mut detached_ids = original.key_ids();
    detached_ids[0] = [0; 64];
    assert_ne!(original.key_ids(), detached_ids);
    assert_eq!(original, roster());
}

#[test]
fn canonical_codec_roundtrips_and_rejects_all_truncations_and_trailing_bytes() {
    let root = roster();
    let bytes = root.encode();
    assert_eq!(bytes.len(), ENCODED_ROSTER_BYTES_V3);
    assert!(bytes.len() <= 8_192);
    assert_eq!(
        hex::encode(Sha512::digest(&bytes)),
        "25db12739b9082fdaa04d8751c765da1b239dcbc62e066c75a43706740c2187a0633253015a1142dcb040d112be2fa378d3779b018c4e69d495165db691b14c7"
    );
    assert_eq!(
        hex::encode(root.commitment()),
        "d8397ce80c25b0f2e33c753a5b106541317ca26ac3727e211094f730d31ff63c5196866977a7e9233b7fcd63a5db38036df366b09d3fd774a53d8e38bba0ec54"
    );
    assert_eq!(DualFamilyRosterV3::decode(&bytes).unwrap(), root);
    for end in 0..bytes.len() {
        assert_eq!(
            DualFamilyRosterV3::decode(&bytes[..end]),
            Err(RootCryptoErrorV3::RosterEncoding)
        );
    }
    let mut appended = bytes.clone();
    appended.push(0);
    assert_eq!(
        DualFamilyRosterV3::decode(&appended),
        Err(RootCryptoErrorV3::RosterEncoding)
    );
    for offset in 0..ROSTER_WIRE_DOMAIN.len() + ROSTER_RULES.len() {
        let mut corrupted = bytes.clone();
        corrupted[offset] ^= 1;
        assert!(DualFamilyRosterV3::decode(&corrupted).is_err());
    }
}

#[test]
fn decoder_refuses_noncanonical_order_or_altered_policy_or_lengths() {
    let root = roster();
    let mut bytes = root.encode();
    let head = ROSTER_WIRE_DOMAIN.len() + ROSTER_RULES.len();
    let record = 5 + RootSuiteV3::MlDsa87.spki_bytes();
    let first = bytes[head..head + record].to_vec();
    let second = bytes[head + record..head + 2 * record].to_vec();
    bytes[head..head + record].copy_from_slice(&second);
    bytes[head + record..head + 2 * record].copy_from_slice(&first);
    assert_eq!(
        DualFamilyRosterV3::decode(&bytes),
        Err(RootCryptoErrorV3::RosterEncoding)
    );
    for offset in head..head + 5 {
        let mut bad = root.encode();
        bad[offset] ^= 0x80;
        assert!(DualFamilyRosterV3::decode(&bad).is_err());
    }
    let mut downgrade = root.encode();
    downgrade[ROSTER_WIRE_DOMAIN.len() + 3] = 1;
    assert_eq!(
        DualFamilyRosterV3::decode(&downgrade),
        Err(RootCryptoErrorV3::RosterEncoding)
    );
}

#[test]
fn complete_statement_is_framed_and_maximum_payload_is_supported() {
    let statement = vec![0xad; MAX_STATEMENT_BYTES_V3];
    let message = approval_message_v3(&statement).unwrap();
    assert_eq!(&message[..APPROVAL_DOMAIN_V3.len()], APPROVAL_DOMAIN_V3);
    assert_eq!(
        &message[APPROVAL_DOMAIN_V3.len()..APPROVAL_DOMAIN_V3.len() + 8],
        &(statement.len() as u64).to_be_bytes()
    );
    assert_eq!(&message[APPROVAL_DOMAIN_V3.len() + 8..], statement);
    let root = roster();
    for signer in root.key_ids() {
        let proof = possession_message_v3(&statement, &root, signer).unwrap();
        assert!(proof.len() <= MAX_MESSAGE_BYTES_V3);
        assert!(proof.windows(statement.len()).any(|part| part == statement));
    }
    for bad in [Vec::new(), vec![0; MAX_STATEMENT_BYTES_V3 + 1]] {
        assert_eq!(
            approval_message_v3(&bad),
            Err(RootCryptoErrorV3::MessageLength)
        );
        assert_eq!(
            operation_commitment_v3(&bad),
            Err(RootCryptoErrorV3::MessageLength)
        );
    }
}

#[test]
fn operation_identity_contains_intent_but_no_selected_quorum_or_signature_bytes() {
    let first = b"normal|scope|generation|epoch|sequence|nonce|validity|complete-policy|payload";
    let baseline = operation_commitment_v3(first).unwrap();
    assert_eq!(
        hex::encode(baseline),
        "ee5039c45fe103582ee7f04003bf81cf437be9df98d9b694792c3599cdc6b558242c480a0dee707a17590769ce745a0b21a964e50eda1ff12b7d1927035dee27"
    );
    let mut second = first.to_vec();
    second.push(0);
    assert_ne!(baseline, operation_commitment_v3(&second).unwrap());
    assert_ne!(baseline, commitment(APPROVAL_DOMAIN_V3, &[first]));
    assert_ne!(
        baseline,
        commitment(b"TRNM/RootRecoveryNativeOperation/v2\0", &[first])
    );
    assert_eq!(baseline, operation_commitment_v3(first).unwrap());
}

#[test]
fn successor_possession_binds_full_roster_role_and_full_intent() {
    let root = roster();
    let signer = root.key_ids()[0];
    let statement = b"recover|old-policy|complete-successor|nonce|payload";
    let proof = possession_message_v3(statement, &root, signer).unwrap();
    assert_ne!(proof, approval_message_v3(statement).unwrap());
    for other in &root.key_ids()[1..] {
        assert_ne!(
            proof,
            possession_message_v3(statement, &root, *other).unwrap()
        );
    }
    assert_ne!(
        proof,
        possession_message_v3(b"rotate|same-successor|other-nonce", &root, signer).unwrap()
    );
    let mut changed = root.keys().to_vec();
    changed[5] = public(RootSuiteV3::SlhDsaSha2_256s, 17);
    let changed = DualFamilyRosterV3::from_keys(changed).unwrap();
    assert_ne!(
        proof,
        possession_message_v3(statement, &changed, signer).unwrap()
    );
    assert_eq!(
        possession_message_v3(statement, &root, [0; 64]),
        Err(RootCryptoErrorV3::SignerSet)
    );
}

#[test]
fn failed_reservations_remain_charged_and_never_wrap_or_reset() {
    assert!(VerificationBudgetV3::new(0).is_err());
    assert!(VerificationBudgetV3::new(MAX_VERIFICATIONS_V3 + 1).is_err());
    let mut budget = VerificationBudgetV3::new(10).unwrap();
    budget.reserve(4, 100).unwrap();
    budget.reserve(6, 200).unwrap();
    assert_eq!(budget.attempts(), 10);
    assert_eq!(budget.charged_bytes(), 300);
    assert_eq!(budget.reserve(4, 1), Err(RootCryptoErrorV3::Budget));
    assert_eq!(budget.attempts(), 14);
    assert_eq!(budget.charged_bytes(), 301);
    assert_eq!(budget.reserve(4, 1), Err(RootCryptoErrorV3::Budget));
    let mut giant = VerificationBudgetV3::new(64).unwrap();
    assert_eq!(giant.reserve(4, u64::MAX), Err(RootCryptoErrorV3::Budget));
    assert_eq!(giant.reserve(4, 99), Err(RootCryptoErrorV3::Budget));
    assert_eq!(giant.charged_bytes(), u64::MAX);
    assert_eq!(giant.attempts(), 8);
}

#[test]
fn shared_budget_has_one_absolute_deadline_and_irreversible_cancellation() {
    assert!(VerificationBudgetV3::with_deadline(64, Instant::now()).is_err());
    let mut budget =
        VerificationBudgetV3::with_deadline(64, Instant::now() + Duration::from_millis(10))
            .unwrap();
    budget.reserve(4, 10).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(budget.checkpoint(), Err(RootCryptoErrorV3::Budget));
    assert_eq!(budget.reserve(6, 20), Err(RootCryptoErrorV3::Budget));
    assert_eq!(budget.attempts(), 10);
    let mut cancelled = VerificationBudgetV3::new(64).unwrap();
    cancelled.cancel();
    assert_eq!(cancelled.reserve(4, 10), Err(RootCryptoErrorV3::Budget));
    assert_eq!(cancelled.attempts(), 4);
}

// These cache unit tests exercise real RustCrypto ML-DSA-87 signatures. Their
// unused SLH keys are structural public fixtures; full real dual-family quorum
// behavior is covered separately by tests/pq_root_v3_native.rs.
#[cfg(feature = "pq-native-openssl")]
fn ml_dsa_cache_fixture() -> (
    DualFamilyRosterV3,
    Vec<(KeyIdV3, crate::pq_candidate::CandidateSigningKey)>,
) {
    use crate::pq_candidate::CandidateSigningKey;
    use zeroize::Zeroizing;

    let mut keys = Vec::new();
    let mut private = Vec::new();
    for fill in 1..=3 {
        let signer = CandidateSigningKey::from_owned_seed(
            CandidateAlgorithm::MlDsa87,
            Zeroizing::new([fill; 32]),
        )
        .unwrap();
        let mut spki = ML_DSA_87_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(signer.public_key());
        let key = RootPublicKeyV3 {
            suite: RootSuiteV3::MlDsa87,
            spki,
        };
        private.push((key.id().unwrap(), signer));
        keys.push(key);
        keys.push(public(RootSuiteV3::SlhDsaSha2_256s, fill));
    }
    (DualFamilyRosterV3::from_keys(keys).unwrap(), private)
}

#[cfg(feature = "pq-native-openssl")]
#[test]
fn native_cache_v3_lazy_shared_and_identity_neutral() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DualFamilyRosterV3>();
    assert_send_sync::<CandidateVerifier>();
    let (root, private) = ml_dsa_cache_fixture();
    let encoded = root.encode();
    let commitment = root.commitment();
    let clone = root.clone();
    let decoded = DualFamilyRosterV3::decode(&encoded).unwrap();
    assert!(root
        .ml_dsa_verifiers
        .iter()
        .all(|slot| slot.get().is_none()));
    assert!(Arc::ptr_eq(&root.ml_dsa_verifiers, &clone.ml_dsa_verifiers));
    assert!(!Arc::ptr_eq(
        &root.ml_dsa_verifiers,
        &decoded.ml_dsa_verifiers
    ));
    let signer = &private
        .iter()
        .find(|(id, _)| *id == root.key_ids()[0])
        .unwrap()
        .1;
    let message = approval_message_v3(b"cache-unit|complete-current-statement").unwrap();
    let signature = signer.sign(&message).unwrap();
    root.verify_signature(0, &message, &signature).unwrap();
    let expanded = root.ml_dsa_verifier(0).unwrap();
    clone.verify_signature(0, &message, &signature).unwrap();
    assert!(std::ptr::eq(expanded, clone.ml_dsa_verifier(0).unwrap()));
    assert!(root.ml_dsa_verifiers[1..]
        .iter()
        .all(|slot| slot.get().is_none()));
    assert!(decoded
        .ml_dsa_verifiers
        .iter()
        .all(|slot| slot.get().is_none()));
    assert_eq!(root, clone);
    assert_eq!(root, decoded);
    assert_eq!(root.encode(), encoded);
    assert_eq!(root.commitment(), commitment);

    // A different roster gets empty slots; editing an exported key copy cannot
    // alter the original bytes or borrow its successfully expanded verifier.
    let mut detached = root.keys().to_vec();
    detached[0] = public(RootSuiteV3::MlDsa87, 17);
    let changed = DualFamilyRosterV3::from_keys(detached).unwrap();
    assert_ne!(changed, root);
    assert_ne!(changed.commitment(), commitment);
    assert!(changed
        .ml_dsa_verifiers
        .iter()
        .all(|slot| slot.get().is_none()));
    assert!(!Arc::ptr_eq(
        &root.ml_dsa_verifiers,
        &changed.ml_dsa_verifiers
    ));
    assert_eq!(root.encode(), encoded);
}

#[cfg(feature = "pq-native-openssl")]
#[test]
fn native_cache_v3_rechecks_exact_message_and_signature() {
    let (root, private) = ml_dsa_cache_fixture();
    let ids = root.key_ids();
    let signer = &private.iter().find(|(id, _)| *id == ids[0]).unwrap().1;
    let message = approval_message_v3(b"cache-unit|exact-signed-message").unwrap();
    let signature = signer.sign(&message).unwrap();
    root.verify_signature(0, &message, &signature).unwrap();
    let expanded = root.ml_dsa_verifier(0).unwrap();
    let mut different_message = message.clone();
    different_message[0] ^= 1;
    assert_eq!(
        root.verify_signature(0, &different_message, &signature),
        Err(RootCryptoErrorV3::SignatureRejected)
    );
    let mut different_signature = signature.clone();
    different_signature[0] ^= 1;
    assert_eq!(
        root.verify_signature(0, &message, &different_signature),
        Err(RootCryptoErrorV3::SignatureRejected)
    );
    let other = &private.iter().find(|(id, _)| *id == ids[1]).unwrap().1;
    assert_eq!(
        root.verify_signature(0, &message, &other.sign(&message).unwrap()),
        Err(RootCryptoErrorV3::SignatureRejected)
    );
    assert!(std::ptr::eq(expanded, root.ml_dsa_verifier(0).unwrap()));
    root.verify_signature(0, &message, &signature).unwrap();
}

#[cfg(feature = "pq-native-openssl")]
#[test]
fn native_cache_v3_waits_for_shape_and_original_budget() {
    let root = roster();
    let ids = root.key_ids();
    let signatures = [0, 1, 3, 4]
        .into_iter()
        .map(|index| RootSignatureV3 {
            signer: ids[index],
            signature: vec![0; root.keys[index].suite.signature_bytes()],
        })
        .collect::<Vec<_>>();
    let message = approval_message_v3(b"shape-only|no-native-expansion").unwrap();
    let input_bytes = verification_input_bytes(message.len(), &signatures, 1);
    let mut short = signatures.clone();
    short[0].signature.pop();
    let short_bytes = verification_input_bytes(message.len(), &short, 1);
    let mut shared = VerificationBudgetV3::new(64).unwrap();
    assert_eq!(
        root.verify_quorum(&message, &short, &mut shared),
        Err(RootCryptoErrorV3::SignatureLength)
    );
    assert_eq!(shared.attempts(), 4);
    assert_eq!(shared.charged_bytes(), short_bytes);
    shared.cancel();
    assert_eq!(
        root.verify_quorum(&message, &signatures, &mut shared),
        Err(RootCryptoErrorV3::Budget)
    );
    assert_eq!(shared.attempts(), 8);
    assert_eq!(shared.charged_bytes(), short_bytes + input_bytes);

    let mut insufficient = VerificationBudgetV3::new(3).unwrap();
    let mut expired = VerificationBudgetV3::new(64).unwrap();
    expired.deadline = Instant::now();
    for refused in [&mut insufficient, &mut expired] {
        assert_eq!(
            root.verify_quorum(&message, &signatures, refused),
            Err(RootCryptoErrorV3::Budget)
        );
        assert_eq!(refused.attempts(), 4);
        assert_eq!(refused.charged_bytes(), input_bytes);
    }
    assert!(root
        .ml_dsa_verifiers
        .iter()
        .all(|slot| slot.get().is_none()));
}
