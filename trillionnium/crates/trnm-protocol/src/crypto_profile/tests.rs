use super::*;
use std::collections::BTreeSet;

// Golden vectors were produced by a separate Python struct/hashlib encoder,
// with no import or execution of this Rust implementation. The fixed binding
// uses network=01*32, parameters=02*32, genesis=03*32, activation=10,
// retirement=100; legacy uses NativeAccounts/v3, candidates WholeSystem/v1.
// The work vector independently hashes:
// hashlib.sha512(b"TRNM/CryptoProfile/ExternalWork/v1\0"
//   + len(raw).to_bytes(8, "big") + raw).hexdigest()
// where raw is the exact 1,596-byte config/pon/work-profile-v1.json.
const WORK_DIGEST: &str = concat!(
    "6da47a17baafdcf3748010f4fc5a9291a31ed0a8fd3ac26e41df98cd5f7685bc8f8d",
    "80325c21105bb21b1b1c24da723e4345306c1f8e579cb8f5d5c6dc0c0632"
);
const LEGACY_ID: &str = concat!(
    "383f7248521f19c04186c1e900b3cba5d7b459b34ace38f5bbbe8fa5c91dbe92",
    "d85f92a5a1c313c1cef420a48cd4849136144ca9228e156b6bae5d120025cafd"
);
const CANDIDATE65_ID: &str = concat!(
    "8f572de360c4ffa4681d027b3c2ef0499e159ad3de2e5eccaedcffb8149e88fd",
    "fec814ae4523e25fbbe402d05b5eed54b3287c40aca16b006d504b4832dcd3ba"
);
const CANDIDATE87_ID: &str = concat!(
    "3d95c89d2e8ffe72d936476106fba9583d7f93a0c984fd6881d9475c3f5fa7a8",
    "47e723340e0c33688310e75697221f2ac3fd58f8d08f75097a04ae5a8bfa83a5"
);

fn fixed_binding(scope: ProfileScope, protocol_version: u32) -> ProfileBinding {
    ProfileBinding {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        protocol_version,
        scope,
        activation_height: 10,
        retirement_height: Some(100),
    }
}

fn candidate(profile: CryptoProfile) -> BoundCryptoProfile {
    profile
        .bind(fixed_binding(ProfileScope::WholeSystemCandidate, 1))
        .unwrap()
}

fn legacy(activation: u64, retirement: Option<u64>) -> BoundCryptoProfile {
    CryptoProfile::LegacyMlDsa65V1
        .bind(ProfileBinding {
            activation_height: activation,
            retirement_height: retirement,
            ..fixed_binding(ProfileScope::NativeAccounts, 3)
        })
        .unwrap()
}

fn envelope<'a>(ids: &'a [[u8; 64]], payload: &'a [u8]) -> CandidateEnvelope<'a> {
    CandidateEnvelope {
        purpose: CryptoPurpose::FinalUse,
        owner_generation: 7,
        key_epoch: 3,
        sequence: 11,
        valid_from_height: 10,
        valid_until_height: 99,
        signer_ids: ids,
        payload,
    }
}

fn rejected<T>(result: Result<T, ProfileError>, expected: ProfileError) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("unexpected success; expected {expected:?}"),
    }
}

// These deliberately noncryptographic fixtures exercise the protocol parser.
// Acceptance returns UnverifiedCandidateSignatures, never authentication.
struct UnverifiedSigners {
    ids: Vec<[u8; 64]>,
    keys: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
}

impl UnverifiedSigners {
    fn new(profile: &BoundCryptoProfile, count: u8) -> Self {
        let mut rows: Vec<_> = (1..=count)
            .map(|byte| {
                let key = vec![byte; profile.profile().public_key_bytes()];
                let id = profile.commitment(HashPurpose::KeyIdentity, &key).unwrap();
                (id, key)
            })
            .collect();
        rows.sort_unstable_by_key(|row| row.0);
        Self {
            ids: rows.iter().map(|row| row.0).collect(),
            keys: rows.into_iter().map(|row| row.1).collect(),
            signatures: (0..count)
                .map(|_| vec![0; profile.profile().signature_bytes()])
                .collect(),
        }
    }

    fn keys(&self) -> Vec<&[u8]> {
        self.keys.iter().map(Vec::as_slice).collect()
    }

    fn signatures(&self) -> Vec<&[u8]> {
        self.signatures.iter().map(Vec::as_slice).collect()
    }
}

#[test]
fn independent_python_sha512_vectors_bind_complete_configuration_and_work() {
    assert_eq!(WORK_PROFILE_BYTES.len(), 1_596);
    assert_eq!(hex::encode(native_work_configuration_digest()), WORK_DIGEST);
    let cases = [
        (legacy(10, Some(100)), 2605, LEGACY_ID),
        (
            CryptoProfile::LegacyMlDsa65V1
                .bind(fixed_binding(ProfileScope::NativePeer, 2))
                .unwrap(),
            1800,
            concat!(
                "910e3ccd6b4a32dadd1d74e222402e21f5ac67e4a31ab4cfaee102588f0ba000",
                "5d01cf70b300af2bea278adb479e8b556bb2b7798dea8ad326100ebbadc7087c"
            ),
        ),
        (
            candidate(CryptoProfile::CandidateMlDsa65V1),
            1529,
            CANDIDATE65_ID,
        ),
        (
            candidate(CryptoProfile::CandidateMlDsa87V1),
            1529,
            CANDIDATE87_ID,
        ),
    ];
    for (profile, expected_bytes, expected_id) in cases {
        assert_eq!(profile.canonical_configuration().len(), expected_bytes);
        assert_eq!(profile.id().to_hex(), expected_id);
    }
}

#[test]
fn candidate_configuration_commits_actual_envelope_commitment_and_wire_domains() {
    for kind in [
        CryptoProfile::CandidateMlDsa65V1,
        CryptoProfile::CandidateMlDsa87V1,
    ] {
        let profile = candidate(kind);
        let configuration = profile.canonical_configuration();
        let mut expected_order = Vec::new();
        for domain in [
            ENVELOPE_DOMAIN,
            COMMITMENT_DOMAIN,
            CPQ1_MAGIC.as_slice(),
            CANDIDATE_MESSAGE_ENCODING,
            CANDIDATE_WIRE_ENCODING,
            CANDIDATE_COMMITMENT_ENCODING,
        ] {
            // Construct each framed field independently of the production field
            // helper. Merely naming CPQ1 elsewhere cannot satisfy this check.
            let mut framed = (domain.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(domain);
            let positions: Vec<_> = configuration
                .windows(framed.len())
                .enumerate()
                .filter_map(|(at, value)| (value == framed).then_some(at))
                .collect();
            assert_eq!(positions.len(), 1);
            let mut changed = configuration.clone();
            changed[positions[0] + 4] ^= 1;
            assert_ne!(hex::encode(Sha512::digest(&changed)), profile.id().to_hex());
            expected_order.extend_from_slice(&framed);
        }
        assert!(configuration
            .windows(expected_order.len())
            .any(|value| value == expected_order));

        let fixtures = UnverifiedSigners::new(&profile, 1);
        let keys = fixtures.keys();
        let signatures = fixtures.signatures();
        let expected = envelope(&fixtures.ids, b"candidate domain binding");
        let message = profile.candidate_message(&expected).unwrap();
        let wire = profile
            .candidate_wire(&expected, &keys, &signatures)
            .unwrap();
        assert!(message.starts_with(ENVELOPE_DOMAIN));
        assert!(wire.starts_with(CPQ1_MAGIC));
        // These bytes are deliberately not real signatures. This only proves
        // that the shared wire grammar yields an unverified parsed view.
        assert!(profile
            .check_candidate_wire(&wire, &expected, &keys)
            .is_ok());
    }
}

#[test]
fn independent_python_vectors_cover_full_messages_key_ids_and_payload_commitments() {
    let ids = [[0x11; 64], [0x22; 64]];
    let payload = b"fixed payload\0\xff";
    let cases = [
        (
            CryptoProfile::CandidateMlDsa65V1,
            concat!(
                "62729ec888002409e53b78b282d945db4dd053631ee420db54d17fcc171bdfea",
                "2e23016de914ca2dd52ab02e0216b10610ea32ec0dc5f67e7c7d8a088683b941"
            ),
            concat!(
                "f35d1be0d5a4d987ece3db69cc06a5f866713b3181f2a58b9bf2329c097474d4",
                "b7f260757ed24c129f90956c00b0e804a2e67e3979430f1534de1241aa5eed29"
            ),
            concat!(
                "acd56df42eb8d3319807009ff89374d1c1f3908a76473f6c4d9644d1ac08441c",
                "2e93106794ba147a49eb831d954fcc854a10f4752811914fc951f9281852d569"
            ),
        ),
        (
            CryptoProfile::CandidateMlDsa87V1,
            concat!(
                "ba704811e1b34308e00a5e9ead76acc8fb57db80ec71084df3b93db8b68baf99",
                "174254aaaf6a9e553adfdf8f62bac6b68036f41fafa43c8139d4bc1b4aa91f43"
            ),
            concat!(
                "ca8d068d6e11e1c2658d7e27137b74a1d195d02084b5e465c8d286a2460729f3",
                "3b1a24697c8c998b66c19daf7cacca8a54eb9ab7dabb5ebd9d2c35a0914554a9"
            ),
            concat!(
                "08022f1e411492cb876c2395b210574dec4acdfe60f12c28b9e3d0bd1cd721ff",
                "5f84f1dc2a5f53625105fc7505eb8686081c4fd29069f452d608b0e160efdca6"
            ),
        ),
    ];
    for (kind, payload_digest, key_id, message_digest) in cases {
        let profile = candidate(kind);
        let key = vec![7; kind.public_key_bytes()];
        assert_eq!(
            hex::encode(profile.commitment(HashPurpose::Payload, payload).unwrap()),
            payload_digest
        );
        assert_eq!(
            hex::encode(profile.commitment(HashPurpose::KeyIdentity, &key).unwrap()),
            key_id
        );
        let message = profile.candidate_message(&envelope(&ids, payload)).unwrap();
        assert_eq!(message.len(), 350);
        assert_eq!(hex::encode(Sha512::digest(&message)), message_digest);
    }
}

#[test]
fn every_trusted_binding_dimension_changes_profile_identity() {
    let base = fixed_binding(ProfileScope::NativeAccounts, 2);
    let original = CryptoProfile::LegacyMlDsa65V1.bind(base).unwrap();
    let mut identities = BTreeSet::from([original.id()]);
    for field in 0..8 {
        let mut changed = base;
        match field {
            0 => changed.network[31] ^= 1,
            1 => changed.genesis[31] ^= 1,
            2 => changed.parameters[31] ^= 1,
            3 => changed.protocol_version = 4,
            4 => changed.scope = ProfileScope::NativePeer,
            5 => changed.activation_height = 11,
            6 => changed.retirement_height = Some(101),
            7 => changed.retirement_height = None,
            _ => unreachable!(),
        }
        let bound = CryptoProfile::LegacyMlDsa65V1.bind(changed).unwrap();
        assert!(identities.insert(bound.id()), "binding field {field}");
        rejected(
            original.require_claim(bound.id()),
            ProfileError::ProfileMismatch,
        );
    }
    assert_ne!(
        candidate(CryptoProfile::CandidateMlDsa65V1).id(),
        candidate(CryptoProfile::CandidateMlDsa87V1).id()
    );
}

#[test]
fn binding_rejects_zero_roots_invalid_windows_and_unsupported_scope_versions() {
    let original = fixed_binding(ProfileScope::NativeAccounts, 3);
    for field in 0..8 {
        let mut changed = original;
        match field {
            0 => changed.network = [0; 32],
            1 => changed.parameters = [0; 32],
            2 => changed.genesis = [0; 32],
            3 => changed.retirement_height = Some(10),
            4 => changed.retirement_height = Some(9),
            5 => changed.protocol_version = 1,
            6 => changed.protocol_version = 7,
            7 => changed.scope = ProfileScope::WholeSystemCandidate,
            _ => unreachable!(),
        }
        rejected(
            CryptoProfile::LegacyMlDsa65V1.bind(changed),
            ProfileError::InvalidBinding,
        );
    }
    for kind in [
        CryptoProfile::CandidateMlDsa65V1,
        CryptoProfile::CandidateMlDsa87V1,
    ] {
        rejected(kind.bind(original), ProfileError::InvalidBinding);
        rejected(
            kind.bind(fixed_binding(ProfileScope::WholeSystemCandidate, 2)),
            ProfileError::InvalidBinding,
        );
    }
    rejected(
        CryptoProfile::LegacyMlDsa65V1.bind(fixed_binding(ProfileScope::NativePeer, 3)),
        ProfileError::InvalidBinding,
    );
    for version in [0, 1, 2, 3, 4, 6, u32::MAX] {
        rejected(
            CryptoProfile::LegacyMlDsa65V1.bind(fixed_binding(ProfileScope::Operator, version)),
            ProfileError::InvalidBinding,
        );
    }
}

#[test]
fn identifier_text_has_one_exact_lowercase_encoding() {
    let original = candidate(CryptoProfile::CandidateMlDsa65V1).id();
    assert_eq!(CryptoProfileId::from_hex(CANDIDATE65_ID).unwrap(), original);
    assert_eq!(original.as_bytes().len(), 64);
    for malformed in [
        CANDIDATE65_ID.to_uppercase(),
        format!("0x{CANDIDATE65_ID}"),
        format!(" {CANDIDATE65_ID}"),
        format!("{CANDIDATE65_ID}\n"),
        CANDIDATE65_ID[..127].to_owned(),
        format!("{CANDIDATE65_ID}0"),
        format!("g{}", &CANDIDATE65_ID[1..]),
        "é".repeat(64),
        String::new(),
    ] {
        rejected(
            CryptoProfileId::from_hex(&malformed),
            ProfileError::Encoding,
        );
    }
    // A syntactically valid unknown ID does not become an allowed profile.
    let zero = CryptoProfileId::from_hex(&"0".repeat(128)).unwrap();
    rejected(
        candidate(CryptoProfile::CandidateMlDsa65V1).require_claim(zero),
        ProfileError::ProfileMismatch,
    );
}

#[test]
fn both_candidates_and_message_chosen_ids_are_refused_for_current_effects() {
    for kind in [
        CryptoProfile::CandidateMlDsa65V1,
        CryptoProfile::CandidateMlDsa87V1,
    ] {
        let bound = candidate(kind);
        let id = bound.id();
        let policy = CryptoProfilePolicy::from_trusted_state(bound, 20, 1, vec![]).unwrap();
        rejected(policy.select_current(id), ProfileError::CandidateOnly);
        rejected(
            policy.select_historical(id, 20),
            ProfileError::CandidateOnly,
        );
    }
    let bound = legacy(10, Some(100));
    let id = bound.id();
    let policy = CryptoProfilePolicy::from_trusted_state(bound, 20, 1, vec![]).unwrap();
    assert_eq!(policy.select_current(id).unwrap().selected().id(), id);
    for foreign in [
        candidate(CryptoProfile::CandidateMlDsa65V1).id(),
        candidate(CryptoProfile::CandidateMlDsa87V1).id(),
        CryptoProfileId::from_hex(&"0".repeat(128)).unwrap(),
    ] {
        rejected(
            policy.select_current(foreign),
            ProfileError::ProfileMismatch,
        );
        rejected(
            policy.select_historical(foreign, 20),
            ProfileError::UnknownProfile,
        );
    }
}

#[test]
fn current_selection_enforces_activation_and_exclusive_retirement() {
    for (height, active) in [(9, false), (10, true), (99, true), (100, false)] {
        let bound = legacy(10, Some(100));
        let id = bound.id();
        let policy = CryptoProfilePolicy::from_trusted_state(bound, height, 1, vec![]).unwrap();
        if active {
            assert_eq!(policy.select_current(id).unwrap().selected().id(), id);
        } else {
            rejected(policy.select_current(id), ProfileError::Inactive);
        }
    }
}

#[test]
fn historical_records_keep_their_own_window_and_cannot_select_current_effects() {
    let first = legacy(10, Some(20));
    let second = legacy(20, Some(30));
    let current = legacy(30, Some(100));
    let first_id = first.id();
    let second_id = second.id();
    let current_id = current.id();
    let policy =
        CryptoProfilePolicy::from_trusted_state(current, 40, 3, vec![second, first]).unwrap();
    for (id, first_height, last_height) in [(first_id, 10, 19), (second_id, 20, 29)] {
        for height in [first_height, last_height] {
            let historical = policy.select_historical(id, height).unwrap();
            assert_eq!(historical.record_height(), height);
            assert_eq!(historical.selected().id(), id);
        }
        rejected(
            policy.select_historical(id, first_height - 1),
            ProfileError::Inactive,
        );
        rejected(
            policy.select_historical(id, last_height + 1),
            ProfileError::Inactive,
        );
        rejected(policy.select_current(id), ProfileError::ProfileMismatch);
    }
    assert!(policy.select_current(current_id).is_ok());
    assert!(policy.select_historical(current_id, 40).is_ok());
    rejected(
        policy.select_historical(current_id, 41),
        ProfileError::Inactive,
    );
    rejected(
        policy.select_historical(current_id, 29),
        ProfileError::Inactive,
    );
}

#[test]
fn history_refuses_duplicate_open_overlapping_and_future_intervals() {
    let current = legacy(40, Some(100));
    let first = legacy(10, Some(20));
    let cases = [
        vec![first.clone(), first.clone()],
        vec![legacy(10, None)],
        vec![legacy(10, Some(41))],
        vec![first.clone(), legacy(19, Some(30))],
        vec![legacy(19, Some(30)), first],
        vec![current.clone()],
    ];
    for history in cases {
        rejected(
            CryptoProfilePolicy::from_trusted_state(current.clone(), 50, 1, history),
            ProfileError::InvalidBinding,
        );
    }
    // Touching half-open intervals are allowed, even if registry input is not sorted.
    assert!(CryptoProfilePolicy::from_trusted_state(
        current,
        50,
        1,
        vec![legacy(20, Some(40)), legacy(10, Some(20))],
    )
    .is_ok());
}

#[test]
fn history_refuses_foreign_roots_scopes_candidates_and_excess_entries() {
    let current = legacy(100, None);
    let original = legacy(10, Some(20));
    for field in 0..3 {
        let mut binding = *original.binding();
        match field {
            0 => binding.network[0] ^= 1,
            1 => binding.genesis[0] ^= 1,
            2 => {
                binding.scope = ProfileScope::NativePeer;
                binding.protocol_version = 2;
            }
            _ => unreachable!(),
        }
        let old = CryptoProfile::LegacyMlDsa65V1.bind(binding).unwrap();
        rejected(
            CryptoProfilePolicy::from_trusted_state(current.clone(), 100, 1, vec![old]),
            ProfileError::InvalidBinding,
        );
    }
    rejected(
        CryptoProfilePolicy::from_trusted_state(
            current.clone(),
            100,
            1,
            vec![candidate(CryptoProfile::CandidateMlDsa65V1)],
        ),
        ProfileError::InvalidBinding,
    );
    let history: Vec<_> = (0..16).map(|i| legacy(2 * i, Some(2 * i + 1))).collect();
    assert!(
        CryptoProfilePolicy::from_trusted_state(current.clone(), 100, 1, history.clone()).is_ok()
    );
    let mut excessive = history;
    excessive.push(legacy(40, Some(41)));
    rejected(
        CryptoProfilePolicy::from_trusted_state(current.clone(), 100, 1, excessive),
        ProfileError::InvalidBinding,
    );
    rejected(
        CryptoProfilePolicy::from_trusted_state(current, 100, 0, vec![]),
        ProfileError::InvalidBinding,
    );
}

#[test]
fn current_observation_is_rechecked_against_generation_identity_and_height() {
    let bound = legacy(10, Some(100));
    let id = bound.id();
    let before = CryptoProfilePolicy::from_trusted_state(bound.clone(), 20, 7, vec![]).unwrap();
    let selected = before.select_current(id).unwrap();
    assert!(before.recheck_current(&selected).is_ok());
    let revoked = CryptoProfilePolicy::from_trusted_state(bound.clone(), 20, 8, vec![]).unwrap();
    rejected(revoked.recheck_current(&selected), ProfileError::StaleState);
    let expired = CryptoProfilePolicy::from_trusted_state(bound.clone(), 100, 7, vec![]).unwrap();
    rejected(expired.recheck_current(&selected), ProfileError::Inactive);
    let mut changed = *bound.binding();
    changed.parameters[0] ^= 1;
    let changed = CryptoProfile::LegacyMlDsa65V1.bind(changed).unwrap();
    let changed = CryptoProfilePolicy::from_trusted_state(changed, 20, 7, vec![]).unwrap();
    rejected(changed.recheck_current(&selected), ProfileError::StaleState);
}

#[test]
fn signature_profiles_cannot_replace_work_challenge_or_ticket_hashes() {
    for bound in [
        legacy(10, Some(100)),
        candidate(CryptoProfile::CandidateMlDsa65V1),
        candidate(CryptoProfile::CandidateMlDsa87V1),
    ] {
        for purpose in [HashPurpose::WorkChallenge, HashPurpose::WorkTicket] {
            assert_eq!(
                bound.profile().hash_rule(purpose),
                HashRule::ExternalNativeWork
            );
            assert_eq!(bound.profile().hash_rule(purpose).output_bytes(), Some(32));
            rejected(
                bound.commitment(purpose, b"must remain native PNW1"),
                ProfileError::WorkProfileBoundary,
            );
        }
    }
    let legacy = CryptoProfile::LegacyMlDsa65V1;
    assert_eq!(legacy.hash_rule(HashPurpose::KeyIdentity), HashRule::Sha256);
    assert_eq!(legacy.hash_rule(HashPurpose::Payload), HashRule::Sha384);
    assert_eq!(
        legacy.hash_rule(HashPurpose::StateCommitment),
        HashRule::NotIntegrated
    );
}

#[test]
fn candidate_commitments_bind_purpose_profile_full_payload_and_length() {
    let profile = candidate(CryptoProfile::CandidateMlDsa65V1);
    let mut distinct = BTreeSet::new();
    for purpose in [
        HashPurpose::KeyIdentity,
        HashPurpose::Payload,
        HashPurpose::StateCommitment,
        HashPurpose::ReleaseCommitment,
        HashPurpose::ProofCommitment,
        HashPurpose::Address,
        HashPurpose::MerkleNode,
        HashPurpose::ProofTranscript,
    ] {
        assert_eq!(profile.profile().hash_rule(purpose), HashRule::Sha512);
        assert!(distinct.insert(profile.commitment(purpose, b"same bytes").unwrap()));
    }
    let original = profile
        .commitment(HashPurpose::Payload, b"same bytes")
        .unwrap();
    assert_ne!(
        original,
        profile
            .commitment(HashPurpose::Payload, b"same bytes\0")
            .unwrap()
    );
    assert_ne!(
        original,
        candidate(CryptoProfile::CandidateMlDsa87V1)
            .commitment(HashPurpose::Payload, b"same bytes")
            .unwrap()
    );
    assert!(profile
        .commitment(HashPurpose::Payload, &vec![0; 65_536])
        .is_ok());
    rejected(
        profile.commitment(HashPurpose::Payload, &vec![0; 65_537]),
        ProfileError::Size,
    );
    rejected(
        legacy(10, Some(100)).commitment(HashPurpose::Payload, b"legacy exact owner"),
        ProfileError::UnsupportedPurpose,
    );
}

#[test]
fn complete_message_binds_each_authority_field_payload_and_signer_set() {
    let profile = candidate(CryptoProfile::CandidateMlDsa65V1);
    let ids = [[1; 64], [2; 64]];
    let other_ids = [[1; 64], [3; 64]];
    let original = profile
        .candidate_message(&envelope(&ids, b"payload"))
        .unwrap();
    for field in 0..8 {
        let mut changed = envelope(&ids, b"payload");
        match field {
            0 => changed.purpose = CryptoPurpose::Current,
            1 => changed.owner_generation += 1,
            2 => changed.key_epoch += 1,
            3 => changed.sequence += 1,
            4 => changed.valid_from_height += 1,
            5 => changed.valid_until_height -= 1,
            6 => changed.signer_ids = &other_ids,
            7 => changed.payload = b"payloae",
            _ => unreachable!(),
        }
        assert_ne!(profile.candidate_message(&changed).unwrap(), original);
        rejected(
            profile.check_candidate_message(profile.id(), &original, &changed),
            ProfileError::Encoding,
        );
    }
    let mut purposes = BTreeSet::new();
    for purpose in CryptoPurpose::ALL {
        let mut changed = envelope(&ids, b"payload");
        changed.purpose = purpose;
        assert!(purposes.insert(profile.candidate_message(&changed).unwrap()));
    }
    assert_eq!(purposes.len(), 10);
}

#[test]
fn candidate_message_refuses_empty_duplicate_zero_unordered_and_excess_signers() {
    let profile = candidate(CryptoProfile::CandidateMlDsa87V1);
    for ids in [
        vec![],
        vec![[0; 64]],
        vec![[1; 64], [1; 64]],
        vec![[2; 64], [1; 64]],
        (1..=9).map(|i| [i; 64]).collect(),
    ] {
        rejected(
            profile.candidate_message(&envelope(&ids, b"x")),
            ProfileError::SignerSet,
        );
    }
    let ids: Vec<_> = (1..=8).map(|i| [i; 64]).collect();
    assert!(profile.candidate_message(&envelope(&ids, b"x")).is_ok());
}

#[test]
fn candidate_message_rejects_zero_authority_fields_and_outside_lifetime() {
    let profile = candidate(CryptoProfile::CandidateMlDsa65V1);
    let ids = [[1; 64]];
    for field in 0..6 {
        let mut invalid = envelope(&ids, b"x");
        match field {
            0 => invalid.owner_generation = 0,
            1 => invalid.key_epoch = 0,
            2 => invalid.sequence = 0,
            3 => invalid.valid_from_height = 100,
            4 => invalid.valid_from_height = 9,
            5 => invalid.valid_until_height = 100,
            _ => unreachable!(),
        }
        rejected(
            profile.candidate_message(&invalid),
            ProfileError::InvalidBinding,
        );
    }
    let mut single_height = envelope(&ids, b"x");
    single_height.valid_until_height = single_height.valid_from_height;
    assert!(profile.candidate_message(&single_height).is_ok());
}

#[test]
fn complete_multisignature_wire_accounts_for_payload_metadata_keys_and_signatures() {
    assert_eq!(CANDIDATE_HEADER_BYTES, 207);
    for (kind, expected_wire_bytes) in [
        (CryptoProfile::CandidateMlDsa65V1, 107_696),
        (CryptoProfile::CandidateMlDsa87V1, 123_360),
    ] {
        let profile = candidate(kind);
        let signers = UnverifiedSigners::new(&profile, 8);
        let payload = vec![0x5a; 64_817];
        let expected = envelope(&signers.ids, &payload);
        let message = profile.candidate_message(&expected).unwrap();
        assert_eq!(message.len(), 65_536);
        let wire = profile
            .candidate_wire(&expected, &signers.keys(), &signers.signatures())
            .unwrap();
        assert_eq!(wire.len(), expected_wire_bytes);
        assert!(wire.len() <= CANDIDATE_MAX_WIRE_BYTES);
        assert!(profile
            .check_candidate_wire(&wire, &expected, &signers.keys())
            .is_ok());
        let oversized = vec![0x5a; 64_818];
        rejected(
            profile.candidate_message(&envelope(&signers.ids, &oversized)),
            ProfileError::Size,
        );
        rejected(
            profile.candidate_wire(
                &envelope(&signers.ids, &oversized),
                &signers.keys(),
                &signers.signatures(),
            ),
            ProfileError::Size,
        );
    }
}

#[test]
fn candidate_wire_returns_borrowed_syntax_without_claiming_zero_signatures_are_valid() {
    for kind in [
        CryptoProfile::CandidateMlDsa65V1,
        CryptoProfile::CandidateMlDsa87V1,
    ] {
        let profile = candidate(kind);
        let signers = UnverifiedSigners::new(&profile, 2);
        let expected = envelope(&signers.ids, b"full signed payload");
        let message = profile.candidate_message(&expected).unwrap();
        let wire = profile
            .candidate_wire(&expected, &signers.keys(), &signers.signatures())
            .unwrap();
        let checked = profile
            .check_candidate_wire(&wire, &expected, &signers.keys())
            .unwrap();
        assert_eq!(checked.message(), message);
        assert_eq!(checked.message().as_ptr(), wire[8..].as_ptr());
        assert_eq!(checked.signatures().len(), 2);
        for (i, signature) in checked.signatures().iter().enumerate() {
            assert_eq!(*signature, signers.signatures[i]);
            let offset = 8
                + message.len()
                + i * (kind.public_key_bytes() + kind.signature_bytes() + 8)
                + kind.public_key_bytes()
                + 8;
            assert_eq!(signature.as_ptr(), wire[offset..].as_ptr());
        }
    }
}

#[test]
fn message_and_wire_do_not_accept_other_parameter_sets_or_caller_context() {
    let profile65 = candidate(CryptoProfile::CandidateMlDsa65V1);
    let profile87 = candidate(CryptoProfile::CandidateMlDsa87V1);
    let signers65 = UnverifiedSigners::new(&profile65, 2);
    let signers87 = UnverifiedSigners::new(&profile87, 2);
    let expected65 = envelope(&signers65.ids, b"payload");
    let expected87 = envelope(&signers87.ids, b"payload");
    let wire87 = profile87
        .candidate_wire(&expected87, &signers87.keys(), &signers87.signatures())
        .unwrap();
    rejected(
        profile65.check_candidate_wire(&wire87, &expected65, &signers65.keys()),
        ProfileError::Encoding,
    );
    rejected(
        profile65.check_candidate_message(
            profile87.id(),
            &profile87.candidate_message(&expected87).unwrap(),
            &expected65,
        ),
        ProfileError::ProfileMismatch,
    );
    let wire65 = profile65
        .candidate_wire(&expected65, &signers65.keys(), &signers65.signatures())
        .unwrap();
    let mut changed = expected65;
    changed.purpose = CryptoPurpose::Recovery;
    rejected(
        profile65.check_candidate_wire(&wire65, &changed, &signers65.keys()),
        ProfileError::Encoding,
    );
}

#[test]
fn candidate_wire_refuses_length_forgery_key_substitution_and_extra_tail() {
    let profile = candidate(CryptoProfile::CandidateMlDsa87V1);
    let signers = UnverifiedSigners::new(&profile, 2);
    let expected = envelope(&signers.ids, b"payload");
    let message = profile.candidate_message(&expected).unwrap();
    let wire = profile
        .candidate_wire(&expected, &signers.keys(), &signers.signatures())
        .unwrap();
    let first_key_length = 8 + message.len();
    let first_key = first_key_length + 4;
    let first_signature_length = first_key + 2_592;
    let first_signature = first_signature_length + 4;
    let second_key_length = first_signature + 4_627;

    for cut in [
        0,
        1,
        3,
        4,
        7,
        8,
        8 + message.len() - 1,
        first_key_length,
        first_key_length + 3,
        first_key,
        first_key + 2_591,
        first_signature_length,
        first_signature_length + 3,
        first_signature,
        second_key_length - 1,
        second_key_length,
        wire.len() - 1,
    ] {
        assert!(
            profile
                .check_candidate_wire(&wire[..cut], &expected, &signers.keys())
                .is_err(),
            "truncation at {cut}"
        );
    }
    for (offset, expected_error) in [
        (0, ProfileError::Encoding),
        (8 + ENVELOPE_DOMAIN.len(), ProfileError::Encoding),
        (8 + ENVELOPE_DOMAIN.len() + 64, ProfileError::Encoding),
        (first_key_length - 1, ProfileError::Encoding),
        (first_key, ProfileError::SignerSet),
    ] {
        let mut altered = wire.clone();
        altered[offset] ^= 1;
        rejected(
            profile.check_candidate_wire(&altered, &expected, &signers.keys()),
            expected_error,
        );
    }
    for offset in [
        4,
        first_key_length,
        first_signature_length,
        second_key_length,
    ] {
        for replacement in [0u32.to_be_bytes(), u32::MAX.to_be_bytes()] {
            let mut altered = wire.clone();
            altered[offset..offset + 4].copy_from_slice(&replacement);
            rejected(
                profile.check_candidate_wire(&altered, &expected, &signers.keys()),
                ProfileError::Size,
            );
        }
    }
    for tail in [vec![0], wire[first_key_length..second_key_length].to_vec()] {
        let mut altered = wire.clone();
        altered.extend_from_slice(&tail);
        rejected(
            profile.check_candidate_wire(&altered, &expected, &signers.keys()),
            ProfileError::Encoding,
        );
    }
    // Duplicate a complete signer record; the expected pinned set is unchanged.
    let mut duplicate = wire.clone();
    duplicate[second_key_length..].copy_from_slice(&wire[first_key_length..second_key_length]);
    rejected(
        profile.check_candidate_wire(&duplicate, &expected, &signers.keys()),
        ProfileError::SignerSet,
    );
}

#[test]
fn candidate_wire_requires_exact_full_key_and_signature_sets() {
    let profile = candidate(CryptoProfile::CandidateMlDsa65V1);
    let signers = UnverifiedSigners::new(&profile, 2);
    let expected = envelope(&signers.ids, b"payload");
    let keys = signers.keys();
    let signatures = signers.signatures();
    let wire = profile
        .candidate_wire(&expected, &keys, &signatures)
        .unwrap();
    rejected(
        profile.candidate_wire(&expected, &keys[..1], &signatures),
        ProfileError::SignerSet,
    );
    rejected(
        profile.candidate_wire(&expected, &keys, &signatures[..1]),
        ProfileError::SignerSet,
    );
    rejected(
        profile.check_candidate_wire(&wire, &expected, &keys[..1]),
        ProfileError::SignerSet,
    );
    rejected(
        profile.check_candidate_wire(&wire, &expected, &[keys[0], keys[0]]),
        ProfileError::SignerSet,
    );
    rejected(
        profile.candidate_wire(&expected, &[&keys[0][..1_951], keys[1]], &signatures),
        ProfileError::SignerSet,
    );
    rejected(
        profile.candidate_wire(&expected, &keys, &[&signatures[0][..3_308], signatures[1]]),
        ProfileError::SignerSet,
    );
    let foreign_key = vec![0xee; 1_952];
    rejected(
        profile.candidate_wire(&expected, &[&foreign_key, keys[1]], &signatures),
        ProfileError::SignerSet,
    );
    rejected(
        profile.check_candidate_wire(&wire, &expected, &[&foreign_key, keys[1]]),
        ProfileError::SignerSet,
    );
}

#[test]
fn candidate_wire_size_cap_and_legacy_namespace_are_fail_closed() {
    let profile = candidate(CryptoProfile::CandidateMlDsa65V1);
    let signers = UnverifiedSigners::new(&profile, 1);
    let expected = envelope(&signers.ids, b"payload");
    rejected(
        profile.check_candidate_wire(&vec![0; 131_073], &expected, &signers.keys()),
        ProfileError::Size,
    );
    rejected(
        legacy(10, Some(100)).candidate_message(&expected),
        ProfileError::CandidateOnly,
    );
    rejected(
        profile.check_candidate_message(profile.id(), &vec![0; 65_537], &expected),
        ProfileError::Size,
    );
}

#[test]
fn failed_wire_validation_does_not_refund_reserved_attempts_or_bytes() {
    let profile = candidate(CryptoProfile::CandidateMlDsa65V1);
    let signers = UnverifiedSigners::new(&profile, 2);
    let expected = envelope(&signers.ids, b"payload");
    let mut wire = profile
        .candidate_wire(&expected, &signers.keys(), &signers.signatures())
        .unwrap();
    wire[0] ^= 1;
    let mut budget = CandidateVerificationBudget::new();
    budget.reserve(wire.len(), 2).unwrap();
    rejected(
        profile.check_candidate_wire(&wire, &expected, &signers.keys()),
        ProfileError::Encoding,
    );
    assert_eq!(budget.attempts(), 2);
    assert_eq!(budget.charged_bytes(), wire.len() as u64);
    budget.reserve(wire.len(), 2).unwrap();
    assert_eq!(budget.attempts(), 4);
    assert_eq!(budget.charged_bytes(), 2 * wire.len() as u64);
}

#[test]
fn every_multisignature_attempt_is_cumulative_and_exhaustion_latches() {
    let mut budget = CandidateVerificationBudget::new();
    for batch in 1..=8 {
        budget.reserve(100, 8).unwrap();
        assert_eq!(budget.attempts(), batch * 8);
        assert_eq!(budget.charged_bytes(), batch * 100);
    }
    rejected(budget.reserve(100, 1), ProfileError::Budget);
    assert_eq!(budget.attempts(), 65);
    assert_eq!(budget.charged_bytes(), 900);
    rejected(budget.reserve(1, 1), ProfileError::Budget);
    assert_eq!(budget.attempts(), 65);
    assert_eq!(budget.charged_bytes(), 900);
}

#[test]
fn complete_batch_byte_ceiling_is_preserved_without_subrequest_resets() {
    let mut budget = CandidateVerificationBudget::default();
    for _ in 0..64 {
        budget.reserve(131_072, 1).unwrap();
    }
    assert_eq!(budget.attempts(), 64);
    assert_eq!(budget.charged_bytes(), 8_388_608);
    rejected(budget.reserve(1, 1), ProfileError::Budget);
    assert_eq!(budget.charged_bytes(), 8_388_609);
    rejected(budget.reserve(0, 1), ProfileError::Budget);
    assert_eq!(budget.charged_bytes(), 8_388_609);
}

#[test]
fn invalid_reservations_are_charged_and_cannot_revive_the_budget() {
    for (wire_bytes, verifications) in [(1, 0), (1, 9), (131_073, 1)] {
        let mut budget = CandidateVerificationBudget::new();
        rejected(
            budget.reserve(wire_bytes, verifications),
            ProfileError::Budget,
        );
        assert_eq!(budget.attempts(), verifications as u64);
        assert_eq!(budget.charged_bytes(), wire_bytes as u64);
        rejected(budget.reserve(1, 1), ProfileError::Budget);
        assert_eq!(budget.attempts(), verifications as u64);
        assert_eq!(budget.charged_bytes(), wire_bytes as u64);
    }
}

#[test]
fn counter_overflow_never_wraps_or_restores_verification_credit() {
    for (attempts, bytes) in [(u64::MAX, 0), (0, u64::MAX), (u64::MAX, u64::MAX)] {
        let mut budget = CandidateVerificationBudget {
            attempts,
            bytes,
            exhausted: false,
        };
        rejected(budget.reserve(1, 1), ProfileError::Budget);
        assert_eq!(
            (budget.attempts(), budget.charged_bytes()),
            (attempts, bytes)
        );
        rejected(budget.reserve(0, 1), ProfileError::Budget);
        assert_eq!(
            (budget.attempts(), budget.charged_bytes()),
            (attempts, bytes)
        );
    }
}

#[test]
fn bounded_wire_reads_reject_arithmetic_overflow_without_advancing_cursor() {
    let mut cursor = usize::MAX - 1;
    rejected(take(b"x", &mut cursor, 8), ProfileError::Size);
    assert_eq!(cursor, usize::MAX - 1);
    let mut cursor = 0;
    rejected(read_u32(&[0; 3], &mut cursor), ProfileError::Size);
    assert_eq!(cursor, 0);
}

fn includes_framed_field(configuration: &[u8], value: &[u8]) -> bool {
    let mut expected = (value.len() as u32).to_be_bytes().to_vec();
    expected.extend_from_slice(value);
    configuration
        .windows(expected.len())
        .any(|part| part == expected)
}

fn assert_named_limit(configuration: &[u8], name: &[u8], value: u64) {
    let mut expected = (name.len() as u32).to_be_bytes().to_vec();
    expected.extend_from_slice(name);
    expected.extend_from_slice(&value.to_be_bytes());
    assert!(
        configuration
            .windows(expected.len())
            .any(|part| part == expected),
        "missing exact named limit {}={value}",
        String::from_utf8_lossy(name)
    );
}

fn account_version(version: u32) -> crate::pq_native_accounts_v2::AccountProfile {
    use crate::pq_native_accounts_v2::AccountProfile;
    match version {
        2 => AccountProfile::AccountsV2,
        3 => AccountProfile::QuotaV3,
        4 => AccountProfile::TasksV4,
        5 => AccountProfile::TasksV5,
        6 => AccountProfile::ApplicationV6,
        _ => panic!("not a registered account version"),
    }
}

#[test]
fn independent_python_ids_freeze_every_native_account_version() {
    for (version, bytes, expected_id) in [
        (
            2,
            2606,
            concat!(
                "792e3511e569b364e187eb8d14c916895f2873c8fe392c4e935321672166aacbc",
                "740e4641f48a587a80f71ea6b469e538981c6719fdb8a62fd9d257edd7d0072"
            ),
        ),
        (3, 2605, LEGACY_ID),
        (
            4,
            2613,
            concat!(
                "4d181af073cc8f456c7ccd58cd6fd6ffef6d8f26c886ca37acbb3c02a361d1030",
                "6cd0c5827206bf85f5b45d2ee935208a968abce620a1622b284480f9ab15532"
            ),
        ),
        (
            5,
            2621,
            concat!(
                "6de9dcb15de8f7a3abeb91bf62f69be797c0be890bbf1e7207ebac94dd9deefe7",
                "11c99e0685b00a774eabf53001da822280d0f636c55a1dbab02853500ac04e2"
            ),
        ),
        (
            6,
            2678,
            concat!(
                "57ffe4aff51421e5d4e9a97f6d8a349dae07e9a5c9216e341ce3c3ebd5e284878",
                "92831c251315dc2b0788061e08931d19dfa72cbb3d32064c2e5d978bdd62dbc"
            ),
        ),
    ] {
        let bound = CryptoProfile::LegacyMlDsa65V1
            .bind(fixed_binding(ProfileScope::NativeAccounts, version))
            .unwrap();
        assert_eq!(
            bound.canonical_configuration().len(),
            bytes,
            "version {version}"
        );
        assert_eq!(bound.id().to_hex(), expected_id, "version {version}");
    }
}

#[test]
fn legacy_account_descriptors_contain_actual_shared_domains_and_distinct_limits() {
    use crate::{pq_frame as frame, pq_native_accounts_v2 as account};
    for version in 2..=6 {
        let actual = account_version(version);
        let bound = CryptoProfile::LegacyMlDsa65V1
            .bind(fixed_binding(ProfileScope::NativeAccounts, version))
            .unwrap();
        let configuration = bound.canonical_configuration();
        for domain in [
            frame::TPQ1_MAGIC.as_slice(),
            frame::DOMAIN,
            frame::PUBLIC_KEY_ID_DOMAIN,
            frame::PAYLOAD_TAG,
            frame::ML_DSA_65_SPKI_PREFIX.as_slice(),
            actual.name().as_bytes(),
            actual.prefix().as_slice(),
            actual.packet_prefix().as_slice(),
            actual.statement_domain(),
            actual.context_domain(),
            actual.wire_domain(),
        ] {
            assert!(
                includes_framed_field(&configuration, domain),
                "version {version}"
            );
        }
        assert!(includes_framed_field(&configuration,
            b"owner-context:SHA256(domain,network,parameters,genesis,account,profile-name,kind,role);wire-id:SHA256(wire-domain,BE32-length,raw);statement-id:SHA384(statement-domain,body,witness-descriptors)"));
        assert!(!configuration
            .windows(b"TRNM/CPQ1/".len())
            .any(|p| p == b"TRNM/CPQ1/"));
        for (name, value) in [
            (
                b"TPQ1-payload-bytes".as_slice(),
                frame::TPQ1_MAX_PAYLOAD_BYTES,
            ),
            (b"TPQ1-unsigned-bytes", frame::TPQ1_UNSIGNED_BYTES),
            (b"TPQ1-signed-bytes", frame::TPQ1_SIGNED_BYTES),
            (b"raw-public-key-bytes", frame::ML_DSA_65_PUBLIC_KEY_BYTES),
            (b"SPKI-bytes", frame::ML_DSA_65_SPKI_BYTES),
            (b"signature-bytes", frame::ML_DSA_65_SIGNATURE_BYTES),
            (b"transaction-envelope-bytes", actual.maximum_bytes()),
            (b"transactions-per-packet", actual.maximum_transactions()),
            (b"verifications-per-packet", actual.maximum_verifications()),
            (
                b"transaction-bytes-per-packet",
                account::MAX_TRANSACTION_BYTES,
            ),
            (b"maximum-payload-bytes", actual.maximum_payload_bytes()),
            (b"transfer-base-bytes", account::TRANSFER_BASE_BYTES),
            (b"transfer-memo-bytes", account::TRANSFER_MAX_MEMO_BYTES),
            (
                b"conflict-envelope-bytes",
                account::MAX_CONFLICT_ENVELOPE_BYTES,
            ),
            (
                b"conflict-extra-verifications",
                account::CONFLICT_EVIDENCE_VERIFICATIONS,
            ),
        ] {
            assert_named_limit(&configuration, name, value as u64);
        }
        let (envelope_bytes, transaction_count, verification_count, payload_bytes) = match version {
            2 | 3 => (9432, 256, 512, 554),
            4 => (9432, 256, 512, 652),
            5 => (9432, 256, 512, 1032),
            6 => (16384, 64, 64, 12675),
            _ => unreachable!(),
        };
        assert_eq!(actual.maximum_bytes(), envelope_bytes);
        assert_eq!(actual.maximum_transactions(), transaction_count);
        assert_eq!(actual.maximum_verifications(), verification_count);
        assert_eq!(actual.maximum_payload_bytes(), payload_bytes);
    }
}

#[test]
fn peer_descriptor_uses_live_directions_domains_and_full_wire_budgets() {
    use crate::pq_legacy_profile as peer;
    let bound = CryptoProfile::LegacyMlDsa65V1
        .bind(fixed_binding(ProfileScope::NativePeer, 2))
        .unwrap();
    let configuration = bound.canonical_configuration();
    for domain in [
        peer::PROFILE.as_bytes(),
        peer::REQUEST_MAGIC.as_slice(),
        peer::RESPONSE_MAGIC.as_slice(),
        peer::POLICY_DOMAIN,
        peer::PEER_CONTEXT_DOMAIN,
        peer::OPERATION_DOMAIN,
        peer::RESPONSE_BYTES_DOMAIN,
        peer::RESPONSE_SCHEMA.as_bytes(),
        peer::TRANSPORT_MODE.as_bytes(),
    ] {
        assert!(includes_framed_field(&configuration, domain));
    }
    assert_eq!(
        (
            peer::PEER_PURPOSE,
            peer::REQUEST_DIRECTION,
            peer::RESPONSE_DIRECTION
        ),
        (6, 1, 2)
    );
    for (name, value) in [
        (b"wire-bytes".as_slice(), peer::MAX_WIRE as u64),
        (
            b"signed-payload-bytes",
            peer::MAX_SIGNED_PAYLOAD_BYTES as u64,
        ),
        (b"ledger-bytes", peer::MAX_LEDGER_BYTES),
        (b"ledger-records", peer::MAX_RECORDS),
        (b"ingress-connections", peer::MAX_INGRESS_CONNECTIONS),
        (b"ingress-bytes", peer::MAX_INGRESS_BYTES),
        (b"inbound-verifications", peer::MAX_INBOUND_VERIFICATIONS),
        (b"pinned-peer-roster", peer::MAX_PEERS as u64),
        (
            b"lifetime-seconds-local-admission",
            peer::MAX_LIFETIME_SECONDS,
        ),
        (b"signers-per-direction", 1),
    ] {
        assert_named_limit(&configuration, name, value);
    }
    assert_eq!(peer::MAX_WIRE, 2_097_152);
    assert_eq!(peer::MAX_SIGNED_PAYLOAD_BYTES, 2_093_657);
    assert_eq!(peer::MAX_LEDGER_BYTES, 16_777_216);
    assert_eq!(peer::MAX_INGRESS_BYTES, 33_554_432);
    assert_ne!(
        bound.id(),
        CryptoProfile::LegacyMlDsa65V1
            .bind(fixed_binding(ProfileScope::NativeAccounts, 2))
            .unwrap()
            .id()
    );
}

fn independently_expected_roles(version: u32, kind: u8) -> Option<&'static [(u8, bool)]> {
    if (1..=5).contains(&kind) {
        return Some(&[(1, false)]);
    }
    if version >= 3 {
        if kind == 10 {
            return Some(&[(1, false)]);
        }
        if kind == 11 {
            return Some(&[(1, false), (2, false)]);
        }
    }
    if version >= 5 {
        if [18, 19, 20].contains(&kind) {
            return Some(&[(1, false)]);
        }
        if [21, 22].contains(&kind) {
            return Some(&[(1, false), (2, false)]);
        }
    }
    if version == 4 {
        if [18, 20].contains(&kind) {
            return Some(&[(1, false)]);
        }
        if kind == 21 {
            return Some(&[(1, false), (2, false)]);
        }
    }
    if version == 6 && [6, 7, 8, 9, 14, 15, 16, 17, 23, 24].contains(&kind) {
        return Some(&[(1, false)]);
    }
    match kind {
        128 => Some(&[(2, true)]),
        129 => Some(&[(3, false), (4, true)]),
        130 => Some(&[(5, false), (6, true)]),
        _ => None,
    }
}

#[test]
fn all_256_account_kind_slots_bind_original_roles_counts_and_carried_keys() {
    for version in 2..=6 {
        let actual = account_version(version);
        let label = b"signer-roles-and-count:exact-native-account-kind-registry";
        let mut expected = (label.len() as u32).to_be_bytes().to_vec();
        expected.extend_from_slice(label);
        for kind in 0..=u8::MAX {
            let roles = independently_expected_roles(version, kind);
            assert_eq!(
                crate::pq_native_accounts_v2::roles(actual, kind).ok(),
                roles,
                "version {version}, kind {kind}"
            );
            expected.push(kind);
            match roles {
                None => expected.push(0),
                Some(roles) => {
                    expected.extend_from_slice(&[1, roles.len() as u8]);
                    for &(role, carried) in roles {
                        expected.extend_from_slice(&[role, u8::from(carried)]);
                    }
                }
            }
        }
        let configuration = CryptoProfile::LegacyMlDsa65V1
            .bind(fixed_binding(ProfileScope::NativeAccounts, version))
            .unwrap()
            .canonical_configuration();
        assert!(
            configuration
                .windows(expected.len())
                .any(|part| part == expected),
            "version {version} has an incomplete or altered role table"
        );
    }
}

#[test]
fn history_preserves_old_parameters_and_protocol_without_current_upgrade_authority() {
    let current = CryptoProfile::LegacyMlDsa65V1
        .bind(ProfileBinding {
            activation_height: 20,
            ..fixed_binding(ProfileScope::NativeAccounts, 6)
        })
        .unwrap();
    let old = CryptoProfile::LegacyMlDsa65V1
        .bind(ProfileBinding {
            parameters: [9; 32],
            retirement_height: Some(20),
            ..fixed_binding(ProfileScope::NativeAccounts, 2)
        })
        .unwrap();
    let old_id = old.id();
    let policy = CryptoProfilePolicy::from_trusted_state(current, 30, 2, vec![old]).unwrap();
    let record = policy.select_historical(old_id, 19).unwrap();
    assert_eq!(record.selected().binding().parameters, [9; 32]);
    assert_eq!(record.selected().binding().protocol_version, 2);
    rejected(policy.select_current(old_id), ProfileError::ProfileMismatch);
    rejected(policy.select_historical(old_id, 20), ProfileError::Inactive);
}

#[test]
fn trusted_retirement_preserves_open_descriptor_and_original_id() {
    let old = legacy(10, None);
    let old_id = old.id();
    let original_bytes = old.canonical_configuration();
    let before = CryptoProfilePolicy::from_trusted_state(old.clone(), 19, 7, vec![]).unwrap();
    let selected_before = before.select_current(old_id).unwrap();
    let current = legacy(30, None);
    // The existing planned-retirement API still refuses an open history entry.
    rejected(
        CryptoProfilePolicy::from_trusted_state(current.clone(), 40, 8, vec![old.clone()]),
        ProfileError::InvalidBinding,
    );
    let retired = RetiredCryptoProfile::from_trusted_state(old, 20).unwrap();
    assert_eq!(retired.profile().id(), old_id);
    assert_eq!(retired.profile().canonical_configuration(), original_bytes);
    assert_eq!(retired.profile().binding().retirement_height, None);
    assert_eq!(retired.effective_retirement_height(), 20);
    let policy =
        CryptoProfilePolicy::from_trusted_state_with_retirements(current, 40, 8, vec![retired])
            .unwrap();
    for height in [10, 19] {
        let historical = policy.select_historical(old_id, height).unwrap();
        assert_eq!(historical.selected().id(), old_id);
        assert_eq!(
            historical.selected().canonical_configuration(),
            original_bytes
        );
    }
    let rebound = legacy(10, Some(20));
    assert_ne!(rebound.id(), old_id);
    rejected(
        policy.select_historical(rebound.id(), 19),
        ProfileError::UnknownProfile,
    );
    rejected(policy.select_current(old_id), ProfileError::ProfileMismatch);
    rejected(
        policy.recheck_current(&selected_before),
        ProfileError::StaleState,
    );
}

#[test]
fn trusted_retirement_must_narrow_a_nonempty_declared_interval() {
    for end in [0, 9, 10] {
        rejected(
            RetiredCryptoProfile::from_trusted_state(legacy(10, None), end),
            ProfileError::InvalidBinding,
        );
    }
    let declared = legacy(10, Some(100));
    let declared_id = declared.id();
    rejected(
        RetiredCryptoProfile::from_trusted_state(declared.clone(), 101),
        ProfileError::InvalidBinding,
    );
    assert!(RetiredCryptoProfile::from_trusted_state(declared.clone(), 100).is_ok());
    let shortened = RetiredCryptoProfile::from_trusted_state(declared, 80).unwrap();
    assert_eq!(shortened.profile().id(), declared_id);
    assert!(shortened.profile().active_at(80));
    let policy = CryptoProfilePolicy::from_trusted_state_with_retirements(
        legacy(80, None),
        90,
        2,
        vec![shortened],
    )
    .unwrap();
    assert!(policy.select_historical(declared_id, 79).is_ok());
    rejected(
        policy.select_historical(declared_id, 80),
        ProfileError::Inactive,
    );
}

#[test]
fn trusted_retirement_history_keeps_exclusive_ends_and_gaps() {
    let first = legacy(10, None);
    let second = legacy(25, None);
    let current = legacy(40, None);
    let (first_id, second_id, current_id) = (first.id(), second.id(), current.id());
    let policy = CryptoProfilePolicy::from_trusted_state_with_retirements(
        current,
        50,
        3,
        vec![
            RetiredCryptoProfile::from_trusted_state(second, 30).unwrap(),
            RetiredCryptoProfile::from_trusted_state(first, 20).unwrap(),
        ],
    )
    .unwrap();
    for (id, start, end) in [(first_id, 10, 20), (second_id, 25, 30)] {
        for height in [start, end - 1] {
            assert!(policy.select_historical(id, height).is_ok());
        }
        for height in [start - 1, end, 39] {
            rejected(policy.select_historical(id, height), ProfileError::Inactive);
        }
    }
    rejected(
        policy.select_historical(current_id, 39),
        ProfileError::Inactive,
    );
    assert!(policy.select_historical(current_id, 50).is_ok());
    rejected(
        policy.select_historical(current_id, 51),
        ProfileError::Inactive,
    );
    // Adjacent intervals remain valid, even in reverse registration order.
    assert!(CryptoProfilePolicy::from_trusted_state_with_retirements(
        legacy(40, None),
        50,
        3,
        vec![
            RetiredCryptoProfile::from_trusted_state(legacy(20, None), 40).unwrap(),
            RetiredCryptoProfile::from_trusted_state(legacy(10, None), 20).unwrap(),
        ],
    )
    .is_ok());
}

#[test]
fn trusted_retirement_policy_refuses_duplicate_overlap_and_late_end() {
    let current = legacy(40, None);
    let first = RetiredCryptoProfile::from_trusted_state(legacy(10, None), 20).unwrap();
    let overlapping = RetiredCryptoProfile::from_trusted_state(legacy(19, None), 30).unwrap();
    let cases = [
        vec![first.clone(), first.clone()],
        vec![first.clone(), overlapping.clone()],
        vec![overlapping, first],
        vec![RetiredCryptoProfile::from_trusted_state(legacy(10, None), 41).unwrap()],
        vec![RetiredCryptoProfile::from_trusted_state(current.clone(), 41).unwrap()],
    ];
    for history in cases {
        rejected(
            CryptoProfilePolicy::from_trusted_state_with_retirements(
                current.clone(),
                50,
                1,
                history,
            ),
            ProfileError::InvalidBinding,
        );
    }
}

#[test]
fn trusted_retirement_policy_preserves_foreign_candidate_and_capacity_refusals() {
    let current = legacy(100, None);
    let original = legacy(10, None);
    for field in 0..3 {
        let mut binding = *original.binding();
        match field {
            0 => binding.network[0] ^= 1,
            1 => binding.genesis[0] ^= 1,
            2 => {
                binding.scope = ProfileScope::NativePeer;
                binding.protocol_version = 2;
            }
            _ => unreachable!(),
        }
        let old = CryptoProfile::LegacyMlDsa65V1.bind(binding).unwrap();
        let retired = RetiredCryptoProfile::from_trusted_state(old, 20).unwrap();
        rejected(
            CryptoProfilePolicy::from_trusted_state_with_retirements(
                current.clone(),
                100,
                1,
                vec![retired],
            ),
            ProfileError::InvalidBinding,
        );
    }
    for kind in [
        CryptoProfile::CandidateMlDsa65V1,
        CryptoProfile::CandidateMlDsa87V1,
    ] {
        rejected(
            RetiredCryptoProfile::from_trusted_state(candidate(kind), 20),
            ProfileError::InvalidBinding,
        );
    }
    let history: Vec<_> = (0..16)
        .map(|i| RetiredCryptoProfile::from_trusted_state(legacy(2 * i, None), 2 * i + 1).unwrap())
        .collect();
    assert!(CryptoProfilePolicy::from_trusted_state_with_retirements(
        current.clone(),
        100,
        1,
        history.clone(),
    )
    .is_ok());
    let mut excessive = history;
    excessive.push(RetiredCryptoProfile::from_trusted_state(legacy(40, None), 41).unwrap());
    rejected(
        CryptoProfilePolicy::from_trusted_state_with_retirements(
            current.clone(),
            100,
            1,
            excessive,
        ),
        ProfileError::InvalidBinding,
    );
    rejected(
        CryptoProfilePolicy::from_trusted_state_with_retirements(current, 100, 0, vec![]),
        ProfileError::InvalidBinding,
    );
}

#[test]
fn trusted_retirement_preserves_original_parameters_and_protocol() {
    let old = CryptoProfile::LegacyMlDsa65V1
        .bind(ProfileBinding {
            parameters: [9; 32],
            retirement_height: None,
            ..fixed_binding(ProfileScope::NativeAccounts, 2)
        })
        .unwrap();
    let old_id = old.id();
    let current = CryptoProfile::LegacyMlDsa65V1
        .bind(ProfileBinding {
            activation_height: 20,
            retirement_height: None,
            ..fixed_binding(ProfileScope::NativeAccounts, 6)
        })
        .unwrap();
    let policy = CryptoProfilePolicy::from_trusted_state_with_retirements(
        current,
        30,
        2,
        vec![RetiredCryptoProfile::from_trusted_state(old, 20).unwrap()],
    )
    .unwrap();
    let record = policy.select_historical(old_id, 19).unwrap();
    assert_eq!(record.selected().id(), old_id);
    assert_eq!(record.selected().binding().parameters, [9; 32]);
    assert_eq!(record.selected().binding().protocol_version, 2);
    rejected(policy.select_historical(old_id, 20), ProfileError::Inactive);
    rejected(policy.select_current(old_id), ProfileError::ProfileMismatch);
}

#[test]
fn trusted_retirement_policy_never_activates_current_candidates() {
    for kind in [
        CryptoProfile::CandidateMlDsa65V1,
        CryptoProfile::CandidateMlDsa87V1,
    ] {
        let bound = candidate(kind);
        let id = bound.id();
        let policy =
            CryptoProfilePolicy::from_trusted_state_with_retirements(bound, 20, 1, vec![]).unwrap();
        rejected(policy.select_current(id), ProfileError::CandidateOnly);
        rejected(
            policy.select_historical(id, 20),
            ProfileError::CandidateOnly,
        );
    }
}

#[test]
fn trusted_retirement_policy_rechecks_current_generation_identity_and_height() {
    let current = legacy(40, Some(100));
    let id = current.id();
    let before =
        CryptoProfilePolicy::from_trusted_state_with_retirements(current.clone(), 50, 7, vec![])
            .unwrap();
    let selected = before.select_current(id).unwrap();
    assert!(before.recheck_current(&selected).is_ok());
    let changed_generation =
        CryptoProfilePolicy::from_trusted_state_with_retirements(current.clone(), 50, 8, vec![])
            .unwrap();
    rejected(
        changed_generation.recheck_current(&selected),
        ProfileError::StaleState,
    );
    let expired =
        CryptoProfilePolicy::from_trusted_state_with_retirements(current.clone(), 100, 7, vec![])
            .unwrap();
    rejected(expired.recheck_current(&selected), ProfileError::Inactive);
    let mut binding = *current.binding();
    binding.parameters[0] ^= 1;
    let different = CryptoProfile::LegacyMlDsa65V1.bind(binding).unwrap();
    let changed_id =
        CryptoProfilePolicy::from_trusted_state_with_retirements(different, 50, 7, vec![]).unwrap();
    rejected(
        changed_id.recheck_current(&selected),
        ProfileError::StaleState,
    );
}
