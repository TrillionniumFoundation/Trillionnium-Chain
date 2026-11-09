#![cfg(feature = "pq-native-openssl")]
//! Mandatory real native operations when the feature is enabled. No skip,
//! subprocess verifier, committed private fixture or successful double exists.
use openssl::asn1::Asn1Object;
use openssl::pkey::{Id, PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::sign::{Signer, Verifier};
use trnm_crypto_primitives::pq_root_v3::{
    approval_message_v3, operation_commitment_v3, possession_message_v3, DualFamilyRosterV3,
    RootCryptoErrorV3, RootPublicKeyV3, RootSignatureV3, RootSuiteV3, VerificationBudgetV3,
    ENCODED_ROSTER_BYTES_V3, MAX_MESSAGE_BYTES_V3, MAX_STATEMENT_BYTES_V3,
};

// Resolve an exact standard OID through the linked native library. This uses
// only runtime ephemeral keys and the existing safe rust-openssl interface.
fn generate(oid: &str) -> PKey<Private> {
    assert!(
        openssl::version::number() >= 0x3050_0000,
        "actual OpenSSL 3.5+ required; no skip or successful fallback"
    );
    let object = Asn1Object::from_str(oid).unwrap();
    let mut context = PkeyCtx::new_id(Id::from_raw(object.nid().as_raw())).unwrap();
    context.keygen_init().unwrap();
    context.keygen().unwrap()
}

struct Fixture {
    roster: DualFamilyRosterV3,
    private: Vec<([u8; 64], PKey<Private>)>,
}
impl Fixture {
    fn new() -> Self {
        let mut keys = Vec::new();
        let mut private = Vec::new();
        for (suite, oid) in [
            (RootSuiteV3::MlDsa87, "2.16.840.1.101.3.4.3.19"),
            (RootSuiteV3::SlhDsaSha2_256s, "2.16.840.1.101.3.4.3.24"),
        ] {
            for _ in 0..3 {
                let owned = generate(oid);
                let public = RootPublicKeyV3 {
                    suite,
                    spki: owned.public_key_to_der().unwrap(),
                };
                let id = public.id().unwrap();
                keys.push(public);
                private.push((id, owned));
            }
        }
        Self {
            roster: DualFamilyRosterV3::from_keys(keys).unwrap(),
            private,
        }
    }
    fn sign(&self, signer: [u8; 64], message: &[u8]) -> RootSignatureV3 {
        let key = &self.private.iter().find(|(id, _)| *id == signer).unwrap().1;
        let mut signing = Signer::new_without_digest(key).unwrap();
        let signature = signing.sign_oneshot_to_vec(message).unwrap();
        let mut independent = Verifier::new_without_digest(key).unwrap();
        assert!(independent.verify_oneshot(&signature, message).unwrap());
        RootSignatureV3 { signer, signature }
    }
    fn quorum(&self, message: &[u8], pairs: [[usize; 2]; 2]) -> Vec<RootSignatureV3> {
        let ids = self.roster.key_ids();
        let mut rows = Vec::with_capacity(4);
        for (family, pair) in pairs.into_iter().enumerate() {
            for index in pair {
                rows.push(self.sign(ids[family * 3 + index], message));
            }
        }
        rows
    }
    fn possessions(&self, statement: &[u8]) -> Vec<RootSignatureV3> {
        self.roster
            .key_ids()
            .into_iter()
            .map(|signer| {
                self.sign(
                    signer,
                    &possession_message_v3(statement, &self.roster, signer).unwrap(),
                )
            })
            .collect()
    }
}
fn budget() -> VerificationBudgetV3 {
    VerificationBudgetV3::new(64).unwrap()
}

#[test]
fn exact_oid_native_generation_and_cross_backend_ml87_verification_work() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .roster
            .keys()
            .iter()
            .map(|key| key.spki.len())
            .collect::<Vec<_>>(),
        vec![2_614, 2_614, 2_614, 82, 82, 82]
    );
    let message =
        approval_message_v3(b"normal|scope|root|epoch|nonce|sequence|validity|payload").unwrap();
    let signatures = fixture.quorum(&message, [[0, 1], [0, 1]]);
    let mut shared = budget();
    let verified = fixture
        .roster
        .verify_quorum(&message, &signatures, &mut shared)
        .unwrap();
    assert_eq!(verified.len(), 4);
    assert_eq!(shared.attempts(), 4);
    assert_eq!(
        DualFamilyRosterV3::decode(&fixture.roster.encode()).unwrap(),
        fixture.roster
    );
}

#[test]
fn all_nine_quorum_pairs_verify_one_operation_identity() {
    let fixture = Fixture::new();
    let statement = b"normal|complete-policy|same-semantic-intent|same-nonce";
    let message = approval_message_v3(statement).unwrap();
    let identities = fixture.roster.key_ids();
    // Six real signatures can supply every permitted subset. The semantic ID
    // remains independent of the chosen witnesses and signature randomness.
    let all = identities
        .iter()
        .map(|id| fixture.sign(*id, &message))
        .collect::<Vec<_>>();
    let choices = [[0, 1], [0, 2], [1, 2]];
    let expected = operation_commitment_v3(statement).unwrap();
    let mut shared = budget();
    for ml in choices {
        for slh in choices {
            let chosen = [
                all[ml[0]].clone(),
                all[ml[1]].clone(),
                all[3 + slh[0]].clone(),
                all[3 + slh[1]].clone(),
            ];
            assert_eq!(
                fixture
                    .roster
                    .verify_quorum(&message, &chosen, &mut shared)
                    .unwrap()
                    .len(),
                4
            );
            assert_eq!(operation_commitment_v3(statement).unwrap(), expected);
        }
    }
    assert_eq!(shared.attempts(), 36);
}

#[test]
fn complete_maximum_statement_and_all_six_successor_possessions_verify() {
    let current = Fixture::new();
    let successor = Fixture::new();
    let mut statement = vec![0x49; MAX_STATEMENT_BYTES_V3];
    statement[..64].copy_from_slice(&current.roster.commitment());
    statement[64..128].copy_from_slice(&successor.roster.commitment());
    let message = approval_message_v3(&statement).unwrap();
    let approvals = current.quorum(&message, [[0, 1], [0, 1]]);
    let possessions = successor.possessions(&statement);
    let mut shared = VerificationBudgetV3::new(10).unwrap();
    current
        .roster
        .verify_quorum(&message, &approvals, &mut shared)
        .unwrap();
    assert_eq!(
        successor
            .roster
            .verify_possessions(&statement, &possessions, &mut shared)
            .unwrap()
            .len(),
        6
    );
    assert_eq!(shared.attempts(), 10);
    assert!(successor
        .roster
        .verify_possessions(&statement, &possessions, &mut shared)
        .is_err());
}

#[test]
fn each_family_corruption_and_one_family_only_fail_without_or_fallback() {
    let fixture = Fixture::new();
    let message = approval_message_v3(b"revoke|full-revocation-intent").unwrap();
    let good = fixture.quorum(&message, [[0, 1], [0, 1]]);
    let mut shared = budget();
    for index in [0, 2] {
        let mut changed = good.clone();
        changed[index].signature[0] ^= 1;
        assert!(fixture
            .roster
            .verify_quorum(&message, &changed, &mut shared)
            .is_err());
    }
    for changed in [&good[..2], &good[2..]] {
        assert_eq!(
            fixture.roster.verify_quorum(&message, changed, &mut shared),
            Err(RootCryptoErrorV3::SignerSet)
        );
    }
    let mut duplicate = good.clone();
    duplicate[1] = duplicate[0].clone();
    assert_eq!(
        fixture
            .roster
            .verify_quorum(&message, &duplicate, &mut shared),
        Err(RootCryptoErrorV3::SignerSet)
    );
    // Even genuine extra approvals cannot change the fixed wire requirement
    // of exactly two members of each family or be silently discarded.
    let mut extra = good.clone();
    for signer in [fixture.roster.key_ids()[2], fixture.roster.key_ids()[5]] {
        extra.push(fixture.sign(signer, &message));
        assert_eq!(
            fixture.roster.verify_quorum(&message, &extra, &mut shared),
            Err(RootCryptoErrorV3::SignerSet)
        );
    }
    assert_eq!(shared.attempts(), 28);
}

#[test]
fn complete_intent_and_domain_mutations_invalidate_real_current_signatures() {
    let fixture = Fixture::new();
    let statement = b"normal|scope|current-policy|generation|epoch|sequence|nonce|validity|payload";
    let message = approval_message_v3(statement).unwrap();
    let approvals = fixture.quorum(&message, [[0, 1], [0, 1]]);
    let mut shared = budget();
    let mut changed = statement.to_vec();
    changed[0] ^= 1;
    let mut changed_domain = message.clone();
    changed_domain[0] ^= 1;
    let digest_substitute = operation_commitment_v3(statement).unwrap();
    for other in [
        approval_message_v3(&changed).unwrap(),
        changed_domain,
        digest_substitute.to_vec(),
    ] {
        assert!(fixture
            .roster
            .verify_quorum(&other, &approvals, &mut shared)
            .is_err());
    }
    let next = Fixture::new();
    assert_eq!(
        next.roster.verify_quorum(&message, &approvals, &mut shared),
        Err(RootCryptoErrorV3::SignerSet)
    );
}

#[test]
fn every_successor_proof_is_mandatory_and_cannot_move_between_roles_or_intents() {
    let fixture = Fixture::new();
    let statement = b"recover|complete-current-root|complete-successor-root|sequence|nonce";
    let possessions = fixture.possessions(statement);
    let mut shared = VerificationBudgetV3::new(128).unwrap();
    for index in 0..6 {
        let mut missing = possessions.clone();
        missing.remove(index);
        assert_eq!(
            fixture
                .roster
                .verify_possessions(statement, &missing, &mut shared),
            Err(RootCryptoErrorV3::SignerSet)
        );
    }
    for index in [0, 5] {
        let mut changed = possessions.clone();
        changed[index].signature[0] ^= 1;
        assert!(fixture
            .roster
            .verify_possessions(statement, &changed, &mut shared)
            .is_err());
    }
    assert!(fixture
        .roster
        .verify_possessions(
            b"rotate|other-intent|other-nonce",
            &possessions,
            &mut shared
        )
        .is_err());
    let mut wrong_role = possessions.clone();
    wrong_role[0] = fixture.sign(
        wrong_role[0].signer,
        &approval_message_v3(statement).unwrap(),
    );
    assert!(fixture
        .roster
        .verify_possessions(statement, &wrong_role, &mut shared)
        .is_err());
    let approval_rows = [
        possessions[0].clone(),
        possessions[1].clone(),
        possessions[3].clone(),
        possessions[4].clone(),
    ];
    assert!(fixture
        .roster
        .verify_quorum(
            &approval_message_v3(statement).unwrap(),
            &approval_rows,
            &mut shared
        )
        .is_err());
}

#[test]
fn genuine_shake_key_is_rejected_despite_identical_key_and_signature_sizes() {
    let owned = generate("2.16.840.1.101.3.4.3.30");
    let public = RootPublicKeyV3 {
        suite: RootSuiteV3::SlhDsaSha2_256s,
        spki: owned.public_key_to_der().unwrap(),
    };
    assert_eq!(public.spki.len(), 82);
    let mut signer = Signer::new_without_digest(&owned).unwrap();
    let signature = signer
        .sign_oneshot_to_vec(b"real SHAKE signature has the same length")
        .unwrap();
    assert_eq!(
        signature.len(),
        RootSuiteV3::SlhDsaSha2_256s.signature_bytes()
    );
    assert_eq!(public.id(), Err(RootCryptoErrorV3::PublicKeyEncoding));
}

#[test]
fn malformed_and_cancelled_attempts_use_the_original_budget_before_crypto() {
    let fixture = Fixture::new();
    let message = approval_message_v3(b"normal|bounded-intent").unwrap();
    let valid = fixture.quorum(&message, [[0, 1], [0, 1]]);
    let mut shared = VerificationBudgetV3::new(8).unwrap();
    let mut short = valid.clone();
    short[0].signature.pop();
    assert_eq!(
        fixture.roster.verify_quorum(&message, &short, &mut shared),
        Err(RootCryptoErrorV3::SignatureLength)
    );
    assert_eq!(shared.attempts(), 4);
    assert_eq!(
        fixture
            .roster
            .verify_quorum(&vec![0; MAX_MESSAGE_BYTES_V3 + 1], &valid, &mut shared),
        Err(RootCryptoErrorV3::MessageLength)
    );
    assert_eq!(shared.attempts(), 8);
    assert_eq!(
        fixture.roster.verify_quorum(&message, &valid, &mut shared),
        Err(RootCryptoErrorV3::Budget)
    );
    assert_eq!(shared.attempts(), 12);
    let mut cancelled = budget();
    cancelled.cancel();
    assert_eq!(
        fixture
            .roster
            .verify_quorum(&message, &valid, &mut cancelled),
        Err(RootCryptoErrorV3::Budget)
    );
    assert_eq!(cancelled.attempts(), 4);
}

#[test]
fn warm_roster_preserves_full_quorum_and_budget_accounting() {
    let fixture = Fixture::new();
    let message = approval_message_v3(b"normal|warm-roster|same-original-operation").unwrap();
    let signatures = fixture.quorum(&message, [[0, 1], [0, 1]]);
    let expected_input_bytes = (ENCODED_ROSTER_BYTES_V3
        + message.len()
        + signatures
            .iter()
            .map(|row| 64 + row.signature.len())
            .sum::<usize>()) as u64;
    let encoded = fixture.roster.encode();
    let commitment = fixture.roster.commitment();
    let clone = fixture.roster.clone();
    let mut shared = VerificationBudgetV3::new(28).unwrap();

    for root in [&fixture.roster, &clone] {
        assert_eq!(
            root.verify_quorum(&message, &signatures, &mut shared)
                .unwrap()
                .len(),
            4
        );
    }
    assert_eq!(shared.attempts(), 8);
    assert_eq!(shared.charged_bytes(), 2 * expected_input_bytes);

    // Warming either clone does not cache a message or a successful signature.
    // Both families still verify on every public call and spend the full charge.
    let mut changed_message = message.clone();
    changed_message[0] ^= 1;
    assert!(clone
        .verify_quorum(&changed_message, &signatures, &mut shared)
        .is_err());
    for index in [0, 2] {
        let mut changed = signatures.clone();
        changed[index].signature[0] ^= 1;
        assert!(clone
            .verify_quorum(&message, &changed, &mut shared)
            .is_err());
    }
    assert_eq!(shared.attempts(), 20);
    assert_eq!(shared.charged_bytes(), 5 * expected_input_bytes);

    let decoded = DualFamilyRosterV3::decode(&encoded).unwrap();
    for root in [&decoded, &fixture.roster] {
        root.verify_quorum(&message, &signatures, &mut shared)
            .unwrap();
        assert_eq!(root, &fixture.roster);
        assert_eq!(root.encode(), encoded);
        assert_eq!(root.commitment(), commitment);
    }
    assert_eq!(shared.attempts(), 28);
    assert_eq!(shared.charged_bytes(), 7 * expected_input_bytes);
    assert_eq!(
        clone.verify_quorum(&message, &signatures, &mut shared),
        Err(RootCryptoErrorV3::Budget)
    );
    assert_eq!(shared.attempts(), 32);
    assert_eq!(shared.charged_bytes(), 8 * expected_input_bytes);

    let mut cancelled = budget();
    cancelled.cancel();
    assert_eq!(
        clone.verify_quorum(&message, &signatures, &mut cancelled),
        Err(RootCryptoErrorV3::Budget)
    );
    assert_eq!(cancelled.attempts(), 4);
    assert_eq!(cancelled.charged_bytes(), expected_input_bytes);
}
