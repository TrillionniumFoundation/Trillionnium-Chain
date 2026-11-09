use super::*;
use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
};
use sha2::Sha256;
use std::{process::Command, sync::OnceLock};
use trnm_crypto_primitives::pq_root_v3::{possession_message_v3, RootPublicKeyV3, RootSuiteV3};

struct Fixture {
    policy: RootPolicyV3,
    keys: BTreeMap<DigestV3, PKey<Private>>,
}
impl Fixture {
    fn generate(expiry: u64) -> Self {
        let binary =
            std::env::var("TRNM_PQ_OPENSSL").expect("explicit pinned OpenSSL test executable");
        let pin = std::env::var("TRNM_PQ_OPENSSL_SHA256").expect("explicit executable SHA256");
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(&binary).unwrap())),
            pin
        );
        let mut public = Vec::new();
        let mut keys = BTreeMap::new();
        for (name, suite) in [
            ("ML-DSA-87", RootSuiteV3::MlDsa87),
            ("SLH-DSA-SHA2-256s", RootSuiteV3::SlhDsaSha2_256s),
        ] {
            for _ in 0..3 {
                let result = Command::new(&binary)
                    .args(["genpkey", "-algorithm", name, "-outform", "DER"])
                    .env("OPENSSL_CONF", "/dev/null")
                    .output()
                    .unwrap();
                assert!(result.status.success(), "real key generation failed");
                let key = PKey::private_key_from_der(&result.stdout).unwrap();
                let row = RootPublicKeyV3 {
                    suite,
                    spki: key.public_key_to_der().unwrap(),
                };
                keys.insert(row.id().unwrap(), key);
                public.push(row);
            }
        }
        Self {
            policy: RootPolicyV3 {
                roster: DualFamilyRosterV3::from_keys(public).unwrap(),
                expires_at_unix: expiry,
            },
            keys,
        }
    }
    fn sign(&self, signer: DigestV3, message: &[u8]) -> RootSignatureV3 {
        let mut native = Signer::new_without_digest(&self.keys[&signer]).unwrap();
        RootSignatureV3 {
            signer,
            signature: native.sign_oneshot_to_vec(message).unwrap(),
        }
    }
    fn approvals(
        &self,
        statement: &RootStatementV3,
        ml: [usize; 2],
        slh: [usize; 2],
    ) -> Vec<RootSignatureV3> {
        let keys = self.policy.roster.keys();
        let mut rows = Vec::new();
        for (suite, selected) in [
            (RootSuiteV3::MlDsa87, ml),
            (RootSuiteV3::SlhDsaSha2_256s, slh),
        ] {
            let members: Vec<_> = keys.iter().filter(|key| key.suite == suite).collect();
            for index in selected {
                rows.push(self.sign(
                    members[index].id().unwrap(),
                    &statement.signing_message().unwrap(),
                ));
            }
        }
        rows
    }
    fn envelope(&self, statement: RootStatementV3, next: Option<&Fixture>) -> RootEnvelopeV3 {
        let approvals = self.approvals(&statement, [0, 1], [0, 1]);
        let successor_possessions = next.map_or_else(Vec::new, |next| {
            next.policy
                .roster
                .key_ids()
                .into_iter()
                .map(|id| {
                    let message = possession_message_v3(
                        &statement.encode().unwrap(),
                        &next.policy.roster,
                        id,
                    )
                    .unwrap();
                    next.sign(id, &message)
                })
                .collect()
        });
        RootEnvelopeV3 {
            statement,
            approvals,
            successor_possessions,
        }
    }
}
fn fixtures() -> (&'static Fixture, &'static Fixture) {
    static KEYS: OnceLock<(Fixture, Fixture)> = OnceLock::new();
    let (old, next) = KEYS.get_or_init(|| (Fixture::generate(400), Fixture::generate(1000)));
    (old, next)
}
fn state() -> RootStateV3 {
    RootStateV3::bootstrap([7; 64], fixtures().0.policy.clone(), 100).unwrap()
}
fn intent() -> ReleaseIntentV3 {
    ReleaseIntentV3::from_bytes(
        ReleaseUseV3::Install,
        b"complete bundle",
        b"complete contract",
        b"actual executable bytes",
        [8; 32],
    )
    .unwrap()
}
fn statement(state: &RootStateV3, nonce: u8, action: RootActionV3) -> RootStatementV3 {
    RootStatementV3 {
        scope: state.scope(),
        generation: state.generation(),
        sequence: state.sequence() + 1,
        predecessor: state.checkpoint(),
        nonce: [nonce; 32],
        valid_from_unix: 100,
        expires_at_unix: 900,
        action,
    }
}
fn budget() -> VerificationBudgetV3 {
    VerificationBudgetV3::new(64).unwrap()
}
fn normal(state: &RootStateV3, nonce: u8) -> RootEnvelopeV3 {
    fixtures().0.envelope(
        statement(state, nonce, RootActionV3::Normal { intent: intent() }),
        None,
    )
}

#[test]
fn native_v3_all_five_actions_require_real_fixed_dual_quorum() {
    let (old, next) = fixtures();
    for action in [
        RootActionV3::Normal { intent: intent() },
        RootActionV3::Rotate {
            next: next.policy.clone(),
        },
        RootActionV3::Revoke {
            keys: vec![old.policy.roster.key_ids()[0]],
        },
        RootActionV3::Recover {
            next: next.policy.clone(),
        },
        RootActionV3::PolicyChange {
            next: next.policy.clone(),
        },
    ] {
        let mut owner = state();
        let successor = action.successor().map(|_| next);
        let envelope = old.envelope(statement(&owner, 1, action), successor);
        let before = owner.encode().unwrap();
        let mut bad = envelope.clone();
        bad.approvals[0].signature[10] ^= 1;
        assert!(owner.apply(&bad, 110, &mut budget()).is_err());
        assert_eq!(owner.encode().unwrap(), before);
        owner.apply(&envelope, 110, &mut budget()).unwrap();
        assert_eq!(owner.sequence(), 1);
        assert_eq!(owner.nonce_count(), 1);
    }
}

#[test]
fn native_v3_successor_requires_every_separate_possession() {
    let (old, next) = fixtures();
    let base = state();
    let envelope = old.envelope(
        statement(
            &base,
            2,
            RootActionV3::Rotate {
                next: next.policy.clone(),
            },
        ),
        Some(next),
    );
    for index in 0..6 {
        let mut bad = envelope.clone();
        bad.successor_possessions[index].signature[8] ^= 1;
        let mut owner = base.clone();
        assert!(owner.apply(&bad, 111, &mut budget()).is_err());
        assert_eq!(owner, base);
    }
    let mut missing = envelope.clone();
    missing.successor_possessions.pop();
    assert!(base.clone().apply(&missing, 111, &mut budget()).is_err());
    let mut no_old = envelope.clone();
    no_old.approvals.clear();
    assert!(base.clone().apply(&no_old, 111, &mut budget()).is_err());
}

#[test]
fn native_v3_shared_budget_does_not_reset_between_old_and_successor() {
    let (old, next) = fixtures();
    let mut owner = state();
    let envelope = old.envelope(
        statement(
            &owner,
            3,
            RootActionV3::Rotate {
                next: next.policy.clone(),
            },
        ),
        Some(next),
    );
    let before = owner.clone();
    let mut insufficient = VerificationBudgetV3::new(9).unwrap();
    assert!(owner.apply(&envelope, 111, &mut insufficient).is_err());
    assert_eq!(owner, before);
    assert!(insufficient.attempts() >= 9);
    // Cancellation of an already charged original budget must be observed
    // before context processing or another verification, without resetting
    // the prior successful current-quorum reservation or mutating the state.
    let mut cancelled = VerificationBudgetV3::new(14).unwrap();
    old.policy
        .roster
        .verify_quorum(
            &envelope.statement.signing_message().unwrap(),
            &envelope.approvals,
            &mut cancelled,
        )
        .unwrap();
    let charged = cancelled.charged_bytes();
    assert_eq!(cancelled.attempts(), 4);
    cancelled.cancel();
    assert_eq!(
        owner.apply(&envelope, 111, &mut cancelled),
        Err(RootErrorV3::from(RootCryptoErrorV3::Budget))
    );
    assert_eq!(owner, before);
    assert_eq!(cancelled.attempts(), 4);
    assert_eq!(cancelled.charged_bytes(), charged);
    owner
        .apply(&envelope, 111, &mut VerificationBudgetV3::new(10).unwrap())
        .unwrap();
}

#[test]
fn native_v3_nine_quorum_choices_share_semantic_operation() {
    let old = fixtures().0;
    let base = state();
    let body = statement(&base, 4, RootActionV3::Normal { intent: intent() });
    let operation = body.operation_id().unwrap();
    let message = body.signing_message().unwrap();
    let signed: BTreeMap<_, _> = old
        .policy
        .roster
        .key_ids()
        .into_iter()
        .map(|id| (id, old.sign(id, &message)))
        .collect();
    let ml: Vec<_> = old
        .policy
        .roster
        .keys()
        .iter()
        .filter(|k| k.suite == RootSuiteV3::MlDsa87)
        .map(|k| k.id().unwrap())
        .collect();
    let slh: Vec<_> = old
        .policy
        .roster
        .keys()
        .iter()
        .filter(|k| k.suite == RootSuiteV3::SlhDsaSha2_256s)
        .map(|k| k.id().unwrap())
        .collect();
    for m in [[0, 1], [0, 2], [1, 2]] {
        for s in [[0, 1], [0, 2], [1, 2]] {
            let approvals = [ml[m[0]], ml[m[1]], slh[s[0]], slh[s[1]]]
                .iter()
                .map(|id| signed[id].clone())
                .collect();
            let envelope = RootEnvelopeV3 {
                statement: body.clone(),
                approvals,
                successor_possessions: vec![],
            };
            let mut owner = base.clone();
            assert_eq!(
                owner.apply(&envelope, 111, &mut budget()).unwrap(),
                operation
            );
            assert!(owner.apply(&envelope, 111, &mut budget()).is_err());
        }
    }
}

#[test]
fn native_v3_nonce_and_revocations_survive_generation_change() {
    let (old, next) = fixtures();
    let mut owner = state();
    let revoke = old.envelope(
        statement(
            &owner,
            5,
            RootActionV3::Revoke {
                keys: vec![old.policy.roster.key_ids()[0]],
            },
        ),
        None,
    );
    owner.apply(&revoke, 111, &mut budget()).unwrap();
    let body = statement(
        &owner,
        6,
        RootActionV3::Recover {
            next: next.policy.clone(),
        },
    );
    let mut rotation = old.envelope(body.clone(), Some(next));
    // Select the two surviving members of each family explicitly.
    let revoked = *owner.revoked().iter().next().unwrap();
    rotation.approvals = old
        .policy
        .roster
        .keys()
        .iter()
        .filter(|k| k.id().unwrap() != revoked)
        .fold(BTreeMap::<u8, Vec<DigestV3>>::new(), |mut map, key| {
            let tag = if key.suite == RootSuiteV3::MlDsa87 {
                1
            } else {
                2
            };
            map.entry(tag).or_default().push(key.id().unwrap());
            map
        })
        .values()
        .flat_map(|ids| ids.iter().take(2))
        .map(|id| old.sign(*id, &body.signing_message().unwrap()))
        .collect();
    owner.apply(&rotation, 112, &mut budget()).unwrap();
    assert!(owner.revoked().contains(&revoked));
    assert_eq!(owner.nonce_count(), 2);
    let retry = next.envelope(
        statement(&owner, 5, RootActionV3::Normal { intent: intent() }),
        None,
    );
    assert!(matches!(
        owner.apply(&retry, 113, &mut budget()),
        Err(RootErrorV3::Nonce)
    ));
    let resurrection = next.envelope(
        statement(
            &owner,
            7,
            RootActionV3::Recover {
                next: old.policy.clone(),
            },
        ),
        Some(old),
    );
    assert!(owner.apply(&resurrection, 114, &mut budget()).is_err());
}

#[test]
fn native_v3_current_intent_rechecks_rotation_revocation_and_expiry() {
    let (old, next) = fixtures();
    let mut base = state();
    let envelope = normal(&base, 8);
    let operation = base.apply(&envelope, 110, &mut budget()).unwrap();
    assert!(base.check_current(operation, 110).unwrap().matches_bytes(
        b"complete bundle",
        b"complete contract",
        b"actual executable bytes"
    ));
    assert!(base.check_current(operation, 99).is_err());
    assert!(base.check_current(operation, 400).is_err());
    let mut rotated = base.clone();
    let transition = old.envelope(
        statement(
            &rotated,
            9,
            RootActionV3::Rotate {
                next: next.policy.clone(),
            },
        ),
        Some(next),
    );
    rotated.apply(&transition, 111, &mut budget()).unwrap();
    assert!(rotated.check_current(operation, 112).is_err());
    let mut revoked = base.clone();
    let transition = old.envelope(
        statement(
            &revoked,
            10,
            RootActionV3::Revoke {
                keys: vec![envelope.approvals[0].signer],
            },
        ),
        None,
    );
    revoked.apply(&transition, 111, &mut budget()).unwrap();
    assert!(matches!(
        revoked.check_current(operation, 112),
        Err(RootErrorV3::Revoked)
    ));
}

#[test]
fn native_v3_expired_recovery_keeps_both_current_quorums() {
    let (old, next) = fixtures();
    let mut owner = state();
    let rotate = old.envelope(
        statement(
            &owner,
            11,
            RootActionV3::Rotate {
                next: next.policy.clone(),
            },
        ),
        Some(next),
    );
    assert!(owner.apply(&rotate, 401, &mut budget()).is_err());
    let recover = old.envelope(
        statement(
            &owner,
            11,
            RootActionV3::Recover {
                next: next.policy.clone(),
            },
        ),
        Some(next),
    );
    let mut missing_family = recover.clone();
    missing_family.approvals.truncate(2);
    assert!(owner.apply(&missing_family, 401, &mut budget()).is_err());
    owner.apply(&recover, 401, &mut budget()).unwrap();
    assert_eq!(owner.generation(), 2);
}

#[test]
fn native_v3_full_intent_scope_epoch_predecessor_and_time_are_bound() {
    let original = state();
    let envelope = normal(&original, 12);
    let mut variants = Vec::new();
    let mut bad = envelope.clone();
    bad.statement.scope[0] ^= 1;
    variants.push(bad);
    let mut bad = envelope.clone();
    bad.statement.generation += 1;
    variants.push(bad);
    let mut bad = envelope.clone();
    bad.statement.sequence += 1;
    variants.push(bad);
    let mut bad = envelope.clone();
    bad.statement.predecessor[0] ^= 1;
    variants.push(bad);
    let mut bad = envelope.clone();
    bad.statement.nonce[0] ^= 1;
    variants.push(bad);
    let mut bad = envelope.clone();
    bad.statement.expires_at_unix += 1;
    variants.push(bad);
    let mut bad = envelope.clone();
    if let RootActionV3::Normal { intent } = &mut bad.statement.action {
        intent.contract.push(1);
    }
    variants.push(bad);
    for bad in variants {
        let mut owner = original.clone();
        assert!(owner.apply(&bad, 111, &mut budget()).is_err());
        assert_eq!(owner, original);
    }
}

#[test]
fn native_v3_canonical_wire_rejects_aliases_truncation_and_unknown_action() {
    let envelope = normal(&state(), 13);
    let raw = envelope.encode().unwrap();
    assert_eq!(RootEnvelopeV3::decode(&raw).unwrap().encode().unwrap(), raw);
    for end in [0, 1, ENVELOPE.len(), raw.len() - 1] {
        assert!(RootEnvelopeV3::decode(&raw[..end]).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(RootEnvelopeV3::decode(&extra).is_err());
    let mut unknown = envelope.statement.encode().unwrap();
    unknown[STATEMENT.len() + 192] = 255;
    assert!(RootStatementV3::decode(&unknown).is_err());
    let mut legacy = envelope.statement.encode().unwrap();
    legacy[0] ^= 1;
    assert!(RootStatementV3::decode(&legacy).is_err());
    let policy = fixtures().0.policy.encode().unwrap();
    assert_eq!(RootPolicyV3::decode(&policy).unwrap(), fixtures().0.policy);
}

#[test]
fn native_v3_capacity_never_prunes_nonce_history() {
    let mut owner = state();
    for index in 0..MAX_ROOT_OPERATIONS_V3 {
        let mut nonce = [0; 32];
        nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
        owner.nonces.insert(nonce);
    }
    let before = owner.clone();
    let envelope = normal(&owner, 14);
    assert!(matches!(
        owner.apply(&envelope, 111, &mut budget()),
        Err(RootErrorV3::Capacity)
    ));
    assert_eq!(owner, before);
}

#[test]
fn native_v3_time_is_exclusive_unix_and_artifact_observations_are_exact() {
    let mut owner = state();
    let mut body = statement(&owner, 15, RootActionV3::Normal { intent: intent() });
    body.expires_at_unix = 120;
    let envelope = fixtures().0.envelope(body, None);
    assert!(owner.apply(&envelope, 120, &mut budget()).is_err());
    let operation = owner.apply(&envelope, 119, &mut budget()).unwrap();
    let checked = owner.check_current(operation, 119).unwrap();
    assert!(!checked.matches_bytes(
        b"other bundle",
        b"complete contract",
        b"actual executable bytes"
    ));
    assert!(!checked.matches_bytes(
        b"complete bundle",
        b"other contract",
        b"actual executable bytes"
    ));
    assert!(!checked.matches_bytes(
        b"complete bundle",
        b"complete contract",
        b"changed executable bytes"
    ));
    assert!(owner.check_current(operation, 120).is_err());
}

#[test]
fn native_v3_bounded_intent_rejects_unbounded_material_before_hashing() {
    let too_large = vec![1; MAX_RELEASE_INTENT_PART_BYTES_V3 + 1];
    assert!(ReleaseIntentV3::from_bytes(
        ReleaseUseV3::Install,
        &too_large,
        b"contract",
        b"artifact",
        [1; 32]
    )
    .is_err());
    assert!(ReleaseIntentV3::from_bytes(
        ReleaseUseV3::Install,
        b"bundle",
        b"contract",
        b"",
        [1; 32]
    )
    .is_err());
    let mut claimed = intent();
    claimed.artifact_size = MAX_ROOT_ARTIFACT_BYTES_V3 + 1;
    assert!(claimed.encode().is_err());
}
