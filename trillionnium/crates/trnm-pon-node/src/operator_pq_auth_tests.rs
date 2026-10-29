//! Real ML-DSA signatures through the existing authorization and durable journal.
//! Synthetic local sources establish neither outside Registry2 truth nor deployment.
use super::*;
use crate::{
    operator_continuous_history as history, operator_continuous_policy as policy,
    operator_continuous_recipient as recipient, operator_continuous_recovery as recovery,
    operator_continuous_test_support as fixtures,
};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use zeroize::Zeroizing;

fn key(byte: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([byte; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    PqNativeSigningKey::from_owned_seed(seed, id).unwrap()
}
fn identity() -> history::Identity {
    let mut value = fixtures::identity();
    value.schema = PQ_IDENTITY.into();
    value.registry_key = hex::encode(key(71).public_spki());
    value.task_key = hex::encode(key(72).public_spki());
    value
}
fn sign<T: Serialize>(body: &T, domain: &[u8]) -> (Vec<u8>, String) {
    let message = |role| {
        Profile::PqV3
            .message(b"unused-classical-domain", domain, body, role)
            .unwrap()
    };
    let raw = serde_json::to_vec(&serde_json::json!({
        "body":body,
        "registry_signature":hex::encode(key(71).sign_exact_message(&message(1)).unwrap()),
        "task_signature":hex::encode(key(72).sign_exact_message(&message(2)).unwrap()),
    }))
    .unwrap();
    (raw, crate::operator_task_policy::digest_bytes(&message(0)))
}
fn allocation(now: u64, budget_digest: &str) -> (Vec<u8>, recipient::Authority) {
    let mut body = fixtures::allocation("search");
    body.schema = "restricted-continuous-recipient-allocation-pq-v3".into();
    body.identity = identity();
    body.local_budget_digest = budget_digest.into();
    body.issued_ns = now;
    body.expires_ns = now + 60_000_000_000;
    body.claim.operation = recipient::operation_id(&body.identity, &body.claim).unwrap();
    let (raw, _) = sign(&body, b"TRNM/PoN/ContinuousRecipient/PQ/v3\0");
    let authority = recipient::Authority {
        identity: identity(),
        expected: body.clone(),
        expected_envelope_sha256: crate::operator_task_policy::digest_bytes(&raw),
        latest_allocator_sequence: body.allocator_sequence,
        latest_allocator_digest: body.allocator_record_sha256,
    };
    (raw, authority)
}

#[test]
fn pq_continuous_two_roles_have_no_classical_or_other_domain_fallback() {
    let now = crate::operator_task_policy::now_ns().unwrap();
    let (raw, authority) = allocation(now, &"11".repeat(32));
    assert!(recipient::authenticate(&raw, &authority, now).is_ok());
    let mut bad: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    bad["task_signature"] = bad["registry_signature"].clone();
    let bad = serde_json::to_vec(&bad).unwrap();
    let mut outside = authority;
    outside.expected_envelope_sha256 = crate::operator_task_policy::digest_bytes(&bad);
    assert_eq!(
        recipient::authenticate(&bad, &outside, now).err(),
        Some(PolicyError::Signature)
    );
    let mut old = fixtures::identity();
    old.registry_key = identity().registry_key;
    assert!(old.validate().is_err());
    let mut pq = identity();
    pq.task_key = fixtures::identity().task_key;
    assert!(pq.validate().is_err());
    let key = key(71);
    let public = hex::encode(key.public_spki());
    let mut budget = SignatureBudget::pair();
    for _ in 0..2 {
        assert!(Profile::PqV3
            .verify(&public, b"one", &"00".repeat(64), &mut budget)
            .is_err());
    }
    assert_eq!(
        Profile::PqV3.verify(
            &public,
            b"one",
            &hex::encode(key.sign_exact_message(b"one").unwrap()),
            &mut budget
        ),
        Err(PolicyError::Capacity)
    );
}

#[test]
fn pq_continuous_real_budget_allocation_replay_and_cold_journal_keep_authority() {
    let now = crate::operator_task_policy::now_ns().unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let identity = identity();
    let mut journal =
        history::Journal::open(dir.path(), uid, &identity, &history::Anchor::empty()).unwrap();
    let mut delegation = fixtures::delegation(1);
    delegation.schema = "restricted-continuous-registry2-budget-delegation-pq-v3".into();
    delegation.not_before_ns = now;
    delegation.expires_ns = now + 60_000_000_000;
    let body = history::BudgetIncrease {
        schema: "restricted-continuous-budget-increase-pq-v3".into(),
        identity: identity.clone(),
        sequence: 1,
        previous_digest: None,
        exact_prior_journal: journal.anchor(),
        exact_usage_digest: journal.usage_digest().unwrap(),
        ceilings: history::Ceilings {
            global: fixtures::usage(),
            tasks: BTreeMap::from([("10".repeat(32), fixtures::usage())]),
            classes: BTreeMap::from([("structured".into(), fixtures::usage())]),
        },
        issued_ns: now,
        expires_ns: delegation.expires_ns,
        revoked: false,
        delegation,
    };
    let (raw, digest) = sign(&body, b"TRNM/PoN/ContinuousBudget/PQ/v3\0");
    let authority = history::BumpAuthority {
        identity: identity.clone(),
        expected: body,
        envelope_sha256: crate::operator_task_policy::digest_bytes(&raw),
        latest_sequence: 1,
        latest_digest: digest.clone(),
    };
    let bump = history::authenticate_bump(&raw, &authority, now).unwrap();
    journal.increase(&bump).unwrap();
    let (raw, authority) = allocation(now, &digest);
    let permission = recipient::authenticate(&raw, &authority, now).unwrap();
    journal.reserve_allocation(&permission).unwrap();
    let head = journal.anchor();
    let usage = journal.usage_digest().unwrap();
    assert_eq!(
        journal.reserve_allocation(&permission),
        Err(PolicyError::Replay)
    );
    assert_eq!(journal.anchor(), head);
    assert_eq!(journal.usage_digest().unwrap(), usage);
    drop(journal);
    assert!(history::Journal::open(dir.path(), uid, &fixtures::identity(), &head).is_err());
    let mut reopened = history::Journal::open(dir.path(), uid, &identity, &head).unwrap();
    assert_eq!(reopened.usage_digest().unwrap(), usage);
    assert_eq!(
        reopened.reserve_allocation(&permission),
        Err(PolicyError::Replay)
    );
    let row: serde_json::Value = serde_json::from_slice(
        &fs::read(dir.path().join("entry-00000000000000000001.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(row["schema"], "restricted-continuous-journal-row-pq-v3");
}

#[test]
fn pq_continuous_view_pins_every_nested_authority_and_keeps_original_permit_fences() {
    let now = crate::operator_task_policy::now_ns().unwrap();
    let (raw, authority) = allocation(now, &"11".repeat(32));
    let claim = authority.expected.claim.clone();
    let view = policy::TaskView {
        schema: "restricted-continuous-task-view-pq-v3".into(),
        identity: identity(),
        sequence: 1,
        previous_digest: None,
        actual_parent: claim.parent.clone(),
        actual_generation: 0,
        declared_binding: fixtures::binding(),
        allocation_envelopes: vec![crate::operator_task_policy::digest_bytes(&raw)],
        searches: Vec::new(),
        allowed_transactions: Vec::new(),
        issued_ns: now,
        expires_ns: now + 60_000_000_000,
        revoked: false,
        pool_selections: Vec::new(),
        lease_edge: None,
        lease_transition_operation: None,
    };
    // The recipient's declared task is sufficient here; no search request is
    // authorized by this fixture, so use the existing reconcile view shape.
    let mut input = policy::tests::inputs();
    let mut allocation_body = authority.expected;
    allocation_body.claim.purpose = "parent-reconcile".into();
    allocation_body.claim.operation =
        recipient::operation_id(&allocation_body.identity, &allocation_body.claim).unwrap();
    let (raw, _) = sign(&allocation_body, b"TRNM/PoN/ContinuousRecipient/PQ/v3\0");
    let mut view = view;
    view.searches.clear();
    view.allocation_envelopes = vec![crate::operator_task_policy::digest_bytes(&raw)];
    let (raw_view, view_digest) = sign(&view, b"TRNM/PoN/ContinuousView/PQ/v3\0");
    input.raw_view = raw_view;
    input.view_authority.identity = identity();
    input.view_authority.expected = view;
    input.view_authority.envelope_sha256 =
        crate::operator_task_policy::digest_bytes(&input.raw_view);
    input.view_authority.latest_digest = view_digest;
    input.allocations = vec![policy::SignedAllocationInput {
        authority: recipient::Authority {
            identity: identity(),
            expected: allocation_body.clone(),
            expected_envelope_sha256: crate::operator_task_policy::digest_bytes(&raw),
            latest_allocator_sequence: allocation_body.allocator_sequence,
            latest_allocator_digest: allocation_body.allocator_record_sha256,
        },
        raw,
    }];
    let verified = policy::authenticate(&input, now).unwrap();
    assert!(verified.check_window(now).is_ok());
    assert!(verified.check_window(now + 60_000_000_000).is_err());
    let marker = verified.marker(&input.journal_path).unwrap();
    assert!(String::from_utf8(marker).unwrap().contains(PQ_MODE));
    input.allocations[0].authority.identity = fixtures::identity();
    assert!(policy::authenticate(&input, now).is_err());
}

#[test]
fn pq_continuous_recovery_signature_cannot_forge_a_closed_process() {
    let now = crate::operator_task_policy::now_ns().unwrap();
    let mut body = recovery::tests::verified(
        history::Anchor {
            sequence: 1,
            digest: "92".repeat(32),
        },
        "93".repeat(32),
    )
    .body;
    body.schema = "restricted-continuous-known-unclean-restart-pq-v3".into();
    body.identity = identity();
    body.issued_ns = now;
    body.expires_ns = now + 1_000_000_000;
    let (raw, digest) = sign(&body, b"TRNM/PoN/ContinuousKnownUnclean/PQ/v3\0");
    let input = recovery::Input {
        authority: recovery::Authority {
            identity: identity(),
            expected: body,
            envelope_sha256: crate::operator_task_policy::digest_bytes(&raw),
            body_digest: digest,
        },
        raw,
    };
    let verified = recovery::authenticate(&input, &identity(), now).unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = history::Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &history::Anchor::empty(),
    )
    .unwrap();
    let before = journal.anchor();
    assert!(journal.issue_known_unclean_restart(&verified).is_err());
    assert_eq!(journal.anchor(), before);
    assert!(recovery::authenticate(&input, &identity(), now + 1_000_000_000).is_err());
}
