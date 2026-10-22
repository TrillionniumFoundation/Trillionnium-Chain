//! Unexecuted test definitions. Real Ed25519 verification and filesystem I/O,
//! not proof that a synthetic task has Native/model/source/economic qualification.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};

pub(crate) fn body() -> Grant {
    let start = now_ns().unwrap();
    let d = || "11".repeat(32);
    let allocation = Allocation {
        cpu_ns: 60_000_000_000,
        material_bytes: 100_000,
        da_bytes: 100_000,
        funding_units: 1,
        reuse_uses: 0,
    };
    let mut grant = Grant {
        schema: MODE.into(),
        context: Context {
            registry_id: d(),
            operator_id: d(),
            network: d(),
            parameters: d(),
            source_commit: "22".repeat(20),
            node_policy_source: d(),
            registry2_package: d(),
            actual_parent: d(),
        },
        registry_sequence: 1,
        registry_digest: d(),
        registry_previous_digest: None,
        declaration_digest: d(),
        exact_packet_sha256: "01".repeat(32),
        operation_id: d(),
        task: Task {
            purpose: "maintenance-tag1".into(),
            native_task: d(),
            lease_sha256: d(),
            model_id: "synthetic-public-policy-test-not-qualified".into(),
            model_revision: "33".repeat(20),
            model_material: d(),
            native_model: d(),
            layer_tensor: "declared-test-layer".into(),
            layer_index: 0,
            layer_selector: d(),
            input_material: d(),
            native_input: d(),
            dimension: 64,
            field_modulus: Q,
            encoding: "canonical-u32-le".into(),
            a_sha256: d(),
            b_sha256: d(),
            full_material_catalog: d(),
            recipe_sha256: d(),
        },
        instance_class: "structured".into(),
        nonce_first: 1,
        nonce_last: 10,
        source_class: "declared-same-operator".into(),
        cost_class: "unmeasured".into(),
        cost_evidence: None,
        preprocessing: "forbidden".into(),
        prepared_artifact: None,
        setup_record: None,
        funding_commitment: d(),
        funding_evidence: d(),
        declared_funding_units: 2,
        retention_until_ns: start + 2_000_000_000_000,
        allocation: allocation.clone(),
        limits: Limits {
            operations: 2,
            allocation: Allocation {
                cpu_ns: allocation.cpu_ns * 2,
                material_bytes: allocation.material_bytes * 2,
                da_bytes: allocation.da_bytes * 2,
                funding_units: 2,
                reuse_uses: 0,
            },
        },
        not_before_ns: start,
        expires_ns: start + 1_000_000_000_000,
        revoked: false,
        allowed_task_commands: Vec::new(),
    };
    grant.operation_id = operator_operation_id(&grant.context, &grant.exact_packet_sha256).unwrap();
    grant
}
pub(crate) fn signed(body: Grant) -> (Vec<u8>, ExternalAuthority) {
    // Fixed public test seeds only. No operational signing key is used.
    let registry = signing_key_from_hex(&"07".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"09".repeat(32)).unwrap();
    let raw = serde_json::to_vec(&Envelope {
        registry_signature: sign_hex(&registry, &message(&body, 1)),
        task_signature: sign_hex(&task, &message(&body, 2)),
        body: body.clone(),
    })
    .unwrap();
    let external = ExternalAuthority {
        registry_key: public_key_hex(&registry),
        task_key: public_key_hex(&task),
        latest_sequence: body.registry_sequence,
        latest_digest: body.registry_digest.clone(),
        expected_envelope_sha256: sha(&raw),
        expected: body,
    };
    (raw, external)
}
pub(crate) fn authenticated(body: Grant) -> VerifiedPolicy {
    let (raw, external) = signed(body);
    authenticate(&raw, &external, external.expected.not_before_ns + 1).unwrap()
}
fn next_packet(prior: &Grant, number: u8) -> Grant {
    let mut next = prior.clone();
    next.registry_sequence += 1;
    next.registry_previous_digest = Some(prior.registry_digest.clone());
    next.registry_digest = sha(&next.registry_sequence.to_le_bytes());
    next.exact_packet_sha256 = format!("{number:02x}").repeat(32);
    next.operation_id = operator_operation_id(&next.context, &next.exact_packet_sha256).unwrap();
    next
}
fn facts(policy: &VerifiedPolicy, number: u8) -> NativeFacts {
    NativeFacts {
        network: policy.body.context.network.clone(),
        parameters: policy.body.context.parameters.clone(),
        parent: policy.body.context.actual_parent.clone(),
        task: policy.body.task.clone(),
        packet_sha256: format!("{number:02x}").repeat(32),
        header_nonce: 1,
    }
}
pub(crate) fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
pub(crate) fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[test]
fn outside_two_roles_and_complete_expected_context_are_mandatory() {
    let (raw, mut external) = signed(body());
    let now = external.expected.not_before_ns + 1;
    assert!(authenticate(&raw, &external, now).is_ok());
    external.task_key = external.registry_key.clone();
    assert_eq!(
        authenticate(&raw, &external, now).err(),
        Some(PolicyError::ExternalContext)
    );
    let (raw, mut external) = signed(body());
    external.expected.task.layer_index = 1;
    assert_eq!(
        authenticate(&raw, &external, external.expected.not_before_ns + 1).err(),
        Some(PolicyError::ExternalContext)
    );
}
#[test]
fn candidate_self_issuer_or_old_role_signature_is_not_authorized() {
    let (raw, mut external) = signed(body());
    let stranger = signing_key_from_hex(&"0b".repeat(32)).unwrap();
    external.task_key = public_key_hex(&stranger);
    assert_eq!(
        authenticate(&raw, &external, external.expected.not_before_ns + 1).err(),
        Some(PolicyError::Signature)
    );
    let (raw, mut external) = signed(body());
    let mut envelope: Envelope = serde_json::from_slice(&raw).unwrap();
    envelope.task_signature = envelope.registry_signature.clone();
    let changed = serde_json::to_vec(&envelope).unwrap();
    external.expected_envelope_sha256 = sha(&changed);
    assert_eq!(
        authenticate(&changed, &external, external.expected.not_before_ns + 1).err(),
        Some(PolicyError::Signature)
    );
}
#[test]
fn wrong_matrix_full_material_parent_class_and_time_fail_before_claim() {
    let policy = authenticated(body());
    let now = policy.body.not_before_ns + 1;
    let original = facts(&policy, 1);
    assert!(policy.check(&original, now).is_ok());
    for changed in [2013265921, 4294967290] {
        let mut f = facts(&policy, 1);
        f.task.field_modulus = changed;
        assert_eq!(policy.check(&f, now), Err(PolicyError::NativeBinding));
    }
    let mut f = facts(&policy, 1);
    f.task.full_material_catalog = "aa".repeat(32);
    assert_eq!(policy.check(&f, now), Err(PolicyError::NativeBinding));
    let mut f = facts(&policy, 1);
    f.parent = "aa".repeat(32);
    assert_eq!(policy.check(&f, now), Err(PolicyError::NativeBinding));
    assert_eq!(
        policy.check(&original, policy.body.expires_ns),
        Err(PolicyError::Window)
    );
    let mut wrong = body();
    wrong.instance_class = "arbitrary".into();
    assert_eq!(validate(&wrong), Err(PolicyError::Input));
}
#[test]
fn reservation_is_durable_no_refund_and_replay_is_global_across_declaration() {
    let dir = directory();
    let policy = authenticated(body());
    let now = policy.body.not_before_ns + 1;
    let f = facts(&policy, 1);
    {
        let mut journal = Journal::open(dir.path(), uid(), &policy).unwrap();
        journal.reserve(&policy, &f, now).unwrap();
        assert_eq!(
            journal.reserve(&policy, &f, now).err(),
            Some(PolicyError::Replay)
        );
    }
    let mut journal = Journal::open(dir.path(), uid(), &policy).unwrap();
    assert_eq!(
        journal.reserve(&policy, &f, now).err(),
        Some(PolicyError::Replay)
    );
    let second = authenticated(next_packet(&policy.body, 2));
    journal.reserve(&second, &facts(&second, 2), now).unwrap();
    let third = authenticated(next_packet(&second.body, 3));
    assert_eq!(
        journal.reserve(&third, &facts(&third, 3), now).err(),
        Some(PolicyError::Budget)
    );
}
#[test]
fn class_budget_does_not_reset_when_declaration_changes() {
    let dir = directory();
    let mut first = body();
    first.limits.operations = 1;
    let policy = authenticated(first.clone());
    let now = first.not_before_ns + 1;
    let mut journal = Journal::open(dir.path(), uid(), &policy).unwrap();
    journal.reserve(&policy, &facts(&policy, 1), now).unwrap();
    let mut second = next_packet(&first, 2);
    second.declaration_digest = "cc".repeat(32);
    let changed = authenticated(second);
    assert_eq!(
        journal.reserve(&changed, &facts(&changed, 2), now).err(),
        Some(PolicyError::Budget)
    );
}
#[test]
fn latest_anchor_cannot_roll_back_and_revocation_cannot_refund() {
    let dir = directory();
    let first = body();
    let policy = authenticated(first.clone());
    {
        let mut journal = Journal::open(dir.path(), uid(), &policy).unwrap();
        journal
            .reserve(&policy, &facts(&policy, 1), first.not_before_ns + 1)
            .unwrap();
    }
    let mut next = first.clone();
    next.registry_sequence = 2;
    next.registry_previous_digest = Some(first.registry_digest.clone());
    next.registry_digest = "ab".repeat(32);
    next.revoked = true;
    let revoked = authenticated(next);
    {
        let mut journal = Journal::open(dir.path(), uid(), &revoked).unwrap();
        assert_eq!(
            journal
                .reserve(&revoked, &facts(&revoked, 2), first.not_before_ns + 1)
                .err(),
            Some(PolicyError::Revoked)
        );
        assert_eq!(journal.claims.len(), 1);
    }
    assert_eq!(
        Journal::open(dir.path(), uid(), &policy).err(),
        Some(PolicyError::ExternalContext)
    );
}
#[test]
fn held_journal_refuses_symlink_hardlink_and_partial_claim() {
    let policy = authenticated(body());
    let dir = directory();
    let mut journal = Journal::open(dir.path(), uid(), &policy).unwrap();
    journal
        .reserve(&policy, &facts(&policy, 1), policy.body.not_before_ns + 1)
        .unwrap();
    let claim = dir
        .path()
        .join(format!("claim-{}.json", journal.claims[0].operation));
    drop(journal);
    let copy = dir.path().join("unexpected.json");
    fs::hard_link(&claim, &copy).unwrap();
    assert!(Journal::open(dir.path(), uid(), &policy).is_err());
    fs::remove_file(&copy).unwrap();
    let raw = fs::read(&claim).unwrap();
    fs::remove_file(&claim).unwrap();
    let other = directory();
    let target = other.path().join("claim.json");
    fs::write(&target, &raw).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &claim).unwrap();
    assert!(Journal::open(dir.path(), uid(), &policy).is_err());
    fs::remove_file(&claim).unwrap();
    fs::write(&claim, b"{").unwrap();
    fs::set_permissions(&claim, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Journal::open(dir.path(), uid(), &policy).is_err());
}
#[test]
fn uncertain_accounting_latch_survives_restart_without_erasing_claims() {
    let policy = authenticated(body());
    let dir = directory();
    let mut journal = Journal::open(dir.path(), uid(), &policy).unwrap();
    journal
        .reserve(&policy, &facts(&policy, 1), policy.body.not_before_ns + 1)
        .unwrap();
    journal.mark_unavailable().unwrap();
    drop(journal);
    assert!(Journal::open(dir.path(), uid(), &policy).is_err());
    assert!(dir.path().join("unavailable.json").is_file());
    assert_eq!(
        fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("claim-"))
            .count(),
        1
    );
}
#[test]
fn old_unqualified_register_work_command_is_rejected_without_whitelist_fallback() {
    let policy = authenticated(body());
    let raw = trnm_protocol::pon_wire::Envelope {
        network: [1; 32],
        sender: [1; 32],
        tag: 12,
        nonce: 1,
        expiry: 100,
        fee_limit: 100,
        payload: vec![2; 32],
        signature: [0; 64],
    };
    let encoded = raw.encode().unwrap();
    assert_eq!(
        policy.check_commands(&[encoded]),
        Err(PolicyError::NativeBinding)
    );
}

#[test]
fn signed_exact_packet_is_checked_before_any_durable_reservation() {
    let policy = authenticated(body());
    let dir = directory();
    let mut journal = Journal::open(dir.path(), uid(), &policy).unwrap();
    let now = policy.body.not_before_ns + 1;
    // A different complete packet digest is not covered by the same task/A/B/nonce.
    assert_eq!(
        journal.reserve(&policy, &facts(&policy, 2), now).err(),
        Some(PolicyError::NativeBinding)
    );
    assert!(journal.claims.is_empty());
    assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("claim-")));
    journal.reserve(&policy, &facts(&policy, 1), now).unwrap();
    assert_eq!(journal.claims.len(), 1);
    let mut wrong_operation = body();
    wrong_operation.operation_id = "ff".repeat(32);
    assert_eq!(validate(&wrong_operation), Err(PolicyError::NativeBinding));
}
#[test]
fn exact_packet_and_operation_changes_are_covered_by_both_signing_roles() {
    let original = body();
    let mut other = original.clone();
    other.exact_packet_sha256 = "02".repeat(32);
    other.operation_id = operator_operation_id(&other.context, &other.exact_packet_sha256).unwrap();
    assert_ne!(message(&original, 1), message(&other, 1));
    assert_ne!(message(&original, 2), message(&other, 2));
    let (raw, mut external) = signed(original);
    let mut envelope: Envelope = serde_json::from_slice(&raw).unwrap();
    envelope.body = other.clone();
    let changed = serde_json::to_vec(&envelope).unwrap();
    external.expected = other;
    external.expected_envelope_sha256 = sha(&changed);
    assert_eq!(
        authenticate(&changed, &external, external.expected.not_before_ns + 1).err(),
        Some(PolicyError::Signature)
    );
}
