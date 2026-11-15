//! Meaningful source definitions only; no synthetic task is Native qualification.
use super::*;
use std::os::unix::fs::PermissionsExt;
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
pub(crate) fn view() -> TaskView {
    let now = base::now_ns().unwrap();
    let h = || "11".repeat(32);
    let allocation = Allocation {
        cpu_ns: 60_000_000_000,
        material_bytes: 100_000,
        da_bytes: 100_000,
        funding_units: 1,
        reuse_uses: 0,
    };
    let mut v = TaskView {
        schema: MODE.into(),
        context: Context {
            registry_id: h(),
            operator_id: h(),
            network: h(),
            parameters: h(),
            source_commit: "22".repeat(20),
            node_policy_source: h(),
            registry2_package: h(),
            actual_parent: h(),
        },
        registry_sequence: 1,
        registry_digest: h(),
        registry_previous_digest: None,
        declaration_digest: h(),
        task: Task {
            purpose: "maintenance-tag1".into(),
            native_task: h(),
            lease_sha256: h(),
            model_id: "unqualified-source-fixture".into(),
            model_revision: "33".repeat(20),
            model_material: h(),
            native_model: h(),
            layer_tensor: "unqualified-declared-layer".into(),
            layer_index: 0,
            layer_selector: h(),
            input_material: h(),
            native_input: h(),
            dimension: 64,
            field_modulus: 4294967291,
            encoding: "canonical-u32-le".into(),
            a_sha256: h(),
            b_sha256: h(),
            full_material_catalog: h(),
            recipe_sha256: h(),
        },
        instance_class: "structured".into(),
        source_class: "declared-same-operator".into(),
        cost_class: "unmeasured".into(),
        cost_evidence: None,
        preprocessing: "forbidden".into(),
        prepared_artifact: None,
        setup_record: None,
        funding_commitment: h(),
        funding_evidence: h(),
        declared_funding_units: 4,
        limits: Limits {
            operations: 4,
            allocation: Allocation {
                cpu_ns: allocation.cpu_ns * 4,
                material_bytes: allocation.material_bytes * 4,
                da_bytes: allocation.da_bytes * 4,
                funding_units: 4,
                reuse_uses: 0,
            },
        },
        retention_until_ns: now + 2_000_000_000_000,
        not_before_ns: now,
        expires_ns: now + 1_000_000_000_000,
        revoked: false,
        allowed_task_commands: Vec::new(),
        permissions: Vec::new(),
    };
    let s = SearchIntent {
        miner: h(),
        timestamp: 1,
        exact_transactions_sha256: transactions_sha256(&[]).unwrap(),
        exact_group_ids: Vec::new(),
        nonce_first: 1,
        nonce_count: 8,
    };
    let payload = search_payload_sha256(&s).unwrap();
    let nonce = "44".repeat(32);
    v.permissions.push(OperationGrant {
        purpose: Purpose::Search,
        operation_id: operation_id(&v.context, &Purpose::Search, &nonce, &payload).unwrap(),
        operation_nonce: nonce,
        expected_generation: 0,
        payload_sha256: payload,
        search: Some(s),
        related_search_operation: None,
        allocation,
    });
    v
}
fn sign(v: TaskView) -> (Vec<u8>, ExternalAuthority) {
    let r = signing_key_from_hex(&"07".repeat(32)).unwrap();
    let t = signing_key_from_hex(&"09".repeat(32)).unwrap();
    let raw = serde_json::to_vec(&ViewEnvelope {
        registry_signature: sign_hex(&r, &signing_message(&v, 1).unwrap()),
        task_signature: sign_hex(&t, &signing_message(&v, 2).unwrap()),
        body: v.clone(),
    })
    .unwrap();
    let e = ExternalAuthority {
        registry_key: public_key_hex(&r),
        task_key: public_key_hex(&t),
        latest_sequence: v.registry_sequence,
        latest_digest: v.registry_digest.clone(),
        expected_envelope_sha256: sha(&raw),
        expected: v,
    };
    (raw, e)
}
pub(crate) fn verified(v: TaskView) -> VerifiedView {
    let (raw, e) = sign(v);
    authenticate(&raw, &e, e.expected.not_before_ns + 1).unwrap()
}
fn facts(v: &VerifiedView, index: usize) -> NativeFacts {
    let p = &v.body.permissions[index];
    NativeFacts {
        context: v.body.context.clone(),
        task: v.body.task.clone(),
        generation: p.expected_generation,
        purpose: p.purpose.clone(),
        payload_sha256: p.payload_sha256.clone(),
    }
}
fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
#[test]
fn taskview_has_no_dummy_packet_and_no_pool_or_work_domain_fallback() {
    let mut v = view();
    v.permissions.clear();
    let v = verified(v);
    assert!(v
        .permission(&Purpose::WinnerValidation, &"11".repeat(32))
        .is_err());
    let json = serde_json::to_value(&v.body).unwrap();
    assert!(json.get("exact_packet_sha256").is_none());
    let mut extra = json;
    extra["exact_packet_sha256"] = serde_json::json!("11".repeat(32));
    assert!(serde_json::from_value::<TaskView>(extra).is_err());
    assert_ne!(TASK_DOMAIN, b"TRNM-RESTRICTED-NODE-GRANT2");
    assert_ne!(TASK_DOMAIN, b"TRNM-RESTRICTED-NODE-POOL-GRANT1");
}
#[test]
fn outside_latest_two_keys_and_full_expected_parent_search_are_mandatory() {
    let (raw, mut e) = sign(view());
    let now = e.expected.not_before_ns + 1;
    assert!(authenticate(&raw, &e, now).is_ok());
    e.expected.permissions[0]
        .search
        .as_mut()
        .unwrap()
        .nonce_count = 9;
    assert!(authenticate(&raw, &e, now).is_err());
    let (raw, mut e) = sign(view());
    e.latest_sequence = 2;
    assert!(authenticate(&raw, &e, now).is_err());
    let (raw, mut e) = sign(view());
    e.task_key = e.registry_key.clone();
    assert!(authenticate(&raw, &e, now).is_err());
}
#[test]
fn wrong_parent_generation_and_ordered_transaction_digest_refuse_before_native() {
    let v = verified(view());
    let f = facts(&v, 0);
    assert!(v.check(&f, v.body.not_before_ns + 1).is_ok());
    let mut bad = f.clone();
    bad.context.actual_parent = "55".repeat(32);
    assert!(v.check(&bad, v.body.not_before_ns + 1).is_err());
    bad = f;
    bad.generation = 1;
    assert!(v.check(&bad, v.body.not_before_ns + 1).is_err());
    assert_ne!(
        transactions_sha256(&[vec![1; 159], vec![2; 159]]).unwrap(),
        transactions_sha256(&[vec![2; 159], vec![1; 159]]).unwrap()
    );
}
#[test]
fn nonce_zero_overflow_and_unbounded_search_are_not_mining_permissions() {
    for (first, count) in [(0, 1), (u64::MAX, 2), (1, 4097)] {
        let mut v = view();
        let s = v.permissions[0].search.as_mut().unwrap();
        s.nonce_first = first;
        s.nonce_count = count;
        assert!(validate(&v).is_err());
    }
}
#[test]
fn fresh_v3_journal_rejects_mode2_identity_and_keeps_replay_after_restart() {
    let d = dir();
    let v = verified(view());
    let mut j = Journal::open(d.path(), uid(), &v).unwrap();
    let f = facts(&v, 0);
    j.reserve(&v, &f, v.body.not_before_ns + 1).unwrap();
    assert_eq!(
        j.reserve(&v, &f, v.body.not_before_ns + 1).err(),
        Some(PolicyError::Replay)
    );
    drop(j);
    let mut reopened = Journal::open(d.path(), uid(), &v).unwrap();
    assert_eq!(
        reopened.reserve(&v, &f, v.body.not_before_ns + 1).err(),
        Some(PolicyError::Replay)
    );
    drop(reopened);
    let ip = d.path().join("identity.json");
    let mut identity: Identity = read(&ip, uid()).unwrap();
    identity.schema = "restricted-owner-node-journal-v2".into();
    fs::write(&ip, serde_json::to_vec(&identity).unwrap()).unwrap();
    assert!(Journal::open(d.path(), uid(), &v).is_err());
}
#[test]
fn linked_revoke_highwater_cancels_epoch_without_refund_or_rollback() {
    let d = dir();
    let old = verified(view());
    let mut j = Journal::open(d.path(), uid(), &old).unwrap();
    let f = facts(&old, 0);
    let r = j.reserve(&old, &f, old.body.not_before_ns + 1).unwrap();
    let mut next = old.body.clone();
    next.registry_sequence = 2;
    next.registry_previous_digest = Some(old.body.registry_digest.clone());
    next.registry_digest = "66".repeat(32);
    next.revoked = true;
    let next = verified(next);
    j.advance(&next).unwrap();
    assert!(j.recheck(&old, &r, &f, old.body.not_before_ns + 1).is_err());
    assert_eq!(
        next.check_window(next.body.not_before_ns + 1).err(),
        Some(PolicyError::Revoked)
    );
    drop(j);
    assert!(Journal::open(d.path(), uid(), &old).is_err());
    assert!(d.path().read_dir().unwrap().any(|r| r
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("claim-")));
}
#[test]
fn task_and_class_budget_accumulates_across_views_and_purposes() {
    let d = dir();
    let mut first = view();
    first.limits.operations = 1;
    let old = verified(first);
    let mut j = Journal::open(d.path(), uid(), &old).unwrap();
    j.reserve(&old, &facts(&old, 0), old.body.not_before_ns + 1)
        .unwrap();
    let mut n = old.body.clone();
    n.registry_sequence = 2;
    n.registry_previous_digest = Some(old.body.registry_digest.clone());
    n.registry_digest = "77".repeat(32);
    n.permissions[0].purpose = Purpose::ParentReconcile;
    n.permissions[0].payload_sha256 = n.context.actual_parent.clone();
    n.permissions[0].search = None;
    n.permissions[0].operation_nonce = "88".repeat(32);
    n.permissions[0].operation_id = operation_id(
        &n.context,
        &n.permissions[0].purpose,
        &n.permissions[0].operation_nonce,
        &n.permissions[0].payload_sha256,
    )
    .unwrap();
    let n = verified(n);
    j.advance(&n).unwrap();
    assert_eq!(
        j.reserve(&n, &facts(&n, 0), n.body.not_before_ns + 1).err(),
        Some(PolicyError::Budget)
    );
}
#[test]
fn unknown_accounting_blocks_restart_and_does_not_remove_reserved_history() {
    let d = dir();
    let v = verified(view());
    let mut j = Journal::open(d.path(), uid(), &v).unwrap();
    j.reserve(&v, &facts(&v, 0), v.body.not_before_ns + 1)
        .unwrap();
    j.mark_unavailable().unwrap();
    drop(j);
    assert!(Journal::open(d.path(), uid(), &v).is_err());
    assert!(d.path().join("unavailable.json").exists());
    assert!(d.path().read_dir().unwrap().any(|r| r
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("claim-")));
}
#[test]
fn search_intent_cannot_be_reused_as_winner_validation_capability() {
    let v = verified(view());
    let mut f = facts(&v, 0);
    f.purpose = Purpose::WinnerValidation;
    assert!(v.check(&f, v.body.not_before_ns + 1).is_err());
    let d = dir();
    let mut j = Journal::open(d.path(), uid(), &v).unwrap();
    let f = facts(&v, 0);
    let r = j.reserve(&v, &f, v.body.not_before_ns + 1).unwrap();
    let epoch = Arc::new(AtomicU64::new(1));
    let p = Permit {
        view: Arc::new(v),
        facts: f,
        reservation: r,
        epoch: epoch.clone(),
        expected_epoch: 1,
        unavailable: Arc::new(AtomicBool::new(false)),
    };
    assert!(p.progress().is_ok());
    epoch.store(2, Ordering::Release);
    assert!(p.progress().is_err());
}

#[test]
fn same_purpose_payload_cannot_redirect_a_selected_operation_id() {
    let mut v = view();
    let mut next = v.permissions[0].clone();
    next.operation_nonce = "ab".repeat(32);
    next.operation_id = operation_id(
        &v.context,
        &next.purpose,
        &next.operation_nonce,
        &next.payload_sha256,
    )
    .unwrap();
    assert_ne!(next.operation_id, v.permissions[0].operation_id);
    v.permissions.push(next);
    assert_eq!(validate(&v).err(), Some(PolicyError::Input));
}
#[test]
fn catalog_and_parent_reconcile_bind_distinct_exact_payloads() {
    let mut v = view();
    let mut p = v.permissions[0].clone();
    p.purpose = Purpose::ParentReconcile;
    p.search = None;
    p.payload_sha256 = v.context.actual_parent.clone();
    p.operation_id = operation_id(
        &v.context,
        &p.purpose,
        &p.operation_nonce,
        &p.payload_sha256,
    )
    .unwrap();
    v.permissions = vec![p];
    assert!(validate(&v).is_ok());
    v.permissions[0].payload_sha256 = "fe".repeat(32);
    assert!(validate(&v).is_err());
}
#[test]
fn journal_namespace_rejects_same_registry_with_different_external_keys_or_source() {
    let d = dir();
    let v = verified(view());
    let j = Journal::open(d.path(), uid(), &v).unwrap();
    drop(j);
    let mut changed = verified(view());
    changed.registry_key = "fe".repeat(32);
    assert!(Journal::open(d.path(), uid(), &changed).is_err());
    let mut changed = verified(view());
    changed.body.context.source_commit = "fe".repeat(20);
    assert!(Journal::open(d.path(), uid(), &changed).is_err());
}

#[test]
fn changing_declared_class_does_not_reset_one_task_reservations() {
    let d = dir();
    let mut v = view();
    v.limits.operations = 1;
    let old = verified(v);
    let mut j = Journal::open(d.path(), uid(), &old).unwrap();
    j.reserve(&old, &facts(&old, 0), old.body.not_before_ns + 1)
        .unwrap();
    let mut next = old.body.clone();
    next.registry_sequence = 2;
    next.registry_previous_digest = Some(old.body.registry_digest.clone());
    next.registry_digest = "cd".repeat(32);
    next.instance_class = "dense".into();
    next.permissions[0].operation_nonce = "ef".repeat(32);
    next.permissions[0].operation_id = operation_id(
        &next.context,
        &next.permissions[0].purpose,
        &next.permissions[0].operation_nonce,
        &next.permissions[0].payload_sha256,
    )
    .unwrap();
    let next = verified(next);
    j.advance(&next).unwrap();
    assert_eq!(
        j.reserve(&next, &facts(&next, 0), next.body.not_before_ns + 1)
            .err(),
        Some(PolicyError::Budget)
    );
}
#[test]
fn changing_task_does_not_reset_one_declared_class_reservations() {
    let d = dir();
    let mut v = view();
    v.limits.operations = 1;
    let old = verified(v);
    let mut j = Journal::open(d.path(), uid(), &old).unwrap();
    j.reserve(&old, &facts(&old, 0), old.body.not_before_ns + 1)
        .unwrap();
    let mut next = old.body.clone();
    next.registry_sequence = 2;
    next.registry_previous_digest = Some(old.body.registry_digest.clone());
    next.registry_digest = "cd".repeat(32);
    next.task.native_task = "ef".repeat(32);
    next.permissions[0].operation_nonce = "ab".repeat(32);
    next.permissions[0].operation_id = operation_id(
        &next.context,
        &next.permissions[0].purpose,
        &next.permissions[0].operation_nonce,
        &next.permissions[0].payload_sha256,
    )
    .unwrap();
    let next = verified(next);
    j.advance(&next).unwrap();
    assert_eq!(
        j.reserve(&next, &facts(&next, 0), next.body.not_before_ns + 1)
            .err(),
        Some(PolicyError::Budget)
    );
}
#[test]
fn complete_declared_task_binding_changes_on_lease_matrix_or_class() {
    let v = view();
    let binding = task_binding_sha256(&v).unwrap();
    let mut changed = v.clone();
    changed.task.lease_sha256 = "ab".repeat(32);
    assert_ne!(binding, task_binding_sha256(&changed).unwrap());
    let mut changed = v.clone();
    changed.task.a_sha256 = "ab".repeat(32);
    assert_ne!(binding, task_binding_sha256(&changed).unwrap());
    let mut changed = v.clone();
    changed.instance_class = "dense".into();
    assert_ne!(binding, task_binding_sha256(&changed).unwrap());
    let mut changed = v.clone();
    changed.allowed_task_commands = vec!["ab".repeat(32)];
    assert_ne!(binding, task_binding_sha256(&changed).unwrap());
}
#[test]
fn full_signed_command_bytes_need_both_allowlist_and_ordered_batch_binding() {
    let mut v = view();
    let first = vec![1u8; 159];
    let second = vec![2u8; 159];
    assert!(check_allowed_transactions(&v, std::slice::from_ref(&first)).is_err());
    v.allowed_task_commands = vec![sha(&first)];
    assert!(check_allowed_transactions(&v, std::slice::from_ref(&first)).is_ok());
    assert!(check_allowed_transactions(&v, std::slice::from_ref(&second)).is_err());
    let mut changed = first.clone();
    changed[158] ^= 1;
    assert!(check_allowed_transactions(&v, &[changed]).is_err());
    assert_ne!(
        transactions_sha256(&[first.clone(), second.clone()]).unwrap(),
        transactions_sha256(&[second, first]).unwrap()
    );
}
#[test]
fn outside_signing_bytes_require_new_role_and_valid_complete_body() {
    let v = view();
    assert_ne!(
        task_view_signing_bytes(&v, 1).unwrap(),
        task_view_signing_bytes(&v, 2).unwrap()
    );
    assert!(task_view_signing_bytes(&v, 0).is_err());
    let mut wrong = v;
    wrong.task.field_modulus = 2013265921;
    assert!(task_view_signing_bytes(&wrong, 1).is_err());
}
#[test]
fn held_fault_sink_survives_open_failure_and_unfinished_operation_unwind() {
    let d = dir();
    let v = verified(view());
    let journal = Journal::open(d.path(), uid(), &v).unwrap();
    let unavailable = Arc::new(AtomicBool::new(false));
    let fault = journal.unfinished_fault(unavailable.clone()).unwrap();
    drop(journal);
    drop(fault);
    assert!(unavailable.load(Ordering::Acquire));
    assert!(d.path().join("unavailable.json").is_file());
    assert!(Journal::open(d.path(), uid(), &v).is_err());
    let other = dir();
    let journal = Journal::open(other.path(), uid(), &v).unwrap();
    let unavailable = Arc::new(AtomicBool::new(false));
    let fault = journal.unfinished_fault(unavailable.clone()).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _fault = fault;
            panic!("expected source fault-sink mechanism");
        }))
        .is_err()
    );
    assert!(unavailable.load(Ordering::Acquire));
    drop(journal);
    assert!(Journal::open(other.path(), uid(), &v).is_err());
}
