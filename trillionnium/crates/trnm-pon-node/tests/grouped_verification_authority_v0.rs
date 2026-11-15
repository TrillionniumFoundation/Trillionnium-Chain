//! Closed-owner controls. All keys and material are public research fixtures;
//! two receiver keys do not establish two independent operators or real demand.
use std::{cell::Cell, path::Path};
use trnm_crypto_primitives::{
    pon_grouped_fresh_seal_v0 as seal, pon_routed_int257_grouped as grouped, public_key_hex,
    sign_hex, signing_key_from_hex,
};
use trnm_pon_node::{
    grouped_fresh_admission_v0 as admission, grouped_verification_authority_v0::*, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Hash};

const NOW: u64 = 1_500_000_000;
fn seed(index: u64) -> String {
    hex::encode(hash(b"DEV-ONLY-GROUPED-OWNER-KEY", &[&index.to_be_bytes()]))
}
fn public(index: u64) -> Hash {
    hex::decode(public_key_hex(&signing_key_from_hex(&seed(index)).unwrap()))
        .unwrap()
        .try_into()
        .unwrap()
}
fn signature(index: u64, message: &[u8]) -> Vec<u8> {
    hex::decode(sign_hex(
        &signing_key_from_hex(&seed(index)).unwrap(),
        message,
    ))
    .unwrap()
}
fn material() -> (grouped::Model, Vec<grouped::Request>) {
    let matrix = |salt: usize| {
        std::array::from_fn(|r| std::array::from_fn(|k| ((r * 13 + k * 7 + salt) % 9) as i32 - 4))
    };
    let model = grouped::Model {
        version: [18; 32],
        base: matrix(1),
        router: matrix(3),
        deltas: std::array::from_fn(|e| matrix(e + 5)),
    };
    let requests = (0..16)
        .map(|i| grouped::Request {
            id: hash(b"GROUPED-OWNER-REQUEST", &[&(i as u64).to_be_bytes()]),
            scope: [21; 32],
            arrival_ns: 1_000_000_000,
            deadline_ns: 2_000_000_000,
            x: std::array::from_fn(|k| {
                if k == 256 {
                    8
                } else {
                    ((i * 11 + k * 3) % 17) as i32 - 8
                }
            }),
        })
        .collect();
    (model, requests)
}
fn verified(
    node: &Node,
    model: &grouped::Model,
    requests: &[grouped::Request],
) -> admission::VerifiedAdmission {
    let prepared = grouped::PreparedModel::new(model.clone()).unwrap();
    let intent = admission::CapsuleIntent {
        registry_id: [1; 32],
        registry_digest: [2; 32],
        previous_registry_digest: [0; 32],
        demand_id: [3; 32],
        source_record: [4; 32],
        authorization_scope: requests[0].scope,
        withdrawal_head: [6; 32],
        model_commitment: prepared.commitment(),
        request_precommitment: request_precommitment(&prepared, requests).unwrap(),
        batch_id: [9; 32],
        transactions_commitment: [10; 32],
        payee: [11; 32],
        operation_id: [12; 32],
        registry_sequence: 1,
        model_generation: 1,
        timestamp_ms: 1500,
        not_before_ns: 1_000_000_000,
        expires_ns: 2_000_000_000,
        available_until_ns: 3_000_000_000,
        nonce_first: 1,
        nonce_count: 16,
    };
    let body = admission::CapsuleBody::from_node(node, intent).unwrap();
    let raw = admission::signed_capsule(
        &body,
        signature(
            40,
            &admission::signing_message(&body, admission::SigningRole::Requester),
        )
        .try_into()
        .unwrap(),
        signature(
            41,
            &admission::signing_message(&body, admission::SigningRole::Source),
        )
        .try_into()
        .unwrap(),
    );
    let authority = admission::PinnedAuthority {
        requester_key: public(40),
        source_key: public(41),
        latest_sequence: 1,
        latest_digest: body.intent().registry_digest,
        expected_capsule_sha256: admission::sha256(&raw),
        expected: body,
    };
    admission::verify_capsule(&raw, &authority, node, NOW).unwrap()
}
struct Fixture {
    node: Node,
    relation: FrozenRelation,
    policy: BudgetPolicy,
}
fn fixture_at(path: &Path, limit: u64, per_candidate: u64) -> Fixture {
    let node = Node::open(
        &path.join("node.sqlite"),
        Settings::development(Some(1_700_000_000)).unwrap(),
        1,
    )
    .unwrap();
    let (model, requests) = material();
    let admission = verified(&node, &model, &requests);
    let relation = FrozenRelation::prepare(admission, model, requests, &node, NOW).unwrap();
    let policy = BudgetPolicy::new(
        public(75),
        [77; 32],
        1,
        limit,
        per_candidate,
        vec![public(73), public(74)],
        &relation,
    )
    .unwrap();
    Fixture {
        node,
        relation,
        policy,
    }
}
fn submission(f: &Fixture, receiver: u64, id: u64, nonce: u64, action: Action) -> Submission {
    let candidate = f.relation.candidate_for_nonce(nonce).unwrap();
    let claim = f.relation.canonical_claim(candidate).unwrap();
    let proof = seal::prove(
        f.relation.challenge(candidate).unwrap(),
        claim.statement_commitment,
    );
    let mut s = Submission {
        receiver: public(receiver),
        request_id: hash(b"GROUPED-OWNER-OP", &[&id.to_be_bytes()]),
        candidate,
        claim,
        proof,
        signature: vec![],
    };
    sign(&mut s, &f.policy, receiver, action);
    s
}
fn sign(s: &mut Submission, p: &BudgetPolicy, receiver: u64, action: Action) {
    s.signature = signature(receiver, &s.signing_message(p, action).unwrap());
}
fn run(a: &mut VerificationAuthority, s: &Submission, f: &Fixture) -> Result<SubmissionState> {
    a.execute(s, &f.relation, &f.node, || NOW, |_| true)
}
fn receipt(state: SubmissionState) -> Receipt {
    match state {
        SubmissionState::Complete {
            receipt,
            cached: false,
        } => *receipt,
        _ => panic!("new completed receipt expected"),
    }
}

#[test]
fn full_reference_and_seal_execute_inside_one_aggregate_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    let s = submission(&f, 73, 1, 1, Action::Execute);
    let count = Cell::new(0);
    let first = receipt(
        a.execute(
            &s,
            &f.relation,
            &f.node,
            || NOW,
            |_| {
                count.set(count.get() + 1);
                true
            },
        )
        .unwrap(),
    );
    assert!(matches!(
        first.outcome,
        Outcome::VerifiedHit | Outcome::VerifiedMiss
    ));
    assert_eq!(first.cost.full_cell_calls, 1);
    assert!(first.cost.full_cell_verified);
    assert_eq!(first.cost.seed_queries, 1);
    assert_eq!(first.cost.step_queries, 64);
    assert!(first.first_record);
    assert_eq!(first.chainwork_awarded, 0);
    assert_eq!(count.get(), 67);
    let retry = a
        .execute(
            &s,
            &f.relation,
            &f.node,
            || panic!("cached retry clock"),
            |_| panic!("cached retry replay"),
        )
        .unwrap();
    assert!(matches!(
        retry,
        SubmissionState::Complete { cached: true, .. }
    ));
    let replay_observation = retry.observation();
    assert_eq!(replay_observation["new_candidate_completion"], false);
    assert_eq!(replay_observation["cached_receipt_is_historical"], true);
    assert_eq!(
        replay_observation["cached_response_does_not_revalidate_context"],
        true
    );
    let snapshot = a.snapshot().unwrap();
    assert_eq!(snapshot["reserved"], 1);
    assert_eq!(snapshot["step_queries_known"], 64);
    let second = submission(&f, 74, 2, 1, Action::Execute);
    assert!(matches!(
        run(&mut a, &second, &f),
        Err(AuthorityError::CandidateClosed)
    ));
}

#[test]
fn bad_cell_and_bad_seal_burn_before_work_and_do_not_close_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let path = dir.path().join("owner.sqlite");
    let mut a = VerificationAuthority::create(&path, f.policy.clone()).unwrap();
    let mut cell = submission(&f, 73, 1, 1, Action::Execute);
    cell.claim.product.logits[0][0] += 1;
    sign(&mut cell, &f.policy, 73, Action::Execute);
    let first = receipt(
        a.execute(
            &cell,
            &f.relation,
            &f.node,
            || NOW,
            |p| {
                if p == Progress::Started {
                    let db = rusqlite::Connection::open_with_flags(
                        &path,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                    )
                    .unwrap();
                    let state: String = db
                        .query_row("SELECT state FROM submissions WHERE sequence=1", [], |r| {
                            r.get(0)
                        })
                        .unwrap();
                    assert_eq!(state, "started");
                }
                true
            },
        )
        .unwrap(),
    );
    assert_eq!(first.outcome, Outcome::RelationRejected);
    assert_eq!(first.cost.full_cell_calls, 1);
    assert!(!first.cost.full_cell_verified);
    assert_eq!(first.cost.step_queries, 0);
    let mut bad = submission(&f, 74, 2, 1, Action::Execute);
    bad.proof[133] ^= 1;
    sign(&mut bad, &f.policy, 74, Action::Execute);
    let second = receipt(run(&mut a, &bad, &f).unwrap());
    assert_eq!(second.outcome, Outcome::RelationRejected);
    assert!(second.cost.full_cell_verified);
    assert_eq!(second.cost.step_queries, 64);
    assert!(!second.first_record);
    let good = submission(&f, 73, 3, 1, Action::Execute);
    assert!(receipt(run(&mut a, &good, &f).unwrap()).first_record);
    assert_eq!(a.snapshot().unwrap()["reserved"], 3);
}

#[test]
fn two_receiver_identities_share_one_fixed_epoch_cap() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 5, 3);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    for i in 0..5 {
        let receiver = 73 + i % 2;
        let s = submission(&f, receiver, i + 1, 1 + i / 3, Action::Reserve);
        assert!(matches!(
            a.reserve(&s).unwrap(),
            SubmissionState::Reserved { .. }
        ));
    }
    let s = submission(&f, 74, 20, 3, Action::Execute);
    assert!(matches!(
        run(&mut a, &s, &f),
        Err(AuthorityError::EpochBudget)
    ));
    let snap = a.snapshot().unwrap();
    assert_eq!(snap["reserved"], 5);
    assert_eq!(snap["remaining"], 0);
    assert_eq!(
        snap["per_receiver_reservations"][hex::encode(public(73))],
        3
    );
    assert_eq!(
        snap["per_receiver_reservations"][hex::encode(public(74))],
        2
    );
    assert_eq!(snap["step_queries_known"], 0);
    assert_eq!(snap["epoch_step_query_upper"], 320);
}

#[test]
fn candidate_cap_unregistered_receivers_and_new_candidate_names_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 2);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    for id in 1..=2 {
        let s = submission(&f, 73, id, 1, Action::Reserve);
        a.reserve(&s).unwrap();
    }
    assert!(matches!(
        a.reserve(&submission(&f, 74, 3, 1, Action::Reserve)),
        Err(AuthorityError::CandidateBudget)
    ));
    let mut s = submission(&f, 73, 4, 2, Action::Execute);
    s.receiver = public(76);
    sign(&mut s, &f.policy, 76, Action::Execute);
    assert!(matches!(run(&mut a, &s, &f), Err(AuthorityError::Receiver)));
    s.receiver = public(73);
    s.candidate = [99; 32];
    sign(&mut s, &f.policy, 73, Action::Execute);
    assert!(matches!(
        run(&mut a, &s, &f),
        Err(AuthorityError::Candidate)
    ));
    assert_eq!(a.snapshot().unwrap()["reserved"], 2);
}

#[test]
fn action_receiver_fingerprint_and_policy_are_signed() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    let mut s = submission(&f, 73, 1, 1, Action::Reserve);
    a.reserve(&s).unwrap();
    a.reserve(&s).unwrap();
    assert_eq!(a.snapshot().unwrap()["reserved"], 1);
    assert!(matches!(
        run(&mut a, &s, &f),
        Err(AuthorityError::Signature)
    ));
    s.signature = signature(74, &s.signing_message(&f.policy, Action::Execute).unwrap());
    assert!(matches!(
        run(&mut a, &s, &f),
        Err(AuthorityError::Signature)
    ));
    sign(&mut s, &f.policy, 73, Action::Execute);
    s.proof[133] ^= 1;
    assert!(matches!(
        run(&mut a, &s, &f),
        Err(AuthorityError::Signature)
    ));
    sign(&mut s, &f.policy, 73, Action::Execute);
    assert!(matches!(
        run(&mut a, &s, &f),
        Err(AuthorityError::IdempotencyConflict)
    ));
    s.proof[133] ^= 1;
    sign(&mut s, &f.policy, 73, Action::Execute);
    run(&mut a, &s, &f).unwrap();
    assert_eq!(a.snapshot().unwrap()["reserved"], 1);
}

#[test]
fn cancellation_after_seventeen_steps_is_charged_and_cached_on_retry() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    let s = submission(&f, 73, 1, 1, Action::Execute);
    let r = receipt(
        a.execute(
            &s,
            &f.relation,
            &f.node,
            || NOW,
            |p| p != Progress::Step(17),
        )
        .unwrap(),
    );
    assert_eq!(r.outcome, Outcome::Cancelled);
    assert_eq!(r.cost.step_queries, 17);
    assert_eq!(r.cost.seed_queries, 1);
    assert_eq!(r.endpoint, None);
    assert!(!r.first_record);
    let retry = a
        .execute(
            &s,
            &f.relation,
            &f.node,
            || panic!("retry clock"),
            |_| panic!("retry work"),
        )
        .unwrap();
    assert!(matches!(
        retry,
        SubmissionState::Complete { cached: true, .. }
    ));
    assert_eq!(a.snapshot().unwrap()["step_queries_known"], 17);
    let again = submission(&f, 74, 2, 1, Action::Execute);
    run(&mut a, &again, &f).unwrap();
    assert_eq!(a.snapshot().unwrap()["step_queries_known"], 81);
    assert_eq!(a.snapshot().unwrap()["reserved"], 2);
}

#[test]
fn reopen_keeps_completed_and_abandoned_reservations_without_refund() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 4, 3);
    let path = dir.path().join("owner.sqlite");
    let mut a = VerificationAuthority::create(&path, f.policy.clone()).unwrap();
    let first = submission(&f, 73, 1, 1, Action::Reserve);
    a.reserve(&first).unwrap();
    let abandoned = submission(&f, 74, 2, 2, Action::Reserve);
    a.reserve(&abandoned).unwrap();
    let done = submission(&f, 73, 3, 3, Action::Execute);
    run(&mut a, &done, &f).unwrap();
    drop(a);
    let mut a = VerificationAuthority::open(&path, f.policy.clone()).unwrap();
    assert_eq!(a.snapshot().unwrap()["reserved"], 3);
    assert_eq!(a.snapshot().unwrap()["remaining"], 1);
    assert!(matches!(
        run(&mut a, &done, &f).unwrap(),
        SubmissionState::Complete { cached: true, .. }
    ));
    let mut first = first;
    sign(&mut first, &f.policy, 73, Action::Execute);
    run(&mut a, &first, &f).unwrap();
    assert_eq!(a.snapshot().unwrap()["reserved"], 3);
    let snapshot = a.snapshot().unwrap();
    assert_eq!(snapshot["states"]["reserved"], 1);
}

#[test]
fn one_owner_lock_and_create_only_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let path = dir.path().join("owner.sqlite");
    let a = VerificationAuthority::create(&path, f.policy.clone()).unwrap();
    assert!(matches!(
        VerificationAuthority::open(&path, f.policy.clone()),
        Err(AuthorityError::JournalBusy)
    ));
    assert!(matches!(
        VerificationAuthority::create(&path, f.policy.clone()),
        Err(AuthorityError::Journal)
    ));
    drop(a);
    VerificationAuthority::open(&path, f.policy).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_and_hardlink_owner_files_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let path = dir.path().join("owner.sqlite");
    drop(VerificationAuthority::create(&path, f.policy.clone()).unwrap());
    let link = dir.path().join("link.sqlite");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(matches!(
        VerificationAuthority::open(&link, f.policy.clone()),
        Err(AuthorityError::Journal)
    ));
    let hard = dir.path().join("hard.sqlite");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(matches!(
        VerificationAuthority::open(&path, f.policy.clone()),
        Err(AuthorityError::Journal)
    ));
    assert!(matches!(
        VerificationAuthority::open(&hard, f.policy),
        Err(AuthorityError::Journal)
    ));
}

#[test]
fn changed_epoch_and_deleted_rows_fail_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let path = dir.path().join("owner.sqlite");
    let mut a = VerificationAuthority::create(&path, f.policy.clone()).unwrap();
    a.reserve(&submission(&f, 73, 1, 1, Action::Reserve))
        .unwrap();
    drop(a);
    let other = BudgetPolicy::new(
        public(75),
        [78; 32],
        2,
        8,
        4,
        vec![public(73), public(74)],
        &f.relation,
    )
    .unwrap();
    assert!(matches!(
        VerificationAuthority::open(&path, other),
        Err(AuthorityError::Policy)
    ));
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("DELETE FROM submissions", []).unwrap();
    drop(db);
    assert!(matches!(
        VerificationAuthority::open(&path, f.policy),
        Err(AuthorityError::JournalCorrupt)
    ));
}

#[test]
fn successful_miss_also_closes_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 32, 4);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    let target = f.node.expected_target(f.node.active().unwrap().0).unwrap();
    let (nonce, s) = (1..=16)
        .find_map(|nonce| {
            let s = submission(&f, 73, nonce, nonce, Action::Execute);
            (s.proof[102..] > target[..]).then_some((nonce, s))
        })
        .expect("deterministic fixture has a miss");
    let r = receipt(run(&mut a, &s, &f).unwrap());
    assert_eq!(r.outcome, Outcome::VerifiedMiss);
    assert!(r.first_record);
    let other = submission(&f, 74, 100, nonce, Action::Execute);
    assert!(matches!(
        run(&mut a, &other, &f),
        Err(AuthorityError::CandidateClosed)
    ));
}

#[test]
fn already_reserved_second_receiver_cannot_replay_closed_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    let mut first = submission(&f, 73, 1, 1, Action::Reserve);
    let mut second = submission(&f, 74, 2, 1, Action::Reserve);
    a.reserve(&first).unwrap();
    a.reserve(&second).unwrap();
    sign(&mut first, &f.policy, 73, Action::Execute);
    sign(&mut second, &f.policy, 74, Action::Execute);
    run(&mut a, &first, &f).unwrap();
    assert!(matches!(
        run(&mut a, &second, &f),
        Err(AuthorityError::CandidateClosed)
    ));
    let snapshot = a.snapshot().unwrap();
    assert_eq!(snapshot["reserved"], 2);
    assert_eq!(snapshot["step_queries_known"], 64);
}

#[test]
fn material_pins_and_expired_context_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let (mut model, requests) = material();
    let admission = verified(&f.node, &model, &requests);
    model.base[0][0] += 1;
    assert!(matches!(
        FrozenRelation::prepare(admission, model, requests, &f.node, NOW),
        Err(AuthorityError::MaterialBinding)
    ));
    let (model, mut requests) = material();
    let admission = verified(&f.node, &model, &requests);
    requests[0].x[0] += 1;
    assert!(matches!(
        FrozenRelation::prepare(admission, model, requests, &f.node, NOW),
        Err(AuthorityError::MaterialBinding)
    ));
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    let s = submission(&f, 73, 1, 1, Action::Execute);
    let r = receipt(
        a.execute(&s, &f.relation, &f.node, || 2_000_000_000, |_| true)
            .unwrap(),
    );
    assert_eq!(r.outcome, Outcome::ContextRejected);
    assert_eq!(r.cost.full_cell_calls, 0);
    assert_eq!(a.snapshot().unwrap()["reserved"], 1);
}

#[test]
fn clock_rollback_after_replay_burns_but_never_records_success() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let mut a =
        VerificationAuthority::create(&dir.path().join("owner.sqlite"), f.policy.clone()).unwrap();
    let s = submission(&f, 73, 1, 1, Action::Execute);
    let calls = Cell::new(0);
    let r = receipt(
        a.execute(
            &s,
            &f.relation,
            &f.node,
            || {
                let n = calls.get();
                calls.set(n + 1);
                NOW - n
            },
            |_| true,
        )
        .unwrap(),
    );
    assert_eq!(r.outcome, Outcome::ContextRejected);
    assert_eq!(r.cost.step_queries, 64);
    assert!(!r.first_record);
}

#[test]
fn abrupt_process_exit_leaves_started_unknown_and_no_free_retry() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 8, 4);
    let path = dir.path().join("owner.sqlite");
    drop(VerificationAuthority::create(&path, f.policy.clone()).unwrap());
    drop(f);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_exit_helper", "--nocapture"])
        .env("TRNM_GROUPED_OWNER_CRASH_DIRECTORY", dir.path())
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(86),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let f = fixture_at(dir.path(), 8, 4);
    let mut a = VerificationAuthority::open(&path, f.policy.clone()).unwrap();
    let s = submission(&f, 73, 1, 1, Action::Execute);
    let state = a
        .execute(
            &s,
            &f.relation,
            &f.node,
            || panic!("unknown retry clock"),
            |_| panic!("unknown retry work"),
        )
        .unwrap();
    assert!(matches!(state, SubmissionState::Unknown { sequence: 1 }));
    let snapshot = a.snapshot().unwrap();
    assert_eq!(snapshot["reserved"], 1);
    assert_eq!(snapshot["states"]["unknown"], 1);
    assert_eq!(snapshot["step_queries_known"], 0);
    assert_eq!(snapshot["step_queries_unknown_upper"], 64);
    assert_eq!(snapshot["full_cell_calls_unknown_upper"], 1);
    let next = submission(&f, 74, 2, 1, Action::Execute);
    run(&mut a, &next, &f).unwrap();
    assert_eq!(a.snapshot().unwrap()["reserved"], 2);
}

#[test]
fn process_exit_helper() {
    let Some(path) = std::env::var_os("TRNM_GROUPED_OWNER_CRASH_DIRECTORY") else {
        return;
    };
    let path = Path::new(&path);
    let f = fixture_at(path, 8, 4);
    let mut a = VerificationAuthority::open(&path.join("owner.sqlite"), f.policy.clone()).unwrap();
    let s = submission(&f, 73, 1, 1, Action::Execute);
    let _ = a.execute(
        &s,
        &f.relation,
        &f.node,
        || NOW,
        |p| {
            if p == Progress::Started {
                std::process::exit(86)
            }
            true
        },
    );
    panic!("fixture must exit immediately after durable start")
}

#[test]
fn correctly_resigned_foreign_request_scope_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(
        &dir.path().join("node.sqlite"),
        Settings::development(Some(1_700_000_000)).unwrap(),
        1,
    )
    .unwrap();
    let (model, mut requests) = material();
    requests[1].scope = [22; 32];
    // The helper recomputes the commitment and verifies both fresh signatures.
    // Rejection therefore cannot be explained by a stale hash or bad signature.
    let verified = verified(&node, &model, &requests);
    assert!(matches!(
        FrozenRelation::prepare(verified, model, requests, &node, NOW),
        Err(AuthorityError::AuthorizationScope)
    ));
}

#[test]
fn two_owner_files_with_the_same_policy_are_a_global_cap_counterexample() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture_at(dir.path(), 1, 1);
    let mut first =
        VerificationAuthority::create(&dir.path().join("first.sqlite"), f.policy.clone()).unwrap();
    let mut second =
        VerificationAuthority::create(&dir.path().join("second.sqlite"), f.policy.clone()).unwrap();
    let s = submission(&f, 73, 1, 1, Action::Execute);
    assert!(receipt(run(&mut first, &s, &f).unwrap()).first_record);
    assert!(receipt(run(&mut second, &s, &f).unwrap()).first_record);
    assert_eq!(first.snapshot().unwrap()["reserved"], 1);
    assert_eq!(second.snapshot().unwrap()["reserved"], 1);
    assert_eq!(f.policy.observation()["anti_clone_or_rollback"], false);
    // The same digest does not certify a unique live owner. A transfer claim
    // needs external enforcement of the sole-owner/closed-topology assumption.
    assert_eq!(
        first.snapshot().unwrap()["policy"]["policy"],
        second.snapshot().unwrap()["policy"]["policy"]
    );
}
