//! Actual enabled native operation; no injected VerifiedView, Permit or empty
//! catalog. The signed fixture authority is local and synthetic, not external
//! Registry2/production authorization or a real-model quality experiment.
use super::*;
use crate::operator_continuous_recipient as recipient;
use serde_json::{json, Value};
use std::time::Instant;
#[path = "history_import_fixture.rs"]
mod fixture;
use fixture::{Fixture, ViewInput};

fn first(f: &Fixture) -> ViewInput {
    f.view(
        1,
        None,
        history::Anchor::empty(),
        (f.settings.genesis(), 0),
        1,
        true,
    )
}
fn open(f: &Fixture, view: &mut ViewInput, workers: usize) -> Node {
    Node::open_operator_continuous_checkpoint_with_workers(
        &f.store(),
        view.inputs.take().unwrap(),
        Instant::now() + Duration::from_secs(30),
        workers,
    )
    .unwrap()
    .0
}
fn head(node: &Node) -> history::Anchor {
    serde_json::from_value(node.continuous_journal_head().unwrap()).unwrap()
}
fn checked(step: &OwnedHistoryStepResult, workers: u64) {
    assert!(step.accounting_record_persisted);
    assert!(!step.accounting_fault_persistence_failed);
    assert!(!step.cpu.accounting_unavailable);
    assert!(!step.cpu.live_refused);
    assert_eq!(step.cpu.spawned_workers, workers);
    assert_eq!(step.cpu.started_workers, workers);
    assert_eq!(step.cpu.finished_workers, workers);
    assert_eq!(step.cpu.known_workers, workers);
    assert_eq!(
        step.cpu.total_cpu_ns,
        Some(step.cpu.owner_cpu_ns.unwrap() + step.cpu.scoped_worker_cpu_ns.unwrap())
    );
    assert_eq!(
        step.cpu.total_cpu_ns,
        Some(step.cpu.live_paid_cpu_ns.unwrap() + step.cpu.residual_cpu_ns.unwrap())
    );
    assert!(step.cpu.total_cpu_ns.unwrap() > 0);
    if workers > 0 {
        assert!(step.cpu.scoped_worker_cpu_ns.unwrap() > 0);
    }
}
fn same_receipt(saved: &Value, read: &Value) {
    for field in [
        "scope",
        "linked_operations",
        "started_record_sha256",
        "settled_record_sha256",
        "owner_cpu_ns",
        "scoped_worker_cpu_ns",
        "total_cpu_ns",
        "live_paid_cpu_ns",
        "residual_cpu_ns",
        "spawned",
        "started",
        "finished",
        "known",
    ] {
        assert_eq!(saved[field], read[field], "cold durable field {field}");
    }
}
fn assert_replay_keeps_journal(node: &Node, old: &ViewInput, settlement: &OwnedHistoryStepResult) {
    let owner = node.continuous_owner.as_ref().unwrap();
    let verified = recipient::authenticate(
        &old.signed_validation,
        &old.validation_authority,
        crate::operator_task_policy::now_ns().unwrap(),
    )
    .unwrap();
    let mut journal = owner.journal.lock().unwrap();
    let before = journal.anchor();
    let usage = journal.usage_digest().unwrap();
    assert_eq!(
        journal.reserve_allocation(&verified),
        Err(crate::operator_task_policy::PolicyError::Replay)
    );
    // Public replay is refused before another interval starts or settles. A
    // direct second raw settle_cpu deliberately faults the original journal;
    // that distinct terminal-invariant test must not poison this reopen test.
    let retained = journal.scope_receipt(&scope_id(&old.validation)).unwrap();
    assert_eq!(Some(retained.total_cpu_ns), settlement.cpu.total_cpu_ns);
    assert_eq!(journal.anchor(), before);
    assert_eq!(journal.usage_digest().unwrap(), usage);
}

#[test]
fn signed_history_single_successor_runs_two_children_and_cold_reopen_preserves_once_only_settlement(
) {
    let f = Fixture::new();
    let mut view = first(&f);
    let mut node = open(&f, &mut view, 2);
    assert!(
        node.continuous_startup_receipt().unwrap()["total_cpu_ns"]
            .as_u64()
            .unwrap()
            > 0
    );
    let points = AtomicU64::new(0);
    let result = node
        .receive_owned_history_operation(f.request(&view), &|_| {
            points.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
        .unwrap();
    assert!(
        result.completed,
        "{}",
        serde_json::to_string(&result).unwrap()
    );
    assert!(!result.public_network_ready);
    checked(&result.validation, 2);
    checked(result.activation.as_ref().unwrap(), 0);
    assert!(points.load(Ordering::Acquire) > 10);
    let active = node.active().unwrap();
    assert_eq!(active, (f.packet.id().unwrap(), 1));
    let validation = node.continuous_scope_receipt(&view.validation).unwrap();
    let activation = node.continuous_scope_receipt(&view.activation).unwrap();
    let before = head(&node);
    let process = node.continuous_process_cpu_snapshot().unwrap();
    assert_eq!(process["claims"], 4);
    assert_eq!(process["pending_scopes"], 0);
    assert!(node
        .receive_owned_history_operation(f.request(&view), &|_| Ok(()))
        .is_err());
    assert_eq!(head(&node), before);
    assert_replay_keeps_journal(&node, &view, &result.validation);
    node.close_continuous_checkpoint().unwrap();
    let closed = head(&node);
    drop(node);
    let mut next = f.view(2, Some(view.view_digest.clone()), closed, active, 5, false);
    let reopened = open(&f, &mut next, 2);
    assert_eq!(reopened.active().unwrap(), active);
    same_receipt(
        &validation,
        &reopened.continuous_scope_receipt(&view.validation).unwrap(),
    );
    same_receipt(
        &activation,
        &reopened.continuous_scope_receipt(&view.activation).unwrap(),
    );
    assert_replay_keeps_journal(&reopened, &view, &result.validation);
    let flow = reopened
        .continuous_cpu_domain()
        .unwrap()
        .observe_actual_flow()
        .unwrap()
        .unwrap();
    assert_eq!(flow.initial_credit_ns, 0); // real refill, never a restart burst
    let process_after = reopened.continuous_process_cpu_snapshot().unwrap();
    assert_eq!(process_after["claims"], 6);
    assert_eq!(process_after["pending_scopes"], 0);
    eprintln!(
        "HISTORY_NATIVE_ENABLED {}",
        json!({"result":result,"validation_receipt":validation,
        "activation_receipt":activation,"reopened_process":process_after,"reopened_initial_credit_ns":flow.initial_credit_ns,
        "actual_producer":f.native_receipt,"actual_reference":f.reference_receipt,
        "public_host_enabled_path_executed":false,"external_registry2_admission":false})
    );
    reopened.close_continuous_checkpoint().unwrap();
}

#[test]
fn signed_history_actual_child_cancellation_joins_settles_reopens_and_needs_new_signed_claim() {
    let f = Fixture::new();
    let mut view = first(&f);
    let mut node = open(&f, &mut view, 2);
    let cancel = node.continuous_cancellation_handle().unwrap();
    let owner_thread = std::thread::current().id();
    let child_cancelled = AtomicBool::new(false);
    let result = node
        .receive_owned_history_operation(f.request(&view), &|point| {
            if point
                == OwnedHistoryProgress::Execution(
                    trnm_mvcc_fee::pon_executor::ExecutionProgress::AfterPrepare { index: 0 },
                )
            {
                assert_ne!(std::thread::current().id(), owner_thread);
                assert!(cancel.cancel().unwrap());
                child_cancelled.store(true, Ordering::Release);
            }
            Ok(())
        })
        .unwrap();
    assert!(child_cancelled.load(Ordering::Acquire));
    assert!(!result.completed);
    assert!(result.validation.native_id.is_none());
    assert!(result
        .validation
        .native_error
        .as_deref()
        .unwrap()
        .contains("CpuUnknown"));
    assert!(result.activation.is_none());
    checked(&result.validation, 2);
    assert_eq!(node.active().unwrap(), (f.settings.genesis(), 0));
    assert!(node.packet(f.packet.id().unwrap()).is_err());
    assert_eq!(
        node.continuous_cpu_domain()
            .unwrap()
            .observe()
            .unwrap()
            .in_flight,
        0
    );
    let receipt = node.continuous_scope_receipt(&view.validation).unwrap();
    let before = head(&node);
    assert!(!cancel.cancel().unwrap());
    assert!(node
        .receive_owned_history_operation(f.request(&view), &|_| Ok(()))
        .is_err());
    assert_eq!(head(&node), before);
    assert_replay_keeps_journal(&node, &view, &result.validation);
    node.close_continuous_checkpoint().unwrap();
    let closed = head(&node);
    drop(node);
    let mut next = f.view(
        2,
        Some(view.view_digest.clone()),
        closed,
        (f.settings.genesis(), 0),
        5,
        true,
    );
    let mut reopened = open(&f, &mut next, 2);
    same_receipt(
        &receipt,
        &reopened.continuous_scope_receipt(&view.validation).unwrap(),
    );
    assert_replay_keeps_journal(&reopened, &view, &result.validation);
    let success = reopened
        .receive_owned_history_operation(f.request(&next), &|_| Ok(()))
        .unwrap();
    assert!(
        success.completed,
        "{}",
        serde_json::to_string(&success).unwrap()
    );
    checked(&success.validation, 2);
    assert_eq!(
        reopened.continuous_process_cpu_snapshot().unwrap()["claims"],
        7
    );
    eprintln!(
        "HISTORY_NATIVE_CHILD_CANCEL {}",
        json!({"cancelled_result":result,"retained_receipt":receipt,
        "new_signed_claim_result":success,"reopened_process":reopened.continuous_process_cpu_snapshot().unwrap(),
        "new_budget_installed":false,"refund":false})
    );
    reopened.close_continuous_checkpoint().unwrap();
}

#[test]
fn signed_history_internal_activation_cancel_retains_admission_and_requires_fresh_view_for_retry() {
    let f = Fixture::new();
    let mut view = first(&f);
    let mut node = open(&f, &mut view, 2);
    let cancel = node.continuous_cancellation_handle().unwrap();
    let calls = AtomicU64::new(0);
    let result = node
        .receive_owned_history_operation(f.request(&view), &|point| {
            if point == OwnedHistoryProgress::Activation
                && calls.fetch_add(1, Ordering::AcqRel) == 11
            {
                assert!(cancel.cancel().unwrap());
            }
            Ok(())
        })
        .unwrap();
    assert!(calls.load(Ordering::Acquire) >= 12);
    assert!(!result.completed);
    checked(&result.validation, 2);
    assert_eq!(result.validation.native_id, Some(f.packet.id().unwrap()));
    let activation = result.activation.as_ref().unwrap();
    checked(activation, 0);
    assert!(activation
        .native_error
        .as_deref()
        .unwrap()
        .contains("CpuUnknown"));
    assert_eq!(node.active().unwrap(), (f.settings.genesis(), 0));
    assert_eq!(
        node.packet(f.packet.id().unwrap())
            .unwrap()
            .encode()
            .unwrap(),
        f.packet.encode().unwrap()
    );
    let settled = node.continuous_scope_receipt(&view.activation).unwrap();
    let prior_validation = node.continuous_scope_receipt(&view.validation).unwrap();
    node.close_continuous_checkpoint().unwrap();
    let closed = head(&node);
    drop(node);
    eprintln!(
        "HISTORY_NATIVE_BEFORE_ACTIVATION_COLD_REOPEN {}",
        json!({
        "cancelled_result":result,"settled_activation":settled,"closed_head":closed})
    );
    let mut next = f.view(
        2,
        Some(view.view_digest.clone()),
        closed,
        (f.settings.genesis(), 0),
        5,
        true,
    );
    let selection = HistoryRecoverySelection {
        schema: "restricted-continuous-single-successor-recovery-v1".into(),
        target: hex::encode(f.packet.id().unwrap()),
        prior_validation_operation_id: view.validation.clone(),
        prior_validation_settled_record_sha256: prior_validation["settled_record_sha256"]
            .as_str()
            .unwrap()
            .into(),
        validation_operation_id: next.validation.clone(),
        activation_operation_id: next.activation.clone(),
    };
    let mut held = Node::open_operator_continuous_history_recovery(
        &f.store(),
        next.inputs.take().unwrap(),
        Instant::now() + Duration::from_secs(30),
        2,
        selection.clone(),
    )
    .unwrap();
    assert_eq!(held.active().unwrap(), (f.settings.genesis(), 0));
    same_receipt(&settled, &held.scope_receipt(&view.activation).unwrap());
    same_receipt(
        &prior_validation,
        &held.scope_receipt(&view.validation).unwrap(),
    );
    let before = head(&held.node);
    let owner = held.node.continuous_owner.as_ref().unwrap().clone();
    assert!(owner
        .permission("startup-catalog", &f.binding.task.full_material_catalog)
        .err()
        .unwrap()
        .to_string()
        .contains("RECOVERY_SELECTED_OPERATION_ONLY"));
    let mut unrelated = f.view(
        3,
        Some(next.view_digest.clone()),
        before.clone(),
        held.active().unwrap(),
        9,
        true,
    );
    assert!(held
        .node
        .refresh_operator_continuous_view(unrelated.inputs.take().unwrap())
        .unwrap_err()
        .to_string()
        .contains("RECOVERY_INCOMPLETE"));
    assert!(held
        .node
        .begin_remote_history_cpu_epoch()
        .unwrap_err()
        .to_string()
        .contains("HISTORY_DURABLE_REQUIRED"));
    for field in [
        "target",
        "old-operation",
        "old-settlement",
        "fresh-operation",
    ] {
        let mut wrong = selection.clone();
        match field {
            "target" => wrong.target = hex::encode(f.settings.genesis()),
            "old-operation" => wrong.prior_validation_operation_id = view.activation.clone(),
            "old-settlement" => wrong.prior_validation_settled_record_sha256 = "00".repeat(32),
            "fresh-operation" => wrong.validation_operation_id = view.validation.clone(),
            _ => unreachable!(),
        }
        assert!(
            held.node
                .continuous_authorized_history_recovery(
                    &owner,
                    &wrong,
                    f.settings.genesis(),
                    0,
                    f.packet.id().unwrap()
                )
                .is_err(),
            "{field}"
        );
    }
    assert_eq!(head(&held.node), before);
    let success = held
        .resume_native_fixture(&f.page, fixture::CLOCK, &|_| Ok(()))
        .unwrap();
    assert!(
        success.completed,
        "{}",
        serde_json::to_string(&success).unwrap()
    );
    checked(&success.validation, 0); // already durable identical packet, no repeated M06
    let success = serde_json::to_value(success).unwrap();
    assert!(held
        .resume_native_fixture(&f.page, fixture::CLOCK, &|_| Ok(()))
        .err()
        .unwrap()
        .to_string()
        .contains("ALREADY_ATTEMPTED"));
    let (reopened, _, _) = held.into_ready().unwrap();
    assert_eq!(reopened.active().unwrap(), (f.packet.id().unwrap(), 1));
    eprintln!(
        "HISTORY_NATIVE_ACTIVATION_CANCEL {}",
        json!({"cancelled_result":result,
        "retained_activation":settled,"fresh_signed_retry":success,"rollback_of_admission":false})
    );
    reopened.close_continuous_checkpoint().unwrap();
}

#[test]
fn signed_history_refuses_unselected_or_malformed_input_without_free_decode_or_generic_fallback() {
    let f = Fixture::new();
    let mut view = first(&f);
    let mut node = open(&f, &mut view, 2);
    let before = head(&node);
    let mut request = f.request(&view);
    request.activation_operation_id = &view.validation;
    assert!(node
        .receive_owned_history_operation(request, &|_| Ok(()))
        .is_err());
    assert_eq!(head(&node), before);
    assert!(node
        .begin_remote_history_cpu_epoch()
        .unwrap_err()
        .to_string()
        .contains("OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED"));
    let request = OwnedHistoryRequest {
        raw_page: b"{invalid-json",
        ..f.request(&view)
    };
    let rejected = node
        .receive_owned_history_operation(request, &|_| Ok(()))
        .unwrap();
    checked(&rejected.validation, 0);
    assert!(rejected.validation.native_error.is_some());
    assert!(!rejected.completed);
    assert!(rejected.activation.is_none());
    assert_eq!(node.continuous_process_cpu_snapshot().unwrap()["claims"], 3);
    assert_eq!(node.active().unwrap(), (f.settings.genesis(), 0));
    let before = head(&node);
    assert!(node
        .receive_owned_history_operation(f.request(&view), &|_| Ok(()))
        .is_err());
    assert_eq!(head(&node), before);
    assert_replay_keeps_journal(&node, &view, &rejected.validation);
    eprintln!(
        "HISTORY_NATIVE_DECODE_REJECT {}",
        serde_json::to_string(&rejected).unwrap()
    );
    let old_cancel = node.continuous_cancellation_handle().unwrap();
    let mut next = f.view(
        2,
        Some(view.view_digest.clone()),
        head(&node),
        node.active().unwrap(),
        5,
        true,
    );
    node.refresh_operator_continuous_view(next.inputs.take().unwrap())
        .unwrap();
    assert!(!old_cancel.cancel().unwrap());
    assert!(node
        .continuous_cancellation_handle()
        .unwrap()
        .cancel()
        .unwrap());
    node.close_continuous_checkpoint().unwrap();
}

#[test]
fn signed_history_actual_sigkill_known_prefix_settles_once_and_new_process_resumes_exact_successor()
{
    process::run();
}

// This is an executable child fixture, not a skipped correctness gate. The
// preceding mandatory test invokes it twice with exact pinned configuration:
// one actual SIGKILL, one actual successful fresh-process resume.
#[test]
#[ignore = "only the owned process fixture supplies a pinned child configuration"]
fn history_process_child_helper() {
    process::child();
}

#[path = "history_process_tests.rs"]
mod process;

#[test]
fn signed_history_rejects_unsigned_view_unbounded_workers_and_signed_packet_outside_budget_nonce_window(
) {
    let mut f = Fixture::new();
    let mut bad = first(&f);
    let journal_path = f.dir.path().join("journal");
    let mut envelope: Value =
        serde_json::from_slice(&bad.inputs.as_ref().unwrap().raw_view).unwrap();
    envelope["task_signature"] = json!("00".repeat(64));
    let raw = serde_json::to_vec(&envelope).unwrap();
    let inputs = bad.inputs.as_mut().unwrap();
    inputs.raw_view = raw.clone();
    inputs.view_authority.envelope_sha256 = crate::operator_task_policy::digest_bytes(&raw);
    let rejected = Node::open_operator_continuous_checkpoint_with_workers(
        &f.store(),
        bad.inputs.take().unwrap(),
        Instant::now() + Duration::from_secs(10),
        2,
    );
    assert!(rejected.err().unwrap().to_string().contains("Signature"));
    let mut good = first(&f);
    let rejected = Node::open_operator_continuous_checkpoint_with_workers(
        &f.store(),
        good.inputs.take().unwrap(),
        Instant::now() + Duration::from_secs(10),
        3,
    );
    assert!(rejected.err().unwrap().to_string().contains("WORKERS"));
    let mut pristine = first(&f);
    let selection = HistoryRecoverySelection {
        schema: "restricted-continuous-single-successor-recovery-v1".into(),
        target: hex::encode(f.packet.id().unwrap()),
        prior_validation_operation_id: "00".repeat(32),
        prior_validation_settled_record_sha256: "00".repeat(32),
        validation_operation_id: pristine.validation.clone(),
        activation_operation_id: pristine.activation.clone(),
    };
    assert!(Node::open_operator_continuous_history_recovery(
        &f.store(),
        pristine.inputs.take().unwrap(),
        Instant::now() + Duration::from_secs(10),
        2,
        selection
    )
    .err()
    .unwrap()
    .to_string()
    .contains("HISTORY_RECOVERY_NOT_FRESH"));
    let journal = history::Journal::open(
        &journal_path,
        rustix::process::geteuid().as_raw(),
        &f.identity,
        &history::Anchor::empty(),
    )
    .unwrap();
    assert!(journal.pristine());
    assert!(!f.store().exists());
    drop(journal);
    let excluded = f.packet.header.nonce.checked_add(1).unwrap();
    f.budget.delegation.nonce_first = excluded;
    f.budget.delegation.nonce_last = excluded;
    (f.budget_raw, f.budget_digest) = crate::operator_continuous_test_support::signed(
        b"TRNM-RESTRICTED-CONTINUOUS-BUDGET2",
        &f.budget,
    );
    let mut view = first(&f);
    let mut node = open(&f, &mut view, 2);
    let work = AtomicU64::new(0);
    let rejected = node
        .receive_owned_history_operation(f.request(&view), &|point| {
            if matches!(point, OwnedHistoryProgress::Work(_)) {
                work.fetch_add(1, Ordering::AcqRel);
            }
            Ok(())
        })
        .unwrap();
    assert!(
        !rejected.completed,
        "signed packet escaped the original signed nonce budget: {}",
        serde_json::to_string(&rejected).unwrap()
    );
    assert!(rejected.validation.native_id.is_none());
    assert!(rejected
        .validation
        .native_error
        .as_deref()
        .unwrap()
        .contains("NativeBinding"));
    assert_eq!(work.load(Ordering::Acquire), 0);
    checked(&rejected.validation, 0);
    assert!(rejected.activation.is_none());
    eprintln!(
        "HISTORY_NATIVE_NONCE_BUDGET_REJECT {}",
        serde_json::to_string(&rejected).unwrap()
    );
    // The pre-existing protected single-packet receiver must obey the same
    // upper delegation. Fresh real signatures select a new operation, so a
    // spent History claim cannot explain this independent rejection.
    let mut fresh = f.view(
        2,
        Some(view.view_digest.clone()),
        head(&node),
        node.active().unwrap(),
        5,
        true,
    );
    node.refresh_operator_continuous_view(fresh.inputs.take().unwrap())
        .unwrap();
    let direct = node
        .receive_owned_continuous_packet(f.packet.clone(), fixture::CLOCK)
        .unwrap();
    let direct_receipt = node.continuous_scope_receipt(&fresh.validation).unwrap();
    eprintln!(
        "HISTORY_NATIVE_ORIGINAL_RECEIVER_NONCE {}",
        json!({"actual_result":direct,
        "actual_receipt":direct_receipt,"packet_nonce":f.packet.header.nonce,
        "budget_nonce_first":f.budget.delegation.nonce_first,"budget_nonce_last":f.budget.delegation.nonce_last})
    );
    assert!(
        direct.native_id.is_none(),
        "original protected receiver escaped original nonce delegation: {}",
        serde_json::to_string(&direct).unwrap()
    );
    assert!(direct
        .native_error
        .as_deref()
        .unwrap()
        .contains("NativeBinding"));
    assert_eq!(direct.cpu.spawned_workers, 0);
    assert!(!direct.cpu.accounting_unavailable);
    assert!(node.packet(f.packet.id().unwrap()).is_err());
    node.close_continuous_checkpoint().unwrap();
}

#[test]
fn signed_history_actual_child_panic_joins_and_retains_known_original_cpu_receipt() {
    let f = Fixture::new();
    let mut view = first(&f);
    let mut node = open(&f, &mut view, 2);
    let owner_thread = std::thread::current().id();
    let result = node
        .receive_owned_history_operation(f.request(&view), &|point| {
            if point
                == OwnedHistoryProgress::Execution(
                    trnm_mvcc_fee::pon_executor::ExecutionProgress::AfterPrepare { index: 0 },
                )
            {
                assert_ne!(std::thread::current().id(), owner_thread);
                panic!("controlled History child panic after paid signature verification");
            }
            Ok(())
        })
        .unwrap();
    checked(&result.validation, 2);
    assert!(!result.completed);
    assert!(result.activation.is_none());
    assert!(result
        .validation
        .native_error
        .as_deref()
        .unwrap()
        .contains("WORKER_PANIC"));
    assert_eq!(node.active().unwrap(), (f.settings.genesis(), 0));
    assert_eq!(
        node.continuous_process_cpu_snapshot().unwrap()["pending_scopes"],
        0
    );
    assert_replay_keeps_journal(&node, &view, &result.validation);
    eprintln!(
        "HISTORY_NATIVE_CHILD_PANIC {}",
        json!({"result":result,"receipt":node.continuous_scope_receipt(&view.validation).unwrap()})
    );
    // Deliberately exercise the raw internal invariant at the END of this
    // fixture. It must reject duplicate CPU and preserve spent history, while
    // persisting the original fault; this is not a successful clean reopen.
    let mut journal = node
        .continuous_owner
        .as_ref()
        .unwrap()
        .journal
        .lock()
        .unwrap();
    let before = journal.anchor();
    let usage = journal.usage_digest().unwrap();
    assert_eq!(
        journal.settle_cpu(scope_id(&view.validation), &result.validation.cpu),
        Err(crate::operator_task_policy::PolicyError::CpuUnknown)
    );
    assert_eq!(journal.anchor(), before);
    assert_eq!(journal.usage_digest().unwrap(), usage);
    assert!(journal.unavailable_handle().load(Ordering::Acquire));
    drop(journal);
    assert!(node.close_continuous_checkpoint().is_err());
    drop(node);
    assert!(history::Journal::open(
        &f.dir.path().join("journal"),
        rustix::process::geteuid().as_raw(),
        &f.identity,
        &before
    )
    .is_err());
    eprintln!(
        "HISTORY_NATIVE_RAW_DOUBLE_SETTLE_REJECT {}",
        json!({"retained_head":before,
        "usage_unchanged":true,"fault_persisted":true,"clean_reopen_refused":true})
    );
}
