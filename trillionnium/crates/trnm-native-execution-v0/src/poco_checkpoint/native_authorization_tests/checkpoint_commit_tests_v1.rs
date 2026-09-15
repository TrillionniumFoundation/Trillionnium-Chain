use super::*;
use trnm_consensus_types::Cev0AdmissionBudgetV0;

fn raw_proof(prepared: &PreparedNativePocoCheckpointV0) -> Vec<u8> {
    checkpoint_two_seal_proof(prepared)
        .try_cev0_bytes()
        .unwrap()
}

#[test]
fn strict_checkpoint_commit_precedes_handoff_and_creates_no_seal_application() {
    let directory = tempfile::tempdir().unwrap();
    let app = open(&directory.path().join("application.sqlite3"), config());
    let headers = ordinary_prefix(&app);
    let prepared = preparation(&app, &headers);
    let raw = raw_proof(&prepared);
    let executed = execute_prepared_checkpoint(&app, &prepared);
    assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 7);
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let receipt = app
        .commit_poco_checkpoint_for_handoff_v1(prepared, executed, &raw, &mut budget)
        .unwrap();
    assert_eq!(receipt.header().height().get(), 8);
    assert_eq!(receipt.durable_row().commit_sequence_v0(), Some(17));
    assert!(budget.signature_work() > 0);
    assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 8);
    for seal_height in [9, 10] {
        assert!(app
            .read_finalized_by_height_v0(HeightV0::new(seal_height))
            .is_err());
    }
    // Neither handoff role was an input to commit. Only now construct the
    // separately verified test certificate from the real native read receipt.
    let anchor = certificate_after_native_receipt(&receipt);
    let confirmed = app
        .complete_poco_checkpoint_handoff_v0(receipt, &anchor)
        .unwrap();
    assert_eq!(confirmed.durable_row().commit_sequence_v0(), Some(17));
}

#[test]
fn corrupt_checkpoint_signature_is_rejected_before_commit_with_charged_work() {
    let directory = tempfile::tempdir().unwrap();
    let app = open(&directory.path().join("application.sqlite3"), config());
    let headers = ordinary_prefix(&app);
    let prepared = preparation(&app, &headers);
    let proof = checkpoint_two_seal_proof(&prepared);
    let signature = proof.child().proposer_signature().as_bytes();
    let mut raw = proof.try_cev0_bytes().unwrap();
    let positions: Vec<_> = raw
        .windows(signature.len())
        .enumerate()
        .filter_map(|(i, b)| (b == signature).then_some(i))
        .collect();
    assert_eq!(positions.len(), 1);
    raw[positions[0]] ^= 1;
    let executed = execute_prepared_checkpoint(&app, &prepared);
    let before = std::fs::read(app.path()).unwrap();
    let head = app.confirmed_committed_head_v0().unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let error = app
        .commit_poco_checkpoint_for_handoff_v1(prepared, executed, &raw, &mut budget)
        .err()
        .expect("corrupt signature");
    assert!(matches!(
        error,
        NativeCheckpointCommitErrorV1::BeforeCommit(_)
    ));
    assert!(budget.signature_work() > 0);
    assert_eq!(std::fs::read(app.path()).unwrap(), before);
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), head);
}

#[test]
fn checkpoint_commit_budget_and_canonical_bytes_fail_before_application_change() {
    for failure in ["work", "bytes", "trailing"] {
        let directory = tempfile::tempdir().unwrap();
        let app = open(&directory.path().join("application.sqlite3"), config());
        let headers = ordinary_prefix(&app);
        let prepared = preparation(&app, &headers);
        let mut raw = raw_proof(&prepared);
        let executed = execute_prepared_checkpoint(&app, &prepared);
        let before = std::fs::read(app.path()).unwrap();
        let mut budget = match failure {
            "work" => Cev0AdmissionBudgetV0::new(raw.len(), 0),
            "bytes" => Cev0AdmissionBudgetV0::new(raw.len() - 1, 1000),
            _ => {
                raw.push(0);
                Cev0AdmissionBudgetV0::protocol_v0()
            }
        };
        let error = app
            .commit_poco_checkpoint_for_handoff_v1(prepared, executed, &raw, &mut budget)
            .err()
            .expect(failure);
        assert!(matches!(
            error,
            NativeCheckpointCommitErrorV1::BeforeCommit(_)
        ));
        assert_eq!(std::fs::read(app.path()).unwrap(), before, "{failure}");
        assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 7);
    }
}

#[test]
fn unrelated_real_execution_cannot_be_committed_with_checkpoint_proof() {
    let directory = tempfile::tempdir().unwrap();
    let app = open(&directory.path().join("application.sqlite3"), config());
    let headers = ordinary_prefix(&app);
    let prepared = preparation(&app, &headers);
    let raw = raw_proof(&prepared);
    let _real_checkpoint_p = execute_prepared_checkpoint(&app, &prepared);
    let different = app
        .read_finalized_by_height_v0(HeightV0::new(7))
        .unwrap()
        .executed_v0()
        .clone();
    let before = std::fs::read(app.path()).unwrap();
    let error = app
        .commit_poco_checkpoint_for_handoff_v1(
            prepared,
            different,
            &raw,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .err()
        .expect("wrong execution");
    assert!(matches!(
        error,
        NativeCheckpointCommitErrorV1::BeforeCommit(_)
    ));
    assert_eq!(std::fs::read(app.path()).unwrap(), before);
}

#[test]
fn missing_or_halted_preparation_stops_checkpoint_before_native_commit() {
    for fault in ["delete", "halt", "replace"] {
        let directory = tempfile::tempdir().unwrap();
        let app = open(&directory.path().join("application.sqlite3"), config());
        let headers = ordinary_prefix(&app);
        let prepared = preparation(&app, &headers);
        let raw = raw_proof(&prepared);
        let executed = execute_prepared_checkpoint(&app, &prepared);
        let path = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(app.path());
        if fault == "replace" {
            std::fs::rename(&path, path.with_extension("retained-evidence")).unwrap();
        } else {
            let connection = rusqlite::Connection::open(&path).unwrap();
            if fault == "delete" {
                connection.execute("DELETE FROM preparations", []).unwrap();
            } else {
                connection.execute("INSERT INTO safety_halt(singleton,reason,conflict_checksum) VALUES (1,'test halt',?1)", [&[1u8;32][..]]).unwrap();
            }
        }
        let before = std::fs::read(app.path()).unwrap();
        let error = app
            .commit_poco_checkpoint_for_handoff_v1(
                prepared,
                executed,
                &raw,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .err()
            .expect(fault);
        assert!(matches!(
            error,
            NativeCheckpointCommitErrorV1::BeforeCommit(_)
        ));
        assert_eq!(std::fs::read(app.path()).unwrap(), before, "{fault}");
    }
}

#[test]
fn another_native_owner_cannot_consume_held_preparation() {
    let directory = tempfile::tempdir().unwrap();
    let app = open(&directory.path().join("application.sqlite3"), config());
    let headers = ordinary_prefix(&app);
    let prepared = preparation(&app, &headers);
    let raw = raw_proof(&prepared);
    let _source_execution = execute_prepared_checkpoint(&app, &prepared);
    let other_directory = tempfile::tempdir().unwrap();
    let other = open(
        &other_directory.path().join("application.sqlite3"),
        config(),
    );
    let other_headers = ordinary_prefix(&other);
    let other_prepared = preparation(&other, &other_headers);
    let other_executed = execute_prepared_checkpoint(&other, &other_prepared);
    let before = std::fs::read(other.path()).unwrap();
    let error = other
        .commit_poco_checkpoint_for_handoff_v1(
            prepared,
            other_executed,
            &raw,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .err()
        .expect("foreign namespace");
    assert!(matches!(
        error,
        NativeCheckpointCommitErrorV1::BeforeCommit(_)
    ));
    assert_eq!(std::fs::read(other.path()).unwrap(), before);
}

#[test]
fn checkpoint_commit_fsync_uncertainty_recovers_one_effect_after_reopen() {
    use crate::durable::{
        arm_sync_store_commit_boundary_fault_v0, SyncStoreCommitBoundaryFaultPointV0,
    };
    for point in [
        SyncStoreCommitBoundaryFaultPointV0::Database,
        SyncStoreCommitBoundaryFaultPointV0::Directory,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        let app = open(&path, config());
        let headers = ordinary_prefix(&app);
        let original_request = next_request(&app);
        let prepared = preparation(&app, &headers);
        let raw = raw_proof(&prepared);
        let executed = execute_prepared_checkpoint(&app, &prepared);
        let fault = arm_sync_store_commit_boundary_fault_v0(app.path(), point);
        let error = app
            .commit_poco_checkpoint_for_handoff_v1(
                prepared,
                executed.clone(),
                &raw,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .err()
            .expect("sync failure");
        assert!(matches!(error, NativeCheckpointCommitErrorV1::Uncertain(_)));
        drop(fault);
        drop(app);
        let reopened = DurableNativeApplicationV0::open(&path, config()).unwrap();
        let before = reopened.confirmed_committed_head_v0().unwrap();
        assert_eq!(before.height().get(), 8);
        let prepare_again = || {
            reopened
                .prepare_native_poco_checkpoint_v0(
                    &original_request,
                    View::new(8),
                    reopened.config_v0().validator_set_v0().validators()[3].id(),
                    &cutoff_proof(&headers, reopened.config_v0()),
                    &headers[3].try_cev0_bytes().unwrap(),
                )
                .unwrap()
        };
        let receipt = reopened
            .commit_poco_checkpoint_for_handoff_v1(
                prepare_again(),
                executed.clone(),
                &raw,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(receipt.durable_row().commit_sequence_v0(), Some(17));
        let repeat = reopened
            .commit_poco_checkpoint_for_handoff_v1(
                prepare_again(),
                executed,
                &raw,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(repeat.durable_row().commit_sequence_v0(), Some(17));
        assert_eq!(reopened.confirmed_committed_head_v0().unwrap(), before);
        assert!(reopened
            .read_finalized_by_height_v0(HeightV0::new(9))
            .is_err());
    }
}
