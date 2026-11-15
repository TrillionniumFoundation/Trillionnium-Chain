//! Real Node preparation controls. Synthetic dormant genesis accounts exercise
//! bounded reads; these tests do not claim public service or throughput results.
use super::*;
use crate::{development_public, Error, ErrorCode, Settings};
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_executor::{ExecutionControl, ExecutionProgress};

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}

fn open(path: &Path, settings: Settings, workers: usize, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings, workers).unwrap()
    } else {
        Node::open(path, settings, workers).unwrap()
    }
}

fn signed_transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = trnm_protocol::pon_wire::Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

#[test]
fn registered_prepare_pre_cancel_keeps_error_before_material_or_parent_io() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let node = open(directory.path(), settings.clone(), 4, false);
    let (model, input, _, _) = settings.consensus_maintenance_material().unwrap();
    let before = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    for code in [
        ErrorCode::PublicRequestCancelled,
        ErrorCode::PublicRequestDeadline,
    ] {
        for parent in [settings.genesis(), [0; 32]] {
            for material in [model.as_slice(), &[]] {
                let calls = AtomicUsize::new(0);
                let on_progress = |point| -> Result<()> {
                    assert_eq!(point, ExecutionProgress::BeforeParentBinding);
                    calls.fetch_add(1, Ordering::AcqRel);
                    Err(Error::new(code))
                };
                let error = node
                    .prepare_registered_material_controlled(
                        parent,
                        vec![],
                        development_public(0).unwrap(),
                        11,
                        4096,
                        material,
                        &input,
                        &ExecutionControl::new(&on_progress, &()),
                    )
                    .err()
                    .expect("cancelled preparation returned a candidate");
                assert!(error.is(code));
                assert!(!error.requires_owner_stop());
                assert_eq!(calls.load(Ordering::Acquire), 1);
                assert_eq!(node.read_active().unwrap(), before);
                assert_eq!(node.stats().unwrap(), stats);
            }
        }
    }
}

#[test]
fn registered_prepare_cancels_inside_active_row_scan_before_execution() {
    let mut settings = settings();
    for index in 0_u64..1024 {
        settings.initial.insert(
            format!(
                "account:{}",
                hex::encode(hash(b"prepare-cancel-dormant", &[&index.to_le_bytes()]))
            ),
            serde_json::json!({"balance":0,"nonce":7}),
        );
    }
    continuity_v1::check_state(&settings.initial, 0, &settings.app).unwrap();
    settings.genesis = hash(
        b"genesis",
        &[
            &settings.network(),
            &settings.parameters(),
            &settings.state_root(&settings.initial).unwrap(),
            &settings.genesis_time().to_le_bytes(),
        ],
    );
    let (model, input, _, _) = settings.consensus_maintenance_material().unwrap();
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path(), settings.clone(), 4, authenticated);
        let before = node.read_active().unwrap();
        let stats = node.stats().unwrap();
        // The eighth boundary is inside the actual >1,024-row parent scan.
        // No State clone, signature preparation or worker may have started.
        let calls = AtomicUsize::new(0);
        let on_progress = |point| -> Result<()> {
            assert_eq!(point, ExecutionProgress::BeforeParentBinding);
            if calls.fetch_add(1, Ordering::AcqRel) + 1 == 8 {
                Err(Error::new(ErrorCode::PublicMutationCpuBudget))
            } else {
                Ok(())
            }
        };
        let error = node
            .prepare_registered_material_controlled(
                settings.genesis(),
                vec![signed_transfer(&settings, 1)],
                development_public(0).unwrap(),
                11,
                4096,
                &model,
                &input,
                &ExecutionControl::new(&on_progress, &()),
            )
            .err()
            .expect("parent scan ignored its owner budget");
        assert!(error.is(ErrorCode::PublicMutationCpuBudget));
        assert!(!error.requires_owner_stop());
        assert_eq!(calls.load(Ordering::Acquire), 8);
        assert_eq!(node.read_active().unwrap(), before);
        assert_eq!(node.stats().unwrap(), stats);
        drop(node);
        let reopened = open(directory.path(), settings.clone(), 4, authenticated);
        assert_eq!(reopened.read_active().unwrap(), before);
        assert_eq!(reopened.stats().unwrap(), stats);
    }
}

#[test]
fn registered_prepare_cancels_during_inactive_ancestry_read_and_retries() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node = open(directory.path(), settings.clone(), 4, false);
    let miner = development_public(0).unwrap();
    let mut parent = settings.genesis();
    for height in 1..=3 {
        let packet = node
            .make_consensus_maintenance(parent, vec![], miner, 1 + height * 10, 4096)
            .unwrap();
        parent = node.admit(&packet, 100_000).unwrap();
    }
    assert_eq!(node.active().unwrap().0, settings.genesis());
    let before = node.read_active().unwrap();
    let parent_state = node.state_at(parent).unwrap();
    let stats = node.stats().unwrap();
    let (model, input, _, _) = settings.consensus_maintenance_material().unwrap();
    let calls = AtomicUsize::new(0);
    let on_progress = |point| -> Result<()> {
        assert_eq!(point, ExecutionProgress::BeforeParentBinding);
        if calls.fetch_add(1, Ordering::AcqRel) + 1 == 6 {
            Err(Error::new(ErrorCode::PublicRequestCancelled))
        } else {
            Ok(())
        }
    };
    let error = node
        .prepare_registered_material_controlled(
            parent,
            vec![],
            miner,
            41,
            4096,
            &model,
            &input,
            &ExecutionControl::new(&on_progress, &()),
        )
        .err()
        .expect("inactive parent walk ignored cancellation");
    assert!(error.is(ErrorCode::PublicRequestCancelled));
    assert_eq!(calls.load(Ordering::Acquire), 6);
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.state_at(parent).unwrap(), parent_state);
    assert_eq!(node.stats().unwrap(), stats);

    let reference = node
        .make_with_registered_material(parent, vec![], miner, 41, 4096, &model, &input)
        .unwrap();
    let retry = node
        .prepare_registered_material_controlled(
            parent,
            vec![],
            miner,
            41,
            4096,
            &model,
            &input,
            &ExecutionControl::new(&|_| Ok(()), &()),
        )
        .unwrap()
        .search(4096)
        .unwrap();
    assert_eq!(retry.encode().unwrap(), reference.encode().unwrap());
    let id = node.admit(&retry, 100_000).unwrap();
    node.activate(id).unwrap();
    let committed = node.read_active().unwrap();
    drop(node);
    let reopened = open(directory.path(), settings, 1, false);
    assert_eq!(reopened.read_active().unwrap(), committed);
}

#[test]
fn registered_prepare_control_preserves_packets_errors_and_cold_commit() {
    for workers in [1, 4] {
        for maintenance in [false, true] {
            let settings = settings();
            let reference_dir = tempfile::tempdir().unwrap();
            let controlled_dir = tempfile::tempdir().unwrap();
            let mut reference = open(reference_dir.path(), settings.clone(), workers, true);
            let mut controlled = open(controlled_dir.path(), settings.clone(), workers, true);
            let (model, input, _, _) = if maintenance {
                settings.consensus_maintenance_material().unwrap()
            } else {
                settings.bootstrap_task_material().unwrap()
            };
            let parent = settings.genesis();
            let miner = development_public(0).unwrap();
            let before = controlled.read_active().unwrap();
            for invalid in [vec![signed_transfer(&settings, 2)], vec![vec![1]]] {
                let expected = reference
                    .prepare_registered_material(
                        parent,
                        invalid.clone(),
                        miner,
                        11,
                        4096,
                        &model,
                        &input,
                    )
                    .err()
                    .expect("invalid reference command succeeded");
                let actual = controlled
                    .prepare_registered_material_controlled(
                        parent,
                        invalid,
                        miner,
                        11,
                        4096,
                        &model,
                        &input,
                        &ExecutionControl::new(&|_| Ok(()), &()),
                    )
                    .err()
                    .expect("invalid controlled command succeeded");
                assert_eq!(actual.to_string(), expected.to_string());
                assert_eq!(controlled.read_active().unwrap(), before);
            }
            let transactions = vec![signed_transfer(&settings, 1)];
            let expected = reference
                .make_with_registered_material(
                    parent,
                    transactions.clone(),
                    miner,
                    11,
                    4096,
                    &model,
                    &input,
                )
                .unwrap();
            let actual = controlled
                .prepare_registered_material_controlled(
                    parent,
                    transactions,
                    miner,
                    11,
                    4096,
                    &model,
                    &input,
                    &ExecutionControl::new(&|_| Ok(()), &()),
                )
                .unwrap()
                .search(4096)
                .unwrap();
            assert_eq!(actual.encode().unwrap(), expected.encode().unwrap());
            let expected_id = reference.admit(&expected, 100_000).unwrap();
            reference.activate(expected_id).unwrap();
            let actual_id = controlled.admit(&actual, 100_000).unwrap();
            controlled.activate(actual_id).unwrap();
            assert_eq!(actual_id, expected_id);
            let committed = reference.read_active().unwrap();
            assert_eq!(controlled.read_active().unwrap(), committed);
            assert_eq!(controlled.stats().unwrap(), reference.stats().unwrap());
            drop(controlled);
            let reopened = open(controlled_dir.path(), settings, workers, true);
            assert_eq!(reopened.read_active().unwrap(), committed);
        }
    }
}
