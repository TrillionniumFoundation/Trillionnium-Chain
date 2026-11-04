use super::*;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

const ORIGINAL_SCHEMA: &str = "pon-native-history-arithmetic-observation-v1";
const LEGACY_SCHEMA: &str = "pon-native-legacy-reorg-observation-v1";

fn role<'a>(snapshot: &'a Value, name: &str) -> &'a Value {
    snapshot["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["role"] == name)
        .unwrap()
}

fn sql_site<'a>(snapshot: &'a Value, name: &str) -> &'a Value {
    snapshot["sql_commit"]["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["site"] == name)
        .unwrap()
}

fn assert_unentered_site(snapshot: &Value, name: &str) {
    let site = sql_site(snapshot, name);
    assert_eq!(site["totals"]["calls_started"], 0);
    assert_eq!(site["calls_in_flight"], 0);
    assert!(site["totals"]["wall_ns"].is_null());
    assert!(site["totals"]["cpu_ns"].is_null());
}

fn assert_empty(snapshot: &Value) {
    assert_eq!(snapshot["schema"], LEGACY_SCHEMA);
    assert_eq!(snapshot["backend"], "legacy");
    assert_eq!(snapshot["enabled"], true);
    assert_eq!(snapshot["has_consensus_authority"], false);
    assert_eq!(snapshot["stage_observation_failed"], false);
    assert_eq!(snapshot["roles"].as_array().unwrap().len(), 2);
    for name in ["staging_validation", "active_tail_validation"] {
        let row = role(snapshot, name);
        assert_eq!(row["totals"]["calls"], 0);
        assert!(row["complete_wall_ns"].is_null());
        assert!(row["complete_cpu_ns"].is_null());
        assert!(row["known_cpu_ns_subtotal"].is_null());
        assert!(row["per_outcome_counts"].is_null());
    }
    assert_eq!(
        snapshot["sql_commit"]["schema"],
        "pon-native-legacy-reorg-sql-commit-call-observation-v1"
    );
    for name in [
        "admission_persistence",
        "atomic",
        "reorg_step",
        "reorg_termination",
    ] {
        assert_unentered_site(snapshot, name);
    }
}

fn assert_entered(snapshot: &Value) {
    assert_eq!(snapshot["schema"], LEGACY_SCHEMA);
    assert_eq!(snapshot["stage_observation_failed"], false);
    assert_eq!(snapshot["has_consensus_authority"], false);
    for name in ["staging_validation", "active_tail_validation"] {
        let row = role(snapshot, name);
        assert!(row["totals"]["calls"].as_u64().unwrap() > 0);
        assert!(row["complete_wall_ns"].is_u64());
        assert_eq!(row["counter_saturated"], false);
        assert!(row["per_outcome_counts"].is_null());
        if row["totals"]["cpu_unknown_calls"].as_u64().unwrap() > 0 {
            assert!(row["complete_cpu_ns"].is_null());
        }
    }
    let site = sql_site(snapshot, "reorg_step");
    assert!(site["totals"]["calls_succeeded"].as_u64().unwrap() > 0);
    assert_eq!(site["totals"]["calls_failed"], 0);
    assert_eq!(site["calls_in_flight"], 0);
    assert_eq!(snapshot["sql_commit"]["observation_failed"], false);
    assert_unentered_site(snapshot, "admission_persistence");
    assert_unentered_site(snapshot, "atomic");
}

fn transfer(node: &Node, nonce: u64, recipient: u64) -> Vec<u8> {
    let mut payload = development_public(recipient).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: node.settings().network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
            .unwrap();
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}

fn fork_pair(control_path: &Path, observed_path: &Path) -> (Node, Node, Hash, u64) {
    let settings = Settings::development(Some(1)).unwrap();
    let builder_directory = tempfile::tempdir().unwrap();
    let mut builder = Node::open(builder_directory.path(), settings.clone(), 2).unwrap();
    let first_nonce = builder.next_nonce(development_public(0).unwrap()).unwrap();
    let left = builder
        .make(
            settings.genesis(),
            vec![transfer(&builder, first_nonce, 1)],
            development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let right = builder
        .make(
            settings.genesis(),
            vec![transfer(&builder, first_nonce, 2)],
            development_public(1).unwrap(),
            12,
            4096,
        )
        .unwrap();
    let right_id = builder.admit(&right, 1000).unwrap();
    let target = builder
        .make(
            right_id,
            vec![transfer(&builder, first_nonce + 1, 3)],
            development_public(1).unwrap(),
            22,
            4096,
        )
        .unwrap();
    let target_id = target.id().unwrap();
    drop(builder);

    // Both measured owners receive the same packets and the same operation
    // sequence. Reopening after admission would activate the best pending tip.
    let mut control = Node::open(control_path, settings.clone(), 2).unwrap();
    let mut observed = Node::open(observed_path, settings, 2).unwrap();
    for node in [&mut control, &mut observed] {
        let left_id = node.admit(&left, 1000).unwrap();
        assert_eq!(node.activate(left_id).unwrap(), left_id);
        assert_eq!(node.admit(&right, 1000).unwrap(), right_id);
        assert_eq!(node.admit(&target, 1000).unwrap(), target_id);
        assert_eq!(
            node.next_nonce(development_public(0).unwrap()).unwrap(),
            first_nonce + 1
        );
    }
    assert_eq!(control.read_active().unwrap(), observed.read_active().unwrap());
    (control, observed, target_id, first_nonce)
}

fn activate_with_trace(
    node: &mut Node,
    target: Hash,
    cancel: bool,
) -> (Result<Hash>, Vec<String>, u64) {
    let mut cuts = Vec::new();
    let mut checkpoints = 0_u64;
    let result = node.activate_with_fault_and_progress(
        target,
        Some(&mut |point| {
            cuts.push(point.to_owned());
            if cancel && point == "attach:1" {
                Err(Error::new(crate::ErrorCode::LegacyRequestDeadline))
            } else {
                Ok(())
            }
        }),
        &mut || {
            checkpoints += 1;
            Ok(())
        },
        None,
    );
    (result, cuts, checkpoints)
}

fn lifecycle(node: &Node) -> (u64, u64, u64, Option<u64>, String) {
    node.db
        .query_row(
            "SELECT reorg.done,reorg.cursor,reorg_lifecycle_v1.outcome,
                    reorg_lifecycle_v1.cancelled_cursor,reorg_lifecycle_v1.reason
             FROM reorg,reorg_lifecycle_v1 ORDER BY operation DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap()
}

#[test]
fn legacy_observation_opt_in_is_local_and_keeps_unentered_unknown() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    let original = node.native_history_arithmetic_observation();
    assert_eq!(original["schema"], ORIGINAL_SCHEMA);
    let active = node.read_active().unwrap();
    assert!(node.enable_native_legacy_reorg_observation());
    let empty = node.native_history_arithmetic_observation();
    assert_empty(&empty);
    assert!(node.enable_native_legacy_reorg_observation());
    assert_eq!(node.native_history_arithmetic_observation(), empty);

    let error = node
        .activate_with_fault_and_progress(
            settings.genesis(),
            None,
            &mut || Err(Error::new(crate::ErrorCode::LegacyRequestDeadline)),
            None,
        )
        .unwrap_err();
    assert!(error.is(crate::ErrorCode::LegacyRequestDeadline));
    assert_eq!(node.native_history_arithmetic_observation(), empty);
    assert_eq!(node.read_active().unwrap(), active);

    let authenticated_directory = tempfile::tempdir().unwrap();
    let authenticated =
        Node::open_with_authenticated_state(authenticated_directory.path(), settings, 2).unwrap();
    let original = authenticated.native_history_arithmetic_observation();
    assert_eq!(original["schema"], ORIGINAL_SCHEMA);
    assert!(!authenticated.enable_native_legacy_reorg_observation());
    assert_eq!(authenticated.native_history_arithmetic_observation(), original);
}

#[test]
fn legacy_observation_preserves_signed_reorg_state_and_progress() {
    let control_directory = tempfile::tempdir().unwrap();
    let observed_directory = tempfile::tempdir().unwrap();
    let (mut control, mut observed, target, first_nonce) =
        fork_pair(control_directory.path(), observed_directory.path());
    assert!(observed.enable_native_legacy_reorg_observation());
    let (control_result, control_cuts, control_progress) =
        activate_with_trace(&mut control, target, false);
    let (observed_result, observed_cuts, observed_progress) =
        activate_with_trace(&mut observed, target, false);
    let snapshot = observed.native_history_arithmetic_observation();
    assert_eq!(control_result.unwrap(), target);
    assert_eq!(observed_result.unwrap(), target);
    assert_eq!(observed_cuts, control_cuts);
    assert_eq!(observed_progress, control_progress);
    assert!(control_progress > 0);
    assert!(control_cuts.iter().any(|point| point == "detach:0"));
    assert!(control_cuts.iter().any(|point| point == "attach:1"));
    assert!(control_cuts.iter().any(|point| point == "published"));
    let active = control.read_active().unwrap();
    assert_eq!(observed.read_active().unwrap(), active);
    assert_eq!(active.0, target);
    assert_eq!(
        control.settings().state_root(&active.2).unwrap(),
        control.record(target).unwrap().root
    );
    for node in [&control, &observed] {
        assert_eq!(
            node.next_nonce(development_public(0).unwrap()).unwrap(),
            first_nonce + 2
        );
    }
    assert_entered(&snapshot);
    assert_unentered_site(&snapshot, "reorg_termination");
    assert!(observed.enable_native_legacy_reorg_observation());
    assert_eq!(observed.native_history_arithmetic_observation(), snapshot);
    let control_observation = control.native_history_arithmetic_observation();
    assert_eq!(control_observation["schema"], ORIGINAL_SCHEMA);

    let settings = observed.settings().clone();
    drop(observed);
    let reopened = Node::open(observed_directory.path(), settings, 2).unwrap();
    let cold_observation = reopened.native_history_arithmetic_observation();
    assert_eq!(cold_observation["schema"], ORIGINAL_SCHEMA);
    assert_eq!(reopened.read_active().unwrap(), active);
    assert_eq!(
        reopened.next_nonce(development_public(0).unwrap()).unwrap(),
        first_nonce + 2
    );
}

#[test]
fn legacy_observation_preserves_cancelled_and_failed_reorg_outcomes() {
    for cancel in [true, false] {
        let control_directory = tempfile::tempdir().unwrap();
        let observed_directory = tempfile::tempdir().unwrap();
        let (mut control, mut observed, target, first_nonce) =
            fork_pair(control_directory.path(), observed_directory.path());
        let before = control.read_active().unwrap();
        let original_root = control.record(target).unwrap().root;
        if !cancel {
            let mut wrong_root = original_root;
            wrong_root[0] ^= 1;
            for node in [&control, &observed] {
                assert_eq!(
                    node.db
                        .execute(
                            "UPDATE blocks SET state_root=? WHERE id=?",
                            params![wrong_root.as_slice(), target.as_slice()],
                        )
                        .unwrap(),
                    1
                );
            }
        }
        assert!(observed.enable_native_legacy_reorg_observation());
        let (control_result, control_cuts, control_progress) =
            activate_with_trace(&mut control, target, cancel);
        let (observed_result, observed_cuts, observed_progress) =
            activate_with_trace(&mut observed, target, cancel);
        let snapshot = observed.native_history_arithmetic_observation();
        let control_error = control_result.unwrap_err();
        let observed_error = observed_result.unwrap_err();
        assert_eq!(observed_error.kind(), control_error.kind());
        assert_eq!(observed_error.to_string(), control_error.to_string());
        assert_eq!(observed_cuts, control_cuts);
        assert_eq!(observed_progress, control_progress);
        assert!(control_progress > 0);
        assert_eq!(control.read_active().unwrap(), before);
        assert_eq!(observed.read_active().unwrap(), before);
        for node in [&control, &observed] {
            assert_eq!(
                node.next_nonce(development_public(0).unwrap()).unwrap(),
                first_nonce + 1
            );
        }
        let retained = lifecycle(&control);
        assert_eq!(lifecycle(&observed), retained);
        assert_entered(&snapshot);
        if cancel {
            assert!(observed_error.is(crate::ErrorCode::LegacyRequestDeadline));
            assert_eq!((retained.0, retained.2), (2, 2));
            assert!(retained.1 > 0);
            assert_eq!(retained.3, Some(retained.1));
            assert_eq!(retained.4, "REQUEST_DEADLINE");
            assert!(
                sql_site(&snapshot, "reorg_termination")["totals"]["calls_succeeded"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        } else {
            assert_eq!(observed_error.to_string(), "ROOT");
            assert!(observed_error.requires_owner_stop());
            assert_eq!((retained.0, retained.2), (0, 0));
            assert!(retained.1 > 0);
            assert!(retained.3.is_none());
            assert!(retained.4.is_empty());
            assert_unentered_site(&snapshot, "reorg_termination");
            for node in [&control, &observed] {
                assert_eq!(
                    node.db
                        .execute(
                            "UPDATE blocks SET state_root=? WHERE id=?",
                            params![original_root.as_slice(), target.as_slice()],
                        )
                        .unwrap(),
                    1
                );
            }
        }
        assert!(observed.enable_native_legacy_reorg_observation());
        assert_eq!(observed.native_history_arithmetic_observation(), snapshot);
    }
}
