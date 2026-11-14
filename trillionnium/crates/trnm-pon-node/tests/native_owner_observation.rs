//! Actual native relation, snapshot, owner and refusal tests; no network risk fit.
#[path = "../examples/support/native_owner_scenario.rs"]
mod scenario;

use rusqlite::{params, Connection};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{consensus, development_public, Error, ErrorCode, Node, Packet, Settings};
use trnm_pon_node::{OwnerCensusLimits, OwnerCensusProgress};

fn one_block(authenticated: bool) -> (tempfile::TempDir, Node, Packet) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = if authenticated {
        Node::open_with_authenticated_state(directory.path(), settings, 1)
    } else {
        Node::open(directory.path(), settings, 1)
    }
    .unwrap();
    let packet = node
        .make(
            node.settings().genesis(),
            vec![],
            development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    node.admit(&packet, 100).unwrap();
    node.activate_observed(packet.id().unwrap(), 100).unwrap();
    (directory, node, packet)
}

fn census(node: &Node) -> Value {
    serde_json::to_value(
        node.native_owner_census(100, OwnerCensusLimits::default())
            .unwrap(),
    )
    .unwrap()
}

fn no_global_claim(value: &Value) {
    for name in [
        "unadmitted_local_packets_covered",
        "remote_private_branches_covered",
        "global_ready_attested",
        "world_coverage_attested",
        "physical_clock_authenticated",
        "exported_artifact_authenticated",
        "probabilistic_environment_bound",
        "six_successor_risk_qualified",
        "execution_authority",
    ] {
        assert_eq!(value[name], false, "{name}");
    }
}

#[test]
fn actual_legacy_and_authenticated_census_replays_full_native_relation_without_persistence() {
    for authenticated in [false, true] {
        let (_directory, node, packet) = one_block(authenticated);
        let before = node.stats().unwrap();
        let output = census(&node);
        assert_eq!(node.stats().unwrap(), before);
        assert_eq!(output["active_tip"], hex::encode(packet.id().unwrap()));
        assert_eq!(output["active_generation"], 1);
        assert_eq!(output["rows"].as_array().unwrap().len(), 2);
        let row = &output["rows"][1];
        assert_eq!(row["full_native_work_replayed"], true);
        assert_eq!(row["full_native_application_replayed"], true);
        assert_eq!(row["retained_state_and_deltas_equal"], true);
        assert_eq!(
            row["required_work_hex"],
            hex::encode(
                consensus::required_work(packet.header.target)
                    .unwrap()
                    .bytes()
            )
        );
        assert_eq!(row["chainwork_hex"], row["required_work_hex"]);
        assert_eq!(output["eligible_max_score_hex"], row["chainwork_hex"]);
        assert_eq!(output["raw_selection_deficit_hex"], "0".repeat(128));
        assert_eq!(output["rows"][0]["chainwork_hex"], "0".repeat(128));
        assert_eq!(output["complete_for_all_admitted_rows_in_snapshot"], true);
        assert_eq!(output["snapshot_released_without_commit"], true);
        assert_eq!(output["confirmation_depth"], 6);
        assert_eq!(output["confirmation_work_multiplier"], 6);
        no_global_claim(&output);
    }
}

#[test]
fn local_view_digest_stable_but_owner_incarnation_and_observation_attempt_are_not_reused() {
    let (directory, node, _) = one_block(false);
    let first = census(&node);
    let second = census(&node);
    assert_eq!(
        first["local_view_commitment"],
        second["local_view_commitment"]
    );
    assert_eq!(
        first["owner_observation_instance"],
        second["owner_observation_instance"]
    );
    assert!(second["owner_attempt"].as_u64() > first["owner_attempt"].as_u64());
    let settings = node.settings().clone();
    drop(node);
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    let third = census(&reopened);
    assert_ne!(
        third["owner_observation_instance"],
        first["owner_observation_instance"]
    );
    assert_eq!(
        third["local_view_commitment"],
        first["local_view_commitment"]
    );
}

#[test]
fn block_byte_limits_and_native_work_cancellation_never_return_a_partial_census() {
    let (_directory, node, _) = one_block(false);
    let before = node.stats().unwrap();
    for limits in [
        OwnerCensusLimits {
            maximum_blocks: 1,
            ..OwnerCensusLimits::default()
        },
        OwnerCensusLimits {
            maximum_packet_bytes: 1,
            ..OwnerCensusLimits::default()
        },
    ] {
        let error = node.native_owner_census(100, limits).unwrap_err();
        assert!(error.to_string().contains("BUDGET"));
    }
    for cancel_at_work in [true, false] {
        let error = node
            .native_owner_census_with_progress(100, OwnerCensusLimits::default(), &|point| {
                if (cancel_at_work
                    && matches!(
                        point,
                        OwnerCensusProgress::Work(pon_work::VerificationProgress::BeforeReplay)
                    ))
                    || (!cancel_at_work && matches!(point, OwnerCensusProgress::BeforeOutput))
                {
                    Err(Error::new(ErrorCode::LegacyRequestDeadline))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.is(ErrorCode::LegacyRequestDeadline));
        assert!(!error.requires_owner_stop());
    }
    assert_eq!(node.stats().unwrap(), before);
    assert_eq!(census(&node)["owner_attempt"], 5);
}

#[test]
fn callback_error_text_never_acquires_retained_data_stop_authority() {
    let (_directory, node, _) = one_block(false);
    let error = node
        .native_owner_census_with_progress(100, OwnerCensusLimits::default(), &|point| {
            if matches!(point, OwnerCensusProgress::BeforeOutput) {
                Err(Error::from("ROOT"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "ROOT");
    assert!(!error.requires_owner_stop());
    assert!(node
        .native_owner_census(100, OwnerCensusLimits::default())
        .is_ok());
}

#[test]
fn foreign_state_changing_commit_during_read_snapshot_is_detected_after_release() {
    let (directory, node, _) = one_block(false);
    let foreign = Mutex::new(Connection::open(directory.path().join("native.sqlite")).unwrap());
    let changed = AtomicBool::new(false);
    let before = node.stats().unwrap();
    let error = node
        .native_owner_census_with_progress(100, OwnerCensusLimits::default(), &|point| {
            if matches!(point, OwnerCensusProgress::BeforeOutput)
                && !changed.swap(true, Ordering::SeqCst)
            {
                // An actual foreign data change advances SQLite's data_version.
                // A no-op UPDATE can write no page and has no such guarantee.
                foreign.lock().unwrap().execute(
                    "INSERT INTO metadata(key,value) VALUES('census-test-foreign-change',X'01')",
                    [],
                )?;
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "OWNER_CENSUS_EPOCH_CHANGED");
    assert!(changed.load(Ordering::SeqCst));
    assert_eq!(node.stats().unwrap(), before);
    assert!(node
        .native_owner_census(100, OwnerCensusLimits::default())
        .is_ok());
}

#[test]
fn prior_filtering_sql_view_cannot_hide_an_admitted_fork_from_a_complete_census() {
    let (directory, mut node, _) = one_block(false);
    let rival = node
        .make(
            node.settings().genesis(),
            vec![],
            development_public(2).unwrap(),
            12,
            4096,
        )
        .unwrap();
    let rival_id = node.admit(&rival, 100).unwrap();
    assert_eq!(census(&node)["rows"].as_array().unwrap().len(), 3);
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    foreign
        .execute_batch("ALTER TABLE blocks RENAME TO blocks_hidden;")
        .unwrap();
    foreign
        .execute_batch(&format!(
            "CREATE VIEW blocks AS SELECT * FROM blocks_hidden WHERE id != X'{}';",
            hex::encode(rival_id)
        ))
        .unwrap();
    let error = node
        .native_owner_census(100, OwnerCensusLimits::default())
        .unwrap_err();
    assert_eq!(error.to_string(), "OWNER_CENSUS_SCHEMA");
    assert!(error.requires_owner_stop());
}

#[test]
fn corrupted_retained_product_is_reverified_instead_of_trusting_admitted_metadata() {
    let (directory, node, packet) = one_block(false);
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let mut corrupt = packet.clone();
    corrupt.proof[4 + 2 * pon_work::CELLS * 4] ^= 1;
    assert_eq!(corrupt.id().unwrap(), packet.id().unwrap());
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![corrupt.encode().unwrap(), packet.id().unwrap().as_slice()],
        )
        .unwrap();
    let error = node
        .native_owner_census(100, OwnerCensusLimits::default())
        .unwrap_err();
    assert!(error.to_string().starts_with("WORK:"), "{error}");
    assert!(error.requires_owner_stop());
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![packet.encode().unwrap(), packet.id().unwrap().as_slice()],
        )
        .unwrap();
    assert!(node
        .native_owner_census(100, OwnerCensusLimits::default())
        .is_ok());
}

#[test]
fn retained_chainwork_or_missing_packet_cannot_be_certified() {
    let (directory, node, packet) = one_block(false);
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let id = packet.id().unwrap();
    foreign
        .execute(
            "UPDATE blocks SET chainwork=? WHERE id=?",
            params![[0_u8; 64].as_slice(), id.as_slice()],
        )
        .unwrap();
    assert!(node
        .native_owner_census(100, OwnerCensusLimits::default())
        .is_err());
    let work = consensus::required_work(packet.header.target)
        .unwrap()
        .bytes();
    foreign
        .execute(
            "UPDATE blocks SET chainwork=?,packet=NULL WHERE id=?",
            params![work.as_slice(), id.as_slice()],
        )
        .unwrap();
    assert!(node
        .native_owner_census(100, OwnerCensusLimits::default())
        .is_err());
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![packet.encode().unwrap(), id.as_slice()],
        )
        .unwrap();
    assert!(node
        .native_owner_census(100, OwnerCensusLimits::default())
        .is_ok());
}

#[test]
fn pnp2_growth_is_explicitly_unsupported_without_a_pnp1_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2("owner-census-unsupported-pnp2")
    .unwrap();
    let node = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
    let error = node
        .native_owner_census(100, OwnerCensusLimits::default())
        .unwrap_err();
    assert_eq!(error.to_string(), "OWNER_CENSUS_PROFILE_UNSUPPORTED");
}

#[test]
fn actual_two_owner_execution_covers_hidden_inventory_six_successors_ties_reorg_and_time_maturity()
{
    let run = scenario::run().unwrap();
    let report = &run.report;
    assert_eq!(report["native_execution_exercised"], true);
    assert_eq!(report["native_runtime_attested"], false);
    assert_eq!(report["confirmations"][0]["confirmed"], true);
    assert_eq!(report["confirmations"][1]["reorged"], true);
    assert_eq!(report["confirmations"][1]["confirmed"], false);
    let snapshots = report["snapshots"].as_array().unwrap();
    let get =
        |name: &str| -> &Value { &snapshots.iter().find(|r| r["name"] == name).unwrap()["census"] };
    assert_eq!(snapshots.len(), 11);
    assert_eq!(
        get("alice_before_hidden_branch")["local_view_commitment"],
        get("alice_after_hidden_branch")["local_view_commitment"]
    );
    assert_eq!(get("bob_unseen_a1")["rows"].as_array().unwrap().len(), 1);
    let deferred = get("alice_future_ancestor_deferred");
    let child = &report["references"]["current_time_child"];
    let child_row = deferred["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == *child)
        .unwrap();
    assert!(
        child_row["timestamp"].as_u64().unwrap()
            <= deferred["observed_now"].as_u64().unwrap()
                + deferred["future_skew_seconds"].as_u64().unwrap()
    );
    assert_eq!(child_row["ancestry_time_eligible"], false);
    let reorg = get("alice_after_strict_reorg_b8");
    assert_ne!(reorg["raw_selection_deficit_hex"], "0".repeat(128));
    assert_eq!(
        reorg["active_tip"],
        report["references"]["hidden_competing_tip"]
    );
    let mature = get("alice_future_mature_pending");
    assert_eq!(mature["active_tip"], reorg["active_tip"]);
    assert!(mature["eligible_max_ids"]
        .as_array()
        .unwrap()
        .contains(child));
    for snapshot in snapshots {
        no_global_claim(&snapshot["census"]);
    }
    assert_eq!(
        report["packet_artifacts"].as_array().unwrap().len(),
        run.artifacts.len()
    );
    assert!(run
        .artifacts
        .iter()
        .any(|p| p.kind == "invalid_product_control"));
    assert!(run
        .artifacts
        .iter()
        .all(|p| p.bytes.len() > pon_work::PROOF_BYTES));
    assert!(run
        .artifacts
        .iter()
        .any(|p| hex::encode(p.id) == report["references"]["target_block"]));
}
