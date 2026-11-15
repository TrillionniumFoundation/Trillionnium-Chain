use super::*;
use crate::pon_executor::{root_for_config, State};
use serde_json::json;
use trnm_protocol::pon_wire::Header;

fn source(state: State) -> (Config, SourcePins, CheckpointMaterial) {
    let cfg = Config::installed().unwrap();
    let material = CheckpointMaterial {
        genesis: [81; 32],
        trace: [82; 32],
        header: Header {
            network: cfg.network,
            parameters: cfg.parameters,
            parent: [83; 32],
            height: 10,
            timestamp: 1200,
            target: [255; 32],
            miner: [84; 32],
            transactions: [0; 32],
            state: root_for_config(&state, &cfg).unwrap(),
            receipts: [0; 32],
            work_task: [85; 32],
            nonce: 0,
        },
        state,
    };
    let pins = SourcePins {
        network: cfg.network,
        genesis: material.genesis,
        checkpoint: material.header.block_id(material.trace),
    };
    (cfg, pins, material)
}
fn empty() -> State {
    State::from([
        ("meta:issued".into(), json!(0)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
    ])
}

#[test]
fn empty_ledger_inventory_never_certifies_external_obligations_or_retirement() {
    let (cfg, pins, material) = source(empty());
    let report = inspect_checkpoint(pins, &material, &cfg).unwrap();
    assert_eq!(report.disposition, LedgerDisposition::NoLedgerCarryFound);
    assert_eq!(report.state_rows, 2);
    assert_eq!(report.inert_metadata_rows, 2);
    assert_eq!(report.unresolved_scope.len(), 5);
    let json = serde_json::to_value(&report).unwrap();
    assert!(json.get("activation_authorized").is_none());
    assert!(json.get("source_retired").is_none());
    assert_eq!(material.state, empty());
}

#[test]
fn zero_accounts_and_nonce_floors_are_preserved_as_identity_obligations() {
    for nonce in [0, 7, u64::MAX] {
        let mut state = empty();
        state.insert(
            format!("account:{}", hex::encode([1; 32])),
            json!({"balance":0,"nonce":nonce}),
        );
        let (cfg, pins, material) = source(state);
        let report = inspect_checkpoint(pins, &material, &cfg).unwrap();
        assert_eq!(report.disposition, LedgerDisposition::PreservationRequired);
        assert_eq!(report.accounts.rows, 1);
        assert_eq!(report.accounts.nonzero_rows, 0);
        assert_eq!(report.accounts_with_nonce_floor, usize::from(nonce > 0));
        assert_eq!(report.greatest_nonce_floor, nonce);
    }
}

#[test]
fn all_monetary_namespaces_and_zero_obligations_are_counted_without_netting() {
    let mut state = empty();
    state.insert("meta:issued".into(), json!(150));
    state.insert(
        format!("account:{}", hex::encode([1; 32])),
        json!({"balance":10,"nonce":9}),
    );
    // These fixtures exercise the inventory, not original task execution.
    for (prefix, field, amount) in [
        ("task", "remaining", 20),
        ("quota", "remaining", 30),
        ("release", "remaining", 40),
        ("reward", "amount", 50),
    ] {
        state.insert(
            format!("{prefix}:{}", hex::encode([2; 32])),
            json!({field:amount}),
        );
        state.insert(
            format!("{prefix}:{}", hex::encode([3; 32])),
            json!({field:0}),
        );
    }
    let (cfg, pins, material) = source(state.clone());
    let report = inspect_checkpoint(pins, &material, &cfg).unwrap();
    assert_eq!(report.issued_units, 150);
    for (rows, units) in [
        (&report.tasks, 20),
        (&report.quotas, 30),
        (&report.releases, 40),
        (&report.rewards, 50),
    ] {
        assert_eq!(rows.rows, 2);
        assert_eq!(rows.nonzero_rows, 1);
        assert_eq!(rows.units, units);
    }
    assert_eq!(report.state_rows, report.inert_metadata_rows + 9);
    assert_eq!(report.disposition, LedgerDisposition::PreservationRequired);
    assert_eq!(material.state, state);
}

#[test]
fn unknown_debt_revocation_execution_and_active_model_rows_block_empty_inference() {
    for key in [
        "debt:legacy",
        "revoked:legacy",
        "execution:pending",
        "model:current",
    ] {
        let mut state = empty();
        state.insert(key.into(), json!("needs-independent-owner"));
        let (cfg, pins, material) = source(state);
        let report = inspect_checkpoint(pins, &material, &cfg).unwrap();
        assert_eq!(report.disposition, LedgerDisposition::PreservationRequired);
        assert_eq!(report.unclassified_rows, 1);
        assert_eq!(report.unclassified_key_examples, vec![key]);
    }
}

#[test]
fn inventory_counts_every_opaque_row_but_bounds_diagnostic_key_examples() {
    let mut state = empty();
    for i in 0..100 {
        state.insert(format!("external:{i:03}"), json!(0));
    }
    let (cfg, pins, material) = source(state);
    let report = inspect_checkpoint(pins, &material, &cfg).unwrap();
    assert_eq!(report.unclassified_rows, 100);
    assert_eq!(report.unclassified_key_examples.len(), 16);
    assert_eq!(
        report.state_rows,
        report.inert_metadata_rows + report.unclassified_rows
    );
}

#[test]
fn inventory_rejects_wrong_pins_changed_state_and_inconsistent_issued_supply() {
    let (cfg, pins, material) = source(empty());
    for altered in [
        SourcePins {
            network: [91; 32],
            ..pins
        },
        SourcePins {
            genesis: [92; 32],
            ..pins
        },
        SourcePins {
            checkpoint: [93; 32],
            ..pins
        },
    ] {
        assert_eq!(
            inspect_checkpoint(altered, &material, &cfg).unwrap_err(),
            "PQ_INVENTORY_CHECKPOINT"
        );
    }
    let mut changed = material.clone();
    changed.state.insert("hidden:liability".into(), json!(0));
    assert_eq!(
        inspect_checkpoint(pins, &changed, &cfg).unwrap_err(),
        "PQ_INVENTORY_ROOT"
    );
    let mut inconsistent = empty();
    inconsistent.insert("meta:issued".into(), json!(1));
    let (cfg, pins, material) = source(inconsistent);
    assert_eq!(
        inspect_checkpoint(pins, &material, &cfg).unwrap_err(),
        "CONSERVATION"
    );
}

#[test]
fn malformed_account_is_not_relabelled_as_an_empty_ledger() {
    let mut state = empty();
    state.insert(
        format!("account:{}", hex::encode([1; 32])),
        json!({"balance":0,"nonce":0,"retired":true}),
    );
    let (cfg, pins, material) = source(state);
    assert_eq!(
        inspect_checkpoint(pins, &material, &cfg).unwrap_err(),
        "PQ_INVENTORY_ACCOUNT"
    );
}
