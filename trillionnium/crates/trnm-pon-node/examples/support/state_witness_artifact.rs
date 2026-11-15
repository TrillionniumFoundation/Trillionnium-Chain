//! Companion observations reuse the actual signed/admitted account fixture.
//! No private data, network operation, or alternate consensus admission is used.
use super::{rows, Fixture};
use serde_json::{json, Value};
use std::sync::Mutex;
use trnm_mvcc_fee::pon_executor;
use trnm_pon_node::account_archive_execution::{
    self,
    state_witness::{
        StateCommitment, StateRow, StateWitness, StateWitnessError, StateWitnessProgress,
    },
    BlockInput, CheckedExecutionError, StateExecutionInput,
};
use trnm_protocol::pon_wire::hash;

struct Case {
    label: &'static str,
    source: &'static str,
    witness: StateWitness,
    cancel_at: Option<StateWitnessProgress>,
    expected: CheckedExecutionError,
}

fn base(
    fixture: &Fixture,
    source: &'static str,
    label: &'static str,
    code: StateWitnessError,
) -> Case {
    let row = fixture
        .state_witness_blocks
        .as_ref()
        .unwrap()
        .iter()
        .find(|row| row["label"] == source)
        .unwrap();
    Case {
        label,
        source,
        witness: serde_json::from_value(row["state_witness"].clone()).unwrap(),
        cancel_at: None,
        expected: CheckedExecutionError::StateWitness(code),
    }
}

fn rehash(value: &mut StateCommitment) {
    // A self-consistent public claim remains untrusted. These mutations exercise
    // comparison with the opaque actual-parent anchor, not only digest syntax.
    value.id = hash(
        b"checked-state-commitment-v1",
        &[
            &value.network,
            &value.parameters,
            &value.genesis,
            &value.state_root,
            &value.account_root,
            &value.account_count.to_le_bytes(),
            &value.account_balance.to_le_bytes(),
            &value.non_account_root,
            &value.non_account_count.to_le_bytes(),
            &value.escrow_balance.to_le_bytes(),
            &value.reward_balance.to_le_bytes(),
            &value.issued.to_le_bytes(),
        ],
    );
}

fn binding(fixture: &Fixture) -> Value {
    let active = fixture.node.read_active().unwrap();
    json!({"native_active":active.0,"native_height":active.1,
        "native_state_root":pon_executor::root(&active.2).unwrap(),
        "archive_active":fixture.archive.active().unwrap(),
        "archive_storage":fixture.archive.observation().unwrap(),
        "archive_rows_hash":hash(b"account-execution-observed-rows-v1",
            &[&serde_json::to_vec(&rows(&fixture.archive_path)).unwrap()])})
}

fn reject(fixture: &Fixture, case: Case) -> Value {
    let original = fixture
        .blocks
        .iter()
        .find(|row| row["label"] == case.source)
        .unwrap();
    let parent = serde_json::from_value(original["parent"].clone()).unwrap();
    let checkpoint = serde_json::from_value(original["parent_checkpoint"]["id"].clone()).unwrap();
    let state: pon_executor::State =
        serde_json::from_value(original["parent_state"].clone()).unwrap();
    let miner = serde_json::from_value(original["miner"].clone()).unwrap();
    let transactions: Vec<_> = original["transactions_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| hex::decode(raw.as_str().unwrap()).unwrap())
        .collect();
    let witnesses: Vec<_> = serde_json::from_value(original["witnesses"].clone()).unwrap();
    let before_state = state.clone();
    let before_witness = case.witness.clone();
    let before = binding(fixture);
    let stages = Mutex::new(Vec::new());
    let error = account_archive_execution::execute_with_state_witness_and_progress(
        &fixture.settings,
        &fixture.archive,
        checkpoint,
        &state,
        BlockInput {
            transactions: &transactions,
            height: original["height"].as_u64().unwrap(),
            miner,
            parent_id: parent,
        },
        StateExecutionInput {
            accounts: &witnesses,
            state: &case.witness,
        },
        &|stage| {
            stages.lock().unwrap().push(format!("{stage:?}"));
            if Some(stage) == case.cancel_at {
                Err(CheckedExecutionError::Cancelled)
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert_eq!(error, case.expected, "{}", case.label);
    assert_eq!(state, before_state);
    assert_eq!(case.witness, before_witness);
    let after = binding(fixture);
    assert_eq!(after, before);
    let outcome = match error {
        CheckedExecutionError::StateWitness(code) => {
            json!({"kind":"state_witness","code":format!("{code:?}")})
        }
        other => json!({"kind":"checked","code":format!("{other:?}")}),
    };
    json!({"label":case.label,"source_positive_label":case.source,"state_witness":case.witness,
        "cancel_at":case.cancel_at.map(|stage| format!("{stage:?}")),"outcome":outcome,
        "progress":stages.into_inner().unwrap(),"before":before,"after":after,
        "parent_unchanged":true,"archive_unchanged":true,"input_witness_unchanged":true})
}

pub(super) fn negative_cases(fixture: &mut Fixture) -> Vec<Value> {
    let mut cases = Vec::new();
    let mut case = base(
        fixture,
        "main-01",
        "witness-parent-checkpoint",
        StateWitnessError::Context,
    );
    case.witness.parent_checkpoint[0] ^= 1;
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "witness-parent-id",
        StateWitnessError::Context,
    );
    case.witness.parent_id[0] ^= 1;
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "witness-parent-height",
        StateWitnessError::Context,
    );
    case.witness.parent_height += 1;
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "commitment-id",
        StateWitnessError::Commitment,
    );
    case.witness.commitment.id[0] ^= 1;
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "commitment-account-count",
        StateWitnessError::Commitment,
    );
    case.witness.commitment.account_count += 1;
    rehash(&mut case.witness.commitment);
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "commitment-account-balance",
        StateWitnessError::Commitment,
    );
    case.witness.commitment.account_balance += 1;
    rehash(&mut case.witness.commitment);
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "commitment-issued",
        StateWitnessError::Commitment,
    );
    case.witness.commitment.issued += 1;
    rehash(&mut case.witness.commitment);
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "commitment-context",
        StateWitnessError::Commitment,
    );
    case.witness.commitment.parameters[0] ^= 1;
    rehash(&mut case.witness.commitment);
    cases.push(case);
    for (source, label, prefix, remaining) in [
        ("main-02", "missing-future-reward", "reward:", None),
        ("main-02", "missing-future-task", "task:", Some(false)),
        ("main-13", "missing-cleanup-task", "task:", Some(true)),
        (
            "main-01",
            "missing-maintenance",
            "consensus-maintenance-v1",
            None,
        ),
    ] {
        let mut case = base(fixture, source, label, StateWitnessError::Partition);
        let index = case
            .witness
            .non_accounts
            .iter()
            .position(|row| {
                row.key.starts_with(prefix)
                    && remaining
                        .is_none_or(|zero| (row.value["remaining"].as_u64().unwrap() == 0) == zero)
            })
            .unwrap();
        let removed = case.witness.non_accounts.remove(index);
        if label == "missing-future-reward" {
            assert!(removed.value["maturity"].as_u64().unwrap() > 2);
        }
        if label == "missing-future-task" {
            assert!(removed.value["deadline"].as_u64().unwrap() > 2);
        }
        if label == "missing-cleanup-task" {
            assert!(removed.value["deadline"].as_u64().unwrap() < 13);
        }
        cases.push(case);
    }
    let mut case = base(
        fixture,
        "main-01",
        "changed-non-account-value",
        StateWitnessError::Partition,
    );
    case.witness
        .non_accounts
        .iter_mut()
        .find(|row| row.key == "meta:issued")
        .unwrap()
        .value = json!(40_000_001);
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "duplicate-non-account",
        StateWitnessError::CanonicalOrder,
    );
    case.witness
        .non_accounts
        .push(case.witness.non_accounts.last().unwrap().clone());
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "reordered-non-accounts",
        StateWitnessError::CanonicalOrder,
    );
    case.witness.non_accounts.swap(0, 1);
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "injected-account-row",
        StateWitnessError::AccountRow,
    );
    case.witness.non_accounts.insert(
        0,
        StateRow {
            key: format!("account:{}", hex::encode(super::key(0))),
            value: json!({"balance":10_000_000,"nonce":0}),
        },
    );
    cases.push(case);
    let mut case = base(
        fixture,
        "main-01",
        "extra-non-account",
        StateWitnessError::Partition,
    );
    case.witness.non_accounts.push(StateRow {
        key: "unrecognized-retained-key".into(),
        value: Value::Null,
    });
    cases.push(case);
    for (label, point) in [
        (
            "cancel-before-mandatory",
            StateWitnessProgress::BeforeMandatoryVerification,
        ),
        (
            "cancel-after-mandatory",
            StateWitnessProgress::AfterMandatoryVerification,
        ),
        (
            "cancel-before-successor",
            StateWitnessProgress::BeforeSuccessorVerification,
        ),
        (
            "cancel-after-successor",
            StateWitnessProgress::AfterSuccessorVerification,
        ),
        ("cancel-before-output", StateWitnessProgress::BeforeOutput),
    ] {
        let mut case = base(fixture, "main-01", label, StateWitnessError::Observation);
        case.cancel_at = Some(point);
        case.expected = CheckedExecutionError::Cancelled;
        cases.push(case);
    }
    assert_eq!(cases.len(), 22);
    cases
        .into_iter()
        .map(|case| reject(fixture, case))
        .collect()
}
