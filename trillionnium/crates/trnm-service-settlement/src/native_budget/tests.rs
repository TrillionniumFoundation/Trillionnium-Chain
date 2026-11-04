//! Adapter/journal counterexamples with an explicitly synthetic owner. These
//! rows test accounting, never claim that fixture JSON authenticates a chain.
//! The real Node owner bridge and ordinary native transfers require integration tests.
use super::*;
use serde_json::json;

fn configuration() -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        max_records: 32,
    }
}
fn anchor() -> NativeBudgetAnchorV1 {
    NativeBudgetAnchorV1 {
        network: [1; 32],
        parameters: [2; 32],
        genesis: [3; 32],
        block: [4; 32],
        state_root: [5; 32],
        height: 5,
        generation: 0,
    }
}
#[derive(Clone)]
struct SyntheticOwner {
    anchor: NativeBudgetAnchorV1,
    rows: BTreeMap<NativeFundingSourceV1, Value>,
    payment: Option<NativePaymentObservationV1>,
}
impl SyntheticOwner {
    fn new() -> Self {
        Self {
            anchor: anchor(),
            rows: BTreeMap::new(),
            payment: None,
        }
    }
    fn advance(&mut self, height: u64) {
        self.anchor.generation += 1;
        self.anchor.height = height;
        self.anchor.block = [self.anchor.generation as u8 + 10; 32];
        self.anchor.state_root = [self.anchor.generation as u8 + 20; 32];
    }
}
impl NativeFundingOwnerV1 for SyntheticOwner {
    fn observe_funding(
        &mut self,
        source: NativeFundingSourceV1,
    ) -> NativeBudgetResultV1<NativeFundingObservationV1> {
        Ok(NativeFundingObservationV1 {
            anchor: self.anchor,
            source,
            row: self.rows.get(&source).cloned(),
        })
    }
    fn observe_payment(
        &mut self,
        _query: &NativePaymentQueryV1,
    ) -> NativeBudgetResultV1<NativePaymentObservationV1> {
        self.payment.clone().ok_or(NativeBudgetErrorV1::Invalid(
            "NATIVE_PAYMENT_PROOF_UNAVAILABLE",
        ))
    }
}
fn source(lane: NativeBudgetLaneV1, seed: u8) -> NativeFundingSourceV1 {
    match lane {
        NativeBudgetLaneV1::Mining => NativeFundingSourceV1::Reward([seed; 32]),
        NativeBudgetLaneV1::Contribution => NativeFundingSourceV1::Release([seed; 32]),
        NativeBudgetLaneV1::Evaluation
        | NativeBudgetLaneV1::Storage
        | NativeBudgetLaneV1::Repair => NativeFundingSourceV1::Task([seed; 32]),
        NativeBudgetLaneV1::Serving => NativeFundingSourceV1::Quota([seed; 32]),
    }
}
fn resources(lane: NativeBudgetLaneV1, n: u64) -> NativeBudgetResourcesV1 {
    match lane {
        NativeBudgetLaneV1::Mining => NativeBudgetResourcesV1::Mining {
            verified_work_units: n,
            cpu_ns: n,
        },
        NativeBudgetLaneV1::Contribution => NativeBudgetResourcesV1::Contribution {
            training_cpu_ns: n,
            parameter_bytes: n,
        },
        NativeBudgetLaneV1::Evaluation => NativeBudgetResourcesV1::Evaluation {
            evaluation_cpu_ns: n,
            evaluated_examples: n,
        },
        NativeBudgetLaneV1::Storage => NativeBudgetResourcesV1::Storage {
            retained_bytes: n,
            retained_byte_blocks: n,
        },
        NativeBudgetLaneV1::Repair => NativeBudgetResourcesV1::Repair {
            cpu_ns: n,
            download_bytes: n,
            upload_bytes: n,
            attempts: n,
        },
        NativeBudgetLaneV1::Serving => NativeBudgetResourcesV1::Serving {
            inference_cpu_ns: n,
            output_tokens: n,
        },
    }
}
fn native_row(lane: NativeBudgetLaneV1) -> Value {
    let mut row = json!({"owner":hex_string(&[9;32]),"remaining":100,"provider":hex_string(&[8;32]),"deadline":100,"status":"reserved","output":null});
    match lane {
        NativeBudgetLaneV1::Mining => {
            row = json!({"owner":hex_string(&[9;32]),"amount":100,"maturity":10})
        }
        NativeBudgetLaneV1::Contribution => {
            row["status"] = json!("open");
            row["budget"] = json!(100);
            row["total"] = json!(10);
            row["maturity"] = json!(10);
            row["root"] = json!(hex_string(&[7; 32]));
            row["claims"] = json!({});
        }
        NativeBudgetLaneV1::Serving => {
            row["consumer"] = json!(hex_string(&[6; 32]));
            row["units"] = json!(10);
        }
        _ => {}
    }
    row
}
fn setup(
    lane: NativeBudgetLaneV1,
) -> (
    tempfile::TempDir,
    NativeBudgetStoreV1,
    SyntheticOwner,
    NativeBudgetPolicyV1,
    NativeBudgetClaimV1,
) {
    let directory = tempfile::tempdir().unwrap();
    let mut store =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .unwrap();
    let mut owner = SyntheticOwner::new();
    let source = source(lane, 40);
    owner.rows.insert(source, native_row(lane));
    let policy = NativeBudgetPolicyV1 {
        budget: [50; 32],
        source,
        monetary_cap: 100,
        deadline: 80,
        resource_cap: resources(lane, 10),
        max_inflight: 2,
    };
    assert_eq!(
        store.open_budget(&mut owner, policy.clone()).unwrap(),
        NativeBudgetReplayV1::New
    );
    let claim = NativeBudgetClaimV1 {
        claim: [60; 32],
        budget: policy.budget,
        subject: if lane == NativeBudgetLaneV1::Mining {
            [40; 32]
        } else {
            [70; 32]
        },
        beneficiary: if lane == NativeBudgetLaneV1::Mining {
            [9; 32]
        } else {
            [8; 32]
        },
        monetary_reservation: if matches!(
            source,
            NativeFundingSourceV1::Task(_) | NativeFundingSourceV1::Reward(_)
        ) {
            100
        } else {
            20
        },
        resource_reservation: resources(lane, 4),
    };
    (directory, store, owner, policy, claim)
}

#[test]
fn all_six_lanes_bind_actual_row_shapes_and_payment_stays_an_owner_proof() {
    for lane in [
        NativeBudgetLaneV1::Mining,
        NativeBudgetLaneV1::Contribution,
        NativeBudgetLaneV1::Evaluation,
        NativeBudgetLaneV1::Storage,
        NativeBudgetLaneV1::Repair,
        NativeBudgetLaneV1::Serving,
    ] {
        let (directory, mut store, mut owner, policy, claim) = setup(lane);
        store.reserve(&mut owner, claim.clone()).unwrap();
        assert_eq!(
            store
                .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
                .unwrap(),
            NativeBudgetReplayV1::New
        );
        store
            .record_resources(
                claim.claim,
                NativeResourceOutcomeV1::Positive,
                Some(resources(lane, 3)),
            )
            .unwrap();
        store
            .complete_effect(claim.claim, [80; 32], [82; 32])
            .unwrap();
        let payment_operation = if lane == NativeBudgetLaneV1::Mining {
            claim.subject
        } else {
            [83; 32]
        };
        assert!(store
            .record_native_payment(&mut owner, claim.claim, payment_operation)
            .is_err());
        owner.advance(12);
        owner.payment = Some(NativePaymentObservationV1 {
            anchor: owner.anchor,
            source: policy.source,
            subject: claim.subject,
            beneficiary: claim.beneficiary,
            operation: payment_operation,
            gross_escrow_debit: claim.monetary_reservation,
            beneficiary_credit: claim.monetary_reservation
                - u64::from(lane == NativeBudgetLaneV1::Serving),
        });
        assert_eq!(
            store
                .record_native_payment(&mut owner, claim.claim, payment_operation)
                .unwrap(),
            NativeBudgetReplayV1::New
        );
        assert_eq!(
            store
                .record_native_payment(&mut owner, claim.claim, payment_operation)
                .unwrap(),
            NativeBudgetReplayV1::Done
        );
        let report = store.report().unwrap();
        assert_eq!(
            report["budgets"][0]["historically_observed_native_gross_debit"],
            claim.monetary_reservation
        );
        assert_eq!(report["authorizes_native_payment"], false);
        assert_eq!(report["current_branch_payment_finality"], false);
        drop(store);
        assert_eq!(
            NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
                .unwrap()
                .report()
                .unwrap(),
            report
        );
    }
}

#[test]
fn source_is_rechecked_before_each_new_effect_and_cannot_be_reassigned_across_lanes() {
    let (_directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let before = store.report().unwrap();
    let mut other = policy.clone();
    other.budget = [51; 32];
    other.resource_cap = resources(NativeBudgetLaneV1::Repair, 10);
    assert!(store
        .open_budget(&mut owner, other)
        .unwrap_err()
        .to_string()
        .contains("SOURCE_REPIN"));
    for changed in [json!(0), json!(true), json!("100"), json!(1.5)] {
        owner.rows.get_mut(&policy.source).unwrap()["remaining"] = changed;
        assert!(store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .is_err());
        assert_eq!(store.report().unwrap(), before);
    }
    owner
        .rows
        .insert(policy.source, native_row(NativeBudgetLaneV1::Storage));
    owner.rows.get_mut(&policy.source).unwrap()["provider"] = json!(hex_string(&[88; 32]));
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .is_err());
    owner.rows.remove(&policy.source);
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .is_err());
    assert_eq!(store.report().unwrap(), before);
}

#[test]
fn reorg_and_restart_preserve_pending_and_completed_effects_without_redispatch() {
    let (directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
    owner.advance(2);
    owner.rows.remove(&policy.source);
    drop(store);
    let mut store =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .unwrap();
    assert_eq!(
        store.reserve(&mut owner, claim.clone()).unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
    let mut new = claim.clone();
    new.claim = [61; 32];
    new.subject = [71; 32];
    assert!(store.reserve(&mut owner, new.clone()).is_err());
    store
        .record_resources(claim.claim, NativeResourceOutcomeV1::Unknown, None)
        .unwrap();
    assert_eq!(
        store.report().unwrap()["budgets"][0]["resource_charge"],
        json!([4, 4, 0, 0])
    );
    store
        .complete_effect(claim.claim, [80; 32], [82; 32])
        .unwrap();
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [89; 32])
        .is_err());
    assert!(store
        .complete_effect(claim.claim, [80; 32], [89; 32])
        .is_err());
    owner.advance(6);
    owner
        .rows
        .insert(policy.source, native_row(NativeBudgetLaneV1::Serving));
    new.subject = claim.subject;
    assert!(store
        .reserve(&mut owner, new)
        .unwrap_err()
        .to_string()
        .contains("SUBJECT_REPLAY"));
}

#[test]
fn unknown_cost_is_full_and_repair_dimensions_are_independently_bounded() {
    let (_directory, mut store, mut owner, _policy, mut claim) = setup(NativeBudgetLaneV1::Repair);
    for dimension in 0..4 {
        let mut v = [1; 4];
        v[dimension] = 11;
        claim.resource_reservation = NativeBudgetResourcesV1::Repair {
            cpu_ns: v[0],
            download_bytes: v[1],
            upload_bytes: v[2],
            attempts: v[3],
        };
        assert!(store
            .reserve(&mut owner, claim.clone())
            .unwrap_err()
            .to_string()
            .contains("RESOURCES"));
    }
    claim.resource_reservation = resources(NativeBudgetLaneV1::Repair, 4);
    store.reserve(&mut owner, claim.clone()).unwrap();
    assert!(store
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::Unknown,
            Some(resources(NativeBudgetLaneV1::Repair, 0))
        )
        .is_err());
    store
        .record_resources(claim.claim, NativeResourceOutcomeV1::Unknown, None)
        .unwrap();
    assert_eq!(
        store.report().unwrap()["budgets"][0]["resource_charge"],
        json!([4, 4, 4, 4])
    );
    assert!(store
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::Positive,
            Some(resources(NativeBudgetLaneV1::Repair, 1))
        )
        .is_err());
    assert_eq!(
        store.report().unwrap()["budgets"][0]["committed_units"],
        100
    );
}

#[test]
fn expiry_charges_unknown_jobs_without_removing_pending_target_intents() {
    let (directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
    assert!(store.close_expired(&mut owner, policy.budget).is_err());
    owner.advance(policy.deadline);
    owner.rows.remove(&policy.source);
    store.close_expired(&mut owner, policy.budget).unwrap();
    let report = store.report().unwrap();
    assert_eq!(report["budgets"][0]["closed"], true);
    assert_eq!(report["budgets"][0]["resource_charge"], json!([4, 4, 0, 0]));
    assert_eq!(report["budgets"][0]["pending_effects"], 1);
    drop(store);
    let mut store =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .unwrap();
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
    store
        .complete_effect(claim.claim, [80; 32], [82; 32])
        .unwrap();
}

#[test]
fn payment_requires_exact_source_beneficiary_operation_and_real_fee_split() {
    let (_directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::Positive,
            Some(resources(NativeBudgetLaneV1::Serving, 2)),
        )
        .unwrap();
    let correct = NativePaymentObservationV1 {
        anchor: owner.anchor,
        source: policy.source,
        subject: claim.subject,
        beneficiary: claim.beneficiary,
        operation: [90; 32],
        gross_escrow_debit: 20,
        beneficiary_credit: 18,
    };
    let before = store.report().unwrap();
    for field in 0..6 {
        let mut bad = correct.clone();
        match field {
            0 => bad.source = NativeFundingSourceV1::Quota([41; 32]),
            1 => bad.subject = [71; 32],
            2 => bad.beneficiary = [99; 32],
            3 => bad.operation = [91; 32],
            4 => bad.gross_escrow_debit = 21,
            _ => bad.beneficiary_credit = 21,
        }
        owner.payment = Some(bad);
        assert!(store
            .record_native_payment(&mut owner, claim.claim, [90; 32])
            .is_err());
        assert_eq!(store.report().unwrap(), before);
    }
    owner.payment = Some(correct);
    store
        .record_native_payment(&mut owner, claim.claim, [90; 32])
        .unwrap();
    assert_eq!(
        store.report().unwrap()["budgets"][0]["historically_observed_beneficiary_credit"],
        18
    );
}

#[test]
fn old_owner_generation_and_context_cannot_authorize_new_jobs() {
    let (_directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Serving);
    owner.advance(6);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let current = owner.anchor;
    for field in 0..3 {
        owner.anchor = current;
        match field {
            0 => owner.anchor.generation = 0,
            1 => owner.anchor.block = [99; 32],
            _ => owner.anchor.network = [99; 32],
        }
        assert!(store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .is_err());
    }
    owner.anchor = current;
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
}

#[test]
fn journal_damage_foreign_store_and_policy_repin_are_fail_closed() {
    let (directory, mut store, mut owner, mut policy, _claim) = setup(NativeBudgetLaneV1::Serving);
    policy.resource_cap = resources(NativeBudgetLaneV1::Serving, 100);
    assert!(store.open_budget(&mut owner, policy).is_err());
    let path = directory.path().join("budget.sqlite");
    drop(store);
    let database = Connection::open(&path).unwrap();
    database
        .execute(
            "UPDATE native_budget_events_v1 SET root=?1 WHERE sequence=1",
            [[88u8; 32].as_slice()],
        )
        .unwrap();
    drop(database);
    assert!(NativeBudgetStoreV1::open(&path, configuration()).is_err());
    let foreign = directory.path().join("foreign.sqlite");
    Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE foreign_balance(amount INTEGER)")
        .unwrap();
    assert!(NativeBudgetStoreV1::open(&foreign, configuration()).is_err());
}

#[test]
fn two_store_handles_cannot_double_reserve_the_same_native_funds() {
    let (directory, store, owner, _policy, claim) = setup(NativeBudgetLaneV1::Serving);
    drop(store);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for seed in [1u8, 2] {
        let path = directory.path().join("budget.sqlite");
        let mut owner = owner.clone();
        let mut claim = claim.clone();
        claim.claim = [seed; 32];
        claim.subject = [seed + 20; 32];
        claim.monetary_reservation = 75;
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = NativeBudgetStoreV1::open(&path, configuration()).unwrap();
            barrier.wait();
            store.reserve(&mut owner, claim).is_ok()
        }));
    }
    assert_eq!(
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
    let report =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .unwrap()
            .report()
            .unwrap();
    assert_eq!(report["claim_count"], 1);
    assert_eq!(report["budgets"][0]["committed_units"], 75);
}

#[test]
fn global_operation_binding_cannot_be_reused_for_another_claim() {
    let (_directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let mut second = claim.clone();
    second.claim = [61; 32];
    second.subject = [71; 32];
    store.reserve(&mut owner, second.clone()).unwrap();
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
    let before = store.report().unwrap();
    assert!(store
        .begin_effect(&mut owner, second.claim, [80; 32], [81; 32])
        .unwrap_err()
        .to_string()
        .contains("OPERATION_REPLAY"));
    assert!(store
        .complete_effect(second.claim, [80; 32], [82; 32])
        .is_err());
    assert_eq!(store.report().unwrap(), before);
}

#[test]
fn journal_namespace_and_length_framing_have_an_exact_independent_vector() {
    assert_eq!(
        hex_string(&event_root([1; 32], 3, b"abc")),
        "541843a630996a05694fd9ec40f9543c524b612b62740eb0c54ecea86ea2204c"
    );
    assert_ne!(
        event_root([1; 32], 3, b"abc"),
        event_root([1; 32], 3, b"abc\0")
    );
}

#[test]
fn task_existing_receipt_must_bind_subject_before_reservation_and_intent() {
    let (_directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Storage);
    owner.advance(6);
    owner.rows.get_mut(&policy.source).unwrap()["status"] = json!("receipt");
    owner.rows.get_mut(&policy.source).unwrap()["output"] = json!(hex_string(&[71; 32]));
    let before = store.report().unwrap();
    assert!(store.reserve(&mut owner, claim.clone()).is_err());
    assert_eq!(store.report().unwrap(), before);
    owner.rows.get_mut(&policy.source).unwrap()["output"] = json!(hex_string(&claim.subject));
    store.reserve(&mut owner, claim.clone()).unwrap();
    let before = store.report().unwrap();
    owner.advance(7);
    for output in [
        Value::Null,
        json!(hex_string(&[0; 32])),
        json!(hex_string(&[71; 32])),
        json!("AB".repeat(32)),
    ] {
        owner.rows.get_mut(&policy.source).unwrap()["output"] = output;
        assert!(store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .is_err());
        assert_eq!(store.report().unwrap(), before);
    }
    owner.rows.get_mut(&policy.source).unwrap()["status"] = json!("reserved");
    owner.rows.get_mut(&policy.source).unwrap()["output"] = json!(hex_string(&claim.subject));
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .is_err());
    owner.rows.get_mut(&policy.source).unwrap()["status"] = json!("receipt");
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::New
    );
}

#[test]
fn release_claim_is_rechecked_before_the_first_external_intent() {
    let (_directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Contribution);
    store.reserve(&mut owner, claim.clone()).unwrap();
    owner.advance(12);
    owner.rows.get_mut(&policy.source).unwrap()["remaining"] = json!(80);
    owner.rows.get_mut(&policy.source).unwrap()["claims"][hex_string(&claim.subject)] = json!(20);
    let before = store.report().unwrap();
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .is_err());
    assert_eq!(store.report().unwrap(), before);
}

#[test]
fn native_reward_budget_and_claim_cannot_invent_fractional_maturation() {
    let (_directory, mut store, mut owner, mut policy, mut claim) =
        setup(NativeBudgetLaneV1::Mining);
    policy.budget = [51; 32];
    policy.source = source(NativeBudgetLaneV1::Mining, 41);
    policy.monetary_cap = 50;
    owner
        .rows
        .insert(policy.source, native_row(NativeBudgetLaneV1::Mining));
    let before = store.report().unwrap();
    assert!(store.open_budget(&mut owner, policy).is_err());
    assert_eq!(store.report().unwrap(), before);
    claim.monetary_reservation = 25;
    assert!(store.reserve(&mut owner, claim.clone()).is_err());
    claim.monetary_reservation = 100;
    store.reserve(&mut owner, claim).unwrap();
}

#[test]
fn native_reward_payment_requires_original_reward_identity_and_entire_amount() {
    let (_directory, mut store, mut owner, policy, mut claim) = setup(NativeBudgetLaneV1::Mining);
    claim.monetary_reservation = 100;
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::Positive,
            Some(resources(NativeBudgetLaneV1::Mining, 2)),
        )
        .unwrap();
    owner.advance(12);
    let mut payment = NativePaymentObservationV1 {
        anchor: owner.anchor,
        source: policy.source,
        subject: claim.subject,
        beneficiary: claim.beneficiary,
        operation: [90; 32],
        gross_escrow_debit: 100,
        beneficiary_credit: 100,
    };
    let before = store.report().unwrap();
    owner.payment = Some(payment.clone());
    assert!(store
        .record_native_payment(&mut owner, claim.claim, [90; 32])
        .is_err());
    assert_eq!(store.report().unwrap(), before);
    payment.operation = claim.subject;
    payment.gross_escrow_debit = 99;
    payment.beneficiary_credit = 99;
    owner.payment = Some(payment.clone());
    assert!(store
        .record_native_payment(&mut owner, claim.claim, claim.subject)
        .is_err());
    assert_eq!(store.report().unwrap(), before);
    payment.gross_escrow_debit = 100;
    payment.beneficiary_credit = 100;
    owner.payment = Some(payment);
    store
        .record_native_payment(&mut owner, claim.claim, claim.subject)
        .unwrap();
}

#[test]
fn native_quota_payment_preserves_zero_credit_when_actual_fee_consumes_gross() {
    let (_directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::Positive,
            Some(resources(NativeBudgetLaneV1::Serving, 2)),
        )
        .unwrap();
    owner.payment = Some(NativePaymentObservationV1 {
        anchor: owner.anchor,
        source: policy.source,
        subject: claim.subject,
        beneficiary: claim.beneficiary,
        operation: [90; 32],
        gross_escrow_debit: 20,
        beneficiary_credit: 0,
    });
    store
        .record_native_payment(&mut owner, claim.claim, [90; 32])
        .unwrap();
    let report = store.report().unwrap();
    assert_eq!(
        report["budgets"][0]["historically_observed_native_gross_debit"],
        20
    );
    assert_eq!(
        report["budgets"][0]["historically_observed_beneficiary_credit"],
        0
    );
}

#[test]
fn closed_source_and_unknown_cost_cannot_be_reallocated_after_reorg() {
    let (directory, mut store, mut owner, mut policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
    owner.advance(policy.deadline);
    store.close_expired(&mut owner, policy.budget).unwrap();
    drop(store);
    let mut store =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .unwrap();
    owner.advance(6);
    policy.budget = [51; 32];
    policy.monetary_cap = 1;
    let before = store.report().unwrap();
    assert!(store.open_budget(&mut owner, policy).is_err());
    assert_eq!(store.report().unwrap(), before);
    assert_eq!(before["budgets"][0]["committed_units"], 20);
    assert_eq!(before["budgets"][0]["resource_charge"], json!([4, 4, 0, 0]));
}

#[test]
fn reports_read_one_snapshot_while_another_handle_appends() {
    let (directory, store, owner, _policy, claim) = setup(NativeBudgetLaneV1::Serving);
    let path = directory.path().join("budget.sqlite");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writer_barrier = barrier.clone();
    let writer = std::thread::spawn(move || {
        let mut owner = owner;
        let mut writer = NativeBudgetStoreV1::open(&path, configuration()).unwrap();
        writer_barrier.wait();
        for seed in 1u8..=10 {
            let mut next = claim.clone();
            next.claim = [seed; 32];
            next.subject = [seed + 20; 32];
            next.monetary_reservation = 1;
            next.resource_reservation = resources(NativeBudgetLaneV1::Serving, 1);
            writer.reserve(&mut owner, next.clone()).unwrap();
            writer
                .record_resources(
                    next.claim,
                    NativeResourceOutcomeV1::Positive,
                    Some(resources(NativeBudgetLaneV1::Serving, 1)),
                )
                .unwrap();
            std::thread::yield_now();
        }
    });
    barrier.wait();
    for _ in 0..100 {
        let report = store.report().unwrap();
        assert_eq!(
            report["budgets"][0]["committed_units"],
            report["claim_count"]
        );
        std::thread::yield_now();
    }
    writer.join().unwrap();
    assert_eq!(store.report().unwrap()["claim_count"], 10);
}

#[test]
fn reward_same_id_with_changed_sibling_fees_cannot_fund_new_physical_work() {
    let (_directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Mining);
    let before = store.report().unwrap();
    owner.advance(6);
    owner.rows.get_mut(&policy.source).unwrap()["amount"] = json!(200);
    assert!(store.reserve(&mut owner, claim.clone()).is_err());
    assert_eq!(store.report().unwrap(), before);
    owner.rows.get_mut(&policy.source).unwrap()["amount"] = json!(100);
    store.reserve(&mut owner, claim.clone()).unwrap();
    owner.advance(5);
    owner.rows.get_mut(&policy.source).unwrap()["amount"] = json!(200);
    let before = store.report().unwrap();
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .is_err());
    assert_eq!(store.report().unwrap(), before);
}

#[test]
fn native_task_and_quota_cannot_reserve_an_impossible_zero_output() {
    for lane in [NativeBudgetLaneV1::Storage, NativeBudgetLaneV1::Serving] {
        let (_directory, mut store, mut owner, _policy, mut claim) = setup(lane);
        claim.subject = [0; 32];
        let before = store.report().unwrap();
        assert!(store.reserve(&mut owner, claim).is_err());
        assert_eq!(store.report().unwrap(), before);
    }
}

#[test]
fn effect_window_refusal_does_not_consume_an_intent_or_change_its_exact_binding() {
    let (_directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let before = store.report().unwrap();
    for (from, until) in [(6, 10), (1, 5), (5, 5), (10, 5)] {
        assert!(store
            .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], from, until)
            .is_err());
        assert_eq!(store.report().unwrap(), before);
    }
    assert_eq!(
        store
            .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    let pending = store.report().unwrap();
    assert!(store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 4, 6)
        .is_err());
    assert!(store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 7)
        .is_err());
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .is_err());
    assert_eq!(store.report().unwrap(), pending);
    assert_eq!(
        store
            .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
}

#[test]
fn an_in_window_anchor_cannot_override_its_cancelled_native_funding_row() {
    let (_directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let before = store.report().unwrap();
    owner.advance(6);
    owner.rows.get_mut(&policy.source).unwrap()["status"] = json!("cancelled");
    owner.rows.get_mut(&policy.source).unwrap()["remaining"] = json!(0);
    assert!(store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 1, 20)
        .is_err());
    assert_eq!(store.report().unwrap(), before);
    owner.rows.remove(&policy.source);
    assert!(store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 1, 20)
        .is_err());
    assert_eq!(store.report().unwrap(), before);
}

#[test]
fn effect_window_replay_survives_reorg_and_restart_only_for_reconciliation() {
    let (directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
        .unwrap();
    let before = store.report().unwrap();
    owner.advance(2);
    owner.rows.remove(&policy.source);
    drop(store);
    let mut store =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .unwrap();
    assert_eq!(
        store
            .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
    assert_eq!(store.report().unwrap(), before);
    assert!(store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 1, 20)
        .is_err());
    store
        .complete_effect(claim.claim, [80; 32], [82; 32])
        .unwrap();
    assert_eq!(
        store
            .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
            .unwrap(),
        NativeBudgetReplayV1::Done
    );
}

#[test]
fn journal_replay_rechecks_the_recorded_window_against_its_own_anchor() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
        .unwrap();
    let (sequence, payload): (u64, Vec<u8>) = store
        .connection
        .query_row(
            "SELECT sequence,payload FROM native_budget_events_v1 ORDER BY sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let previous: Vec<u8> = store
        .connection
        .query_row(
            "SELECT root FROM native_budget_events_v1 WHERE sequence=?1",
            [sequence - 1],
            |r| r.get(0),
        )
        .unwrap();
    let mut event: Event = borsh::from_slice(&payload).unwrap();
    match &mut event {
        Event::Intent { window, .. } => *window = Some((6, 10)),
        _ => panic!("expected intent"),
    }
    let payload = encoded(&event).unwrap();
    let root = event_root(fixed(previous).unwrap(), sequence, &payload);
    // Even a correctly reframed local entry must pass the retained semantic
    // checks; this test does not claim a secret MAC against a hostile host.
    store
        .connection
        .execute(
            "UPDATE native_budget_events_v1 SET payload=?1,root=?2 WHERE sequence=?3",
            params![payload, root.as_slice(), sequence],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE native_budget_meta_v1 SET root=?1 WHERE singleton=1",
            [root.as_slice()],
        )
        .unwrap();
    drop(store);
    let error =
        match NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration()) {
            Ok(_) => panic!("invalid stored window accepted"),
            Err(error) => error,
        };
    assert!(error.to_string().contains("EFFECT_WINDOW"));
}

#[test]
fn journal_write_fence_refuses_suppressed_intent_before_new_dispatch() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let before = store.report().unwrap();
    // These are real SQLite triggers on an already-open journal, not mocked
    // execute() results. Both statements report success without storing intent.
    let outside = Connection::open(directory.path().join("budget.sqlite")).unwrap();
    outside.execute_batch("CREATE TRIGGER suppress_intent BEFORE INSERT ON native_budget_events_v1 BEGIN SELECT RAISE(IGNORE); END;
        CREATE TRIGGER suppress_head BEFORE UPDATE ON native_budget_meta_v1 BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let outcome = store.begin_effect(&mut owner, claim.claim, [80; 32], [81; 32]);
    let actual_sequence: u64 = outside
        .query_row(
            "SELECT sequence FROM native_budget_meta_v1 WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(outcome.is_err(), "New dispatch escaped without a stored intent: {outcome:?}; actual_sequence={actual_sequence}, before={}", before["sequence"]);
    outside
        .execute_batch("DROP TRIGGER suppress_intent; DROP TRIGGER suppress_head;")
        .unwrap();
    assert_eq!(store.report().unwrap(), before);
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
}

#[test]
fn journal_write_fence_refuses_successful_statements_that_rewind_the_intent() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let before = store.report().unwrap();
    let outside = Connection::open(directory.path().join("budget.sqlite")).unwrap();
    // Unlike RAISE(IGNORE), both top-level statements affect one row. The
    // trigger removes the new event and restores a perfectly valid old head.
    outside
        .execute_batch(
            "CREATE TRIGGER rewind_intent AFTER UPDATE ON native_budget_meta_v1
        WHEN NEW.sequence > OLD.sequence BEGIN
        DELETE FROM native_budget_events_v1 WHERE sequence=NEW.sequence;
        UPDATE native_budget_meta_v1 SET sequence=OLD.sequence,root=OLD.root WHERE singleton=1;
        END;",
        )
        .unwrap();
    let outcome = store.begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6);
    let actual_sequence: u64 = outside
        .query_row(
            "SELECT sequence FROM native_budget_meta_v1 WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(outcome.is_err(), "New dispatch escaped after SQLite rewound intent: {outcome:?}; actual_sequence={actual_sequence}, before={}", before["sequence"]);
    outside
        .execute_batch("DROP TRIGGER rewind_intent;")
        .unwrap();
    assert_eq!(store.report().unwrap(), before);
    assert_eq!(
        store
            .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    assert_eq!(
        store
            .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 6)
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
}

#[test]
fn journal_write_fence_rechecks_live_namespace_for_same_id_replay_and_report() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
    let before = store.report().unwrap();
    let outside = Connection::open(directory.path().join("budget.sqlite")).unwrap();
    outside.pragma_update(None, "user_version", 2).unwrap();
    let replay = store.begin_effect(&mut owner, claim.claim, [80; 32], [81; 32]);
    assert!(
        replay.is_err(),
        "same-id replay ignored changed live namespace: {replay:?}"
    );
    assert!(store.report().is_err());
    outside.pragma_update(None, "user_version", 1).unwrap();
    assert_eq!(store.report().unwrap(), before);
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
}
#[test]
fn journal_write_fence_committed_readback_requires_exact_prefix_and_allows_valid_append() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
    let (state, sequence, root) = load_snapshot(&store.connection, &configuration()).unwrap();
    let payload: Vec<u8> = store
        .connection
        .query_row(
            "SELECT payload FROM native_budget_events_v1 WHERE sequence=?1",
            [sequence],
            |r| r.get(0),
        )
        .unwrap();
    let expected = JournalReadback {
        sequence,
        root,
        payload: Some(&payload),
        state: &state,
    };
    let mut other =
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .unwrap();
    other
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::NoGain,
            Some(resources(NativeBudgetLaneV1::Serving, 2)),
        )
        .unwrap();
    // A legitimate append between commit and readback must not falsely erase
    // the writer's exact prefix or invent an extra New permission on retry.
    let (current, current_sequence, _) =
        load_snapshot_checked(&store.connection, &configuration(), Some(expected)).unwrap();
    assert_eq!(current_sequence, sequence + 1);
    assert_eq!(
        current.claim(claim.claim).unwrap().outcome,
        Some(NativeResourceOutcomeV1::NoGain)
    );
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
    let transaction = store.connection.unchecked_transaction().unwrap();
    assert!(check_exact_readback(&transaction, &configuration(), expected).is_err());
    drop(transaction);
    let mut wrong_payload = payload.clone();
    wrong_payload[0] ^= 1;
    assert!(load_snapshot_checked(
        &store.connection,
        &configuration(),
        Some(JournalReadback {
            payload: Some(&wrong_payload),
            ..expected
        })
    )
    .is_err());
    let mut wrong_state = state.clone();
    wrong_state
        .claims
        .get_mut(&claim.claim)
        .unwrap()
        .effect
        .as_mut()
        .unwrap()
        .receipt = Some([90; 32]);
    assert!(load_snapshot_checked(
        &store.connection,
        &configuration(),
        Some(JournalReadback {
            state: &wrong_state,
            ..expected
        })
    )
    .is_err());
    assert!(load_snapshot_checked(
        &store.connection,
        &configuration(),
        Some(JournalReadback {
            root: [0; 32],
            ..expected
        })
    )
    .is_err());
}

#[test]
fn journal_write_fence_same_id_replay_never_uses_an_old_memory_state() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .unwrap();
    let before = store.report().unwrap();
    let (sequence, root): (u64, Vec<u8>) = store
        .connection
        .query_row(
            "SELECT sequence,root FROM native_budget_meta_v1 WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let outside = Connection::open(directory.path().join("budget.sqlite")).unwrap();
    outside
        .execute(
            "UPDATE native_budget_events_v1 SET root=?1 WHERE sequence=?2",
            params![[88u8; 32].as_slice(), sequence],
        )
        .unwrap();
    assert!(store
        .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
        .is_err());
    assert!(store.report().is_err());
    outside
        .execute(
            "UPDATE native_budget_events_v1 SET root=?1 WHERE sequence=?2",
            params![root, sequence],
        )
        .unwrap();
    assert_eq!(store.report().unwrap(), before);
    assert_eq!(
        store
            .begin_effect(&mut owner, claim.claim, [80; 32], [81; 32])
            .unwrap(),
        NativeBudgetReplayV1::Pending
    );
}
#[test]
fn journal_write_fence_does_not_hide_user_objects_behind_sql_like_underscore() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    let before = store.report().unwrap();
    let outside = Connection::open(directory.path().join("budget.sqlite")).unwrap();
    // SQLite reserves the literal sqlite_ prefix. SQL LIKE's underscore also
    // matches X, so sqliteX... is a legal user trigger, never an internal row.
    outside.execute_batch("CREATE TRIGGER sqliteX_hidden_intent BEFORE INSERT ON native_budget_events_v1 BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(
        store.report().is_err(),
        "user trigger was hidden by SQL LIKE underscore"
    );
    assert!(store.reserve(&mut owner, claim.clone()).is_err());
    assert!(
        NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
            .is_err()
    );
    outside
        .execute_batch("DROP TRIGGER sqliteX_hidden_intent;")
        .unwrap();
    assert_eq!(store.report().unwrap(), before);
    assert_eq!(
        store.reserve(&mut owner, claim).unwrap(),
        NativeBudgetReplayV1::Pending
    );
}

#[test]
fn native_payment_readback_rechecks_exact_current_owner_and_never_changes_history() {
    let (directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Serving);
    store.reserve(&mut owner, claim.clone()).unwrap();
    assert!(store
        .reobserve_native_payment(&mut owner, claim.claim)
        .is_err());
    store
        .record_resources(
            claim.claim,
            NativeResourceOutcomeV1::Positive,
            Some(resources(NativeBudgetLaneV1::Serving, 2)),
        )
        .unwrap();
    owner.advance(12);
    let historical = NativePaymentObservationV1 {
        anchor: owner.anchor,
        source: policy.source,
        subject: claim.subject,
        beneficiary: claim.beneficiary,
        operation: [90; 32],
        gross_escrow_debit: 20,
        beneficiary_credit: 18,
    };
    owner.payment = Some(historical.clone());
    store
        .record_native_payment(&mut owner, claim.claim, historical.operation)
        .unwrap();
    let report = store.report().unwrap();
    owner.advance(13);
    let mut current = historical.clone();
    current.anchor = owner.anchor;
    owner.payment = Some(current.clone());
    let readback = store
        .reobserve_native_payment(&mut owner, claim.claim)
        .unwrap();
    assert_eq!(readback.historical, historical);
    assert_eq!(readback.observed, current);
    assert_eq!(store.report().unwrap(), report);
    for field in 0..10 {
        let mut bad = current.clone();
        match field {
            0 => bad.source = NativeFundingSourceV1::Quota([41; 32]),
            1 => bad.subject = [71; 32],
            2 => bad.beneficiary = [99; 32],
            3 => bad.operation = [91; 32],
            4 => bad.gross_escrow_debit = 19,
            5 => bad.beneficiary_credit = 17,
            6 => bad.anchor.network[0] ^= 1,
            7 => bad.anchor.parameters[0] ^= 1,
            8 => bad.anchor.genesis[0] ^= 1,
            _ => bad.anchor = anchor(),
        }
        owner.payment = Some(bad);
        assert!(store
            .reobserve_native_payment(&mut owner, claim.claim)
            .is_err());
        assert_eq!(store.report().unwrap(), report);
    }
    owner.payment = None;
    assert!(matches!(
        store.reobserve_native_payment(&mut owner, claim.claim),
        Err(NativeBudgetErrorV1::Invalid(
            "NATIVE_PAYMENT_PROOF_UNAVAILABLE"
        ))
    ));
    assert_eq!(store.report().unwrap(), report);
    drop(store);
    let store = NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
        .unwrap();
    assert!(store
        .reobserve_native_payment(&mut owner, claim.claim)
        .is_err());
    assert_eq!(store.report().unwrap(), report);
    owner.payment = Some(current.clone());
    let readback = store
        .reobserve_native_payment(&mut owner, claim.claim)
        .unwrap();
    assert_eq!(readback.historical, historical);
    assert_eq!(readback.observed, current);
    assert_eq!(store.report().unwrap(), report);
}

#[test]
fn completed_effect_readback_requires_exact_history_and_original_chain() {
    let (directory, mut store, mut owner, policy, claim) = setup(NativeBudgetLaneV1::Storage);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 20)
        .unwrap();
    assert!(store
        .reobserve_completed_effect(
            &mut owner,
            claim.claim,
            [80; 32],
            [81; 32],
            Some((5, 20)),
            [82; 32],
        )
        .is_err());
    store
        .complete_effect(claim.claim, [80; 32], [82; 32])
        .unwrap();
    let report = store.report().unwrap();
    for field in 0..5 {
        let (mut id, mut operation, mut effect, mut window, mut receipt) =
            (claim.claim, [80; 32], [81; 32], Some((5, 20)), [82; 32]);
        match field {
            0 => id[0] ^= 1,
            1 => operation[0] ^= 1,
            2 => effect[0] ^= 1,
            3 => window = Some((5, 19)),
            _ => receipt[0] ^= 1,
        }
        assert!(store
            .reobserve_completed_effect(&mut owner, id, operation, effect, window, receipt)
            .is_err());
        assert_eq!(store.report().unwrap(), report);
    }
    owner.advance(21);
    owner.rows.remove(&policy.source);
    for field in 0..3 {
        let mut wrong = owner.clone();
        match field {
            0 => wrong.anchor.network[0] ^= 1,
            1 => wrong.anchor.parameters[0] ^= 1,
            _ => wrong.anchor.genesis[0] ^= 1,
        }
        assert!(store
            .reobserve_completed_effect(
                &mut wrong,
                claim.claim,
                [80; 32],
                [81; 32],
                Some((5, 20)),
                [82; 32],
            )
            .is_err());
        assert_eq!(store.report().unwrap(), report);
    }
    drop(store);
    let store = NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
        .unwrap();
    let observed = store
        .reobserve_completed_effect(
            &mut owner,
            claim.claim,
            [80; 32],
            [81; 32],
            Some((5, 20)),
            [82; 32],
        )
        .unwrap();
    assert_eq!(observed, owner.anchor);
    assert_eq!(store.report().unwrap(), report);
}

#[test]
fn completed_effect_readback_rejects_stale_or_changed_owner_after_restart() {
    let (directory, mut store, mut owner, _policy, claim) = setup(NativeBudgetLaneV1::Storage);
    let stale = owner.clone();
    owner.advance(6);
    store.reserve(&mut owner, claim.clone()).unwrap();
    store
        .begin_effect_in_window(&mut owner, claim.claim, [80; 32], [81; 32], 5, 20)
        .unwrap();
    store
        .complete_effect(claim.claim, [80; 32], [82; 32])
        .unwrap();
    let report = store.report().unwrap();

    for reopen in [false, true] {
        if reopen {
            drop(store);
            store =
                NativeBudgetStoreV1::open(&directory.path().join("budget.sqlite"), configuration())
                    .unwrap();
        }
        for field in 0..4 {
            let mut wrong = owner.clone();
            match field {
                // An earlier real owner snapshot is still stale after the
                // effect completes and its journal is reopened.
                0 => wrong = stale.clone(),
                1 => wrong.anchor.block[0] ^= 1,
                2 => wrong.anchor.state_root[0] ^= 1,
                // A height that could retire the physical obligation cannot
                // be substituted without a new owner generation.
                _ => wrong.anchor.height = 20,
            }
            assert!(matches!(
                store.reobserve_completed_effect(
                    &mut wrong,
                    claim.claim,
                    [80; 32],
                    [81; 32],
                    Some((5, 20)),
                    [82; 32],
                ),
                Err(NativeBudgetErrorV1::Invalid("BUDGET_STALE_OWNER_SNAPSHOT"))
            ));
            assert_eq!(store.report().unwrap(), report);
        }
        let observed = store
            .reobserve_completed_effect(
                &mut owner,
                claim.claim,
                [80; 32],
                [81; 32],
                Some((5, 20)),
                [82; 32],
            )
            .unwrap();
        assert_eq!(observed, owner.anchor);
        assert_eq!(store.report().unwrap(), report);
    }
}
