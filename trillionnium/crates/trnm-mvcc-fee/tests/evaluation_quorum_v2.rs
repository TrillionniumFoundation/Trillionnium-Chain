//! Cross-implementation frozen/commit/reveal/conflict/closure/store conformance.
//! Seeded context values scope these vectors to the evaluation state machine;
//! trnm-pon-node's model_evidence_v3 test covers signed native model admission.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex, verify_hex_strict};
use trnm_mvcc_fee::{
    model_evidence_v3,
    pon_executor::Config,
    public_evaluation::{self as evaluation, Reveal},
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn public(who: u64) -> Hash {
    signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .unwrap()
        .verifying_key()
        .to_bytes()
}
fn digest(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn excluded(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|who| hex::encode(public(who.as_u64().unwrap())))
        .collect()
}
fn input() -> Value {
    serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/evaluation-quorum-v2.json"
    ))
    .unwrap()
}
fn configure(context: &Value, profile: &str) -> Config {
    let mut cfg = Config::installed_with_model_profiles(
        profile,
        "legacy-task-v1",
        model_evidence_v3::PROFILE,
    )
    .unwrap();
    cfg.network = digest(&context["network"]);
    cfg.parameters = digest(&context["parameters"]);
    cfg.family = digest(&context["family"]);
    cfg.plan = digest(&context["plan"]);
    cfg.params["model_evidence_tasks_hash"] = context["dataset"].clone();
    cfg
}
fn frozen(cfg: &Config, context: &Value, row: &Value) -> Value {
    let contribution = json!({"owner":hex::encode(public(3)),"artifact":context["artifact"],
        "components_root":context["components_root"],"parent":context["parent"]});
    evaluation::freeze(
        cfg,
        digest(&context["candidate"]),
        &contribution,
        row["generation"].as_u64().unwrap() * 128 + 1,
        &excluded(&row["excluded"]),
    )
    .unwrap()
}
fn transaction(value: &Value, cfg: &Config) -> Envelope {
    let bytes = hex::decode(value.as_str().unwrap()).unwrap();
    let tx = Envelope::decode(&bytes).unwrap();
    assert_eq!(tx.network, cfg.network);
    verify_hex_strict(
        &hex::encode(tx.sender),
        &tx.signing_digest().unwrap(),
        &hex::encode(tx.signature),
    )
    .unwrap();
    tx
}
fn reveal(tx: &Envelope) -> Reveal {
    assert_eq!(tx.tag, 15);
    Reveal {
        candidate: tx.payload[..32].try_into().unwrap(),
        round: tx.payload[32..64].try_into().unwrap(),
        evaluator: tx.sender,
        plan: tx.payload[64..96].try_into().unwrap(),
        evidence: tx.payload[96..128].try_into().unwrap(),
        score: u64::from_le_bytes(tx.payload[128..136].try_into().unwrap()),
        salt: tx.payload[136..168].try_into().unwrap(),
    }
}
fn conflicts(e: &mut Value, cfg: &Config, candidate: Hash, rows: &Value) {
    for pair in rows.as_array().unwrap() {
        let a = hex::decode(pair[0].as_str().unwrap()).unwrap();
        let b = hex::decode(pair[1].as_str().unwrap()).unwrap();
        evaluation::conflict(e, cfg, candidate, &a, &b).unwrap();
    }
}

#[test]
fn independent_reference_vectors_match_native_domains_counts_and_records() {
    let input = input();
    let context = &input["context"];
    let candidate = digest(&context["candidate"]);
    let cases = input["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let cfg = configure(context, row["profile"].as_str().unwrap());
        let frozen = frozen(&cfg, context, row);
        assert_eq!(frozen, row["frozen"], "{name}: frozen plan/domain");
        let mut e = evaluation::hydrate(&frozen, candidate, &BTreeMap::new()).unwrap();
        let start = row["generation"].as_u64().unwrap() * 128;
        for raw in row["commits"].as_array().unwrap() {
            let tx = transaction(raw, &cfg);
            assert_eq!(tx.tag, 14);
            evaluation::commit(
                &mut e,
                &hex::encode(tx.sender),
                tx.payload[32..64].try_into().unwrap(),
                tx.payload[64..96].try_into().unwrap(),
                start + 16,
            )
            .unwrap();
        }
        for raw in row["reveals"].as_array().unwrap() {
            let tx = transaction(raw, &cfg);
            evaluation::reveal(&mut e, reveal(&tx), start + 32).unwrap();
        }
        conflicts(&mut e, &cfg, candidate, &row["conflicts_before"]);
        evaluation::close_with_disqualified(&mut e, start + 48, &excluded(&row["global_before"]))
            .unwrap();
        assert_eq!(
            e["closed"], row["expected_closed"],
            "{name}: native closure"
        );
        assert_eq!(
            hex::encode(evaluation::closed_digest(&e).unwrap()),
            row["expected_closed_digest"],
            "{name}: closed domain"
        );
        conflicts(&mut e, &cfg, candidate, &row["conflicts_after"]);
        if row["appeal"] == true {
            let result = evaluation::closed_digest(&e).unwrap();
            let author = hex::encode(public(3));
            evaluation::appeal(
                &mut e,
                &author,
                &author,
                result,
                [1; 32],
                [2; 32],
                start + 49,
            )
            .unwrap();
        }
        assert_eq!(
            e["closed"], row["expected_closed"],
            "{name}: historical closure immutable"
        );
        let current = excluded(&row["global_after"]);
        assert_eq!(
            evaluation::adoption_allowed_with_disqualified(&e, start + 56, &current).is_ok(),
            row["expected_adoption"].as_bool().unwrap(),
            "{name}: adoption"
        );
        if evaluation::quorum_enabled(&cfg) {
            assert_eq!(
                evaluation::quorum_v2::adoption_allowed(&e, start + 56, true, &current).is_ok(),
                row["expected_component_adoption"].as_bool().unwrap(),
                "{name}: component"
            );
            if row["expected_adoption"] == true {
                for field in ["quorum", "candidate"] {
                    let mut substituted = e.clone();
                    substituted["closed"][field] = if field == "quorum" {
                        json!(1)
                    } else {
                        json!(hex::encode([91; 32]))
                    };
                    assert_eq!(
                        evaluation::adoption_allowed_with_disqualified(
                            &substituted,
                            start + 56,
                            &current
                        ),
                        Err("PUBLIC_EVAL_ADOPTION"),
                        "{name}: changed closure {field}"
                    );
                }
            }
        }
        let rows = evaluation::record_rows(candidate, &e).unwrap();
        assert_eq!(
            hex::encode(hash(
                b"native-evaluation-test-rows-v2",
                &[&serde_json::to_vec(&rows).unwrap()]
            )),
            row["expected_rows_digest"],
            "{name}: exact storage namespace/schema/rows"
        );
        let compact = evaluation::compact(&e).unwrap();
        let hydrated = evaluation::hydrate(&compact, candidate, &rows).unwrap();
        e["record_counts"] = compact["record_counts"].clone();
        assert_eq!(hydrated, e, "{name}: compact roundtrip");
        if !rows.is_empty() {
            let substituted: BTreeMap<_, _> = rows
                .into_iter()
                .map(|(key, value)| {
                    (
                        key.replace("evaluation-record-v3:", "wrong-record-v3:")
                            .replace("evaluation-record-v2:", "wrong-record-v2:"),
                        value,
                    )
                })
                .collect();
            assert!(
                evaluation::hydrate(&compact, candidate, &substituted).is_err(),
                "{name}: foreign namespace"
            );
        }
    }
}

#[test]
fn fresh_profile_refuses_attested_models_and_cross_version_replay() {
    for model in [
        "linear-expert-dev-v1",
        trnm_mvcc_fee::integer_factor_candidate_v2::PROFILE,
        "smollm2-135m-cpu-dev-v1",
    ] {
        assert!(Config::installed_with_model_profiles(
            evaluation::QUORUM_PROFILE,
            "legacy-task-v1",
            model
        )
        .is_err());
    }
    for model in [
        model_evidence_v3::PROFILE,
        trnm_mvcc_fee::model_composition_v4::PROFILE,
    ] {
        let legacy =
            Config::installed_with_model_profiles(evaluation::PROFILE, "legacy-task-v1", model)
                .unwrap();
        let fresh = Config::installed_with_model_profiles(
            evaluation::QUORUM_PROFILE,
            "legacy-task-v1",
            model,
        )
        .unwrap();
        assert_ne!(fresh.network, legacy.network);
        assert_ne!(fresh.parameters, legacy.parameters);
        assert_ne!(fresh.plan, legacy.plan);
        assert_eq!(
            fresh.params["consensus_revision"],
            evaluation::QUORUM_REVISION
        );
        assert_eq!(fresh.evaluators.len(), 4);
        assert_eq!(legacy.evaluators.len(), 3);
    }
    let input = input();
    let context = &input["context"];
    let row = &input["cases"][3];
    let cfg = configure(context, evaluation::QUORUM_PROFILE);
    let compact = frozen(&cfg, context, row);
    let candidate = digest(&context["candidate"]);
    let tx = transaction(&row["reveals"][0], &cfg);
    let value = reveal(&tx);
    let old = evaluation::reveal_commitment(
        value.round,
        candidate,
        value.evaluator,
        value.plan,
        value.evidence,
        value.score,
        value.salt,
    );
    let mut e = evaluation::hydrate(&compact, candidate, &BTreeMap::new()).unwrap();
    evaluation::commit(&mut e, &hex::encode(value.evaluator), value.round, old, 16).unwrap();
    assert_eq!(
        evaluation::reveal(&mut e, value, 32),
        Err("PUBLIC_EVAL_COMMITMENT_BINDING")
    );
    let mut downgrade = compact.clone();
    downgrade["storage_revision"] = json!(2);
    assert!(evaluation::hydrate(&downgrade, candidate, &BTreeMap::new()).is_err());
    let mut unknown = compact.clone();
    unknown["storage_revision"] = json!(4);
    assert!(evaluation::hydrate(&unknown, candidate, &BTreeMap::new()).is_err());
    let mut rerostered = evaluation::hydrate(&compact, candidate, &BTreeMap::new()).unwrap();
    let mut roster: BTreeSet<_> = rerostered["plan"]["roster"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap().to_owned())
        .collect();
    roster.insert(hex::encode(public(4)));
    rerostered["plan"]["roster"] = json!(roster);
    rerostered["plan"]["quorum"] = json!(3);
    // The separately committed generation remains valid; the full frozen
    // round must still reject a well-formed replacement roster/threshold.
    evaluation::quorum_v2::validate_plan(&rerostered["plan"]).unwrap();
    assert_eq!(
        evaluation::close(&mut rerostered, 48),
        Err("PUBLIC_EVAL_ROUND")
    );
    assert!(rerostered["closed"].is_null());
    let mut reparented = compact;
    reparented["plan"]["parent"] = json!(hex::encode([19; 32]));
    assert_eq!(
        evaluation::round(&reparented),
        Err("PUBLIC_EVAL_GENERATION")
    );
}

#[test]
fn retained_reveals_recheck_commitments_at_restore_close_and_adoption() {
    let input = input();
    let context = &input["context"];
    let candidate = digest(&context["candidate"]);
    // Both retained classic formats use the exact same commitments as live
    // admission. Altering one retained byte is not a new evaluator statement.
    for index in [0, 3, 6] {
        let row = &input["cases"][index];
        let cfg = configure(context, row["profile"].as_str().unwrap());
        let mut e =
            evaluation::hydrate(&frozen(&cfg, context, row), candidate, &BTreeMap::new()).unwrap();
        for raw in row["commits"].as_array().unwrap() {
            let tx = transaction(raw, &cfg);
            evaluation::commit(
                &mut e,
                &hex::encode(tx.sender),
                tx.payload[32..64].try_into().unwrap(),
                tx.payload[64..96].try_into().unwrap(),
                16,
            )
            .unwrap();
        }
        for raw in row["reveals"].as_array().unwrap() {
            let tx = transaction(raw, &cfg);
            evaluation::reveal(&mut e, reveal(&tx), 32).unwrap();
        }
        evaluation::close(&mut e, 48).unwrap();
        let signer = e["reveals"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        for field in ["commitment", "salt", "evidence", "score"] {
            let mut changed = e.clone();
            if field == "commitment" {
                changed["commits"][&signer] = json!(hex::encode([91; 32]));
            } else if field == "score" {
                changed["reveals"][&signer][field] =
                    json!(e["reveals"][&signer][field].as_u64().unwrap() + 1);
            } else {
                changed["reveals"][&signer][field] = json!(hex::encode([91; 32]));
            }
            let adopted = if index == 6 {
                evaluation::quorum_v2::adoption_allowed(&changed, 56, true, &BTreeSet::new())
            } else {
                evaluation::adoption_allowed(&changed, 56)
            };
            assert_eq!(
                adopted,
                Err("PUBLIC_EVAL_COMMITMENT_BINDING"),
                "{}: {field} cannot be adopted",
                row["name"]
            );
            let records = evaluation::record_rows(candidate, &changed).unwrap();
            let compact = evaluation::compact(&changed).unwrap();
            assert_eq!(
                evaluation::hydrate(&compact, candidate, &records),
                Err("PUBLIC_EVAL_COMMITMENT_BINDING"),
                "{}: {field} cannot be restored",
                row["name"]
            );
            changed["closed"] = Value::Null;
            assert_eq!(
                evaluation::close(&mut changed, 48),
                Err("PUBLIC_EVAL_COMMITMENT_BINDING"),
                "{}: {field} cannot close",
                row["name"]
            );
            assert!(changed["closed"].is_null());
        }
    }
}

fn closed_classic(index: usize) -> (Value, Config, Hash) {
    let input = input();
    let context = &input["context"];
    let row = &input["cases"][index];
    let cfg = configure(context, evaluation::PROFILE);
    let candidate = digest(&context["candidate"]);
    let mut e =
        evaluation::hydrate(&frozen(&cfg, context, row), candidate, &BTreeMap::new()).unwrap();
    for raw in row["commits"].as_array().unwrap() {
        let tx = transaction(raw, &cfg);
        evaluation::commit(
            &mut e,
            &hex::encode(tx.sender),
            tx.payload[32..64].try_into().unwrap(),
            tx.payload[64..96].try_into().unwrap(),
            16,
        )
        .unwrap();
    }
    for raw in row["reveals"].as_array().unwrap() {
        evaluation::reveal(&mut e, reveal(&transaction(raw, &cfg)), 32).unwrap();
    }
    evaluation::close(&mut e, 48).unwrap();
    assert_eq!(e["closed"], row["expected_closed"]);
    (e, cfg, candidate)
}

fn restore(e: &Value, candidate: Hash) -> Result<Value, &'static str> {
    evaluation::hydrate(
        &evaluation::compact(e).unwrap(),
        candidate,
        &evaluation::record_rows(candidate, e).unwrap(),
    )
}

#[test]
fn classic_retained_closure_rejects_substituted_summary_at_use_and_restore() {
    let (e, _, candidate) = closed_classic(0);
    assert!(evaluation::adoption_allowed(&e, 56).is_ok());
    for (field, replacement) in [
        ("schema", json!("pon-native-closed-evaluation-v3")),
        ("round", json!(hex::encode([91; 32]))),
        ("candidate", json!(hex::encode([91; 32]))),
        ("status", json!("aborted")),
        ("score", json!(18)),
        ("score", Value::Null),
        ("missing_reveal_count", json!(1)),
        ("conflict_count_before_close", json!(1)),
        ("records_digest", json!(hex::encode([91; 32]))),
        ("closed_height", json!(47)),
        ("objective_model_quality", json!(true)),
        ("independent_governance_accepted", json!(true)),
        ("execution_authority", json!(true)),
    ] {
        let mut changed = e.clone();
        changed["closed"][field] = replacement;
        assert_eq!(
            evaluation::adoption_allowed(&changed, 56),
            Err("PUBLIC_EVAL_CLOSED_BINDING"),
            "{field}: substitute must not authorize adoption"
        );
        assert_eq!(
            restore(&changed, candidate),
            Err("PUBLIC_EVAL_CLOSED_BINDING"),
            "{field}: substitute must not be restored"
        );
    }
    let mut future = e.clone();
    future["closed"]["closed_height"] = json!(57);
    assert!(restore(&future, candidate).is_ok());
    assert_eq!(
        evaluation::adoption_allowed(&future, 56),
        Err("PUBLIC_EVAL_ADOPTION")
    );
    assert!(evaluation::adoption_allowed(&future, 57).is_ok());
}

#[test]
fn classic_retained_closure_recounts_aborts_and_accepts_complete_zero_score() {
    let (aborted, _, candidate) = closed_classic(1);
    assert!(restore(&aborted, candidate).is_ok());
    assert!(evaluation::closed_digest(&aborted).is_ok());
    for (field, value) in [
        ("status", json!("complete-scored")),
        ("score", json!(0)),
        ("missing_reveal_count", json!(0)),
        ("records_digest", json!(hex::encode([91; 32]))),
    ] {
        let mut changed = aborted.clone();
        changed["closed"][field] = value;
        assert_eq!(
            restore(&changed, candidate),
            Err("PUBLIC_EVAL_CLOSED_BINDING"),
            "aborted {field}"
        );
    }

    let (mut zero, cfg, _) = closed_classic(0);
    zero["closed"] = Value::Null;
    zero["commits"] = json!({});
    zero["reveals"] = json!({});
    for raw in input()["cases"][0]["reveals"].as_array().unwrap() {
        let mut value = reveal(&transaction(raw, &cfg));
        value.score = 0;
        let commitment = evaluation::reveal_commitment_for(&zero, &value).unwrap();
        evaluation::commit(
            &mut zero,
            &hex::encode(value.evaluator),
            value.round,
            commitment,
            16,
        )
        .unwrap();
        evaluation::reveal(&mut zero, value, 32).unwrap();
    }
    assert_eq!(evaluation::close(&mut zero, 48), Ok(Some(0)));
    assert_eq!(zero["closed"]["status"], "complete-scored");
    assert!(restore(&zero, candidate).is_ok());
    assert!(evaluation::closed_digest(&zero).is_ok());
    assert_eq!(
        evaluation::adoption_allowed(&zero, 56),
        Err("PUBLIC_EVAL_ADOPTION")
    );
}

fn add_classic_conflict(e: &mut Value, cfg: &Config, candidate: Hash, index: usize) {
    let original = transaction(&input()["cases"][0]["commits"][index], cfg);
    let who = (0..3).find(|who| public(*who) == original.sender).unwrap();
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    let mut changed = original.clone();
    changed.payload[64] ^= 1;
    changed.signature = hex::decode(sign_hex(&key, &changed.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    evaluation::conflict(
        e,
        cfg,
        candidate,
        &original.encode().unwrap(),
        &changed.encode().unwrap(),
    )
    .unwrap();
}

#[test]
fn classic_retained_closure_preserves_legal_appeals_and_late_conflicts() {
    let (mut e, cfg, candidate) = closed_classic(0);
    let closed = e["closed"].clone();
    let result = evaluation::closed_digest(&e).unwrap();
    // This is only an identifier. Existing callers can calculate it from the
    // compact record; restoring or adopting it requires complete validation.
    assert_eq!(
        evaluation::closed_digest(&evaluation::compact(&e).unwrap()),
        Ok(result)
    );
    let author = hex::encode(public(3));
    evaluation::appeal(&mut e, &author, &author, result, [1; 32], [2; 32], 49).unwrap();
    assert!(restore(&e, candidate).is_ok());
    assert!(evaluation::adoption_allowed(&e, 56).is_ok());
    add_classic_conflict(&mut e, &cfg, candidate, 0);
    assert_eq!(e["closed"], closed);
    assert!(restore(&e, candidate).is_ok());
    assert_eq!(evaluation::closed_digest(&e), Ok(result));
    assert_eq!(
        evaluation::adoption_allowed(&e, 56),
        Err("PUBLIC_EVAL_ADOPTION")
    );
    let mut changed = e.clone();
    changed["closed"]["records_digest"] = json!(hex::encode([91; 32]));
    assert_eq!(
        restore(&changed, candidate),
        Err("PUBLIC_EVAL_CLOSED_BINDING")
    );

    let (mut early, _, _) = closed_classic(0);
    early["closed"] = Value::Null;
    add_classic_conflict(&mut early, &cfg, candidate, 0);
    assert_eq!(evaluation::close(&mut early, 48), Ok(None));
    assert_eq!(early["closed"]["conflict_count_before_close"], 1);
    assert!(restore(&early, candidate).is_ok());
    let result = evaluation::closed_digest(&early).unwrap();
    add_classic_conflict(&mut early, &cfg, candidate, 1);
    assert!(restore(&early, candidate).is_ok());
    assert_eq!(evaluation::closed_digest(&early), Ok(result));
    assert!(evaluation::adoption_allowed(&early, 56).is_err());
}

fn closed_quorum(index: usize) -> (Value, Config, Hash) {
    let input = input();
    let context = &input["context"];
    let row = &input["cases"][index];
    let cfg = configure(context, evaluation::QUORUM_PROFILE);
    let candidate = digest(&context["candidate"]);
    let mut e =
        evaluation::hydrate(&frozen(&cfg, context, row), candidate, &BTreeMap::new()).unwrap();
    let start = row["generation"].as_u64().unwrap() * 128;
    for raw in row["commits"].as_array().unwrap() {
        let tx = transaction(raw, &cfg);
        evaluation::commit(
            &mut e,
            &hex::encode(tx.sender),
            tx.payload[32..64].try_into().unwrap(),
            tx.payload[64..96].try_into().unwrap(),
            start + 16,
        )
        .unwrap();
    }
    for raw in row["reveals"].as_array().unwrap() {
        evaluation::reveal(&mut e, reveal(&transaction(raw, &cfg)), start + 32).unwrap();
    }
    conflicts(&mut e, &cfg, candidate, &row["conflicts_before"]);
    evaluation::close_with_disqualified(&mut e, start + 48, &excluded(&row["global_before"]))
        .unwrap();
    assert_eq!(e["closed"], row["expected_closed"]);
    (e, cfg, candidate)
}

#[test]
fn quorum_retained_closure_cannot_authorize_adoption_before_its_height() {
    let (mut e, _, candidate) = closed_quorum(3);
    assert!(evaluation::adoption_allowed(&e, 56).is_ok());
    e["closed"]["closed_height"] = json!(57);
    // Restoration has no current-height authority. Consumption must still
    // refuse a semantically valid closure that is later than the caller.
    assert!(restore(&e, candidate).is_ok());
    assert_eq!(
        evaluation::adoption_allowed(&e, 56),
        Err("PUBLIC_EVAL_ADOPTION")
    );
    assert!(evaluation::adoption_allowed(&e, 57).is_ok());
}

#[test]
fn quorum_retained_closure_rejects_substituted_summary_at_use_and_restore() {
    let (e, _, candidate) = closed_quorum(3);
    assert!(evaluation::adoption_allowed(&e, 56).is_ok());
    for (field, replacement) in [
        ("records_digest", json!(hex::encode([91; 32]))),
        ("schema", json!("pon-native-closed-evaluation-v2")),
        ("round", json!(hex::encode([91; 32]))),
        ("candidate", json!(hex::encode([91; 32]))),
        ("generation_context", json!(hex::encode([91; 32]))),
        ("quorum", json!(3)),
        ("status", json!("aborted")),
        ("score", json!(18)),
        ("score", Value::Null),
        ("evidence", json!(hex::encode([91; 32]))),
        ("closed_height", json!(47)),
        ("eligible_reveal_count", json!(3)),
        ("matching_reveal_count", json!(3)),
        ("missing_reveal_count", json!(0)),
        ("disqualified_count_before_close", json!(1)),
        (
            "disqualified_signers_before_close",
            json!([hex::encode(public(1))]),
        ),
        ("conflict_count_before_close", json!(1)),
        ("objective_model_quality", json!(true)),
        ("independent_governance_accepted", json!(true)),
        ("execution_authority", json!(true)),
        ("consensus_finality", json!(true)),
        ("unknown_authority", json!(true)),
    ] {
        let mut changed = e.clone();
        changed["closed"][field] = replacement;
        assert!(
            evaluation::adoption_allowed(&changed, 56).is_err(),
            "{field}: substituted summary must not authorize adoption"
        );
        assert!(
            restore(&changed, candidate).is_err(),
            "{field}: substituted summary must not be restored"
        );
    }
    for field in e["closed"].as_object().unwrap().keys() {
        let mut missing = e.clone();
        missing["closed"].as_object_mut().unwrap().remove(field);
        assert!(
            evaluation::adoption_allowed(&missing, 56).is_err(),
            "missing {field}"
        );
        assert!(restore(&missing, candidate).is_err(), "missing {field}");
    }
}

#[test]
fn quorum_retained_closure_preserves_nonempty_history_after_more_conflicts() {
    let (mut e, cfg, candidate) = closed_quorum(9);
    let original = e["closed"].clone();
    let result = evaluation::closed_digest(&e).unwrap();
    assert_eq!(original["conflict_count_before_close"], json!(1));
    assert!(evaluation::adoption_allowed(&e, 56).is_ok());
    conflicts(
        &mut e,
        &cfg,
        candidate,
        &input()["cases"][12]["conflicts_after"],
    );
    assert_eq!(e["conflicts"].as_object().unwrap().len(), 2);
    assert_eq!(e["closed"], original);
    assert!(restore(&e, candidate).is_ok());
    assert_eq!(evaluation::closed_digest(&e), Ok(result));
    assert!(evaluation::adoption_allowed(&e, 56).is_err());
}
