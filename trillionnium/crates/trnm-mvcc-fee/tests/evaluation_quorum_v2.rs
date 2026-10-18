//! Cross-implementation frozen/commit/reveal/conflict/closure/store conformance.
//! Seeded context values scope these vectors to the evaluation state machine;
//! trnm-pon-node's model_evidence_v3 test covers signed native model admission.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use trnm_crypto_primitives::{signing_key_from_hex, verify_hex_strict};
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
    let mut reparented = compact;
    reparented["plan"]["parent"] = json!(hex::encode([19; 32]));
    assert_eq!(
        evaluation::round(&reparented),
        Err("PUBLIC_EVAL_GENERATION")
    );
}
