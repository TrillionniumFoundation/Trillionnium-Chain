//! Actual signed M06 joint update, native quorum, adoption and successor-parent tests.
//! Public-row memorization supplies deterministic positive/negative controls only.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::model_task_windows_v1::{self as windows, PinnedTaskWindows, SignedTaskWindows};
use trnm_mvcc_fee::{
    integer_factor_candidate_v2 as factor, model_evolution_v5 as evolution,
    pon_executor::{self, Config, State},
    public_evaluation as evaluation,
};
use trnm_protocol::{
    integer_evolution_v3::{EvolutionOperationV3, EvolutionWitnessV3},
    pon_wire::{hash, Envelope, Hash},
};

fn public(who: u64) -> Hash {
    signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .unwrap()
        .verifying_key()
        .to_bytes()
}
fn config() -> Config {
    Config::installed_with_model_profiles(
        evaluation::QUORUM_PROFILE,
        "legacy-task-v1",
        evolution::PROFILE,
    )
    .unwrap()
}
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/model-evolution-v5.json"
    ))
    .unwrap()
}
const WINDOW_MANIFEST: &[u8] = include_bytes!(
    "../../../../formal/pon-nakamoto-v1/vectors/model-task-windows-v1.manifest.json"
);
fn window_vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/model-task-windows-v1.json"
    ))
    .unwrap()
}
fn configured_windows(raw: &[u8], owner: Hash, sha256: Hash) -> Result<Config, &'static str> {
    Config::installed_with_model_profiles_and_task_windows(
        evaluation::QUORUM_PROFILE,
        "legacy-task-v1",
        evolution::PROFILE,
        Some(PinnedTaskWindows { raw, sha256, owner }),
    )
}
fn resign_windows(manifest: &mut SignedTaskWindows) -> Vec<u8> {
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-TASK-WINDOW-OWNER",
        &[&0_u64.to_le_bytes()],
    )))
    .unwrap();
    manifest.signature = sign_hex(
        &key,
        &windows::signing_digest(config().family, manifest).unwrap(),
    );
    serde_json::to_vec(manifest).unwrap()
}
fn vector_rows(value: &Value) -> Vec<Vec<i16>> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            row.as_array()
                .unwrap()
                .iter()
                .map(|value| i16::try_from(value.as_i64().unwrap()).unwrap())
                .collect()
        })
        .collect()
}
fn compare_witness(witness: &EvolutionWitnessV3, expected: &Value) {
    assert_eq!(hex::encode(witness.encode().unwrap()), expected["payload"]);
    assert_eq!(
        hex::encode(witness.candidate_artifact),
        expected["artifact"]
    );
    assert_eq!(hex::encode(witness.update_id), expected["update"]);
    assert_eq!(
        hex::encode(witness.contribution_id),
        expected["contribution"]
    );
}
fn initial(cfg: &Config) -> State {
    let mut state = factor::bootstrap_state(cfg).unwrap();
    state.insert("meta:issued".into(), json!(40_000_000));
    for who in 0..4 {
        state.insert(
            format!("account:{}", hex::encode(public(who))),
            json!({"balance":10_000_000,"nonce":0}),
        );
    }
    state
}
fn nonce(state: &State, who: u64) -> u64 {
    state[&format!("account:{}", hex::encode(public(who)))]["nonce"]
        .as_u64()
        .unwrap()
        + 1
}
fn signed(cfg: &Config, state: &State, who: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    let mut tx = Envelope {
        network: cfg.network,
        sender: public(who),
        nonce: nonce(state, who),
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn step(state: &State, cfg: &Config, height: u64, transactions: &[Vec<u8>]) -> State {
    pon_executor::execute(state, transactions, height, public(3), [4; 32], 2, cfg)
        .unwrap()
        .state
}
fn rejected(state: &State, cfg: &Config, height: u64, tx: Vec<u8>, expected: &str) {
    let before = state.clone();
    let error = pon_executor::execute(state, &[tx], height, public(3), [4; 32], 2, cfg)
        .err()
        .unwrap();
    assert_eq!(error, expected);
    assert_eq!(state, &before);
}
fn digest(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn candidate(state: &State, cid: Hash) -> &Value {
    &state[&format!("contribution:{}", hex::encode(cid))]
}
fn trained(passes: usize) -> Vec<Vec<i16>> {
    let policy = trnm_mvcc_fee::model_evidence_v3::installed_policy().unwrap();
    let mut weights = vec![vec![0_i16; 257]; 3];
    for _ in 0..passes {
        for task in policy["tasks"].as_array().unwrap() {
            let x: Vec<_> = task["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| i16::try_from(v.as_i64().unwrap()).unwrap())
                .collect();
            let scores: Vec<i64> = weights
                .iter()
                .map(|row| {
                    row.iter()
                        .zip(&x)
                        .map(|(&a, &b)| i64::from(a) * i64::from(b))
                        .sum()
                })
                .collect();
            let mut prediction = 0;
            for i in 1..3 {
                if scores[i] > scores[prediction] {
                    prediction = i;
                }
            }
            let label = task["label"].as_u64().unwrap() as usize;
            if prediction != label {
                for (i, &feature) in x.iter().enumerate() {
                    weights[prediction][i] -= feature;
                    weights[label][i] += feature;
                }
            }
        }
    }
    (0..3)
        .map(|i| {
            weights[i]
                .iter()
                .zip(&weights[0])
                .map(|(&a, &b)| a - b)
                .collect()
        })
        .collect()
}
fn rank_two(target: u8, rows: &[Vec<i16>]) -> EvolutionOperationV3 {
    let mut factors = vec![0, 0, 1, 0, 0, 1];
    factors.extend(&rows[1]);
    factors.extend(&rows[2]);
    EvolutionOperationV3 {
        target,
        rank: 2,
        factors,
    }
}
fn initial_operations() -> Vec<EvolutionOperationV3> {
    let mut router = vec![0_i16; 260];
    router[1] = 1;
    router[259] = 1;
    vec![
        EvolutionOperationV3 {
            target: 1,
            rank: 1,
            factors: router,
        },
        rank_two(3, &trained(1)),
    ]
}
fn self_root(w: &mut EvolutionWitnessV3, who: u64, score: u64) {
    w.components_root = hash(
        b"allocation-leaf",
        &[&w.contribution_id, &public(who), &score.to_le_bytes()],
    );
}
fn attest(cfg: &Config, state: &State, cid: Hash, who: u64, tag: u8) -> Vec<u8> {
    let record = evolution::evidence(state, cid).unwrap();
    let frozen = &candidate(state, cid)["public_evaluation"];
    let round = evaluation::round(frozen).unwrap();
    let reveal = evaluation::Reveal {
        candidate: cid,
        round,
        evaluator: public(who),
        plan: cfg.plan,
        evidence: digest(&record["digest"]),
        score: record["score"].as_u64().unwrap(),
        salt: [who as u8 + 1; 32],
    };
    let mut payload = cid.to_vec();
    payload.extend(round);
    if tag == 14 {
        payload.extend(evaluation::reveal_commitment_for(frozen, &reveal).unwrap());
    } else {
        payload.extend(cfg.plan);
        payload.extend(reveal.evidence);
        payload.extend(reveal.score.to_le_bytes());
        payload.extend(reveal.salt);
    }
    signed(cfg, state, who, tag, payload)
}
fn close(mut state: State, cfg: &Config, cid: Hash, start: u64) -> State {
    for (offset, tag) in [(16, 14), (32, 15)] {
        let transactions: Vec<_> = [1, 2]
            .into_iter()
            .map(|who| attest(cfg, &state, cid, who, tag))
            .collect();
        state = step(&state, cfg, start + offset, &transactions);
    }
    step(&state, cfg, start + 48, &[])
}
fn release(
    cfg: &Config,
    state: &State,
    w: &EvolutionWitnessV3,
    leaf: Hash,
    score: u64,
) -> (Hash, Vec<u8>) {
    let budget = 1000_u64;
    let id = hash(
        b"release",
        &[
            &w.parent_ref,
            &w.contribution_id,
            &budget.to_le_bytes(),
            &w.components_root,
            &score.to_le_bytes(),
        ],
    );
    let mut payload = id.to_vec();
    payload.extend(w.parent_ref);
    payload.extend(w.contribution_id);
    payload.extend(budget.to_le_bytes());
    payload.extend(w.components_root);
    payload.extend(score.to_le_bytes());
    payload.push(1);
    payload.extend(leaf);
    payload.extend(score.to_le_bytes());
    (id, signed(cfg, state, 3, 8, payload))
}

#[test]
fn actual_joint_router_expert_then_base_and_mask_adopt_from_real_successor_parent() {
    let cfg = config();
    let mut state = initial(&cfg);
    let oracle = vector();
    assert_eq!(hex::encode(cfg.network), oracle["context"]["network"]);
    assert_eq!(hex::encode(cfg.parameters), oracle["context"]["parameters"]);
    assert_eq!(hex::encode(cfg.family), oracle["context"]["family"]);
    assert_eq!(hex::encode(cfg.plan), oracle["context"]["plan"]);
    assert_eq!(cfg.params, oracle["context"]["params"]);
    assert_eq!(hex::encode(public(0)), oracle["author"]);
    let mut first =
        evolution::build_witness(&state, &cfg, public(0), 0, 7, initial_operations(), [0; 32])
            .unwrap();
    self_root(&mut first, 0, 200_000);
    compare_witness(&first, &oracle["first"]);
    assert_eq!(
        first.contribution_id,
        evolution::contribution_id(&cfg, public(0), &first)
    );
    state = step(
        &state,
        &cfg,
        1,
        &[signed(&cfg, &state, 0, 24, first.encode().unwrap())],
    );
    let evidence = evolution::evidence(&state, first.contribution_id).unwrap();
    assert_eq!(evidence["candidate_correct"], 24);
    assert_eq!(evidence["parent_correct"], 3);
    assert_eq!(evidence["strongest_correct"], 19);
    assert_eq!(evidence["score"], 200_000);
    assert_eq!(evidence["fresh_dataset_activation"], false);
    state = close(state, &cfg, first.contribution_id, 0);
    assert_eq!(
        candidate(&state, first.contribution_id)["status"],
        "evaluated"
    );
    let (first_release, tx) = release(&cfg, &state, &first, first.contribution_id, 200_000);
    rejected(
        &state,
        &cfg,
        56,
        release(&cfg, &state, &first, [9; 32], 200_000).1,
        "EVOLUTION_SELF_ALLOCATION",
    );
    let closed_state = state.clone();
    state = step(&state, &cfg, 56, &[tx]);
    assert_eq!(state["model:current"], hex::encode(first_release));
    let actual = evolution::current_model(&state, &cfg).unwrap();
    assert_eq!(hex::encode(actual.encode()), oracle["first"]["model"]);
    assert_eq!(hex::encode(first_release), oracle["first"]["release"]);
    assert_eq!(actual.id(), first.candidate_artifact);
    assert!(actual.is_evolution());
    assert_eq!(actual.active_experts(), 7);
    assert_eq!(actual.coefficients()[771 + 257 + 256], 1);
    assert!(actual.coefficients()[3 * 771..4 * 771]
        .iter()
        .any(|&v| v != 0));
    assert!(actual.coefficients()[..771].iter().all(|&v| v == 0));
    assert_eq!(
        evolution::current_model(&closed_state, &cfg).unwrap().id(),
        first.parent_artifact
    );
    let w1 = trained(1);
    let w2 = trained(2);
    let difference: Vec<Vec<i16>> = w2
        .iter()
        .zip(&w1)
        .map(|(a, b)| a.iter().zip(b).map(|(&x, &y)| x - y).collect())
        .collect();
    let mut second = evolution::build_witness(
        &state,
        &cfg,
        public(0),
        1,
        2,
        vec![rank_two(0, &difference)],
        [0; 32],
    )
    .unwrap();
    assert_eq!(second.parent_ref, first_release);
    assert_eq!(second.parent_artifact, first.candidate_artifact);
    self_root(&mut second, 0, 40_000);
    compare_witness(&second, &oracle["second"]);
    state = step(
        &state,
        &cfg,
        129,
        &[signed(&cfg, &state, 0, 24, second.encode().unwrap())],
    );
    let evidence = evolution::evidence(&state, second.contribution_id).unwrap();
    assert_eq!(evidence["candidate_correct"], 25);
    assert_eq!(evidence["parent_correct"], 24);
    assert_eq!(evidence["score"], 40_000);
    state = close(state, &cfg, second.contribution_id, 128);
    let (second_release, tx) = release(&cfg, &state, &second, second.contribution_id, 40_000);
    state = step(&state, &cfg, 184, &[tx]);
    let actual = evolution::current_model(&state, &cfg).unwrap();
    assert_eq!(hex::encode(actual.encode()), oracle["second"]["model"]);
    assert_eq!(state["model:current"], hex::encode(second_release));
    assert_eq!(actual.active_experts(), 2);
    assert!(actual.coefficients()[..771].iter().any(|&v| v != 0));
    assert_eq!(actual.coefficients()[771 + 257 + 256], 1);
    let mut neutral =
        evolution::build_witness(&state, &cfg, public(0), 2, 3, vec![], [0; 32]).unwrap();
    self_root(&mut neutral, 0, 0);
    compare_witness(&neutral, &oracle["neutral"]);
    state = step(
        &state,
        &cfg,
        257,
        &[signed(&cfg, &state, 0, 24, neutral.encode().unwrap())],
    );
    let record = evolution::evidence(&state, neutral.contribution_id).unwrap();
    assert_eq!(record["candidate_correct"], 25);
    assert_eq!(record["score"], 0);
    state = close(state, &cfg, neutral.contribution_id, 256);
    assert!(pon_executor::execute(
        &state,
        &[release(&cfg, &state, &neutral, neutral.contribution_id, 0).1],
        312,
        public(3),
        [4; 32],
        2,
        &cfg
    )
    .is_err());
    assert_eq!(state["model:current"], hex::encode(second_release));
}

#[test]
fn native_refuses_forged_parent_hash_basis_alias_noop_and_cross_profile() {
    let cfg = config();
    let state = initial(&cfg);
    assert!(evolution::build_witness(&state, &cfg, public(0), 0, 7, vec![], [0; 32]).is_err());
    let noop = EvolutionOperationV3 {
        target: 0,
        rank: 1,
        factors: vec![0; 260],
    };
    assert_eq!(
        evolution::build_witness(&state, &cfg, public(0), 0, 2, vec![noop], [0; 32]).unwrap_err(),
        "EVOLUTION_NOOP_OPERATION"
    );
    let overflow = EvolutionOperationV3 {
        target: 0,
        rank: 1,
        factors: vec![32767; 260],
    };
    assert_eq!(
        evolution::build_witness(&state, &cfg, public(0), 0, 7, vec![overflow], [0; 32])
            .unwrap_err(),
        "EVOLUTION_DELTA_RANGE"
    );
    let first =
        evolution::build_witness(&state, &cfg, public(0), 0, 7, initial_operations(), [8; 32])
            .unwrap();
    let mut forged = first.clone();
    forged.candidate_artifact[0] ^= 1;
    rejected(
        &state,
        &cfg,
        1,
        signed(&cfg, &state, 0, 24, forged.encode().unwrap()),
        "EVOLUTION_COMPUTED_HASH",
    );
    let mut foreign = first.clone();
    foreign.parent_ref[0] ^= 1;
    rejected(
        &state,
        &cfg,
        1,
        signed(&cfg, &state, 0, 24, foreign.encode().unwrap()),
        "EVOLUTION_PARENT",
    );
    let admitted = step(
        &state,
        &cfg,
        1,
        &[signed(&cfg, &state, 0, 24, first.encode().unwrap())],
    );
    let mut equivalent = initial_operations();
    for coefficient in &mut equivalent[0].factors {
        *coefficient = -*coefficient;
    }
    let duplicate =
        evolution::build_witness(&admitted, &cfg, public(1), 0, 7, equivalent, [9; 32]).unwrap();
    assert_eq!(duplicate.update_id, first.update_id);
    assert_ne!(duplicate.contribution_id, first.contribution_id);
    rejected(
        &admitted,
        &cfg,
        2,
        signed(&cfg, &admitted, 1, 24, duplicate.encode().unwrap()),
        "DUPLICATE_FUNCTION_UPDATE",
    );
    let old = Config::installed_with_model_profiles(
        evaluation::QUORUM_PROFILE,
        "legacy-task-v1",
        trnm_mvcc_fee::model_evidence_v3::PROFILE,
    )
    .unwrap();
    for profile in [
        trnm_mvcc_fee::model_evidence_v3::PROFILE,
        trnm_mvcc_fee::model_composition_v4::PROFILE,
    ] {
        let historical = Config::installed_with_model_profiles(
            evaluation::QUORUM_PROFILE,
            "legacy-task-v1",
            profile,
        )
        .unwrap();
        let expected = &vector()["historical"][profile];
        assert_eq!(hex::encode(historical.network), expected["network"]);
        assert_eq!(hex::encode(historical.parameters), expected["parameters"]);
        assert_eq!(hex::encode(historical.family), expected["family"]);
        assert_eq!(hex::encode(historical.plan), expected["plan"]);
        assert_eq!(
            historical.params["factor_genesis_artifact"],
            expected["genesis_artifact"]
        );
    }
    let old_state = initial(&old);
    rejected(
        &old_state,
        &old,
        1,
        signed(&old, &old_state, 0, 24, first.encode().unwrap()),
        "EVOLUTION_PROFILE",
    );
    let old_input = factor::FactorInputV2 {
        slot: 0,
        rank: 2,
        coefficients: rank_two(2, &trained(1)).factors,
    };
    let old_witness =
        factor::build_witness(&old_state, &old, public(0), 0, old_input, [1; 32]).unwrap();
    rejected(
        &state,
        &cfg,
        1,
        signed(&cfg, &state, 0, 23, old_witness.encode().unwrap()),
        "FACTOR_PROFILE",
    );
    assert_ne!(cfg.network, old.network);
    assert_ne!(cfg.parameters, old.parameters);
    assert_ne!(cfg.family, old.family);
    assert_ne!(cfg.plan, old.plan);
    assert_eq!(old.params["consensus_revision"], 15);
    assert_eq!(cfg.params["consensus_revision"], 16);
    assert!(Config::installed_with_model_profiles(
        evaluation::PROFILE,
        "legacy-task-v1",
        evolution::PROFILE
    )
    .is_err());
    assert!(!old_state.keys().any(|k| k.starts_with("linear-model-v3:")));
    assert!(!state.keys().any(|k| k.starts_with("linear-model-v2:")));
    let legacy = factor::IntegerModelV2::genesis(old.family);
    let newer = evolution::current_model(&state, &cfg).unwrap();
    assert_eq!(legacy.encode().len(), 7756);
    assert_eq!(newer.encode().len(), 7758);
    assert!(factor::IntegerModelV2::decode(&newer.encode(), cfg.family).is_err());
    assert!(factor::IntegerModelV2::decode_evolution(&legacy.encode(), old.family).is_err());
    let mut corrupt = newer.encode();
    corrupt[47] = 1;
    assert!(factor::IntegerModelV2::decode_evolution(&corrupt, cfg.family).is_err());
}

#[test]
fn pinned_new_text_windows_select_frozen_roots_and_replay_actual_parent_controls_at_activation() {
    let oracle = window_vector();
    let cfg = configured_windows(
        WINDOW_MANIFEST,
        digest(&oracle["owner"]),
        digest(&oracle["sha256"]),
    )
    .unwrap();
    let manifest: SignedTaskWindows = serde_json::from_slice(WINDOW_MANIFEST).unwrap();
    let default = config();
    assert_ne!(cfg.network, default.network);
    assert_ne!(cfg.parameters, default.parameters);
    assert_ne!(cfg.plan, default.plan);
    assert_eq!(cfg.family, default.family);
    let cloned = cfg.clone();
    let mut state = initial(&cfg);
    let mut parent = None;
    let mut previous_rows = vec![vec![0_i16; 257]; 3];
    let mut previous_evidence = [0; 32];
    for index in 0..2 {
        let generation = index as u64;
        let material =
            trnm_mvcc_fee::model_evidence_v3::evaluation_material(&cloned, generation).unwrap();
        assert_eq!(material["tasks"], oracle["windows"][index]["rows"]);
        assert_eq!(material["tasks_root"], manifest.windows[index].tasks_root);
        let trained = vector_rows(&oracle["windows"][index]["trained"]);
        let operations = if index == 0 {
            let mut router = vec![0_i16; 260];
            router[1] = 1;
            router[259] = 1;
            vec![
                EvolutionOperationV3 {
                    target: 1,
                    rank: 1,
                    factors: router,
                },
                rank_two(3, &trained),
            ]
        } else {
            let difference: Vec<Vec<i16>> = trained
                .iter()
                .zip(&previous_rows)
                .map(|(a, b)| a.iter().zip(b).map(|(&x, &y)| x - y).collect())
                .collect();
            vec![rank_two(0, &difference)]
        };
        let score = oracle["windows"][index]["score"].as_u64().unwrap();
        let mut witness =
            evolution::build_witness(&state, &cfg, public(0), generation, 7, operations, [0; 32])
                .unwrap();
        if let Some(parent) = parent {
            assert_eq!(witness.parent_ref, parent);
        }
        self_root(&mut witness, 0, score);
        let start = generation * 128;
        state = step(
            &state,
            &cfg,
            start + 1,
            &[signed(&cfg, &state, 0, 24, witness.encode().unwrap())],
        );
        let record = evolution::evidence(&state, witness.contribution_id).unwrap();
        for field in [
            "candidate_correct",
            "parent_correct",
            "strongest_correct",
            "score",
        ] {
            assert_eq!(
                record[field], oracle["windows"][index][field],
                "window {index} {field}"
            );
        }
        assert_eq!(record["tasks"], material["tasks_root"]);
        assert_eq!(record["rows"], 6);
        assert_eq!(record["independent_accepted"], false);
        assert_eq!(record["task_window"]["source_class"], "controlled-source");
        assert_eq!(
            candidate(&state, witness.contribution_id)["public_evaluation"]["plan"]["dataset"],
            material["tasks_root"]
        );
        let commits: Vec<_> = [1, 2]
            .into_iter()
            .map(|who| attest(&cfg, &state, witness.contribution_id, who, 14))
            .collect();
        state = step(&state, &cfg, start + 16, &commits);
        if index == 1 {
            let mut wrong =
                Envelope::decode(&attest(&cfg, &state, witness.contribution_id, 1, 15)).unwrap();
            wrong.payload[96..128].copy_from_slice(&previous_evidence);
            rejected(
                &state,
                &cfg,
                start + 32,
                signed(&cfg, &state, 1, 15, wrong.payload),
                "MODEL_EVIDENCE_REVEAL",
            );
        }
        let reveals: Vec<_> = [1, 2]
            .into_iter()
            .map(|who| attest(&cfg, &state, witness.contribution_id, who, 15))
            .collect();
        state = step(&state, &cfg, start + 32, &reveals);
        state = step(&state, &cfg, start + 48, &[]);
        let (release_id, transaction) =
            release(&cfg, &state, &witness, witness.contribution_id, score);
        state = step(&state, &cfg, start + 56, &[transaction]);
        assert_eq!(state["model:current"], hex::encode(release_id));
        assert_eq!(
            evolution::current_model(&state, &cfg).unwrap().id(),
            witness.candidate_artifact
        );
        parent = Some(release_id);
        previous_rows = trained;
        previous_evidence = digest(&record["digest"]);
    }
    let mut future = manifest;
    for window in &mut future.windows {
        window.activate_round += 1;
    }
    let raw = resign_windows(&mut future);
    let future =
        configured_windows(&raw, digest(&oracle["owner"]), Sha256::digest(&raw).into()).unwrap();
    let material = trnm_mvcc_fee::model_evidence_v3::evaluation_material(&future, 0).unwrap();
    assert_eq!(material["tasks"].as_array().unwrap().len(), 25);
    assert!(material["task_window"].is_null());
    assert_eq!(
        trnm_mvcc_fee::model_evidence_v3::evaluation_material(&future, 1).unwrap()["tasks"],
        oracle["windows"][0]["rows"]
    );
}

#[test]
fn external_data_owner_signature_roots_order_and_repeated_content_fail_closed() {
    let oracle = window_vector();
    let owner = digest(&oracle["owner"]);
    assert_eq!(
        configured_windows(WINDOW_MANIFEST, owner, [0; 32]).err(),
        Some("TASK_WINDOW_PIN")
    );
    assert_eq!(
        configured_windows(WINDOW_MANIFEST, public(0), digest(&oracle["sha256"])).err(),
        Some("TASK_WINDOW_OWNER")
    );
    let original: SignedTaskWindows = serde_json::from_slice(WINDOW_MANIFEST).unwrap();
    let mut bad = original.clone();
    bad.signature.replace_range(..2, "00");
    let raw = serde_json::to_vec(&bad).unwrap();
    assert_eq!(
        configured_windows(&raw, owner, Sha256::digest(&raw).into()).err(),
        Some("TASK_WINDOW_SIGNATURE")
    );
    for (case, expected) in [
        (0, "TASK_WINDOW_ACTIVATION"),
        (1, "TASK_WINDOW_REPEATED_DATA"),
        (2, "TASK_WINDOW_ROOT"),
        (3, "TASK_WINDOW_CONTENT_HASH"),
        (4, "TASK_WINDOW_SOURCE_REVISION"),
        (5, "TASK_WINDOW_ORDER"),
        (6, "TASK_WINDOW_CLASSES"),
    ] {
        let mut manifest = original.clone();
        match case {
            0 => manifest.windows.swap(0, 1),
            1 => {
                manifest.windows[1] = manifest.windows[0].clone();
                manifest.windows[1].activate_round = 1;
            }
            2 => manifest.windows[0].tasks_root = hex::encode([9; 32]),
            3 => manifest.windows[0].tasks[0].content_sha256 = hex::encode([9; 32]),
            4 => manifest.windows[0].source_revision = hex::encode([9; 32]),
            5 => manifest.windows[0].tasks.reverse(),
            6 => {
                for task in &mut manifest.windows[0].tasks {
                    task.label = 0;
                }
            }
            _ => unreachable!(),
        }
        let raw = resign_windows(&mut manifest);
        assert_eq!(
            configured_windows(&raw, owner, Sha256::digest(&raw).into()).err(),
            Some(expected),
            "case {case}"
        );
    }
    let mut unknown: Value = serde_json::from_slice(WINDOW_MANIFEST).unwrap();
    unknown["arbitrary_features"] = json!([]);
    let raw = serde_json::to_vec(&unknown).unwrap();
    assert_eq!(
        configured_windows(&raw, owner, Sha256::digest(&raw).into()).err(),
        Some("TASK_WINDOW_ENCODING")
    );
    assert!(Config::installed_with_model_profiles_and_task_windows(
        evaluation::QUORUM_PROFILE,
        "legacy-task-v1",
        trnm_mvcc_fee::model_evidence_v3::PROFILE,
        Some(PinnedTaskWindows {
            raw: WINDOW_MANIFEST,
            sha256: digest(&oracle["sha256"]),
            owner
        })
    )
    .is_err());
}
