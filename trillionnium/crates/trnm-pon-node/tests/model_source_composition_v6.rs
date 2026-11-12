//! Known-source partition controls through the original signed M06 executor.
//! The 25 training/evaluation rows are public historical fixtures. Consecutive
//! M06 execution is distinct from a PNW1 chain, independent model benefit, unknown
//! source discovery, production adoption, or a general incentive theorem.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1, integer_factor_candidate_v2 as factor, model_evidence_v3,
    model_source_composition_v6 as composition,
    pon_commitment::{CacheLimits, CheckedExecutionParent},
    pon_executor::{self, Config, ExecutionControl, PrefixContext, State},
    public_evaluation as evaluation,
};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::{
    integer_factor_v2::FactorWitnessV2,
    pon_wire::{hash, Envelope, Hash},
};

const FEATURES: usize = 257;
const BUDGET: u64 = 100_000;
const CLOCK: u64 = 1_800_100_000;

fn context() -> (Config, Settings) {
    (
        Config::installed_with_model_profiles(
            evaluation::PROFILE,
            continuity_v1::PROFILE,
            composition::PROFILE,
        )
        .unwrap(),
        Settings::development_with_model_profiles(
            None,
            evaluation::PROFILE,
            continuity_v1::PROFILE,
            composition::PROFILE,
        )
        .unwrap(),
    )
}
fn initial(c: &Config, settings: &Settings) -> State {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    assert_eq!(node.settings().network(), c.network);
    node.read_active().unwrap().2
}
fn signing_key(who: u64) -> String {
    hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))
}
fn signed(c: &Config, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key = signing_key_from_hex(&signing_key(who)).unwrap();
    let mut tx = Envelope {
        network: c.network,
        sender: development_public(who).unwrap(),
        nonce,
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
fn account(state: &State, who: u64) -> &Value {
    &state[&format!("account:{}", hex::encode(development_public(who).unwrap()))]
}
fn nonce(state: &State, who: u64) -> u64 {
    account(state, who)["nonce"].as_u64().unwrap() + 1
}
fn object(state: &State, cid: Hash) -> &Value {
    &state[&format!("contribution:{}", hex::encode(cid))]
}
fn read_hash(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn rows() -> Vec<(Vec<i16>, usize)> {
    let policy: Value = serde_json::from_str(include_str!(
        "../../../../config/pon/model-evidence-v3.json"
    ))
    .unwrap();
    let tasks = policy["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 25);
    tasks
        .iter()
        .map(|task| {
            let features = task["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| i16::try_from(v.as_i64().unwrap()).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(features.len(), FEATURES);
            (features, task["label"].as_u64().unwrap() as usize)
        })
        .collect()
}
fn argmax(scores: &[i64; 3]) -> usize {
    let mut prediction = 0;
    for index in 1..3 {
        if scores[index] > scores[prediction] {
            prediction = index;
        }
    }
    prediction
}
fn dot(a: &[i16], b: &[i16]) -> i64 {
    a.iter()
        .zip(b)
        .map(|(&a, &b)| i64::from(a) * i64::from(b))
        .sum()
}
/// Deterministic perceptron visits, with the lowest class winning ties. Subtract
/// row zero after training: the returned rows are A for B=[[0,0],[1,0],[0,1]].
fn trained(rotation: usize, visits: usize) -> Vec<i16> {
    let rows = rows();
    let mut weights = [vec![0_i16; FEATURES], vec![0; FEATURES], vec![0; FEATURES]];
    for visit in 0..visits {
        let (features, target) = &rows[(rotation + visit) % rows.len()];
        let prediction = argmax(&weights.each_ref().map(|w| dot(w, features)));
        if prediction != *target {
            for (index, &feature) in features.iter().enumerate() {
                weights[prediction][index] -= feature;
                weights[*target][index] += feature;
            }
        }
    }
    weights[1..]
        .iter()
        .flat_map(|row| row.iter().zip(&weights[0]).map(|(&w, &base)| w - base))
        .collect()
}
fn add(a: &[i16], b: &[i16]) -> Vec<i16> {
    assert_eq!(a.len(), 2 * FEATURES);
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(&a, &b)| a.checked_add(b).unwrap())
        .collect()
}
fn subtract(a: &[i16], b: &[i16]) -> Vec<i16> {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(&a, &b)| a.checked_sub(b).unwrap())
        .collect()
}
fn correct(model: &[i16]) -> u64 {
    rows()
        .iter()
        .filter(|(features, label)| {
            argmax(&[
                0,
                dot(&model[..FEATURES], features),
                dot(&model[FEATURES..], features),
            ]) == *label
        })
        .count() as u64
}
fn full_model(c: &Config, model: &[i16]) -> factor::IntegerModelV2 {
    let mut coefficients = vec![0; 5 * 3 * FEATURES];
    // Zero base and router select expert slot zero; normalized class row zero is zero.
    coefficients[7 * FEATURES..9 * FEATURES].copy_from_slice(model);
    factor::IntegerModelV2::from_coefficients(c.family, coefficients).unwrap()
}
fn stored_model(state: &State, c: &Config, id: Hash) -> factor::IntegerModelV2 {
    let prefix = format!("linear-model-v2:{}:", hex::encode(id));
    let chunks = state[&format!("{prefix}meta")]["chunks"].as_u64().unwrap();
    let mut bytes = Vec::new();
    for index in 0..chunks {
        bytes.extend(hex::decode(state[&format!("{prefix}{index:02}")].as_str().unwrap()).unwrap());
    }
    let model = factor::IntegerModelV2::decode(&bytes, c.family).unwrap();
    assert_eq!(model.id(), id);
    model
}
fn witness(
    state: &State,
    c: &Config,
    who: u64,
    round: u64,
    delta: &[i16],
    root: Hash,
) -> FactorWitnessV2 {
    let mut coefficients = vec![0, 0, 1, 0, 0, 1];
    coefficients.extend(delta);
    factor::build_witness(
        state,
        c,
        development_public(who).unwrap(),
        round,
        factor::FactorInputV2 {
            slot: 0,
            rank: 2,
            coefficients,
        },
        root,
    )
    .unwrap()
}

#[derive(Clone)]
struct Allocation {
    cid: Hash,
    who: u64,
    weight: u64,
}
impl Allocation {
    fn leaf(&self, c: &Config) -> Hash {
        composition::allocation_leaf(
            c,
            self.cid,
            development_public(self.who).unwrap(),
            self.weight,
        )
    }
}
struct Fixture {
    authors: Vec<u64>,
    components: Vec<FactorWitnessV2>,
    bundle: FactorWitnessV2,
    allocations: Vec<Allocation>,
}
impl Fixture {
    fn new(
        state: &State,
        c: &Config,
        authors: &[u64],
        parts: &[Vec<i16>],
        bundle_model: &[i16],
        weights: &[u64],
        payees: &[u64],
    ) -> Self {
        assert_eq!(authors.len(), parts.len());
        assert_eq!(authors.len(), weights.len());
        assert_eq!(authors.len(), payees.len());
        let components = parts
            .iter()
            .zip(authors)
            .map(|(delta, &who)| witness(state, c, who, 0, delta, [8; 32]))
            .collect::<Vec<_>>();
        let mut allocations = components
            .iter()
            .zip(weights)
            .zip(payees)
            .map(|((component, &weight), &who)| Allocation {
                cid: component.contribution_id,
                who,
                weight,
            })
            .collect::<Vec<_>>();
        allocations.sort_by_key(|allocation| allocation.cid);
        let root = allocation_root(c, &allocations);
        let bundle = witness(state, c, 3, 0, bundle_model, root);
        Self {
            authors: authors.to_vec(),
            components,
            bundle,
            allocations,
        }
    }
    fn ids(&self) -> Vec<Hash> {
        self.components
            .iter()
            .chain(std::iter::once(&self.bundle))
            .map(|component| component.contribution_id)
            .collect()
    }
    fn submissions(&self, state: &State, c: &Config) -> Vec<Vec<u8>> {
        let mut next = BTreeMap::new();
        let mut result = Vec::new();
        for (component, &who) in self.components.iter().zip(&self.authors) {
            let n = next.entry(who).or_insert_with(|| nonce(state, who));
            result.push(signed(c, who, *n, 23, component.encode().unwrap()));
            *n += 1;
        }
        let n = next.entry(3).or_insert_with(|| nonce(state, 3));
        result.push(signed(c, 3, *n, 23, self.bundle.encode().unwrap()));
        result
    }
    fn release(&self, state: &State, c: &Config) -> (Hash, Vec<u8>) {
        let total = self
            .allocations
            .iter()
            .map(|allocation| allocation.weight)
            .sum();
        let root = allocation_root(c, &self.allocations);
        let id = composition::release_id(
            c,
            self.bundle.parent_ref,
            self.bundle.contribution_id,
            BUDGET,
            root,
            total,
        );
        let mut payload = id.to_vec();
        payload.extend(self.bundle.parent_ref);
        payload.extend(self.bundle.contribution_id);
        payload.extend(BUDGET.to_le_bytes());
        payload.extend(root);
        payload.extend(total.to_le_bytes());
        payload.push(u8::try_from(self.allocations.len()).unwrap());
        for allocation in &self.allocations {
            payload.extend(allocation.cid);
            payload.extend(allocation.weight.to_le_bytes());
        }
        (id, signed(c, 3, nonce(state, 3), 8, payload))
    }
    fn proof(&self, c: &Config, position: usize, legacy: bool) -> Vec<Hash> {
        let mut layer = self
            .allocations
            .iter()
            .map(|allocation| {
                if legacy {
                    legacy_leaf(allocation)
                } else {
                    allocation.leaf(c)
                }
            })
            .collect::<Vec<_>>();
        let mut index = position;
        let mut siblings = Vec::new();
        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(*layer.last().unwrap());
            }
            siblings.push(layer[index ^ 1]);
            layer = layer
                .chunks_exact(2)
                .map(|pair| {
                    if legacy {
                        legacy_pair(pair[0], pair[1])
                    } else {
                        composition::pair(pair[0], pair[1])
                    }
                })
                .collect();
            index /= 2;
        }
        if !legacy {
            assert_eq!(layer[0], allocation_root(c, &self.allocations));
        }
        siblings
    }
    fn claim(
        &self,
        state: &State,
        c: &Config,
        released: Hash,
        position: usize,
        legacy: bool,
    ) -> Vec<u8> {
        let allocation = &self.allocations[position];
        let siblings = self.proof(c, position, legacy);
        let mut payload = released.to_vec();
        payload.extend(allocation.cid);
        payload.extend(allocation.weight.to_le_bytes());
        payload.push(u8::try_from(siblings.len()).unwrap());
        for sibling in siblings {
            payload.extend(sibling);
        }
        signed(c, allocation.who, nonce(state, allocation.who), 9, payload)
    }
    fn all_claims(&self, state: &State, c: &Config, released: Hash) -> Vec<Vec<u8>> {
        let mut next = BTreeMap::new();
        self.allocations
            .iter()
            .enumerate()
            .map(|(position, allocation)| {
                let payload = Envelope::decode(&self.claim(state, c, released, position, false))
                    .unwrap()
                    .payload;
                let n = next
                    .entry(allocation.who)
                    .or_insert_with(|| nonce(state, allocation.who));
                let raw = signed(c, allocation.who, *n, 9, payload);
                *n += 1;
                raw
            })
            .collect()
    }
}
fn composition_record<'a>(state: &'a State, release: &Value) -> &'a Value {
    let reference = &release["model_composition_v6"];
    assert_eq!(
        reference["schema"],
        "native-model-source-composition-reference-v6"
    );
    let key = reference["record_key"].as_str().unwrap();
    assert!(key.starts_with("model-source-composition-v6:"));
    let record = &state[key];
    assert_eq!(
        record["schema"],
        "native-model-source-composition-record-v6"
    );
    assert_eq!(
        key,
        format!(
            "model-source-composition-v6:{}",
            record["bundle"].as_str().unwrap()
        )
    );
    assert_eq!(reference["policy"], record["policy"]);
    assert_eq!(reference["digest"], record["digest"]);
    // The original state root canonically encodes validated JSON values with
    // serde_json::to_vec. Both records retain its unchanged 4096-byte row cap.
    assert!(serde_json::to_vec(release).unwrap().len() <= 4096);
    assert!(serde_json::to_vec(record).unwrap().len() <= 4096);
    record
}
fn allocation_root(c: &Config, allocations: &[Allocation]) -> Hash {
    composition::allocation_root(
        allocations
            .iter()
            .map(|allocation| allocation.leaf(c))
            .collect(),
    )
    .unwrap()
}
fn legacy_leaf(allocation: &Allocation) -> Hash {
    hash(
        b"allocation-leaf",
        &[
            &allocation.cid,
            &development_public(allocation.who).unwrap(),
            &allocation.weight.to_le_bytes(),
        ],
    )
}
fn legacy_pair(a: Hash, b: Hash) -> Hash {
    if a < b {
        hash(b"allocation-node", &[&a, &b])
    } else {
        hash(b"allocation-node", &[&b, &a])
    }
}
fn step(state: &State, c: &Config, height: u64, txs: &[Vec<u8>]) -> State {
    pon_executor::execute(
        state,
        txs,
        height,
        development_public(3).unwrap(),
        [4; 32],
        4,
        c,
    )
    .unwrap_or_else(|error| panic!("signed M06 height {height}: {error}"))
    .state
}
fn advance(state: &State, c: &Config, from: u64, to: u64) -> State {
    let mut result = state.clone();
    for height in from + 1..=to {
        result = step(&result, c, height, &[]);
        continuity_v1::check_state(&result, height, c).unwrap();
    }
    result
}
fn attestations(state: &State, c: &Config, ids: &[Hash], tag: u8) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    for who in [0, 1, 2] {
        let mut next = nonce(state, who);
        for &cid in ids {
            if object(state, cid)["owner"] == hex::encode(development_public(who).unwrap()) {
                continue;
            }
            let evidence = composition::evidence(state, cid).unwrap();
            let round = evaluation::round(&object(state, cid)["public_evaluation"]).unwrap();
            let score = evidence["score"].as_u64().unwrap();
            let digest = read_hash(&evidence["digest"]);
            let salt = [who as u8 + 1; 32];
            let mut payload = cid.to_vec();
            payload.extend(round);
            if tag == 14 {
                payload.extend(
                    evaluation::reveal_commitment_for(
                        &object(state, cid)["public_evaluation"],
                        &evaluation::Reveal {
                            round,
                            candidate: cid,
                            evaluator: development_public(who).unwrap(),
                            plan: c.plan,
                            evidence: digest,
                            score,
                            salt,
                        },
                    )
                    .unwrap(),
                );
            } else {
                assert_eq!(tag, 15);
                payload.extend(c.plan);
                payload.extend(digest);
                payload.extend(score.to_le_bytes());
                payload.extend(salt);
            }
            result.push(signed(c, who, next, tag, payload));
            next += 1;
        }
    }
    result
}
fn qualified(initial: &State, c: &Config, fixture: &Fixture) -> State {
    let mut state = initial.clone();
    for height in 1..=55 {
        let txs = match height {
            1 => fixture.submissions(&state, c),
            16 => attestations(&state, c, &fixture.ids(), 14),
            32 => attestations(&state, c, &fixture.ids(), 15),
            _ => Vec::new(),
        };
        state = step(&state, c, height, &txs);
        continuity_v1::check_state(&state, height, c).unwrap();
    }
    for cid in fixture.ids() {
        let evaluation = evaluation::read_evaluation(&state, cid).unwrap();
        assert_eq!(evaluation["closed"]["status"], "complete-scored");
        assert_eq!(evaluation["closed"]["missing_reveal_count"], 0);
    }
    state
}
fn assert_release_refusal_is_atomic(state: &State, c: &Config, tx: Vec<u8>, expected: &str) {
    assert_eq!(
        pon_executor::execute(
            state,
            std::slice::from_ref(&tx),
            56,
            development_public(3).unwrap(),
            [4; 32],
            4,
            c
        )
        .err(),
        Some(expected)
    );
    let progress = |_| Ok::<_, &'static str>(());
    let mut prefix = CheckedExecutionParent::bind(
        state,
        pon_executor::root(state).unwrap(),
        None,
        CacheLimits::default(),
    )
    .unwrap()
    .into_prefix_with_control(
        PrefixContext {
            timestamp: None,
            height: 56,
            miner: development_public(3).unwrap(),
            parent_id: [4; 32],
        },
        c,
        &ExecutionControl::new(&progress, &()),
    )
    .unwrap();
    let mut payload = development_public(3).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let transfer = signed(c, 2, nonce(state, 2), 1, payload);
    let before = prefix
        .execute(std::slice::from_ref(&transfer))
        .unwrap()
        .output;
    assert_eq!(
        prefix.execute(&[transfer.clone(), tx]).unwrap_err(),
        expected
    );
    assert_eq!(prefix.len(), 1);
    let after = prefix.execute(&[transfer]).unwrap().output;
    assert_eq!(before.state, after.state);
    assert_eq!(before.receipts, after.receipts);
    assert_eq!(before.root, after.root);
    assert!(after
        .state
        .iter()
        .filter(|(key, _)| key.starts_with("model-source-v6:"))
        .all(|(_, value)| value["reserved_units"] == 0));
    assert!(!after
        .state
        .keys()
        .any(|key| key.starts_with("model-source-composition-v6:")));
}
struct Vectors {
    original: Vec<Vec<i16>>,
    split: Vec<Vec<i16>>,
    four_parts: Vec<Vec<i16>>,
    bundle: Vec<i16>,
}
fn vectors() -> Vectors {
    let a = trained(0, 25);
    let b = trained(1, 25);
    let bundle = add(&a, &b);
    let mut z = vec![0; 2 * FEATURES];
    z[FEATURES - 1] = 1000;
    z[2 * FEATURES - 1] = -1000;
    let split = vec![
        add(&a, &z),
        z.iter().map(|value| -value).collect(),
        b.clone(),
    ];
    assert_eq!(add(&add(&split[0], &split[1]), &split[2]), bundle);
    assert_eq!([correct(&a), correct(&b), correct(&bundle)], [24, 23, 25]);
    assert_eq!(
        split.iter().map(|part| correct(part)).collect::<Vec<_>>(),
        [2, 20, 23]
    );
    assert_eq!(
        split
            .iter()
            .map(|part| correct(&subtract(&bundle, part)))
            .collect::<Vec<_>>(),
        [20, 2, 24]
    );
    let four_parts = vec![
        add(&a, &z),
        z.iter().map(|value| -2 * value).collect(),
        z,
        b.clone(),
    ];
    assert_eq!(
        add(
            &add(&add(&four_parts[0], &four_parts[1]), &four_parts[2]),
            &four_parts[3]
        ),
        bundle
    );
    Vectors {
        original: vec![a, b],
        split,
        four_parts,
        bundle,
    }
}
struct PaidCase {
    fixture: Fixture,
    state: State,
    released: Hash,
    source: Hash,
    source_gross: u64,
    other_gross: u64,
    group_net: i128,
}
fn paid_case(initial: &State, c: &Config, fixture: Fixture, bundle: &[i16]) -> PaidCase {
    let mut state = qualified(initial, c, &fixture);
    let source = read_hash(
        &object(&state, fixture.components[0].contribution_id)["model_evidence_v6"]["source"],
    );
    let other = read_hash(
        &object(&state, fixture.components.last().unwrap().contribution_id)["model_evidence_v6"]
            ["source"],
    );
    assert_ne!(source, other);
    if fixture.authors.contains(&1) {
        assert_eq!(
            read_hash(
                &object(&state, fixture.components[1].contribution_id)["model_evidence_v6"]
                    ["source"]
            ),
            source
        );
    }
    assert_eq!(
        state[&composition::source_key(0, source)]["intakes"],
        fixture.authors.iter().filter(|&&who| who <= 1).count()
    );
    let (released, tx) = fixture.release(&state, c);
    state = step(&state, c, 56, &[tx]);
    assert_eq!(state["model:current"], hex::encode(released));
    assert_eq!(
        stored_model(&state, c, fixture.bundle.candidate_artifact),
        full_model(c, bundle)
    );
    let record = &state[&format!("release:{}", hex::encode(released))];
    assert_eq!(record["schema"], "native-model-source-release-v6");
    let measured = composition_record(&state, record);
    assert_eq!(measured["correct"], 25);
    assert_eq!(measured["strongest_correct"], 24);
    assert_eq!(measured["total_weight"], 120_000);
    assert_eq!(measured["evaluation_status"], "complete-scored");
    assert_eq!(measured["rows"], 25);
    assert_eq!(measured["observed_rows"], 25);
    for group in measured["sources"].as_array().unwrap() {
        for artifact in ["aggregate_artifact", "without_artifact"] {
            assert_ne!(read_hash(&group[artifact]), [0; 32]);
        }
        for correct in ["aggregate_correct", "without_correct"] {
            assert!(group[correct].as_u64().unwrap() <= 25);
        }
    }
    for flag in [
        "prospective_accepted",
        "independent_accepted",
        "public_reward_eligible",
        "unknown_common_control_discovered",
        "shapley_fairness_accepted",
    ] {
        assert_eq!(measured[flag], false);
    }
    assert_eq!(record["remaining"], BUDGET);
    assert_eq!(
        state[&composition::source_key(0, source)]["reserved_units"],
        66_666
    );
    assert_eq!(
        state[&composition::source_key(0, other)]["reserved_units"],
        33_333
    );
    state = advance(&state, c, 56, 75);
    let before = state.clone();
    let txs = fixture.all_claims(&state, c, released);
    state = step(&state, c, 76, &txs);
    let record = &state[&format!("release:{}", hex::encode(released))];
    composition_record(&state, record);
    assert_eq!(
        record["claims"].as_object().unwrap().len(),
        fixture.allocations.len()
    );
    assert_eq!(record["remaining"], 1);
    let mut source_gross = 0;
    let mut other_gross = 0;
    let mut payee_gross_and_fees = BTreeMap::<u64, (u64, u64)>::new();
    for (allocation, raw) in fixture.allocations.iter().zip(&txs) {
        let amount = (u128::from(BUDGET) * u128::from(allocation.weight) / 120_000) as u64;
        assert_eq!(record["claims"][hex::encode(allocation.cid)], amount);
        let fee = c.fees[9] + raw.len() as u64 * c.params["byte_fee_units"].as_u64().unwrap();
        let total = payee_gross_and_fees.entry(allocation.who).or_default();
        total.0 += amount;
        total.1 += fee;
        if allocation.who <= 1 {
            source_gross += amount;
        } else {
            other_gross += amount;
        }
    }
    for (who, (gross, fees)) in payee_gross_and_fees {
        assert_eq!(
            account(&state, who)["balance"].as_u64().unwrap(),
            account(&before, who)["balance"].as_u64().unwrap() + gross - fees
        );
    }
    assert_eq!((source_gross, other_gross), (66_666, 33_333));
    assert_eq!(
        source_gross + other_gross + record["remaining"].as_u64().unwrap(),
        BUDGET
    );
    assert_eq!(
        state[&composition::source_key(0, source)]["reserved_units"],
        66_666
    );
    assert_eq!(
        state[&composition::source_key(0, other)]["reserved_units"],
        33_333
    );
    let group_balance = |s: &State| {
        account(s, 0)["balance"].as_u64().unwrap() + account(s, 1)["balance"].as_u64().unwrap()
    };
    let group_net = i128::from(group_balance(&state)) - i128::from(group_balance(initial));
    PaidCase {
        fixture,
        state,
        released,
        source,
        source_gross,
        other_gross,
        group_net,
    }
}

#[test]
fn source_aggregation_keeps_original_and_split_gross_reservations_and_dust_identical() {
    let (c, settings) = context();
    let initial = initial(&c, &settings);
    assert_eq!(model_evidence_v3::MAX_INTAKES, 4);
    assert_eq!(model_evidence_v3::MAX_RESERVED_UNITS, BUDGET);
    let vectors = vectors();
    let original = paid_case(
        &initial,
        &c,
        Fixture::new(
            &initial,
            &c,
            &[0, 2],
            &vectors.original,
            &vectors.bundle,
            &[80_000, 40_000],
            &[0, 2],
        ),
        &vectors.bundle,
    );
    let split = paid_case(
        &initial,
        &c,
        Fixture::new(
            &initial,
            &c,
            &[0, 1, 2],
            &vectors.split,
            &vectors.bundle,
            &[80_000, 0, 40_000],
            &[0, 1, 2],
        ),
        &vectors.bundle,
    );
    let four_parts = paid_case(
        &initial,
        &c,
        Fixture::new(
            &initial,
            &c,
            &[0, 1, 1, 2],
            &vectors.four_parts,
            &vectors.bundle,
            &[80_000, 0, 0, 40_000],
            &[0, 1, 1, 2],
        ),
        &vectors.bundle,
    );
    assert_eq!(
        original.fixture.bundle.candidate_artifact,
        split.fixture.bundle.candidate_artifact
    );
    assert_eq!(original.source, split.source);
    assert_eq!(original.source_gross, split.source_gross);
    assert_eq!(original.other_gross, split.other_gross);
    assert_eq!(
        original.fixture.bundle.candidate_artifact,
        four_parts.fixture.bundle.candidate_artifact
    );
    assert_eq!(original.source, four_parts.source);
    assert_eq!(original.source_gross, four_parts.source_gross);
    assert_eq!(original.other_gross, four_parts.other_gross);
    assert_eq!(four_parts.fixture.allocations.len(), 4);
    assert!(
        split.group_net < original.group_net,
        "extra split commands retain their real charged fees"
    );
    assert!(four_parts.group_net < split.group_net);
    eprintln!(
        "native-v6-partition-control {}",
        json!({
            "schema":"native-model-source-partition-control-v6",
            "scope":"ordinary-Node-genesis-and-signed-M06-contiguous-1-through-76",
            "original_gross":original.source_gross,"split_gross":split.source_gross,
            "four_component_gross":four_parts.source_gross,
            "other_gross":split.other_gross,"dust":1,
            "original_source_net_after_own_fees":original.group_net.to_string(),
            "split_source_net_after_own_fees":split.group_net.to_string(),
            "four_component_source_net_after_own_fees":four_parts.group_net.to_string(),
            "original_final_root":hex::encode(pon_executor::root(&original.state).unwrap()),
            "split_final_root":hex::encode(pon_executor::root(&split.state).unwrap()),
            "four_component_final_root":hex::encode(pon_executor::root(&four_parts.state).unwrap()),
            "maximum_component_count":4,"release_and_evidence_row_cap_bytes":4096,
            "PNW1_chain_verified":false,"independent_future_task_gain":false,
            "unknown_common_control_discovered":false,"production_activation":false
        })
    );
}

#[test]
fn old_component_omission_weights_wrong_payee_and_missing_source_representative_refuse_atomically()
{
    let (c, settings) = context();
    let initial = initial(&c, &settings);
    let vectors = vectors();
    let cases = [
        Fixture::new(
            &initial,
            &c,
            &[0, 1, 2],
            &vectors.split,
            &vectors.bundle,
            &[200_000, 920_000, 40_000],
            &[0, 1, 2],
        ),
        Fixture::new(
            &initial,
            &c,
            &[0, 2],
            &vectors.original,
            &vectors.bundle,
            &[80_000, 40_000],
            &[1, 2],
        ),
        Fixture::new(
            &initial,
            &c,
            &[1, 2],
            &vectors.original,
            &vectors.bundle,
            &[80_000, 40_000],
            &[1, 2],
        ),
    ];
    for (fixture, expected) in
        cases
            .into_iter()
            .zip(["MODEL_SOURCE_WEIGHT", "ROOT", "MODEL_SOURCE_PAYEE"])
    {
        let state = qualified(&initial, &c, &fixture);
        assert_release_refusal_is_atomic(&state, &c, fixture.release(&state, &c).1, expected);
    }
}

#[test]
fn v6_release_and_claim_refuse_v4_hash_domains_without_allocating_money() {
    let (c, settings) = context();
    let initial = initial(&c, &settings);
    let vectors = vectors();
    let fixture = Fixture::new(
        &initial,
        &c,
        &[0, 2],
        &vectors.original,
        &vectors.bundle,
        &[80_000, 40_000],
        &[0, 2],
    );
    let state = qualified(&initial, &c, &fixture);
    let (released, tx) = fixture.release(&state, &c);
    let mut raw = Envelope::decode(&tx).unwrap().payload;
    let root = allocation_root(&c, &fixture.allocations);
    let legacy_id = hash(
        b"release",
        &[
            &fixture.bundle.parent_ref,
            &fixture.bundle.contribution_id,
            &BUDGET.to_le_bytes(),
            &root,
            &120_000_u64.to_le_bytes(),
        ],
    );
    assert_ne!(released, legacy_id);
    raw[..32].copy_from_slice(&legacy_id);
    assert_release_refusal_is_atomic(&state, &c, signed(&c, 3, nonce(&state, 3), 8, raw), "ROOT");
    let released_state = step(&state, &c, 56, &[tx]);
    let claimable = advance(&released_state, &c, 56, 75);
    let legacy_claim = fixture.claim(&claimable, &c, released, 0, true);
    assert!(pon_executor::execute(
        &claimable,
        &[legacy_claim],
        76,
        development_public(3).unwrap(),
        [4; 32],
        4,
        &c
    )
    .is_err());
    assert_eq!(
        claimable[&format!("release:{}", hex::encode(released))]["remaining"],
        BUDGET
    );
    for allocation in &fixture.allocations {
        assert_ne!(allocation.leaf(&c), legacy_leaf(allocation));
    }
}

#[test]
fn duplicate_claim_and_expiry_conserve_source_money_and_refund_only_remaining_dust() {
    let (c, settings) = context();
    let initial = initial(&c, &settings);
    let vectors = vectors();
    let paid = paid_case(
        &initial,
        &c,
        Fixture::new(
            &initial,
            &c,
            &[0, 2],
            &vectors.original,
            &vectors.bundle,
            &[80_000, 40_000],
            &[0, 2],
        ),
        &vectors.bundle,
    );
    let duplicate = paid.fixture.claim(&paid.state, &c, paid.released, 0, false);
    assert_eq!(
        pon_executor::execute(
            &paid.state,
            &[duplicate],
            77,
            development_public(3).unwrap(),
            [4; 32],
            4,
            &c
        )
        .err(),
        Some("DUPLICATE")
    );
    let key = format!("release:{}", hex::encode(paid.released));
    let deadline = paid.state[&key]["deadline"].as_u64().unwrap();
    assert!(deadline > 76);
    let before = advance(&paid.state, &c, 76, deadline - 1);
    let owner = hex::encode(development_public(3).unwrap());
    let maturing: u64 = before
        .iter()
        .filter(|(key, row)| {
            key.starts_with("reward:")
                && row["owner"] == owner
                && row["maturity"].as_u64().unwrap() <= deadline
        })
        .map(|(_, row)| row["amount"].as_u64().unwrap())
        .sum();
    let refunded = step(&before, &c, deadline, &[]);
    assert_eq!(refunded[&key]["remaining"], 0);
    assert_eq!(refunded[&key]["status"], "expired");
    // The same producer receives ordinary matured rewards. Account for those
    // separately: exactly the retained one-unit dust returns from this release.
    assert_eq!(
        account(&refunded, 3)["balance"].as_u64().unwrap(),
        account(&before, 3)["balance"].as_u64().unwrap() + maturing + 1
    );
    assert_eq!(refunded[&key]["claims"], paid.state[&key]["claims"]);
    assert_eq!(
        refunded[&key]["model_composition_v6"],
        paid.state[&key]["model_composition_v6"]
    );
    assert_eq!(
        composition_record(&refunded, &refunded[&key]),
        composition_record(&paid.state, &paid.state[&key])
    );
    // Original source quotas are per round and are pruned by the unchanged
    // round cleanup. The release retains its separate monetary obligation.
    assert!(!refunded.contains_key(&composition::source_key(0, paid.source)));
    continuity_v1::check_state(&refunded, deadline, &c).unwrap();
    let late = paid.fixture.claim(&refunded, &c, paid.released, 0, false);
    assert!(pon_executor::execute(
        &refunded,
        &[late],
        deadline + 1,
        development_public(3).unwrap(),
        [4; 32],
        4,
        &c
    )
    .is_err());
}

#[test]
fn ordinary_node_admit_activate_and_cold_reopen_retain_v6_contribution_state() {
    let (c, settings) = context();
    let directory = tempfile::tempdir().unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    let (parent, _, initial) = node.read_active().unwrap();
    let vectors = vectors();
    let fixture = Fixture::new(
        &initial,
        &c,
        &[0, 2],
        &vectors.original,
        &vectors.bundle,
        &[80_000, 40_000],
        &[0, 2],
    );
    let packet = node
        .make_consensus_maintenance(
            parent,
            fixture.submissions(&initial, &c),
            development_public(3).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    let active = node.read_active().unwrap();
    for cid in fixture.ids() {
        assert!(composition::evidence(&active.2, cid).is_ok());
    }
    drop(node);
    let cold = Node::open(directory.path(), settings, 2).unwrap();
    assert_eq!(cold.read_active().unwrap(), active);
    assert_eq!(cold.read_active().unwrap().0, id);
    assert_eq!(active.2["model:current"], initial["model:current"]);
}
