//! Exact source aggregation and native funded settlement in an opt-in V6 context.
//! Every training row below is already public historical evaluation material.
//! These deliberately memorizing fixtures make no prospective efficacy claim.
use serde_json::{json, Value};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1, integer_factor_candidate_v2 as factor, model_composition_v6 as composition,
    model_evidence_v3,
    pon_executor::{self, Config, State},
    public_evaluation as evaluation,
};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::{
    integer_factor_v2::FactorWitnessV2,
    pon_wire::{hash, Envelope, Hash, WireError},
};

const CLOCK: u64 = 1_800_100_000;
const FEATURES: usize = 257;

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
/// Sign the actual malformed bytes so order/duplicate refusals do not depend on
/// a bad signature. The ordinary producer API correctly refuses to encode them.
fn signed_noncanonical(c: &Config, nonce: u64, payload: &[u8]) -> Vec<u8> {
    let mut raw = b"PNX1".to_vec();
    raw.extend(c.network);
    raw.extend(development_public(3).unwrap());
    raw.extend(nonce.to_le_bytes());
    raw.extend(2000_u64.to_le_bytes());
    raw.extend(1_000_000_u64.to_le_bytes());
    raw.push(8);
    raw.extend(u16::try_from(payload.len()).unwrap().to_le_bytes());
    raw.extend(payload);
    let key = signing_key_from_hex(&signing_key(3)).unwrap();
    let signature = sign_hex(&key, &hash(b"tx-sign", &[&raw]));
    raw.extend(hex::decode(signature).unwrap());
    raw
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
    fn leaf(&self) -> Hash {
        hash(
            b"source-allocation-leaf-v6",
            &[
                &self.cid,
                &development_public(self.who).unwrap(),
                &self.weight.to_le_bytes(),
            ],
        )
    }
}
fn pair(a: Hash, b: Hash) -> Hash {
    if a < b {
        hash(b"allocation-node", &[&a, &b])
    } else {
        hash(b"allocation-node", &[&b, &a])
    }
}
fn allocation_root(allocations: &[Allocation]) -> Hash {
    let mut leaves = allocations.iter().map(Allocation::leaf).collect::<Vec<_>>();
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().unwrap());
        }
        leaves = leaves.chunks_exact(2).map(|x| pair(x[0], x[1])).collect();
    }
    leaves[0]
}
struct Fixture {
    components: Vec<FactorWitnessV2>,
    bundle: FactorWitnessV2,
    allocations: Vec<Allocation>,
}
impl Fixture {
    fn new(
        state: &State,
        c: &Config,
        round: u64,
        deltas: &[Vec<i16>],
        bundle: &[i16],
        weights: &[u64],
    ) -> Self {
        assert_eq!(deltas.len(), weights.len());
        let components = deltas
            .iter()
            .enumerate()
            .map(|(who, delta)| witness(state, c, who as u64, round, delta, [8; 32]))
            .collect::<Vec<_>>();
        let mut allocations = components
            .iter()
            .zip(weights)
            .enumerate()
            .map(|(who, (component, &weight))| Allocation {
                cid: component.contribution_id,
                who: who as u64,
                weight,
            })
            .collect::<Vec<_>>();
        allocations.sort_by_key(|a| a.cid);
        let bundle = witness(state, c, 3, round, bundle, allocation_root(&allocations));
        Self {
            components,
            bundle,
            allocations,
        }
    }
    fn ids(&self) -> Vec<Hash> {
        self.components
            .iter()
            .chain(std::iter::once(&self.bundle))
            .map(|w| w.contribution_id)
            .collect()
    }
    fn submissions(&self, state: &State, c: &Config) -> Vec<Vec<u8>> {
        let mut txs = self
            .components
            .iter()
            .enumerate()
            .map(|(who, w)| {
                signed(
                    c,
                    who as u64,
                    nonce(state, who as u64),
                    23,
                    w.encode().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        txs.push(signed(
            c,
            3,
            nonce(state, 3) + u64::from(self.components.len() == 4),
            23,
            self.bundle.encode().unwrap(),
        ));
        txs
    }
    fn release(&self, state: &State, c: &Config, budget: u64) -> (Hash, Vec<u8>) {
        release(state, c, &self.bundle, budget, &self.allocations)
    }
    fn claims(&self, state: &State, c: &Config, release: Hash) -> Vec<Vec<u8>> {
        assert_eq!(self.allocations.len(), 2);
        self.allocations
            .iter()
            .enumerate()
            .map(|(index, allocation)| {
                claim(
                    state,
                    c,
                    release,
                    allocation,
                    self.allocations[1 - index].leaf(),
                )
            })
            .collect()
    }
}
fn release(
    state: &State,
    c: &Config,
    bundle: &FactorWitnessV2,
    budget: u64,
    allocations: &[Allocation],
) -> (Hash, Vec<u8>) {
    let total: u64 = allocations.iter().map(|a| a.weight).sum();
    let root = allocation_root(allocations);
    let id = hash(
        b"source-release-v6",
        &[
            &bundle.parent_ref,
            &bundle.contribution_id,
            &budget.to_le_bytes(),
            &root,
            &total.to_le_bytes(),
        ],
    );
    let mut payload = id.to_vec();
    payload.extend(bundle.parent_ref);
    payload.extend(bundle.contribution_id);
    payload.extend(budget.to_le_bytes());
    payload.extend(root);
    payload.extend(total.to_le_bytes());
    payload.push(u8::try_from(allocations.len()).unwrap());
    for allocation in allocations {
        payload.extend(allocation.cid);
        payload.extend(allocation.weight.to_le_bytes());
    }
    (id, signed(c, 3, nonce(state, 3), 8, payload))
}
fn claim(
    state: &State,
    c: &Config,
    release: Hash,
    allocation: &Allocation,
    sibling: Hash,
) -> Vec<u8> {
    let mut payload = release.to_vec();
    payload.extend(allocation.cid);
    payload.extend(allocation.weight.to_le_bytes());
    payload.push(1);
    payload.extend(sibling);
    signed(c, allocation.who, nonce(state, allocation.who), 9, payload)
}
fn attestations(state: &State, c: &Config, ids: &[Hash], tag: u8) -> Vec<Vec<u8>> {
    let mut txs = Vec::new();
    let evaluators = if evaluation::quorum_enabled(c) {
        [0, 1, 3]
    } else {
        [0, 1, 2]
    };
    for who in evaluators {
        let mut next = nonce(state, who);
        for &cid in ids {
            if object(state, cid)["owner"] == hex::encode(development_public(who).unwrap()) {
                continue;
            }
            let evidence = composition::evidence(state, cid).unwrap();
            let round = evaluation::round(&object(state, cid)["public_evaluation"]).unwrap();
            let salt = [who as u8 + 1; 32];
            let score = evidence["score"].as_u64().unwrap();
            let digest = read_hash(&evidence["digest"]);
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
            txs.push(signed(c, who, next, tag, payload));
            next += 1;
        }
    }
    txs
}
fn append(node: &mut Node, parent: Hash, height: u64, txs: Vec<Vec<u8>>) -> Hash {
    assert_eq!(node.parent_height(parent).unwrap() + 1, height);
    let packet = node
        .make_consensus_maintenance(
            parent,
            txs,
            development_public(3).unwrap(),
            node.settings().genesis_time() + height * 10,
            4096,
        )
        .unwrap();
    assert_eq!(packet.header.height, height);
    assert_eq!(
        packet.header.work_task,
        continuity_v1::maintenance_task().unwrap()
    );
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    id
}
fn refuse(node: &Node, parent: Hash, height: u64, tx: Vec<u8>, expected: &str) {
    let active = node.read_active().unwrap();
    let error = node
        .make_consensus_maintenance(
            parent,
            vec![tx],
            development_public(3).unwrap(),
            node.settings().genesis_time() + height * 10,
            4096,
        )
        .unwrap_err();
    assert_eq!(error.to_string(), expected);
    assert_eq!(node.read_active().unwrap(), active);
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
    .unwrap_or_else(|error| panic!("native M06 height {height}: {error}"))
    .state
}

/// Continuity requires every intervening maturity/reward transition. Execute
/// them through M06; no artificial reward rows or sparse-height parent states.
fn advance_continuity(state: &State, c: &Config, from: u64, to: u64, txs: &[Vec<u8>]) -> State {
    assert!(continuity_v1::enabled(c) && from < to);
    assert!(to < c.params["subsidy_halving_interval"].as_u64().unwrap());
    let expected_issued = state["meta:issued"].as_u64().unwrap()
        + (to - from) * c.params["block_subsidy_units"].as_u64().unwrap();
    let maturity = c.params["reward_maturity_blocks"].as_u64().unwrap();
    let mut next = state.clone();
    for height in from + 1..=to {
        next = step(&next, c, height, if height == to { txs } else { &[] });
        let mut actual = next
            .range("reward:".to_owned()..)
            .take_while(|(key, _)| key.starts_with("reward:"))
            .map(|(_, value)| value["maturity"].as_u64().unwrap())
            .collect::<Vec<_>>();
        actual.sort_unstable();
        let expected = (height.saturating_sub(maturity) + 1..=height)
            .map(|mined| mined + maturity)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "complete native reward queue at {height}");
    }
    assert_eq!(next["meta:issued"], expected_issued);
    next
}

#[test]
fn source_quorum_replays_two_generations_with_the_actual_nonzero_parent() {
    let c = Config::installed_with_model_profiles(
        evaluation::QUORUM_PROFILE,
        continuity_v1::PROFILE,
        composition::PROFILE,
    )
    .unwrap();
    let settings = Settings::development_with_model_profiles(
        None,
        evaluation::QUORUM_PROFILE,
        continuity_v1::PROFILE,
        composition::PROFILE,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), settings, 4).unwrap();
    let initial = node.read_active().unwrap().2;
    let a = trained(0, 10);
    let b = trained(16, 10);
    let parent = add(&a, &b);
    let target = add(&trained(0, 25), &trained(1, 25));
    assert_eq!(
        [correct(&a), correct(&b), correct(&parent), correct(&target)],
        [21, 21, 24, 25]
    );
    let first = Fixture::new(&initial, &c, 0, &[a, b], &parent, &[1, 1]);
    let mut state = step(&initial, &c, 1, &first.submissions(&initial, &c));
    for (from, height, tag) in [(1, 16, 14), (16, 32, 15)] {
        state = advance_continuity(
            &state,
            &c,
            from,
            height,
            &attestations(&state, &c, &first.ids(), tag),
        );
    }
    state = advance_continuity(&state, &c, 32, 48, &[]);
    for cid in first.ids() {
        let e = evaluation::read_evaluation(&state, cid).unwrap();
        assert_eq!(e["closed"]["matching_reveal_count"], 2);
        assert_eq!(e["closed"]["missing_reveal_count"], 1);
    }
    let (first_release, tx) = first.release(&state, &c, 1000);
    state = advance_continuity(&state, &c, 48, 56, &[tx]);
    assert_eq!(state["model:current"], hex::encode(first_release));
    state = advance_continuity(&state, &c, 56, 76, &first.claims(&state, &c, first_release));
    let paid = &state[&format!("release:{}", hex::encode(first_release))];
    assert_eq!(paid["remaining"], 0);
    for allocation in &first.allocations {
        assert_eq!(paid["claims"][hex::encode(allocation.cid)], 500);
    }
    state = advance_continuity(&state, &c, 76, 128, &[]);
    // Consecutive M06 execution is distinct from a PNW1 packet history.
    // Both zero-standalone-gain components have positive exact bundle marginals.
    let mut z = vec![0_i16; 2 * FEATURES];
    z[FEATURES - 1] = -32;
    let absolute = [add(&parent, &z), subtract(&target, &z)];
    assert_eq!([correct(&absolute[0]), correct(&absolute[1])], [23, 23]);
    let deltas = absolute
        .iter()
        .map(|model| subtract(model, &parent))
        .collect::<Vec<_>>();
    let second = Fixture::new(&state, &c, 1, &deltas, &subtract(&target, &parent), &[1, 1]);
    assert_eq!(second.bundle.parent_ref, first_release);
    state = step(&state, &c, 129, &second.submissions(&state, &c));
    for component in &second.components {
        assert_eq!(
            composition::evidence(&state, component.contribution_id).unwrap()["score"],
            0
        );
    }
    for (from, height, tag) in [(129, 144, 14), (144, 160, 15)] {
        state = advance_continuity(
            &state,
            &c,
            from,
            height,
            &attestations(&state, &c, &second.ids(), tag),
        );
    }
    state = advance_continuity(&state, &c, 160, 176, &[]);
    let cid = second.components[0].contribution_id;
    let e = evaluation::read_evaluation(&state, cid).unwrap();
    assert_eq!(e["closed"]["score"], 0);
    assert_eq!(e["closed"]["status"], "complete-scored");
    assert_eq!(e["plan"]["generation"], 1);
    assert_eq!(e["plan"]["parent"], hex::encode(first_release));
    let mut payload = cid.to_vec();
    payload.extend(evaluation::closed_digest(&e).unwrap());
    payload.extend([1; 32]);
    payload.extend([2; 32]);
    state = step(
        &state,
        &c,
        177,
        &[signed(&c, 0, nonce(&state, 0), 17, payload)],
    );
    let (second_release, tx) = second.release(&state, &c, 1000);
    state = advance_continuity(&state, &c, 177, 184, &[tx]);
    assert_eq!(state["model:current"], hex::encode(second_release));
    assert_ne!(first_release, second_release);
    assert_eq!(
        stored_model(&state, &c, second.bundle.candidate_artifact),
        full_model(&c, &target)
    );
    assert_eq!(
        composition::evidence(&state, second.bundle.contribution_id).unwrap()["candidate_correct"],
        25
    );
    state = advance_continuity(
        &state,
        &c,
        184,
        204,
        &second.claims(&state, &c, second_release),
    );
    let paid = &state[&format!("release:{}", hex::encode(second_release))];
    assert_eq!(paid["remaining"], 0);
    for allocation in &second.allocations {
        assert_eq!(paid["claims"][hex::encode(allocation.cid)], 500);
    }
    // The fixed public rows are now saturated. This is two bounded empirical
    // updates, not untouched future-data activation or unlimited improvement.
}

fn source_reservations(state: &State, round: u64) -> Value {
    let prefix = format!("model-source-v6:{round}:");
    Value::Object(
        state
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(_, value)| {
                (
                    value["source"].as_str().unwrap().to_owned(),
                    value["reserved_units"].clone(),
                )
            })
            .collect(),
    )
}

#[test]
fn same_full_source_split_alias_and_permutation_preserve_native_entitlements() {
    use std::collections::BTreeMap;
    // The historical V4 counterexample remains unchanged in its own target.
    // This runs the new source profile through signed M06 transitions from
    // ordinary Node genesis. Fees are measured independently of gross rights.
    fn run_case(
        initial: &State,
        c: &Config,
        label: &str,
        authors: &[u64],
        parts: &[Vec<i16>],
        bundle_model: &[i16],
        weights: &[u64],
    ) -> Value {
        let components = parts
            .iter()
            .zip(authors)
            .map(|(delta, &who)| witness(initial, c, who, 0, delta, [8; 32]))
            .collect::<Vec<_>>();
        let mut allocations = components
            .iter()
            .zip(authors)
            .zip(weights)
            .map(|((component, &who), &weight)| Allocation {
                cid: component.contribution_id,
                who,
                weight,
            })
            .collect::<Vec<_>>();
        allocations.sort_by_key(|allocation| allocation.cid);
        let bundle = witness(
            initial,
            c,
            3,
            0,
            bundle_model,
            allocation_root(&allocations),
        );
        let fixture = Fixture {
            components,
            bundle,
            allocations,
        };
        let mut state = initial.clone();
        let mut released = [0; 32];
        let mut publication = Value::Null;
        let mut commands = Vec::new();
        let mut source_ids = BTreeMap::new();
        for height in 1..=75 {
            let txs = match height {
                1 => {
                    let mut txs = fixture
                        .components
                        .iter()
                        .zip(authors)
                        .map(|(component, &who)| {
                            signed(c, who, nonce(&state, who), 23, component.encode().unwrap())
                        })
                        .collect::<Vec<_>>();
                    txs.push(signed(
                        c,
                        3,
                        nonce(&state, 3),
                        23,
                        fixture.bundle.encode().unwrap(),
                    ));
                    txs
                }
                16 => attestations(&state, c, &fixture.ids(), 14),
                32 => attestations(&state, c, &fixture.ids(), 15),
                56 => {
                    let (id, tx) = fixture.release(&state, c, 100_000);
                    released = id;
                    vec![tx]
                }
                _ => vec![],
            };
            if !txs.is_empty() {
                commands.push(json!({"height":height,"transactions":txs.iter().map(hex::encode).collect::<Vec<_>>(),"before_root":hex::encode(pon_executor::root(&state).unwrap())}));
            }
            state = step(&state, c, height, &txs);
            continuity_v1::check_state(&state, height, c).unwrap();
            if height == 1 {
                for (component, &who) in fixture.components.iter().zip(authors) {
                    let contribution = object(&state, component.contribution_id);
                    assert_eq!(contribution["parent"], initial["model:current"]);
                    assert_eq!(
                        contribution["owner"],
                        hex::encode(development_public(who).unwrap())
                    );
                    assert_eq!(
                        stored_model(&state, c, component.candidate_artifact),
                        full_model(
                            c,
                            &parts[authors.iter().position(|&author| author == who).unwrap()]
                        )
                    );
                    source_ids.insert(who, read_hash(&contribution["model_evidence_v6"]["source"]));
                }
            }
            if height == 48 {
                for cid in fixture.ids() {
                    let evaluation = evaluation::read_evaluation(&state, cid).unwrap();
                    assert_eq!(evaluation["closed"]["status"], "complete-scored");
                    assert_eq!(evaluation["closed"]["missing_reveal_count"], 0);
                }
            }
            if height == 56 {
                assert_eq!(state["model:current"], hex::encode(released));
                assert_eq!(
                    stored_model(&state, c, fixture.bundle.candidate_artifact),
                    full_model(c, bundle_model)
                );
                publication = state[&format!("release:{}", hex::encode(released))].clone();
                assert_eq!(publication["model_composition_v6"]["correct"], 25);
                assert_eq!(
                    publication["model_composition_v6"]["shapley_fairness_accepted"],
                    false
                );
            }
        }
        let alias_author = *authors.iter().find(|&&who| who <= 1).unwrap();
        let alias_id = source_ids[&alias_author];
        assert_ne!(alias_id, source_ids[&2]);
        if authors.contains(&0) && authors.contains(&1) {
            assert_eq!(source_ids[&0], source_ids[&1]);
        }
        let before_claim = state.clone();
        let mut claim_txs = Vec::new();
        for (position, allocation) in fixture.allocations.iter().enumerate() {
            let mut index = position;
            let mut layer = fixture
                .allocations
                .iter()
                .map(Allocation::leaf)
                .collect::<Vec<_>>();
            let mut siblings = Vec::new();
            while layer.len() > 1 {
                if layer.len() % 2 == 1 {
                    layer.push(*layer.last().unwrap());
                }
                siblings.push(layer[index ^ 1]);
                layer = layer
                    .chunks_exact(2)
                    .map(|pairing| pair(pairing[0], pairing[1]))
                    .collect();
                index /= 2;
            }
            assert_eq!(layer[0], allocation_root(&fixture.allocations));
            let mut payload = released.to_vec();
            payload.extend(allocation.cid);
            payload.extend(allocation.weight.to_le_bytes());
            payload.push(u8::try_from(siblings.len()).unwrap());
            for sibling in siblings {
                payload.extend(sibling);
            }
            claim_txs.push(signed(
                c,
                allocation.who,
                nonce(&state, allocation.who),
                9,
                payload,
            ));
        }
        commands.push(json!({"height":76,"transactions":claim_txs.iter().map(hex::encode).collect::<Vec<_>>(),"before_root":hex::encode(pon_executor::root(&state).unwrap())}));
        state = step(&state, c, 76, &claim_txs);
        continuity_v1::check_state(&state, 76, c).unwrap();
        let receipt = &state[&format!("release:{}", hex::encode(released))];
        assert_eq!(receipt["remaining"], 1);
        let mut payments = BTreeMap::new();
        let mut reservations = BTreeMap::<Hash, u64>::new();
        for (allocation, raw) in fixture.allocations.iter().zip(&claim_txs) {
            let amount = publication["model_composition_v6"]["payments"]
                .as_array()
                .unwrap()
                .iter()
                .find(|payment| payment["contribution"] == hex::encode(allocation.cid))
                .unwrap()["amount"]
                .as_u64()
                .unwrap();
            assert_eq!(receipt["claims"][hex::encode(allocation.cid)], amount);
            let fee = c.fees[9] + raw.len() as u64 * c.params["byte_fee_units"].as_u64().unwrap();
            assert_eq!(
                account(&state, allocation.who)["balance"].as_u64().unwrap(),
                account(&before_claim, allocation.who)["balance"]
                    .as_u64()
                    .unwrap()
                    + amount
                    - fee
            );
            *reservations.entry(source_ids[&allocation.who]).or_default() += amount;
            payments.insert(allocation.who.to_string(), json!({"gross":amount,"claim_fee":fee,"weight":allocation.weight,"before_claim":account(&before_claim, allocation.who),"after_claim":account(&state, allocation.who)}));
        }
        for (source, amount) in &reservations {
            assert_eq!(
                state[&composition::source_key(0, *source)]["reserved_units"],
                *amount
            );
            assert!(*amount <= 100_000);
        }
        let alias_source = &state[&composition::source_key(0, alias_id)];
        assert_eq!(
            alias_source["intakes"],
            authors.iter().filter(|&&who| who <= 1).count()
        );
        let group_gross = payments
            .get("0")
            .map_or(0, |p| p["gross"].as_u64().unwrap())
            + payments
                .get("1")
                .map_or(0, |p| p["gross"].as_u64().unwrap());
        let balances = |state: &State| {
            account(state, 0)["balance"].as_u64().unwrap()
                + account(state, 1)["balance"].as_u64().unwrap()
        };
        let group_net_change = i128::from(balances(&state)) - i128::from(balances(initial));
        json!({"label":label,"scope":"signed-M06-contiguous-heights-1-through-76-not-a-PNW1-chain","bundle_artifact":hex::encode(fixture.bundle.candidate_artifact),"bundle_model_hex":hex::encode(full_model(c, bundle_model).encode()),"parent_model_hex":hex::encode(factor::IntegerModelV2::genesis(c.family).encode()),"component_authors":authors,"component_ids":fixture.components.iter().map(|component|hex::encode(component.contribution_id)).collect::<Vec<_>>(),"bundle_contribution":hex::encode(fixture.bundle.contribution_id),"component_model_hex":parts.iter().map(|part|hex::encode(full_model(c, part).encode())).collect::<Vec<_>>(),"weights":weights,"release":hex::encode(released),"publication":publication,"claims":receipt["claims"],"source_budgets":source_reservations(&state,0),"known_alias_source":hex::encode(alias_id),"known_alias_quota":alias_source,"alias_gross_payment":group_gross,"alias_net_account_change_after_all_own_fees":group_net_change.to_string(),"alias_accounts_initial":[account(initial,0),account(initial,1)],"alias_accounts_final":[account(&state,0),account(&state,1)],"payments":payments,"signed_commands":commands,"final_state_root":hex::encode(pon_executor::root(&state).unwrap()),"prospective_accepted":false,"public_reward_eligible":false,"shapley_fairness_accepted":false})
    }

    let directory = tempfile::tempdir().unwrap();
    let (c, settings) = context();
    let node = Node::open(directory.path(), settings, 2).unwrap();
    let initial = node.read_active().unwrap().2;
    drop(node);
    assert_eq!(model_evidence_v3::MAX_INTAKES, 4);
    assert_eq!(model_evidence_v3::MAX_RESERVED_UNITS, 100_000);
    let a = trained(0, 25);
    let b = trained(1, 25);
    let bundle = add(&a, &b);
    let mut z = vec![0; 2 * FEATURES];
    z[FEATURES - 1] = 1000;
    z[2 * FEATURES - 1] = -1000;
    let split = [
        add(&a, &z),
        z.iter().map(|value| -value).collect(),
        b.clone(),
    ];
    assert_eq!(add(&add(&split[0], &split[1]), &split[2]), bundle);
    assert_eq!([correct(&a), correct(&b), correct(&bundle)], [24, 23, 25]);
    assert_eq!(split.each_ref().map(|part| correct(part)), [2, 20, 23]);
    assert_eq!(
        split
            .each_ref()
            .map(|part| correct(&subtract(&bundle, part))),
        [20, 2, 24]
    );
    let original = run_case(
        &initial,
        &c,
        "original",
        &[0, 2],
        &[a.clone(), b.clone()],
        &bundle,
        &[1, 1],
    );
    let divided = run_case(
        &initial,
        &c,
        "split",
        &[0, 1, 2],
        &split,
        &bundle,
        &[1, 1, 1],
    );
    assert_eq!(original["bundle_artifact"], divided["bundle_artifact"]);
    assert_eq!(original["bundle_model_hex"], divided["bundle_model_hex"]);
    assert_eq!(original["parent_model_hex"], divided["parent_model_hex"]);
    assert_eq!(original["component_ids"][1], divided["component_ids"][2]);
    assert_eq!(
        original["component_model_hex"][1],
        divided["component_model_hex"][2]
    );
    assert_eq!(original["alias_gross_payment"], 66_666);
    assert_eq!(divided["alias_gross_payment"], 66_666);
    assert_eq!(original["payments"]["2"]["gross"], 33_333);
    assert_eq!(divided["payments"]["2"]["gross"], 33_333);
    let aliased = run_case(&initial, &c, "alias", &[1, 2], &[a, b], &bundle, &[1, 1]);
    let permuted = run_case(
        &initial,
        &c,
        "permuted",
        &[2, 1, 0],
        &[split[2].clone(), split[1].clone(), split[0].clone()],
        &bundle,
        &[1, 1, 1],
    );
    let invariant = &original["publication"]["model_composition_v6"];
    for candidate in [&divided, &aliased, &permuted] {
        let record = &candidate["publication"]["model_composition_v6"];
        for key in [
            "game_digest",
            "sources",
            "total_weight",
            "budget",
            "allocated",
            "refund",
        ] {
            assert_eq!(invariant[key], record[key], "{key}");
        }
        assert_eq!(candidate["alias_gross_payment"], 66_666);
        assert_eq!(candidate["known_alias_quota"]["reserved_units"], 66_666);
    }
    assert_eq!(invariant["total_weight"], 120_000);
    assert_eq!(invariant["refund"], 1);
    let net = |value: &Value| {
        value["alias_net_account_change_after_all_own_fees"]
            .as_str()
            .unwrap()
            .parse::<i128>()
            .unwrap()
    };
    assert!(
        net(&divided) < net(&original),
        "extra signed intake/claim fees remain separate"
    );
    assert_eq!(net(&permuted), net(&divided));
    eprintln!(
        "native-v6-source-invariance {}",
        json!({"schema":"native-model-composition-v6-source-invariance-v1","initialization":"ordinary-Node-open-genesis-state-only","evaluation_profile":evaluation::PROFILE,"continuity_profile":continuity_v1::PROFILE,"model_profile":composition::PROFILE,"genesis_state_root":hex::encode(pon_executor::root(&initial).unwrap()),"public_historical_rows":rows().len(),"max_intakes_per_source_round":model_evidence_v3::MAX_INTAKES,"max_reserved_units_per_source_round":model_evidence_v3::MAX_RESERVED_UNITS,"ordinary_Node_submission_verified":false,"PNW1_chain_verified":false,"independent_History_confirmation_verified":false,"network":hex::encode(c.network),"parameters":hex::encode(c.parameters),"family":hex::encode(c.family),"plan":hex::encode(c.plan),"original":original,"split":divided,"aliased":aliased,"permuted":permuted,"same_complete_bundle":true,"unknown_common_control_discovered":false,"source_cap_bypassed":false,"unauthorized_payer_debit":false,"production_activation":false,"economic_security_qualified":false})
    );
}

#[test]
fn native_source_release_reorg_reopen_and_duplicate_claim_are_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let (c, settings) = context();
    assert_eq!(c.params["consensus_revision"], composition::REVISION);
    assert_eq!(composition::REVISION, 17);
    let legacy = Settings::development_with_model_profiles(
        None,
        evaluation::PROFILE,
        continuity_v1::PROFILE,
        trnm_mvcc_fee::model_composition_v4::PROFILE,
    )
    .unwrap();
    assert_ne!(settings.network(), legacy.network());
    assert_ne!(settings.parameters(), legacy.parameters());
    assert_ne!(settings.genesis(), legacy.genesis());
    let mut node = Node::open(directory.path(), settings.clone(), 4).unwrap();
    let initial = node.read_active().unwrap().2;
    let a = trained(0, 25);
    let b = trained(1, 25);
    let sum = add(&a, &b);
    // These two installed authors share one source; source entitlement is
    // computed once and the fixed internal policy divides it equally.
    let fixture = Fixture::new(&initial, &c, 0, &[a, b], &sum, &[1, 1]);
    let mut tip = settings.genesis();
    let mut before_release_tip = tip;
    let mut released = [0; 32];
    for height in 1..=76 {
        let before = node.state_at(tip).unwrap();
        let txs = match height {
            1 => fixture.submissions(&before, &c),
            16 => attestations(&before, &c, &fixture.ids(), 14),
            32 => attestations(&before, &c, &fixture.ids(), 15),
            56 => {
                let (id, tx) = fixture.release(&before, &c, 100_000);
                released = id;
                vec![tx]
            }
            76 => fixture.claims(&before, &c, released),
            _ => vec![],
        };
        tip = append(&mut node, tip, height, txs);
        if height == 55 {
            before_release_tip = tip;
        }
        let state = node.state_at(tip).unwrap();
        continuity_v1::check_state(&state, height, &c).unwrap();
        for (_, value) in state.iter().filter(|(key, _)| key.starts_with("release:")) {
            assert!(serde_json::to_vec(value).unwrap().len() <= 4096);
        }
    }
    let completed = node.read_active().unwrap();
    assert_eq!(completed.0, tip);
    let record = &completed.2[&format!("release:{}", hex::encode(released))];
    assert_eq!(record["remaining"], 0);
    assert_eq!(
        record["model_composition_v6"]["sources"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        record["model_composition_v6"]["sources"][0]["reward"],
        100_000
    );
    for allocation in &fixture.allocations {
        assert_eq!(record["claims"][hex::encode(allocation.cid)], 50_000);
    }
    let source = read_hash(
        &object(&completed.2, fixture.components[0].contribution_id)["model_evidence_v6"]["source"],
    );
    assert_eq!(
        completed.2[&composition::source_key(0, source)]["reserved_units"],
        100_000
    );
    let duplicate = fixture.claims(&completed.2, &c, released)[0].clone();
    refuse(&node, tip, 77, duplicate, "DUPLICATE");
    drop(node);
    node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    assert_eq!(node.read_active().unwrap(), completed);

    // The alternate branch omits the funded release. Every fork packet still
    // executes the ordinary maintenance work, admission, activation and owner.
    let mut fork = before_release_tip;
    for height in 56..=77 {
        fork = append(&mut node, fork, height, vec![]);
    }
    let rolled_back = node.read_active().unwrap();
    assert_eq!(rolled_back.0, fork);
    assert_eq!(rolled_back.2["model:current"], initial["model:current"]);
    assert!(!rolled_back
        .2
        .contains_key(&format!("release:{}", hex::encode(released))));
    assert_eq!(
        rolled_back.2[&composition::source_key(0, source)]["reserved_units"],
        0
    );
    continuity_v1::check_state(&rolled_back.2, 77, &c).unwrap();
    drop(node);
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), rolled_back);
    eprintln!(
        "native-v6-source-owner {}",
        json!({
            "schema":"native-model-composition-v6-owner-v1",
            "source_release":hex::encode(released),
            "ordinary_node_packets":98,
            "paid_source_total":100_000,
            "reopen_paid_state_equal":true,
            "reorg_source_reservation":0,
            "reopen_reorg_state_equal":true,
            "original_final_root":hex::encode(pon_executor::root(&completed.2).unwrap()),
            "reorg_final_root":hex::encode(pon_executor::root(&rolled_back.2).unwrap()),
            "prospective_accepted":false,
            "economic_security_qualified":false
        })
    );
}

#[test]
fn signed_source_marker_and_packaging_failures_preserve_the_parent() {
    let directory = tempfile::tempdir().unwrap();
    let (c, settings) = context();
    let node = Node::open(directory.path(), settings, 2).unwrap();
    let initial = node.read_active().unwrap().2;
    let a = trained(0, 25);
    let b = trained(1, 25);
    let bundle = add(&a, &b);
    let fixture = Fixture::new(&initial, &c, 0, &[a, b], &bundle, &[2, 1]);
    let mut state = step(&initial, &c, 1, &fixture.submissions(&initial, &c));
    for (from, height, tag) in [(1, 16, 14), (16, 32, 15)] {
        state = advance_continuity(
            &state,
            &c,
            from,
            height,
            &attestations(&state, &c, &fixture.ids(), tag),
        );
    }
    state = advance_continuity(&state, &c, 32, 55, &[]);
    let (release_id, tx) = fixture.release(&state, &c, 100_000);
    let before = state.clone();
    assert_eq!(
        pon_executor::execute(
            &state,
            std::slice::from_ref(&tx),
            56,
            development_public(3).unwrap(),
            [4; 32],
            4,
            &c
        )
        .err(),
        Some("MODEL_SOURCE_MARKER")
    );
    assert_eq!(state, before);
    assert!(!state.contains_key(&format!("release:{}", hex::encode(release_id))));
    assert!(state
        .iter()
        .filter(|(key, _)| key.starts_with("model-source-v6:"))
        .all(|(_, value)| value["reserved_units"] == 0));
    let mut payload = Envelope::decode(&tx).unwrap().payload;
    let first = payload[145..185].to_vec();
    let second = payload[185..225].to_vec();
    payload[145..185].copy_from_slice(&second);
    payload[185..225].copy_from_slice(&first);
    let malformed = signed_noncanonical(&c, nonce(&state, 3), &payload);
    assert_eq!(
        Envelope::decode(&malformed).unwrap_err(),
        WireError::Noncanonical
    );
    assert_eq!(
        pon_executor::execute(
            &state,
            &[malformed],
            56,
            development_public(3).unwrap(),
            [4; 32],
            4,
            &c
        )
        .err(),
        Some("ENCODING")
    );
    assert_eq!(state, before);
}
