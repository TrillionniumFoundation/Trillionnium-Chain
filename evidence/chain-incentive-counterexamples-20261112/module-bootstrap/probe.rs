use serde_json::{json, Value};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex, public_key_hex};
use trnm_mvcc_fee::{integer_factor_candidate_v2 as factor, model_composition_v4 as composition, pon_executor::{self, Config, State}, public_evaluation as evaluation};
use trnm_protocol::{integer_factor_v2::FactorWitnessV2, pon_wire::{hash, Envelope, Hash}};
const FEATURES:usize=257;
fn development_public(who:u64)->Result<Hash,String>{let key=signing_key_from_hex(&signing_key(who)).map_err(|e|e.to_string())?;Ok(hex::decode(public_key_hex(&key)).unwrap().try_into().unwrap())}
#[derive(Clone)] struct Allocation { cid:Hash, who:u64, weight:u64 }
impl Allocation { fn leaf(&self)->Hash{hash(b"allocation-leaf", &[&self.cid,&development_public(self.who).unwrap(),&self.weight.to_le_bytes()])} }
struct Fixture { components:Vec<FactorWitnessV2>, bundle:FactorWitnessV2, allocations:Vec<Allocation> }
impl Fixture {fn ids(&self)->Vec<Hash>{self.components.iter().chain(std::iter::once(&self.bundle)).map(|w|w.contribution_id).collect()}
fn release(&self,state:&State,c:&Config,budget:u64)->(Hash,Vec<u8>){release(state,c,&self.bundle,budget,&self.allocations)}}
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
        "/workspace/scratch/3069292387f3/incentives/config/pon/model-evidence-v3.json"
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
        b"release",
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
fn source_reservations(state: &State, round: u64) -> Value {
    let prefix = format!("model-source-v4:{round}:");
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
fn same_full_bundle_admits_split_reward_redistribution_with_known_aliases() {
    use std::collections::BTreeMap;
    // This preserves an economic counterexample to decomposition-invariant
    // attribution. It is not a forgery, a source-cap bypass, public reward
    // qualification or evidence that an unwilling publisher can be charged.
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
                    source_ids.insert(who, read_hash(&contribution["model_evidence_v4"]["source"]));
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
                assert_eq!(publication["model_composition_v4"]["correct"], 25);
                assert_eq!(
                    publication["model_composition_v4"]["shapley_fairness_accepted"],
                    false
                );
            }
        }
        assert_ne!(source_ids[&0], source_ids[&2]);
        if authors.contains(&1) {
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
        let receipt = &state[&format!("release:{}", hex::encode(released))];
        assert_eq!(receipt["remaining"], 1);
        let total = fixture
            .allocations
            .iter()
            .map(|allocation| allocation.weight)
            .sum::<u64>();
        let mut payments = BTreeMap::new();
        let mut reservations = BTreeMap::<Hash, u64>::new();
        for (allocation, raw) in fixture.allocations.iter().zip(&claim_txs) {
            let amount =
                u64::try_from(100_000_u128 * u128::from(allocation.weight) / u128::from(total))
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
        let alias_source = &state[&composition::source_key(0, source_ids[&0])];
        assert_eq!(
            alias_source["intakes"],
            if authors.contains(&1) { 2 } else { 1 }
        );
        let group_gross = payments.get("0").unwrap()["gross"].as_u64().unwrap()
            + payments
                .get("1")
                .map_or(0, |p| p["gross"].as_u64().unwrap());
        let balances = |state: &State| {
            account(state, 0)["balance"].as_u64().unwrap()
                + account(state, 1)["balance"].as_u64().unwrap()
        };
        let group_net_change = i128::from(balances(&state)) - i128::from(balances(initial));
        json!({"label":label,"scope":"signed-M06-contiguous-heights-1-through-76-not-a-PNW1-chain","bundle_artifact":hex::encode(fixture.bundle.candidate_artifact),"bundle_model_hex":hex::encode(full_model(c, bundle_model).encode()),"parent_model_hex":hex::encode(factor::IntegerModelV2::genesis(c.family).encode()),"component_authors":authors,"component_model_hex":parts.iter().map(|part|hex::encode(full_model(c, part).encode())).collect::<Vec<_>>(),"weights":weights,"release":hex::encode(released),"publication":publication,"claims":receipt["claims"],"source_budgets":source_reservations(&state,0),"known_alias_source":hex::encode(source_ids[&0]),"known_alias_quota":alias_source,"alias_gross_payment":group_gross,"alias_net_account_change_after_all_own_fees":group_net_change.to_string(),"alias_accounts_initial":[account(initial,0),account(initial,1)],"alias_accounts_final":[account(&state,0),account(&state,1)],"payments":payments,"signed_commands":commands,"final_state_root":hex::encode(pon_executor::root(&state).unwrap()),"prospective_accepted":false,"public_reward_eligible":false,"shapley_fairness_accepted":false})
    }

    let c=Config::installed_with_model_profiles(evaluation::PROFILE,pon_executor::LEGACY_TASK_PROFILE,composition::PROFILE).unwrap();
    let mut initial=factor::bootstrap_state(&c).unwrap();
    let count=c.params["genesis_accounts"].as_u64().unwrap();
    let funding=c.params["genesis_funding_units_per_account"].as_u64().unwrap();
    initial.insert("meta:issued".into(),json!(count*funding));
    for who in 0..count {initial.insert(format!("account:{}",hex::encode(development_public(who).unwrap())),json!({"balance":funding,"nonce":0}));}
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
        &[a, b],
        &bundle,
        &[80_000, 40_000],
    );
    let divided = run_case(
        &initial,
        &c,
        "split",
        &[0, 1, 2],
        &split,
        &bundle,
        &[200_000, 920_000, 40_000],
    );
    assert_eq!(original["bundle_artifact"], divided["bundle_artifact"]);
    assert_eq!(original["bundle_model_hex"], divided["bundle_model_hex"]);
    assert_eq!(original["parent_model_hex"], divided["parent_model_hex"]);
    assert_eq!(original["alias_gross_payment"], 66_666);
    assert_eq!(divided["alias_gross_payment"], 96_551);
    assert_eq!(original["payments"]["2"]["gross"], 33_333);
    assert_eq!(divided["payments"]["2"]["gross"], 3_448);
    assert_eq!(
        original["publication"]["model_composition_v4"]["zero_subset_checks"],
        1
    );
    assert_eq!(
        divided["publication"]["model_composition_v4"]["zero_subset_checks"],
        4
    );
    let net = |value: &Value| {
        value["alias_net_account_change_after_all_own_fees"]
            .as_str()
            .unwrap()
            .parse::<i128>()
            .unwrap()
    };
    assert!(net(&divided) > net(&original));
    eprintln!(
        "native-v4-split-counterexample {}",
        json!({"schema":"native-model-composition-v4-split-counterexample-v1","network":hex::encode(c.network),"parameters":hex::encode(c.parameters),"family":hex::encode(c.family),"plan":hex::encode(c.plan),"original":original,"split":divided,"same_complete_bundle":true,"unknown_common_control_discovered":false,"source_cap_bypassed":false,"unauthorized_payer_debit":false,"production_activation":false,"economic_security_qualified":false})
    );
}

fn main(){same_full_bundle_admits_split_reward_redistribution_with_known_aliases();}
