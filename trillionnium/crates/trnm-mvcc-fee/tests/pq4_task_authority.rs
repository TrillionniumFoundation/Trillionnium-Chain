//! Real ML-DSA task-role and State-transition controls. Public fixture keys only.
use serde_json::json;
use trnm_crypto_primitives::{pon_work, qualified_work_task::TaskMaterial};
use trnm_mvcc_fee::pon_executor::{
    self as exec,
    pq_accounts_v2::{self as pq, tasks_v4 as tasks},
    BlockExecution, Config, ExecutionControl, State,
};
use trnm_protocol::{
    pon_wire::Hash,
    pq_native_accounts_v2 as wire,
    qualified_work_task::pq_lifecycle_v4::{DemandLeaseV4, TaskRegistrationV4},
};
#[path = "../../trnm-protocol/tests/support/native_pq_task_fixture.rs"]
mod fixture;
use fixture::{Key, Witness};

fn setup() -> (Config, State, [Key; 3]) {
    let keys = [
        Key::public_test_seed(201),
        Key::public_test_seed(202),
        Key::public_test_seed(203),
    ];
    let accounts: Vec<_> = keys
        .iter()
        .map(|k| pq::GenesisAccount {
            spki: k.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let (cfg, state, _) = pq::genesis_tasks_v4(&accounts, 1000).unwrap();
    (cfg, state, keys)
}
fn execute(
    parent: &State,
    cfg: &Config,
    height: u64,
    rows: &[Vec<u8>],
    workers: usize,
) -> exec::Result<exec::Output> {
    let progress = |_| Ok::<(), std::convert::Infallible>(());
    match exec::execute_with_control(
        parent,
        BlockExecution {
            timestamp: Some(1000 + height),
            transactions: rows,
            height,
            miner: [221; 32],
            parent_id: [height as u8; 32],
            workers,
        },
        cfg,
        &ExecutionControl::new(&progress, &()),
    ) {
        Ok(out) => Ok(out),
        Err(exec::ExecutionError::Relation(error)) => Err(error),
        Err(exec::ExecutionError::Cancelled(impossible)) => match impossible {},
    }
}
fn account(state: &State, id: Hash) -> &serde_json::Value {
    &state[&format!("account:{}", hex::encode(id))]
}
fn sign(
    cfg: &Config,
    requester: Hash,
    nonce: u64,
    generation: u64,
    kind: u8,
    payload: &[u8],
    witnesses: &[Witness<'_>],
) -> Vec<u8> {
    fixture::signed(
        &fixture::common(pq::context(cfg).unwrap(), requester, nonce, generation),
        kind,
        payload,
        witnesses,
        None,
    )
}
fn open(cfg: &Config, lease: &DemandLeaseV4, key: &Key, nonce: u64) -> Vec<u8> {
    sign(
        cfg,
        lease.requester,
        nonce,
        1,
        18,
        &lease.encode().unwrap(),
        &[fixture::primary(key, 1)],
    )
}
fn task() -> Hash {
    let (_, _, a, b) = fixture::material();
    pon_work::task_id(&a, &b).unwrap()
}
fn register(
    cfg: &Config,
    lease: &DemandLeaseV4,
    requester: &Key,
    source: &Key,
    nonce: u64,
    source_generation: u64,
) -> Vec<u8> {
    sign(
        cfg,
        lease.requester,
        nonce,
        1,
        21,
        &fixture::registration(lease, task(), 1, [0; 32])
            .encode()
            .unwrap(),
        &[
            fixture::primary(requester, 1),
            fixture::source(source, source_generation),
        ],
    )
}
fn opened() -> (Config, State, [Key; 3], DemandLeaseV4) {
    let (cfg, initial, keys) = setup();
    let lease = fixture::lease(pq::context(&cfg).unwrap(), keys[0].id, keys[1].id);
    let out = execute(&initial, &cfg, 1, &[open(&cfg, &lease, &keys[0], 1)], 1).unwrap();
    (cfg, out.state, keys, lease)
}
fn rotate(cfg: &Config, state: &State, old: &Key, new: &Key) -> Vec<u8> {
    let nonce = account(state, old.id)["nonce"].as_u64().unwrap() + 1;
    let payload = [
        2_u64.to_be_bytes().as_slice(),
        &pq::authority_digest(state, old.id, cfg).unwrap(),
    ]
    .concat();
    sign(
        cfg,
        old.id,
        nonce,
        1,
        wire::ROTATE,
        &payload,
        &[
            Witness {
                key: old,
                role: 3,
                generation: 1,
                carried: false,
            },
            Witness {
                key: new,
                role: 4,
                generation: 2,
                carried: true,
            },
        ],
    )
}

#[test]
fn actual_two_state_owners_charge_two_proofs_and_retain_four_bounded_witness_leaves() {
    let (cfg, state, keys, lease) = opened();
    let raw = register(&cfg, &lease, &keys[0], &keys[1], 2, 1);
    assert_eq!(raw.len(), 7894);
    let before = state.clone();
    let out = execute(&state, &cfg, 2, std::slice::from_ref(&raw), 4).unwrap();
    assert_eq!(state, before);
    assert_eq!(out.metrics.signature_verifications, 2);
    assert_eq!(account(&out.state, keys[0].id)["nonce"], 2);
    assert_eq!(account(&out.state, keys[1].id), account(&state, keys[1].id));
    let fee = cfg.fees[21] + raw.len() as u64 * cfg.params["byte_fee_units"].as_u64().unwrap();
    assert_eq!(
        account(&out.state, keys[0].id)["balance"].as_u64().unwrap(),
        account(&state, keys[0].id)["balance"].as_u64().unwrap() - fee
    );
    let witnesses: Vec<_> = out
        .state
        .iter()
        .filter(|(k, _)| k.starts_with(tasks::WITNESS_PREFIX))
        .collect();
    assert_eq!(witnesses.len(), 4);
    assert_eq!(
        witnesses
            .iter()
            .flat_map(|(_, v)| hex::decode(v.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>(),
        raw
    );
    assert!(out
        .state
        .values()
        .all(|v| serde_json::to_vec(v).unwrap().len() <= 4096));
    assert!(tasks::eligible_task(&out.state, task(), 2, &cfg).is_err());
    let (model, input, a, b) = fixture::material();
    let (eligible, admission) = tasks::admit_material(
        &out.state,
        task(),
        3,
        &cfg,
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
    )
    .unwrap();
    assert_eq!(eligible.lease(), &lease);
    assert_eq!(eligible.statement_id(), admission.manifest_id());
    assert_eq!(admission.matrix_task(), task());
    assert_eq!(
        out.state[&tasks::slot_key(0).unwrap()]["source_sequence"],
        1
    );
}

#[test]
fn either_bad_inner_or_outer_proof_wrong_account_and_wrong_source_never_spend_nonce_or_fee() {
    let (cfg, state, keys, lease) = opened();
    let good = register(&cfg, &lease, &keys[0], &keys[1], 2, 1);
    let parsed =
        wire::UnverifiedEnvelope::decode_for_profile(&good, wire::AccountProfile::TasksV4).unwrap();
    let mut variants = Vec::new();
    for witness in parsed.witnesses() {
        let offset = witness.frame.as_ptr() as usize - good.as_ptr() as usize;
        let mut bad = good.clone();
        bad[offset + witness.frame.len() - 1] ^= 1;
        variants.push(bad);
    }
    // A complete, valid outer proof cannot stand in for the source proof.
    variants.push(good[..good.len() - trnm_protocol::pq_frame::TPQ1_SIGNED_BYTES].to_vec());
    let mut downgraded = good.clone();
    let source_offset = parsed.witnesses()[1].frame.as_ptr() as usize - good.as_ptr() as usize;
    downgraded[source_offset + 5] = 0x19; // Explicit classical-algorithm relabel.
    variants.push(downgraded);
    variants.push(register(&cfg, &lease, &keys[0], &keys[2], 2, 1));
    variants.push(register(&cfg, &lease, &keys[2], &keys[1], 2, 1));
    variants.push(sign(
        &cfg,
        keys[2].id,
        1,
        1,
        21,
        &fixture::registration(&lease, task(), 1, [0; 32])
            .encode()
            .unwrap(),
        &[fixture::primary(&keys[2], 1), fixture::source(&keys[1], 1)],
    ));
    for bad in variants {
        let before = state.clone();
        assert!(pq::prepare_signature(&state, &bad, 1002, &cfg).is_err());
        assert!(execute(&state, &cfg, 2, &[bad], 1).is_err());
        assert_eq!(state, before);
    }
    assert_eq!(
        execute(&state, &cfg, 2, &[good], 1)
            .unwrap()
            .metrics
            .signature_verifications,
        2
    );
}

#[test]
fn actual_signed_nonce_previous_statement_and_parent_lease_bindings_refuse_cross_branch_replay() {
    let (cfg, state, keys, lease) = opened();
    let good = register(&cfg, &lease, &keys[0], &keys[1], 2, 1);
    for mut request in [
        fixture::registration(&lease, task(), 2, [0; 32]),
        fixture::registration(&lease, task(), 1, [77; 32]),
    ] {
        let raw = sign(
            &cfg,
            lease.requester,
            2,
            1,
            21,
            &request.encode().unwrap(),
            &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
        );
        assert!(execute(&state, &cfg, 2, &[raw], 1).is_err());
        request.lease_id = [76; 32];
        let raw = sign(
            &cfg,
            lease.requester,
            2,
            1,
            21,
            &request.encode().unwrap(),
            &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
        );
        assert!(execute(&state, &cfg, 2, &[raw], 1).is_err());
    }
    let post = execute(&state, &cfg, 2, std::slice::from_ref(&good), 1).unwrap();
    assert!(execute(&post.state, &cfg, 3, std::slice::from_ref(&good), 1).is_err());
    let (_, initial, _) = setup();
    let alternate = fixture::lease(pq::context(&cfg).unwrap(), keys[0].id, keys[2].id);
    assert_eq!(alternate.demand_id, lease.demand_id);
    assert_ne!(alternate.id().unwrap(), lease.id().unwrap());
    let branch = execute(&initial, &cfg, 1, &[open(&cfg, &alternate, &keys[0], 1)], 1).unwrap();
    assert!(execute(&branch.state, &cfg, 2, &[good], 1).is_err());
    assert_eq!(
        branch.state[&tasks::slot_key(0).unwrap()]["source_sequence"],
        0
    );
}

#[test]
fn source_and_requester_rotations_exclude_task_use_in_both_orders_then_accept_current_keys() {
    for owner in [0, 1] {
        let (cfg, state, keys, lease) = opened();
        let next = Key::public_test_seed(210 + owner as u8);
        let rotation = rotate(&cfg, &state, &keys[owner], &next);
        let old = register(&cfg, &lease, &keys[0], &keys[1], 2, 1);
        for rows in [
            vec![rotation.clone(), old.clone()],
            vec![old.clone(), rotation.clone()],
        ] {
            assert_eq!(
                execute(&state, &cfg, 2, &rows, 4).err(),
                Some("PQ2_AUTHORITY_BLOCK_MUTEX")
            );
        }
        let rotated = execute(&state, &cfg, 2, &[rotation], 1).unwrap();
        assert!(execute(&rotated.state, &cfg, 3, &[old], 1).is_err());
        let raw = sign(
            &cfg,
            lease.requester,
            if owner == 0 { 3 } else { 2 },
            if owner == 0 { 2 } else { 1 },
            21,
            &fixture::registration(&lease, task(), 1, [0; 32])
                .encode()
                .unwrap(),
            &[
                fixture::primary(
                    if owner == 0 { &next } else { &keys[0] },
                    if owner == 0 { 2 } else { 1 },
                ),
                fixture::source(
                    if owner == 1 { &next } else { &keys[1] },
                    if owner == 1 { 2 } else { 1 },
                ),
            ],
        );
        let out = execute(&rotated.state, &cfg, 3, &[raw], 4).unwrap();
        assert!(tasks::eligible_task(&out.state, task(), 4, &cfg).is_ok());
        assert_eq!(out.metrics.signature_verifications, 2);
    }
}

#[test]
fn retired_registration_cannot_authorize_work_and_current_dual_proofs_restore_the_same_meter() {
    let (cfg, state, keys, lease) = opened();
    let registered = execute(
        &state,
        &cfg,
        2,
        &[register(&cfg, &lease, &keys[0], &keys[1], 2, 1)],
        1,
    )
    .unwrap();
    let prior_eligible = tasks::eligible_task(&registered.state, task(), 3, &cfg).unwrap();
    let prior = prior_eligible.statement_id();
    let product = [77; 32];
    let mut consumed = registered.state.clone();
    assert!(tasks::consume_output(&mut consumed, &prior_eligible, product, 3, &cfg).unwrap());
    assert_eq!(consumed[&tasks::slot_key(0).unwrap()]["output_count"], 1);
    let revoke = sign(
        &cfg,
        lease.requester,
        3,
        1,
        20,
        &fixture::revocation(&lease).encode().unwrap(),
        &[fixture::primary(&keys[0], 1)],
    );
    let mut revoked = execute(&registered.state, &cfg, 3, &[revoke], 1)
        .unwrap()
        .state;
    let before = revoked.clone();
    assert!(!tasks::consume_output(&mut revoked, &prior_eligible, product, 3, &cfg).unwrap());
    assert_eq!(revoked, before);
    let next = Key::public_test_seed(213);
    let rotated = execute(
        &consumed,
        &cfg,
        3,
        &[rotate(&cfg, &consumed, &keys[1], &next)],
        1,
    )
    .unwrap();
    assert!(tasks::eligible_task(&rotated.state, task(), 4, &cfg).is_err());
    let mut successor = rotated.state.clone();
    assert!(!tasks::consume_output(&mut successor, &prior_eligible, product, 3, &cfg).unwrap());
    assert_eq!(successor, rotated.state);
    let request = fixture::registration(&lease, task(), 2, prior);
    let raw = sign(
        &cfg,
        lease.requester,
        3,
        1,
        21,
        &request.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&next, 2)],
    );
    let current = execute(&rotated.state, &cfg, 4, &[raw], 1).unwrap();
    let eligible = tasks::eligible_task(&current.state, task(), 5, &cfg).unwrap();
    assert_eq!(
        eligible.manifest().output_meter,
        request.manifest.output_meter
    );
    assert_eq!(
        current.state[&tasks::slot_key(0).unwrap()]["source_sequence"],
        2
    );
    assert_eq!(
        current.state[&tasks::slot_key(0).unwrap()]["output_count"],
        1
    );
    assert_eq!(
        current.state[&tasks::slot_key(0).unwrap()]["output_product"],
        hex::encode(product)
    );
}

#[test]
fn open_register_and_revoke_register_pairs_refuse_both_block_orders_without_partial_effects() {
    let (cfg, initial, keys) = setup();
    let lease = fixture::lease(pq::context(&cfg).unwrap(), keys[0].id, keys[1].id);
    let opened = open(&cfg, &lease, &keys[0], 1);
    let registered = register(&cfg, &lease, &keys[0], &keys[1], 2, 1);
    for rows in [
        vec![opened.clone(), registered.clone()],
        vec![registered.clone(), opened.clone()],
    ] {
        assert!(execute(&initial, &cfg, 1, &rows, 4).is_err());
    }
    let state = execute(&initial, &cfg, 1, &[opened], 1).unwrap().state;
    let revoke = sign(
        &cfg,
        lease.requester,
        3,
        1,
        20,
        &fixture::revocation(&lease).encode().unwrap(),
        &[fixture::primary(&keys[0], 1)],
    );
    for rows in [
        vec![revoke.clone(), registered.clone()],
        vec![registered.clone(), revoke],
    ] {
        assert_eq!(
            execute(&state, &cfg, 2, &rows, 4).err(),
            Some("PQ4_TASK_BLOCK_MUTEX")
        );
        assert_eq!(state[&tasks::slot_key(0).unwrap()]["source_sequence"], 0);
    }
}

#[test]
fn missing_reordered_duplicate_oversized_and_other_task_witness_fragments_cannot_authorize() {
    let (cfg, state, keys, lease) = opened();
    let registered = execute(
        &state,
        &cfg,
        2,
        &[register(&cfg, &lease, &keys[0], &keys[1], 2, 1)],
        1,
    )
    .unwrap()
    .state;
    let names: Vec<_> = (0..4)
        .map(|i| format!("{}00:{i}", tasks::WITNESS_PREFIX))
        .collect();
    let mut variants = Vec::new();
    let mut bad = registered.clone();
    bad.remove(&names[1]);
    variants.push(bad);
    let mut bad = registered.clone();
    bad.insert(names[0].clone(), registered[&names[1]].clone());
    bad.insert(names[1].clone(), registered[&names[0]].clone());
    variants.push(bad);
    let mut bad = registered.clone();
    bad.insert(names[2].clone(), registered[&names[1]].clone());
    variants.push(bad);
    let mut bad = registered.clone();
    bad.insert(names[3].clone(), registered[&names[2]].clone());
    variants.push(bad);
    let mut bad = registered.clone();
    bad.insert(
        names[1].clone(),
        json!(format!("{}00", registered[&names[1]].as_str().unwrap())),
    );
    variants.push(bad);
    let mut bad = registered.clone();
    let value = bad[&names[1]].as_str().unwrap().to_owned();
    bad.insert(names[1].clone(), json!(&value[..value.len() - 2]));
    variants.push(bad);
    let mut bad = registered.clone();
    bad.insert(format!("{}00:4", tasks::WITNESS_PREFIX), json!(""));
    variants.push(bad);
    let mut other: TaskRegistrationV4 = fixture::registration(&lease, [71; 32], 1, [0; 32]);
    other.manifest.output_meter = other.manifest.derived_output_meter();
    let other_raw = sign(
        &cfg,
        lease.requester,
        2,
        1,
        21,
        &other.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    let other_state = execute(&state, &cfg, 2, &[other_raw], 1).unwrap().state;
    let mut bad = registered.clone();
    bad.insert(names[1].clone(), other_state[&names[1]].clone());
    variants.push(bad);
    for bad in variants {
        assert!(tasks::eligible_task(&bad, task(), 3, &cfg).is_err());
    }
    assert!(tasks::eligible_task(&registered, task(), 3, &cfg).is_ok());
}

#[test]
fn full_32_task_slot_capacity_counts_64_real_proofs_and_never_enlarges_state_values() {
    let (cfg, initial, keys) = setup();
    let mut leases = Vec::new();
    let mut opens = Vec::new();
    for index in 0..32 {
        let mut lease = fixture::lease(pq::context(&cfg).unwrap(), keys[0].id, keys[1].id);
        lease.slot = index;
        lease.generation = u64::from(index) + 1;
        lease.demand_id = lease.derived_demand_id();
        opens.push(open(&cfg, &lease, &keys[0], u64::from(index) + 1));
        leases.push(lease);
    }
    let state = execute(&initial, &cfg, 1, &opens, 4).unwrap().state;
    let mut registrations = Vec::new();
    for (index, lease) in leases.iter().enumerate() {
        let request = fixture::registration(lease, [index as u8 + 1; 32], 1, [0; 32]);
        registrations.push(sign(
            &cfg,
            keys[0].id,
            33 + index as u64,
            1,
            21,
            &request.encode().unwrap(),
            &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
        ));
    }
    assert_eq!(registrations.iter().map(Vec::len).sum::<usize>(), 252608);
    let out = execute(&state, &cfg, 2, &registrations, 4).unwrap();
    assert_eq!(out.metrics.signature_verifications, 64);
    assert_eq!(
        out.state
            .keys()
            .filter(|k| k.starts_with(tasks::SLOT_PREFIX))
            .count(),
        32
    );
    assert_eq!(
        out.state
            .keys()
            .filter(|k| k.starts_with(tasks::WITNESS_PREFIX))
            .count(),
        128
    );
    assert!(out
        .state
        .values()
        .all(|v| serde_json::to_vec(v).unwrap().len() <= 4096));
    assert_eq!(account(&out.state, keys[0].id)["nonce"], 64);
    let mut over = leases[0].clone();
    over.slot = 32;
    over.generation = 33;
    over.demand_id = over.derived_demand_id();
    assert!(over.encode().is_err());
    let mut overflow = registrations.clone();
    while overflow.iter().map(Vec::len).sum::<usize>() <= wire::MAX_TRANSACTION_BYTES {
        overflow.push(registrations[0].clone());
    }
    assert!(execute(&state, &cfg, 2, &overflow, 4).is_err());
    assert_eq!(account(&state, keys[0].id)["nonce"], 32);
}

#[test]
fn legacy_commands_old_profiles_wrong_material_and_unsigned_inner_wrappers_are_refused() {
    let (cfg, state, keys, lease) = opened();
    let raw = register(&cfg, &lease, &keys[0], &keys[1], 2, 1);
    for profile in [
        wire::AccountProfile::AccountsV2,
        wire::AccountProfile::QuotaV3,
    ] {
        assert!(wire::UnverifiedEnvelope::decode_for_profile(&raw, profile).is_err());
    }
    for tag in [6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 19, 22, 23, 24] {
        let mut old = raw.clone();
        old[5] = tag;
        assert!(pq::prepare_signature(&state, &old, 1002, &cfg).is_err());
    }
    let mut old = raw.clone();
    old[..5].copy_from_slice(b"NPQ3\x03");
    assert!(pq::prepare_signature(&state, &old, 1002, &cfg).is_err());
    let out = execute(&state, &cfg, 2, &[raw], 1).unwrap();
    let (mut model, input, a, b) = fixture::material();
    model[0] ^= 1;
    assert!(tasks::admit_material(
        &out.state,
        task(),
        3,
        &cfg,
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b
        }
    )
    .is_err());
    let mut legacy = out.state.clone();
    legacy.insert(
        "qualified-demand-slot-v2:00".into(),
        json!({"schema":"qualified-demand-slot-record-v2"}),
    );
    assert!(pq::validate_state(&legacy, &cfg).is_err());
}
