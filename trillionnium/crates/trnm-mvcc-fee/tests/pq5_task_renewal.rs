//! Real ML-DSA task-role and State-transition controls. Public fixture keys only.
use serde_json::json;
use trnm_crypto_primitives::{pon_work, qualified_work_task::TaskMaterial};
use trnm_mvcc_fee::pon_executor::{
    self as exec,
    pq_accounts_v2::{self as pq, tasks_v5 as tasks},
    BlockExecution, Config, ExecutionControl, State,
};
use trnm_protocol::{
    pon_wire::Hash,
    pq_native_accounts_v2 as wire,
    qualified_work_task::pq_lifecycle_v5::{DemandLeaseV5, TaskRegistrationV5},
};
#[path = "../../trnm-protocol/tests/support/native_pq_task_fixture_v5.rs"]
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
    let (cfg, state, _) = pq::genesis_tasks_v5(&accounts, 1000).unwrap();
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
fn open(cfg: &Config, lease: &DemandLeaseV5, key: &Key, nonce: u64) -> Vec<u8> {
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
    lease: &DemandLeaseV5,
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
fn opened() -> (Config, State, [Key; 3], DemandLeaseV5) {
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
fn actual_two_state_owners_charge_two_proofs_and_retain_five_bounded_witness_leaves() {
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
    assert_eq!(witnesses.len(), 5);
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
        wire::UnverifiedEnvelope::decode_for_profile(&good, wire::AccountProfile::TasksV5).unwrap();
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
            Some("PQ5_TASK_BLOCK_MUTEX")
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
    let names: Vec<_> = (0..5)
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
    bad.insert(format!("{}00:5", tasks::WITNESS_PREFIX), json!(""));
    variants.push(bad);
    let mut other: TaskRegistrationV5 = fixture::registration(&lease, [71; 32], 1, [0; 32]);
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
        160
    );
    assert!(out
        .state
        .values()
        .all(|v| serde_json::to_vec(v).unwrap().len() <= 4096));
    assert_eq!(account(&out.state, keys[0].id)["nonce"], 64);
    let renewals: Vec<_> = leases
        .iter()
        .enumerate()
        .map(|(index, lease)| {
            let next = fixture::successor(lease, 3, lease.expires + 50);
            let prior = trnm_crypto_primitives::qualified_work_task::pq_lifecycle_v5::statement_id(
                &registrations[index],
            )
            .unwrap();
            let request = fixture::atomic(lease, &next, [index as u8 + 1; 32], 2, prior);
            sign(
                &cfg,
                keys[0].id,
                65 + index as u64,
                1,
                22,
                &request.encode().unwrap(),
                &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
            )
        })
        .collect();
    assert_eq!(renewals.iter().map(Vec::len).sum::<usize>(), 264768);
    let renewed = execute(&out.state, &cfg, 3, &renewals, 4).unwrap();
    assert_eq!(renewed.metrics.signature_verifications, 64);
    assert_eq!(account(&renewed.state, keys[0].id)["nonce"], 96);
    assert_eq!(
        renewed
            .state
            .keys()
            .filter(|k| k.starts_with(tasks::WITNESS_PREFIX))
            .count(),
        160
    );
    assert!(renewed
        .state
        .values()
        .all(|v| serde_json::to_vec(v).unwrap().len() <= 4096));
    let mut aggregate = renewals;
    for index in 0..61 {
        let mut payload = keys[2].id.to_vec();
        payload.extend(1_u64.to_le_bytes());
        payload.extend(512_u16.to_be_bytes());
        payload.extend([0_u8; 512]);
        let raw = sign(
            &cfg,
            keys[0].id,
            97 + index,
            1,
            1,
            &payload,
            &[fixture::primary(&keys[0], 1)],
        );
        assert_eq!(raw.len(), 4263);
        aggregate.push(raw);
        if index == 59 {
            assert_eq!(aggregate.iter().map(Vec::len).sum::<usize>(), 520548);
            pq::validate_block(&out.state, &aggregate, [221; 32], Some(1003), &cfg).unwrap();
        }
    }
    assert_eq!(aggregate.iter().map(Vec::len).sum::<usize>(), 524811);
    assert_eq!(
        pq::validate_block(&out.state, &aggregate, [221; 32], Some(1003), &cfg).err(),
        Some("PQ2_TRANSACTION_LIMIT")
    );

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
        wire::AccountProfile::TasksV4,
    ] {
        assert!(wire::UnverifiedEnvelope::decode_for_profile(&raw, profile).is_err());
    }
    for tag in [6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 23, 24] {
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
    let mut forged_config = cfg.clone();
    forged_config.params["native_pq_accounts_profile"] =
        json!(wire::AccountProfile::TasksV4.name());
    assert!(pq::context(&forged_config).is_err());
    // Even a syntactically exact, really dual-signed CLAIM cannot import through
    // this fresh-only profile's absent protected migration anchor.
    let mut claim = vec![71_u8; 216];
    claim[112..144].copy_from_slice(&keys[2].id);
    claim[208..216].copy_from_slice(&1_u64.to_be_bytes());
    let raw = sign(
        &cfg,
        keys[2].id,
        1,
        0,
        wire::CLAIM,
        &claim,
        &[
            Witness {
                key: &keys[0],
                role: 5,
                generation: 1,
                carried: false,
            },
            Witness {
                key: &keys[2],
                role: 6,
                generation: 1,
                carried: true,
            },
        ],
    );
    assert_eq!(raw.len(), 9432);
    assert_eq!(
        pq::prepare_signature(&state, &raw, 1003, &cfg).err(),
        Some("PQ2_TRUSTED_MIGRATION_REQUIRED")
    );
    let before = state.clone();
    assert!(execute(&state, &cfg, 3, &[raw], 1).is_err());
    assert_eq!(state, before);
}

fn active() -> (Config, State, [Key; 3], DemandLeaseV5, Hash) {
    let (cfg, state, keys, lease) = opened();
    let raw = register(&cfg, &lease, &keys[0], &keys[1], 2, 1);
    let prior =
        trnm_crypto_primitives::qualified_work_task::pq_lifecycle_v5::statement_id(&raw).unwrap();
    let state = execute(&state, &cfg, 2, &[raw], 1).unwrap().state;
    (cfg, state, keys, lease, prior)
}
fn atomic_raw(
    cfg: &Config,
    previous: &DemandLeaseV5,
    successor: &DemandLeaseV5,
    keys: &[Key; 3],
    nonce: u64,
    sequence: u64,
    prior: Hash,
) -> Vec<u8> {
    sign(
        cfg,
        previous.requester,
        nonce,
        1,
        22,
        &fixture::atomic(previous, successor, task(), sequence, prior)
            .encode()
            .unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    )
}
#[test]
fn atomic_renewal_exact_codec_two_real_proofs_five_chunks_and_old_profile_refusal() {
    use trnm_protocol::qualified_work_task::pq_lifecycle_v5 as codec;
    let (cfg, state, keys, lease, prior) = active();
    let next = fixture::successor(&lease, 3, lease.expires + 50);
    let request = fixture::atomic(&lease, &next, task(), 2, prior);
    let payload = request.encode().unwrap();
    assert_eq!(payload.len(), 1032);
    assert_eq!(codec::AtomicRenewTaskV5::decode(&payload).unwrap(), request);
    assert_eq!(
        fixture::renewal(&lease, &next, prior)
            .encode()
            .unwrap()
            .len(),
        412
    );
    assert_eq!(fixture::revocation(&next).encode().unwrap().len(), 348);
    let raw = atomic_raw(&cfg, &lease, &next, &keys, 3, 2, prior);
    assert_eq!(raw.len(), 8274);
    for profile in [
        wire::AccountProfile::AccountsV2,
        wire::AccountProfile::QuotaV3,
        wire::AccountProfile::TasksV4,
    ] {
        assert!(wire::UnverifiedEnvelope::decode_for_profile(&raw, profile).is_err());
    }
    for bytes in [
        &payload[..payload.len() - 1],
        &[payload.as_slice(), &[0]].concat(),
    ] {
        assert!(codec::AtomicRenewTaskV5::decode(bytes).is_err());
    }
    let out = execute(&state, &cfg, 3, std::slice::from_ref(&raw), 4).unwrap();
    assert_eq!(out.metrics.signature_verifications, 2);
    assert_eq!(account(&out.state, keys[0].id)["nonce"], 3);
    assert_eq!(account(&out.state, keys[1].id), account(&state, keys[1].id));
    let fee = cfg.fees[22] + 8274 * cfg.params["byte_fee_units"].as_u64().unwrap();
    assert_eq!(
        account(&out.state, keys[0].id)["balance"].as_u64().unwrap(),
        account(&state, keys[0].id)["balance"].as_u64().unwrap() - fee
    );
    let chunks: Vec<_> = (0..5)
        .map(|i| {
            hex::decode(
                out.state[&format!("{}00:{i}", tasks::WITNESS_PREFIX)]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![2000, 2000, 2000, 2000, 274]
    );
    assert_eq!(chunks.concat(), raw);
    assert!(out
        .state
        .values()
        .all(|v| serde_json::to_vec(v).unwrap().len() <= 4096));
    assert_eq!(
        tasks::eligible_task(&out.state, task(), lease.expires + 1, &cfg)
            .unwrap()
            .lease(),
        &next
    );
    assert!(tasks::eligible_task(&state, task(), lease.expires + 1, &cfg).is_err());
    assert_eq!(
        lease
            .lineage_id(pq::context(&cfg).unwrap().genesis)
            .unwrap(),
        next.lineage_id(pq::context(&cfg).unwrap().genesis).unwrap()
    );
    assert_ne!(lease.id().unwrap(), next.id().unwrap());
    assert!(
        trnm_protocol::qualified_work_task::pq_lifecycle_v4::DemandLeaseV4::decode(
            &next.encode().unwrap()
        )
        .is_err()
    );
}
#[test]
fn requester_only_renewal_is_cold_valid_but_awaits_new_source_and_preserves_past_output() {
    let (cfg, state, keys, initial, prior) = active();
    let signed = fixture::successor(&initial, 3, initial.expires + 50);
    let atomic = atomic_raw(&cfg, &initial, &signed, &keys, 3, 2, prior);
    let prior = trnm_crypto_primitives::qualified_work_task::pq_lifecycle_v5::statement_id(&atomic)
        .unwrap();
    let mut state = execute(&state, &cfg, 3, &[atomic], 1).unwrap().state;
    let fifth = format!("{}00:4", tasks::WITNESS_PREFIX);
    assert_eq!(
        hex::decode(state[&fifth].as_str().unwrap()).unwrap().len(),
        274
    );
    let eligible = tasks::eligible_task(&state, task(), 4, &cfg).unwrap();
    // Advance the ordinary block/reward owner before recording its verified
    // output; a direct task-meter update cannot manufacture block 4's reward.
    state = execute(&state, &cfg, 4, &[], 1).unwrap().state;
    assert!(tasks::consume_output(&mut state, &eligible, [81; 32], 4, &cfg).unwrap());
    let next = fixture::successor(&signed, 5, signed.expires + 50);
    let renewal = sign(
        &cfg,
        signed.requester,
        4,
        1,
        19,
        &fixture::renewal(&signed, &next, prior).encode().unwrap(),
        &[fixture::primary(&keys[0], 1)],
    );
    assert_eq!(renewal.len(), 4121);
    let out = execute(&state, &cfg, 5, &[renewal], 1).unwrap();
    assert_eq!(out.metrics.signature_verifications, 1);
    let pending = out.state;
    pq::validate_state(&pending, &cfg).unwrap();
    let row = &pending[&tasks::slot_key(0).unwrap()];
    assert_eq!(row["status"], "awaiting-source");
    assert_eq!(row["signed_lease"], hex::encode(signed.encode().unwrap()));
    assert_eq!(row["lease"], hex::encode(next.encode().unwrap()));
    assert_eq!(row["initial_lease"], hex::encode(initial.encode().unwrap()));
    assert_eq!(row["statement_kind"], 22);
    assert_eq!(pending[&fifth], state[&fifth]);
    assert_eq!(row["output_height"], 4);
    assert!(tasks::eligible_task(&pending, task(), 6, &cfg).is_err());
    assert!(tasks::eligible_task(&pending, task(), signed.expires + 1, &cfg).is_err());
    let stale = sign(
        &cfg,
        signed.requester,
        5,
        1,
        21,
        &fixture::registration(&signed, task(), 3, prior)
            .encode()
            .unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    assert_eq!(
        execute(&pending, &cfg, 6, &[stale], 1).err(),
        Some("PQ5_TASK_LEASE_BINDING")
    );
    let registration = sign(
        &cfg,
        next.requester,
        5,
        1,
        21,
        &fixture::registration(&next, task(), 3, prior)
            .encode()
            .unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    let restored = execute(&pending, &cfg, 6, &[registration], 4)
        .unwrap()
        .state;
    let current = tasks::eligible_task(&restored, task(), signed.expires + 1, &cfg).unwrap();
    assert_eq!(current.lease(), &next);
    assert_eq!(
        current.manifest().output_meter,
        eligible.manifest().output_meter
    );
    assert_eq!(restored[&tasks::slot_key(0).unwrap()]["output_count"], 1);
    assert_eq!(restored[&tasks::slot_key(0).unwrap()]["output_height"], 4);
    assert_eq!(restored[&tasks::slot_key(0).unwrap()]["source_sequence"], 3);
    assert_eq!(restored[&fifth], "");
}

#[test]
fn renewal_block_may_credit_verified_parent_output_without_granting_pending_future_work() {
    for atomic in [false, true] {
        let (cfg, state, keys, lease, prior) = active();
        let eligible = tasks::eligible_task(&state, task(), 3, &cfg).unwrap();
        let next = fixture::successor(&lease, 3, lease.expires + 50);
        let raw = if atomic {
            atomic_raw(&cfg, &lease, &next, &keys, 3, 2, prior)
        } else {
            sign(
                &cfg,
                lease.requester,
                3,
                1,
                19,
                &fixture::renewal(&lease, &next, prior).encode().unwrap(),
                &[fixture::primary(&keys[0], 1)],
            )
        };
        let mut next_state = execute(&state, &cfg, 3, &[raw], 1).unwrap().state;
        assert!(tasks::consume_output(&mut next_state, &eligible, [82; 32], 3, &cfg).unwrap());
        let before = next_state.clone();
        assert!(!tasks::consume_output(&mut next_state, &eligible, [82; 32], 3, &cfg).unwrap());
        assert_eq!(next_state, before);
        assert!(tasks::consume_output(&mut next_state, &eligible, [83; 32], 3, &cfg).is_err());
        assert_eq!(next_state, before);
        assert_eq!(
            tasks::eligible_task(&next_state, task(), 4, &cfg).is_ok(),
            atomic
        );
    }
}
#[test]
fn atomic_renewal_bad_each_proof_role_account_nonce_branch_or_prior_spends_nothing() {
    let (cfg, state, keys, lease, prior) = active();
    let next = fixture::successor(&lease, 3, lease.expires + 50);
    let good = atomic_raw(&cfg, &lease, &next, &keys, 3, 2, prior);
    let parsed =
        wire::UnverifiedEnvelope::decode_for_profile(&good, wire::AccountProfile::TasksV5).unwrap();
    let mut invalid = vec![];
    for witness in parsed.witnesses() {
        let offset = witness.frame.as_ptr() as usize - good.as_ptr() as usize;
        let mut bad = good.clone();
        bad[offset + witness.frame.len() - 1] ^= 1;
        invalid.push(bad);
    }
    let request = fixture::atomic(&lease, &next, task(), 2, prior);
    for (requester, source) in [(&keys[2], &keys[1]), (&keys[0], &keys[2])] {
        invalid.push(sign(
            &cfg,
            lease.requester,
            3,
            1,
            22,
            &request.encode().unwrap(),
            &[fixture::primary(requester, 1), fixture::source(source, 1)],
        ));
    }
    for (nonce, sequence, old) in [
        (2, 2, prior),
        (4, 2, prior),
        (3, 1, prior),
        (3, 2, [0; 32]),
        (3, 2, [9; 32]),
    ] {
        invalid.push(atomic_raw(&cfg, &lease, &next, &keys, nonce, sequence, old));
    }
    let mut wrong = request.clone();
    wrong.expected_lease_id = [91; 32];
    invalid.push(sign(
        &cfg,
        lease.requester,
        3,
        1,
        22,
        &wrong.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    ));
    let mut swapped = good.clone();
    swapped[5] = 21;
    invalid.push(swapped);
    for raw in invalid {
        let before = state.clone();
        assert!(execute(&state, &cfg, 3, &[raw], 4).is_err());
        assert_eq!(state, before);
    }
    let consumed = execute(&state, &cfg, 3, std::slice::from_ref(&good), 4)
        .unwrap()
        .state;
    assert!(execute(&consumed, &cfg, 4, &[good], 1).is_err());
}
#[test]
fn renewal_rejects_expired_gap_wrong_revision_changed_scope_and_changed_material_atomically() {
    let (cfg, state, keys, lease, prior) = active();
    let good = fixture::successor(&lease, 3, lease.expires + 50);
    let mut variants = vec![];
    let mut v = good.clone();
    v.revision += 1;
    variants.push(v);
    let mut v = good.clone();
    v.not_before = 4;
    variants.push(v);
    let mut v = good.clone();
    v.expires = lease.expires;
    v.available_until = v.expires + 100;
    variants.push(v);
    let mut v = good.clone();
    v.source = keys[2].id;
    variants.push(v);
    let mut v = good.clone();
    v.authorization_scope = [98; 32];
    variants.push(v);
    let mut v = good.clone();
    v.availability_root = [97; 32];
    variants.push(v);
    for next in variants {
        let raw = atomic_raw(&cfg, &lease, &next, &keys, 3, 2, prior);
        let before = state.clone();
        assert!(execute(&state, &cfg, 3, &[raw], 1).is_err());
        assert_eq!(state, before);
    }
    assert!(execute(
        &state,
        &cfg,
        lease.expires + 1,
        &[atomic_raw(&cfg, &lease, &good, &keys, 3, 2, prior)],
        1
    )
    .is_err());
    let mut changed = fixture::atomic(&lease, &good, [96; 32], 2, prior);
    changed.registration.manifest.output_meter =
        changed.registration.manifest.derived_output_meter();
    let raw = sign(
        &cfg,
        lease.requester,
        3,
        1,
        22,
        &changed.encode().unwrap(),
        &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
    );
    assert!(execute(&state, &cfg, 3, &[raw], 1).is_err());
    let next = execute(
        &state,
        &cfg,
        3,
        &[atomic_raw(&cfg, &lease, &good, &keys, 3, 2, prior)],
        1,
    )
    .unwrap()
    .state;
    let stale_revoke = sign(
        &cfg,
        lease.requester,
        4,
        1,
        20,
        &fixture::revocation(&lease).encode().unwrap(),
        &[fixture::primary(&keys[0], 1)],
    );
    assert!(execute(&next, &cfg, 4, &[stale_revoke], 1).is_err());
}
#[test]
fn renew_rotate_revoke_and_register_pairs_refuse_both_orders_then_use_current_authority() {
    for owner in [0, 1] {
        let (cfg, state, keys, lease, prior) = active();
        let next = fixture::successor(&lease, 3, lease.expires + 50);
        let raw = atomic_raw(&cfg, &lease, &next, &keys, 3, 2, prior);
        let new = Key::public_test_seed(180 + owner as u8);
        let rotation = rotate(&cfg, &state, &keys[owner], &new);
        for rows in [
            vec![raw.clone(), rotation.clone()],
            vec![rotation.clone(), raw.clone()],
        ] {
            assert_eq!(
                execute(&state, &cfg, 3, &rows, 4).err(),
                Some("PQ2_AUTHORITY_BLOCK_MUTEX")
            );
        }
        let rotated = execute(&state, &cfg, 3, &[rotation], 1).unwrap().state;
        assert!(execute(&rotated, &cfg, 4, std::slice::from_ref(&raw), 1).is_err());
        let current = sign(
            &cfg,
            lease.requester,
            if owner == 0 { 4 } else { 3 },
            if owner == 0 { 2 } else { 1 },
            22,
            &fixture::atomic(&lease, &next, task(), 2, prior)
                .encode()
                .unwrap(),
            &[
                fixture::primary(
                    if owner == 0 { &new } else { &keys[0] },
                    if owner == 0 { 2 } else { 1 },
                ),
                fixture::source(
                    if owner == 1 { &new } else { &keys[1] },
                    if owner == 1 { 2 } else { 1 },
                ),
            ],
        );
        assert!(tasks::eligible_task(
            &execute(&rotated, &cfg, 4, &[current], 1).unwrap().state,
            task(),
            5,
            &cfg
        )
        .is_ok());
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
            vec![raw.clone(), revoke.clone()],
            vec![revoke.clone(), raw.clone()],
        ] {
            assert_eq!(
                execute(&state, &cfg, 3, &rows, 4).err(),
                Some("PQ5_TASK_BLOCK_MUTEX")
            );
        }
        let revoked = execute(&state, &cfg, 3, &[revoke], 1).unwrap().state;
        assert!(execute(&revoked, &cfg, 4, &[raw], 1).is_err());
        let renew = sign(
            &cfg,
            lease.requester,
            3,
            1,
            19,
            &fixture::renewal(&lease, &next, prior).encode().unwrap(),
            &[fixture::primary(&keys[0], 1)],
        );
        let source = sign(
            &cfg,
            lease.requester,
            4,
            1,
            21,
            &fixture::registration(&next, task(), 2, prior)
                .encode()
                .unwrap(),
            &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
        );
        for rows in [
            vec![renew.clone(), source.clone()],
            vec![source.clone(), renew.clone()],
        ] {
            assert!(execute(&state, &cfg, 3, &rows, 4).is_err());
        }
    }
}
#[test]
fn atomic_all_five_fragment_boundaries_and_mixed_statement_bytes_fail_cold_authorization() {
    let (cfg, state, keys, lease, prior) = active();
    let next = fixture::successor(&lease, 3, lease.expires + 50);
    let raw = atomic_raw(&cfg, &lease, &next, &keys, 3, 2, prior);
    let out = execute(&state, &cfg, 3, &[raw], 1).unwrap().state;
    let other = fixture::successor(&lease, 3, lease.expires + 60);
    let fork = execute(
        &state,
        &cfg,
        3,
        &[atomic_raw(&cfg, &lease, &other, &keys, 3, 2, prior)],
        1,
    )
    .unwrap()
    .state;
    for index in 0..5 {
        let key = format!("{}00:{index}", tasks::WITNESS_PREFIX);
        let text = out[&key].as_str().unwrap();
        for replacement in [
            None,
            Some(json!(&text[..text.len() - 2])),
            Some(json!(format!("{text}00"))),
            Some(fork[&key].clone()),
        ] {
            let mut bad = out.clone();
            if let Some(value) = replacement {
                bad.insert(key.clone(), value);
            } else {
                bad.remove(&key);
            }
            // Identical fragments are not substitutions; force a same-length byte mutation.
            if bad == out {
                let mut bytes = hex::decode(text).unwrap();
                bytes[0] ^= 1;
                bad.insert(key.clone(), json!(hex::encode(bytes)));
            }
            assert!(tasks::eligible_task(&bad, task(), 4, &cfg).is_err());
        }
    }
    let mut reordered = out.clone();
    reordered.insert(
        format!("{}00:0", tasks::WITNESS_PREFIX),
        out[&format!("{}00:1", tasks::WITNESS_PREFIX)].clone(),
    );
    reordered.insert(
        format!("{}00:1", tasks::WITNESS_PREFIX),
        out[&format!("{}00:0", tasks::WITNESS_PREFIX)].clone(),
    );
    assert!(tasks::eligible_task(&reordered, task(), 4, &cfg).is_err());
}

#[test]
fn incremental_atomic_renewal_prefix_uses_original_parent_and_rolls_back_rejected_suffix() {
    use trnm_crypto_primitives::qualified_work_task::pq_lifecycle_v5 as crypto;
    use trnm_mvcc_fee::pon_commitment::{CacheLimits, CheckedExecutionParent};
    use trnm_mvcc_fee::pon_executor::{ExecutionError, ExecutionProgress, PrefixContext};

    let (cfg, initial, keys) = setup();
    let first = fixture::lease(pq::context(&cfg).unwrap(), keys[0].id, keys[1].id);
    let mut second = first.clone();
    second.slot = 1;
    second.generation = 2;
    second.demand_id = second.derived_demand_id();
    let leases = [first, second];
    let tasks = [task(), [42; 32]];
    let opens: Vec<_> = leases
        .iter()
        .enumerate()
        .map(|(index, lease)| open(&cfg, lease, &keys[0], index as u64 + 1))
        .collect();
    let opened = execute(&initial, &cfg, 1, &opens, 1).unwrap().state;
    let registrations: Vec<_> = leases
        .iter()
        .enumerate()
        .map(|(index, lease)| {
            sign(
                &cfg,
                keys[0].id,
                index as u64 + 3,
                1,
                21,
                &fixture::registration(lease, tasks[index], 1, [0; 32])
                    .encode()
                    .unwrap(),
                &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
            )
        })
        .collect();
    let parent = execute(&opened, &cfg, 2, &registrations, 1).unwrap().state;
    let original_parent = parent.clone();
    let renew = |index: usize, nonce, prior| {
        let lease = &leases[index];
        let next = fixture::successor(lease, 3, lease.expires + 50);
        sign(
            &cfg,
            keys[0].id,
            nonce,
            1,
            22,
            &fixture::atomic(lease, &next, tasks[index], 2, prior)
                .encode()
                .unwrap(),
            &[fixture::primary(&keys[0], 1), fixture::source(&keys[1], 1)],
        )
    };
    let priors = registrations
        .iter()
        .map(|raw| crypto::statement_id(raw).unwrap())
        .collect::<Vec<_>>();
    let raws = [renew(0, 5, priors[0]), renew(1, 6, priors[1])];
    let first_expected = execute(&parent, &cfg, 3, &raws[..1], 1).unwrap();
    let full_expected = execute(&parent, &cfg, 3, &raws, 4).unwrap();
    let progress = |_| Ok::<(), &'static str>(());
    let mut prefix = CheckedExecutionParent::bind(
        &parent,
        exec::root(&parent).unwrap(),
        None,
        CacheLimits::default(),
    )
    .unwrap()
    .into_prefix_with_control(
        PrefixContext {
            timestamp: Some(1003),
            height: 3,
            miner: [221; 32],
            parent_id: [3; 32],
        },
        &cfg,
        &ExecutionControl::new(&progress, &()),
    )
    .unwrap();
    let compare = |actual: &exec::Output, expected: &exec::Output| {
        assert_eq!(actual.state, expected.state);
        assert_eq!(actual.receipts, expected.receipts);
        assert_eq!(actual.root, expected.root);
    };
    compare(&prefix.execute(&raws[..1]).unwrap().output, &first_expected);
    // Revalidating the identical complete prefix must not interpret its already
    // applied renewal as a request against the successor lease.
    let repeated = prefix.execute(&raws[..1]).unwrap();
    compare(&repeated.output, &first_expected);
    assert_eq!(repeated.output.metrics.signature_verifications, 0);

    for (suffix, error) in [
        (renew(0, 6, priors[0]), "PQ5_TASK_BLOCK_MUTEX"),
        (renew(1, 6, [99; 32]), "PQ5_TASK_RENEWAL"),
        (
            rotate(&cfg, &parent, &keys[1], &Key::public_test_seed(204)),
            "PQ2_AUTHORITY_BLOCK_MUTEX",
        ),
    ] {
        let rejected = [raws[0].clone(), suffix];
        assert_eq!(execute(&parent, &cfg, 3, &rejected, 1).err(), Some(error));
        assert_eq!(prefix.execute(&rejected).err(), Some(error));
        assert_eq!(prefix.len(), 1);
        compare(&prefix.execute(&raws[..1]).unwrap().output, &first_expected);
    }

    let cancel = |point| {
        if point == (ExecutionProgress::AfterApply { index: 1 }) {
            Err("renewal-suffix-cancelled")
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        prefix.execute_with_control(&raws, &ExecutionControl::new(&cancel, &())),
        Err(ExecutionError::Cancelled("renewal-suffix-cancelled"))
    ));
    assert_eq!(prefix.len(), 1);
    compare(&prefix.execute(&raws[..1]).unwrap().output, &first_expected);
    let completed = prefix.execute(&raws).unwrap();
    compare(&completed.output, &full_expected);
    assert_eq!(completed.output.metrics.signature_verifications, 2);
    assert_eq!(prefix.len(), 2);
    assert_eq!(account(&completed.output.state, keys[0].id)["nonce"], 6);
    compare(&prefix.execute(&raws).unwrap().output, &full_expected);
    assert_eq!(parent, original_parent);
}
