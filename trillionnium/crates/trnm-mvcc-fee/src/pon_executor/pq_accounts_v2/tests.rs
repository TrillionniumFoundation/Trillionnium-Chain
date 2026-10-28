use super::*;
use crate::pon_executor::{self, BlockExecution, ExecutionControl};
#[path = "../../../../trnm-protocol/tests/support/native_pq_accounts_fixture.rs"]
mod fixture;
use fixture::{Key, Witness};

fn setup() -> (Config, State, Hash, Key, Key) {
    let a = Key::public_test_seed(101);
    let b = Key::public_test_seed(102);
    let (cfg, state, genesis) = genesis(
        &[
            GenesisAccount {
                spki: a.spki.clone(),
                balance: 10_000_000,
            },
            GenesisAccount {
                spki: b.spki.clone(),
                balance: 10_000_000,
            },
        ],
        1000,
    )
    .unwrap();
    (cfg, state, genesis, a, b)
}
fn common(cfg: &Config, account: Hash, nonce: u64, generation: u64) -> wire::Common {
    wire::Common {
        context: context(cfg).unwrap(),
        account,
        nonce,
        expires_at: 2000,
        max_fee: 100_000,
        generation,
    }
}
fn ordinary(
    cfg: &Config,
    key: &Key,
    account: Hash,
    nonce: u64,
    generation: u64,
    kind: u8,
    payload: &[u8],
) -> Vec<u8> {
    fixture::signed(
        &common(cfg, account, nonce, generation),
        kind,
        payload,
        &[Witness {
            key,
            role: 1,
            generation,
            carried: false,
        }],
        None,
    )
}
fn transfer_payload(recipient: Hash, amount: u64) -> Vec<u8> {
    [
        recipient.as_slice(),
        &amount.to_le_bytes(),
        &0_u16.to_be_bytes(),
    ]
    .concat()
}
fn execute(
    parent: &State,
    cfg: &Config,
    height: u64,
    miner: Hash,
    raws: &[Vec<u8>],
    timestamp: Option<u64>,
) -> Result<pon_executor::Output> {
    pon_executor::relation_only(pon_executor::execute_with_control(
        parent,
        BlockExecution {
            timestamp,
            transactions: raws,
            height,
            miner,
            parent_id: [height as u8; 32],
            workers: 1,
        },
        cfg,
        &ExecutionControl::new(&pon_executor::no_cancellation, &()),
    ))
}

#[test]
fn real_pq_positive_funding_registration_state_resolved_transfer_and_zero_credit() {
    let (cfg, state, _, a, _) = setup();
    let new = Key::public_test_seed(103);
    let raw = ordinary(&cfg, &a, a.id, 1, 1, 1, &transfer_payload(new.id, 100_000));
    assert_eq!(raw.len(), 3751);
    let funded = execute(&state, &cfg, 1, new.id, &[raw], Some(1001)).unwrap();
    let name = hex::encode(new.id);
    assert_eq!(
        funded.state[&format!("account:{name}")],
        json!({"balance":100_000,"nonce":0})
    );
    assert!(!funded.state.contains_key(&auth_key(&name)));
    let register = fixture::signed(
        &common(&cfg, new.id, 1, 0),
        wire::REGISTER,
        &1_u64.to_be_bytes(),
        &[Witness {
            key: &new,
            role: 2,
            generation: 1,
            carried: true,
        }],
        None,
    );
    assert_eq!(register.len(), 5691);
    let active = execute(&funded.state, &cfg, 2, new.id, &[register], Some(1002)).unwrap();
    assert_eq!(active.state[&auth_key(&name)], authority(1, new.id, false));
    let raw = ordinary(&cfg, &new, new.id, 2, 1, 1, &transfer_payload(a.id, 17));
    let done = execute(&active.state, &cfg, 3, new.id, &[raw], Some(1003)).unwrap();
    assert_eq!(done.metrics.signature_verifications, 1);
    assert_eq!(done.state[&format!("account:{name}")]["nonce"], 2);
    validate_state(&done.state, &cfg).unwrap();
    assert_eq!(
        done.root,
        pon_executor::root_for_config(&done.state, &cfg).unwrap()
    );
    let empty = Key::public_test_seed(104);
    let zero = ordinary(&cfg, &a, a.id, 1, 1, 1, &transfer_payload(empty.id, 0));
    let out = execute(&state, &cfg, 1, empty.id, &[zero], Some(1001)).unwrap();
    assert!(!out
        .state
        .contains_key(&format!("account:{}", hex::encode(empty.id))));
    // Exercise the actual original zero-subsidy reward producer and maturity
    // function directly. This is an M06 boundary control, not a mined block.
    let height = cfg.limit("subsidy_halving_interval").unwrap() * 64;
    let mut zero_reward_state = state.clone();
    let updates =
        super::super::block_reward_updates(&state, height, empty.id, [9; 32], 0, &cfg).unwrap();
    assert!(updates
        .iter()
        .any(|(k, v)| k.starts_with("reward:") && v["amount"] == 0));
    zero_reward_state.extend(updates);
    super::super::mandatory(
        &mut zero_reward_state,
        height + cfg.limit("reward_maturity_blocks").unwrap(),
        &cfg,
        None,
        None,
    )
    .unwrap();
    assert!(!zero_reward_state.contains_key(&format!("account:{}", hex::encode(empty.id))));
}

#[test]
fn dual_rotation_keeps_stable_task_permissions_and_actual_key_reads() {
    let (cfg, state, _, owner, provider) = setup();
    let next = Key::public_test_seed(105);
    let budget = 50_000_u64;
    let deadline = 20_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &cfg.network,
            &cfg.parameters,
            &owner.id,
            &1_u64.to_le_bytes(),
            &provider.id,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let payload = [
        task.as_slice(),
        &provider.id,
        &budget.to_le_bytes(),
        &deadline.to_le_bytes(),
    ]
    .concat();
    let reserve = ordinary(&cfg, &owner, owner.id, 1, 1, 2, &payload);
    let reserved = execute(&state, &cfg, 1, owner.id, &[reserve], Some(1001)).unwrap();
    let rotation_payload = [
        2_u64.to_be_bytes().as_slice(),
        &authority_digest(&reserved.state, owner.id, &cfg).unwrap(),
    ]
    .concat();
    let rotate = fixture::signed(
        &common(&cfg, owner.id, 2, 1),
        wire::ROTATE,
        &rotation_payload,
        &[
            Witness {
                key: &owner,
                role: 3,
                generation: 1,
                carried: false,
            },
            Witness {
                key: &next,
                role: 4,
                generation: 2,
                carried: true,
            },
        ],
        None,
    );
    let rotated = execute(
        &reserved.state,
        &cfg,
        2,
        owner.id,
        std::slice::from_ref(&rotate),
        Some(1002),
    )
    .unwrap();
    assert_eq!(rotated.metrics.signature_verifications, 2);
    let name = hex::encode(owner.id);
    assert_eq!(
        rotated.state[&auth_key(&name)],
        authority(2, next.id, false)
    );
    assert_eq!(
        rotated.state[&status_key(&name, 1)],
        authority(1, owner.id, true)
    );
    let cancelled = ordinary(&cfg, &next, owner.id, 3, 2, 3, &task);
    let prepared = prepare_signature(&rotated.state, &cancelled, 1003, &cfg).unwrap();
    let patch = apply(&rotated.state, &prepared, 3, &cfg, None).unwrap();
    for key in [auth_key(&name), key_key(&name, 2), status_key(&name, 2)] {
        assert!(patch.reads.contains_key(&key));
    }
    let cancelled = execute(&rotated.state, &cfg, 3, owner.id, &[cancelled], Some(1003)).unwrap();
    assert_eq!(
        cancelled.state[&format!("task:{}", hex::encode(task))]["status"],
        "cancelled"
    );
    let old = ordinary(&cfg, &owner, owner.id, 3, 1, 3, &task);
    assert!(execute(&rotated.state, &cfg, 3, owner.id, &[old], Some(1003)).is_err());
    let wrong = ordinary(&cfg, &provider, provider.id, 1, 1, 3, &task);
    assert!(execute(&rotated.state, &cfg, 3, owner.id, &[wrong], Some(1003)).is_err());
    let output = [9; 32];
    let receipt = ordinary(
        &cfg,
        &provider,
        provider.id,
        1,
        1,
        4,
        &[task.as_slice(), &output].concat(),
    );
    let received = execute(&rotated.state, &cfg, 3, owner.id, &[receipt], Some(1003)).unwrap();
    let accept = ordinary(
        &cfg,
        &next,
        owner.id,
        3,
        2,
        5,
        &[task.as_slice(), &output].concat(),
    );
    let settled = execute(&received.state, &cfg, 4, owner.id, &[accept], Some(1004)).unwrap();
    assert_eq!(
        settled.state[&format!("task:{}", hex::encode(task))]["status"],
        "settled"
    );
    // The same-account authority-changing rule is independent of transaction order.
    let extra = ordinary(
        &cfg,
        &owner,
        owner.id,
        3,
        1,
        1,
        &transfer_payload(provider.id, 1),
    );
    for raws in [vec![rotate.clone(), extra.clone()], vec![extra, rotate]] {
        assert_eq!(
            validate_block(&reserved.state, &raws, owner.id, Some(1002), &cfg),
            Err("PQ2_AUTHORITY_BLOCK_MUTEX")
        );
    }
}

// These M06 unit controls deliberately use an UNVERIFIED synthetic Header.
// Its externally selected hash is a trust fixture, not an asserted W1 proof.
// The separate native Node control must export an actually admitted source block.
fn synthetic_legacy_checkpoint(owner: Hash, provider: Hash) -> (Config, CheckpointMaterial, Hash) {
    let cfg = Config::installed().unwrap();
    let state = State::from([
        ("meta:issued".into(), json!(20_010_123)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
        (
            format!("account:{}", hex::encode(owner)),
            json!({"balance":10_000_000,"nonce":7}),
        ),
        (
            format!("account:{}", hex::encode(provider)),
            json!({"balance":10_000_000,"nonce":3}),
        ),
        (
            format!("task:{}", hex::encode([207; 32])),
            json!({"owner":hex::encode(owner),"provider":hex::encode(provider),"remaining":10_000,"deadline":30,"status":"reserved","output":null}),
        ),
        (
            format!("reward:{}", hex::encode([208; 32])),
            json!({"owner":hex::encode(provider),"amount":123,"maturity":17}),
        ),
    ]);
    let material = CheckpointMaterial {
        genesis: [209; 32],
        header: trnm_protocol::pon_wire::Header {
            network: cfg.network,
            parameters: cfg.parameters,
            parent: [210; 32],
            height: 10,
            timestamp: 1200,
            target: [255; 32],
            miner: owner,
            transactions: [0; 32],
            state: pon_executor::root_for_config(&state, &cfg).unwrap(),
            receipts: [0; 32],
            work_task: [211; 32],
            nonce: 0,
        },
        trace: [212; 32],
        state,
    };
    let checkpoint = material.header.block_id(material.trace);
    (cfg, material, checkpoint)
}
fn synthetic_registry(
    cfg: &Config,
    material: &CheckpointMaterial,
    rows: &[(Hash, &Key)],
) -> TrustedPqPrecommitments {
    TrustedPqPrecommitments::pin(
        cfg.network,
        material.genesis,
        &rows
            .iter()
            .map(|(account, key)| PrecommittedAccount {
                source_account: *account,
                spki: key.spki.clone(),
                generation: 9,
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
fn synthetic_repin(
    registry: TrustedPqPrecommitments,
    cfg: &Config,
    mut material: CheckpointMaterial,
) -> Result<TrustedMigrationAnchor> {
    material.header.state = pon_executor::root_for_config(&material.state, cfg)?;
    let checkpoint = material.header.block_id(material.trace);
    registry.pin_checkpoint(checkpoint, material, cfg)
}
fn claim(cfg: &Config, stable: Hash, nonce: u64, prior: &Key, next: &Key) -> Vec<u8> {
    fixture::signed(
        &common(cfg, stable, nonce, 0),
        wire::CLAIM,
        &migration_claim_payload(cfg, stable).unwrap(),
        &[
            Witness {
                key: prior,
                role: 5,
                generation: 9,
                carried: false,
            },
            Witness {
                key: next,
                role: 6,
                generation: 1,
                carried: true,
            },
        ],
        None,
    )
}

#[test]
fn anchored_migration_conserves_all_accounts_tasks_rewards_and_claims_once() {
    let owner = [201; 32];
    let provider = [202; 32];
    let prior_owner = Key::public_test_seed(101);
    let prior_provider = Key::public_test_seed(102);
    let new_owner = Key::public_test_seed(103);
    let (source_cfg, source, checkpoint) = synthetic_legacy_checkpoint(owner, provider);
    let registry = synthetic_registry(
        &source_cfg,
        &source,
        &[(owner, &prior_owner), (provider, &prior_provider)],
    );
    let anchor = registry
        .pin_checkpoint(checkpoint, source.clone(), &source_cfg)
        .unwrap();
    let (cfg, state, _) = genesis_with_trusted_migration(&[], 1500, anchor).unwrap();
    assert_eq!(state["meta:issued"], source.state["meta:issued"]);
    assert_eq!(super::super::funds(&state).unwrap(), 20_010_123);
    for (key, value) in source
        .state
        .iter()
        .filter(|(key, _)| key.starts_with("account:"))
    {
        assert_eq!(state[key], *value);
    }
    let task = format!("task:{}", hex::encode([207; 32]));
    let reward = format!("reward:{}", hex::encode([208; 32]));
    assert_eq!(state[&task]["remaining"], 10_000);
    assert_eq!(state[&task]["deadline"], 20);
    assert_eq!(state[&reward]["amount"], 123);
    assert_eq!(state[&reward]["maturity"], 7);
    assert_eq!(
        crate::continuity_v1::capacity(&state, 0, &cfg)
            .unwrap()
            .reward_queue_reserve,
        19
    );
    let mut missing_reward = state.clone();
    missing_reward.remove(&reward);
    assert!(crate::continuity_v1::check_state(&missing_reward, 0, &cfg).is_err());
    let unauthorized = ordinary(&cfg, &prior_owner, owner, 8, 1, 3, &[207; 32]);
    assert!(execute(&state, &cfg, 1, new_owner.id, &[unauthorized], Some(1501)).is_err());
    let raw = claim(&cfg, owner, 8, &prior_owner, &new_owner);
    assert_eq!(raw.len(), 9432);
    let out = execute(
        &state,
        &cfg,
        1,
        new_owner.id,
        std::slice::from_ref(&raw),
        Some(1501),
    )
    .unwrap();
    let name = hex::encode(owner);
    assert_eq!(out.metrics.signature_verifications, 2);
    assert_eq!(out.state[&format!("account:{name}")]["nonce"], 8);
    assert_eq!(
        out.state[&auth_key(&name)],
        authority(1, new_owner.id, false)
    );
    assert_eq!(out.state[&format!("pq-import-v2:{name}")]["claimed"], true);
    assert!(execute(&out.state, &cfg, 2, new_owner.id, &[raw], Some(1502)).is_err());
    let cancel = ordinary(&cfg, &new_owner, owner, 9, 1, 3, &[207; 32]);
    let cancelled = execute(&out.state, &cfg, 2, new_owner.id, &[cancel], Some(1502)).unwrap();
    assert_eq!(cancelled.state[&task]["status"], "cancelled");
    assert_eq!(cancelled.state[&task]["remaining"], 0);
    assert_eq!(
        super::super::funds(&cancelled.state).unwrap(),
        super::super::num(&cancelled.state["meta:issued"]).unwrap()
    );
    validate_state(&cancelled.state, &cfg).unwrap();
    let mut mature = cancelled.state;
    for height in 3..=7 {
        mature = execute(
            &mature,
            &cfg,
            height,
            new_owner.id,
            &[],
            Some(1500 + height),
        )
        .unwrap()
        .state;
    }
    assert!(!mature.contains_key(&reward));
    assert_eq!(
        mature[&format!("account:{}", hex::encode(provider))]["balance"],
        10_000_123
    );
    assert_eq!(
        mature[&format!("account:{}", hex::encode(provider))]["nonce"],
        3
    );
    assert_eq!(
        mature[&format!("pq-import-v2:{}", hex::encode(provider))]["claimed"],
        false
    );
    assert_eq!(
        crate::continuity_v1::capacity(&mature, 7, &cfg)
            .unwrap()
            .reward_queue_reserve,
        13
    );
    // Claim's old independent PQ precommitment is not the legacy Ed key. Both
    // prior proof and new possession are cryptographic. A wrong prior signer
    // or corrupted new possession fails; an owner may legitimately select a
    // different new key when BOTH proofs authenticate that same complete core.
    let forged = claim(&cfg, owner, 8, &prior_provider, &new_owner);
    assert!(execute(&state, &cfg, 1, new_owner.id, &[forged], Some(1501)).is_err());
    let mut bad = claim(&cfg, owner, 8, &prior_owner, &new_owner);
    *bad.last_mut().unwrap() ^= 1;
    assert!(execute(&state, &cfg, 1, new_owner.id, &[bad], Some(1501)).is_err());
    let (fresh, _, _, _, _) = setup();
    assert!(migration_claim_payload(&fresh, owner).is_err());
}

#[test]
fn migration_refuses_omissions_ambiguous_ids_untranslated_liabilities_and_unbound_roots() {
    let owner = [201; 32];
    let provider = [202; 32];
    let a = Key::public_test_seed(101);
    let b = Key::public_test_seed(102);
    let (cfg, material, checkpoint) = synthetic_legacy_checkpoint(owner, provider);
    let registry = synthetic_registry(&cfg, &material, &[(owner, &a), (provider, &b)]);
    let missing = synthetic_registry(&cfg, &material, &[(owner, &a)]);
    assert!(missing
        .pin_checkpoint(checkpoint, material.clone(), &cfg)
        .is_err());
    let extra = synthetic_registry(
        &cfg,
        &material,
        &[(owner, &a), (provider, &b), ([203; 32], &a)],
    );
    assert!(extra
        .pin_checkpoint(checkpoint, material.clone(), &cfg)
        .is_err());
    let mut wrong_root = material.clone();
    wrong_root.header.state[0] ^= 1;
    assert!(registry
        .clone()
        .pin_checkpoint(checkpoint, wrong_root, &cfg)
        .is_err());
    let mut incomplete = material.clone();
    incomplete
        .state
        .remove(&format!("reward:{}", hex::encode([208; 32])));
    assert!(synthetic_repin(registry.clone(), &cfg, incomplete).is_err());
    for height in [0, u64::MAX] {
        let mut bad = material.clone();
        bad.header.height = height;
        assert!(synthetic_repin(registry.clone(), &cfg, bad).is_err());
    }
    let mut nonce = material.clone();
    nonce
        .state
        .get_mut(&format!("account:{}", hex::encode(owner)))
        .unwrap()["nonce"] = json!(u64::MAX);
    assert!(synthetic_repin(registry.clone(), &cfg, nonce).is_err());
    for (key, field, value) in [
        (
            format!("task:{}", hex::encode([207; 32])),
            "deadline",
            10_u64,
        ),
        (
            format!("reward:{}", hex::encode([208; 32])),
            "maturity",
            10_u64,
        ),
        (
            format!("reward:{}", hex::encode([208; 32])),
            "maturity",
            31_u64,
        ),
    ] {
        let mut bad = material.clone();
        bad.state.get_mut(&key).unwrap()[field] = json!(value);
        assert!(synthetic_repin(registry.clone(), &cfg, bad).is_err());
    }
    let mut liability = material.clone();
    liability
        .state
        .insert("quota:unsupported".into(), json!({"remaining":1}));
    liability
        .state
        .insert("meta:issued".into(), json!(20_010_124));
    assert!(synthetic_repin(registry.clone(), &cfg, liability).is_err());
    // A colliding destination seed account is rejected instead of replacing or
    // double-crediting a source balance. Here account ID is deliberately a PQ ID.
    let (collision_cfg, collision, collision_id) = synthetic_legacy_checkpoint(a.id, provider);
    let collision_registry =
        synthetic_registry(&collision_cfg, &collision, &[(a.id, &a), (provider, &b)]);
    let anchor = collision_registry
        .pin_checkpoint(collision_id, collision, &collision_cfg)
        .unwrap();
    assert!(genesis_with_trusted_migration(
        &[GenesisAccount {
            spki: a.spki.clone(),
            balance: 1
        }],
        1500,
        anchor
    )
    .is_err());
    // Exact boundary translation uses subtraction, with no overflow or fresh
    // grace period: source MAX-1 -> destination 0, obligations MAX -> 1.
    let mut edge = material.clone();
    edge.header.height = u64::MAX - 1;
    edge.state
        .get_mut(&format!("task:{}", hex::encode([207; 32])))
        .unwrap()["deadline"] = json!(u64::MAX);
    edge.state
        .get_mut(&format!("reward:{}", hex::encode([208; 32])))
        .unwrap()["maturity"] = json!(u64::MAX);
    let anchor = synthetic_repin(registry, &cfg, edge).unwrap();
    let (_, state, _) = genesis_with_trusted_migration(&[], 1500, anchor).unwrap();
    assert_eq!(
        state[&format!("task:{}", hex::encode([207; 32]))]["deadline"],
        1
    );
    assert_eq!(
        state[&format!("reward:{}", hex::encode([208; 32]))]["maturity"],
        1
    );
}
