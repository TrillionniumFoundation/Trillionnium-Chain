//! Genuine ML-DSA quota authority controls over the original M06 transition.
use serde_json::json;
use trnm_mvcc_fee::pon_executor::{
    self as exec, pq_accounts_v2 as pq, BlockExecution, Config, ExecutionControl, State,
};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    pq_native_accounts_v2 as wire,
};
#[path = "../../trnm-protocol/tests/support/native_pq_quota_fixture.rs"]
mod fixture;
use fixture::{Key, Witness};

fn setup() -> (Config, State, [Key; 3]) {
    let keys = [
        Key::public_test_seed(171),
        Key::public_test_seed(172),
        Key::public_test_seed(173),
    ];
    let accounts: Vec<_> = keys
        .iter()
        .map(|k| pq::GenesisAccount {
            spki: k.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let (cfg, state, _) = pq::genesis_quota_v3(&accounts, 1000).unwrap();
    (cfg, state, keys)
}
fn common(cfg: &Config, account: Hash, nonce: u64, generation: u64) -> wire::Common {
    wire::Common {
        context: pq::context(cfg).unwrap(),
        account,
        nonce,
        generation,
        expires_at: 2000,
        max_fee: 100_000,
    }
}
fn execute(
    parent: &State,
    cfg: &Config,
    height: u64,
    rows: &[Vec<u8>],
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
            workers: 1,
        },
        cfg,
        &ExecutionControl::new(&progress, &()),
    ) {
        Ok(output) => Ok(output),
        Err(exec::ExecutionError::Relation(error)) => Err(error),
        Err(exec::ExecutionError::Cancelled(impossible)) => match impossible {},
    }
}
fn account(state: &State, id: Hash) -> &serde_json::Value {
    &state[&format!("account:{}", hex::encode(id))]
}
fn reserve(cfg: &Config, keys: &[Key; 3], units: u64) -> (Hash, Vec<u8>) {
    reserve_at_nonce(cfg, keys, units, 1)
}
fn reserve_at_nonce(cfg: &Config, keys: &[Key; 3], units: u64, nonce: u64) -> (Hash, Vec<u8>) {
    let [owner, consumer, provider] = keys;
    let deadline = 50_u64;
    let quota = hash(
        b"quota-instance-v3",
        &[
            &cfg.network,
            &cfg.parameters,
            &owner.id,
            &nonce.to_le_bytes(),
            &consumer.id,
            &provider.id,
            &units.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let payload = [
        quota.as_slice(),
        &consumer.id,
        &provider.id,
        &units.to_le_bytes(),
        &deadline.to_le_bytes(),
    ]
    .concat();
    let raw = fixture::signed(
        &common(cfg, owner.id, nonce, 1),
        10,
        &payload,
        &[Witness {
            key: owner,
            role: 1,
            generation: 1,
            carried: false,
        }],
        None,
    );
    assert_eq!(raw.len(), 3821);
    (quota, raw)
}
fn consume(
    cfg: &Config,
    quota: Hash,
    provider: &Key,
    consumer: &Key,
    nonce: u64,
    consumer_generation: u64,
    units: u64,
) -> Vec<u8> {
    let payload = [quota.as_slice(), &units.to_le_bytes(), &[91; 32]].concat();
    fixture::signed(
        &common(cfg, provider.id, nonce, 1),
        11,
        &payload,
        &[
            Witness {
                key: provider,
                role: 1,
                generation: 1,
                carried: false,
            },
            Witness {
                key: consumer,
                role: 2,
                generation: consumer_generation,
                carried: false,
            },
        ],
        None,
    )
}
fn rotate(cfg: &Config, state: &State, old: &Key, new: &Key) -> Vec<u8> {
    let nonce = account(state, old.id)["nonce"].as_u64().unwrap() + 1;
    let payload = [
        2_u64.to_be_bytes().as_slice(),
        &pq::authority_digest(state, old.id, cfg).unwrap(),
    ]
    .concat();
    fixture::signed(
        &common(cfg, old.id, nonce, 1),
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
        None,
    )
}
fn funded() -> (Config, State, [Key; 3], Hash) {
    let (cfg, state, keys) = setup();
    let (quota, raw) = reserve(&cfg, &keys, 10_000);
    let funded = execute(&state, &cfg, 1, &[raw]).unwrap();
    assert_eq!(funded.metrics.signature_verifications, 1);
    (cfg, funded.state, keys, quota)
}

#[test]
fn actual_dual_pq_quota_conserves_escrow_fee_nonce_and_consumer_identity() {
    let (cfg, state, keys, quota) = funded();
    let raw = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10);
    assert_eq!(raw.len(), 7314);
    assert!(wire::UnverifiedEnvelope::decode(&raw).is_err());
    let fee = cfg.fees[11] + raw.len() as u64 * cfg.params["byte_fee_units"].as_u64().unwrap();
    let cost = 10 * cfg.params["quota_unit_price"].as_u64().unwrap();
    let before = state.clone();
    let output = execute(&state, &cfg, 2, std::slice::from_ref(&raw)).unwrap();
    assert_eq!(state, before);
    assert_eq!(output.metrics.signature_verifications, 2);
    assert_eq!(
        account(&output.state, keys[1].id),
        account(&state, keys[1].id)
    );
    assert_eq!(account(&output.state, keys[2].id)["nonce"], 1);
    assert_eq!(
        account(&output.state, keys[2].id)["balance"],
        account(&state, keys[2].id)["balance"].as_u64().unwrap() + cost - fee
    );
    let q = &output.state[&format!("quota:{}", hex::encode(quota))];
    assert_eq!(q["units"], 9990);
    assert_eq!(
        q["remaining"],
        10_000 * cfg.params["quota_unit_price"].as_u64().unwrap() - cost
    );
    assert_eq!(q["consumer"], hex::encode(keys[1].id));
    assert_eq!(
        output.state["meta:issued"].as_u64().unwrap(),
        state["meta:issued"].as_u64().unwrap() + 1000
    );
    assert_eq!(
        output.root,
        exec::root_for_config(&output.state, &cfg).unwrap()
    );
    assert_eq!(
        execute(&output.state, &cfg, 3, &[raw]).expect_err("provider nonce cannot replay"),
        "NONCE"
    );
}

#[test]
fn both_real_proofs_current_state_consumer_and_nonconsuming_rejections_are_required() {
    let (cfg, state, keys, quota) = funded();
    let raw = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10);
    let before = state.clone();
    for at in [
        176 + 72 + wire::WITNESS_DESCRIPTOR_BYTES + 176 + 2,
        raw.len() - 1,
    ] {
        let mut bad = raw.clone();
        bad[at] ^= 1;
        assert_eq!(
            execute(&state, &cfg, 2, &[bad]).expect_err("actual signature required"),
            "PQ2_SIGNATURE"
        );
    }
    let wrong = consume(&cfg, quota, &keys[2], &keys[0], 1, 1, 10);
    assert_eq!(
        execute(&state, &cfg, 2, &[wrong]).expect_err("current quota consumer"),
        "PQ3_STALE_CONSUMER_AUTHORITY"
    );
    let wrong_provider = consume(&cfg, quota, &keys[0], &keys[1], 2, 1, 10);
    assert_eq!(
        execute(&state, &cfg, 2, &[wrong_provider]).expect_err("actual provider"),
        "AUTHORITY"
    );
    let too_small = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 1);
    assert_eq!(
        execute(&state, &cfg, 2, &[too_small]).expect_err("fee comes from actual escrow cost"),
        "FUNDS"
    );
    let over = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10_001);
    assert_eq!(
        execute(&state, &cfg, 2, &[over]).expect_err("quota units are bounded"),
        "LIMIT"
    );
    assert!(execute(&state, &cfg, 2, &[raw.clone(), raw]).is_err());
    assert_eq!(state, before);
}

#[test]
fn consumer_and_provider_rotations_are_exclusive_in_both_block_orders() {
    let (cfg, state, keys, quota) = funded();
    let next = Key::public_test_seed(174);
    let usage = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10);
    for old in [&keys[1], &keys[2]] {
        let rotation = rotate(&cfg, &state, old, &next);
        for rows in [
            vec![rotation.clone(), usage.clone()],
            vec![usage.clone(), rotation.clone()],
        ] {
            assert_eq!(
                execute(&state, &cfg, 2, &rows).expect_err("no stale generation in either order"),
                "PQ2_AUTHORITY_BLOCK_MUTEX"
            );
        }
    }
    let rotation = rotate(&cfg, &state, &keys[1], &next);
    let rotated = execute(&state, &cfg, 2, &[rotation]).unwrap();
    assert_eq!(
        execute(&rotated.state, &cfg, 3, std::slice::from_ref(&usage))
            .expect_err("retired consumer key"),
        "PQ3_STALE_CONSUMER_AUTHORITY"
    );
    let fresh = consume(&cfg, quota, &keys[2], &next, 1, 2, 10);
    let output = execute(&rotated.state, &cfg, 3, &[fresh]).unwrap();
    assert_eq!(output.metrics.signature_verifications, 2);
    assert_eq!(account(&output.state, keys[1].id)["nonce"], 1);
    assert_eq!(
        output.state[&format!("quota:{}", hex::encode(quota))]["consumer"],
        hex::encode(keys[1].id)
    );
    // Explicit original-parent branch semantics, not an off-chain revocation reset.
    assert!(execute(&state, &cfg, 2, &[usage]).is_ok());
}

#[test]
fn rotated_provider_uses_stable_account_and_rejects_retired_proof_without_spending() {
    let (cfg, state, keys, quota) = funded();
    let next = Key::public_test_seed(175);
    let old_usage = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10);
    let rotation = rotate(&cfg, &state, &keys[2], &next);
    let rotated = execute(&state, &cfg, 2, &[rotation]).unwrap();
    let before = rotated.state.clone();
    assert_eq!(
        execute(&rotated.state, &cfg, 3, &[old_usage]).unwrap_err(),
        "PQ2_STALE_AUTHORITY"
    );
    assert_eq!(rotated.state, before);
    let payload = [quota.as_slice(), &10_u64.to_le_bytes(), &[95; 32]].concat();
    let usage = fixture::signed(
        &common(&cfg, keys[2].id, 2, 2),
        11,
        &payload,
        &[
            Witness {
                key: &next,
                role: 1,
                generation: 2,
                carried: false,
            },
            Witness {
                key: &keys[1],
                role: 2,
                generation: 1,
                carried: false,
            },
        ],
        None,
    );
    let applied = execute(&rotated.state, &cfg, 3, &[usage]).unwrap();
    assert_eq!(applied.metrics.signature_verifications, 2);
    assert_eq!(account(&applied.state, keys[2].id)["nonce"], 2);
    assert!(!applied
        .state
        .contains_key(&format!("account:{}", hex::encode(next.id))));
    assert_eq!(
        applied.state[&format!("quota:{}", hex::encode(quota))]["provider"],
        hex::encode(keys[2].id)
    );
    assert_eq!(
        account(&applied.state, keys[1].id),
        account(&before, keys[1].id)
    );
}

#[test]
fn consumer_registration_and_quota_use_require_separate_parent_authority() {
    let (_, _, keys) = setup();
    let accounts: Vec<_> = [&keys[0], &keys[2]]
        .iter()
        .map(|key| pq::GenesisAccount {
            spki: key.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let (cfg, genesis, _) = pq::genesis_quota_v3(&accounts, 1000).unwrap();
    let transfer_payload = [
        keys[1].id.as_slice(),
        &1_000_000_u64.to_le_bytes(),
        &0_u16.to_le_bytes(),
    ]
    .concat();
    let transfer = fixture::signed(
        &common(&cfg, keys[0].id, 1, 1),
        1,
        &transfer_payload,
        &[Witness {
            key: &keys[0],
            role: 1,
            generation: 1,
            carried: false,
        }],
        None,
    );
    let pending = execute(&genesis, &cfg, 1, &[transfer]).unwrap();
    assert!(!pending
        .state
        .contains_key(&format!("pq-auth-v2:{}", hex::encode(keys[1].id))));
    let (quota, reservation) = reserve_at_nonce(&cfg, &keys, 1000, 2);
    let reserved = execute(&pending.state, &cfg, 2, &[reservation]).unwrap();
    let usage = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10);
    let before = reserved.state.clone();
    assert_eq!(
        execute(&reserved.state, &cfg, 3, std::slice::from_ref(&usage)).unwrap_err(),
        "PQ2_AUTHORITY_REQUIRED"
    );
    let registration = fixture::signed(
        &common(&cfg, keys[1].id, 1, 0),
        wire::REGISTER,
        &1_u64.to_be_bytes(),
        &[Witness {
            key: &keys[1],
            role: 2,
            generation: 1,
            carried: true,
        }],
        None,
    );
    for rows in [
        vec![registration.clone(), usage.clone()],
        vec![usage.clone(), registration.clone()],
    ] {
        assert_eq!(
            execute(&reserved.state, &cfg, 3, &rows).unwrap_err(),
            "PQ2_AUTHORITY_BLOCK_MUTEX"
        );
        assert_eq!(reserved.state, before);
    }
    let registered = execute(&reserved.state, &cfg, 3, &[registration]).unwrap();
    let applied = execute(&registered.state, &cfg, 4, &[usage]).unwrap();
    assert_eq!(applied.metrics.signature_verifications, 2);
    assert_eq!(account(&applied.state, keys[1].id)["nonce"], 1);
    assert_eq!(account(&applied.state, keys[2].id)["nonce"], 1);
    assert_eq!(
        applied.state[&format!("quota:{}", hex::encode(quota))]["units"],
        990
    );
}

#[test]
fn same_block_quota_creation_cannot_supply_consumer_authority() {
    let (cfg, state, keys) = setup();
    let (quota, reservation) = reserve(&cfg, &keys, 1000);
    let usage = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10);
    let before = state.clone();
    for rows in [
        vec![reservation.clone(), usage.clone()],
        vec![usage.clone(), reservation.clone()],
    ] {
        assert!(execute(&state, &cfg, 1, &rows).is_err());
        assert_eq!(state, before);
    }
    let reserved = execute(&state, &cfg, 1, &[reservation]).unwrap();
    assert!(execute(&reserved.state, &cfg, 2, &[usage]).is_ok());
}

#[test]
fn full_dual_proof_capacity_allows_71_and_refuses_72_without_mutation() {
    let (cfg, state, keys, quota) = funded();
    let rows: Vec<_> = (1..=72)
        .map(|nonce| consume(&cfg, quota, &keys[2], &keys[1], nonce, 1, 10))
        .collect();
    assert!(rows.iter().all(|r| r.len() == 7314));
    assert_eq!(rows[..71].iter().map(Vec::len).sum::<usize>(), 519294);
    assert_eq!(rows.iter().map(Vec::len).sum::<usize>(), 526608);
    let before = state.clone();
    let good = execute(&state, &cfg, 2, &rows[..71]).unwrap();
    assert_eq!(good.metrics.signature_verifications, 142);
    assert_eq!(account(&good.state, keys[2].id)["nonce"], 71);
    assert_eq!(
        account(&good.state, keys[1].id),
        account(&state, keys[1].id)
    );
    assert_eq!(
        good.state[&format!("quota:{}", hex::encode(quota))]["units"],
        9290
    );
    assert_eq!(
        execute(&state, &cfg, 2, &rows).expect_err("complete witness bytes count"),
        "PQ2_TRANSACTION_LIMIT"
    );
    assert_eq!(state, before);
}

#[test]
fn v2_cannot_opt_into_quota_and_v3_context_cannot_be_relabelled() {
    let (cfg, state, keys, quota) = funded();
    let raw = consume(&cfg, quota, &keys[2], &keys[1], 1, 1, 10);
    let accounts: Vec<_> = keys
        .iter()
        .map(|key| pq::GenesisAccount {
            spki: key.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let (old, old_state, _) = pq::genesis(&accounts, 1000).unwrap();
    assert_ne!(pq::context(&old).unwrap(), pq::context(&cfg).unwrap());
    assert!(pq::prepare_signature(&old_state, &raw, 1002, &old).is_err());
    assert!(wire::signing_core(
        &common(&old, keys[0].id, 1, 1),
        10,
        &[0; 112],
        &[wire::WitnessKey {
            role: 1,
            generation: 1,
            key_id: keys[0].id,
            spki: None
        }]
    )
    .is_err());
    let mut relabelled = raw.clone();
    relabelled[..5].copy_from_slice(b"NPQ2\x02");
    assert!(pq::prepare_signature(&old_state, &relabelled, 1002, &old).is_err());
    let mut modified = cfg.clone();
    modified.params["native_pq_accounts_profile"] = json!(wire::PROFILE);
    assert_eq!(
        pq::prepare_signature(&state, &raw, 1002, &modified).err(),
        Some("PQ2_CONFIG_CHANGED")
    );
}
