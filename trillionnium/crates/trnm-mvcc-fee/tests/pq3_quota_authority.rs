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
            timestamp: Some(cfg.params["genesis_timestamp"].as_u64().unwrap() + height),
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
    let [owner, consumer, provider] = keys;
    let deadline = 50_u64;
    let quota = hash(
        b"quota-instance-v3",
        &[
            &cfg.network,
            &cfg.parameters,
            &owner.id,
            &1_u64.to_le_bytes(),
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
        &common(cfg, owner.id, 1, 1),
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

#[test]
fn trusted_quota_profile_claim_redecodes_under_exact_config_and_consumes_once() {
    // Unverified synthetic checkpoint for this narrow M06 regression only.
    // The separate native Node case supplies actual admitted source W1 work.
    use trnm_protocol::pon_wire::Header;
    let source_cfg = Config::installed().unwrap();
    let stable = [201; 32];
    let prior = Key::public_test_seed(201);
    let next = Key::public_test_seed(202);
    let source = State::from([
        ("meta:issued".into(), json!(10_000_000)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
        (
            format!("account:{}", hex::encode(stable)),
            json!({"balance":10_000_000,"nonce":7}),
        ),
    ]);
    let material = pq::CheckpointMaterial {
        genesis: [209; 32],
        header: Header {
            network: source_cfg.network,
            parameters: source_cfg.parameters,
            parent: [210; 32],
            height: 10,
            timestamp: 1200,
            target: [255; 32],
            miner: stable,
            transactions: [0; 32],
            state: exec::root_for_config(&source, &source_cfg).unwrap(),
            receipts: [0; 32],
            work_task: [211; 32],
            nonce: 0,
        },
        trace: [212; 32],
        state: source,
    };
    let registry = pq::TrustedPqPrecommitments::pin(
        source_cfg.network,
        material.genesis,
        &[pq::PrecommittedAccount {
            source_account: stable,
            spki: prior.spki.clone(),
            generation: 9,
        }],
    )
    .unwrap();
    let anchor = registry
        .pin_checkpoint(
            material.header.block_id(material.trace),
            material,
            &source_cfg,
        )
        .unwrap();
    let (cfg, state, _) = pq::genesis_quota_v3_with_trusted_migration(&[], 1500, anchor).unwrap();
    let raw = fixture::signed(
        &common(&cfg, stable, 8, 0),
        wire::CLAIM,
        &pq::migration_claim_payload(&cfg, stable).unwrap(),
        &[
            Witness {
                key: &prior,
                role: 5,
                generation: 9,
                carried: false,
            },
            Witness {
                key: &next,
                role: 6,
                generation: 1,
                carried: true,
            },
        ],
        None,
    );
    assert!(wire::UnverifiedEnvelope::decode(&raw).is_err());
    assert!(pq::decode_for_config(&raw, &cfg).is_ok());
    assert!(pq::prepare_signature(&state, &raw, 1501, &cfg).is_ok());
    let output = execute(&state, &cfg, 1, std::slice::from_ref(&raw)).unwrap();
    assert_eq!(output.metrics.signature_verifications, 2);
    assert_eq!(account(&output.state, stable)["nonce"], 8);
    assert_eq!(
        output.state[&format!("pq-import-v2:{}", hex::encode(stable))]["claimed"],
        true
    );
    assert_eq!(
        output.state[&format!("pq-auth-v2:{}", hex::encode(stable))]["key_id"],
        hex::encode(next.id)
    );
    assert_eq!(output.state["meta:issued"], 10_001_000);
    assert!(execute(&output.state, &cfg, 2, &[raw]).is_err());
}
