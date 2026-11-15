use super::*;
use ml_dsa::{Keypair, MlDsa65, SigningKey};
use serde_json::json;
use trnm_protocol::{
    content_commitment::{observe_bytes, ContentClaimV1},
    crypto_profile::{CryptoProfile, ProfileBinding, ProfileScope},
    pon_wire::Header,
};

fn budget() -> ContentReadBudget {
    ContentReadBudget::new(4, 1_000_000_000).unwrap()
}
fn context(kind: ContentKind) -> ContentContextV1 {
    let profile = CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap();
    ContentContextV1::new(&profile, kind, [9; 64], 7).unwrap()
}
fn state() -> State {
    State::from([
        ("account:fixture".into(), json!({"balance":100,"nonce":2})),
        ("unknown:zero-liability".into(), json!({"remaining":0})),
    ])
}
fn registry() -> Vec<PrecommittedAccount> {
    [11u8, 12u8]
        .into_iter()
        .map(|id| {
            let signing = SigningKey::<MlDsa65>::from_seed(&[id; 32].into());
            let mut spki =
                include_bytes!("../../../trnm-protocol/tests/fixtures/pq_transfer/public.der")
                    [..22]
                    .to_vec();
            spki.extend(signing.verifying_key().encode().as_slice());
            PrecommittedAccount {
                source_account: [id; 32],
                generation: 1,
                spki,
            }
        })
        .collect()
}
fn checkpoint(cfg: &Config) -> CheckpointMaterial {
    CheckpointMaterial {
        genesis: [21; 32],
        trace: [22; 32],
        state: state(),
        header: Header {
            network: cfg.network,
            parameters: cfg.parameters,
            parent: [23; 32],
            height: 20,
            timestamp: 1000,
            target: [255; 32],
            miner: [24; 32],
            transactions: [25; 32],
            state: [26; 32],
            receipts: [27; 32],
            work_task: [28; 32],
            nonce: 3,
        },
    }
}
fn snapshot(ctx: &ContentContextV1, state: &State, cfg: &Config) -> ObservedContentV1 {
    observe_state_snapshot_v1(ctx, &mut budget(), state, cfg).unwrap()
}
fn migration(
    ctx: &ContentContextV1,
    cfg: &Config,
    material: &CheckpointMaterial,
    accounts: &[PrecommittedAccount],
) -> ObservedContentV1 {
    observe_migration_checkpoint_v1(
        ctx,
        &mut budget(),
        MigrationCheckpointSourceV1 {
            material,
            configuration: cfg,
            legacy_checkpoint: material.header.block_id(material.trace),
            precommitted_accounts: accounts,
        },
    )
    .unwrap()
}

#[test]
fn complete_state_is_deterministic_and_stream_charges_include_eof() {
    let cfg = Config::installed().unwrap();
    let ctx = context(ContentKind::StateSnapshot);
    let original = state();
    let reordered = original
        .iter()
        .rev()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut quota = budget();
    let observed = observe_state_snapshot_v1(&ctx, &mut quota, &original, &cfg).unwrap();
    assert_eq!(observed.claim(), snapshot(&ctx, &reordered, &cfg).claim());
    assert_eq!(quota.reads_reserved(), 1);
    assert_eq!(quota.bytes_reserved(), observed.claim().content_len() + 1);
    assert_eq!(original, state());
    let (mut input, length) = SnapshotReader::new(&original, &cfg, Vec::new()).unwrap();
    let mut bytes = Vec::new();
    let mut one = [0u8; 1];
    while input.read(&mut one).unwrap() != 0 {
        bytes.push(one[0]);
    }
    assert_eq!(bytes.len() as u64, length);
    assert_eq!(&bytes[..4], b"CST1");
    let independent_read = observe_bytes(&ctx, &mut budget(), &bytes).unwrap();
    observed.claim().verify(&independent_read).unwrap();
}

#[test]
fn every_actual_state_row_and_configuration_field_changes_the_commitment() {
    let cfg = Config::installed().unwrap();
    let ctx = context(ContentKind::StateSnapshot);
    let original = state();
    let expected = snapshot(&ctx, &original, &cfg);
    for changed in [
        State::from([("account:fixture".into(), json!({"balance":100,"nonce":3}))]),
        State::from([("account:fixture".into(), json!({"balance":100,"nonce":2}))]),
        State::from([("other:fixture".into(), json!({"balance":100,"nonce":2}))]),
    ] {
        assert!(expected
            .claim()
            .verify(&snapshot(&ctx, &changed, &cfg))
            .is_err());
    }
    let mut variants = Vec::new();
    let mut changed = cfg.clone();
    changed.network[0] ^= 1;
    variants.push(changed);
    let mut changed = cfg.clone();
    changed.parameters[0] ^= 1;
    variants.push(changed);
    let mut changed = cfg.clone();
    changed.family[0] ^= 1;
    variants.push(changed);
    let mut changed = cfg.clone();
    changed.plan[0] ^= 1;
    variants.push(changed);
    let mut changed = cfg.clone();
    changed.evaluators.insert("extra-owner".into());
    variants.push(changed);
    let mut changed = cfg.clone();
    changed.fees[24] += 1;
    variants.push(changed);
    let mut changed = cfg.clone();
    changed.params["actual-new-parameter"] = json!(17);
    variants.push(changed);
    let mut changed = cfg.clone();
    changed.model_registry = json!({"actual":"replacement"});
    variants.push(changed);
    for changed in variants {
        assert!(expected
            .claim()
            .verify(&snapshot(&ctx, &original, &changed))
            .is_err());
    }
}

#[test]
fn same_legacy_checkpoint_and_root_cannot_stand_in_for_actual_migration_state() {
    let cfg = Config::installed().unwrap();
    let material = checkpoint(&cfg);
    let accounts = registry();
    let ctx = context(ContentKind::MigrationCheckpoint);
    let observed = migration(&ctx, &cfg, &material, &accounts);
    let mut changed = material.clone();
    changed.state.insert("unclassified:debt".into(), json!(999));
    assert_eq!(material.header.state, changed.header.state);
    assert_eq!(
        material.header.block_id(material.trace),
        changed.header.block_id(changed.trace)
    );
    assert!(observed
        .claim()
        .verify(&migration(&ctx, &cfg, &changed, &accounts))
        .is_err());
    let old_digest_only = observe_bytes(&ctx, &mut budget(), &material.header.state).unwrap();
    assert!(observed.claim().verify(&old_digest_only).is_err());
    assert!(ContentClaimV1::decode(&material.header.state).is_err());
}

#[test]
fn migration_binds_full_header_genesis_trace_and_complete_registry() {
    let cfg = Config::installed().unwrap();
    let material = checkpoint(&cfg);
    let accounts = registry();
    let ctx = context(ContentKind::MigrationCheckpoint);
    let expected = migration(&ctx, &cfg, &material, &accounts);
    for selector in 0..12 {
        let mut changed = material.clone();
        match selector {
            0 => changed.header.parent[0] ^= 1,
            1 => changed.header.height += 1,
            2 => changed.header.timestamp += 1,
            3 => changed.header.target[0] ^= 1,
            4 => changed.header.miner[0] ^= 1,
            5 => changed.header.transactions[0] ^= 1,
            6 => changed.header.state[0] ^= 1,
            7 => changed.header.receipts[0] ^= 1,
            8 => changed.header.work_task[0] ^= 1,
            9 => changed.header.nonce += 1,
            10 => changed.genesis[0] ^= 1,
            _ => changed.trace[0] ^= 1,
        }
        assert!(expected
            .claim()
            .verify(&migration(&ctx, &cfg, &changed, &accounts))
            .is_err());
    }
    let mut variants = Vec::new();
    let mut changed = accounts.clone();
    changed[0].generation += 1;
    variants.push(changed);
    let mut changed = accounts.clone();
    changed[0].source_account[0] -= 1;
    variants.push(changed);
    let mut changed = accounts.clone();
    changed[0].spki = accounts[1].spki.clone();
    variants.push(changed);
    variants.push(accounts[..1].to_vec());
    for changed in variants {
        assert!(expected
            .claim()
            .verify(&migration(&ctx, &cfg, &material, &changed))
            .is_err());
    }
    let mut altered_parameters = cfg.clone();
    altered_parameters.params["actual-new-parameter"] = json!(7);
    assert!(expected
        .claim()
        .verify(&migration(&ctx, &altered_parameters, &material, &accounts))
        .is_err());
}

#[test]
fn kinds_contexts_and_legacy_locator_are_not_interchangeable() {
    let cfg = Config::installed().unwrap();
    let material = checkpoint(&cfg);
    let accounts = registry();
    let ctx = context(ContentKind::StateSnapshot);
    let wrong = context(ContentKind::ModelManifest);
    assert!(observe_state_snapshot_v1(&wrong, &mut budget(), &material.state, &cfg).is_err());
    assert!(observe_migration_checkpoint_v1(
        &ctx,
        &mut budget(),
        MigrationCheckpointSourceV1 {
            material: &material,
            configuration: &cfg,
            legacy_checkpoint: material.header.block_id(material.trace),
            precommitted_accounts: &accounts,
        }
    )
    .is_err());
    let migration_context = context(ContentKind::MigrationCheckpoint);
    assert!(observe_migration_checkpoint_v1(
        &migration_context,
        &mut budget(),
        MigrationCheckpointSourceV1 {
            material: &material,
            configuration: &cfg,
            legacy_checkpoint: [51; 32],
            precommitted_accounts: &accounts,
        }
    )
    .is_err());
    let observed = snapshot(&ctx, &material.state, &cfg);
    for offset in [4, 69, 133, 141, 149] {
        let mut changed = observed.claim().encode();
        changed[offset] ^= 1;
        assert!(ContentClaimV1::decode(&changed)
            .unwrap()
            .verify(&observed)
            .is_err());
    }
}

#[test]
fn unsupported_or_unbounded_source_encodings_fail_closed() {
    let cfg = Config::installed().unwrap();
    let ctx = context(ContentKind::StateSnapshot);
    let mut deep = json!(0);
    for _ in 0..=MAX_JSON_DEPTH {
        deep = json!([deep]);
    }
    for bad in [
        json!(0.5),
        json!("non-ASCII: é"),
        json!("x".repeat(4096)),
        deep,
    ] {
        assert!(observe_state_snapshot_v1(
            &ctx,
            &mut budget(),
            &State::from([("x".into(), bad)]),
            &cfg
        )
        .is_err());
    }
    assert!(observe_state_snapshot_v1(
        &ctx,
        &mut budget(),
        &State::from([("x".repeat(161), json!(0))]),
        &cfg
    )
    .is_err());
    let too_many = (0..=MAX_SNAPSHOT_ROWS_V1)
        .map(|i| (i.to_string(), json!(0)))
        .collect();
    assert!(observe_state_snapshot_v1(&ctx, &mut budget(), &too_many, &cfg).is_err());
    let accounts = registry();
    let (opaque, _, _) = crate::pon_executor::pq_accounts_v2::genesis(
        &[crate::pon_executor::pq_accounts_v2::GenesisAccount {
            spki: accounts[0].spki.clone(),
            balance: 10_000_000,
        }],
        1000,
    )
    .unwrap();
    assert!(observe_state_snapshot_v1(&ctx, &mut budget(), &state(), &opaque).is_err());
}

#[test]
fn registry_order_duplicates_zero_generation_and_malformed_keys_are_refused() {
    let cfg = Config::installed().unwrap();
    let material = checkpoint(&cfg);
    let ctx = context(ContentKind::MigrationCheckpoint);
    let accounts = registry();
    let mut variants = vec![vec![], vec![accounts[0].clone(), accounts[0].clone()]];
    let mut changed = accounts.clone();
    changed.reverse();
    variants.push(changed);
    let mut changed = accounts.clone();
    changed[0].generation = 0;
    variants.push(changed);
    let mut changed = accounts.clone();
    changed[0].spki.pop();
    variants.push(changed);
    for bad in variants {
        assert!(observe_migration_checkpoint_v1(
            &ctx,
            &mut budget(),
            MigrationCheckpointSourceV1 {
                material: &material,
                configuration: &cfg,
                legacy_checkpoint: material.header.block_id(material.trace),
                precommitted_accounts: &bad,
            }
        )
        .is_err());
    }
}

#[test]
fn refused_stream_budget_cannot_be_reset_with_a_smaller_snapshot() {
    let cfg = Config::installed().unwrap();
    let ctx = context(ContentKind::StateSnapshot);
    let mut quota = ContentReadBudget::new(3, 100).unwrap();
    assert!(observe_state_snapshot_v1(&ctx, &mut quota, &state(), &cfg).is_err());
    assert!(quota.exhausted());
    assert!(observe_state_snapshot_v1(&ctx, &mut quota, &State::new(), &cfg).is_err());
}
