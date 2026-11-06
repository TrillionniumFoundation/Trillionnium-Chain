//! NPQ6 migration composition, not a deployed-chain retirement certificate.
//! Positive cases use an explicitly trusted source fixture and actual destination
//! Node/W1/SQLite owners. A real legacy checkpoint retains its unsupported rows.
#[path = "support/pq_application_migration_v6.rs"]
mod support;

use serde_json::json;
use support::{key, row, signed, Fixture, OWNER, PROVIDER, REWARD, TASK};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_executor::{pq_accounts_v2 as pq, Config};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    pq_native_accounts_v2::{self as wire, AccountProfile},
};

#[test]
fn npq6_anchored_claim_preserves_obligations_rotates_and_cold_reopens() {
    let f = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_pq_network(directory.path(), f.settings.clone(), 1, &f.policy).unwrap();
    assert_eq!(node.state_at(f.settings.genesis()).unwrap(), f.initial);
    let owner = row("account", OWNER);
    let provider = row("account", PROVIDER);
    let task = row("task", TASK);
    let reward = row("reward", REWARD);
    assert_eq!(f.initial[&owner], json!({"balance":10_000_000,"nonce":7}));
    assert_eq!(
        f.initial[&provider],
        json!({"balance":10_000_000,"nonce":3})
    );
    assert_eq!(
        f.initial[&task],
        json!({"owner":hex::encode(OWNER),"provider":hex::encode(PROVIDER),
        "remaining":10_000,"deadline":20,"status":"reserved","output":null})
    );
    assert_eq!(
        f.initial[&reward],
        json!({"owner":hex::encode(PROVIDER),"amount":123,"maturity":7})
    );
    assert_eq!(f.initial["meta:issued"], 40_010_123);
    assert!(!f.initial.contains_key(&row("pq-auth-v2", OWNER)));

    let claim = f.claim(AccountProfile::ApplicationV6);
    let claimed = f.append(&mut node, vec![claim.clone()]);
    let claim_fee = f.cfg.params["native_pq_v2_base_fees"][wire::CLAIM.to_string()]
        .as_u64()
        .unwrap()
        + claim.len() as u64 * f.cfg.limit("byte_fee_units").unwrap();
    assert_eq!(
        claimed[&owner],
        json!({"balance":10_000_000 - claim_fee,"nonce":8})
    );
    assert_eq!(claimed[&row("pq-import-v2", OWNER)]["claimed"], true);
    assert_eq!(claimed[&row("pq-import-v2", OWNER)]["source_nonce"], 7);
    assert_eq!(claimed[&row("pq-auth-v2", OWNER)]["generation"], 1);
    assert_eq!(
        claimed[&row("pq-auth-v2", OWNER)]["key_id"],
        hex::encode(f.next.public_key_id())
    );
    assert_eq!(claimed[&task], f.initial[&task]);
    assert_eq!(claimed[&reward], f.initial[&reward]);
    f.refuses(&node, claim, "PQ2_IMPORT_LOCKED");

    let payload = [
        2_u64.to_be_bytes().as_slice(),
        &pq::authority_digest(&claimed, OWNER, &f.cfg).unwrap(),
    ]
    .concat();
    let rotation = signed(
        AccountProfile::ApplicationV6,
        &f.common(9, 1),
        wire::ROTATE,
        &payload,
        &[(&f.next, 3, 1, false), (&f.rotated, 4, 2, true)],
    );
    let rotated = f.append(&mut node, vec![rotation]);
    assert_eq!(rotated[&owner]["nonce"], 9);
    assert_eq!(rotated[&row("pq-auth-v2", OWNER)]["generation"], 2);
    let mut rewound = rotated.clone();
    rewound.get_mut(&owner).unwrap()["nonce"] = json!(8);
    assert!(f.settings.state_root(&rewound).is_err());
    f.refuses(
        &node,
        f.command(&f.next, 1, 10, 3, &TASK),
        "PQ2_STALE_AUTHORITY",
    );
    f.refuses(&node, f.command(&f.rotated, 2, 9, 3, &TASK), "NONCE");

    let cancel = f.command(&f.rotated, 2, 10, 3, &TASK);
    let cancel_fee = f.cfg.fees[3] + cancel.len() as u64 * f.cfg.limit("byte_fee_units").unwrap();
    let cancelled = f.append(&mut node, vec![cancel]);
    assert_eq!(cancelled[&task]["status"], "cancelled");
    assert_eq!(cancelled[&task]["remaining"], 0);
    assert_eq!(
        cancelled[&owner]["balance"],
        rotated[&owner]["balance"].as_u64().unwrap() + 10_000 - cancel_fee
    );
    assert_eq!(cancelled[&owner]["nonce"], 10);
    let active = node.active().unwrap();
    drop(node);
    let mut node =
        Node::open_with_pq_network(directory.path(), f.settings.clone(), 1, &f.policy).unwrap();
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(node.state_at(active.0).unwrap(), cancelled);
    f.refuses(
        &node,
        f.command(&f.next, 1, 11, 3, &TASK),
        "PQ2_STALE_AUTHORITY",
    );
    let mut mature = cancelled;
    for _ in 4..=7 {
        mature = f.append(&mut node, vec![]);
    }
    assert!(!mature.contains_key(&reward));
    assert_eq!(mature[&provider], json!({"balance":10_000_123,"nonce":3}));
    assert_eq!(mature[&row("pq-import-v2", PROVIDER)]["claimed"], false);
    assert!(!mature.contains_key(&row("pq-auth-v2", PROVIDER)));
    let transfer = [
        PROVIDER.as_slice(),
        &7_u64.to_le_bytes(),
        &0_u16.to_be_bytes(),
    ]
    .concat();
    let final_state = f.append(&mut node, vec![f.command(&f.rotated, 2, 11, 1, &transfer)]);
    assert_eq!(final_state[&provider]["balance"], 10_000_130);
    assert_eq!(final_state[&owner]["nonce"], 11);
    let final_active = node.active().unwrap();
    drop(node);
    let reopened =
        Node::open_with_pq_network(directory.path(), f.settings.clone(), 1, &f.policy).unwrap();
    assert_eq!(reopened.active().unwrap(), final_active);
    assert_eq!(reopened.state_at(final_active.0).unwrap(), final_state);
}

#[test]
fn npq6_migration_requires_both_claim_signatures_and_the_selected_domain() {
    let f = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_pq_network(directory.path(), f.settings.clone(), 1, &f.policy).unwrap();
    let transfer = [
        PROVIDER.as_slice(),
        &1_u64.to_le_bytes(),
        &0_u16.to_be_bytes(),
    ]
    .concat();
    f.refuses(
        &node,
        f.command(&f.prior, 9, 8, 1, &transfer),
        "PQ2_AUTHORITY_REQUIRED",
    );
    for profile in [AccountProfile::AccountsV2, AccountProfile::TasksV5] {
        let mut old = f.claim(profile);
        f.refuses(&node, old.clone(), "PQ2_ENCODING");
        old[..5].copy_from_slice(b"NPQ6\x06");
        f.refuses(&node, old, "PQ2_ENCODING");
    }
    let valid = f.claim(AccountProfile::ApplicationV6);
    let parsed =
        wire::UnverifiedEnvelope::decode_for_profile(&valid, AccountProfile::ApplicationV6)
            .unwrap();
    assert_eq!(parsed.witnesses().len(), 2);
    for witness in parsed.witnesses() {
        let offset = valid
            .windows(witness.frame.len())
            .position(|bytes| bytes == witness.frame)
            .unwrap();
        let mut corrupt = valid.clone();
        corrupt[offset + witness.frame.len() - 1] ^= 1;
        f.refuses(&node, corrupt, "PQ2_SIGNATURE");
    }
    let accepted = f.append(&mut node, vec![valid]);
    assert_eq!(accepted[&row("account", OWNER)]["nonce"], 8);
    assert_eq!(accepted[&row("pq-import-v2", OWNER)]["claimed"], true);
}

#[test]
fn admitted_legacy_checkpoint_cannot_drop_unhandled_work_state_for_migration() {
    let settings = Settings::development(None).unwrap();
    let cfg = Config::installed().unwrap();
    assert_eq!(
        (settings.network(), settings.parameters()),
        (cfg.network, cfg.parameters)
    );
    let prior: Vec<_> = (0..4).map(|index| key(240 + index)).collect();
    let registry = pq::TrustedPqPrecommitments::pin(
        settings.network(),
        settings.genesis(),
        &prior
            .iter()
            .enumerate()
            .map(|(index, key)| pq::PrecommittedAccount {
                source_account: development_public(index as u64).unwrap(),
                spki: key.public_spki().to_vec(),
                generation: 9,
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let owner = development_public(0).unwrap();
    let provider = development_public(1).unwrap();
    let budget = 10_000_u64;
    let deadline = 30_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &cfg.network,
            &cfg.parameters,
            &owner,
            &1_u64.to_le_bytes(),
            &provider,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut transaction = Envelope {
        network: settings.network(),
        sender: owner,
        nonce: 1,
        expiry: settings.genesis_time() + 1000,
        fee_limit: 100_000,
        tag: 2,
        payload: [
            task.as_slice(),
            &provider,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ]
        .concat(),
        signature: [0; 64],
    };
    let source_key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    transaction.signature = hex::decode(sign_hex(
        &source_key,
        &transaction.signing_digest().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![transaction.encode().unwrap()],
            provider,
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let checkpoint = node.admit(&packet, settings.genesis_time() + 100).unwrap();
    node.activate(checkpoint).unwrap();
    let retained = node.packet(checkpoint).unwrap();
    let state = node.state_at(checkpoint).unwrap();
    let inventory = node
        .inspect_pq_migration_checkpoint(pq::migration_inventory_v1::SourcePins {
            network: settings.network(),
            genesis: settings.genesis(),
            checkpoint,
        })
        .unwrap();
    assert_eq!(state[&row("account", owner)]["nonce"], 1);
    assert_eq!(state[&row("task", task)]["remaining"], budget);
    assert_eq!(inventory.rewards.rows, 1);
    assert!(inventory.unclassified_rows > 0);
    assert!(state.keys().any(|key| key.starts_with("work:")));
    let material = pq::CheckpointMaterial {
        genesis: settings.genesis(),
        header: retained.header,
        trace: retained.proof.last_chunk::<32>().copied().unwrap(),
        state: state.clone(),
    };
    assert_eq!(
        registry.pin_checkpoint(checkpoint, material, &cfg).err(),
        Some("PQ2_UNSUPPORTED_SOURCE_STATE")
    );
    assert_eq!(node.state_at(checkpoint).unwrap(), state);
    let active = node.active().unwrap();
    drop(node);
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.active().unwrap(), active);
    assert_eq!(reopened.state_at(checkpoint).unwrap(), state);
}
