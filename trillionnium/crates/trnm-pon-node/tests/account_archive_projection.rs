//! Real signed growth, native proof admission, heavier branches and cold reopens.
//! The independent archive is only a projection; it never supplies Node's State.
use std::collections::BTreeMap;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, Config},
};
use trnm_pon_node::{
    account_archive_prototype::{
        AccountArchive, ArchiveError, CheckedAccounts, Checkpoint, Context, Limits,
    },
    development_public, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn signed(settings: &Settings, sender: u64, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = development_public(recipient).unwrap().to_vec();
    payload.extend(amount.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(sender).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn add(
    node: &mut Node,
    archive: &mut AccountArchive,
    checkpoints: &mut BTreeMap<Hash, Checkpoint>,
    parent: Hash,
    txs: Vec<Vec<u8>>,
    miner: Hash,
) -> Hash {
    let height = node.parent_height(parent).unwrap() + 1;
    let before = node.state_at(parent).unwrap();
    let packet = node
        .make_consensus_maintenance(parent, txs, miner, 1 + height * 10, 4096)
        .unwrap();
    let id = node.admit(&packet, 100_000).unwrap();
    let after = node.state_at(id).unwrap();
    assert_eq!(pon_executor::root(&after).unwrap(), packet.header.state);
    let checkpoint = archive
        .project_successor(
            checkpoints[&parent].id(),
            &before,
            &after,
            id,
            height,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(checkpoint.source_state_root(), Some(packet.header.state));
    checkpoints.insert(id, checkpoint);
    let selected = node.activate(id).unwrap();
    let wanted = checkpoints[&selected].id();
    let actual = archive.active().unwrap();
    if actual.is_none_or(|active| active.checkpoint != wanted) {
        archive.activate(actual, wanted, &mut || Ok(())).unwrap();
    }
    id
}

#[test]
fn signed_growth_zero_balance_nonce_reentry_heavier_forks_and_reopen_preserve_exact_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let node_path = dir.path().join("node");
    let archive_path = dir.path().join("account-archive.sqlite");
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let context = Context {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    };
    let mut node = Node::open(&node_path, settings.clone(), 1).unwrap();
    let mut archive = AccountArchive::open(&archive_path, context, Limits::default()).unwrap();
    let initial = node.read_active().unwrap();
    let checkpoint = archive
        .project_initial(&initial.2, pon_executor::root(&initial.2).unwrap())
        .unwrap();
    assert_eq!(checkpoint.account_count(), 4);
    archive
        .activate(None, checkpoint.id(), &mut || Ok(()))
        .unwrap();
    let mut checkpoints = BTreeMap::from([(initial.0, checkpoint)]);
    let spend = signed(&settings, 10, 1, 2, 37);
    let config =
        Config::installed_with_profiles("native-public-evaluation-dev-v1", continuity_v1::PROFILE)
            .unwrap();
    let fee =
        config.fees[1] + spend.len() as u64 * config.params["byte_fee_units"].as_u64().unwrap();
    let drained_key = format!("account:{}", hex::encode(development_public(10).unwrap()));
    let new_miner = development_public(79_999).unwrap();
    let mut main = initial.0;
    let mut fork_parent = initial.0;
    let mut signed_count = 0;
    for height in 1..=21 {
        let mut txs = Vec::new();
        if height <= 8 {
            for index in (height - 1) * 16..height * 16 {
                txs.push(signed(&settings, 1, index + 1, 100 + index, 1));
            }
        }
        match height {
            1 => txs.push(signed(&settings, 0, 1, 10, fee + 37)),
            2 => txs.push(spend.clone()),
            3 => txs.push(signed(&settings, 0, 2, 10, fee + 7)),
            4 => {
                let before = node.read_active().unwrap();
                let storage = archive.observation().unwrap();
                let error = node
                    .make_consensus_maintenance(
                        main,
                        vec![spend.clone()],
                        development_public(0).unwrap(),
                        41,
                        4096,
                    )
                    .unwrap_err();
                assert_eq!(error.to_string(), "NONCE");
                assert_eq!(node.read_active().unwrap(), before);
                assert_eq!(archive.observation().unwrap(), storage);
                txs.push(signed(&settings, 10, 2, 2, 7));
            }
            _ => (),
        }
        signed_count += txs.len();
        main = add(
            &mut node,
            &mut archive,
            &mut checkpoints,
            main,
            txs,
            if height == 1 {
                new_miner
            } else {
                development_public(0).unwrap()
            },
        );
        if height == 2 {
            fork_parent = main;
        }
        if height == 2 || height == 4 {
            let state = node.read_active().unwrap().2;
            assert_eq!(state[&drained_key]["balance"], 0);
            assert_eq!(state[&drained_key]["nonce"], height / 2);
            let selected = &checkpoints[&main];
            let witness = archive
                .witness(selected.id(), development_public(10).unwrap())
                .unwrap()
                .0;
            let view = CheckedAccounts::verify(
                context,
                selected,
                &[development_public(10).unwrap()],
                &[witness],
            )
            .unwrap();
            assert_eq!(
                view.check_next_nonce(development_public(10).unwrap(), 1),
                Err(ArchiveError::Nonce)
            );
        }
        if height == 20 {
            let witness = archive
                .witness(checkpoints[&main].id(), new_miner)
                .unwrap()
                .0;
            assert_eq!(witness.account, None); // Reserved reward is not yet an account.
        }
    }
    assert_eq!(signed_count, 132);
    let main_state = node.read_active().unwrap();
    let main_checkpoint = checkpoints[&main].clone();
    assert_eq!(main_checkpoint.account_count(), 134); // 4 genesis +128 transfers +drained +matured miner.
    let old_main_witness = archive
        .witness(main_checkpoint.id(), development_public(10).unwrap())
        .unwrap()
        .0;
    assert_eq!(old_main_witness.account.unwrap().nonce, 2);
    assert!(archive
        .witness(main_checkpoint.id(), new_miner)
        .unwrap()
        .0
        .account
        .is_some());
    drop(node);
    drop(archive);
    node = Node::open(&node_path, settings.clone(), 1).unwrap();
    archive = AccountArchive::open(&archive_path, context, Limits::default()).unwrap();
    assert_eq!(node.read_active().unwrap(), main_state);
    assert_eq!(
        archive.active().unwrap().unwrap().checkpoint,
        main_checkpoint.id()
    );
    // Start at the actual height2 parent. Each admitted branch state is read by ID,
    // even while a shorter side branch cannot win the native required-work rule.
    let mut fork = fork_parent;
    for _height in 3..=22 {
        fork = add(
            &mut node,
            &mut archive,
            &mut checkpoints,
            fork,
            vec![],
            development_public(0).unwrap(),
        );
    }
    assert_eq!(node.active().unwrap().0, fork);
    let fork_state = node.read_active().unwrap();
    let fork_checkpoint = checkpoints[&fork].clone();
    assert_eq!(fork_state.2[&drained_key]["nonce"], 1);
    assert!(matches!(
        CheckedAccounts::verify(
            context,
            &fork_checkpoint,
            &[development_public(10).unwrap()],
            &[old_main_witness]
        ),
        Err(ArchiveError::InvalidWitness)
    ));
    assert!(!fork_state.2.contains_key(&format!(
        "account:{}",
        hex::encode(development_public(227).unwrap())
    )));
    drop(node);
    drop(archive);
    node = Node::open(&node_path, settings.clone(), 1).unwrap();
    archive = AccountArchive::open(&archive_path, context, Limits::default()).unwrap();
    assert_eq!(node.read_active().unwrap(), fork_state);
    assert_eq!(
        archive.active().unwrap().unwrap().checkpoint,
        fork_checkpoint.id()
    );
    let restored22 = add(
        &mut node,
        &mut archive,
        &mut checkpoints,
        main,
        vec![],
        development_public(0).unwrap(),
    );
    let restored23 = add(
        &mut node,
        &mut archive,
        &mut checkpoints,
        restored22,
        vec![],
        development_public(0).unwrap(),
    );
    assert_eq!(node.active().unwrap().0, restored23);
    let restored_state = node.read_active().unwrap();
    let restored_checkpoint = checkpoints[&restored23].clone();
    assert_eq!(restored_state.2[&drained_key]["nonce"], 2);
    assert!(restored_state.2.contains_key(&format!(
        "account:{}",
        hex::encode(development_public(227).unwrap())
    )));
    drop(node);
    drop(archive);
    node = Node::open(&node_path, settings, 1).unwrap();
    archive = AccountArchive::open(&archive_path, context, Limits::default()).unwrap();
    assert_eq!(node.read_active().unwrap(), restored_state);
    assert_eq!(
        archive.active().unwrap().unwrap().checkpoint,
        restored_checkpoint.id()
    );
    for (branch, checkpoint) in &checkpoints {
        let actual = node.state_at(*branch).unwrap();
        assert_eq!(
            checkpoint.source_state_root(),
            Some(pon_executor::root(&actual).unwrap())
        );
    }
    println!(
        "{}",
        serde_json::json!({"schema":"pon-account-archive-signed-projection-observation-v1","result":"PASS","accepted_native_packets":43,"accepted_signed_transfers":signed_count,"new_transfer_recipient_accounts":129,"new_matured_miner_accounts":1,"native_reorganizations":2,"cold_reopens":3,"retained_checkpoints":checkpoints.len(),"final_checkpoint":restored_checkpoint,"storage":archive.observation().unwrap(),"protocol_capacity_changed":false,"archive_used_for_native_execution":false,"public_data_availability_accepted":false})
    );
}
