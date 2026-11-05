//! Actual native Growth admission retains both successor checks while account
//! parsing skips unrelated working rows. Full-State roots remain the oracle.
use super::*;
use crate::account_archive_prototype::take_account_parse_observation;
use crate::{development_public, Error, GrowthPacket, GrowthProgress, Node};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, pon_executor::growth as limits};
use trnm_protocol::pon_wire::{sequence_root, Envelope};

fn selected_settings(working_rows: usize, dormant_accounts: u64) -> Settings {
    let mut source = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    for index in 0..working_rows {
        let prefix = if index.is_multiple_of(2) { "a:" } else { "z:" };
        source
            .initial
            .insert(format!("{prefix}{index:08}"), json!(0));
    }
    // Exact upper range boundary is still ordinary committed working data.
    source.initial.insert("account;boundary".into(), json!(0));
    for index in 0..dormant_accounts {
        source.initial.insert(
            format!(
                "account:{}",
                hex::encode(hash(
                    b"account-prefix-native-dormant-v1",
                    &[&index.to_le_bytes()]
                ))
            ),
            json!({"balance": 0, "nonce": 7}),
        );
    }
    source
        .with_permanent_account_growth_v2("account-prefix-native-test")
        .unwrap()
}

fn transfer(settings: &Settings) -> Vec<u8> {
    let mut payload = development_public(80).unwrap().to_vec();
    payload.extend(1_000u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 2_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

fn full_state_reference(settings: &Settings, packet: &GrowthPacket) -> State {
    let parent = growth_commitment_from_complete_state_v2(settings, &settings.initial).unwrap();
    let partition = limits::AccountPartition {
        parent_count: parent.permanent_account_count,
        parent_balance: parent.permanent_account_balance,
    };
    let header = &packet.header.ledger;
    let out = limits::execute_with_commitment(
        &settings.initial,
        pon_executor::BlockExecution {
            timestamp: None,
            transactions: &packet.transactions,
            height: header.height,
            miner: header.miner,
            parent_id: header.parent,
            workers: 1,
        },
        &settings.app,
        &partition,
        &|_| Ok(()),
        |_, state| {
            growth_commitment_from_complete_state_v2(settings, state)
                .map(|verified| verified.id)
                .map_err(|_| "ACCOUNT_PREFIX_REFERENCE_ROOT")
        },
        &|_| Ok::<_, Error>(()),
    )
    .unwrap();
    assert_eq!(out.root, header.state);
    assert_eq!(sequence_root("receipts", &out.receipts), header.receipts);
    out.state
}

#[test]
fn native_growth_account_prefix_cost_keeps_complete_roots_and_recovery() {
    for (working_rows, dormant_accounts) in [(0, 0), (64, 0), (4_096, 0), (64, 256)] {
        let settings = selected_settings(working_rows, dormant_accounts);
        let directory = tempfile::tempdir().unwrap();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let transaction = transfer(&settings);
        take_account_parse_observation();
        let packet = node
            .make_growth_consensus_maintenance(
                settings.genesis(),
                vec![transaction.clone()],
                development_public(3).unwrap(),
                11,
                4_096,
            )
            .unwrap();
        let make_counts = take_account_parse_observation();
        let recipient = development_public(80).unwrap();
        assert!(packet
            .accounts
            .accounts
            .iter()
            .any(|row| row.owner == recipient && row.account.is_none()));
        let successor_accounts = packet
            .accounts
            .accounts
            .iter()
            .filter(|row| row.account.is_some())
            .count()
            + 1;
        assert_eq!(make_counts, (2, 2 * successor_accounts));
        let complete = full_state_reference(&settings, &packet);
        let expected = growth_commitment_from_complete_state_v2(&settings, &complete).unwrap();
        let commitment_checks = AtomicUsize::new(0);
        let final_checks = AtomicUsize::new(0);
        take_account_parse_observation();
        let id = node
            .admit_growth_with_progress(&packet, 100_000, &|point| {
                match point {
                    GrowthProgress::CommitmentProof(MultiproofProgress::BeforeOutput) => {
                        commitment_checks.fetch_add(1, Ordering::Relaxed);
                    }
                    GrowthProgress::FinalSuccessorProof(MultiproofProgress::BeforeOutput) => {
                        final_checks.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                Ok(())
            })
            .unwrap();
        let admission_counts = take_account_parse_observation();
        assert_eq!(admission_counts, make_counts);
        assert_eq!(commitment_checks.load(Ordering::Relaxed), 1);
        assert_eq!(final_checks.load(Ordering::Relaxed), 1);
        assert_eq!(node.activate(id).unwrap(), id);
        assert_eq!(
            node.growth_observe(id).unwrap().commitment,
            *expected.observation()
        );
        assert_eq!(node.growth_working(id).unwrap(), non_accounts(&complete));
        let sender = development_public(0).unwrap();
        let sender_after = node.growth_account(id, sender).unwrap().unwrap();
        assert_eq!(sender_after.nonce, 1);
        assert_eq!(
            node.growth_account(id, recipient).unwrap().unwrap().balance,
            1_000
        );
        let active = node.active().unwrap();
        drop(node);
        let node = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
        assert_eq!(node.active().unwrap(), active);
        assert_eq!(
            node.growth_observe(id).unwrap().commitment,
            *expected.observation()
        );
        assert_eq!(node.growth_account(id, sender).unwrap(), Some(sender_after));
        let replay_error = node
            .make_growth_consensus_maintenance(
                id,
                vec![transaction],
                development_public(3).unwrap(),
                21,
                4_096,
            )
            .unwrap_err();
        assert_eq!(replay_error.to_string(), "NONCE");
        assert_eq!(node.active().unwrap(), active);
        println!(
            "{}",
            json!({
                "schema": "native-growth-account-prefix-observation-v1",
                "extra_working_rows": working_rows, "dormant_accounts": dormant_accounts,
                "permanent_accounts": expected.permanent_account_count, "working_rows": expected.working_count,
                "proved_successor_accounts": successor_accounts,
                "make_parser_calls": make_counts.0, "make_parser_rows": make_counts.1,
                "admission_parser_calls": admission_counts.0, "admission_parser_rows": admission_counts.1,
                "full_state_root_equal": true, "cold_replay_and_old_nonce_rejection": true,
                "both_successor_proof_passes_retained": true,
                "scope": "actual native make/admit, complete reference roots, durable reopen and nonce rejection; other working-state scans remain",
                "public_service_qualified": false
            })
        );
    }
}
