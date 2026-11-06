//! Real admitted source blocks and NPQ6 claims on a restricted test genesis.
//! This fixture deliberately has no work registry to retire. Ordinary source
//! profiles with unsupported rows remain refused; no production cutover follows.
use super::*;
use crate::store::native_ancestry_commit_tests::{logical_rows, open};
use crate::{development_public, Hash, Settings};
use std::collections::BTreeSet;
use trnm_crypto_primitives::{pq_auth::PqNativeSigningKey, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, pq_accounts_v2 as pq},
};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    pq_frame::{ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES},
    pq_native_accounts_v2::{self as wire, AccountProfile},
};
use zeroize::Zeroizing;

fn key(seed: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([seed; 32]);
    let id = ml_dsa_65_key_id_from_spki(&PqNativeSigningKey::public_spki_from_seed(&seed)).unwrap();
    PqNativeSigningKey::from_owned_seed(seed, id).unwrap()
}
fn key_id(key: &PqNativeSigningKey) -> Hash {
    ml_dsa_65_key_id_from_spki(key.public_spki()).unwrap()
}
fn pins(settings: &Settings, checkpoint: Hash) -> SourcePins {
    SourcePins {
        network: settings.network(),
        genesis: settings.genesis(),
        checkpoint,
    }
}
fn registry(settings: &Settings) -> TrustedPqPrecommitments {
    let key = key(31);
    let accounts = settings
        .initial
        .keys()
        .filter_map(|name| name.strip_prefix("account:"))
        .map(|name| pq::PrecommittedAccount {
            source_account: hex::decode(name).unwrap().try_into().unwrap(),
            spki: key.public_spki().to_vec(),
            generation: 9,
        })
        .collect::<Vec<_>>();
    TrustedPqPrecommitments::pin(settings.network(), settings.genesis(), &accounts).unwrap()
}
fn restricted_source_settings() -> Settings {
    let mut settings =
        Settings::development_with_profiles(Some(1), "legacy-first-two-v3", continuity_v1::PROFILE)
            .unwrap();
    // Explicitly distinct genesis, before a store exists. No admitted source
    // row is removed or edited. This is only a restricted migration fixture.
    settings.initial.retain(|name, _| {
        name.starts_with("account:")
            || name == "meta:issued"
            || name == "model:current"
            || name == continuity_v1::MAINTENANCE_KEY
    });
    settings.genesis = hash(
        b"genesis",
        &[
            &settings.network(),
            &settings.parameters(),
            &pon_executor::root_for_config(&settings.initial, &settings.app).unwrap(),
            &settings.genesis_time().to_le_bytes(),
        ],
    );
    settings
}
fn legacy_command(settings: &Settings, sender: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .unwrap();
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(sender).unwrap(),
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}
fn transfer(settings: &Settings) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(7_u64.to_le_bytes());
    legacy_command(settings, 0, 1, payload)
}
fn task_escrow(settings: &Settings) -> Vec<u8> {
    let owner = development_public(1).unwrap();
    let provider = development_public(0).unwrap();
    let budget = 10_000_u64;
    let deadline = 30_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &owner,
            &1_u64.to_le_bytes(),
            &provider,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    legacy_command(
        settings,
        1,
        2,
        [
            task.as_slice(),
            provider.as_slice(),
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ]
        .concat(),
    )
}
fn claim(settings: &Settings, account: Hash, nonce: u64, prior: &PqNativeSigningKey) -> Vec<u8> {
    let next = key(32);
    let common = wire::Common {
        context: pq::context(&settings.app).unwrap(),
        account,
        nonce,
        expires_at: 2000,
        max_fee: 1_000_000,
        generation: 0,
    };
    let payload = pq::migration_claim_payload(&settings.app, account).unwrap();
    let descriptors = [
        wire::WitnessKey {
            role: 5,
            generation: 9,
            key_id: key_id(prior),
            spki: None,
        },
        wire::WitnessKey {
            role: 6,
            generation: 1,
            key_id: key_id(&next),
            spki: Some(next.public_spki().to_vec()),
        },
    ];
    let frames = [prior, &next]
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            let statement = wire::signing_statement_for_profile(
                AccountProfile::ApplicationV6,
                &common,
                wire::CLAIM,
                &payload,
                &descriptors,
                index,
            )
            .unwrap();
            let signature = key.sign_exact_message(&statement).unwrap();
            let mut raw = statement.to_vec();
            raw.extend((ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
            raw.extend(signature);
            raw
        })
        .collect::<Vec<_>>();
    wire::encode_for_profile(
        AccountProfile::ApplicationV6,
        &common,
        wire::CLAIM,
        &payload,
        &descriptors,
        &frames,
    )
    .unwrap()
}

#[test]
fn admitted_restricted_source_handoff_preserves_nonce_liability_and_claim_on_cold_open() {
    for authenticated in [false, true] {
        let source_directory = tempfile::tempdir().unwrap();
        let source_settings = restricted_source_settings();
        // Retain the external registry selection before admitting the source.
        let prior_registry = registry(&source_settings);
        let commitment = prior_registry.commitment();
        let mut source = open(
            source_directory.path(),
            source_settings.clone(),
            authenticated,
        );
        let packet = source
            .make_consensus_maintenance(
                source_settings.genesis(),
                vec![transfer(&source_settings), task_escrow(&source_settings)],
                development_public(0).unwrap(),
                11,
                4096,
            )
            .unwrap();
        let checkpoint = source.admit(&packet, 1000).unwrap();
        source.activate(checkpoint).unwrap();
        let selected = pins(&source_settings, checkpoint);
        let before = logical_rows(&source.db);
        let changes = source.db.total_changes();
        let (anchor, report) = source
            .prepare_pq_migration_checkpoint(selected, commitment, prior_registry.clone())
            .unwrap();
        assert_eq!(logical_rows(&source.db), before);
        assert_eq!(source.db.total_changes(), changes);
        assert!(source.db.is_autocommit());
        let anchor_id = anchor.id();
        assert_eq!(report.greatest_nonce_floor, 1);
        assert_eq!(report.rewards.rows, 1);
        assert!(report.rewards.units > 0);
        assert_eq!(report.tasks.rows, 1);
        assert_eq!(report.tasks.units, 10_000);
        let source_state = source.state_at(checkpoint).unwrap();
        drop(source);
        let source = open(
            source_directory.path(),
            source_settings.clone(),
            authenticated,
        );
        let (reopened_anchor, reopened_report) = source
            .prepare_pq_migration_checkpoint(selected, commitment, prior_registry)
            .unwrap();
        assert_eq!(reopened_anchor.id(), anchor_id);
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            serde_json::to_value(reopened_report).unwrap()
        );

        let evaluators = [key(91), key(92)];
        let accounts = evaluators
            .iter()
            .map(|key| pq::GenesisAccount {
                spki: key.public_spki().to_vec(),
                balance: 0,
            })
            .collect::<Vec<_>>();
        let destination_settings = Settings::native_pq_application_v6_with_migration(
            &accounts,
            1000,
            anchor,
            &pq::application_v6::ApplicationPolicy {
                evaluators: BTreeSet::from([key_id(&evaluators[0]), key_id(&evaluators[1])]),
                evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
                model_profile: "linear-expert-dev-v1".into(),
            },
        )
        .unwrap();
        assert_eq!(
            destination_settings.initial["meta:issued"],
            source_state["meta:issued"]
        );
        for (name, row) in &source_state {
            if name.starts_with("account:") {
                assert_eq!(&destination_settings.initial[name], row);
            }
            if name.starts_with("task:") {
                let mut expected = row.clone();
                expected["deadline"] = serde_json::json!(row["deadline"].as_u64().unwrap() - 1);
                assert_eq!(destination_settings.initial[name], expected);
            }
            if name.starts_with("reward:") {
                assert_eq!(destination_settings.initial[name]["amount"], row["amount"]);
                assert_eq!(destination_settings.initial[name]["owner"], row["owner"]);
                assert_eq!(
                    destination_settings.initial[name]["maturity"],
                    row["maturity"].as_u64().unwrap() - 1
                );
            }
        }
        let destination_directory = tempfile::tempdir().unwrap();
        let mut destination = open(
            destination_directory.path(),
            destination_settings.clone(),
            authenticated,
        );
        let legacy = development_public(0).unwrap();
        let raw = claim(&destination_settings, legacy, 2, &key(31));
        for rejected in [
            claim(&destination_settings, legacy, 1, &key(31)),
            claim(&destination_settings, legacy, 2, &key(33)),
            transfer(&source_settings),
        ] {
            let before = logical_rows(&destination.db);
            assert!(destination
                .make_consensus_maintenance(
                    destination_settings.genesis(),
                    vec![rejected],
                    legacy,
                    1010,
                    4096
                )
                .is_err());
            assert_eq!(logical_rows(&destination.db), before);
        }
        let packet = destination
            .make_consensus_maintenance(
                destination_settings.genesis(),
                vec![raw.clone()],
                legacy,
                1010,
                4096,
            )
            .unwrap();
        let id = destination.admit(&packet, 2000).unwrap();
        destination.activate(id).unwrap();
        let current = destination.state_at(id).unwrap();
        assert_eq!(
            current[&format!("account:{}", hex::encode(legacy))]["nonce"],
            2
        );
        assert_eq!(
            current[&format!("pq-auth-v2:{}", hex::encode(legacy))]["generation"],
            1
        );
        drop(destination);
        let destination = open(
            destination_directory.path(),
            destination_settings,
            authenticated,
        );
        assert_eq!(destination.state_at(id).unwrap(), current);
        assert!(destination
            .make_consensus_maintenance(id, vec![raw], legacy, 1020, 4096)
            .is_err());
    }
}

#[test]
fn admitted_source_handoff_refuses_wrong_registry_pins_and_unsupported_source_rows() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let registry = registry(&settings);
    let commitment = registry.commitment();
    let mut source = open(directory.path(), settings.clone(), false);
    let packet = source
        .make(
            settings.genesis(),
            vec![transfer(&settings)],
            development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let checkpoint = source.admit(&packet, 1000).unwrap();
    source.activate(checkpoint).unwrap();
    let selected = pins(&settings, checkpoint);
    for wrong in [[0; 48], [3; 48]] {
        let before = logical_rows(&source.db);
        assert_eq!(
            source
                .prepare_pq_migration_checkpoint(selected, wrong, registry.clone())
                .err()
                .unwrap()
                .to_string(),
            "PQ_MIGRATION_REGISTRY_PIN"
        );
        assert_eq!(logical_rows(&source.db), before);
        assert!(source.db.is_autocommit());
    }
    let before = logical_rows(&source.db);
    assert_eq!(
        source
            .prepare_pq_migration_checkpoint(selected, commitment, registry)
            .err()
            .unwrap()
            .to_string(),
        "PQ2_UNSUPPORTED_SOURCE_STATE"
    );
    assert_eq!(logical_rows(&source.db), before);
    assert!(source.db.is_autocommit());
}
