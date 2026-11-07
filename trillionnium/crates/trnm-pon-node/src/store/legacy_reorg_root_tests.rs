//! Complete-input root reuse must not weaken the existing Legacy owner.
//! These are real native packets/SQLite commits, not the paid History campaign.
use super::*;
use serde_json::json;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

const NOW: u64 = 100_000;

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}

fn signed_transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 2_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

fn next_packet(node: &Node, height: u64) -> Packet {
    node.make_consensus_maintenance(
        node.active().unwrap().0,
        vec![signed_transfer(&node.settings, height)],
        development_public(7).unwrap(),
        1 + height * 10,
        4096,
    )
    .unwrap()
}

#[test]
fn legacy_reorg_root_keeps_signed_history_cursor_and_cold_publication() {
    let directory = tempfile::tempdir().unwrap();
    let cfg = settings();
    let mut builder = Node::open(&directory.path().join("builder"), cfg.clone(), 1).unwrap();
    let receiver_path = directory.path().join("receiver");
    let mut receiver = Node::open(&receiver_path, cfg.clone(), 1).unwrap();
    let mut target = cfg.genesis();
    for height in 1..=4 {
        let block = next_packet(&builder, height);
        target = builder.admit(&block, NOW).unwrap();
        builder.activate_observed(target, NOW).unwrap();
        assert_eq!(receiver.admit(&block, NOW).unwrap(), target);
    }
    assert_eq!(receiver.active().unwrap(), (cfg.genesis(), 0));
    let expected = builder.read_active().unwrap();
    let mut trace = Vec::new();
    let error = receiver
        .activate_with_fault(
            target,
            Some(&mut |point| {
                trace.push(point.to_owned());
                if point == "attach:1" {
                    Err(Error::from("legacy-root-process-cut").local_integrity())
                } else {
                    Ok(())
                }
            }),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "legacy-root-process-cut");
    assert_eq!(trace, ["intent", "attach:0", "attach:1"]);
    assert_eq!(receiver.active().unwrap(), (cfg.genesis(), 0));
    assert_eq!(
        receiver
            .db
            .query_row("SELECT cursor,done FROM reorg", [], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
            })
            .unwrap(),
        (2, 0)
    );
    drop(receiver);
    // Cold recovery has no volatile arithmetic and must complete the original
    // committed cursor before one atomic active/events publication.
    let mut reopened = Node::open(&receiver_path, cfg.clone(), 1).unwrap();
    let actual = reopened.read_active().unwrap();
    assert_eq!((actual.0, &actual.2), (expected.0, &expected.2));
    assert_eq!(actual.1, 1);
    assert_eq!(
        reopened
            .db
            .query_row("SELECT cursor,done FROM reorg", [], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
            })
            .unwrap(),
        (4, 1)
    );
    let events: u64 = reopened
        .db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(events, 4);
    assert_eq!(reopened.recover().unwrap(), target);
    let again: u64 = reopened
        .db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(again, events);
    // The actual next signed command reads the installed nonce. This ordinary
    // append still uses the original root path rather than this reorg choice.
    let block = next_packet(&builder, 5);
    let next = builder.admit(&block, NOW).unwrap();
    builder.activate_observed(next, NOW).unwrap();
    assert_eq!(reopened.admit(&block, NOW).unwrap(), next);
    reopened.activate_observed(next, NOW).unwrap();
    assert_eq!(
        reopened.read_active().unwrap().2,
        builder.read_active().unwrap().2
    );
    assert_eq!(
        reopened.next_nonce(development_public(0).unwrap()).unwrap(),
        6
    );
}

#[test]
fn legacy_reorg_root_rechecks_untouched_rows_root_claims_and_original_errors() {
    let directory = tempfile::tempdir().unwrap();
    let cfg = Settings::development(Some(1)).unwrap();
    let node = Node::open(directory.path(), cfg.clone(), 1).unwrap();
    let original = node.read_active().unwrap();
    let arithmetic = node.legacy_reorg_root_arithmetic().unwrap();
    for _ in 0..2 {
        node.check_active_before_commit_with_root_arithmetic(
            &mut || Ok(()),
            None,
            Some(arithmetic),
        )
        .unwrap();
    }
    let compare_tail = || {
        let original = node.check_active_before_commit().unwrap_err();
        let reused = node
            .check_active_before_commit_with_root_arithmetic(&mut || Ok(()), None, Some(arithmetic))
            .unwrap_err();
        assert_eq!(original.to_string(), reused.to_string());
        assert_eq!(original.kind(), reused.kind());
        assert_eq!(original.requires_owner_stop(), reused.requires_owner_stop());
        assert!(reused.requires_owner_stop());
        reused.to_string()
    };
    // A key that no planned command touches still enters the full SQL read and
    // complete root. Neither a warm root nor the unchanged block id authorizes it.
    let tx = node.db.unchecked_transaction().unwrap();
    node.db
        .execute(
            "INSERT INTO kv VALUES(?,?,?)",
            params![
                node.slot().unwrap(),
                "untouched-root-probe",
                b"99".as_slice()
            ],
        )
        .unwrap();
    assert_eq!(compare_tail(), "ROOT");
    tx.rollback().unwrap();
    assert_eq!(node.read_active().unwrap(), original);

    let tx = node.db.unchecked_transaction().unwrap();
    node.db
        .execute(
            "UPDATE blocks SET state_root=zeroblob(32) WHERE id=?",
            [cfg.genesis().as_slice()],
        )
        .unwrap();
    assert_eq!(compare_tail(), "ROOT");
    tx.rollback().unwrap();

    for invalid in [json!(0.0), json!(-0.0), json!("non-ascii:λ")] {
        let mut state = original.2.clone();
        state.insert("late-invalid-input".into(), invalid);
        let old = node
            .check_persisted_state_with_readback(cfg.genesis(), &state, &mut || Ok(()), None)
            .unwrap_err();
        let reused = node
            .check_persisted_state_with_root_arithmetic(
                cfg.genesis(),
                &state,
                &mut || Ok(()),
                None,
                Some(arithmetic),
            )
            .unwrap_err();
        assert_eq!(old.to_string(), reused.to_string());
        assert_eq!(old.kind(), reused.kind());
        assert_eq!(old.requires_owner_stop(), reused.requires_owner_stop());
    }
    assert_eq!(node.read_active().unwrap(), original);
}

#[test]
fn legacy_reorg_root_keeps_all_tail_cancellation_boundaries_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), settings(), 1).unwrap();
    let original = node.read_active().unwrap();
    let mut counts = Vec::new();
    for site in [
        native_authenticated::SqlCommitSite::Atomic,
        native_authenticated::SqlCommitSite::ReorgStep,
    ] {
        let mut count = 0;
        node.atomic_with_readback(
            &mut || {
                count += 1;
                Ok(())
            },
            site,
            |_, _| Ok(None),
        )
        .unwrap();
        assert!(count > 3);
        counts.push(count);
        for stop in 1..=count {
            let mut seen = 0;
            let error = node
                .atomic_with_readback(
                    &mut || {
                        seen += 1;
                        if seen == stop {
                            Err(Error::new(crate::ErrorCode::PublicRequestCancelled))
                        } else {
                            Ok(())
                        }
                    },
                    site,
                    |_, _| {
                        node.db.execute(
                            "INSERT INTO metadata VALUES('root-cancel-probe',zeroblob(32))",
                            [],
                        )?;
                        Ok(None)
                    },
                )
                .unwrap_err();
            assert!(error.is(crate::ErrorCode::PublicRequestCancelled));
            assert_eq!(seen, stop);
            assert!(node.db.is_autocommit());
            let retained: u64 = node
                .db
                .query_row(
                    "SELECT COUNT(*) FROM metadata WHERE key='root-cancel-probe'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retained, 0);
            assert_eq!(node.read_active().unwrap(), original);
        }
    }
    assert_eq!(counts[0], counts[1]);
}

#[test]
fn legacy_reorg_root_never_selects_the_growth_or_authenticated_relation() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = Node::open(&directory.path().join("legacy"), settings(), 1).unwrap();
    assert!(legacy.legacy_reorg_root_arithmetic().is_some());
    let authenticated =
        Node::open_with_authenticated_state(&directory.path().join("native"), settings(), 1)
            .unwrap();
    assert!(authenticated.legacy_reorg_root_arithmetic().is_none());
    let growth = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        growth_profile_v2::PROFILE,
    )
    .unwrap();
    let growth = Node::open(&directory.path().join("growth"), growth, 1).unwrap();
    assert_eq!(growth.state_backend, StateBackend::Legacy);
    assert!(growth.legacy_reorg_root_arithmetic().is_none());
    let actual = growth.read_active().unwrap();
    assert_eq!(
        growth.settings.state_root(&actual.2).unwrap(),
        growth.record(actual.0).unwrap().root
    );
    growth.check_active_before_commit().unwrap();
}

#[test]
fn legacy_reorg_root_preserves_pq_v2_and_v6_state_validation() {
    use crate::ingress::pq_network::{canonical_tests::key, PqNetworkPolicy};
    use std::collections::BTreeSet;

    let accounts: Vec<_> = [1, 2, 3]
        .into_iter()
        .map(|seed| pq_accounts_v2::GenesisAccount {
            spki: key(seed).public_spki().to_vec(),
            balance: 1_000_000_000,
        })
        .collect();
    for application in [false, true] {
        let (app, initial, genesis) = if application {
            pq_accounts_v2::application_v6::genesis(
                &accounts,
                1_000,
                &pq_accounts_v2::application_v6::ApplicationPolicy {
                    evaluators: BTreeSet::from([key(2).public_key_id(), key(3).public_key_id()]),
                    evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
                    model_profile: "linear-expert-dev-v1".into(),
                },
            )
        } else {
            pq_accounts_v2::genesis(&accounts, 1_000)
        }
        .unwrap();
        let cfg = Settings {
            app,
            initial,
            genesis,
            operator_bootstrap: None,
            operator_material: None,
            checkpoint_tile_paths: None,
        };
        let directory = tempfile::tempdir().unwrap();
        let policy = PqNetworkPolicy::new(
            &cfg,
            key(71).public_spki(),
            1,
            [key(72).public_spki().to_vec()],
        )
        .unwrap();
        // Use the actual PQ owner so the malformed-State assertion reaches
        // account validation rather than the Legacy constructor's profile gate.
        let mut node =
            Node::open_with_pq_network(directory.path(), cfg.clone(), 1, &policy).unwrap();
        assert_eq!(node.state_backend, StateBackend::PqNetworkV2);
        assert!(node.legacy_reorg_root_arithmetic().is_none());
        // Isolate the defensive profile predicate. The normal Legacy constructor
        // already refuses PQ, and no SQL operation runs with this test-only tag.
        node.state_backend = StateBackend::Legacy;
        assert!(node.legacy_reorg_root_arithmetic().is_none());
        node.state_backend = StateBackend::PqNetworkV2;
        let mut malformed = cfg.initial.clone();
        let auth = malformed
            .keys()
            .find(|name| name.starts_with("pq-auth-v2:"))
            .unwrap()
            .clone();
        malformed.get_mut(&auth).unwrap()["generation"] = json!(0);
        let expected = cfg.state_root(&malformed).unwrap_err().to_string();
        assert!(expected.starts_with("PQ2_"), "{expected}");
        // Even an attacker-consistent claimed plain root must not make malformed
        // PQ authority leaves valid. Pure arithmetic alone accepts these bytes.
        let plain_root = root(&malformed).unwrap();
        let tx = node.db.unchecked_transaction().unwrap();
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![
                    canonical(&malformed[&auth]).unwrap(),
                    node.slot().unwrap(),
                    auth
                ],
            )
            .unwrap();
        node.db
            .execute(
                "UPDATE blocks SET state_root=? WHERE id=?",
                params![plain_root.as_slice(), genesis.as_slice()],
            )
            .unwrap();
        let refusal = node
            .check_active_before_commit_with_root_arithmetic(
                &mut || Ok(()),
                None,
                node.legacy_reorg_root_arithmetic(),
            )
            .unwrap_err();
        assert_eq!(refusal.to_string(), expected);
        tx.rollback().unwrap();
        node.check_active_before_commit().unwrap();
    }
}
