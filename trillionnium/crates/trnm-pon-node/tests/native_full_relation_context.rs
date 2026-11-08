//! A complete PNW1 relation for the actual PGH2 statement is insufficient for
//! admission. Every negative case is freshly mined at its own header target and
//! passes both full kernels before the original Node rejects its precise context.
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{
    development_public, sequence_root, GrowthPacket, GrowthProgress, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

const NOW: u64 = 100_000;
type Rows = BTreeMap<String, Vec<Vec<String>>>;

fn transfer(settings: &Settings, amount: u64) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(81).unwrap().to_vec();
    payload.extend(amount.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}

fn rows(path: &Path) -> Rows {
    let db =
        Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    tables
        .into_iter()
        .map(|table| {
            assert!(table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = statement.column_count();
            let mut values: Vec<Vec<String>> = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| {
                            row.get::<_, rusqlite::types::Value>(column)
                                .map(|value| format!("{value:?}"))
                        })
                        .collect()
                })
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            values.sort();
            (table, values)
        })
        .collect()
}

fn seal(packet: &mut GrowthPacket, a: &[u32], b: &[u32]) {
    assert_eq!(
        packet.header.ledger.work_task,
        pon_work::task_id(a, b).unwrap()
    );
    let prepared = pon_work::PreparedTask::new(a, b).unwrap();
    for nonce in 0..4096 {
        packet.header.ledger.nonce = nonce;
        let challenge = packet.header.challenge();
        packet.proof = prepared.prove(challenge).unwrap();
        let h = &packet.header.ledger;
        let full = match pon_work::verify_full_limb(challenge, h.work_task, h.target, &packet.proof)
        {
            Ok(work) => work,
            Err(pon_work::WorkError::Target) => continue,
            Err(error) => panic!("fresh full relation failed: {error:?}"),
        };
        let scalar =
            pon_work::verify_reference(challenge, h.work_task, h.target, &packet.proof).unwrap();
        assert_eq!(full.challenge(), challenge);
        assert_eq!(full.task(), h.work_task);
        assert!(full.ticket() <= h.target);
        assert_eq!(full.product().len(), pon_work::CELLS);
        assert_eq!(
            (full.challenge(), full.task(), full.ticket(), full.product()),
            (
                scalar.challenge(),
                scalar.task(),
                scalar.ticket(),
                scalar.product()
            )
        );
        return;
    }
    panic!("finite native work search exhausted");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RejectionStage {
    Context,
    ParentWitness,
    ExecutedRoots,
}

#[test]
fn complete_native_work_does_not_replace_original_branch_body_or_state_checks() {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2("native-full-relation-context")
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let sender = development_public(0).unwrap();
    let miner = development_public(3).unwrap();
    let mut parents = [settings.genesis(); 2];
    for height in 1..=15 {
        for (branch, spacing) in [5, 10].into_iter().enumerate() {
            let packet = node
                .make_growth_consensus_maintenance(
                    parents[branch],
                    vec![],
                    miner,
                    1 + height * spacing,
                    4096,
                )
                .unwrap();
            parents[branch] = node.admit_growth(&packet, NOW).unwrap();
        }
    }
    assert_eq!(node.activate(parents[1]).unwrap(), parents[1]);
    let active_target = node.growth_expected_target(parents[1]).unwrap();
    let mut original = node
        .make_growth_consensus_maintenance(
            parents[0],
            vec![transfer(&settings, 1000)],
            miner,
            81,
            4096,
        )
        .unwrap();
    // At height 16, the real five-second parent needs a different target from
    // the active ten-second branch. No zero/permissive verifier target is used.
    assert_eq!(original.header.ledger.height, 16);
    assert_eq!(
        original.header.ledger.target,
        node.growth_expected_target(parents[0]).unwrap()
    );
    assert_ne!(original.header.ledger.target, active_target);
    let (a, b) = continuity_v1::maintenance_matrices();
    seal(&mut original, &a, &b);
    let before = rows(directory.path());
    let active_before = node.active().unwrap();
    let nonce_before = node.next_nonce(sender).unwrap();
    assert_eq!(nonce_before, 1);
    use RejectionStage::{Context, ExecutedRoots, ParentWitness};
    for (case, expected, stage) in [
        ("network", "NETWORK", Context),
        ("parameters", "NETWORK", Context),
        ("unknown-parent", "UNKNOWN_PARENT", Context),
        ("height", "HEIGHT", Context),
        ("height-i64-overflow", "HEIGHT", Context),
        ("height-u64-max", "HEIGHT", Context),
        ("active-branch-target", "TARGET", Context),
        ("median-time-equality", "TIME", Context),
        ("future-time", "TIME_DEFERRED", Context),
        (
            "ineligible-matching-task",
            "CONTINUITY_MAINTENANCE",
            Context,
        ),
        ("signed-body-root", "ROOT", Context),
        ("rebound-body-stale-roots", "ROOT", ExecutedRoots),
        ("state-root", "ROOT", ExecutedRoots),
        ("receipts-root", "ROOT", ExecutedRoots),
        ("witness-digest", "GROWTH_WITNESS_ROOT", Context),
        (
            "rebound-witness-parent",
            "GROWTH_ARCHIVE:InvalidWitness",
            ParentWitness,
        ),
    ] {
        let mut packet = original.clone();
        let mut task_a = a.clone();
        let h = &mut packet.header.ledger;
        match case {
            "network" => h.network[0] ^= 1,
            "parameters" => h.parameters[0] ^= 1,
            "unknown-parent" => h.parent = [0; 32],
            "height" => h.height -= 1,
            "height-i64-overflow" => h.height = i64::MAX as u64 + 1,
            "height-u64-max" => h.height = u64::MAX,
            "active-branch-target" => h.target = active_target,
            // The actual parent-first eleven timestamps are 76, 71, ..., 26.
            "median-time-equality" => h.timestamp = 51,
            "future-time" => h.timestamp = NOW + 121,
            "ineligible-matching-task" => {
                task_a[0] ^= 1;
                h.work_task = pon_work::task_id(&task_a, &b).unwrap();
                assert_ne!(h.work_task, original.header.ledger.work_task);
            }
            "signed-body-root" | "rebound-body-stale-roots" => {
                // Same signed sender/nonce/owners, different valid amount. The
                // latter binds the new body but retains the old execution roots.
                packet.transactions = vec![transfer(&settings, 999)];
                let root = sequence_root("transactions", &packet.transactions);
                assert_ne!(root, h.transactions);
                if case == "rebound-body-stale-roots" {
                    h.transactions = root;
                }
            }
            "state-root" => h.state[0] ^= 1,
            "receipts-root" => h.receipts[0] ^= 1,
            "witness-digest" => packet.header.witness[0] ^= 1,
            "rebound-witness-parent" => {
                packet.accounts.checkpoint[0] ^= 1;
                packet.header.witness = GrowthPacket::witness_digest(&packet.accounts).unwrap();
            }
            _ => unreachable!(),
        }
        seal(&mut packet, &task_a, &b);
        if case != "witness-digest" {
            let bytes = packet.encode().unwrap();
            assert_eq!(
                GrowthPacket::decode(&bytes).unwrap().encode().unwrap(),
                bytes
            );
        }
        let full_work = AtomicBool::new(false);
        let full_transition = AtomicBool::new(false);
        let error = node
            .admit_growth_with_progress(&packet, NOW, &|point| {
                match point {
                    GrowthProgress::Work(pon_work::VerificationProgress::BeforeVerifiedWork) => {
                        full_work.store(true, Ordering::Relaxed);
                    }
                    GrowthProgress::AfterDeltaEncoding => {
                        full_transition.store(true, Ordering::Relaxed)
                    }
                    GrowthProgress::BeforePersistence => {
                        panic!("{case}: invalid context reached writes")
                    }
                    _ => {}
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.to_string(), expected, "{case}");
        assert_eq!(
            full_work.load(Ordering::Relaxed),
            stage != Context,
            "{case}"
        );
        assert_eq!(
            full_transition.load(Ordering::Relaxed),
            stage == ExecutedRoots,
            "{case}"
        );
        assert_eq!(rows(directory.path()), before, "{case}");
        assert_eq!(node.active().unwrap(), active_before, "{case}");
        assert_eq!(node.next_nonce(sender).unwrap(), nonce_before, "{case}");
        assert!(node.growth_packet(packet.id().unwrap()).is_err(), "{case}");
    }
    let id = node.admit_growth(&original, NOW).unwrap();
    assert_eq!(
        node.active().unwrap(),
        active_before,
        "admission is not activation"
    );
    assert_eq!(node.activate(id).unwrap(), id);
    assert_eq!(node.next_nonce(sender).unwrap(), nonce_before + 1);
    assert_eq!(
        node.growth_account(id, development_public(81).unwrap())
            .unwrap()
            .unwrap()
            .balance,
        1000
    );
    let committed = rows(directory.path());
    let active = node.active().unwrap();
    drop(node);
    let reopened = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
    assert_eq!(reopened.active().unwrap(), active);
    assert_eq!(reopened.next_nonce(sender).unwrap(), nonce_before + 1);
    assert_eq!(
        reopened.growth_packet(id).unwrap().encode().unwrap(),
        original.encode().unwrap()
    );
    assert_eq!(rows(directory.path()), committed);
}
