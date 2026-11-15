use super::*;
use crate::store::native_ancestry_commit_tests::logical_rows;
use crate::{development_public, Settings};
use rusqlite::{params, OptionalExtension};
use serde_json::json;
use std::path::Path;
use trnm_protocol::{
    content_commitment::{observe_bytes, ContentKind},
    crypto_profile::{CryptoProfile, ProfileBinding, ProfileScope},
    pon_wire::Hash,
};

fn open(path: &Path, settings: Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings, 1).unwrap()
    } else {
        Node::open(path, settings, 1).unwrap()
    }
}

fn context(settings: &Settings) -> ContentContextV1 {
    let profile = CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap();
    ContentContextV1::new(&profile, ContentKind::MigrationCheckpoint, [23; 64], 1).unwrap()
}

fn pins(settings: &Settings, checkpoint: Hash) -> SourcePins {
    SourcePins {
        network: settings.network(),
        genesis: settings.genesis(),
        checkpoint,
    }
}

fn budget() -> ContentReadBudget {
    ContentReadBudget::new(2, MAX_MIGRATION_HISTORY_BYTES_V2 + 1).unwrap()
}

fn deadline() -> Instant {
    Instant::now() + MAX_MIGRATION_HISTORY_DURATION_V2
}

fn append(node: &mut Node, parent: Hash, time: u64, miner: u64, active: bool) -> Hash {
    let packet = node
        .make(
            parent,
            vec![],
            development_public(miner).unwrap(),
            time,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 1000).unwrap();
    if active {
        node.activate(id).unwrap();
    }
    id
}

fn chain(authenticated: bool) -> (tempfile::TempDir, Node, Settings, Vec<Hash>) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), settings.clone(), authenticated);
    let mut ids = vec![settings.genesis()];
    for height in 1..=2 {
        let id = append(&mut node, *ids.last().unwrap(), 1 + height * 10, 3, true);
        ids.push(id);
    }
    (directory, node, settings, ids)
}

fn observe(node: &Node, selected: SourcePins) -> ContentClaimV1 {
    let before = logical_rows(&node.db);
    let changes = node.db.total_changes();
    let active = node.active().unwrap();
    let result = node
        .observe_migration_history_v2(
            selected,
            &context(node.settings()),
            &mut budget(),
            deadline(),
        )
        .unwrap();
    assert_eq!(node.db.total_changes(), changes);
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
    assert_eq!(node.active().unwrap(), active);
    result.claim().clone()
}

fn fails_without_writes(node: &Node, selected: SourcePins) -> Error {
    let before = logical_rows(&node.db);
    let changes = node.db.total_changes();
    let active = node.active().unwrap();
    let error = node
        .observe_migration_history_v2(
            selected,
            &context(node.settings()),
            &mut budget(),
            deadline(),
        )
        .unwrap_err();
    assert_eq!(node.db.total_changes(), changes);
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
    assert_eq!(node.active().unwrap(), active);
    error
}

fn source_rejected_before_commitment(node: &Node, selected: SourcePins, code: &str) {
    // The intentionally oversized BLOB is checked using dimensions only; a
    // test-side whole-database dump would itself allocate the malicious input.
    let changes = node.db.total_changes();
    let active = node.active().unwrap();
    let mut used = budget();
    let error = node
        .observe_migration_history_v2(selected, &context(node.settings()), &mut used, deadline())
        .unwrap_err();
    assert_eq!(error.to_string(), code);
    assert_eq!(used.reads_reserved(), 0);
    assert_eq!(used.bytes_reserved(), 0);
    assert_eq!(node.db.total_changes(), changes);
    assert!(node.db.is_autocommit());
    assert_eq!(node.active().unwrap(), active);
}

#[test]
fn native_cmh2_reads_complete_retained_states_across_forks_and_cold_reopen() {
    for authenticated in [false, true] {
        let (directory, mut node, settings, ids) = chain(authenticated);
        let selected = pins(&settings, ids[2]);
        let expected = observe(&node, selected);
        let mut used = budget();
        let readback = node
            .verify_migration_history_v2(selected, &expected, &mut used, deadline())
            .unwrap();
        assert_eq!(readback.block_count(), 2);
        assert_eq!(readback.checkpoint(), ids[2]);
        assert_eq!(readback.observation().claim(), &expected);
        assert_eq!(used.reads_reserved(), 1);
        assert_eq!(used.bytes_reserved(), expected.content_len() + 1);
        let active_before = node.active().unwrap();
        let fork = append(&mut node, settings.genesis(), 12, 7, false);
        let fork_pin = observe(&node, pins(&settings, fork));
        assert_ne!(fork_pin, expected);
        assert_eq!(node.active().unwrap(), active_before);
        let before = logical_rows(&node.db);
        assert!(node
            .verify_migration_history_v2(
                pins(&settings, fork),
                &expected,
                &mut budget(),
                deadline(),
            )
            .is_err());
        assert_eq!(logical_rows(&node.db), before);
        assert!(node.db.is_autocommit());
        assert_eq!(observe(&node, selected), expected);
        drop(node);
        let reopened = open(directory.path(), settings, authenticated);
        assert_eq!(observe(&reopened, selected), expected);
        assert_eq!(reopened.active().unwrap(), active_before);
    }
}

#[test]
fn native_cmh2_genesis_has_actual_state_and_no_fabricated_packet() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), false);
    let selected = pins(&settings, settings.genesis());
    let expected = observe(&node, selected);
    let readback = node
        .verify_migration_history_v2(selected, &expected, &mut budget(), deadline())
        .unwrap();
    assert_eq!(readback.block_count(), 0);
    assert_eq!(readback.checkpoint(), settings.genesis());
    node.db
        .execute(
            "UPDATE blocks SET packet=X'00' WHERE id=?",
            [settings.genesis().as_slice()],
        )
        .unwrap();
    assert_eq!(
        fails_without_writes(&node, selected).to_string(),
        "CMH2_GENESIS_RECORD"
    );
}

#[test]
fn native_cmh2_refuses_corrupt_ancestor_packet_snapshot_and_delta() {
    let (_directory, node, settings, ids) = chain(false);
    let selected = pins(&settings, ids[2]);
    let expected = observe(&node, selected);
    let first = ids[1];
    let packet: Vec<u8> = node
        .db
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [first.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut bad_packet = packet.clone();
    bad_packet[0] ^= 1;
    node.db
        .execute(
            "UPDATE blocks SET packet=?1 WHERE id=?2",
            params![bad_packet, first.as_slice()],
        )
        .unwrap();
    fails_without_writes(&node, selected);
    node.db
        .execute(
            "UPDATE blocks SET packet=?1 WHERE id=?2",
            params![packet, first.as_slice()],
        )
        .unwrap();
    assert_eq!(observe(&node, selected), expected);

    // The complete body remains outside CMH2, but the actual retained packet
    // still has to satisfy its owner's length gate before body allocation.
    node.db
        .execute(
            "UPDATE blocks SET packet=zeroblob(1048577) WHERE id=?",
            [first.as_slice()],
        )
        .unwrap();
    assert_eq!(
        fails_without_writes(&node, selected).to_string(),
        "PACKET_LIMIT"
    );
    node.db
        .execute(
            "UPDATE blocks SET packet=?1 WHERE id=?2",
            params![packet, first.as_slice()],
        )
        .unwrap();
    assert_eq!(observe(&node, selected), expected);

    let old_snapshot: Option<Vec<u8>> = node
        .db
        .query_row(
            "SELECT state FROM snapshots WHERE block=?",
            [first.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    let mut wrong_state = node.state_at(first).unwrap();
    wrong_state.insert("cmh2:unexpected-historical-row".into(), json!(0));
    node.db
        .execute(
            "INSERT OR REPLACE INTO snapshots(block,state) VALUES(?1,?2)",
            params![first.as_slice(), serde_json::to_vec(&wrong_state).unwrap()],
        )
        .unwrap();
    fails_without_writes(&node, selected);
    match old_snapshot {
        Some(bytes) => {
            node.db
                .execute(
                    "UPDATE snapshots SET state=?1 WHERE block=?2",
                    params![bytes, first.as_slice()],
                )
                .unwrap();
        }
        None => {
            node.db
                .execute("DELETE FROM snapshots WHERE block=?", [first.as_slice()])
                .unwrap();
        }
    }
    assert_eq!(observe(&node, selected), expected);

    let (key, old_after): (String, Option<Vec<u8>>) = node
        .db
        .query_row(
            "SELECT key,after FROM deltas WHERE block=? ORDER BY key LIMIT 1",
            [first.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    node.db
        .execute(
            "UPDATE deltas SET after=?1 WHERE block=?2 AND key=?3",
            params![b"null".as_slice(), first.as_slice(), &key],
        )
        .unwrap();
    fails_without_writes(&node, selected);
    node.db
        .execute(
            "UPDATE deltas SET after=?1 WHERE block=?2 AND key=?3",
            params![old_after, first.as_slice(), &key],
        )
        .unwrap();
    assert_eq!(observe(&node, selected), expected);
}

#[test]
fn native_cmh2_requires_full_independent_pin_and_consumes_failed_read_budget() {
    let (_directory, node, settings, ids) = chain(false);
    let selected = pins(&settings, ids[2]);
    let expected = observe(&node, selected);
    let legacy_wrapper = observe_bytes(&context(&settings), &mut budget(), &ids[2]).unwrap();
    let mut used = ContentReadBudget::new(1, expected.content_len() + 1).unwrap();
    let before = logical_rows(&node.db);
    assert!(node
        .verify_migration_history_v2(selected, legacy_wrapper.claim(), &mut used, deadline(),)
        .is_err());
    assert_eq!(used.reads_reserved(), 1);
    assert_eq!(used.bytes_reserved(), expected.content_len() + 1);
    assert!(node
        .verify_migration_history_v2(selected, &expected, &mut used, deadline())
        .is_err());
    assert!(used.exhausted());
    assert_eq!(logical_rows(&node.db), before);
    assert!(node.db.is_autocommit());
}

#[test]
fn native_cmh2_refuses_oversized_source_snapshot_and_delta_before_materialization() {
    let (_directory, node, settings, ids) = chain(false);
    let selected = pins(&settings, ids[2]);
    let expected = observe(&node, selected);
    let first = ids[1];
    // Legacy height one has no periodic snapshot. This non-JSON oversized BLOB
    // must fail the admission query, before JSON decoding or a root calculation.
    let count: u64 = node
        .db
        .query_row(
            "SELECT COUNT(*) FROM snapshots WHERE block=?",
            [first.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    node.db
        .execute(
            "INSERT INTO snapshots(block,state) VALUES(?1,zeroblob(?2))",
            params![first.as_slice(), MAX_MIGRATION_HISTORY_BYTES_V2 + 1],
        )
        .unwrap();
    source_rejected_before_commitment(&node, selected, "CMH2_SOURCE_SNAPSHOT");
    let length: u64 = node
        .db
        .query_row(
            "SELECT length(state) FROM snapshots WHERE block=?",
            [first.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(length, MAX_MIGRATION_HISTORY_BYTES_V2 + 1);
    node.db
        .execute("DELETE FROM snapshots WHERE block=?", [first.as_slice()])
        .unwrap();
    assert_eq!(observe(&node, selected), expected);

    let (key, old_after): (String, Option<Vec<u8>>) = node
        .db
        .query_row(
            "SELECT key,after FROM deltas WHERE block=? ORDER BY key LIMIT 1",
            [first.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    node.db
        .execute(
            "UPDATE deltas SET after=zeroblob(?1) WHERE block=?2 AND key=?3",
            params![MAX_SNAPSHOT_VALUE_BYTES_V1 + 1, first.as_slice(), &key],
        )
        .unwrap();
    source_rejected_before_commitment(&node, selected, "CMH2_SOURCE_DIMENSIONS");
    node.db
        .execute(
            "UPDATE deltas SET after=?1 WHERE block=?2 AND key=?3",
            params![old_after, first.as_slice(), &key],
        )
        .unwrap();
    assert_eq!(observe(&node, selected), expected);
}

#[test]
fn native_cmh2_refuses_excess_delta_rows_without_treating_a_prefix_as_complete() {
    let (_directory, node, settings, ids) = chain(false);
    let selected = pins(&settings, ids[2]);
    node.db
        .execute(
            "WITH RECURSIVE numbers(n) AS (
                 SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<?1
             ) INSERT INTO deltas(block,key,before,after)
               SELECT ?2,printf('cmh2:extra:%06d',n),NULL,NULL FROM numbers",
            params![MAX_SOURCE_DELTA_ROWS + 1, ids[1].as_slice()],
        )
        .unwrap();
    source_rejected_before_commitment(&node, selected, "CMH2_SOURCE_DELTA_ROWS");
    let remaining: u64 = node
        .db
        .query_row(
            "SELECT COUNT(*) FROM deltas WHERE block=? AND key LIKE 'cmh2:extra:%'",
            [ids[1].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining, MAX_SOURCE_DELTA_ROWS as u64 + 1);
}

#[test]
fn native_cmh2_refuses_deadlines_foreign_pins_and_overlong_history_without_writes() {
    let (_directory, node, settings, ids) = chain(false);
    let selected = pins(&settings, ids[2]);
    let before = logical_rows(&node.db);
    for invalid in [Instant::now(), Instant::now() + Duration::from_secs(31)] {
        let error = node
            .observe_migration_history_v2(selected, &context(&settings), &mut budget(), invalid)
            .unwrap_err();
        assert_eq!(error.to_string(), "CMH2_DEADLINE_BOUND");
    }
    let mut foreign = selected;
    foreign.network[0] ^= 1;
    assert_eq!(
        fails_without_writes(&node, foreign).to_string(),
        "CMH2_SOURCE_PINS"
    );
    foreign = selected;
    foreign.genesis[0] ^= 1;
    assert_eq!(
        fails_without_writes(&node, foreign).to_string(),
        "CMH2_SOURCE_PINS"
    );
    assert_eq!(logical_rows(&node.db), before);
    // A corrupt record advertises an over-limit source. Refusal occurs before
    // body/state collection, with no invented successful 32-block prefix.
    node.db
        .execute(
            "UPDATE blocks SET height=?1 WHERE id=?2",
            params![
                MAX_MIGRATION_HISTORY_BLOCKS_V2 as u64 + 1,
                ids[2].as_slice()
            ],
        )
        .unwrap();
    assert_eq!(
        fails_without_writes(&node, selected).to_string(),
        "CMH2_BLOCK_LIMIT"
    );
}
