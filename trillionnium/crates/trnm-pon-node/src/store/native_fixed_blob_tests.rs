//! Retained block fields and packets must be bounded before owned decoding.
use super::super::STORED_PACKET_SQL;
use super::*;
use crate::Node;
use rusqlite::types::Value as SqlValue;
use std::error::Error as _;

const ORIGINAL_BLOCK_SQL: &str = "SELECT parent,height,chainwork,CASE WHEN typeof(packet)='blob' THEN substr(packet,1,1048577) ELSE packet END AS packet,state_root FROM blocks WHERE id=?";
const ORIGINAL_PARENT_SQL: &str = "SELECT height,chainwork FROM blocks WHERE id=?";
const MAX_STORED_PACKET_BYTES: usize = 1_048_576;

fn open(path: &std::path::Path) -> Node {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    Node::open_with_authenticated_state(path, settings, 1).unwrap()
}

// Independent copy of the original complete native block verifier. Only its
// original unbounded queries differ from production; no verdict is reused.
fn original(db: &Connection, settings: &Settings, id: Hash) -> Result<NativeBlock> {
    local((|| {
        let (parent, height, work, packet, state): StoredBlockRow = db
            .prepare_cached(ORIGINAL_BLOCK_SQL)?
            .query_row([id.as_slice()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?;
        let parent = parent.map(bytes32).transpose()?;
        let state = bytes32(state)?;
        let work = consensus::Work::from_bytes(bytes64(work)?);
        if id == settings.genesis() {
            ensure(
                parent.is_none()
                    && height == 0
                    && packet.is_none()
                    && work == consensus::Work::from_bytes([0; 64])
                    && state == root(&settings.initial)?,
                "NATIVE_STATE_GENESIS",
            )?;
            return Ok(NativeBlock {
                parent,
                height,
                root: state,
                packet_digest: None,
            });
        }
        let raw = packet.ok_or("NATIVE_STATE_PACKET")?;
        let packet = Packet::decode(&raw)?;
        let h = &packet.header;
        ensure(
            packet.id()? == id
                && h.network == settings.network()
                && h.parameters == settings.parameters()
                && Some(h.parent) == parent
                && h.height == height
                && h.state == state
                && h.transactions == sequence_root("transactions", &packet.transactions),
            "NATIVE_STATE_PACKET",
        )?;
        let (parent_height, parent_work): (u64, Vec<u8>) = db
            .prepare_cached(ORIGINAL_PARENT_SQL)?
            .query_row([h.parent.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        ensure(
            parent_height.checked_add(1) == Some(height)
                && consensus::Work::from_bytes(bytes64(parent_work)?)
                    .checked_add(consensus::required_work(h.target)?)?
                    == work,
            "NATIVE_STATE_PARENT",
        )?;
        Ok(NativeBlock {
            parent,
            height,
            root: state,
            packet_digest: Some(hash(b"native-authenticated-packet-v1", &[&raw])),
        })
    })())
}

fn identity(value: NativeBlock) -> (Option<Hash>, u64, Hash, Option<Hash>) {
    (value.parent, value.height, value.root, value.packet_digest)
}

fn compare_error(node: &Node, id: Hash) {
    let before = original(&node.db, &node.settings, id).err().unwrap();
    let after = native_block(&node.db, &node.settings, id).err().unwrap();
    assert_eq!(after.to_string(), before.to_string());
    assert_eq!(after.kind(), before.kind());
    assert_eq!(after.requires_owner_stop(), before.requires_owner_stop());
    assert!(after.requires_owner_stop());
}

fn attack_values(width: usize) -> Vec<SqlValue> {
    vec![
        SqlValue::Null,
        SqlValue::Integer(7),
        SqlValue::Real(7.5),
        SqlValue::Text("\u{03bb}\0not-a-blob".into()),
        SqlValue::Blob(vec![]),
        SqlValue::Blob(vec![255; width - 1]),
        SqlValue::Blob(vec![255; width]),
        SqlValue::Blob(vec![255; width + 1]),
        SqlValue::Blob(vec![255; 4 * 1024 * 1024]),
    ]
}

#[test]
fn fixed_blob_projection_bounds_owned_bytes_and_preserves_sql_types() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER,chainwork BLOB,packet BLOB,state_root BLOB)").unwrap();
    db.execute(
        "INSERT INTO blocks VALUES(?,NULL,0,?,NULL,?)",
        params![
            [7u8; 32].as_slice(),
            [0u8; 64].as_slice(),
            [0u8; 32].as_slice()
        ],
    )
    .unwrap();
    for (column, index, width) in [
        ("parent", 0, 32),
        ("chainwork", 2, 64),
        ("state_root", 4, 32),
    ] {
        for value in attack_values(width) {
            db.execute(&format!("UPDATE blocks SET {column}=?"), [&value])
                .unwrap();
            let actual: SqlValue = db
                .prepare_cached(NATIVE_BLOCK_SQL)
                .unwrap()
                .query_row([[7u8; 32].as_slice()], |row| row.get(index))
                .unwrap();
            let expected = match &value {
                SqlValue::Blob(bytes) => {
                    SqlValue::Blob(bytes[..bytes.len().min(width + 1)].to_vec())
                }
                _ => value.clone(),
            };
            assert_eq!(actual, expected);
            if column == "chainwork" {
                let parent: SqlValue = db
                    .prepare_cached(NATIVE_PARENT_SQL)
                    .unwrap()
                    .query_row([[7u8; 32].as_slice()], |row| row.get(1))
                    .unwrap();
                assert_eq!(parent, expected);
            }
        }
    }
    // This is the actual SQL-to-owned-payload bound, not SQLite page traffic,
    // allocator peak/RSS, complete Node throughput or an adversary-cost bound.
}

#[test]
fn fixed_block_fields_match_original_errors_after_warm_cache_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(directory.path());
    let genesis = node.settings.genesis();
    let packet = node
        .make_consensus_maintenance(
            genesis,
            vec![],
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 100_000).unwrap();
    let expected = identity(original(&node.db, &node.settings, id).unwrap());
    for capacity in [0, 1, 16] {
        node.db.set_prepared_statement_cache_capacity(capacity);
        for (column, width) in [("parent", 32), ("chainwork", 64), ("state_root", 32)] {
            for value in attack_values(width) {
                if column != "parent" && value == SqlValue::Null {
                    continue;
                }
                assert_eq!(
                    identity(native_block(&node.db, &node.settings, id).unwrap()),
                    expected
                );
                node.db.execute_batch("SAVEPOINT fixed_field").unwrap();
                node.db
                    .execute(
                        &format!("UPDATE blocks SET {column}=? WHERE id=?"),
                        params![value, id.as_slice()],
                    )
                    .unwrap();
                compare_error(&node, id);
                node.db
                    .execute_batch("ROLLBACK TO fixed_field; RELEASE fixed_field")
                    .unwrap();
                assert_eq!(
                    identity(native_block(&node.db, &node.settings, id).unwrap()),
                    expected
                );
            }
        }
    }
}

#[test]
fn fixed_parent_work_matches_original_and_rereads_after_restore() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(directory.path());
    let genesis = node.settings.genesis();
    let packet = node
        .make_consensus_maintenance(
            genesis,
            vec![],
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 100_000).unwrap();
    let expected = identity(original(&node.db, &node.settings, id).unwrap());
    for capacity in [0, 1, 16] {
        node.db.set_prepared_statement_cache_capacity(capacity);
        for value in attack_values(64) {
            if value == SqlValue::Null {
                continue;
            }
            assert_eq!(
                identity(native_block(&node.db, &node.settings, id).unwrap()),
                expected
            );
            node.db.execute_batch("SAVEPOINT fixed_parent").unwrap();
            node.db
                .execute(
                    "UPDATE blocks SET chainwork=? WHERE id=?",
                    params![value, genesis.as_slice()],
                )
                .unwrap();
            compare_error(&node, id);
            node.db
                .execute_batch("ROLLBACK TO fixed_parent; RELEASE fixed_parent")
                .unwrap();
            assert_eq!(
                identity(native_block(&node.db, &node.settings, id).unwrap()),
                expected
            );
        }
    }
}

#[test]
fn fixed_fields_genesis_failure_order_and_cold_reopen_keep_state() {
    let directory = tempfile::tempdir().unwrap();
    let node = open(directory.path());
    let id = node.settings.genesis();
    let expected = node.read_active().unwrap();
    for (column, width) in [("parent", 32), ("chainwork", 64), ("state_root", 32)] {
        for value in attack_values(width) {
            if value == SqlValue::Null {
                continue;
            }
            node.db.execute_batch("SAVEPOINT fixed_genesis").unwrap();
            node.db
                .execute(
                    &format!("UPDATE blocks SET {column}=? WHERE id=?"),
                    params![value, id.as_slice()],
                )
                .unwrap();
            compare_error(&node, id);
            node.db
                .execute_batch("ROLLBACK TO fixed_genesis; RELEASE fixed_genesis")
                .unwrap();
            verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap();
        }
    }
    node.db.execute_batch("SAVEPOINT multiple_damage").unwrap();
    node.db.execute("UPDATE blocks SET parent=zeroblob(4096),state_root=zeroblob(4096),chainwork=zeroblob(4096) WHERE id=?", [id.as_slice()]).unwrap();
    compare_error(&node, id);
    node.db
        .execute_batch("ROLLBACK TO multiple_damage; RELEASE multiple_damage")
        .unwrap();
    drop(node);
    let reopened = open(directory.path());
    assert_eq!(reopened.read_active().unwrap(), expected);
    verify_history(&reopened.db, &reopened.settings, id, &mut || Ok(())).unwrap();
}

fn same_packet_error(before: Error, after: Error) {
    assert_eq!(after.to_string(), before.to_string());
    assert_eq!(after.code(), before.code());
    assert_eq!(after.kind(), before.kind());
    assert_eq!(after.requires_owner_stop(), before.requires_owner_stop());
    match (before.source(), after.source()) {
        (Some(old), Some(new)) => {
            let old = old.downcast_ref::<rusqlite::Error>().unwrap();
            let new = new.downcast_ref::<rusqlite::Error>().unwrap();
            assert_eq!(new, old);
        }
        (None, None) => {}
        _ => panic!("stored packet error source changed"),
    }
}

// Independent original unbounded read, decoder and row binding. Do not derive
// the expected error from the bounded helper or from Node::packet itself.
fn original_packet(node: &Node, id: Hash) -> Result<Packet> {
    let row = node.record(id)?;
    let raw: Option<Vec<u8>> = node.db.query_row(
        "SELECT packet FROM blocks WHERE id=?",
        [id.as_slice()],
        |row| row.get(0),
    )?;
    let raw = raw.ok_or_else(|| {
        let error = Error::from("GENESIS_HAS_NO_PACKET");
        if id == node.settings.genesis() {
            error
        } else {
            error.local_integrity()
        }
    })?;
    let packet =
        Packet::decode_for_settings(&raw, &node.settings).map_err(Error::local_integrity)?;
    ensure(
        packet.id()? == id
            && Some(packet.header.parent) == row.parent
            && packet.header.height == row.height
            && packet.header.state == row.root,
        "STORAGE_PACKET",
    )?;
    Ok(packet)
}

// The duplicate comparison shared by the original admission/observation paths.
// These fixtures have already passed their unchanged packet/context prechecks.
fn original_packet_comparison(node: &Node, packet: &Packet) -> Result<()> {
    let raw: Option<Vec<u8>> = node
        .db
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [packet.id()?.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(raw) = raw {
        ensure(
            raw == packet.encode_for_settings(&node.settings)?,
            "DUPLICATE_CONTENT",
        )?;
    }
    Ok(())
}

#[test]
fn stored_packet_blob_copy_bound_preserves_sql_types_and_boundary() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE blocks(id INTEGER PRIMARY KEY,packet BLOB); INSERT INTO blocks VALUES(1,NULL)").unwrap();
    for value in attack_values(MAX_STORED_PACKET_BYTES) {
        db.execute("UPDATE blocks SET packet=? WHERE id=1", [&value])
            .unwrap();
        // Query the actual production projection rather than a test-only clamp.
        // Removing its bound must fail even if all decoder errors remain equal.
        let projected: SqlValue = db
            .query_row(STORED_PACKET_SQL, [1], |row| row.get(0))
            .unwrap();
        if let SqlValue::Blob(bytes) = &projected {
            assert!(
                bytes.len() <= MAX_STORED_PACKET_BYTES + 1,
                "production packet projection retained {} bytes",
                bytes.len()
            );
        }
        let expected = match &value {
            SqlValue::Blob(bytes) => {
                SqlValue::Blob(bytes[..bytes.len().min(MAX_STORED_PACKET_BYTES + 1)].to_vec())
            }
            _ => value.clone(),
        };
        assert_eq!(projected, expected);
        let old = db.query_row("SELECT packet FROM blocks WHERE id=?", [1], |row| {
            row.get::<_, Option<Vec<u8>>>(0)
        });
        let new = db.query_row(STORED_PACKET_SQL, [1], |row| {
            row.get::<_, Option<Vec<u8>>>(0)
        });
        match (old, new) {
            (Ok(Some(old)), Ok(Some(new))) => {
                assert_eq!(new, old[..old.len().min(MAX_STORED_PACKET_BYTES + 1)]);
                assert!(new.len() <= MAX_STORED_PACKET_BYTES + 1);
                if old.len() <= MAX_STORED_PACKET_BYTES {
                    assert_eq!(new, old);
                } else {
                    assert_eq!(new.len(), MAX_STORED_PACKET_BYTES + 1);
                }
            }
            (Ok(None), Ok(None)) => assert_eq!(value, SqlValue::Null),
            (Err(old), Err(new)) => same_packet_error(old.into(), new.into()),
            _ => panic!("nullable stored packet conversion changed"),
        }
        let old = db.query_row("SELECT packet FROM blocks WHERE id=?", [1], |row| {
            row.get::<_, Vec<u8>>(0)
        });
        let new = db.query_row(STORED_PACKET_SQL, [1], |row| row.get::<_, Vec<u8>>(0));
        match (old, new) {
            (Ok(old), Ok(new)) => {
                assert_eq!(new, old[..old.len().min(MAX_STORED_PACKET_BYTES + 1)]);
            }
            (Err(old), Err(new)) => same_packet_error(old.into(), new.into()),
            _ => panic!("required stored packet conversion changed"),
        }
    }
    // Only retained Rust payload bytes are measured, not SQLite cell/page memory.
}

fn packet_read_controls(node: &mut Node, packet: &Packet, clock: u64) {
    let id = packet.id().unwrap();
    let wire = packet.encode_for_settings(&node.settings).unwrap();
    assert_eq!(
        node.exact_packet_observation(packet).unwrap()["stored_exact"],
        false
    );
    assert_eq!(node.admit(packet, clock).unwrap(), id);
    let observation = node.exact_packet_observation(packet).unwrap();
    assert_eq!(observation["stored_exact"], true);
    for locator in [node.settings.genesis(), [0xa5; 32]] {
        same_packet_error(
            original_packet(node, locator).unwrap_err(),
            node.packet(locator).unwrap_err(),
        );
    }
    for value in attack_values(MAX_STORED_PACKET_BYTES) {
        node.db.execute_batch("SAVEPOINT stored_packet").unwrap();
        node.db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![value, id.as_slice()],
            )
            .unwrap();
        same_packet_error(
            original_packet(node, id).unwrap_err(),
            node.packet(id).unwrap_err(),
        );
        same_packet_error(
            original_packet_comparison(node, packet).unwrap_err(),
            node.check_admission_header_context(packet, clock, None, &mut || Ok(()))
                .unwrap_err(),
        );
        same_packet_error(
            original_packet_comparison(node, packet).unwrap_err(),
            node.exact_packet_observation(packet).unwrap_err(),
        );
        let cancelled = node
            .check_admission_header_context(packet, clock, None, &mut || {
                Err("PUBLIC_REQUEST_CANCELLED".into())
            })
            .unwrap_err();
        same_packet_error("PUBLIC_REQUEST_CANCELLED".into(), cancelled);
        node.db
            .execute_batch("ROLLBACK TO stored_packet; RELEASE stored_packet")
            .unwrap();
        assert_eq!(
            node.packet(id)
                .unwrap()
                .encode_for_settings(&node.settings)
                .unwrap(),
            wire
        );
        assert_eq!(
            node.check_admission_header_context(packet, clock, None, &mut || Ok(()))
                .unwrap(),
            Some(id)
        );
        assert_eq!(node.exact_packet_observation(packet).unwrap(), observation);
    }
    // The row record is still read before the packet, and observation still
    // reads the active record before deciding whether retained bytes are exact.
    node.db.execute_batch("SAVEPOINT packet_order").unwrap();
    node.db
        .execute(
            "UPDATE blocks SET state_root=zeroblob(31),packet=zeroblob(4194304)",
            [],
        )
        .unwrap();
    same_packet_error(
        original_packet(node, id).unwrap_err(),
        node.packet(id).unwrap_err(),
    );
    same_packet_error(
        "STORAGE_HASH".into(),
        node.exact_packet_observation(packet).unwrap_err(),
    );
    let mut foreign = packet.clone();
    foreign.header.network[0] ^= 1;
    same_packet_error(
        "NETWORK".into(),
        node.exact_packet_observation(&foreign).unwrap_err(),
    );
    same_packet_error(
        "NETWORK".into(),
        node.check_admission_header_context(&foreign, clock, None, &mut || Ok(()))
            .unwrap_err(),
    );
    node.db
        .execute_batch("ROLLBACK TO packet_order; RELEASE packet_order")
        .unwrap();
    assert_eq!(node.exact_packet_observation(packet).unwrap(), observation);
}

fn packet_codec_ceiling(
    mut wire: Vec<u8>,
    decode: impl Fn(&[u8]) -> Result<Packet>,
    length_error: &str,
    limit_error: &str,
) {
    decode(&wire).unwrap();
    // At exactly the copy ceiling the decoder must retain its later grammar
    // error, whereas one excess byte and a 4 MiB row hit the original limit.
    wire.resize(MAX_STORED_PACKET_BYTES, 0);
    same_packet_error(length_error.into(), decode(&wire).unwrap_err());
    for size in [MAX_STORED_PACKET_BYTES + 1, 4 * 1024 * 1024] {
        wire.resize(size, 0);
        same_packet_error(limit_error.into(), decode(&wire).unwrap_err());
    }
}

#[test]
fn stored_packet_reads_keep_legacy_errors_provenance_and_restoration() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(directory.path());
    let packet = node
        .make_consensus_maintenance(
            node.settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    packet_codec_ceiling(
        packet.encode().unwrap(),
        Packet::decode,
        "PACKET_LENGTH",
        "PACKET_LIMIT",
    );
    use trnm_protocol::pq_native_accounts_v2::AccountProfile;
    for profile in [
        AccountProfile::AccountsV2,
        AccountProfile::QuotaV3,
        AccountProfile::TasksV4,
        AccountProfile::TasksV5,
        AccountProfile::ApplicationV6,
    ] {
        packet_codec_ceiling(
            crate::pq_application_v6::encode_packet_for_profile(&packet, profile).unwrap(),
            |raw| crate::pq_application_v6::decode_packet_for_profile(raw, profile),
            "PQ2_PACKET_LENGTH",
            "PQ2_PACKET_LIMIT",
        );
    }
    packet_read_controls(&mut node, &packet, 100_000);
    // Cold open recovers the strongest admitted branch. Compare the same
    // active view on both sides rather than expecting recovery to leave genesis.
    node.activate_observed(packet.id().unwrap(), 100_000)
        .unwrap();
    let observation = node.exact_packet_observation(&packet).unwrap();
    drop(node);
    let reopened = open(directory.path());
    assert_eq!(
        reopened.exact_packet_observation(&packet).unwrap(),
        observation
    );
}

#[test]
fn stored_packet_reads_keep_pq_errors_provenance_and_restoration() {
    use crate::ingress::pq_network::canonical_tests::{key, setup, transfer};
    let (settings, policy) = setup();
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let packet = node
        .make_consensus_maintenance(
            settings.genesis(),
            vec![transfer(&settings)],
            key(1).public_key_id(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    packet_read_controls(&mut node, &packet, settings.genesis_time() + 20);
    // Match the active view that cold-open recovery will restore, including
    // the settings-selected PQ acceptance observation for this valid transfer.
    node.activate_observed(packet.id().unwrap(), settings.genesis_time() + 20)
        .unwrap();
    let observation = node.exact_packet_observation(&packet).unwrap();
    let wire = packet.encode_for_settings(&settings).unwrap();
    drop(node);
    let reopened = Node::open_with_pq_network(directory.path(), settings, 1, &policy).unwrap();
    // Replay the original unbounded queries as well as the production read
    // after recovery. A later observation error must not be blamed on storage
    // truncation if both readers preserve the exact valid PQ transfer bytes.
    original_packet_comparison(&reopened, &packet).unwrap();
    for retained in [
        original_packet(&reopened, packet.id().unwrap()).unwrap(),
        reopened.packet(packet.id().unwrap()).unwrap(),
    ] {
        assert_eq!(
            retained.encode_for_settings(&reopened.settings).unwrap(),
            wire
        );
    }
    assert_eq!(
        reopened.exact_packet_observation(&packet).unwrap(),
        observation
    );
}
