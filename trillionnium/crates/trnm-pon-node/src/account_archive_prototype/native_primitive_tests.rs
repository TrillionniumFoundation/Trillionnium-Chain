//! Private prior-algorithm controls for the native account primitive changes.
//! The reference is the retained 03a088f6 implementation, compiled only for tests.
//! Its timed boundary is complete account-tree verification, not Node admission.
use super::*;
use crate::account_archive_prototype::native_store::Root;
use crate::{Error, ErrorCode, ErrorKind, Settings};
use rusqlite::StatementStatus;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Instant;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

fn original_decode(id: Hash, bytes: &[u8]) -> Result<Node> {
    if bytes.len() > MAX_NODE_BYTES || id != hash(b"account-archive-node-record-v1", &[bytes]) {
        return Err(ArchiveError::CorruptRecord);
    }
    let mut r = Reader(bytes);
    let result = match r.take::<1>()?[0] {
        0 => Node::account(
            r.take()?,
            Account {
                balance: u64::from_le_bytes(r.take()?),
                nonce: u64::from_le_bytes(r.take()?),
            },
        ),
        1 => {
            let depth = u16::from_le_bytes(r.take()?) as usize;
            if depth >= 256 {
                return Err(ArchiveError::CorruptRecord);
            }
            let path = r.take()?;
            let left = r.take()?;
            let right = r.take()?;
            let left_hash = r.take()?;
            let right_hash = r.take()?;
            Node {
                id,
                path,
                depth,
                digest: branch(left_hash, right_hash),
                kind: Kind::Fork {
                    left,
                    right,
                    left_hash,
                    right_hash,
                },
            }
        }
        _ => return Err(ArchiveError::CorruptRecord),
    };
    if !r.0.is_empty() || result.id != id {
        return Err(ArchiveError::CorruptRecord);
    }
    Ok(result)
}

fn original_accounts(state: &State) -> Result<BTreeMap<Hash, Account>> {
    let mut out = BTreeMap::new();
    for (key, value) in state {
        let Some(owner) = key.strip_prefix("account:") else {
            continue;
        };
        if owner.len() != 64
            || !owner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ArchiveError::InvalidState);
        }
        let mut address = [0; 32];
        hex::decode_to_slice(owner, &mut address).map_err(|_| ArchiveError::InvalidState)?;
        let value =
            serde_json::from_value(value.clone()).map_err(|_| ArchiveError::InvalidState)?;
        if out.insert(address, value).is_some() {
            return Err(ArchiveError::InvalidState);
        }
    }
    Ok(out)
}

fn original_load(db: &Connection, id: Hash) -> Result<Node> {
    let bytes: Option<Vec<u8>> = db
        .query_row(NODE_SELECT, [id.as_slice()], |row| row.get(0))
        .optional()?;
    original_decode(id, &bytes.ok_or(ArchiveError::DataUnavailable)?)
}

fn original_save(db: &Connection, node: &Node) -> Result<()> {
    let bytes = node.encode();
    let changed = db.execute(
        "INSERT INTO archive_nodes(id,data) VALUES(?,?) ON CONFLICT(id) DO NOTHING",
        params![node.id.as_slice(), &bytes],
    )?;
    if changed == 0 {
        let existing: Vec<u8> =
            db.query_row(NODE_SELECT, [node.id.as_slice()], |row| row.get(0))?;
        if existing != bytes {
            return Err(ArchiveError::CorruptRecord);
        }
    }
    Ok(())
}

fn original_child(
    db: &Connection,
    parent: &Node,
    right_side: bool,
    empty: &[Hash; 257],
) -> Result<Node> {
    let Kind::Fork {
        left,
        right,
        left_hash,
        right_hash,
    } = parent.kind
    else {
        return Err(ArchiveError::CorruptRecord);
    };
    let out = original_load(db, if right_side { right } else { left })?;
    if out.depth <= parent.depth
        || common(&out.path, &parent.path) < parent.depth
        || bit(&out.path, parent.depth) != right_side
        || out.lift(parent.depth + 1, empty) != if right_side { right_hash } else { left_hash }
    {
        return Err(ArchiveError::CorruptRecord);
    }
    Ok(out)
}

fn local(error: ArchiveError) -> Error {
    Error::from(format!("NATIVE_ACCOUNT_STORE:{error:?}")).local_integrity()
}

fn original_verify(
    db: &Connection,
    root: &Root,
    state: &State,
    progress: &mut dyn FnMut() -> crate::Result<()>,
) -> crate::Result<()> {
    let empty = empty_hashes();
    let actual = original_accounts(state).map_err(local)?;
    let node = root
        .node
        .map(|id| original_load(db, id))
        .transpose()
        .map_err(local)?;
    crate::ensure(
        root.count <= 65_536
            && root.node.is_none() == (root.count == 0)
            && node.as_ref().map_or(empty[0], |node| node.lift(0, &empty)) == root.digest,
        "NATIVE_ACCOUNT_ROOT",
    )
    .map_err(Error::local_integrity)?;
    let mut stack = node.into_iter().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut retained = BTreeMap::new();
    let mut balance = 0u64;
    while let Some(node) = stack.pop() {
        progress()?;
        crate::ensure(
            seen.insert(node.id) && seen.len() <= 131_071,
            "NATIVE_ACCOUNT_GRAPH",
        )
        .map_err(Error::local_integrity)?;
        match node.kind {
            Kind::Leaf(owner, value) => {
                crate::ensure(
                    retained.insert(owner, value).is_none(),
                    "NATIVE_ACCOUNT_DUPLICATE",
                )
                .map_err(Error::local_integrity)?;
                balance = balance
                    .checked_add(value.balance)
                    .ok_or("NATIVE_ACCOUNT_BALANCE")?;
            }
            Kind::Fork { .. } => {
                stack.push(original_child(db, &node, true, &empty).map_err(local)?);
                stack.push(original_child(db, &node, false, &empty).map_err(local)?);
            }
        }
    }
    crate::ensure(
        retained == actual && retained.len() as u64 == root.count && balance == root.balance,
        "NATIVE_ACCOUNT_STATE",
    )
    .map_err(Error::local_integrity)
}

fn fields(node: Node) -> (Hash, Hash, usize, Hash, Vec<u8>) {
    (node.id, node.path, node.depth, node.digest, node.encode())
}

#[test]
fn native_leaf_decoder_preserves_complete_original_grammar() {
    let mut nodes = Vec::new();
    for index in 0..16u64 {
        nodes.push(Node::account(
            hash(b"native-primitive-decode-owner", &[&index.to_le_bytes()]),
            Account {
                balance: [0, 1, i64::MAX as u64 + 1, u64::MAX][index as usize % 4],
                nonce: index.wrapping_mul(0x0102_0304_0506_0708),
            },
        ));
    }
    let empty = empty_hashes();
    let (left, right) = if nodes[0].path < nodes[1].path {
        (&nodes[0], &nodes[1])
    } else {
        (&nodes[1], &nodes[0])
    };
    nodes.push(Node::fork(common(&left.path, &right.path), left, right, &empty).unwrap());
    for node in nodes {
        let bytes = node.encode();
        assert_eq!(fields(Node::decode(node.id, &bytes).unwrap()), fields(node));
        let mut corpus: Vec<Vec<u8>> = (0..bytes.len()).map(|n| bytes[..n].to_vec()).collect();
        for len in [bytes.len() + 1, 163, 164, 165] {
            if len > bytes.len() {
                let mut extra = bytes.clone();
                extra.resize(len, 0);
                corpus.push(extra);
            }
        }
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x80;
            corpus.push(changed);
        }
        for changed in corpus {
            let sealed = hash(b"account-archive-node-record-v1", &[&changed]);
            for id in [sealed, hash(b"incorrect-node-id", &[&changed])] {
                assert_eq!(
                    Node::decode(id, &changed).map(fields),
                    original_decode(id, &changed).map(fields),
                    "bytes={} id={}",
                    hex::encode(&changed),
                    hex::encode(id)
                );
            }
        }
    }
}

#[test]
fn native_borrowed_accounts_preserve_arrays_numbers_and_field_failures() {
    let mut values = vec![
        json!({"balance":0,"nonce":0}),
        json!({"balance":u64::MAX,"nonce":u64::MAX}),
        json!([u64::MAX, 1]),
        json!({"balance":0}),
        json!({"nonce":0}),
        json!({"balance":0,"nonce":0,"unknown":null}),
        json!({"a":null,"balance":false,"nonce":"wrong"}),
        json!(null),
        json!(false),
        json!("wrong"),
        json!([]),
        json!([0]),
        json!([0, 0, 0]),
        json!([null, 0]),
    ];
    for number in [
        "0",
        "-0",
        "1",
        "-1",
        "1.0",
        "1e0",
        "1e-100",
        "9223372036854775808",
        "18446744073709551615",
        "18446744073709551616",
        "1e100",
    ] {
        let number: Value = serde_json::from_str(number).unwrap();
        values.push(json!({"balance":number,"nonce":0}));
        values.push(json!({"balance":0,"nonce":number}));
        values.push(json!([number, 0]));
    }
    let valid_key = format!("account:{}", hex::encode([0xab; 32]));
    for value in values {
        for key in [
            valid_key.clone(),
            "account:".into(),
            format!("account:{}", "AB".repeat(32)),
            format!("account:{}", "g".repeat(64)),
            "ordinary:record".into(),
        ] {
            let state = State::from([(key, value.clone())]);
            assert_eq!(accounts(&state), original_accounts(&state), "{state:?}");
        }
    }
    assert_eq!(
        accounts(&State::from([(valid_key, json!([u64::MAX, 1]))]))
            .unwrap()
            .values()
            .next()
            .copied(),
        Some(Account {
            balance: u64::MAX,
            nonce: 1
        })
    );
}

fn selected_runs(db: &Connection) -> i32 {
    db.prepare_cached(NODE_SELECT)
        .unwrap()
        .get_status(StatementStatus::Run)
}

#[test]
fn native_cached_node_statements_read_actual_rows_and_trigger_effects() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let node = Node::account(
        [9; 32],
        Account {
            balance: 7,
            nonce: 3,
        },
    );
    save_node(&db, &node).unwrap();
    db.flush_prepared_statement_cache();
    for expected in 1..=4 {
        assert_eq!(
            fields(load_node(&db, node.id).unwrap()),
            fields(node.clone())
        );
        assert_eq!(selected_runs(&db), expected);
    }
    for _ in 0..2 {
        assert_eq!(save_node(&db, &node), original_save(&db, &node));
    }
    assert_eq!(selected_runs(&db), 6);
    // Existing prepared code must observe changed bytes, missing rows and DDL.
    db.execute("UPDATE archive_nodes SET data=?", [vec![0u8; 164]])
        .unwrap();
    assert_eq!(
        load_node(&db, node.id).map(fields),
        original_load(&db, node.id).map(fields)
    );
    assert_eq!(save_node(&db, &node), original_save(&db, &node));
    db.execute("DELETE FROM archive_nodes", []).unwrap();
    assert_eq!(
        load_node(&db, node.id).map(fields),
        Err(ArchiveError::DataUnavailable)
    );
    db.execute_batch("CREATE TRIGGER suppress_node BEFORE INSERT ON archive_nodes BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert_eq!(save_node(&db, &node), original_save(&db, &node));
    db.execute_batch("DROP TRIGGER suppress_node;").unwrap();
    save_node(&db, &node).unwrap();
    assert_eq!(fields(load_node(&db, node.id).unwrap()), fields(node));
}

fn native_fixture(path: &Path, recipients: usize) -> (Settings, crate::Node, Vec<Hash>) {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = crate::Node::open_with_authenticated_state(path, settings.clone(), 1).unwrap();
    let mut blocks = vec![settings.genesis()];
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    for first in (0..recipients).step_by(64) {
        let mut txs = Vec::new();
        for index in first..(first + 64).min(recipients) {
            let mut payload = crate::development_public(100 + index as u64)
                .unwrap()
                .to_vec();
            payload.extend(10u64.to_le_bytes());
            let mut tx = Envelope {
                network: settings.network(),
                sender: crate::development_public(0).unwrap(),
                nonce: index as u64 + 1,
                expiry: 2000,
                fee_limit: 1_000_000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
                .unwrap()
                .try_into()
                .unwrap();
            txs.push(tx.encode().unwrap());
        }
        let parent = *blocks.last().unwrap();
        let height = node.parent_height(parent).unwrap() + 1;
        let packet = node
            .make_consensus_maintenance(
                parent,
                txs,
                crate::development_public(7).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        let block = node.admit(&packet, 100_000).unwrap();
        node.activate(block).unwrap();
        blocks.push(block);
    }
    // Keep one independently admitted inactive branch from the original parent.
    let packet = node
        .make_consensus_maintenance(
            settings.genesis(),
            Vec::new(),
            crate::development_public(8).unwrap(),
            21,
            4096,
        )
        .unwrap();
    blocks.push(node.admit(&packet, 100_000).unwrap());
    (settings, node, blocks)
}

type Verify =
    fn(&Connection, &Root, &State, &mut dyn FnMut() -> crate::Result<()>) -> crate::Result<()>;
type Verdict = std::result::Result<(), (ErrorKind, Option<ErrorCode>, String)>;
fn verdict(result: crate::Result<()>) -> Verdict {
    result.map_err(|error| (error.kind(), error.code(), error.to_string()))
}
fn observed(
    verify: Verify,
    db: &Connection,
    root: &Root,
    state: &State,
    stop: usize,
) -> (Verdict, usize) {
    let mut visits = 0;
    let result = verify(db, root, state, &mut || {
        visits += 1;
        if visits == stop {
            Err(Error::new(ErrorCode::PublicRequestCancelled))
        } else {
            Ok(())
        }
    });
    (verdict(result), visits)
}

#[test]
fn native_complete_account_checks_keep_branch_bytes_errors_and_progress() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("native");
    let (settings, node, blocks) = native_fixture(&path, 32);
    let db = Connection::open(path.join("native.sqlite")).unwrap();
    let active = node.read_active().unwrap();
    for block in blocks {
        let state = node.state_at(block).unwrap();
        let record = crate::store::native_authenticated::load(&db, block).unwrap();
        db.flush_prepared_statement_cache();
        let current = observed(
            native_store::verify,
            &db,
            &record.accounts,
            &state,
            usize::MAX,
        );
        assert_eq!(
            current,
            observed(original_verify, &db, &record.accounts, &state, usize::MAX)
        );
        assert_eq!(current.0, Ok(()));
        // Run is SQLite's execution count for this actual reused statement.
        // It is not a prepare count, page count, lock duration or Node cost.
        assert_eq!(selected_runs(&db) as usize, current.1);
        for stop in [1, 2, 3, current.1 / 2, current.1, current.1 + 1] {
            assert_eq!(
                observed(native_store::verify, &db, &record.accounts, &state, stop),
                observed(original_verify, &db, &record.accounts, &state, stop)
            );
        }
        let mut incorrect = record.accounts.clone();
        incorrect.balance = incorrect.balance.checked_add(1).unwrap();
        assert_eq!(
            observed(native_store::verify, &db, &incorrect, &state, usize::MAX),
            observed(original_verify, &db, &incorrect, &state, usize::MAX)
        );
        // Both arms delete an as-yet-unread child from the first callback. The
        // subsequent child read must observe that change at the same fence.
        let root = original_load(&db, record.accounts.node.unwrap()).unwrap();
        if let Kind::Fork { right, .. } = root.kind {
            let mut observations = Vec::new();
            for verify in [original_verify as Verify, native_store::verify as Verify] {
                db.execute_batch("BEGIN IMMEDIATE").unwrap();
                let mut visits = 0;
                let result = verify(&db, &record.accounts, &state, &mut || {
                    visits += 1;
                    if visits == 1 {
                        db.execute("DELETE FROM archive_nodes WHERE id=?", [right.as_slice()])?;
                    }
                    Ok(())
                });
                observations.push((verdict(result), visits));
                db.execute_batch("ROLLBACK").unwrap();
            }
            assert_eq!(observations[0], observations[1]);
            assert_eq!(
                observations[0].0.as_ref().unwrap_err().0,
                ErrorKind::LocalStructure
            );
        }
    }
    assert_eq!(node.read_active().unwrap(), active);
    drop(db);
    drop(node);
    let node = crate::Node::open_with_authenticated_state(&path, settings, 1).unwrap();
    assert_eq!(node.read_active().unwrap(), active);
}

#[test]
#[ignore = "explicit release account-verification comparison; no full Node cost claim"]
fn native_complete_account_verification_cost() {
    let path = std::path::PathBuf::from(
        std::env::var("TRNM_NATIVE_ACCOUNT_VERIFY_COST_DIRECTORY")
            .expect("new output directory required"),
    );
    std::fs::create_dir(&path).unwrap();
    let mut output = std::fs::File::create_new(path.join("observations.jsonl")).unwrap();
    let write = |out: &mut std::fs::File, row: &Value| {
        serde_json::to_writer(&mut *out, row).unwrap();
        writeln!(out).unwrap();
        out.flush().unwrap();
    };
    write(
        &mut output,
        &json!({
            "schema":"pon-native-account-verification-cost-v1", "kind":"source",
            "scope":"complete required account-tree verification; excludes full State commitment, Node readiness/admission/history, lock queueing and network",
            "reference":"03a088f6 original decode/accounts/load/verify compiled only for tests",
            "source_sha256": hex::encode(Sha256::digest(include_bytes!("../account_archive_prototype.rs"))),
            "native_store_sha256":hex::encode(Sha256::digest(include_bytes!("native_store.rs"))),
            "control_sha256":hex::encode(Sha256::digest(include_bytes!("native_primitive_tests.rs"))),
            "binary_sha256":hex::encode(Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())),
            "debug_assertions":cfg!(debug_assertions), "sample_pairs":8,
            "cache":"flush prepared statement cache before each arm; OS page cache untouched",
            "retained_statement_runs_scope":"current: actual cumulative Run of reused SELECT; original: zero for a newly created diagnostic statement, not zero original SELECT executions or I/O"
        }),
    );
    if cfg!(debug_assertions) {
        panic!("measure release build only");
    }
    let node_path = path.join("native");
    let (settings, node, blocks) = native_fixture(&node_path, 256);
    let db = Connection::open(node_path.join("native.sqlite")).unwrap();
    for (case, &block) in blocks.iter().enumerate() {
        let state = node.state_at(block).unwrap();
        let record = crate::store::native_authenticated::load(&db, block).unwrap();
        std::fs::write(
            path.join(format!("state-{case}.json")),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        std::fs::write(
            path.join(format!("record-{case}.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        for pair in 0..8 {
            let mut observations = Vec::new();
            for arm in if pair % 2 == 0 { [0, 1] } else { [1, 0] } {
                let verify = if arm == 0 {
                    original_verify as Verify
                } else {
                    native_store::verify as Verify
                };
                db.flush_prepared_statement_cache();
                let start = Instant::now();
                let result = observed(verify, &db, &record.accounts, &state, usize::MAX);
                let elapsed_ns = start.elapsed().as_nanos();
                let runs = selected_runs(&db);
                write(
                    &mut output,
                    &json!({"schema":"pon-native-account-verification-cost-v1", "kind":"sample", "case":case, "block":hex::encode(block), "height":record.height, "account_count":record.accounts.count, "complete_state_keys":state.len(), "pair":pair, "arm":if arm == 0 { "original" } else { "current" }, "elapsed_ns":elapsed_ns, "result":format!("{:?}", result.0), "visited_nodes":result.1, "retained_statement_runs":runs}),
                );
                assert_eq!(result.0, Ok(()));
                if arm == 1 {
                    assert_eq!(runs as usize, result.1);
                }
                observations.push(result);
            }
            assert_eq!(observations[0], observations[1]);
        }
    }
    let active = node.read_active().unwrap();
    drop(db);
    drop(node);
    let reopened = crate::Node::open_with_authenticated_state(&node_path, settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), active);
    write(
        &mut output,
        &json!({"schema":"pon-native-account-verification-cost-v1", "kind":"terminal", "result":"PASS", "blocks_including_genesis":blocks.len(), "signed_transfers":256, "cold_reopen_equal":true, "whole_node_performance_qualified":false}),
    );
}

// Freeze the pre-optimization branch grammar independently of branch().
fn wire_branch_reference(left: Hash, right: Hash) -> Hash {
    hash(b"account-archive-branch-v1", &[&left, &right])
}

#[test]
fn native_branch_single_buffer_matches_original_wire() {
    for bit_index in 0..512usize {
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        if bit_index < 256 {
            left[bit_index / 8] = 1 << (bit_index % 8);
        } else {
            right[(bit_index - 256) / 8] = 1 << (bit_index % 8);
        }
        for (left, right) in [(left, right), (right, left)] {
            assert_eq!(branch(left, right), wire_branch_reference(left, right));
        }
    }
    for index in 0..1024u64 {
        let left = hash(b"branch-encoding-left-fixture", &[&index.to_le_bytes()]);
        let right = hash(b"branch-encoding-right-fixture", &[&index.to_le_bytes()]);
        assert_eq!(branch(left, right), wire_branch_reference(left, right));
        assert_eq!(branch(right, left), wire_branch_reference(right, left));
    }
    for left in [[0; 32], [0xff; 32], [0x80; 32]] {
        for right in [[0; 32], [0xff; 32], [0x01; 32]] {
            assert_eq!(branch(left, right), wire_branch_reference(left, right));
        }
    }
}

#[test]
fn native_branch_single_buffer_preserves_every_lift_depth() {
    let mut original_empty = [[0; 32]; 257];
    original_empty[256] = hash(b"account-archive-empty-v1", &[]);
    for depth in (0..256).rev() {
        original_empty[depth] =
            wire_branch_reference(original_empty[depth + 1], original_empty[depth + 1]);
    }
    assert_eq!(empty_hashes(), original_empty);
    for index in 0..8u64 {
        let node = Node::account(
            hash(b"branch-lift-owner-fixture", &[&index.to_le_bytes()]),
            Account {
                balance: index,
                nonce: u64::MAX - index,
            },
        );
        for depth in 0..=256 {
            let mut reference = node.digest;
            for position in (depth..node.depth).rev() {
                reference = if bit(&node.path, position) {
                    wire_branch_reference(original_empty[position + 1], reference)
                } else {
                    wire_branch_reference(reference, original_empty[position + 1])
                };
            }
            assert_eq!(node.lift(depth, &original_empty), reference);
        }
    }
}

#[test]
#[ignore = "explicit release branch hashing observation; not Node or WAN throughput"]
fn native_branch_single_buffer_cost_observation() {
    if cfg!(debug_assertions) {
        panic!("release comparison required");
    }
    let implementations: [fn(Hash, Hash) -> Hash; 2] = [wire_branch_reference, branch];
    for pair in 0..8usize {
        let mut checksums = [[0u8; 32]; 2];
        for arm in if pair % 2 == 0 { [0, 1] } else { [1, 0] } {
            let mut value = [0x5au8; 32];
            let start = Instant::now();
            for index in 0..65536u64 {
                let mut right = [0xa5u8; 32];
                right[..8].copy_from_slice(&index.to_le_bytes());
                value = std::hint::black_box(implementations[arm](
                    std::hint::black_box(value),
                    std::hint::black_box(right),
                ));
            }
            let elapsed_ns = start.elapsed().as_nanos();
            checksums[arm] = value;
            eprintln!(
                "pon_branch_encoding_cost_v1 {}",
                json!({"pair":pair,"arm":if arm == 0 {"wire-reference"} else {"single-buffer"},"branch_hashes":65536,"elapsed_ns":elapsed_ns,"checksum":hex::encode(value),"whole_node_performance_qualified":false})
            );
        }
        assert_eq!(checksums[0], checksums[1]);
    }
}
