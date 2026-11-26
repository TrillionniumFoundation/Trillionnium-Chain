#![allow(dead_code)]
#![forbid(unsafe_code)]

use rusqlite::{Connection, ErrorCode, OpenFlags, params};
use std::{env, fs, ffi::OsString, io::{self, Read, Write}, path::{Path, PathBuf}, time::Duration};
use trnm_service_settlement::{
    ConsumptionCommittedExecutionContextV1, ConsumptionOperationIdV1, ConsumptionSettlementCommandV1,
    ConsumptionSettlementFreshGenesisTrustBundleV1, ConsumptionSettlementStoreConfigV1,
    ConsumptionSettlementStoreV1, ConsumptionTransitionReceiptV1, Hash32V1,
};
mod error { include!(env!("TRNM_SETTLEMENT_SCHEMA_ERROR")); }
mod codec { include!(env!("TRNM_SETTLEMENT_OPERATION_CODEC")); }
use codec::{canonical_bytes, checksum, digest_value, strict_decode};
use error::{ConsumptionSettlementErrorCodeV1, ConsumptionSettlementResultV1, error};
include!(env!("TRNM_SETTLEMENT_SCHEMA_SOURCE"));
include!(env!("TRNM_SETTLEMENT_MARKERS_SELECTED"));

fn word_hash(value: u64) -> Hash32V1 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    Hash32V1(bytes)
}

fn receipt_identity(receipt: &ConsumptionTransitionReceiptV1) -> [u8; 42] {
    let mut identity = [0; 42];
    identity[..8].copy_from_slice(&receipt.sequence.to_le_bytes());
    identity[8..40].copy_from_slice(&receipt.operation_id.0);
    identity[40..].copy_from_slice(&receipt.operation_kind.to_le_bytes());
    identity
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().collect::<Vec<_>>();
    let path = PathBuf::from(&args[2]);
    let operation = args[1].to_str().unwrap();
    if operation == "try-write" {
        assert_eq!(args.len(), 3);
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        db.busy_timeout(Duration::ZERO)?;
        db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE pending_test_write(x INTEGER)")?;
        return match db.execute_batch("COMMIT") {
            Err(rusqlite::Error::SqliteFailure(code, _)) if code.code == ErrorCode::DatabaseBusy => {
                db.execute_batch("ROLLBACK")?;
                println!("BUSY");
                Ok(())
            }
            result => panic!("unexpected SQLite write-transaction result: {result:?}"),
        };
    }
    if operation == "decode-receipt-fixture" {
        let framed = fs::read(&path)?;
        let (identity, raw) = framed.split_at_checked(42).ok_or("missing fixture identity")?;
        let parsed: ConsumptionTransitionReceiptV1 = strict_decode(raw)?;
        let actual = receipt_identity(&parsed);
        if actual != identity {
            return Err("fixture receipt identity differs".into());
        }
        io::stdout().write_all(&canonical_bytes(&parsed)?)?;
        return Ok(());
    }
    let trust: ConsumptionSettlementFreshGenesisTrustBundleV1 = strict_decode(&fs::read(&args[3])?)?;
    let mut last_height = trust.initial_order_height;
    let mut last_block = trust.initial_order_block_id;
    let context = trust.context.clone();
    let config = ConsumptionSettlementStoreConfigV1 {path: path.clone(), store_id: word_hash(60), trust_bundle: trust};
    match operation {
        "seed" | "seed-receipts" => {
            let owner = ConsumptionSettlementStoreV1::open(config.clone())?;
            let genesis = owner.fresh_readback()?;
            let mut binding = Vec::new();
            binding.extend(genesis.order_height().to_le_bytes());
            binding.extend(genesis.order_block_id().0);
            binding.extend(genesis.durable_state_root().0);
            binding.extend(genesis.durable_journal_root().0);
            binding.extend(config_bytes(&config)?);
            for file in &args[5..] {
                let height = last_height + 1;
                let block = word_hash(1_000 + height);
                let execution = ConsumptionCommittedExecutionContextV1 {
                    schema_version: 1, context: context.clone(), expected_order_height: last_height,
                    expected_order_block_id: last_block, order_height: height, order_block_id: block,
                };
                if operation == "seed-receipts" && file == "-" {
                    owner.advance_empty_committed_execution_v1(&execution)?;
                } else {
                    let command: ConsumptionSettlementCommandV1 = strict_decode(&fs::read(file)?)?;
                    assert!(!owner.execute_committed_execution(&execution, &command)?.replay);
                }
                (last_height, last_block) = (height, block);
            }
            for _ in 0..args[4].to_str().unwrap().parse::<usize>()? {
                let height = last_height + 1;
                let block = word_hash(1_000 + height);
                let execution = ConsumptionCommittedExecutionContextV1 {
                    schema_version: 1, context: context.clone(), expected_order_height: last_height,
                    expected_order_block_id: last_block, order_height: height, order_block_id: block,
                };
                owner.advance_empty_committed_execution_v1(&execution)?;
                (last_height, last_block) = (height, block);
            }
            io::stdout().write_all(&binding)?;
        }
        "verify" | "verify-join" | "verify-journal" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            let head = owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            let markers = load_committed_block_markers(&db, &config)?;
            let tail = markers.last().expect("original marker journal cannot be empty");
            assert_eq!(tail.checksum, head.durable_committed_block_root());
            let count = u64::try_from(markers.len())?;
            let mut diagnostic = Vec::new();
            diagnostic.extend(count.to_le_bytes());
            diagnostic.extend(tail.checksum.0);
            if operation != "verify" {
                let sum: Vec<u8> = db.query_row(
                    "SELECT checksum FROM metadata WHERE singleton=1", [], |row| row.get(0),
                )?;
                assert_eq!(sum.len(), 32);
                diagnostic.extend(head.store_schema_version().to_le_bytes());
                diagnostic.extend(head.sequence().to_le_bytes());
                diagnostic.extend(head.order_height().to_le_bytes());
                diagnostic.extend(head.order_block_id().0);
                diagnostic.extend(head.durable_state_root().0);
                diagnostic.extend(head.durable_journal_root().0);
                diagnostic.extend([0]); // Original public readback rejects a fenced store.
                diagnostic.extend(sum);
            }
            if operation == "verify-journal" {
                let bound = head.durable_journal_root();
                let raw = operation_journal_root_through(&db, u64::MAX)?;
                assert_eq!(raw, bound);
                diagnostic.extend(raw.0);
            }
            drop(db);
            io::stdout().write_all(&diagnostic)?;
        }
        "original-receipt-fixtures" => {
            // Retained owner audits actual committed operations before exporting
            // original typed Borsh data from a separate read-only fixture snapshot.
            let owner = ConsumptionSettlementStoreV1::open_existing(config)?;
            owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let mut stmt = db.prepare("SELECT sequence,operation_id,command,receipt FROM operations ORDER BY sequence")?;
            let mut rows = stmt.query([])?;
            let mut diagnostic = Vec::new();
            while let Some(row) = rows.next()? {
                let sequence: i64 = row.get(0)?;
                let id: Vec<u8> = row.get(1)?;
                let command: ConsumptionSettlementCommandV1 = strict_decode(&row.get::<_, Vec<u8>>(2)?)?;
                let raw: Vec<u8> = row.get(3)?;
                let receipt: ConsumptionTransitionReceiptV1 = strict_decode(&raw)?;
                let mut expected = u64::try_from(sequence)?.to_le_bytes().to_vec();
                assert_eq!(id.len(), 32);
                expected.extend(id);
                expected.extend(command.operation_kind().to_le_bytes());
                assert_eq!(receipt_identity(&receipt).as_slice(), expected);
                let canonical = canonical_bytes(&receipt)?;
                assert_eq!(canonical, raw);
                diagnostic.extend(u16::try_from(canonical.len())?.to_le_bytes());
                diagnostic.extend(expected);
                diagnostic.extend(canonical);
            }
            drop(rows);
            drop(stmt);
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&diagnostic)?;
        }
        "inspect-journal-root" => {
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            io::stdout().write_all(&operation_journal_root_through(&db, u64::MAX)?.0)?;
        }
        "fixture-same-count-receipt-drift" => {
            // Disposable fixture: reuse another genuine receipt and update
            // the exact original row checksum. The original Borsh/replay
            // identity and the committed journal root still must reject it.
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let first: Vec<u8> = db.query_row(
                "SELECT receipt FROM operations WHERE sequence=1", [], |row| row.get(0),
            )?;
            let (id, execution, command, second) = db.query_row(
                "SELECT operation_id,execution,command,receipt FROM operations WHERE sequence=2",
                [], |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,Vec<u8>>(1)?,
                              row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?)),
            )?;
            assert_ne!(first, second);
            let identity = ConsumptionOperationIdV1(id.try_into().expect("exact fixture ID"));
            let sum = operation_checksum(2, identity, &execution, &command, &first);
            assert_eq!(db.execute(
                "UPDATE operations SET receipt=?1, checksum=?2 WHERE sequence=2",
                params![first, sum.0.to_vec()],
            )?, 1);
            let (stored, checksum): (Vec<u8>,Vec<u8>) = db.query_row(
                "SELECT receipt,checksum FROM operations WHERE sequence=2", [],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )?;
            assert_eq!(checksum, operation_checksum(2, identity, &execution, &command, &stored).0);
            let count: u64 = db.query_row("SELECT count(*) FROM operations", [], |row| row.get(0))?;
            assert_eq!(count, 2);
        }
        "fixture-metadata-height-drift" => {
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let (seq, height, block, state, root, journal, fenced) = db.query_row(
                "SELECT sequence,height,block_id,state,state_root,journal_root,fenced FROM metadata WHERE singleton=1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?,
                         row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                         row.get::<_, bool>(6)?)),
            )?;
            let next_height = u64::try_from(height)?.checked_add(1).expect("bounded owned fixture");
            let sum = metadata_checksum(
                &config_bytes(&config)?, u64::try_from(seq)?, next_height,
                Hash32V1(block.try_into().expect("32-byte fixture ID")), &state,
                Hash32V1(root.try_into().expect("32-byte fixture state root")),
                Hash32V1(journal.try_into().expect("32-byte fixture journal root")), fenced,
            );
            assert_eq!(db.execute(
                "UPDATE metadata SET height=?1, checksum=?2 WHERE singleton=1",
                params![i64::try_from(next_height)?, sum.0.to_vec()],
            )?, 1);
        }
        "fixture-parent-height-drift" => {
            // On the disposable original test database only: establish that
            // linkage is checked separately from the exact original checksum.
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let markers = load_committed_block_markers(&db, &config)?;
            let mut mark = markers.into_iter().last().expect("nonempty original fixture");
            assert_eq!(mark.marker_sequence, 2);
            mark.parent_order_height += 1;
            let digest = committed_block_marker_checksum(&config, &mark)?;
            assert_eq!(db.execute(
                "UPDATE committed_blocks SET parent_order_height=?1,checksum=?2 WHERE marker_sequence=2",
                params![i64::try_from(mark.parent_order_height)?, digest.0.to_vec()],
            )?, 1);
            // Prove native/Rust observations should fail on linkage, not checksum.
            assert_eq!(load_committed_block_markers(&db, &config)?.len(), 3);
        }
        _ => panic!("unrecognized marker fixture"),
    }
    Ok(())
}
