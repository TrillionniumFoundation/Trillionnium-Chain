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
include!(env!("TRNM_SETTLEMENT_MARKER_ANCHOR"));
include!(env!("TRNM_SETTLEMENT_COMMAND_IDENTITY"));
use trnm_service_settlement::SCHEMA_VERSION_V1;
include!(env!("TRNM_SETTLEMENT_EXECUTION_VALIDATE"));
use trnm_service_settlement::ConsumptionSettlementKernelStateV1;
include!(env!("TRNM_SETTLEMENT_STATE_ROOT_SELECTED"));

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

fn command_diagnostic(raw: &[u8], kind: u16) -> ConsumptionSettlementResultV1<Vec<u8>> {
    let command: ConsumptionSettlementCommandV1 = strict_decode(raw)?;
    if command.operation_kind() != kind {
        return Err(error(ConsumptionSettlementErrorCodeV1::InvalidBounds, "outside finite command variant"));
    }
    let mut diagnostic = kind.to_le_bytes().to_vec();
    diagnostic.extend(operation_id(&command)?.0);
    diagnostic.extend(canonical_bytes(&command)?);
    Ok(diagnostic)
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
    if operation == "decode-rollup-command-fixture" {
        io::stdout().write_all(&command_diagnostic(&fs::read(&path)?, 25)?)?;
        return Ok(());
    }
    if operation == "decode-receipt-command-fixture" {
        io::stdout().write_all(&command_diagnostic(&fs::read(&path)?, 24)?)?;
        return Ok(());
    }
    if operation == "decode-settle-command-fixture" {
        io::stdout().write_all(&command_diagnostic(&fs::read(&path)?, 26)?)?;
        return Ok(());
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
    if operation == "classify-kernel-state-fixtures" {
        let source = fs::read(&path)?;
        let mut scan = source.as_slice();
        let mut diagnostic = Vec::new();
        while !scan.is_empty() {
            let (width, rest) = scan.split_at_checked(4).ok_or("missing frame length")?;
            let n = u32::from_le_bytes(width.try_into()?) as usize;
            let (raw, remainder) = rest.split_at_checked(n).ok_or("short frame")?;
            scan = remainder;
            if let Ok(parsed) = strict_decode::<ConsumptionSettlementKernelStateV1>(raw) {
                let encoded = canonical_bytes(&parsed)?;
                assert_eq!(encoded, raw);
                diagnostic.extend(u32::try_from(encoded.len() + 32)?.to_le_bytes());
                diagnostic.extend(state_root(&parsed)?.0);
                diagnostic.extend(encoded);
            } else {
                diagnostic.extend(0u32.to_le_bytes());
            }
        }
        io::stdout().write_all(&diagnostic)?;
        return Ok(());
    }
    let trust: ConsumptionSettlementFreshGenesisTrustBundleV1 = strict_decode(&fs::read(&args[3])?)?;
    let mut last_height = trust.initial_order_height;
    let mut last_block = trust.initial_order_block_id;
    let context = trust.context.clone();
    let config = ConsumptionSettlementStoreConfigV1 {path: path.clone(), store_id: word_hash(60), trust_bundle: trust};
    match operation {
        "seed" | "seed-receipts" | "seed-same-block" => {
            let owner = ConsumptionSettlementStoreV1::open(config.clone())?;
            let genesis = owner.fresh_readback()?;
            let mut binding = Vec::new();
            binding.extend(genesis.order_height().to_le_bytes());
            binding.extend(genesis.order_block_id().0);
            binding.extend(genesis.durable_state_root().0);
            binding.extend(genesis.durable_journal_root().0);
            binding.extend(config_bytes(&config)?);
            if operation == "seed-same-block" {
                assert_eq!(args.len(), 7);
            }
            for (index, file) in args[5..].iter().enumerate() {
                let height = if operation == "seed-same-block" && index == 1 {
                    last_height
                } else {
                    last_height + 1
                };
                let block = word_hash(1_000 + height);
                let execution = ConsumptionCommittedExecutionContextV1 {
                    schema_version: 1, context: context.clone(), expected_order_height: last_height,
                    expected_order_block_id: last_block, order_height: height, order_block_id: block,
                };
                if operation == "seed-receipts" && file == "-" {
                    owner.advance_empty_committed_execution_v1(&execution)?;
                } else {
                    let command: ConsumptionSettlementCommandV1 = strict_decode(&fs::read(file)?)?;
                    if operation == "seed-same-block" {
                        assert_eq!(command.operation_kind(), [24, 25][index]);
                    }
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
        "original-rollup-command-fixture" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config)?;
            owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let (raw, recorded_id): (Vec<u8>, Vec<u8>) = db.query_row(
                "SELECT command,operation_id FROM operations WHERE sequence=3", [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let diagnostic = command_diagnostic(&raw, 25)?;
            assert_eq!(diagnostic[2..34], recorded_id);
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&diagnostic)?;
        }
        "observe-actual-state-root" | "observe-kernel-state-shape" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            let observation = owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let (state, stored_root): (Vec<u8>, Vec<u8>) =
                db.query_row("SELECT state,state_root FROM metadata WHERE singleton=1", [],
                             |r| Ok((r.get(0)?, r.get(1)?)))?;
            let parsed: ConsumptionSettlementKernelStateV1 = strict_decode(&state)?;
            assert_eq!(state, canonical_bytes(&parsed)?);
            let root = state_root(&parsed)?;
            assert_eq!(observation.durable_state_root(), root);
            assert_eq!(stored_root, root.0);
            db.close().map_err(|(_, err)| err)?;
            if operation == "observe-kernel-state-shape" {
                let evidence = [
                    u8::try_from(parsed.receipts.len())?,
                    u8::try_from(parsed.receipts.iter().filter(|r| r.assigned_rollup_id.is_some()).count())?,
                    u8::from(parsed.rollup.is_some()),
                    u8::from(parsed.rollup.as_ref().is_some_and(|r| r.consumed_by_settlement_id.is_some())),
                    u8::from(parsed.settlement.is_some()),
                    u8::from(parsed.escrow.closed),
                    u8::from(parsed.escrow.last_settlement_id.is_some()),
                    u8::from(parsed.result.settlement_id.is_some()),
                    u8::try_from(parsed.accounts.len())?,
                ];
                io::stdout().write_all(&observation.order_height().to_le_bytes())?;
                io::stdout().write_all(&evidence)?;
            }
            io::stdout().write_all(&root.0)?;
            io::stdout().write_all(&state)?;
        }
        "observe-first-native-replay-witness" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            let observation = owner.fresh_readback()?;  // Original durable audit replays every operation.
            if observation.sequence() != 1 {
                return Err("witness restricted to one real transition".into());
            }
            let genesis_path = PathBuf::from(&args[4]);
            let genesis_config = ConsumptionSettlementStoreConfigV1 {
                path: genesis_path.clone(), ..config.clone()
            };
            let genesis_owner = ConsumptionSettlementStoreV1::open_existing(genesis_config)?;
            let genesis = genesis_owner.fresh_readback()?;
            assert_eq!(genesis.sequence(), 0);
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let operations: u64 = db.query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))?;
            assert_eq!(operations, 1);
            let (seq, id, execution, command, receipt, sum):
                (u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = db.query_row(
                    "SELECT sequence,operation_id,execution,command,receipt,checksum FROM operations WHERE sequence=1",
                    [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )?;
            let opid = ConsumptionOperationIdV1(array32(id, "operation id")?);
            assert_eq!(sum, operation_checksum(seq, opid, &execution, &command, &receipt).0);
            let typed_execution: ConsumptionCommittedExecutionContextV1 = strict_decode(&execution)?;
            validate_execution_static(&config.trust_bundle, &typed_execution)?;
            let typed_command: ConsumptionSettlementCommandV1 = strict_decode(&command)?;
            if typed_command.operation_kind() != 24 {
                return Err("witness restricted to original AdmitReceipt".into());
            }
            assert_eq!(operation_id(&typed_command)?, opid);
            let typed_receipt: ConsumptionTransitionReceiptV1 = strict_decode(&receipt)?;
            assert_eq!(typed_execution.expected_order_height, genesis.order_height());
            assert_eq!(typed_execution.expected_order_block_id, genesis.order_block_id());
            assert_eq!(typed_execution.order_height, observation.order_height());
            assert_eq!(typed_execution.order_block_id, observation.order_block_id());
            assert_eq!(typed_receipt.settlement_id, None);
            let preview = genesis_owner.preview_before_vote_v1(
                &genesis, typed_execution.order_height, typed_execution.order_block_id, &[typed_command],
            )?;
            assert_eq!(preview.candidate_receipts(), &[typed_receipt]);
            assert_eq!(preview.candidate_post_state_root(), observation.durable_state_root());
            assert_eq!(preview.source_state_root(), genesis.durable_state_root());
            let state: Vec<u8> = db.query_row("SELECT state FROM metadata WHERE singleton=1", [], |r| r.get(0))?;
            let parsed: ConsumptionSettlementKernelStateV1 = strict_decode(&state)?;
            assert_eq!(state_root(&parsed)?, observation.durable_state_root());
            let source_db = open_read_snapshot(&genesis_path)?;
            let before: Vec<u8> = source_db.query_row(
                "SELECT state FROM metadata WHERE singleton=1", [], |r| r.get(0),
            )?;
            let parsed: ConsumptionSettlementKernelStateV1 = strict_decode(&before)?;
            assert_eq!(state_root(&parsed)?, genesis.durable_state_root());
            source_db.close().map_err(|(_, err)| err)?;
            db.close().map_err(|(_, err)| err)?;
            let trust = canonical_bytes(&config.trust_bundle)?;
            let mut stdout = io::stdout().lock();
            for piece in [
                &trust[..], &config.store_id.0, &typed_execution.order_height.to_le_bytes(),
                &typed_execution.order_block_id.0, &opid.0, &execution, &command, &receipt,
                &genesis.durable_state_root().0, &before, &observation.durable_state_root().0, &state,
            ] {
                stdout.write_all(&u32::try_from(piece.len())?.to_le_bytes())?;
                stdout.write_all(piece)?;
            }
        }
        "fixture-empty-marker-interval-drift" => {
            let original = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            assert_eq!(original.fresh_readback()?.sequence(), 4);
            let mut db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            verify_schema(&db)?;
            let mut original_rows = load_committed_block_markers(&db, &config)?;
            assert_eq!(original_rows.len(), 7);
            assert_eq!((original_rows[4].source_operation_sequence, original_rows[4].target_operation_sequence), (3, 3));
            let replacement = Hash32V1([0x91; 32]);
            let tx = db.transaction()?;
            let mut predecessor = original_rows[2].checksum;
            for (i, marker) in original_rows.iter_mut().enumerate().skip(3) {
                match args[4].to_str() {
                    Some("prefix") => {
                        if i > 3 {
                            marker.source_operation_root = replacement;
                        }
                        if i < 6 {
                            marker.target_operation_root = replacement;
                        }
                    }
                    Some("interval") => {
                        if i > 4 {
                            marker.source_operation_sequence = 4;
                        }
                        if i == 4 || i == 5 {
                            marker.target_operation_sequence = 4;
                        }
                    }
                    _ => return Err("unknown owned empty-marker fixture".into()),
                }
                marker.previous_marker_checksum = predecessor;
                marker.checksum = committed_block_marker_checksum(&config, marker)?;
                predecessor = marker.checksum;
                assert_eq!(tx.execute(
                    "UPDATE committed_blocks SET source_operation_sequence=?1,target_operation_sequence=?2,source_operation_root=?3,target_operation_root=?4,previous_marker_checksum=?5,checksum=?6 WHERE marker_sequence=?7",
                    params![marker.source_operation_sequence, marker.target_operation_sequence,
                            marker.source_operation_root.0.to_vec(), marker.target_operation_root.0.to_vec(),
                            marker.previous_marker_checksum.0.to_vec(), marker.checksum.0.to_vec(),
                            marker.marker_sequence],
                )?, 1);
            }
            tx.commit()?;
            db.close().map_err(|(_, err)| err)?;
        }
        "fixture-trailing-empty-state-drift" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            assert_eq!(owner.fresh_readback()?.sequence(), 4);
            drop(owner);
            let mut db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            verify_schema(&db)?;
            let mut rows = load_committed_block_markers(&db, &config)?;
            assert_eq!(rows.len(), 9);
            let mut second = rows.pop().ok_or("missing second trailing marker")?;
            let mut first = rows.pop().ok_or("missing first trailing marker")?;
            for row in [&first, &second] {
                assert_eq!((row.source_operation_sequence, row.target_operation_sequence), (4, 4));
            }
            let replacement = Hash32V1([0x9d; 32]);
            assert_ne!(first.target_state_root, replacement);
            assert_eq!(first.target_state_root, second.source_state_root);
            first.target_state_root = replacement;
            second.source_state_root = replacement;
            first.checksum = committed_block_marker_checksum(&config, &first)?;
            second.previous_marker_checksum = first.checksum;
            second.checksum = committed_block_marker_checksum(&config, &second)?;
            let tx = db.transaction()?;
            for row in [&first, &second] {
                assert_eq!(tx.execute(
                    "UPDATE committed_blocks SET source_state_root=?1,target_state_root=?2,previous_marker_checksum=?3,checksum=?4 WHERE marker_sequence=?5",
                    params![row.source_state_root.0.to_vec(), row.target_state_root.0.to_vec(),
                            row.previous_marker_checksum.0.to_vec(), row.checksum.0.to_vec(), row.marker_sequence],
                )?, 1);
            }
            tx.commit()?;
            db.close().map_err(|(_, err)| err)?;
        }
        "observe-committed-interval-codec" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            let held = open_read_snapshot(&path)?;
            verify_schema(&held)?;
            let head = owner.fresh_readback()?;
            let count = head.sequence();
            assert!(count <= 8);
            let genesis = fs::read(&args[4])?;
            assert_eq!(genesis.len(), 32);
            let markers = load_committed_block_markers(&held, &config)?;
            assert!((1..=16).contains(&markers.len()));
            let mut packet = Vec::new();
            let mut words = |data: &[u8]| packet.extend(data);
            words(&count.to_le_bytes());
            words(&u64::try_from(markers.len())?.to_le_bytes());
            words(&config.trust_bundle.initial_order_height.to_le_bytes());
            words(&config.trust_bundle.initial_order_block_id.0);
            words(&head.order_height().to_le_bytes());
            words(&head.order_block_id().0);
            words(&marker_predecessor_checksum(&config)?.0);
            words(&head.durable_committed_block_root().0);
            words(&genesis);
            words(&operation_journal_root_through(&held, 0)?.0);
            let mut operations = Vec::new();
            {
                let mut stmt = held.prepare("SELECT sequence,execution,receipt FROM operations ORDER BY sequence")?;
                let mut rows = stmt.query([])?;
                let mut seen = 0u64;
                while let Some(row) = rows.next()? {
                    seen += 1;
                    let sequence: u64 = row.get(0)?;
                    assert_eq!(sequence, seen);
                    let execution: ConsumptionCommittedExecutionContextV1 =
                        strict_decode(&row.get::<_, Vec<u8>>(1)?)?;
                    let receipt: ConsumptionTransitionReceiptV1 =
                        strict_decode(&row.get::<_, Vec<u8>>(2)?)?;
                    assert_eq!(receipt.sequence, seen);
                    words(&receipt.post_state_root.0);
                    words(&operation_journal_root_through(&held, seen)?.0);
                    operations.extend(execution.expected_order_height.to_le_bytes());
                    operations.extend(execution.expected_order_block_id.0);
                    operations.extend(execution.order_height.to_le_bytes());
                    operations.extend(execution.order_block_id.0);
                    operations.extend(receipt.order_height.to_le_bytes());
                    operations.extend(receipt.order_block_id.0);
                    operations.extend(receipt.post_state_root.0);
                }
                assert_eq!(seen, count);
            }
            for row in &markers {
                words(&row.marker_sequence.to_le_bytes());
                words(&row.order_height.to_le_bytes());
                words(&row.order_block_id.0);
                words(&row.parent_order_height.to_le_bytes());
                words(&row.parent_order_block_id.0);
                words(&row.source_operation_sequence.to_le_bytes());
                words(&row.target_operation_sequence.to_le_bytes());
                words(&row.source_state_root.0);
                words(&row.target_state_root.0);
                words(&row.source_operation_root.0);
                words(&row.target_operation_root.0);
                words(&row.previous_marker_checksum.0);
                words(&row.checksum.0);
            }
            words(&operations);
            held.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&packet)?;
        }
        "observe-actual-journal-prefixes" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            let observed = owner.fresh_readback()?;
            let count = u32::try_from(observed.sequence())?;
            assert!(count <= 4);
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let mut actual = count.to_le_bytes().to_vec();
            {
                let mut stmt = db.prepare("SELECT receipt FROM operations ORDER BY sequence")?;
                let mut rows = stmt.query([])?;
                let mut seen = 0u32;
                while let Some(row) = rows.next()? {
                    let raw: Vec<u8> = row.get(0)?;
                    let receipt: ConsumptionTransitionReceiptV1 = strict_decode(&raw)?;
                    assert_eq!(receipt.sequence, u64::from(seen + 1));
                    assert!(matches!(raw.len(), 149 | 181));
                    actual.extend(u32::try_from(raw.len())?.to_le_bytes());
                    actual.extend(raw);
                    seen += 1;
                }
                assert_eq!(seen, count);
            }
            let markers = load_committed_block_markers(&db, &config)?;
            let mut roots = Vec::new();
            for seq in 0..=count {
                roots.push(operation_journal_root_through(&db, u64::from(seq))?);
            }
            assert_eq!(roots.last(), Some(&observed.durable_journal_root()));
            let mut proof = Vec::new();
            for m in &markers {
                assert_eq!(roots[usize::try_from(m.source_operation_sequence)?], m.source_operation_root);
                assert_eq!(roots[usize::try_from(m.target_operation_sequence)?], m.target_operation_root);
                proof.extend(m.source_operation_sequence.to_le_bytes());
                proof.extend(m.target_operation_sequence.to_le_bytes());
                proof.extend(m.source_operation_root.0);
                proof.extend(m.target_operation_root.0);
            }
            db.close().map_err(|(_, err)| err)?;
            let all_roots: Vec<u8> = roots.into_iter().flat_map(|r| r.0).collect();
            let mut stdout = io::stdout().lock();
            for piece in [&actual, &all_roots, &proof] {
                stdout.write_all(&u32::try_from(piece.len())?.to_le_bytes())?;
                stdout.write_all(piece)?;
            }
        }
        "observe-settled-state-id" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            let observation = owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let state: Vec<u8> = db.query_row("SELECT state FROM metadata WHERE singleton=1", [], |r| r.get(0))?;
            let typed: ConsumptionSettlementKernelStateV1 = strict_decode(&state)?;
            let root = state_root(&typed)?;
            assert_eq!(observation.durable_state_root(), root);
            let setting = typed.settlement.as_ref().map(|value| value.settlement_id);
            assert_eq!(typed.escrow.last_settlement_id, setting);
            assert_eq!(typed.result.settlement_id, setting);
            assert_eq!(typed.rollup.as_ref().and_then(|row| row.consumed_by_settlement_id), setting);
            let mut proof = [0u8; 33];
            if let Some(id) = setting {
                proof[0] = 1;
                proof[1..].copy_from_slice(&id.0);
            }
            let mut framed = Vec::new();
            let mut frame = |piece: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
                framed.extend(u32::try_from(piece.len())?.to_le_bytes());
                framed.extend(piece);
                Ok(())
            };
            frame(&proof)?;
            frame(&root.0)?;
            frame(&state)?;
            let mut statement = db.prepare("SELECT sequence,operation_id,execution,command,receipt,checksum FROM operations ORDER BY sequence")?;
            let mut rows = statement.query([])?;
            let mut count = 0u64;
            while let Some(row) = rows.next()? {
                count += 1;
                let seq: u64 = row.get(0)?;
                assert_eq!(seq, count);
                let id = ConsumptionOperationIdV1(array32(row.get(1)?, "operation id")?);
                let execution: Vec<u8> = row.get(2)?;
                let command: Vec<u8> = row.get(3)?;
                let receipt: Vec<u8> = row.get(4)?;
                let sum: Vec<u8> = row.get(5)?;
                assert_eq!(operation_checksum(seq, id, &execution, &command, &receipt).0.as_slice(), sum);
                let parsed_execution: ConsumptionCommittedExecutionContextV1 = strict_decode(&execution)?;
                validate_execution_static(&config.trust_bundle, &parsed_execution)?;
                let parsed_command: ConsumptionSettlementCommandV1 = strict_decode(&command)?;
                let parsed_receipt: ConsumptionTransitionReceiptV1 = strict_decode(&receipt)?;
                assert_eq!(id, operation_id(&parsed_command)?);
                assert_eq!(parsed_receipt.operation_id, id);
                assert_eq!(parsed_receipt.order_height, parsed_execution.order_height);
                assert_eq!(parsed_receipt.settlement_id, if parsed_command.operation_kind() == 26 { setting } else { None });
                frame(&execution)?;
                frame(&command)?;
                frame(&receipt)?;
            }
            assert_eq!(count, observation.sequence());
            drop(rows);
            drop(statement);
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&framed)?;
        }
        "fixture-noncanonical-state" => {
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            verify_schema(&db)?;
            let (conf, seq, height, block, state, root, journal, fenced, old_sum):
                (Vec<u8>, u64, u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool, Vec<u8>) =
                db.query_row("SELECT config,sequence,height,block_id,state,state_root,journal_root,fenced,checksum FROM metadata WHERE singleton=1", [],
                             |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))?;
            let block = Hash32V1(array32(block, "block")?);
            let root = Hash32V1(array32(root, "state root")?);
            let journal = Hash32V1(array32(journal, "journal root")?);
            let original: ConsumptionSettlementKernelStateV1 = strict_decode(&state)?;
            let domain = "trnm.portable.v2.consumption-settlement-state-root.candidate.v1";
            assert_eq!(state_root(&original)?, root);
            assert_eq!(codec::digest_encoded(domain, &state)?, root);
            assert_eq!(metadata_checksum(&conf, seq, height, block, &state, root, journal, fenced).0.as_slice(), old_sum);
            let mut changed = state;
            match args[4].to_str() {
                Some("tail") => changed.push(0),
                Some("option") => {
                    assert!(original.receipts.is_empty() && original.rollup.is_none() && changed[4] == 0);
                    changed[4] = 2;
                }
                _ => return Err("unknown test-owned state variant".into()),
            };
            assert!(strict_decode::<ConsumptionSettlementKernelStateV1>(&changed).is_err());
            let raw_root = codec::digest_encoded(domain, &changed)?;
            assert_ne!(raw_root, root);
            let row_sum = metadata_checksum(&conf, seq, height, block, &changed, raw_root, journal, fenced);
            assert_eq!(db.execute("UPDATE metadata SET state=?1,state_root=?2,checksum=?3 WHERE singleton=1",
                                  params![changed, raw_root.0.to_vec(), row_sum.0.to_vec()])?, 1);
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&raw_root.0)?;
            io::stdout().write_all(&row_sum.0)?;
        }
        "fixture-state-root-drift" => {
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            verify_schema(&db)?;
            let (conf, seq, height, block, state, root, journal, fenced, old_sum):
                (Vec<u8>, u64, u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool, Vec<u8>) =
                db.query_row("SELECT config,sequence,height,block_id,state,state_root,journal_root,fenced,checksum FROM metadata WHERE singleton=1", [],
                             |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))?;
            let block = Hash32V1(array32(block, "block")?);
            let root = Hash32V1(array32(root, "state root")?);
            let journal = Hash32V1(array32(journal, "journal root")?);
            let mut parsed: ConsumptionSettlementKernelStateV1 = strict_decode(&state)?;
            assert_eq!(state_root(&parsed)?, root);
            assert_eq!(metadata_checksum(&conf, seq, height, block, &state, root, journal, fenced).0.as_slice(), old_sum);
            // Owned disposable fixture only: retain canonical typed Borsh and
            // the original field widths, but keep the old separately stored root.
            parsed.escrow.version ^= 1;
            let changed = canonical_bytes(&parsed)?;
            let changed_root = state_root(&parsed)?;
            assert_ne!(changed_root, root);
            let new_sum = metadata_checksum(&conf, seq, height, block, &changed, root, journal, fenced);
            assert_eq!(db.execute("UPDATE metadata SET state=?1,checksum=?2 WHERE singleton=1",
                                  params![changed, new_sum.0.to_vec()])?, 1);
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&root.0)?;
            io::stdout().write_all(&changed_root.0)?;
            io::stdout().write_all(&changed)?;
        }
        "original-execution-fixtures" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config.clone())?;
            owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let mut diag = Vec::new();
            let bound = canonical_bytes(&config.trust_bundle.context)?;
            diag.extend(u32::try_from(bound.len())?.to_le_bytes());
            diag.extend(bound);
            let mut statement = db.prepare("SELECT execution FROM operations ORDER BY sequence")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let raw: Vec<u8> = row.get(0)?;
                let parsed: ConsumptionCommittedExecutionContextV1 = strict_decode(&raw)?;
                validate_execution_static(&config.trust_bundle, &parsed)?;
                let canonical = canonical_bytes(&parsed)?;
                assert_eq!(raw, canonical);
                diag.extend(u32::try_from(canonical.len())?.to_le_bytes());
                diag.extend(canonical);
            }
            drop(rows);
            drop(statement);
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&diag)?;
        }
        "classify-execution-fixtures" => {
            let source = fs::read(&args[4])?;
            let mut scan = source.as_slice();
            let mut diag = Vec::new();
            while !scan.is_empty() {
                let span = u32::from_le_bytes(scan[..4].try_into()?) as usize;
                let frame = &scan[4..4 + span];
                scan = &scan[4 + span..];
                let mut result = 100u8;
                if let Some(width) = frame.get(..4) {
                    let n = u32::from_le_bytes(width.try_into()?) as usize;
                    if let Some((expected, raw)) = frame[4..].split_at_checked(n) {
                        if let (Ok(ctx), Ok(ex)) = (
                            strict_decode::<trnm_service_settlement::ProtocolContextV1>(expected),
                            strict_decode::<ConsumptionCommittedExecutionContextV1>(raw),
                        ) {
                            let canonical = canonical_bytes(&ex)?;
                            assert_eq!(canonical, raw);
                            let mut trusted = config.trust_bundle.clone();
                            trusted.context = ctx;
                            result = match validate_execution_static(&trusted, &ex) {
                                Ok(()) => 0,
                                Err(err) => match err.code() {
                                    ConsumptionSettlementErrorCodeV1::InvalidContext => 101,
                                    ConsumptionSettlementErrorCodeV1::StaleVersion => 103,
                                    _ => panic!("Unexpected original execution code: {err}"),
                                },
                            };
                        }
                    }
                }
                diag.push(result);
            }
            io::stdout().write_all(&diag)?;
        }
        "original-receipt-command-fixtures" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config)?;
            owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let mut witness = Vec::new();
            for seq in [1, 2] {
                let (raw, recorded_id): (Vec<u8>, Vec<u8>) = db.query_row(
                    "SELECT command,operation_id FROM operations WHERE sequence=?1", [seq],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let diagnostic = command_diagnostic(&raw, 24)?;
                assert_eq!(diagnostic[2..34], recorded_id);
                witness.extend(u16::try_from(diagnostic.len())?.to_le_bytes());
                witness.extend(diagnostic);
            }
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&witness)?;
        }
        "original-settle-command-fixture" => {
            let owner = ConsumptionSettlementStoreV1::open_existing(config)?;
            owner.fresh_readback()?;
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let (raw, recorded_id): (Vec<u8>, Vec<u8>) = db.query_row(
                "SELECT command,operation_id FROM operations WHERE sequence=4", [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let diagnostic = command_diagnostic(&raw, 26)?;
            assert_eq!(diagnostic[2..34], recorded_id);
            db.close().map_err(|(_, err)| err)?;
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
        "fixture-execution-context-drift" => {
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            verify_schema(&db)?;
            let (seq, id, execution, command, receipt): (u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
                db.query_row("SELECT sequence,operation_id,execution,command,receipt FROM operations WHERE sequence=4", [],
                             |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
            let id = ConsumptionOperationIdV1(id.try_into().expect("exact original physical ID"));
            let mut frame: ConsumptionCommittedExecutionContextV1 = strict_decode(&execution)?;
            validate_execution_static(&config.trust_bundle, &frame)?;
            let mode = args[4].to_str().ok_or("fixture mutation label")?;
            match mode {
                "schema" => frame.schema_version = 2,
                "old-height" => frame.expected_order_height = frame.order_height.checked_add(1).ok_or("height bound")?,
                "coordinate" => {
                    assert!(frame.order_height > frame.expected_order_height);
                    frame.order_block_id.0[0] ^= 1;
                    validate_execution_static(&config.trust_bundle, &frame)?;
                }
                "context" => frame.context.genesis_hash.0[0] ^= 1,
                "trailing" => (),
                _ => panic!("unrecognized disposable execution mutation"),
            }
            let mut changed = canonical_bytes(&frame)?;
            if mode == "trailing" {
                changed.push(0);
            }
            let sum = operation_checksum(seq, id, &changed, &command, &receipt);
            let original = operation_checksum(seq, id, &execution, &command, &receipt);
            assert_ne!(sum, original);
            assert_eq!(db.execute("UPDATE operations SET execution=?1,checksum=?2 WHERE sequence=?3",
                                  params![changed, sum.0.to_vec(), seq])?, 1);
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&sum.0)?;
        }
        "inspect-operation-checksums" | "fixture-row-checksum-drift" => {
            let drift = operation == "fixture-row-checksum-drift";
            let db = if drift {
                Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?
            } else {
                open_read_snapshot(&path)?
            };
            verify_schema(&db)?;
            let mut statement = db.prepare("SELECT sequence,operation_id,execution,command,receipt,checksum FROM operations ORDER BY sequence")?;
            let mut rows = statement.query([])?;
            let mut projection = Vec::new();
            let mut control = None;
            while let Some(row) = rows.next()? {
                let sequence: u64 = row.get(0)?;
                let id = ConsumptionOperationIdV1(row.get::<_, Vec<u8>>(1)?.try_into().expect("fixture ID width"));
                let mut context: Vec<u8> = row.get(2)?;
                let command: Vec<u8> = row.get(3)?;
                let receipt: Vec<u8> = row.get(4)?;
                let mut checksum: Vec<u8> = row.get(5)?;
                let original = operation_checksum(sequence, id, &context, &command, &receipt);
                assert_eq!(original.0.as_slice(), checksum);
                projection.extend(u64::try_from(context.len())?.to_le_bytes());
                projection.extend(original.0);
                if drift && sequence == 4 {
                    match args[4].to_str().unwrap() {
                        "checksum" => checksum[0] ^= 1,
                        "checksum-width" => { checksum.pop(); }
                        "raw-execution" => *context.last_mut().ok_or("empty fixture execution")? ^= 1,
                        "oversized-execution" => context.resize(65537, 0),
                        _ => panic!("unrecognized disposable row mutation"),
                    }
                    let changed = operation_checksum(sequence, id, &context, &command, &receipt);
                    assert_ne!(changed.0.as_slice(), checksum);
                    control = Some((sequence, context, checksum));
                }
            }
            drop(rows);
            drop(statement);
            if drift {
                let (sequence, context, checksum) = control.ok_or("missing original row")?;
                assert_eq!(db.execute(
                    "UPDATE operations SET execution=?1,checksum=?2 WHERE sequence=?3",
                    params![context, checksum, sequence],
                )?, 1);
            }
            db.close().map_err(|(_, err)| err)?;
            io::stdout().write_all(&projection)?;
        }
        "fixture-command-identity-drift" => {
            // Only the test-created Store is touched. Keeps the independently
            // stored receipt/marker roots and recomputes the exact row checksum.
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let control = args[4].to_str().unwrap();
            let seq = if control == "nested-option" { 3_u64 } else { 4 };
            let (id, execution, mut command, receipt): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
                db.query_row("SELECT operation_id,execution,command,receipt FROM operations WHERE sequence=?1",
                             [seq], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            let id = ConsumptionOperationIdV1(id.try_into().expect("fixture operation ID"));
            let valid: ConsumptionSettlementCommandV1 = strict_decode(&command)?;
            assert_eq!(id, operation_id(&valid)?);
            match control {
                "changed-id" => {
                    // A fixed-width field remains Borsh canonical but changes the operation ID.
                    *command.last_mut().ok_or("missing settlement policy hash")? ^= 1;
                    let different: ConsumptionSettlementCommandV1 = strict_decode(&command)?;
                    assert_ne!(id, operation_id(&different)?);
                }
                "trailing" => command.push(0),
                "oversized" => command.resize(65537, 0),
                "nested-option" => {
                    // Mutate a structurally typed nested Receipt option, using
                    // lengths proven independently by the exact frozen fixture.
                    assert_eq!((valid.operation_kind(), command.len()), (25, 2689));
                    assert_eq!(command[923 + 361 - 1], 0);
                    command[923 + 361 - 1] = 2;
                }
                _ => panic!("unrecognized disposable command drift"),
            }
            if control != "changed-id" {
                assert!(strict_decode::<ConsumptionSettlementCommandV1>(&command).is_err());
            }
            let sum = operation_checksum(seq, id, &execution, &command, &receipt);
            assert_eq!(db.execute("UPDATE operations SET command=?1,checksum=?2 WHERE sequence=?3",
                                  params![command, sum.0.to_vec(), seq])?, 1);
            db.close().map_err(|(_, err)| err)?;
        }
        "fixture-rebind-mutated-receipt" => {
            // Owned disposable fixture only. Make the untyped journal-root
            // commitments internally consistent with changed receipt bytes.
            let mut db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let markers = load_committed_block_markers(&db, &config)?;
            let tx = db.transaction()?;
            let (seq, id, context, command, mut raw) = tx.query_row(
                "SELECT sequence,operation_id,execution,command,receipt FROM operations WHERE sequence=4", [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?,
                          row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?)),
            )?;
            let id = ConsumptionOperationIdV1(id.try_into().expect("exact fixture ID"));
            let decoded: ConsumptionTransitionReceiptV1 = strict_decode(&raw)?;
            assert!(decoded.settlement_id.is_some());
            match args[4].to_str().unwrap() {
                "trailing" => raw.push(0),
                "id" => raw[42] ^= 1,
                "sequence" => raw[34] ^= 1,
                "kind" => raw[74] ^= 1,
                _ => panic!("unknown disposable receipt mutation"),
            }
            let sum = operation_checksum(seq, id, &context, &command, &raw);
            assert_eq!(tx.execute(
                "UPDATE operations SET receipt=?1,checksum=?2 WHERE sequence=?3",
                params![raw, sum.0.to_vec(), seq],
            )?, 1);
            let mut previous = markers.first().ok_or("empty marker fixture")?.previous_marker_checksum;
            for mut marker in markers {
                marker.source_operation_root = operation_journal_root_through(&tx, marker.source_operation_sequence)?;
                marker.target_operation_root = operation_journal_root_through(&tx, marker.target_operation_sequence)?;
                marker.previous_marker_checksum = previous;
                marker.checksum = committed_block_marker_checksum(&config, &marker)?;
                previous = marker.checksum;
                assert_eq!(tx.execute(
                    "UPDATE committed_blocks SET source_operation_root=?1,target_operation_root=?2,previous_marker_checksum=?3,checksum=?4 WHERE marker_sequence=?5",
                    params![marker.source_operation_root.0.to_vec(), marker.target_operation_root.0.to_vec(),
                            marker.previous_marker_checksum.0.to_vec(), marker.checksum.0.to_vec(), marker.marker_sequence],
                )?, 1);
            }
            let (sequence, height, block, state, root, fenced) = tx.query_row(
                "SELECT sequence,height,block_id,state,state_root,fenced FROM metadata WHERE singleton=1", [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?, row.get::<_, Vec<u8>>(2)?,
                          row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, bool>(5)?)),
            )?;
            let journal = operation_journal_root_through(&tx, sequence)?;
            let sum = metadata_checksum(
                &config_bytes(&config)?, sequence, height, Hash32V1(block.try_into().expect("fixture block ID")),
                &state, Hash32V1(root.try_into().expect("fixture state root")), journal, fenced,
            );
            assert_eq!(tx.execute("UPDATE metadata SET journal_root=?1,checksum=?2 WHERE singleton=1",
                                  params![journal.0.to_vec(), sum.0.to_vec()])?, 1);
            load_committed_block_markers(&tx, &config)?;
            tx.commit()?;
            io::stdout().write_all(&journal.0)?;
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
