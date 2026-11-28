#![allow(dead_code)]
#![forbid(unsafe_code)]
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension};
use std::{env, fs, ffi::OsString, io::{self, Read, Write}, path::{Path, PathBuf}, time::Duration};
use trnm_service_settlement::{
    ConsumptionCommittedExecutionContextV1, ConsumptionOperationIdV1, ConsumptionSettlementCommandV1,
    ConsumptionSettlementFreshGenesisTrustBundleV1, ConsumptionSettlementStoreConfigV1,
    ConsumptionSettlementStoreV1, ConsumptionTransitionReceiptV1, Hash32V1,
};
mod error { include!(env!("TRNM_SETTLEMENT_SCHEMA_ERROR")); }
mod codec { include!(env!("TRNM_SETTLEMENT_OPERATION_CODEC")); }
use codec::{checksum, digest_value, strict_decode};
use error::{ConsumptionSettlementErrorCodeV1, ConsumptionSettlementResultV1, error};
include!(env!("TRNM_SETTLEMENT_SCHEMA_SOURCE"));
include!(env!("TRNM_SETTLEMENT_OPERATION_SELECTED"));
fn word_hash(value: u64) -> Hash32V1 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    Hash32V1(bytes)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().collect::<Vec<_>>();
    let path = PathBuf::from(&args[2]);
    match args[1].to_str().unwrap() {
        "seed" => {
            assert_eq!(args.len(), 6);
            let trust: ConsumptionSettlementFreshGenesisTrustBundleV1 = strict_decode(&fs::read(&args[3])?)?;
            let mut previous_height = trust.initial_order_height;
            let mut previous_block = trust.initial_order_block_id;
            let context = trust.context.clone();
            let store = ConsumptionSettlementStoreV1::open(ConsumptionSettlementStoreConfigV1 {
                path, store_id: word_hash(60), trust_bundle: trust,
            })?;
            let mut output = io::stdout().lock();
            for path in &args[4..] {
                let command: ConsumptionSettlementCommandV1 = strict_decode(&fs::read(path)?)?;
                let height = previous_height + 1;
                let block = word_hash(1000 + height);
                let execution = ConsumptionCommittedExecutionContextV1 {
                    schema_version: 1, context: context.clone(), expected_order_height: previous_height,
                    expected_order_block_id: previous_block, order_height: height, order_block_id: block,
                };
                let outcome = store.execute_committed_execution(&execution, &command)?;
                assert!(!outcome.replay);
                output.write_all(&outcome.receipt().operation_id.0)?;
                (previous_height, previous_block) = (height, block);
            }
        }
        "lookup" => {
            assert_eq!(args.len(), 4);
            let op_id: [u8; 32] = fs::read(&args[3])?.try_into().expect("original OperationId width");
            let db = open_read_snapshot(&path)?;
            verify_schema(&db)?;
            let observed = load_operation(&db, ConsumptionOperationIdV1(op_id))?;
            let mut diagnostic = Vec::new();
            match observed {
                Some((_, _, receipt)) => {
                    let sum: Vec<u8> = db.query_row(
                        "SELECT checksum FROM operations WHERE operation_id=?1",
                        [op_id.to_vec()], |row| row.get(0),
                    )?;
                    assert_eq!(sum.len(), 32);
                    diagnostic.extend(1_u64.to_le_bytes());
                    diagnostic.extend(receipt.sequence.to_le_bytes());
                    diagnostic.extend(receipt.operation_id.0);
                    diagnostic.extend(sum);
                }
                None => diagnostic.extend(0_u64.to_le_bytes()),
            }
            drop(db);
            io::stdout().write_all(&diagnostic)?;
        }
        "try-write" => {
            assert_eq!(args.len(), 3);
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            db.busy_timeout(Duration::ZERO)?;
            db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE pending_test_write(x INTEGER)")?;
            match db.execute_batch("COMMIT") {
                Err(rusqlite::Error::SqliteFailure(code, _)) if code.code == ErrorCode::DatabaseBusy => {
                    db.execute_batch("ROLLBACK")?;
                    println!("BUSY");
                }
                result => panic!("unexpected SQLite write-transaction result: {result:?}"),
            }
        }
        _ => panic!("unrecognized operation fixture"),
    }
    Ok(())
}
