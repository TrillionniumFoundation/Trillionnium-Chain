#![allow(dead_code)]

use rusqlite::{Connection, ErrorCode, OpenFlags};
use std::{
    env,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

mod original_error {
    include!(env!("TRNM_SETTLEMENT_SCHEMA_ERROR"));
}
use original_error::{ConsumptionSettlementErrorCodeV1, ConsumptionSettlementResultV1, error};
include!(env!("TRNM_SETTLEMENT_SCHEMA_SOURCE"));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().collect::<Vec<_>>();
    assert_eq!(args.len(), 3);
    let path = PathBuf::from(&args[2]);
    match args[1].to_str().unwrap() {
        "seed" => {
            let db = Connection::open(&path)?;
            for sql in [META_SQL, OP_SQL, COMMITTED_BLOCKS_SQL] {
                db.execute_batch(sql)?;
            }
        }
        "verify" => match open_read_snapshot(&path).and_then(|db| verify_schema(&db)) {
            Ok(()) => println!("VALID"),
            Err(e) => println!("{:?}", e.code()),
        },
        "try-write" => {
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
        _ => panic!("unrecognized original schema fixture"),
    }
    Ok(())
}
