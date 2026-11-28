#![forbid(unsafe_code)]

use rusqlite::{Connection, ErrorCode, OpenFlags};
use std::{env, fs, io::{self, Write}, path::PathBuf, time::Duration};
use trnm_service_settlement::{
    ConsumptionSettlementFreshGenesisTrustBundleV1, ConsumptionSettlementStoreConfigV1,
    ConsumptionSettlementStoreV1, Hash32V1,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().collect::<Vec<_>>();
    let mode = args[1].to_str().unwrap();
    let path = PathBuf::from(&args[2]);
    if mode == "try-write" {
        assert_eq!(args.len(), 3);
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        db.busy_timeout(Duration::ZERO)?;
        db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE pending_test_write(x INTEGER)")?;
        match db.execute_batch("COMMIT") {
            Err(rusqlite::Error::SqliteFailure(code, _)) if code.code == ErrorCode::DatabaseBusy => {
                db.execute_batch("ROLLBACK")?;
                println!("BUSY");
                return Ok(());
            }
            result => panic!("unexpected SQLite write-transaction result: {result:?}"),
        }
    }
    assert_eq!(args.len(), 5);
    let bytes = fs::read(&args[3])?;
    let mut trust = borsh::from_slice::<ConsumptionSettlementFreshGenesisTrustBundleV1>(&bytes)?;
    assert_eq!(borsh::to_vec(&trust)?, bytes);
    let identity = args[4].to_str().unwrap().parse::<u8>()?;
    trust.initial_order_height += u64::from(identity) * 8;
    let config = ConsumptionSettlementStoreConfigV1 {path: path.clone(), store_id: Hash32V1([identity; 32]), trust_bundle: trust};
    let encoded = borsh::to_vec(&(config.store_id, &config.trust_bundle))?;
    let mut output = io::stdout().lock();
    match mode {
        "seed" => {
            ConsumptionSettlementStoreV1::open(config)?;
            output.write_all(&encoded)?;
        }
        "verify" => {
            let store = ConsumptionSettlementStoreV1::open_existing(config)?;
            let observed = store.fresh_readback()?;
            output.write_all(&observed.store_schema_version().to_le_bytes())?;
            output.write_all(&observed.sequence().to_le_bytes())?;
            output.write_all(&observed.order_height().to_le_bytes())?;
            output.write_all(&observed.order_block_id().0)?;
            output.write_all(&observed.durable_state_root().0)?;
            output.write_all(&observed.durable_journal_root().0)?;
            output.write_all(&[0])?; // Original open/readback both already reject a fenced store.
            let db = Connection::open_with_flags(&path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW)?;
            let checksum: Vec<u8> = db.query_row("SELECT checksum FROM metadata WHERE singleton=1", [], |row| row.get(0))?;
            assert_eq!(checksum.len(), 32);
            output.write_all(&checksum)?;
        }
        _ => panic!("unrecognized metadata fixture"),
    }
    Ok(())
}
