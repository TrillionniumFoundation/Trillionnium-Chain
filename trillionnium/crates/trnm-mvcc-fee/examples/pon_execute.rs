//! Bounded offline bridge for the native executor. Not a public RPC or Hepta host.
use serde_json::{json, Value};
use std::io::{self, Read};
use trnm_mvcc_fee::pon_executor::{execute, Config, State};
fn h(value: &Value) -> Result<[u8; 32], String> {
    let s = value.as_str().ok_or("hash string")?;
    let mut out = [0; 32];
    hex::decode_to_slice(s, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}
fn run() -> Result<(), String> {
    let mut input = Vec::new();
    io::stdin()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())?;
    if input.len() > 16 * 1024 * 1024 {
        return Err("BRIDGE_LIMIT".into());
    }
    let v: Value = serde_json::from_slice(&input).map_err(|e| e.to_string())?;
    let state: State = serde_json::from_value(v["state"].clone()).map_err(|e| e.to_string())?;
    let txs = v["transactions"]
        .as_array()
        .ok_or("transactions")?
        .iter()
        .map(|x| hex::decode(x.as_str().ok_or("hex")?).map_err(|_| "hex"))
        .collect::<Result<Vec<_>, _>>()?;
    let cfg = Config::installed().map_err(str::to_owned)?;
    if h(&v["network"])? != cfg.network || h(&v["parameters"])? != cfg.parameters {
        return Err("CONTEXT".into());
    }
    let start = std::time::Instant::now();
    let result = execute(
        &state,
        &txs,
        v["height"].as_u64().ok_or("height")?,
        h(&v["miner"])?,
        h(&v["parent"])?,
        v["workers"].as_u64().ok_or("workers")? as usize,
        &cfg,
    )
    .map_err(str::to_owned)?;
    println!(
        "{}",
        json!({"network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),"state":result.state,"receipts":result.receipts.iter().map(hex::encode).collect::<Vec<_>>(),"root":hex::encode(result.root),"metrics":{"workers":result.metrics.workers,"speculative":result.metrics.speculative,"reexecuted":result.metrics.reexecuted,"committed_without_replay":result.metrics.committed_without_replay,"peak_inflight":result.metrics.peak_inflight,"serial_conflict_batches":result.metrics.serial_conflict_batches,"elapsed_ns":start.elapsed().as_nanos().to_string()},"scope":"native-application-not-production-node"})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
