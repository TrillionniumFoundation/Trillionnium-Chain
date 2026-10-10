//! Private framed compute session. No network listener, disk writer or ledger authority.
//! Host-supplied state is root-bound. Successful compute is not chain inclusion.
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use trnm_mvcc_fee::pon_executor::{Config, ExecutionSession, State};
const MAX_FRAME: usize = 16 * 1024 * 1024;
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "closed JSON with unique keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Unique, E> {
                Err(E::custom("FLOAT"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<Unique>()? {
                    out.push(v.0);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("DUPLICATE_KEY"));
                    }
                    out.insert(k, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
fn fields(value: &Value, expected: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("OBJECT")?;
    if object.len() != expected.len() || expected.iter().any(|k| !object.contains_key(*k)) {
        return Err("FIELDS".into());
    }
    Ok(())
}
fn hash(v: &Value) -> Result<[u8; 32], String> {
    let s = v.as_str().ok_or("HASH")?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("HASH".into());
    }
    let mut out = [0; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| "HASH")?;
    Ok(out)
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or("INTEGER".into())
}
fn run() -> Result<(), String> {
    let cfg = Config::installed().map_err(str::to_owned)?;
    let mut session: Option<ExecutionSession> = None;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    loop {
        let mut length = [0; 4];
        match input.read(&mut length[..1]).map_err(|e| e.to_string())? {
            0 => return Ok(()),
            1 => (),
            _ => unreachable!(),
        }
        input
            .read_exact(&mut length[1..])
            .map_err(|_| "SHORT_FRAME")?;
        let n = u32::from_be_bytes(length) as usize;
        if n == 0 || n > MAX_FRAME {
            return Err("FRAME_LIMIT".into());
        }
        let mut body = vec![0; n];
        input.read_exact(&mut body).map_err(|_| "SHORT_FRAME")?;
        let value: Unique = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        let v = value.0;
        let response = match v["op"].as_str().ok_or("OPERATION")? {
            "open" => {
                if session.is_some() {
                    return Err("ALREADY_OPEN".into());
                }
                fields(&v, &["op", "network", "parameters", "state", "root"])?;
                if hash(&v["network"])? != cfg.network || hash(&v["parameters"])? != cfg.parameters
                {
                    return Err("CONTEXT".into());
                }
                let state: State =
                    serde_json::from_value(v["state"].clone()).map_err(|e| e.to_string())?;
                let s = ExecutionSession::new(state, hash(&v["root"])?, cfg.clone())
                    .map_err(str::to_owned)?;
                let response = json!({"op":"opened","root":hex::encode(s.root()),"sequence":s.sequence(),"network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters)});
                session = Some(s);
                response
            }
            "execute" => {
                fields(
                    &v,
                    &[
                        "op",
                        "sequence",
                        "root",
                        "transactions",
                        "height",
                        "miner",
                        "parent",
                        "workers",
                    ],
                )?;
                let s = session.as_mut().ok_or("NOT_OPEN")?;
                let xs = v["transactions"].as_array().ok_or("TRANSACTIONS")?;
                if xs.len() > 256 {
                    return Err("LIMIT".into());
                }
                let mut txs = Vec::new();
                for raw in xs {
                    let text = raw.as_str().ok_or("TRANSACTION")?;
                    if text.len() > 4096
                        || text.len() % 2 != 0
                        || !text
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err("TRANSACTION".into());
                    }
                    txs.push(hex::decode(text).map_err(|_| "TRANSACTION")?);
                }
                let workers = usize::try_from(number(&v["workers"])?).map_err(|_| "WORKERS")?;
                let result = s.execute(
                    (number(&v["sequence"])?, hash(&v["root"])?),
                    &txs,
                    number(&v["height"])?,
                    hash(&v["miner"])?,
                    hash(&v["parent"])?,
                    workers,
                );
                match result {
                    Ok(r) => {
                        json!({"op":"executed","sequence":r.sequence,"predecessor":hex::encode(r.predecessor),
                        "root":hex::encode(r.root),"changes":r.changes.iter().map(|(key,b,a)|json!({"key":key,"before_present":b.is_some(),"before":b,"after_present":a.is_some(),"after":a})).collect::<Vec<_>>(),"receipts":r.receipts.iter().map(hex::encode).collect::<Vec<_>>(),
                        "metrics":{"workers":r.metrics.workers,"workers_spawned":r.metrics.workers_spawned,
                            "signature_verifications":r.metrics.signature_verifications,"reexecuted":r.metrics.reexecuted,
                            "speculative":r.metrics.speculative,"committed_without_replay":r.metrics.committed_without_replay,"serial_conflict_batches":r.metrics.serial_conflict_batches,
                            "peak_inflight":r.metrics.peak_inflight,"state_transition_ns":r.metrics.state_transition_ns.to_string(),
                            "state_root_ns":r.metrics.state_root_ns.to_string(),"commitment_nodes":r.commitment_nodes},
                        "scope":"native-compute-cache-not-chain-authority"})
                    }
                    Err(e) => {
                        json!({"op":"rejected","error":e,"root":hex::encode(s.root()),"sequence":s.sequence()})
                    }
                }
            }
            _ => return Err("OPERATION".into()),
        };
        let bytes = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_FRAME {
            return Err("RESPONSE_LIMIT".into());
        }
        output
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .map_err(|e| e.to_string())?;
        output.write_all(&bytes).map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(2)
    }
}
