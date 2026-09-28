//! Two-language conformance probe, not a production transaction endpoint.
use std::{collections::BTreeMap, env, fs};
use trnm_protocol::pon_wire::*;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: pon_wire header|tx|state path".into());
    }
    if fs::metadata(&args[2])?.len() > 16 * 1024 * 1024 {
        return Err("conformance input limit".into());
    }
    let b = fs::read(&args[2])?;
    let result = match args[1].as_str() {
        "header" => Header::decode(&b).map(|h| h.challenge()),
        "tx" => Envelope::decode(&b).and_then(|t| t.id()),
        "state" => {
            let pairs: Vec<(String, String)> = serde_json::from_slice(&b)?;
            let mut m = BTreeMap::new();
            for (k, v) in pairs {
                if m.insert(hex::decode(k)?, hex::decode(v)?).is_some() {
                    return Err("duplicate state key".into());
                }
            }
            state_root(&m)
        }
        _ => return Err("unknown probe".into()),
    };
    match result {
        Ok(h) => println!("{}", hex::encode(h)),
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(2)
        }
    }
    Ok(())
}
