//! Ordinary native development entrypoint. Signed transactions remain external inputs.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use trnm_pon_node::{development_public, digest, ingress, Error, Node, Packet, Result, Settings};
fn need<'a>(args: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    args.get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}").into())
}
fn number(args: &BTreeMap<String, String>, key: &str, default: u64) -> Result<u64> {
    args.get(key)
        .map(|s| s.parse().map_err(|_| Error::from(format!("invalid {key}"))))
        .unwrap_or(Ok(default))
}
fn read(path: &str, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("INPUT_LIMIT".into());
    }
    Ok(bytes)
}
fn output(path: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
fn run() -> Result<Value> {
    let mut raw = std::env::args().skip(1);
    let command = raw
        .next()
        .ok_or("command: status|mine|submit|export|confirm|sync|serve|push")?;
    let mut args = BTreeMap::new();
    while let Some(key) = raw.next() {
        let value = if key == "--development" {
            "true".into()
        } else {
            raw.next().ok_or("missing argument value")?
        };
        if args.insert(key, value).is_some() {
            return Err("DUPLICATE_OPTION".into());
        }
    }
    if args.get("--development").map(String::as_str) != Some("true") {
        return Err(
            "EXPLICIT_DEVELOPMENT_REQUIRED: public test identities; no monetary value".into(),
        );
    }
    let extra = match command.as_str() {
        "status" | "recover" => "",
        "mine" | "make" => "--transactions --timestamp --output --parent --miner",
        "submit" | "push" => "--packet --peer",
        "export" => "--block --output",
        "confirm" => "--transaction --block",
        "sync" => "--peer --tip --after --pages",
        "serve" => "--listen --seconds",
        _ => return Err("UNKNOWN_COMMAND".into()),
    };
    let allowed = format!("--development --store --genesis-time --workers --logical-now {extra}");
    for key in args.keys() {
        if !allowed.split_whitespace().any(|k| k == key) {
            return Err(format!("UNKNOWN_OPTION:{key}").into());
        }
    }
    if matches!(command.as_str(), "serve" | "sync" | "push") && args.contains_key("--logical-now") {
        return Err("NETWORK_USES_LOCAL_WALL_CLOCK".into());
    }
    if command == "push" {
        let packet = Packet::decode(&read(need(&args, "--packet")?, 1_048_576)?)?;
        let address = need(&args, "--peer")?
            .parse()
            .map_err(|_| Error::from("PEER_ADDRESS"))?;
        return ingress::call(
            address,
            &ingress::Request::Submit {
                packet: hex::encode(packet.encode()?),
            },
        );
    }
    let settings = Settings::development(
        args.get("--genesis-time")
            .map(|s| s.parse().map_err(|_| Error::from("GENESIS_TIME")))
            .transpose()?,
    )?;
    let clock = number(&args, "--logical-now", ingress::now()?)?;
    let mut node = Node::open(
        Path::new(need(&args, "--store")?),
        settings,
        number(&args, "--workers", 1)? as usize,
    )?;
    let value = match command.as_str() {
        "status" | "recover" => node.stats()?,
        "submit" => {
            let packet = Packet::decode(&read(need(&args, "--packet")?, 1_048_576)?)?;
            let id = node.admit(&packet, clock)?;
            node.activate_observed(id, clock)?;
            json!({"block":hex::encode(id),"state":node.stats()?})
        }
        "mine" | "make" => {
            let transactions = if let Some(path) = args.get("--transactions") {
                let text: Vec<String> = serde_json::from_slice(&read(path, 2_097_152)?)?;
                if text.len() > 256 {
                    return Err("TRANSACTION_LIMIT".into());
                }
                text.iter()
                    .map(|s| hex::decode(s).map_err(|_| Error::from("TRANSACTION_HEX")))
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            let timestamp = number(&args, "--timestamp", clock)?;
            let packet = {
                let parent = args
                    .get("--parent")
                    .map(|s| digest(s))
                    .transpose()?
                    .unwrap_or(node.active()?.0);
                let miner = args
                    .get("--miner")
                    .map(|s| digest(s))
                    .transpose()?
                    .unwrap_or(development_public(0)?);
                node.make(parent, transactions, miner, timestamp, 4096)?
            };
            output(need(&args, "--output")?, &packet.encode()?)?;
            if command == "mine" {
                let id = node.admit(&packet, clock)?;
                node.activate_observed(id, clock)?;
            }
            json!({"block":hex::encode(packet.id()?),"attempts":packet.header.nonce+1,"admitted":command=="mine","state":node.stats()?})
        }
        "export" => {
            let packet = node.packet(digest(need(&args, "--block")?)?)?;
            output(need(&args, "--output")?, &packet.encode()?)?;
            json!({"block":hex::encode(packet.id()?)})
        }
        "confirm" => serde_json::to_value(node.confirmation(
            digest(need(&args, "--transaction")?)?,
            digest(need(&args, "--block")?)?,
            clock,
        )?)?,
        "sync" => {
            let address = need(&args, "--peer")?
                .parse()
                .map_err(|_| Error::from("PEER_ADDRESS"))?;
            let tip = digest(need(&args, "--tip")?)?;
            let after = args
                .get("--after")
                .map(|s| digest(s))
                .transpose()?
                .unwrap_or(node.settings().genesis());
            let verified = ingress::sync_from(
                &mut node,
                address,
                tip,
                after,
                number(&args, "--pages", 256)? as usize,
            )?;
            json!({"verified_tip":hex::encode(verified),"state":node.stats()?})
        }
        "serve" => {
            let address = args
                .get("--listen")
                .map(String::as_str)
                .unwrap_or("127.0.0.1:0");
            let address: std::net::SocketAddr =
                address.parse().map_err(|_| Error::from("LISTEN_ADDRESS"))?;
            if !address.ip().is_loopback() {
                return Err("DEVELOPMENT_LOOPBACK_ONLY".into());
            }
            let listener = std::net::TcpListener::bind(address)?;
            println!(
                "{}",
                json!({"event":"listening","address":listener.local_addr()?.to_string(),"state":node.stats()?,"scope":"native-development-loopback"})
            );
            std::io::stdout().flush()?;
            serde_json::to_value(ingress::serve(
                listener,
                node,
                Duration::from_secs(number(&args, "--seconds", 30)?),
                Arc::new(AtomicBool::new(false)),
            )?)?
        }
        _ => return Err("UNKNOWN_COMMAND".into()),
    };
    Ok(
        json!({"result":value,"clock_scope":if args.contains_key("--logical-now"){"logical-test"}else{"local-wall"},"production_activation":false}),
    )
}
fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
