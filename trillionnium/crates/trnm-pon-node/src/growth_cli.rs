//! Explicit local entrypoints for the PGH2/PNP2 development namespace. They use
//! the real native owner and do not pass PNP2 through historical peer handlers.
use super::{need, number, packet_input, read};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_mvcc_fee::{continuity_v1, pon_executor::growth as limits};
use trnm_pon_node::{digest, Error, GrowthPacket, Node, Result, Settings};
use trnm_protocol::pon_wire::{Envelope, Hash};

fn parse_number(args: &BTreeMap<String, String>, name: &str) -> Result<u64> {
    need(args, name)?
        .parse()
        .map_err(|_| format!("invalid {name}").into())
}
fn output_available(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err("GROWTH_OUTPUT_EXISTS".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn write_packet(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|error| Error::from(error.error))?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
fn selected(args: &BTreeMap<String, String>, node: &Node) -> Result<Hash> {
    args.get("--block")
        .map(|s| digest(s))
        .unwrap_or_else(|| Ok(node.active()?.0))
}
fn status(node: &Node) -> Result<Value> {
    let snapshot = node.growth_current_working()?;
    Ok(
        json!({"schema":"native-growth-current-observation-v2","block":hex::encode(snapshot.block),
        "height":snapshot.height,"generation":snapshot.generation,"state_root":hex::encode(snapshot.commitment.id),
        "network":hex::encode(snapshot.commitment.network),"parameters":hex::encode(snapshot.commitment.parameters),
        "genesis":hex::encode(snapshot.commitment.genesis),"working_root":hex::encode(snapshot.commitment.working_root),
        "permanent_account_root":hex::encode(snapshot.commitment.permanent_account_root),
        "permanent_accounts":snapshot.commitment.permanent_account_count,"working_keys":snapshot.working.len(),
        "commitment":snapshot.commitment}),
    )
}

pub(super) fn run(command: &str, args: &BTreeMap<String, String>) -> Result<Value> {
    let extra = match command {
        "growth-status" | "growth-recover" => "",
        "growth-working" => "--key",
        "growth-account" => "--owner --block",
        "growth-witness" => "--owners --block",
        "growth-make" | "growth-mine" => {
            "--transactions --timestamp --output --parent --miner --search-attempts --logical-now"
        }
        "growth-submit" => "--packet --packet-stdin --logical-now",
        "growth-packet-status" => "--packet --packet-stdin",
        "growth-export" => "--block --output",
        "growth-activate" => "--block",
        _ => return Err("GROWTH_COMMAND".into()),
    };
    let allowed = format!("--development --store --growth-namespace --genesis-time {extra}");
    if args
        .keys()
        .any(|key| !allowed.split_whitespace().any(|choice| key == choice))
    {
        return Err("GROWTH_OPTION".into());
    }
    // Reject all malformed inputs and output collisions before Node::open may
    // initialize or recover the explicitly selected native namespace.
    let settings = Settings::development_with_profiles(
        Some(parse_number(args, "--genesis-time")?),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )?
    .with_permanent_account_growth_v2(need(args, "--growth-namespace")?)?;
    let path = Path::new(need(args, "--store")?);
    let owner = args.get("--owner").map(|s| digest(s)).transpose()?;
    let parent = args.get("--parent").map(|s| digest(s)).transpose()?;
    let block = args.get("--block").map(|s| digest(s)).transpose()?;
    if command == "growth-account" && owner.is_none() {
        return Err("GROWTH_OWNER_REQUIRED".into());
    }
    if matches!(command, "growth-export" | "growth-activate") && block.is_none() {
        return Err("GROWTH_BLOCK_REQUIRED".into());
    }
    let output = if matches!(command, "growth-make" | "growth-mine" | "growth-export") {
        let value = Path::new(need(args, "--output")?);
        output_available(value)?;
        Some(value)
    } else {
        None
    };
    let supplied = if matches!(command, "growth-submit" | "growth-packet-status") {
        Some(GrowthPacket::decode(&packet_input(args)?)?)
    } else {
        None
    };
    if command == "growth-packet-status" && !path.join("native.sqlite").is_file() {
        return Err("GROWTH_PACKET_STATUS_EXISTING_STORE_REQUIRED".into());
    }
    let owners = if command == "growth-witness" {
        let raw: Vec<String> = serde_json::from_slice(&read(need(args, "--owners")?, 80_000)?)?;
        if raw.is_empty() || raw.len() > limits::MAX_WITNESS_ACCOUNTS {
            return Err("GROWTH_WITNESS_LIMIT".into());
        }
        Some(raw.iter().map(|s| digest(s)).collect::<Result<Vec<_>>>()?)
    } else {
        None
    };
    let mining = if matches!(command, "growth-make" | "growth-mine") {
        let transactions = if let Some(file) = args.get("--transactions") {
            let encoded: Vec<String> =
                serde_json::from_slice(&read(file, 2 * limits::MAX_PACKET_BYTES as u64)?)?;
            if encoded.len() > 256 {
                return Err("TRANSACTION_LIMIT".into());
            }
            encoded
                .iter()
                .map(|raw| {
                    if !(318..=4096).contains(&raw.len()) {
                        return Err("TRANSACTION_LIMIT".into());
                    }
                    let bytes = hex::decode(raw).map_err(|_| Error::from("TRANSACTION_CODEC"))?;
                    Envelope::decode(&bytes).map_err(|_| Error::from("TRANSACTION_CODEC"))?;
                    Ok(bytes)
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let miner = digest(need(args, "--miner")?)?;
        let timestamp = parse_number(args, "--timestamp")?;
        let attempts = number(args, "--search-attempts", 4096)?;
        if attempts == 0 || attempts > 1_000_000 {
            return Err("GROWTH_SEARCH_LIMIT".into());
        }
        Some((transactions, miner, timestamp, attempts))
    } else {
        None
    };
    let now = number(
        args,
        "--logical-now",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::from("CLOCK"))?
            .as_secs(),
    )?;
    let mut node = if command == "growth-packet-status" {
        Node::open_growth_packet_observer(path, settings)?
    } else {
        Node::open_with_permanent_account_growth_v2(path, settings)?
    };
    let result = match command {
        "growth-status" => status(&node)?,
        "growth-recover" => {
            node.recover()?;
            status(&node)?
        }
        "growth-working" => {
            let snapshot = node.growth_current_working()?;
            let rows = if let Some(key) = args.get("--key") {
                json!({"key":key,"row":snapshot.working.get(key)})
            } else {
                json!(snapshot.working)
            };
            json!({"block":hex::encode(snapshot.block),"height":snapshot.height,"generation":snapshot.generation,
                "state_root":hex::encode(snapshot.commitment.id),"working_root":hex::encode(snapshot.commitment.working_root),"rows":rows})
        }
        "growth-account" => {
            let block = selected(args, &node)?;
            let owner = owner.ok_or("GROWTH_OWNER_REQUIRED")?;
            let account = node.growth_account(block, owner)?;
            json!({"block":hex::encode(block),"owner":hex::encode(owner),"account":account,"authenticated_absence":account.is_none()})
        }
        "growth-witness" => {
            let (checkpoint, proof, observation) = node.growth_account_multiproof(
                selected(args, &node)?,
                &owners.ok_or("GROWTH_WITNESS_LIMIT")?,
            )?;
            json!({"checkpoint":checkpoint,"proof_hex":hex::encode(proof.encode().map_err(|e|Error::from(format!("GROWTH_PROOF:{e:?}")))?),"observation":observation})
        }
        "growth-make" | "growth-mine" => {
            let (transactions, miner, timestamp, attempts) = mining.ok_or("GROWTH_MINING_INPUT")?;
            let packet = node.make_growth_consensus_maintenance(
                parent.unwrap_or(node.active()?.0),
                transactions,
                miner,
                timestamp,
                attempts,
            )?;
            let bytes = packet.encode()?;
            write_packet(output.ok_or("GROWTH_OUTPUT_REQUIRED")?, &bytes)?;
            let id = packet.id()?;
            if command == "growth-mine" {
                node.admit_growth(&packet, now)?;
                node.activate(id)?;
            }
            json!({"block":hex::encode(id),"packet_bytes":bytes.len(),"account_witness_bytes":packet.accounts.encoded_len().map_err(|e|Error::from(format!("GROWTH_PROOF:{e:?}")))?,
                "admitted":command=="growth-mine","state":status(&node)?})
        }
        "growth-submit" => {
            let packet = supplied.ok_or("GROWTH_PACKET_REQUIRED")?;
            let id = node.admit_growth(&packet, now)?;
            let active = node.activate(id)?;
            json!({"block":hex::encode(id),"admitted":true,"active":hex::encode(active),"state":status(&node)?})
        }
        "growth-packet-status" => {
            node.growth_exact_packet_observation(&supplied.ok_or("GROWTH_PACKET_REQUIRED")?)?
        }
        "growth-export" => {
            let packet = node.growth_packet(block.ok_or("GROWTH_BLOCK_REQUIRED")?)?;
            let bytes = packet.encode()?;
            write_packet(output.ok_or("GROWTH_OUTPUT_REQUIRED")?, &bytes)?;
            json!({"block":hex::encode(packet.id()?),"packet_bytes":bytes.len()})
        }
        "growth-activate" => {
            node.activate(block.ok_or("GROWTH_BLOCK_REQUIRED")?)?;
            status(&node)?
        }
        _ => return Err("GROWTH_COMMAND".into()),
    };
    Ok(json!({"profile":limits::PROFILE,"result":result}))
}
