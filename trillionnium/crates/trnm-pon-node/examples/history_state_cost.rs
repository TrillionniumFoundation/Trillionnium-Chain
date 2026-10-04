//! Actual native chain/state growth and local read costs. Logical header spacing
//! is not elapsed network time, throughput, independent operation or acceptance.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, time::Instant};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, ingress, Node, Result, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

mod source_inventory {
    include!("support/distributed_source_inventory.rs");
}

fn source() -> Result<Value> {
    let entries: Vec<_> = source_inventory::FILES
        .iter()
        .map(|(path, bytes)| json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes))}))
        .collect();
    Ok(json!({
        "schema":"pon-history-state-cost-source-v1",
        "source_files":entries,
        "builder_commit_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),
        "builder_tree_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),
        "binary_sha256":hex::encode(Sha256::digest(fs::read(std::env::current_exe()?)?)),
        "architecture":std::env::consts::ARCH,"os":std::env::consts::OS,
        "scope":"actual compiled source bytes and local native execution; builder Git values are claims",
        "logical_header_spacing_seconds":10,"gpu_used":false,"vram_bytes":null,
        "independent_accepted":false,"public_network_ready":false,"production_activation":false
    }))
}

fn transfer(settings: &Settings, index: u64) -> Result<Vec<u8>> {
    let who = index % 4;
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .map_err(|_| "DEVELOPMENT_KEY")?;
    let mut payload = development_public((who + 1) % 4)?.to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(who)?,
        nonce: index / 4 + 1,
        expiry: 10_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(
        &key,
        &tx.signing_digest().map_err(|_| "TRANSACTION_DIGEST")?,
    ))
    .map_err(|_| "SIGNATURE_HEX")?
    .try_into()
    .map_err(|_| "SIGNATURE_LENGTH")?;
    tx.encode().map_err(|_| "TRANSACTION_CODEC".into())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: history_state_cost NEW_DIRECTORY BLOCKS16..8192".into());
    }
    let blocks: u64 = args[1].parse().map_err(|_| "BLOCKS")?;
    if !(16..=8192).contains(&blocks) {
        return Err("BLOCKS16..8192".into());
    }
    let directory = std::path::Path::new(&args[0]);
    fs::create_dir(directory)?;
    println!("{}", source()?);
    let clock = ingress::now()?;
    let genesis_time = clock.checked_sub((blocks + 8) * 10).ok_or("CLOCK")?;
    let settings = Settings::development(Some(genesis_time))?;
    let mut node = Node::open(&directory.join("owner"), settings.clone(), 1)?;
    let first: Vec<_> = (0..64)
        .map(|index| transfer(&settings, index))
        .collect::<Result<_>>()?;
    let mut queries: Vec<(Hash, Hash)> = Vec::new();
    let mut tip = settings.genesis();
    for height in 1..=blocks {
        let transactions = if height == 1 {
            first.clone()
        } else {
            Vec::new()
        };
        let started = Instant::now();
        let packet = node.make(
            tip,
            transactions,
            development_public(height + 20)?,
            genesis_time + height * 10,
            4096,
        )?;
        let made = Instant::now();
        tip = node.admit(&packet, clock)?;
        let admitted = Instant::now();
        node.activate_observed(tip, clock)?;
        let activated = Instant::now();
        if height == 1 {
            queries = first
                .iter()
                .map(|raw| (hash(b"tx-id", &[raw]), tip))
                .collect();
        }
        println!(
            "{}",
            json!({
                "schema":"pon-history-state-cost-block-v1","height":height,
                "block":hex::encode(tip),"attempts":packet.header.nonce+1,
                "execute_and_mine_ns":made.duration_since(started).as_nanos(),
                "verify_and_admit_ns":admitted.duration_since(made).as_nanos(),
                "activate_with_full_clock_scan_ns":activated.duration_since(admitted).as_nanos()
            })
        );
        if height.is_power_of_two() || height == blocks {
            let read_started = Instant::now();
            let (_, generation, state) = node.read_active()?;
            let read_ns = read_started.elapsed().as_nanos();
            for count in [1usize, 16, 64] {
                let before = node.history_read_counters();
                let started = Instant::now();
                let batch = node.confirmations(&queries[..count], clock)?;
                let elapsed = started.elapsed().as_nanos();
                let after = node.history_read_counters();
                if batch.ancestry_checked != height
                    || batch.distinct_bodies_checked != 1
                    || after.header_link_queries - before.header_link_queries != height.div_ceil(64)
                    || after.header_trace_bytes - before.header_trace_bytes != height * 350
                {
                    return Err("HISTORY_COST_OBSERVATION".into());
                }
                println!(
                    "{}",
                    json!({
                        "schema":"pon-history-state-cost-read-v2","height":height,
                        "state_keys":state.len(),"queries":count,"active_generation":generation,
                        "actual_state_read_ns":read_ns,"confirmations_ns":elapsed,
                        "header_link_queries":after.header_link_queries-before.header_link_queries,
                        "header_batch_limit":64,"header_links_checked":batch.ancestry_checked,
                        "header_trace_bytes":after.header_trace_bytes-before.header_trace_bytes,
                        "distinct_bodies_checked":batch.distinct_bodies_checked,
                        "confirmed":batch.observations.iter().filter(|o|o.confirmed).count(),
                        "owner_operation":"single local owner; no concurrent-lock or network measurement"
                    })
                );
            }
            let expected = node.active()?;
            drop(node);
            let reopen_started = Instant::now();
            node = Node::open(&directory.join("owner"), settings.clone(), 1)?;
            let reopen_ns = reopen_started.elapsed().as_nanos();
            if node.active()? != expected || node.read_active()?.2 != state {
                return Err("HISTORY_COST_REOPEN".into());
            }
            println!(
                "{}",
                json!({
                    "schema":"pon-history-state-cost-reopen-v1","height":height,
                    "state_keys":state.len(),"reopen_ns":reopen_ns,"exact_state_equal":true
                })
            );
        }
    }
    println!(
        "{}",
        json!({
            "schema":"pon-history-state-cost-result-v1","complete":true,"blocks":blocks,
            "public_network_ready":false,"independent_accepted":false,"production_activation":false
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        println!(
            "{}",
            json!({
                "schema":"pon-history-state-cost-result-v1","complete":false,"error":error.to_string(),
                "public_network_ready":false,"independent_accepted":false,"production_activation":false
            })
        );
        std::process::exit(1);
    }
}
