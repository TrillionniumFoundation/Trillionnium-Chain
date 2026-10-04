//! Actual native chain/state growth and local read costs. Logical header spacing
//! is not elapsed network time, throughput, independent operation or acceptance.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, time::Instant};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_commitment::{CommitmentMethod, FullRootReason};
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

fn commitment_status(node: &Node) -> Value {
    let status = node.derived_commitment_status();
    let last = status.last.map(|last| {
        let (method, fallback) = match last.method {
            CommitmentMethod::RebuiltTree => ("rebuilt-tree", None),
            CommitmentMethod::CheckedApply => ("checked-apply", None),
            CommitmentMethod::FullRoot(reason) => (
                "full-root",
                Some(match reason {
                    FullRootReason::KeyBudget => "key-budget",
                    FullRootReason::PayloadBudget => "payload-budget",
                    FullRootReason::WorkspaceBudget => "workspace-budget",
                    FullRootReason::DeltaBudget => "delta-budget",
                    FullRootReason::InternalSnapshotMismatch => "internal-snapshot-mismatch",
                }),
            ),
        };
        json!({
            "method":method,"fallback":fallback,"actual_keys":last.actual_keys,
            "actual_payload_bytes":last.actual_payload_bytes,"changed_keys":last.changed_keys,
            "changed_payload_bytes":last.changed_payload_bytes,
            "compressed_nodes":last.compressed_nodes,
            "workspace_charge_bytes":last.workspace_charge_bytes
        })
    });
    json!({
        "cache_root":status.cache_root.map(hex::encode),"cache_keys":status.cache_keys,
        "retained_software_charge_bytes":status.software_charge_bytes,"last":last,
        "process_rss_measured":false
    })
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
            let before_read = commitment_status(&node);
            let read_started = Instant::now();
            let (_, generation, state) = node.read_active()?;
            let read_ns = read_started.elapsed().as_nanos();
            let after_read = commitment_status(&node);
            let mut confirmation_methods = Vec::new();
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
                confirmation_methods.push(json!({
                    "queries":count,"after":commitment_status(&node)
                }));
            }
            // A separately timed full-root reference runs after all confirmation
            // batches, outside their clocks. It is not a KV-only timing, RSS sample,
            // speedup comparison, or a substitute for the actual read fence.
            let reference_started = Instant::now();
            let reference_root = trnm_mvcc_fee::pon_executor::root(&state)?;
            let reference_ns = reference_started.elapsed().as_nanos();
            let expected_root = hex::encode(reference_root);
            let observed_cache_roots_equal = std::iter::once(&before_read)
                .chain(std::iter::once(&after_read))
                .chain(confirmation_methods.iter().map(|row| &row["after"]))
                .all(|status| match &status["cache_root"] {
                    Value::Null => true,
                    Value::String(root) => root == &expected_root,
                    _ => false,
                });
            if reference_root != packet.header.state
                || !observed_cache_roots_equal
                || node
                    .derived_commitment_status()
                    .cache_root
                    .is_some_and(|cached| cached != reference_root)
            {
                return Err("HISTORY_COST_REFERENCE_ROOT".into());
            }
            println!(
                "{}",
                json!({
                    "schema":"pon-history-state-commitment-cost-v1","height":height,
                    "state_keys":state.len(),"active_generation":generation,
                    "actual_state_read_ns":read_ns,"full_reference_root_ns":reference_ns,
                    "expected_root":hex::encode(packet.header.state),
                    "full_reference_root":hex::encode(reference_root),
                    "exact_root_equal":true,"observed_cache_roots_equal":true,
                    "before_read":before_read,"after_read":after_read,
                    "confirmation_methods":confirmation_methods,
                    "full_reference_after_confirmation_batches":true,
                    "timed_reference_mutates_node_cache":false,
                    "public_network_ready":false,"independent_accepted":false,
                    "owner_operation":"single local owner; no concurrent-lock or process-memory measurement"
                })
            );
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
