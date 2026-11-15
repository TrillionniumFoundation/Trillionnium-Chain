//! Explicit development integration fixture using the original signed task and Node owners.
//! `plan` is read-only. `prepare` creates a fresh private directory, admits only
//! reserve/receipt, and leaves the exact acceptance packet for the real Agentd.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, pon_executor::growth as growth_limits};
use trnm_pon_node::{development_public, ingress, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const BUDGET: u64 = 1_000;
const DEADLINE: u64 = 1_000;

fn task_id(settings: &Settings) -> Result<Hash> {
    Ok(hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &development_public(0)?,
            &1u64.to_le_bytes(),
            &development_public(2)?,
            &BUDGET.to_le_bytes(),
            &DEADLINE.to_le_bytes(),
        ],
    ))
}

fn plan(settings: &Settings) -> Result<Value> {
    Ok(json!({
        "schema": "hepta-native-development-task-fixture-v1",
        "network": hex::encode(settings.network()),
        "parameters": hex::encode(settings.parameters()),
        "genesis": hex::encode(settings.genesis()),
        "genesis_time": settings.genesis_time(),
        "evaluation_policy": "legacy-first-two-v3",
        "task_profile": "legacy-task-v1",
        "model_profile": "linear-expert-dev-v1",
        "task_id": hex::encode(task_id(settings)?),
        "owner": hex::encode(development_public(0)?),
        "provider": hex::encode(development_public(2)?),
        "owner_nonce": 1, "provider_nonce": 1,
        "budget": BUDGET, "deadline_height": DEADLINE,
        "known_development_keys": true,
        "independent_operators": false, "production_activation": false,
        "evaluation_qualification": false, "installation_authority": false
    }))
}

fn signed(
    settings: &Settings,
    sender: u64,
    account_sequence: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(sender)?,
        nonce: account_sequence,
        expiry: DEADLINE,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .map_err(|_| "DEVELOPMENT_KEY")?;
    tx.signature = hex::decode(sign_hex(
        &key,
        &tx.signing_digest().map_err(|_| "SIGNING_DIGEST")?,
    ))?
    .try_into()
    .map_err(|_| "SIGNATURE_LENGTH")?;
    Ok(tx.encode().map_err(|_| "TRANSACTION_ENCODING")?)
}

fn prepare(directory: &Path, settings: Settings, backend: &str, output: Hash) -> Result<Value> {
    let now = ingress::now()?;
    if settings
        .genesis_time()
        .checked_add(100)
        .ok_or("TIME_OVERFLOW")?
        >= now
    {
        return Err("GENESIS_MUST_PRECEDE_ACTUAL_WALL_CLOCK_BY_100_SECONDS".into());
    }
    if !matches!(backend, "legacy-v2" | "authenticated-v1") {
        return Err("STATE_BACKEND".into());
    }
    // Never initialize inside or replace an existing candidate's directory.
    fs::create_dir(directory)?;
    let directory = directory.canonicalize()?;
    let store = directory.join("node");
    let mut node = if backend == "authenticated-v1" {
        Node::open_with_authenticated_state(&store, settings.clone(), 1)?
    } else {
        Node::open(&store, settings.clone(), 1)?
    };
    if node.stats()?["height"] != 0
        || node.next_nonces(&[development_public(0)?, development_public(2)?])? != [1, 1]
    {
        return Err("FRESH_DEVELOPMENT_STATE_REQUIRED".into());
    }
    let id = task_id(&settings)?;
    let mut reserve = id.to_vec();
    reserve.extend(development_public(2)?);
    reserve.extend(BUDGET.to_le_bytes());
    reserve.extend(DEADLINE.to_le_bytes());
    let mut receipt = id.to_vec();
    receipt.extend(output);
    let transactions = [
        signed(&settings, 0, 1, 2, reserve)?,
        signed(&settings, 2, 1, 4, receipt.clone())?,
    ];
    let mut prefix_packets = Vec::new();
    for (index, tx) in transactions.into_iter().enumerate() {
        let height = index as u64 + 1;
        let parent = node.active()?.0;
        let packet = node.make(
            parent,
            vec![tx],
            development_public(0)?,
            settings.genesis_time() + height * 10,
            4096,
        )?;
        if packet.header.parent != parent || packet.header.height != height {
            return Err("CONTIGUOUS_PREFIX_REQUIRED".into());
        }
        let packet_id = node.admit(&packet, now)?;
        node.activate_observed(packet_id, now)?;
        let path = directory.join(format!("prefix-{height}.packet"));
        fs::write(&path, packet.encode()?)?;
        prefix_packets
            .push(json!({"height": height, "block": hex::encode(packet_id), "path": path}));
    }
    let accept = signed(&settings, 0, 2, 5, receipt)?;
    let accept_tx_id = hash(b"tx-id", &[&accept]);
    let packet = node.make(
        node.active()?.0,
        vec![accept],
        development_public(0)?,
        settings.genesis_time() + 30,
        4096,
    )?;
    let observation = node.exact_packet_observation(&packet)?;
    if observation["stored_exact"] != false || !observation["accepted_task"].is_null() {
        return Err("FIXTURE_MUST_NOT_SUBMIT_ACCEPTANCE".into());
    }
    let wire = packet.encode()?;
    let packet_path = directory.join("accept.packet");
    fs::write(&packet_path, &wire)?;
    let mut report = plan(&settings)?;
    report["state_backend"] = json!(backend);
    report["store"] = json!(store);
    report["output_sha256"] = json!(hex::encode(output));
    report["accept_tx_id"] = json!(hex::encode(accept_tx_id));
    report["accept_block"] = json!(hex::encode(packet.id()?));
    report["accept_packet"] = json!(packet_path);
    report["accept_packet_sha256"] = json!(hex::encode(Sha256::digest(&wire)));
    report["accept_packet_bytes"] = json!(wire.len());
    report["acceptance_submitted"] = json!(false);
    report["prefix_packets"] = json!(prefix_packets);
    report["prepared_state"] = node.stats()?;
    fs::write(
        directory.join("fixture.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

fn growth_settings(genesis: u64, namespace: &str) -> Result<Settings> {
    Ok(Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )?
    .with_permanent_account_growth_v2(namespace)?)
}

fn growth_plan(settings: &Settings, namespace: &str) -> Result<Value> {
    let mut report = plan(settings)?;
    report["schema"] = json!("hepta-native-development-growth-task-fixture-v1");
    report["evaluation_policy"] = json!("native-public-evaluation-dev-v1");
    report["task_profile"] = json!(continuity_v1::PROFILE);
    report["state_profile"] = json!(growth_limits::PROFILE);
    report["state_backend"] = json!("permanent-account-growth-v2");
    report["packet_profile"] = json!("PNP2");
    report["growth_namespace"] = json!(namespace);
    // Tag 2/4/5 application settlement is independent of the maintenance work
    // profile. The fixture establishes provenance, not model output quality.
    report["consensus_work_is_maintenance"] = json!(true);
    Ok(report)
}

fn growth_prepare(
    directory: &Path,
    settings: Settings,
    namespace: &str,
    output: Hash,
) -> Result<Value> {
    let now = ingress::now()?;
    if settings
        .genesis_time()
        .checked_add(100)
        .ok_or("TIME_OVERFLOW")?
        >= now
    {
        return Err("GENESIS_MUST_PRECEDE_ACTUAL_WALL_CLOCK_BY_100_SECONDS".into());
    }
    fs::create_dir(directory)?;
    let directory = directory.canonicalize()?;
    let store = directory.join("node");
    let mut node = Node::open_with_permanent_account_growth_v2(&store, settings.clone())?;
    if node.active()? != (settings.genesis(), 0) {
        return Err("FRESH_DEVELOPMENT_STATE_REQUIRED".into());
    }
    for owner in [development_public(0)?, development_public(2)?] {
        if node
            .growth_account(settings.genesis(), owner)?
            .is_none_or(|account| account.nonce != 0)
        {
            return Err("FRESH_DEVELOPMENT_STATE_REQUIRED".into());
        }
    }
    let id = task_id(&settings)?;
    let mut reserve = id.to_vec();
    reserve.extend(development_public(2)?);
    reserve.extend(BUDGET.to_le_bytes());
    reserve.extend(DEADLINE.to_le_bytes());
    let mut receipt = id.to_vec();
    receipt.extend(output);
    let transactions = [
        signed(&settings, 0, 1, 2, reserve)?,
        signed(&settings, 2, 1, 4, receipt.clone())?,
    ];
    let mut prefix_packets = Vec::new();
    for (index, tx) in transactions.into_iter().enumerate() {
        let height = index as u64 + 1;
        let parent = node.active()?.0;
        let packet = node.make_growth_consensus_maintenance(
            parent,
            vec![tx],
            development_public(0)?,
            settings.genesis_time() + height * 10,
            4096,
        )?;
        if packet.header.ledger.parent != parent || packet.header.ledger.height != height {
            return Err("CONTIGUOUS_PREFIX_REQUIRED".into());
        }
        let packet_id = node.admit_growth(&packet, now)?;
        node.activate(packet_id)?;
        let observation = node.growth_exact_packet_observation(&packet)?;
        if !observation["accepted_task"].is_null() {
            return Err("PREFIX_MUST_NOT_CLAIM_ACCEPTANCE".into());
        }
        let path = directory.join(format!("prefix-{height}.pnp2"));
        fs::write(&path, packet.encode()?)?;
        prefix_packets
            .push(json!({"height": height, "block": hex::encode(packet_id), "path": path}));
    }
    let accept = signed(&settings, 0, 2, 5, receipt)?;
    let accept_tx_id = Envelope::decode(&accept)
        .map_err(|_| "TRANSACTION_ENCODING")?
        .id()
        .map_err(|_| "TRANSACTION_ENCODING")?;
    let packet = node.make_growth_consensus_maintenance(
        node.active()?.0,
        vec![accept],
        development_public(0)?,
        settings.genesis_time() + 30,
        4096,
    )?;
    let observation = node.growth_exact_packet_observation(&packet)?;
    if observation["stored_exact"] != false || !observation["accepted_task"].is_null() {
        return Err("FIXTURE_MUST_NOT_SUBMIT_ACCEPTANCE".into());
    }
    let wire = packet.encode()?;
    let packet_path = directory.join("accept.pnp2");
    fs::write(&packet_path, &wire)?;
    let current = node.growth_current_working()?;
    let mut report = growth_plan(&settings, namespace)?;
    report["store"] = json!(store);
    report["output_sha256"] = json!(hex::encode(output));
    report["accept_tx_id"] = json!(hex::encode(accept_tx_id));
    report["accept_block"] = json!(hex::encode(packet.id()?));
    report["accept_packet"] = json!(packet_path);
    report["accept_packet_sha256"] = json!(hex::encode(Sha256::digest(&wire)));
    report["accept_packet_bytes"] = json!(wire.len());
    report["acceptance_submitted"] = json!(false);
    report["prefix_packets"] = json!(prefix_packets);
    report["prepared_state"] = json!({
        "block":hex::encode(current.block), "height":current.height,
        "generation":current.generation, "state_root":hex::encode(current.commitment.id)
    });
    fs::write(
        directory.join("fixture.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let report = match args.as_slice() {
        [command, genesis] if command == "plan" => {
            plan(&Settings::development(Some(genesis.parse()?))?)?
        }
        [command, genesis, namespace] if command == "growth-plan" => {
            growth_plan(&growth_settings(genesis.parse()?, namespace)?, namespace)?
        }
        [command, directory, genesis, namespace, output] if command == "growth-prepare" => {
            if output.len() != 64 || !output.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err("LOWERCASE_OUTPUT_SHA256_REQUIRED".into());
            }
            growth_prepare(
                Path::new(directory),
                growth_settings(genesis.parse()?, namespace)?,
                namespace,
                hex::decode(output)?.try_into().map_err(|_| "OUTPUT_LENGTH")?,
            )?
        }
        [command, directory, genesis, backend, output] if command == "prepare" => {
            if output.len() != 64 || !output.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err("LOWERCASE_OUTPUT_SHA256_REQUIRED".into());
            }
            prepare(
                Path::new(directory),
                Settings::development(Some(genesis.parse()?))?,
                backend,
                hex::decode(output)?.try_into().map_err(|_| "OUTPUT_LENGTH")?,
            )?
        }
        _ => return Err("usage: hepta_task_fixture plan GENESIS_TIME | prepare NEW_DIRECTORY GENESIS_TIME legacy-v2|authenticated-v1 OUTPUT_SHA256 | growth-plan GENESIS_TIME GROWTH_NAMESPACE | growth-prepare NEW_DIRECTORY GENESIS_TIME GROWTH_NAMESPACE OUTPUT_SHA256".into()),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
