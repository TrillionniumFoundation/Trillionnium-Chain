//! Explicit ordinary submit/status over an already provisioned NPQ6 owner.
//! No listener, account key, migration, new database or production activation.
use super::{ensure, input, need, number, spki};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
use trnm_pon_node::{ingress, Node, Packet, Result};

#[path = "pq_application_local/config.rs"]
mod config;

pub(crate) fn run(command: &str, args: &BTreeMap<String, String>) -> Result<Value> {
    const ALLOWED: &[&str] = &[
        "--development",
        "--store",
        "--workers",
        "--packet",
        "--packet-stdin",
        "--pq-application-config",
        "--pq-application-config-sha256",
        "--witness-writer-key",
    ];
    ensure(
        matches!(command, "submit" | "packet-status"),
        "PQ_APPLICATION_COMMAND",
    )?;
    ensure(
        args.keys().all(|key| ALLOWED.contains(&key.as_str())),
        "PQ_APPLICATION_OPTION",
    )?;
    ensure(
        args.get("--development").map(String::as_str) == Some("true"),
        "EXPLICIT_DEVELOPMENT_REQUIRED",
    )?;
    let workers =
        usize::try_from(number(args, "--workers", 1)?).map_err(|_| "PQ_APPLICATION_WORKERS")?;
    ensure((1..=64).contains(&workers), "PQ_APPLICATION_WORKERS")?;
    let material = config::load(args)?;
    let raw = super::super::packet_input(args)?;
    let packet = Packet::decode_for_settings(&raw, &material.settings)?;
    let packet_sha256: [u8; 32] = Sha256::digest(&raw).into();
    let store = Path::new(need(args, "--store")?);
    ensure(store.is_absolute(), "PQ_APPLICATION_STORE")?;
    let metadata = std::fs::symlink_metadata(store.join("native.sqlite"))
        .map_err(|_| "PQ_APPLICATION_EXISTING_STORE_REQUIRED")?;
    ensure(metadata.is_file(), "PQ_APPLICATION_EXISTING_STORE_REQUIRED")?;
    let mut node = match material.witness {
        Some(witness) => witness.open_initialized_node(
            store,
            material.settings,
            workers,
            &material.policy,
            need(args, "--witness-writer-key")?,
        )?,
        None => Node::open_existing_with_pq_network(
            store,
            material.settings,
            workers,
            &material.policy,
        )?,
    };
    // Reopening validates the stored owner policy and all original replay
    // state. The packet uses this actual Node's selected account namespace.
    ensure(
        node.settings().is_native_pq_application_v6(),
        "PQ_APPLICATION_PROFILE",
    )?;
    let network = node.settings().network();
    let parameters = node.settings().parameters();
    let genesis = node.settings().genesis();
    node.pq_network_status(&material.policy)?;
    let value = match command {
        "submit" => {
            let now = ingress::now()?;
            let block = node.admit(&packet, now)?;
            node.activate_observed(block, now)?;
            json!({"block":hex::encode(block),"state":node.stats()?})
        }
        "packet-status" => node.exact_packet_observation(&packet)?,
        _ => return Err("PQ_APPLICATION_COMMAND".into()),
    };
    // Only a successfully opened actual owner and completed operation can
    // emit this binding. It is an observation, not an authorization token.
    node.pq_network_status(&material.policy)?;
    Ok(json!({
        "result":value,
        "pq_application_context":{
            "schema":"native-pq-application-local-observation-v1",
            "configuration_sha256":hex::encode(material.configuration_sha256),
            "profile":trnm_mvcc_fee::pon_executor::pq_accounts_v2::application_v6::PROFILE,
            "network":hex::encode(network),"parameters":hex::encode(parameters),
            "genesis":hex::encode(genesis),"network_policy":hex::encode(material.policy.id()),
            "owner_profile":material.owner_profile,
            "packet_sha256":hex::encode(packet_sha256),"block":hex::encode(packet.id()?)
        },
        "clock_scope":"local-wall","local_owner_only":true,
        "whole_node_rollback_protection":false,"production_activation":false
    }))
}
