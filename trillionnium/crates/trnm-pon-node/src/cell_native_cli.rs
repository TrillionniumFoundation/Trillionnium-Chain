//! Explicit native Cell research commands. The expected owner channel and the
//! producer's claim are separate required inputs. No command admits a block.
use super::{digest, need, number, open_operator_node, Error, Node, Result, Settings};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use trnm_pon_node::cell_native_v1 as cell;

pub(super) fn is_command(command: &str) -> bool {
    matches!(
        command,
        "cell-verify-historical" | "cell-verify-live" | "cell-prove-reference"
    )
}

fn input(path: &str, limit: usize, owner: bool) -> Result<Vec<u8>> {
    if owner && !Path::new(path).is_absolute() {
        return Err("CELL_OWNER_FILE_ABSOLUTE".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::from("CELL_INPUT_FILE"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::from("CELL_INPUT_FILE"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err("CELL_INPUT_FILE".into());
    }
    if owner
        && (metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0)
    {
        return Err("CELL_OWNER_FILE".into());
    }
    let mut raw = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut raw)?;
    if raw.len() > limit {
        return Err("CELL_INPUT_LIMIT".into());
    }
    Ok(raw)
}

pub(super) fn run(
    command: &str,
    args: &BTreeMap<String, String>,
    settings: Settings,
    owner_config: Option<trnm_pon_node::operator_task_policy::RestrictedNodeInputs>,
    authenticated_state: bool,
) -> Result<Value> {
    if args.contains_key("--logical-now") {
        return Err("CELL_CLOCK_NOT_CONFIGURABLE".into());
    }
    let store = Path::new(need(args, "--store")?);
    if !store.join("native.sqlite").is_file() {
        return Err("CELL_EXISTING_STORE_REQUIRED".into());
    }
    let parent = digest(need(args, "--cell-parent")?)?;
    let owner_pin = digest(need(args, "--cell-expected-sha256")?)?;
    let owner_raw = input(need(args, "--cell-expected")?, cell::ADMISSION_LIMIT, true)?;
    if <[u8; 32]>::from(Sha256::digest(&owner_raw)) != owner_pin {
        return Err("CELL_OWNER_ADMISSION_SHA256".into());
    }
    let claim = if command == "cell-prove-reference" {
        None
    } else {
        Some(input(
            need(args, "--cell-claim")?,
            cell::CLAIM_LIMIT,
            false,
        )?)
    };
    let attempts = number(args, "--cell-attempts", 1)?;
    if !(1..=4096).contains(&attempts) {
        return Err("CELL_SEARCH_BUDGET".into());
    }
    let output = if command == "cell-prove-reference" {
        Some(Path::new(need(args, "--output")?))
    } else {
        None
    };
    let node: Node = open_operator_node(
        store,
        settings,
        number(args, "--workers", 1)? as usize,
        owner_config,
        authenticated_state,
    )?;
    let expected = node.cell_expected_from_owner(parent, &owner_raw, owner_pin)?;
    let owner_sha256 = hex::encode(expected.owner_admission_sha256());
    if let Some(output) = output {
        let proof = cell::prove_reference(&expected, attempts)?;
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(output)?;
        file.write_all(&proof)?;
        file.sync_all()?;
        return Ok(
            json!({"schema":format!("{}/producer-observation",cell::PROFILE),
            "contract_id":hex::encode(expected.contract_id()),"owner_admission_sha256":owner_sha256,
            "claim_bytes":proof.len(),"claim_sha256":hex::encode(Sha256::digest(&proof)),
            "clock_scope":"verified-parent-state-unix-seconds","consensus_work_admitted":false,
            "production_activation":false}),
        );
    }
    let claim = claim.ok_or("CELL_CLAIM_REQUIRED")?;
    let verified = if command == "cell-verify-live" {
        node.verify_cell_live(&expected, &claim, trnm_pon_node::ingress::now)?
    } else {
        // This branch intentionally never evaluates wall time, including the
        // ordinary CLI's logical/current clock initialisation below it.
        cell::verify_historical(&expected, &claim)?
    };
    Ok(
        json!({"result":verified.observation(),"owner_admission_sha256":owner_sha256,
        "clock_scope":if command == "cell-verify-live" {"local-unix-seconds-before-and-after"}
            else {"verified-parent-state-unix-seconds"},"production_activation":false}),
    )
}
