//! Explicit signed development inputs for finite public-pool campaigns.
//! Produces no block, execution certificate, actual demand or public acceptance.
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, ingress, Result, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    qualified_work_task::lifecycle_v4::{AtomicRenewTaskV4, PROFILE},
};

mod source_inventory {
    include!("support/distributed_source_inventory.rs");
}
fn signature(who: u64, message: &[u8]) -> Result<[u8; 64]> {
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .map_err(|_| "DEVELOPMENT_KEY")?;
    hex::decode(sign_hex(&key, message))
        .map_err(|_| "SIGNATURE_HEX")?
        .try_into()
        .map_err(|_| "SIGNATURE_LENGTH".into())
}
fn transaction(
    settings: &Settings,
    who: u64,
    nonce: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(who)?,
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(who, &tx.signing_digest().map_err(|_| "TRANSACTION_DIGEST")?)?;
    tx.encode().map_err(|_| "TRANSACTION_CODEC".into())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err(
            "usage: public_pool_fixture NEW_DIRECTORY GENESIS_TIME; development inputs only".into(),
        );
    }
    let path = Path::new(&args[0]);
    let genesis = args[1].parse().map_err(|_| "GENESIS_TIME")?;
    let settings = Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        PROFILE,
    )?;
    fs::create_dir(path)?;
    let mut inventory = Vec::new();
    for group in 0..20u64 {
        let mut rows = Vec::new();
        for offset in 0..8u64 {
            let nonce = group * 8 + offset + 1;
            let mut payload = development_public(4)?.to_vec();
            payload.extend(1u64.to_le_bytes());
            let raw = transaction(&settings, 0, nonce, 1, payload)?;
            inventory.push(json!({"group":group,"nonce":nonce,"tag":1,"bytes":raw.len(),
                "raw_digest":hex::encode(hash(b"public-pool-fixture-raw-v1",&[&raw])),"hex":hex::encode(&raw)}));
            rows.push(hex::encode(raw));
        }
        write_new(
            &path.join(format!("bundle-{group:02}.json")),
            &serde_json::to_vec(&rows)?,
        )?;
    }
    let boot = settings.bootstrap_lifecycle_task()?;
    let mut lease = boot.lease;
    lease.revision += 1;
    lease.not_before = 9;
    lease.expires = 1009;
    lease.available_until = 1109;
    let mut signed = boot.signed;
    signed.lease_id = lease.id().map_err(|_| "TASK_LEASE")?;
    signed.manifest.source_record = lease.bound_source_record().map_err(|_| "TASK_LEASE")?;
    signed.manifest.withdrawal_head = lease.withdrawal_frontier().map_err(|_| "TASK_LEASE")?;
    signed.manifest.not_before = lease.not_before;
    signed.manifest.expires = lease.expires;
    signed.manifest.available_until = lease.available_until;
    signed.manifest.demand_nonce = 2;
    signed.signature = signature(0, &signed.signing_message().map_err(|_| "TASK_SIGNATURE")?)?;
    let successor = hex::encode(signed.encode().map_err(|_| "TASK_CODEC")?);
    let raw = transaction(
        &settings,
        1,
        1,
        22,
        AtomicRenewTaskV4 { lease, signed }
            .encode()
            .map_err(|_| "TASK_CODEC")?,
    )?;
    write_new(
        &path.join("atomic-renew-overlap.json"),
        &serde_json::to_vec(&vec![hex::encode(&raw)])?,
    )?;
    inventory.push(json!({"group":"atomic-renew","nonce":1,"sender_index":1,"tag":22,"bytes":raw.len(),
        "raw_digest":hex::encode(hash(b"public-pool-fixture-raw-v1",&[&raw])),"hex":hex::encode(raw)}));
    let source: Vec<_> = source_inventory::FILES
        .iter()
        .map(|(p, b)| {
            json!({"path":p,"bytes":b.len(),
        "digest":hex::encode(hash(b"public-pool-fixture-source-v1",&[b]))})
        })
        .collect();
    let binary = fs::read(std::env::current_exe()?)?;
    let manifest = json!({"schema":"public-pool-development-input-fixture-v1","genesis_time":genesis,
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis()),
        "evaluation_policy":"native-public-evaluation-dev-v1","task_profile":PROFILE,
        "preview_miner":development_public(3)?,
        "public_v3_policy_bits12":hex::encode(ingress::public_v3::PublicPolicy::new(12,std::time::Duration::from_millis(2000))?.id()),
        "transfer_groups":20,"members_per_transfer_group":8,"signed_transfers":160,
        "renewal_submit_after_observed_height":8,"renewal_earliest_containing_height":9,
        "renewal_latest_containing_height":1000,"renewal_filename":"atomic-renew-overlap.json",
        "successor_statement":successor,"inputs":inventory,"source_inventory":source,
        "builder_commit_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),"builder_tree_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),
        "binary_digest":hex::encode(hash(b"public-pool-fixture-binary-v1",&[&binary])),
        "scope":"operator-produced public-key development fixtures; not demand authorization, useful output or independent attestation",
        "public_network_ready":false,"production_activation":false});
    write_new(
        &path.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!(
        "{}",
        json!({"fixture":path,"signed_transfers":160,"atomic_renewals":1,
        "network":hex::encode(settings.network()),"public_network_ready":false,"production_activation":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
