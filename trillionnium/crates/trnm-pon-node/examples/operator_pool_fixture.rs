//! Finite offline operator inputs: only public materials are exported. No Node,
//! remote key transfer, mining, hidden DEV signer, demand truth or acceptance.
use serde_json::json;
use std::{
    fs::{self, DirBuilder},
    os::unix::fs::DirBuilderExt,
    path::Path,
    time::Duration,
};
use trnm_pon_node::{
    digest, ingress,
    operator_deployment::{self as actors, offline},
    Result, Settings,
};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::lifecycle_v4::{AtomicRenewTaskV4, PROFILE},
};
mod source_inventory {
    include!("support/distributed_source_inventory.rs");
}
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn tx(
    settings: &Settings,
    sender: Hash,
    nonce: u64,
    tag: u8,
    payload: Vec<u8>,
    secret: &Path,
) -> Result<Vec<u8>> {
    let mut e = Envelope {
        network: settings.network(),
        sender,
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    e.signature = offline::sign_pinned_digest_from_file(
        &hex::encode(sender),
        e.signing_digest().map_err(|_| "ACTOR_TRANSACTION")?,
        secret,
    )?;
    e.encode().map_err(|_| "ACTOR_TRANSACTION".into())
}
fn run(args: &[String]) -> Result<()> {
    ensure(args.len()==10,"usage: operator_pool_fixture NEWDIR SPEC BOOTSTRAP MODEL INPUT SOURCE_SECRET REQUESTER_SECRET TRANSFER_SECRET TRANSFER_RECIPIENT MINER; explicit development inputs only")?;
    let raw_spec = offline::read_public(Path::new(&args[1]), actors::SPEC_BYTES as u64)?;
    let spec = actors::OperatorDeploymentSpec::decode(&raw_spec)?;
    let raw_bundle = offline::read_public(Path::new(&args[2]), actors::BOOTSTRAP_BYTES as u64)?;
    let bundle: actors::BootstrapBundle = actors::decode(&raw_bundle)?;
    let model = offline::read_public(Path::new(&args[3]), 16384)?;
    let input = offline::read_public(Path::new(&args[4]), 16384)?;
    let settings = Settings::development_with_operator_actors(&spec, &bundle, &model, &input)?;
    let recipient = trnm_mvcc_fee::deployment_actors::operator_key(&args[8])?;
    let miner = trnm_mvcc_fee::deployment_actors::operator_key(&args[9])?;
    ensure(recipient != [0; 32], "ACTOR_RECIPIENT")?;
    ensure(
        spec.allocations.iter().any(|a| a.public_key == args[9]),
        "ACTOR_MINER_FUNDING",
    )?;
    // The supplied transfer signer is explicitly selected by its actual public
    // key and must be funded in the descriptor; all signatures recheck that pin.
    let transfer_public = offline::owned_signer_public(Path::new(&args[7]))?;
    ensure(
        spec.allocations
            .iter()
            .any(|a| a.public_key == transfer_public),
        "ACTOR_TRANSFER_SIGNER_FUNDING",
    )?;
    let transfer = digest(&transfer_public)?;
    ensure(
        transfer != digest(&spec.requester)?,
        "ACTOR_REQUESTER_TRANSFER_NONCE_CONFLICT",
    )?;
    let source_secret = Path::new(&args[5]);
    let requester_secret = Path::new(&args[6]);
    // Validate both actual key pins before publishing any output directory.
    offline::sign_pinned_digest_from_file(
        &spec.source,
        hash(b"operator-fixture-source-pin-v1", &[&settings.network()]),
        source_secret,
    )?;
    offline::sign_pinned_digest_from_file(
        &spec.requester,
        hash(b"operator-fixture-requester-pin-v1", &[&settings.network()]),
        requester_secret,
    )?;
    let mut groups = Vec::new();
    let mut inventory = Vec::new();
    for group in 0..20u64 {
        let mut rows = vec![];
        for offset in 0..8u64 {
            let nonce = group * 8 + offset + 1;
            let mut p = recipient.to_vec();
            p.extend(1u64.to_le_bytes());
            let raw = tx(&settings, transfer, nonce, 1, p, Path::new(&args[7]))?;
            inventory.push(json!({"group":group,"nonce":nonce,"sender":hex::encode(transfer),"tag":1,"bytes":raw.len(),"raw_digest":hex::encode(hash(b"public-pool-fixture-raw-v1",&[&raw])),"hex":hex::encode(&raw)}));
            rows.push(hex::encode(raw));
        }
        groups.push(serde_json::to_vec(&rows)?);
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
    signed.manifest.not_before = 9;
    signed.manifest.expires = 1009;
    signed.manifest.available_until = 1109;
    signed.manifest.demand_nonce = 2;
    signed.signature = offline::sign_pinned_digest_from_file(
        &spec.source,
        signed.signing_message().map_err(|_| "TASK_SIGNATURE")?,
        source_secret,
    )?;
    let successor = hex::encode(signed.encode().map_err(|_| "TASK_CODEC")?);
    let renew = tx(
        &settings,
        digest(&spec.requester)?,
        1,
        22,
        AtomicRenewTaskV4 { lease, signed }
            .encode()
            .map_err(|_| "TASK_CODEC")?,
        requester_secret,
    )?;
    inventory.push(json!({"group":"atomic-renew","nonce":1,"sender":spec.requester,"tag":22,"bytes":renew.len(),"raw_digest":hex::encode(hash(b"public-pool-fixture-raw-v1",&[&renew])),"hex":hex::encode(&renew)}));
    let source:Vec<_>=source_inventory::FILES.iter().map(|(p,b)|json!({"path":p,"bytes":b.len(),"digest":hex::encode(hash(b"public-pool-fixture-source-v1",&[b]))})).collect();
    let binary = fs::read(std::env::current_exe()?)?;
    let out = Path::new(&args[0]);
    DirBuilder::new().mode(0o700).create(out)?;
    for (p, b) in [
        ("deployment-spec.json", raw_spec),
        ("deployment-bootstrap.json", raw_bundle),
        ("bootstrap-model.bin", model),
        ("bootstrap-input.bin", input),
    ] {
        offline::write_new_public(&out.join(p), &b)?;
    }
    for (group, bytes) in groups.iter().enumerate() {
        offline::write_new_public(&out.join(format!("bundle-{group:02}.json")), bytes)?;
    }
    offline::write_new_public(
        &out.join("atomic-renew-overlap.json"),
        &serde_json::to_vec(&vec![hex::encode(renew)])?,
    )?;
    let manifest = json!({"schema":"public-pool-development-input-fixture-v1","actor_profile":actors::PROFILE,"operator_spec_hash":hex::encode(spec.id()?),"genesis_time":spec.genesis_timestamp,"network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis()),"evaluation_policy":spec.evaluation_profile,"task_profile":PROFILE,"model_profile":spec.model_profile,"source_public":spec.source,"requester_public":spec.requester,"transfer_sender":hex::encode(transfer),"transfer_recipient":hex::encode(recipient),"preview_miner":miner,"public_materials":{"spec":"deployment-spec.json","bootstrap":"deployment-bootstrap.json","model":"bootstrap-model.bin","input":"bootstrap-input.bin"},"public_v3_policy_bits12":hex::encode(ingress::public_v3::PublicPolicy::new(12,Duration::from_millis(2000))?.id()),"transfer_groups":20,"members_per_transfer_group":8,"signed_transfers":160,"renewal_submit_after_observed_height":8,"renewal_earliest_containing_height":9,"renewal_latest_containing_height":1000,"renewal_filename":"atomic-renew-overlap.json","successor_statement":successor,"inputs":inventory,"source_inventory":source,"builder_commit_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),"builder_tree_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),"binary_digest":hex::encode(hash(b"public-pool-fixture-binary-v1",&[&binary])),"scope":"explicit operator-owned offline inputs; strict possession not random keys, independence, demand truth, useful output or public acceptance","public_network_ready":false,"production_activation":false,"independent_governance_accepted":false,"hardness_accepted":false,"demand_truth_accepted":false,"objective_model_quality":false});
    offline::write_new_public(
        &out.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!(
        "{}",
        json!({"fixture":out,"signed_transfers":160,"atomic_renewals":1,"actor_profile":actors::PROFILE,"network":hex::encode(settings.network()),"public_network_ready":false,"production_activation":false})
    );
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

#[cfg(test)]
#[path = "../tests/support/operator_fixture.rs"]
mod fixture;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::*;
    use trnm_pon_node::Node;
    fn inputs(base: &Path, transfer: u8) -> (Vec<String>, Settings) {
        let (spec, bundle, m, i, s) = fixture();
        for (name, raw) in [
            ("spec", spec.canonical().unwrap()),
            ("bootstrap", actors::canonical(&bundle).unwrap()),
            ("model", m),
            ("input", i),
            ("source-secret", secret(0).into_bytes()),
            ("requester-secret", secret(1).into_bytes()),
            ("transfer-secret", secret(transfer).into_bytes()),
        ] {
            offline::write_new_public(&base.join(name), &raw).unwrap();
        }
        let mut args = vec![base.join("out").display().to_string()];
        for name in [
            "spec",
            "bootstrap",
            "model",
            "input",
            "source-secret",
            "requester-secret",
            "transfer-secret",
        ] {
            args.push(base.join(name).display().to_string());
        }
        args.push(public(4));
        args.push(public(5));
        (args, s)
    }
    #[test]
    fn actual_offline161_inputs_execute20_native_blocks_and_reopen_public_only() {
        let temp = tempfile::tempdir().unwrap();
        let (args, s) = inputs(temp.path(), 0);
        run(&args).unwrap();
        let output = Path::new(&args[0]);
        let v: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(v["inputs"].as_array().unwrap().len(), 161);
        assert_eq!(v["actor_profile"], actors::PROFILE);
        assert_eq!(v["transfer_sender"], public(0));
        assert_eq!(v["preview_miner"], json!(key(5)));
        let emitted = fs::read(output.join("manifest.json")).unwrap();
        assert!(!String::from_utf8_lossy(&emitted).contains("source-secret"));
        assert!(!String::from_utf8_lossy(&emitted).contains(&secret(0)));
        let (m, i, _, _) = s.bootstrap_task_material().unwrap();
        let boot = s.bootstrap_lifecycle_task().unwrap();
        let mut node = Node::open(&temp.path().join("owner"), s.clone(), 2).unwrap();
        let mut tip = s.genesis();
        for group in 0..20u64 {
            let rows: Vec<String> = serde_json::from_slice(
                &fs::read(output.join(format!("bundle-{group:02}.json"))).unwrap(),
            )
            .unwrap();
            let mut transactions: Vec<Vec<u8>> =
                rows.iter().map(|r| hex::decode(r).unwrap()).collect();
            assert_eq!(transactions[0], transfer(&s, 0, group * 8 + 1, 4, 1));
            if group == 8 {
                let rows: Vec<String> = serde_json::from_slice(
                    &fs::read(output.join("atomic-renew-overlap.json")).unwrap(),
                )
                .unwrap();
                transactions.push(hex::decode(&rows[0]).unwrap());
            }
            let lease = node
                .lifecycle_task_lease(tip, boot.signed.manifest.matrix_task, group + 1)
                .unwrap();
            let signed = if group < 9 {
                boot.signed.clone()
            } else {
                trnm_protocol::qualified_work_task::lifecycle_v2::SignedLifecycleTaskV2::decode(
                    &hex::decode(v["successor_statement"].as_str().unwrap()).unwrap(),
                )
                .unwrap()
            };
            let p = make(&node, tip, transactions, &signed, &lease, &m, &i);
            tip = node.admit(&p, s.genesis_time() + 10000).unwrap();
            node.activate(tip).unwrap();
        }
        assert_eq!(node.next_nonce(key(0)).unwrap(), 161);
        assert_eq!(node.next_nonce(key(1)).unwrap(), 2);
        assert_eq!(
            node.lifecycle_task_lease(tip, boot.signed.manifest.matrix_task, 21)
                .unwrap()
                .revision,
            2
        );
        let state = node.state_at(tip).unwrap();
        drop(node);
        let node = Node::open(&temp.path().join("owner"), s, 1).unwrap();
        assert_eq!(node.active().unwrap(), (tip, 20));
        assert_eq!(node.state_at(tip).unwrap(), state);
        for p in fs::read_dir(output).unwrap() {
            assert!(!p.unwrap().file_name().to_string_lossy().contains("secret"));
        }
        if let Some(destination) = std::env::var_os("TRNM_OPERATOR_PUBLIC_FIXTURE_DIRECTORY") {
            let destination = Path::new(&destination);
            DirBuilder::new().mode(0o700).create(destination).unwrap();
            for entry in fs::read_dir(output).unwrap() {
                let entry = entry.unwrap();
                offline::write_new_public(
                    &destination.join(entry.file_name()),
                    &fs::read(entry.path()).unwrap(),
                )
                .unwrap();
            }
            offline::write_new_public(&destination.join("local-test-observation.json"),&serde_json::to_vec_pretty(&json!({"schema":"operator-offline-fixture-local-test-v1","blocks":20,"transfers":160,"renewals":1,"tip":hex::encode(tip),"state_root":hex::encode(trnm_mvcc_fee::pon_executor::root(&state).unwrap()),"account_nonces":{"transfer":160,"requester":1},"scope":"actual single-host native PNW1 execution and reopen; explicitly disclosed deterministic test keys, logical header time, no physical/public/independent qualification","public_network_ready":false,"hardness_accepted":false,"production_activation":false})).unwrap()).unwrap();
        }
    }
    #[test]
    fn distinct_transfer_signer_allowed_but_requester_conflict_wrong_source_and_unfunded_miner_refused(
    ) {
        let d = tempfile::tempdir().unwrap();
        let (mut args, _) = inputs(d.path(), 5);
        run(&args).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(Path::new(&args[0]).join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["transfer_sender"], public(5));
        args[0] = d.path().join("bad-nonce").display().to_string();
        args[7] = args[6].clone();
        assert!(run(&args)
            .unwrap_err()
            .to_string()
            .contains("ACTOR_REQUESTER_TRANSFER_NONCE_CONFLICT"));
        assert!(!Path::new(&args[0]).exists());
        args[7] = d.path().join("transfer-secret").display().to_string();
        args[5] = args[6].clone();
        assert!(run(&args)
            .unwrap_err()
            .to_string()
            .contains("ACTOR_SIGNER_PIN"));
        assert!(!Path::new(&args[0]).exists());
        args[5] = d.path().join("source-secret").display().to_string();
        args[9] = public(9);
        assert!(run(&args)
            .unwrap_err()
            .to_string()
            .contains("ACTOR_MINER_FUNDING"));
        assert!(!Path::new(&args[0]).exists());
    }
}
