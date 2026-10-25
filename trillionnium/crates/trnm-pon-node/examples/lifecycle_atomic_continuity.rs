//! Real local PNW1 packets across the former1000-height fixture expiry. Logical
//! header spacing is not elapsed5h/72h, useful model output or public qualification.
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};
use trnm_crypto_primitives::{
    qualified_work_task::{
        lifecycle_v2::verify_lifecycle_admission, DevelopmentTaskAdmission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::qualified_task_lifecycle::slot_key;
use trnm_pon_node::{development_public, ingress, Node, Result, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
    qualified_work_task::lifecycle_v3::{AtomicRenewTaskV3, ATOMIC_RENEW_TAG, PROFILE},
};

mod source_inventory {
    include!("support/distributed_source_inventory.rs");
}
const POLICY: &str = "native-public-evaluation-dev-v1";
const RENEW_HEIGHT: u64 = 900;
const MIN_BLOCKS: u64 = 1005;
const MAX_BLOCKS: u64 = 1800;

fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn tree_bytes(path: &Path) -> std::io::Result<u64> {
    let mut count = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        count += if entry.file_type()?.is_dir() {
            tree_bytes(&entry.path())?
        } else {
            entry.metadata()?.len()
        };
    }
    Ok(count)
}
fn signature(who: u64, message: &[u8]) -> Result<[u8; 64]> {
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .map_err(|_| "DEVELOPMENT_KEY")?;
    hex::decode(sign_hex(&key, message))
        .map_err(|_| "SIGNATURE_HEX")?
        .try_into()
        .map_err(|_| "SIGNATURE_LENGTH".into())
}
fn transaction(node: &Node, who: u64, tag: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
    let sender = development_public(who)?;
    let mut tx = Envelope {
        network: node.settings().network(),
        sender,
        nonce: node.next_nonce(sender)?,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(who, &tx.signing_digest().map_err(|_| "TRANSACTION_DIGEST")?)?;
    tx.encode().map_err(|_| "TRANSACTION_CODEC".into())
}
fn resign(
    first: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    source_sequence: u64,
) -> Result<SignedLifecycleTaskV2> {
    let mut manifest = first.manifest.clone();
    manifest.source_record = lease.bound_source_record().map_err(|_| "LEASE")?;
    manifest.withdrawal_head = lease.withdrawal_frontier().map_err(|_| "LEASE")?;
    manifest.not_before = lease.not_before;
    manifest.expires = lease.expires;
    manifest.available_until = lease.available_until;
    manifest.demand_nonce = source_sequence;
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: lease.id().map_err(|_| "LEASE")?,
        manifest,
        signature: [0; 64],
    };
    signed.signature = signature(0, &signed.signing_message().map_err(|_| "TASK_SIGNING")?)?;
    Ok(signed)
}
fn material<'a>(model: &'a [u8], input: &'a [u8], a: &'a [u32], b: &'a [u32]) -> TaskMaterial<'a> {
    TaskMaterial { model, input, a, b }
}
fn admission(
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    artifacts: TaskMaterial<'_>,
    height: u64,
) -> Result<DevelopmentTaskAdmission> {
    verify_lifecycle_admission(
        &signed.encode().map_err(|_| "TASK_CODEC")?,
        artifacts,
        lease,
        height,
    )
    .map_err(|error| format!("TASK_ADMISSION:{error:?}").into())
}
fn quantiles(values: &[u128]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = |p: usize| sorted[(sorted.len() * p).div_ceil(100).saturating_sub(1)];
    json!({"count":sorted.len(),"sum_ns":sorted.iter().sum::<u128>(),
        "p50_ns":if sorted.is_empty(){None}else{Some(rank(50))},
        "p95_ns":if sorted.len()<20{None}else{Some(rank(95))},
        "p99_ns":if sorted.len()<100{None}else{Some(rank(99))},
        "maximum_ns":sorted.last(),"scope":"empirical sequential scheduling-inclusive samples; not independent confidence bounds"})
}
fn fingerprint() -> Result<Value> {
    let entries: Vec<_> = source_inventory::FILES
        .iter()
        .map(|(path, bytes)| {
            json!({"path":path,"bytes":bytes.len(),
        "digest":hex::encode(hash(b"lifecycle-atomic-continuity-source-file-v1",&[bytes]))})
        })
        .collect();
    let raw = serde_json::to_vec(&entries)?;
    let binary = fs::read(std::env::current_exe()?)?;
    Ok(
        json!({"schema":"lifecycle-atomic-continuity-source-v1","builder_commit_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),
        "builder_tree_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),"inventory":entries,
        "inventory_digest":hex::encode(hash(b"lifecycle-atomic-continuity-source-inventory-v1",&[&raw])),
        "example_digest":hex::encode(hash(b"lifecycle-atomic-continuity-example-v1",&[include_bytes!("lifecycle_atomic_continuity.rs")])),
        "binary_digest":hex::encode(hash(b"lifecycle-atomic-continuity-binary-v1",&[&binary])),"binary_bytes":binary.len(),
        "digest_encoding":"TRNM-PON1 domain-separated SHA256; not ordinary sha256sum",
        "scope":"compiled enumerated source/config bytes and builder Git claims; no independent build, host or public-network attestation; null Git claims mean uncommitted development observation"}),
    )
}
struct Journal {
    file: File,
    sequence: u64,
    previous: Hash,
    context: Hash,
}
impl Journal {
    fn append(&mut self, event: Value) -> Result<()> {
        let body = json!({"schema":"lifecycle-atomic-continuity-receipt-v1","sequence":self.sequence+1,
            "previous":hex::encode(self.previous),"context":hex::encode(self.context),"event":event});
        let digest = hash(
            b"lifecycle-atomic-continuity-receipt-v1",
            &[&serde_json::to_vec(&body)?],
        );
        let mut row = body;
        row["digest"] = json!(hex::encode(digest));
        self.file.write_all(&serde_json::to_vec(&row)?)?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        self.sequence += 1;
        self.previous = digest;
        Ok(())
    }
}
fn parse_arguments(args: &[String]) -> Result<(PathBuf, u64)> {
    require(
        (1..=2).contains(&args.len()),
        "usage: lifecycle_atomic_continuity NEW_DIRECTORY [BLOCKS1005..1800]",
    )?;
    let blocks = if args.len() == 2 {
        args[1].parse().map_err(|_| "BLOCKS")?
    } else {
        MIN_BLOCKS
    };
    require(
        (MIN_BLOCKS..=MAX_BLOCKS).contains(&blocks),
        "CONTINUITY_LIMIT",
    )?;
    Ok((PathBuf::from(&args[0]), blocks))
}
fn run() -> Result<()> {
    let (directory, blocks) = parse_arguments(&std::env::args().skip(1).collect::<Vec<_>>())?;
    fs::create_dir(&directory)?;
    fs::create_dir(directory.join("packets"))?;
    let wall_start = ingress::now()?;
    // All logical headers precede the observed wall clock. Ten seconds of header
    // spacing are not ten seconds of actual waiting. Fresh genesis is explicit.
    let genesis = wall_start.checked_sub((blocks + 8) * 10).ok_or("CLOCK")?;
    let settings = Settings::development_with_profiles(Some(genesis), POLICY, PROFILE)?;
    let bootstrap = settings.bootstrap_lifecycle_task()?;
    let (model, input, a, b) = settings.bootstrap_task_material()?;
    let source = fingerprint()?;
    write_new(
        &directory.join("source.json"),
        &serde_json::to_vec_pretty(&source)?,
    )?;
    write_new(&directory.join("maintenance-model.bin"), &model)?;
    write_new(&directory.join("maintenance-input.bin"), &input)?;
    write_new(
        &directory.join("bootstrap-source.qwa2"),
        &bootstrap.signed.encode().map_err(|_| "TASK_CODEC")?,
    )?;
    let configuration = json!({"schema":"lifecycle-atomic-continuity-config-v1","blocks":blocks,"renew_height":RENEW_HEIGHT,
        "reopen_heights":[900,1001],"evaluation_policy":POLICY,"task_profile":PROFILE,
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),"genesis_time":genesis,
        "clock_mode":"logical 10-second headers; actual wall clock observed at admission; no pace or duration claim",
        "source_inventory_digest":source["inventory_digest"],"binary_digest":source["binary_digest"],
        "maintenance_model":hex::encode(bootstrap.signed.manifest.model),"maintenance_input":hex::encode(bootstrap.signed.manifest.input),
        "atomic_renew_tag":22,"atomic_renew_payload_bytes":1028,"standalone_renew_tag19_disabled":true,"old_v2_pair_run_is_not_atomic":true,"development_private_keys_public_fixture":true,"maintenance_useful_output_limit":0,
        "public_network_ready":false,"hardness_accepted":false,"production_activation":false});
    let context = hash(
        b"lifecycle-atomic-continuity-context-v1",
        &[&serde_json::to_vec(&configuration)?],
    );
    write_new(
        &directory.join("config.json"),
        &serde_json::to_vec_pretty(&configuration)?,
    )?;
    let mut journal = Journal {
        file: OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.join("receipts.jsonl"))?,
        sequence: 0,
        previous: [0; 32],
        context,
    };
    let started = Instant::now();
    let mut node: Option<Node> = None;
    let mut attempted = 0_u64;
    let mut made_count = 0_u64;
    let mut admitted = 0_u64;
    let mut activated = 0_u64;
    let mut producer_trials = 0_u64;
    let mut proof_bytes = 0_u64;
    let mut packet_bytes = 0_u64;
    let mut make_samples = Vec::new();
    let mut admit_samples = Vec::new();
    let mut activate_samples = Vec::new();
    let mut rejection_attempts = 0_u64;
    let mut rejected = 0_u64;
    let mut reopen_attempts = 0_u64;
    let mut reopen_successes = 0_u64;
    let mut disk_peak = 0_u64;
    let mut stage = "open";
    let result = (|| -> Result<()> {
        node = Some(Node::open(&directory.join("node"), settings.clone(), 4)?);
        let mut lease = bootstrap.lease.clone();
        let mut signed = bootstrap.signed.clone();
        let first = admission(
            &bootstrap.signed,
            &bootstrap.lease,
            material(&model, &input, &a, &b),
            1,
        )?;
        let mut current = admission(&signed, &lease, material(&model, &input, &a, &b), 1)?;
        journal.append(json!({"kind":"opened","wall_utc_epoch":wall_start,"stats":node.as_ref().ok_or("NODE")?.stats()?}))?;
        for height in 1..=blocks {
            attempted += 1;
            let step_started = Instant::now();
            let n = node.as_mut().ok_or("NODE")?;
            let parent = n.active()?.0;
            require(n.parent_height(parent)? + 1 == height, "HEIGHT")?;
            let disk_before = tree_bytes(&directory.join("node"))?;
            let mut transactions = Vec::new();
            let mut successor = None;
            if height == RENEW_HEIGHT {
                let record = &n.read_active()?.2[&slot_key(0)?];
                let mut renewed = lease.clone();
                renewed.revision += 1;
                renewed.not_before = height;
                renewed.expires = height + 1000;
                renewed.available_until = renewed.expires + 100;
                let next = record["source_sequence"]
                    .as_u64()
                    .ok_or("SOURCE_SEQUENCE")?
                    .checked_add(1)
                    .ok_or("SOURCE_SEQUENCE")?;
                let replacement = resign(&signed, &renewed, next)?;
                require(
                    replacement.manifest.output_meter == signed.manifest.output_meter,
                    "METER_CHANGED",
                )?;
                let atomic = AtomicRenewTaskV3 {
                    lease: renewed.clone(),
                    signed: replacement.clone(),
                };
                let payload = atomic.encode().map_err(|_| "ATOMIC_CODEC")?;
                require(payload.len() == 1028, "ATOMIC_LENGTH")?;
                // These are normal invalid-control regressions, never a proof or
                // transport attack. Every failed make must leave durable state intact.
                let mut invalid = Vec::new();
                invalid.push((
                    "standalone19",
                    transaction(n, 1, 19, renewed.encode().map_err(|_| "LEASE_CODEC")?)?,
                ));
                let mut bad = atomic.clone();
                bad.signed.signature[0] ^= 1;
                invalid.push((
                    "source signature",
                    transaction(n, 1, 22, bad.encode().map_err(|_| "ATOMIC_CODEC")?)?,
                ));
                let mut bad = atomic.clone();
                bad.signed = resign(&signed, &renewed, next + 1)?;
                invalid.push((
                    "source sequence",
                    transaction(n, 1, 22, bad.encode().map_err(|_| "ATOMIC_CODEC")?)?,
                ));
                let mut badlease = renewed.clone();
                badlease.expires = lease.expires;
                badlease.available_until = lease.available_until;
                let bad = AtomicRenewTaskV3 {
                    signed: resign(&signed, &badlease, next)?,
                    lease: badlease,
                };
                invalid.push((
                    "window",
                    transaction(n, 1, 22, bad.encode().map_err(|_| "ATOMIC_CODEC")?)?,
                ));
                let mut partial = transaction(n, 1, 22, payload.clone())?;
                partial.remove(123);
                invalid.push(("partial", partial));
                let original = n.read_active()?;
                let stats = n.stats()?;
                for (case, raw) in invalid {
                    rejection_attempts += 1;
                    let failure = n.make_with_task(
                        parent,
                        vec![raw],
                        development_public(3)?,
                        genesis + height * 10,
                        4096,
                        &current,
                        material(&model, &input, &a, &b),
                    );
                    require(failure.is_err(), "INVALID_CONTROL_ACCEPTED")?;
                    require(
                        n.read_active()? == original && n.stats()? == stats,
                        "FAILED_CONTROL_MUTATED",
                    )?;
                    rejected += 1;
                    journal.append(json!({"kind":"expected-rejection","case":case,"height":height,
                        "error":failure.err().map(|e|e.to_string()),"durable_state_unchanged":true}))?;
                }
                transactions.push(transaction(n, 1, ATOMIC_RENEW_TAG, payload)?);
                write_new(
                    &directory.join("renewal-source.qwa2"),
                    &replacement.encode().map_err(|_| "TASK_CODEC")?,
                )?;
                successor = Some((renewed, replacement));
            }
            stage = "make";
            let clock = Instant::now();
            let packet = n.make_with_task(
                parent,
                transactions,
                development_public(3)?,
                genesis + height * 10,
                4096,
                &current,
                material(&model, &input, &a, &b),
            )?;
            let make_ns = clock.elapsed().as_nanos();
            make_samples.push(make_ns);
            made_count += 1;
            producer_trials = producer_trials
                .checked_add(packet.header.nonce + 1)
                .ok_or("TRIALS")?;
            let encoded = packet.encode()?;
            proof_bytes += packet.proof.len() as u64;
            packet_bytes += encoded.len() as u64;
            stage = "save-packet";
            write_new(
                &directory.join("packets").join(format!("{height:04}.bin")),
                &encoded,
            )?;
            stage = "admit";
            let clock = Instant::now();
            let observed_now = ingress::now()?;
            let id = n.admit(&packet, observed_now)?;
            let admit_ns = clock.elapsed().as_nanos();
            admit_samples.push(admit_ns);
            admitted += 1;
            stage = "activate";
            let clock = Instant::now();
            n.activate_observed(id, observed_now)?;
            let activate_ns = clock.elapsed().as_nanos();
            activate_samples.push(activate_ns);
            activated += 1;
            require(n.active()?.0 == id, "ACTIVE_TIP")?;
            let disk_after = tree_bytes(&directory.join("node"))?;
            disk_peak = disk_peak.max(disk_after);
            let record = n.read_active()?.2[&slot_key(0)?].clone();
            require(record["output_count"] == 0, "MAINTENANCE_OUTPUT")?;
            let ids: Vec<_> = packet
                .transactions
                .iter()
                .map(|raw| {
                    Envelope::decode(raw)
                        .and_then(|tx| tx.id())
                        .map(hex::encode)
                })
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| "TRANSACTION_CODEC")?;
            journal.append(json!({"kind":"packet","height":height,"parent":hex::encode(parent),"block":hex::encode(id),
                "packet_digest":hex::encode(hash(b"lifecycle-atomic-continuity-packet-v1",&[&encoded])),"packet_bytes":encoded.len(),
                "proof_magic":String::from_utf8_lossy(&packet.proof[..4]),"proof_bytes":packet.proof.len(),
                "header_timestamp":packet.header.timestamp,"admission_observed_wall_epoch":observed_now,
                "header_nonce":packet.header.nonce,"producer_search_trials":packet.header.nonce+1,
                "make_ns":make_ns,"admit_ns":admit_ns,"activate_ns":activate_ns,"local_step_ns":step_started.elapsed().as_nanos(),
                "native_store_bytes_before":disk_before,"native_store_bytes_after":disk_after,
                "transaction_ids":ids,"lease_record":record,"scope":"inprocess actual verifier/durable chain; no TCP/public attack or useful model-output claim"}))?;
            if let Some((renewed, replacement)) = successor {
                lease = renewed;
                signed = replacement;
                current = admission(
                    &signed,
                    &lease,
                    material(&model, &input, &a, &b),
                    height + 1,
                )?;
                stage = "old-admission-negative";
                rejection_attempts += 1;
                let clock = Instant::now();
                let old = n.make_with_task(
                    id,
                    vec![],
                    development_public(3)?,
                    genesis + (height + 1) * 10,
                    4096,
                    &first,
                    material(&model, &input, &a, &b),
                );
                require(old.is_err(), "STALE_ADMISSION_ACCEPTED")?;
                rejected += 1;
                journal.append(json!({"kind":"expected-rejection","case":"old admission after renewal","height":height,
                    "elapsed_ns":clock.elapsed().as_nanos(),"error":old.err().map(|error|error.to_string())}))?;
                rejection_attempts += 1;
                let clock = Instant::now();
                let implicit = n.make(
                    id,
                    vec![],
                    development_public(3)?,
                    genesis + (height + 1) * 10,
                    4096,
                );
                require(implicit.is_err(), "IMPLICIT_FALLBACK_ACCEPTED")?;
                rejected += 1;
                journal.append(json!({"kind":"expected-rejection","case":"implicit maintenance route underV3","height":height,
                    "elapsed_ns":clock.elapsed().as_nanos(),"error":implicit.err().map(|error|error.to_string())}))?;
            }
            if [900, 1001].contains(&height) {
                stage = "reopen";
                reopen_attempts += 1;
                let before = n.read_active()?;
                let stats = n.stats()?;
                drop(node.take());
                let clock = Instant::now();
                let reopened = Node::open(&directory.join("node"), settings.clone(), 4)?;
                let after = reopened.read_active()?;
                require(before == after, "REOPEN_STATE")?;
                reopen_successes += 1;
                journal.append(json!({"kind":"reopened","height":height,"elapsed_ns":clock.elapsed().as_nanos(),
                    "stats_before":stats,"stats_after":reopened.stats()?,"identical_active_tip_generation_and_state":true}))?;
                node = Some(reopened);
            }
            if height % 100 == 0 || height == blocks {
                println!(
                    "lifecycle_atomic_continuity height={height} elapsed_ms={}",
                    started.elapsed().as_millis()
                );
            }
        }
        require(
            activated >= MIN_BLOCKS && reopen_successes == 2 && rejected == 7,
            "CONTINUITY_INCOMPLETE",
        )?;
        Ok(())
    })();
    let error = result.as_ref().err().map(|failure| failure.to_string());
    journal.append(
        json!({"kind":"completed","success":result.is_ok(),"stage":stage,"error":error,
        "actual_elapsed_ns":started.elapsed().as_nanos(),"activated_packets":activated}),
    )?;
    let summary = json!({"schema":"lifecycle-atomic-continuity-report-v1","status":if result.is_ok(){"completed"}else{"failed"},
        "error":error,"last_stage":stage,"context":hex::encode(context),"configuration":configuration,
        "source_file":"source.json","attempted_block_heights":attempted,"made_packets":made_count,
        "admitted_packets":admitted,"activated_packets":activated,"producer_search_trials":producer_trials,
        "producer_trial_scope":"Node searches nonce0..budget; accepted header nonce+1 includes failed-target attempts; failed make has no reported partial trial count",
        "actual_elapsed_ns":started.elapsed().as_nanos(),"logical_header_span_seconds":activated*10,
        "clock_scope":"logical progression only; no actual5h/72h waiting, independent operators or public transport test",
        "proof_bytes":proof_bytes,"packet_bytes":packet_bytes,"native_store_peak_bytes":disk_peak,
        "total_artifact_bytes_before_report":tree_bytes(&directory)?,"make":quantiles(&make_samples),
        "admit":quantiles(&admit_samples),"activate":quantiles(&activate_samples),
        "reopen_attempts":reopen_attempts,"reopen_successes":reopen_successes,
        "expected_rejection_attempts":rejection_attempts,"observed_rejections":rejected,
        "receipt_rows":journal.sequence,"receipt_tail":hex::encode(journal.previous),
        "receipt_integrity_scope":"local hash chain detects accidental alteration; publicly reproducible fixture keys and local report are not independent attestation",
        "stats":node.as_ref().map(Node::stats).transpose()?,"maintenance_arithmetic_outputs":0,
        "public_network_ready":false,"work_profile_qualified":false,"hardness_accepted":false,
        "whole_model_utility_accepted":false,"production_activation":false});
    write_new(
        &directory.join("report.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("{}", serde_json::to_string(&summary)?);
    result
}
fn main() {
    if let Err(error) = run() {
        eprintln!("lifecycle_atomic_continuity failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cannot_report_short_or_unbounded_campaign_as_continuity() {
        let args = |blocks: &str| vec!["new-run".to_owned(), blocks.to_owned()];
        assert!(parse_arguments(&args("1004")).is_err());
        assert!(parse_arguments(&args("1801")).is_err());
        assert_eq!(parse_arguments(&args("1005")).unwrap().1, 1005);
        assert_eq!(parse_arguments(&["new-run".to_owned()]).unwrap().1, 1005);
    }
    #[test]
    fn empirical_cost_report_retains_denominator_and_tail_resolution() {
        assert_eq!(quantiles(&[])["count"], 0);
        let one = quantiles(&[5]);
        assert_eq!(one["count"], 1);
        assert_eq!(one["p50_ns"], 5);
        assert!(one["p95_ns"].is_null());
    }
}
