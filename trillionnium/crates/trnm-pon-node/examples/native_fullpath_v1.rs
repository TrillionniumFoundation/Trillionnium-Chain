//! Single-host development observations, not WAN, production or work-cost proof.
//! The parent timestamps flushed events; child durations have process-local clocks.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    sync::Mutex,
    time::Instant,
};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, pon_executor::growth as limits};
use trnm_pon_node::{
    development_public, Error, ErrorCode, GrowthPacket, GrowthProgress, Node, Result, Settings,
};
use trnm_protocol::{
    pon_growth::GROWTH_HEADER_BYTES,
    pon_wire::{hash, Envelope},
};

const NAMESPACE: &str = "pon-native-fullpath-development-v1";
const GENESIS_TIME: u64 = 1_700_000_000;
const NOW: u64 = GENESIS_TIME + 10;
const BOUNDARIES: [&str; 4] = [
    "BeforeReplay",
    "TranscriptTile",
    "BeforeProduct",
    "BeforeVerifiedWork",
];

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn settings() -> Result<Settings> {
    Settings::development_with_profiles(
        Some(GENESIS_TIME),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )?
    .with_permanent_account_growth_v2(NAMESPACE)
}
fn emit(event: &str, receipt: &Value) -> Result<()> {
    let mut value = receipt.clone();
    value["schema"] = json!("pon-native-fullpath-process-v1");
    value["event"] = json!(event);
    value["pid"] = json!(std::process::id());
    value["namespace"] = json!(NAMESPACE);
    value["development"] = json!(true);
    value["compressed_proof_generation_ns"] = Value::Null;
    value["compression_status"] = json!("not_applicable_native_full_verification");
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn read_packet(input: impl Read) -> Result<(GrowthPacket, Vec<u8>)> {
    let mut bytes = Vec::new();
    input
        .take(limits::MAX_PACKET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() <= limits::MAX_PACKET_BYTES, "PACKET_LIMIT")?;
    let packet = GrowthPacket::decode(&bytes)?;
    require(packet.encode()? == bytes, "FULLPATH_NONCANONICAL_PACKET")?;
    Ok((packet, bytes))
}
fn identity(packet: &GrowthPacket, bytes: &[u8]) -> Result<Value> {
    let witness = packet
        .accounts
        .encode()
        .map_err(|e| Error::from(format!("WITNESS:{e:?}")))?;
    let body_start = 4 + GROWTH_HEADER_BYTES;
    let body_end = bytes
        .len()
        .checked_sub(pon_work::PROOF_BYTES + witness.len() + 4)
        .ok_or("PACKET_LENGTH")?;
    let body = bytes.get(body_start..body_end).ok_or("PACKET_LENGTH")?;
    Ok(json!({
        "claim": {"header_hex":hex::encode(packet.header.encode()),
            "trace_hex":hex::encode(&packet.proof[packet.proof.len()-32..]),
            "body_sha256":hex::encode(Sha256::digest(body)),
            "witness_sha256":hex::encode(Sha256::digest(&witness)),
            "packet_sha256":hex::encode(Sha256::digest(bytes))},
        "body_hash_scope":"PNP2 transaction-count and length-prefixed transaction bytes",
        "block_hex":hex::encode(packet.id()?), "parent_hex":hex::encode(packet.header.ledger.parent),
        "task_hex":hex::encode(packet.header.ledger.work_task), "challenge_hex":hex::encode(packet.header.challenge()),
        "packet_bytes":bytes.len(), "height":packet.header.ledger.height,
        "nonce":packet.header.ledger.nonce, "transaction_count":packet.transactions.len()
    }))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|e| Error::from(e.error))?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn transfer(settings: &Settings) -> Result<Vec<u8>> {
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
        .map_err(|_| "DEVELOPMENT_KEY")?;
    let mut payload = development_public(1)?.to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0)?,
        nonce: 1,
        expiry: 1000,
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
#[derive(Default)]
struct WorkProgress {
    counts: [u64; 4],
    first_ns: [Option<u128>; 4],
    last_ns: [Option<u128>; 4],
}
impl WorkProgress {
    fn observe(&mut self, point: pon_work::VerificationProgress, elapsed: u128) {
        let index = match point {
            pon_work::VerificationProgress::BeforeReplay => 0,
            pon_work::VerificationProgress::TranscriptTile { .. } => 1,
            pon_work::VerificationProgress::BeforeProduct => 2,
            pon_work::VerificationProgress::BeforeVerifiedWork => 3,
            _ => return,
        };
        self.counts[index] += 1;
        self.first_ns[index].get_or_insert(elapsed);
        self.last_ns[index] = Some(elapsed);
    }
    fn report(&self) -> Value {
        let mut result = json!({"scope":"admission_call_only; cold-open and observer replay excluded",
            "clock":"nanoseconds since this process admission call", "expected_transcript_tiles":(pon_work::N/pon_work::R).pow(3)});
        for (index, name) in BOUNDARIES.iter().enumerate() {
            result[*name] = json!({"count":self.counts[index], "first_ns":self.first_ns[index], "last_ns":self.last_ns[index]});
        }
        result
    }
}
fn produce(store: &Path, output: &Path, attempts: u64, receipt: &mut Value) -> Result<()> {
    receipt["stage"] = json!("search");
    match fs::symlink_metadata(output) {
        Ok(_) => return Err("FULLPATH_OUTPUT_EXISTS".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let start = Instant::now();
    let settings = settings()?;
    fs::create_dir(store)?;
    let node = Node::open_with_permanent_account_growth_v2(store, settings.clone())?;
    let opened = Instant::now();
    let transactions = vec![transfer(&settings)?];
    let signed = Instant::now();
    receipt["search_attempt_limit"] = json!(attempts);
    receipt["stage"] = json!("search");
    let result = node.make_growth_consensus_maintenance(
        settings.genesis(),
        transactions,
        development_public(2)?,
        NOW,
        attempts,
    );
    let made = Instant::now();
    receipt["execute_and_search_ns"] = json!(made.duration_since(signed).as_nanos());
    let packet = result?;
    let bytes = packet.encode()?; // Identity serialization belongs to the parent search span.
    *receipt = identity(&packet, &bytes)?;
    receipt["search_attempt_limit"] = json!(attempts);
    receipt["nonce_attempts"] = json!(packet
        .header
        .ledger
        .nonce
        .checked_add(1)
        .ok_or("NONCE_OVERFLOW")?);
    receipt["setup_ns"] = json!(opened.duration_since(start).as_nanos());
    receipt["construct_sign_ns"] = json!(signed.duration_since(opened).as_nanos());
    receipt["execute_and_search_ns"] = json!(made.duration_since(signed).as_nanos());
    receipt["search_scope"] = json!("setup, signed transfer, M06, complete native candidate generation and nonce search; identity serialization before event");
    emit("search_complete", receipt)?;
    receipt["stage"] = json!("winner_prepare");
    let prepared = Instant::now();
    let canonical = packet.encode()?;
    require(
        canonical == bytes && GrowthPacket::decode(&canonical)?.encode()? == canonical,
        "FULLPATH_NONCANONICAL_PACKET",
    )?;
    write_new(output, &canonical)?;
    receipt["serialize_and_persist_ns"] = json!(prepared.elapsed().as_nanos());
    drop(node);
    emit("produce_complete", receipt)
}
fn receive(store: &Path, existing: bool, cancel: bool, receipt: &mut Value) -> Result<()> {
    let reading = Instant::now();
    let (packet, bytes) = read_packet(io::stdin().lock())?;
    *receipt = identity(&packet, &bytes)?;
    receipt["read_decode_canonical_ns"] = json!(reading.elapsed().as_nanos());
    emit("packet_received", receipt)?;
    receipt["stage"] = json!("verification");
    let opening = Instant::now();
    if existing {
        require(
            store.join("native.sqlite").is_file(),
            "FULLPATH_EXISTING_STORE_REQUIRED",
        )?;
    } else {
        fs::create_dir(store)?;
    }
    let mut node = Node::open_with_permanent_account_growth_v2(store, settings()?)?;
    receipt["node_open_ns"] = json!(opening.elapsed().as_nanos());
    let before = node.active()?;
    receipt["active_before_hex"] = json!(hex::encode(before.0));
    let progress = Mutex::new(WorkProgress::default());
    let checking = Instant::now();
    let admitted = node.admit_growth_with_progress(&packet, NOW, &|point| {
        if let GrowthProgress::Work(point) = point {
            progress
                .lock()
                .map_err(|_| Error::from("FULLPATH_PROGRESS_POISON"))?
                .observe(point, checking.elapsed().as_nanos());
            if cancel && point == pon_work::VerificationProgress::BeforeVerifiedWork {
                return Err(Error::new(ErrorCode::PublicRequestCancelled));
            }
        }
        Ok(())
    });
    receipt["admission_call_ns"] = json!(checking.elapsed().as_nanos());
    let progress = progress
        .into_inner()
        .map_err(|_| "FULLPATH_PROGRESS_POISON")?;
    receipt["work_progress"] = progress.report();
    let id = admitted?;
    require(!cancel, "FULLPATH_CANCELLATION_NOT_OBSERVED")?;
    let duplicate = progress.counts == [0; 4];
    require(
        duplicate || progress.counts == [1, (pon_work::N / pon_work::R).pow(3) as u64, 1, 1],
        "FULLPATH_INCOMPLETE_REPLAY",
    )?;
    receipt["admission_reused_existing"] = json!(duplicate);
    receipt["admitted_block_hex"] = json!(hex::encode(id));
    emit("admission_complete", receipt)?;
    receipt["stage"] = json!("acceptance");
    let activating = Instant::now();
    let active = node.activate(id)?;
    receipt["activate_ns"] = json!(activating.elapsed().as_nanos());
    receipt["active_after_hex"] = json!(hex::encode(active));
    receipt["active_changed"] = json!(active != before.0);
    receipt["generation_after"] = json!(node.active()?.1);
    drop(node); // Close the writer before the separate read-only snapshot observer.
    emit("receive_complete", receipt)
}
fn observe(store: &Path, input: &Path, receipt: &mut Value) -> Result<()> {
    let (packet, bytes) = read_packet(fs::File::open(input)?)?;
    *receipt = identity(&packet, &bytes)?;
    receipt["stage"] = json!("observation");
    require(
        store.join("native.sqlite").is_file(),
        "FULLPATH_EXISTING_STORE_REQUIRED",
    )?;
    let opening = Instant::now();
    let node = Node::open_growth_packet_observer(store, settings()?)?;
    receipt["observer_open_ns"] = json!(opening.elapsed().as_nanos());
    let checking = Instant::now();
    let observation = node.growth_exact_packet_observation(&packet)?;
    require(
        observation["block"] == receipt["block_hex"],
        "FULLPATH_OBSERVER_IDENTITY",
    )?;
    receipt["observation_ns"] = json!(checking.elapsed().as_nanos());
    receipt["native_observation"] = observation; // Absence remains absence; no forced successful verdict.
    drop(node);
    emit("observe_complete", receipt)
}
fn run(receipt: &mut Value) -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    require(
        args.get(1).map(String::as_str) == Some("--development"),
        "usage: native_fullpath_v1 COMMAND --development [STORE] [PACKET] [SEARCH_ATTEMPTS]",
    )?;
    match args[0].as_str() {
        "context" if args.len() == 2 => {
            let settings = settings()?;
            *receipt = json!({"network_hex":hex::encode(settings.network()), "parameters_hex":hex::encode(settings.parameters()),
                "genesis_hex":hex::encode(settings.genesis()), "parent_hex":hex::encode(settings.genesis()),
                "task_hex":hex::encode(continuity_v1::maintenance_task()?), "genesis_time":GENESIS_TIME,
                "timestamp":NOW, "logical_now":NOW, "logical_clock":true,
                "sender_hex":hex::encode(development_public(0)?), "recipient_hex":hex::encode(development_public(1)?),
                "miner_hex":hex::encode(development_public(2)?), "packet_limit":limits::MAX_PACKET_BYTES,
                "production_activation":false, "quantum_lower_bound_proved":false});
            emit("context", receipt)
        }
        "produce" if args.len() == 5 => {
            let attempts: u64 = args[4].parse().map_err(|_| "SEARCH_ATTEMPTS")?;
            require((1..=1_000_000).contains(&attempts), "SEARCH_ATTEMPTS")?;
            produce(Path::new(&args[2]), Path::new(&args[3]), attempts, receipt)
        }
        "receive" | "receive-cancel" | "resubmit" if args.len() == 3 => receive(
            Path::new(&args[2]),
            args[0] == "resubmit",
            args[0] == "receive-cancel",
            receipt,
        ),
        "observe" if args.len() == 4 => observe(Path::new(&args[2]), Path::new(&args[3]), receipt),
        _ => Err("FULLPATH_ARGUMENTS".into()),
    }
}
fn main() {
    let started = Instant::now();
    let mut receipt = json!({"stage":"arguments"});
    if let Err(error) = run(&mut receipt) {
        receipt["schema"] = json!("pon-native-fullpath-process-v1");
        receipt["event"] = json!("error");
        receipt["status"] = json!("error");
        receipt["error"] = json!(error.to_string());
        receipt["cancelled"] = json!(error.is(ErrorCode::PublicRequestCancelled));
        receipt["process_elapsed_ns"] = json!(started.elapsed().as_nanos());
        eprintln!("{receipt}");
        std::process::exit(2);
    }
}
