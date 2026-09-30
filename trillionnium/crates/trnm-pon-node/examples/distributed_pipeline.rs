//! Separate durable development roles; LAN execution is never inferred from local tests.
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::qualified_work_task::{verify_development_admission, TaskMaterial};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex, verify_hex_strict};
use trnm_pon_node::{
    development_public, digest,
    ingress::{self, AuthenticatedClient, AuthenticatedServer, DevelopmentIdentity, Request},
    Node, Packet, Result, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};
mod source_inventory {
    include!("support/distributed_source_inventory.rs");
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourcePin {
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub inventory_digest: String,
    pub binary_digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub role: String,
    pub scope: String,
    pub run_id: String,
    pub run_root: PathBuf,
    pub source_pin: SourcePin,
    pub genesis_time: u64,
    pub workers: usize,
    pub evaluation_policy: String,
    pub task_profile: String,
    pub pattern: String,
    pub data_blocks: usize,
    pub transactions_per_block: usize,
    pub drain_blocks: usize,
    pub pace_ms: u64,
    pub server_seconds: u64,
    pub poll_ms: u64,
    pub timeout_seconds: u64,
    pub listen: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub auth_secret: PathBuf,
    pub peer_roster: Option<PathBuf>,
    pub server_public: Option<String>,
    pub session_generation: u64,
}
fn ensure(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn fixed_hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn fingerprint() -> Result<Value> {
    let entries: Vec<_> = source_inventory::FILES.iter().map(|(path, bytes)| json!({"path":path,"bytes":bytes.len(),"digest":hex::encode(hash(b"distributed-source-file-v1", &[bytes]))})).collect();
    let raw = serde_json::to_vec(&entries)?;
    let executable = std::env::current_exe()?;
    let binary = bounded_read(&executable, 536_870_912)?;
    Ok(
        json!({"schema":"pon-distributed-fingerprint-v1","commit":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),"tree":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),"inventory_digest":hex::encode(hash(b"distributed-source-inventory-v1", &[&raw])),"inventory":entries,"binary_digest":hex::encode(hash(b"distributed-binary-v1", &[&binary])),"binary_bytes":binary.len(),"digest_encoding":"TRNM-PON1 domain-separated SHA256, not ordinary sha256sum","build_provenance_scope":"builder-pinned Git identifiers and embedded source bytes; not remote hardware attestation","production_activation":false,"public_network_ready":false}),
    )
}
fn pin_of(fp: &Value) -> Result<SourcePin> {
    Ok(serde_json::from_value(
        json!({"commit":fp["commit"],"tree":fp["tree"],"inventory_digest":fp["inventory_digest"],"binary_digest":fp["binary_digest"]}),
    )?)
}
fn validate_config(c: &Config, actual: &SourcePin) -> Result<()> {
    ensure(
        c.schema == "pon-distributed-role-config-v1",
        "CONFIG_SCHEMA",
    )?;
    ensure(
        matches!(c.role.as_str(), "producer" | "validator" | "confirmer"),
        "CONFIG_ROLE",
    )?;
    ensure(
        matches!(c.scope.as_str(), "lan-development" | "local-process-test"),
        "CONFIG_SCOPE",
    )?;
    ensure(
        !c.run_id.is_empty()
            && c.run_id.len() <= 64
            && c.run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "RUN_ID",
    )?;
    ensure(c.run_root.is_absolute(), "RUN_ROOT")?;
    ensure(
        c.source_pin == *actual
            && fixed_hex(&actual.inventory_digest, 64)
            && fixed_hex(&actual.binary_digest, 64),
        "SOURCE_PIN",
    )?;
    if c.scope == "lan-development" {
        ensure(
            actual.commit.as_ref().is_some_and(|s| fixed_hex(s, 40))
                && actual.tree.as_ref().is_some_and(|s| fixed_hex(s, 40)),
            "BUILD_SOURCE_PIN_REQUIRED",
        )?;
        let a = if c.role == "validator" {
            c.listen
        } else {
            c.peer
        }
        .ok_or("ADDRESS_REQUIRED")?;
        ensure(
            !a.ip().is_loopback() && !a.ip().is_unspecified() && a.port() != 0,
            "LAN_ADDRESS",
        )?;
        ensure(c.pace_ms >= 1000, "LIVE_PACING_REQUIRED")?;
    }
    ensure(
        c.genesis_time > 0
            && c.genesis_time <= ingress::now()?
            && c.genesis_time <= i64::MAX as u64,
        "GENESIS_TIME",
    )?;
    ensure([1, 2, 4, 8].contains(&c.workers), "WORKERS")?;
    ensure(
        c.task_profile == "signed-task-dev-v1"
            && matches!(
                c.evaluation_policy.as_str(),
                "closed-round-all-eligible-min-v1" | "native-public-evaluation-dev-v1"
            ),
        "PROFILE",
    )?;
    ensure(matches!(c.pattern.as_str(), "hot" | "disjoint4"), "PATTERN")?;
    ensure(
        (1..=128).contains(&c.data_blocks)
            && (1..=256).contains(&c.transactions_per_block)
            && (6..=32).contains(&c.drain_blocks)
            && c.data_blocks + c.drain_blocks <= 1000,
        "CAMPAIGN_BOUNDS",
    )?;
    ensure(
        c.pace_ms <= 60_000
            && (1..=3600).contains(&c.server_seconds)
            && (10..=10000).contains(&c.poll_ms)
            && (1..=3500).contains(&c.timeout_seconds),
        "TIME_BOUNDS",
    )?;
    ensure(
        (c.data_blocks + c.drain_blocks) as u64 * c.pace_ms < c.server_seconds * 1000
            && c.timeout_seconds <= c.server_seconds,
        "LIFETIME_BUDGET",
    )?;
    ensure(
        (1..=i64::MAX as u64).contains(&c.session_generation),
        "AUTH_GENERATION",
    )?;
    if c.role == "validator" {
        ensure(
            c.listen.is_some()
                && c.peer_roster.is_some()
                && c.peer.is_none()
                && c.server_public.is_none(),
            "VALIDATOR_OPTIONS",
        )?;
    } else {
        ensure(
            c.peer.is_some()
                && c.server_public.as_ref().is_some_and(|s| fixed_hex(s, 64))
                && c.listen.is_none()
                && c.peer_roster.is_none(),
            "CLIENT_OPTIONS",
        )?;
    }
    Ok(())
}
fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure(bytes.len() as u64 <= limit, "INPUT_LIMIT")?;
    Ok(bytes)
}
fn owned_read(path: &Path, limit: u64, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    let mode = m.permissions().mode();
    ensure(
        m.is_file()
            && m.nlink() == 1
            && if private {
                mode & 0o077 == 0
            } else {
                mode & 0o022 == 0
            },
        "AUTH_FILE",
    )?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure(bytes.len() as u64 <= limit, "AUTH_LENGTH")?;
    Ok(bytes)
}
fn secret(c: &Config) -> Result<String> {
    let raw = owned_read(&c.auth_secret, 65, true)?;
    let text = std::str::from_utf8(&raw).map_err(|_| "AUTH_ENCODING")?;
    let s = text.strip_suffix('\n').unwrap_or(text);
    ensure(fixed_hex(s, 64), "AUTH_SECRET")?;
    DevelopmentIdentity::from_secret_hex(s)?;
    Ok(s.into())
}
fn settings(c: &Config) -> Result<Settings> {
    Settings::development_with_profiles(Some(c.genesis_time), &c.evaluation_policy, &c.task_profile)
}
fn client(c: &Config, secret: &str) -> Result<AuthenticatedClient> {
    AuthenticatedClient::new(
        DevelopmentIdentity::from_secret_hex(secret)?,
        c.server_public.clone().ok_or("SERVER_PUBLIC")?,
        c.session_generation,
    )
}
fn save_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn retain_exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        ensure(
            owned_read(path, 268_435_456, true)? == bytes,
            "RECOVERY_ARTIFACT_CONFLICT",
        )
    } else {
        save_new(path, bytes)
    }
}
struct Receipts {
    file: File,
    secret: String,
    sequence: u64,
    previous: String,
    common: Value,
}
impl Receipts {
    fn open(
        c: &Config,
        fp: Value,
        secret: String,
        raw_config: &[u8],
        resume: bool,
    ) -> Result<Self> {
        let key = DevelopmentIdentity::from_secret_hex(&secret)?;
        let roster_digest = c
            .peer_roster
            .as_ref()
            .map(|path| {
                owned_read(path, 16384, false)
                    .map(|raw| hex::encode(hash(b"distributed-peer-roster-file-v1", &[&raw])))
            })
            .transpose()?;
        let common = json!({"run_id":c.run_id,"role":c.role,"scope":c.scope,"source":pin_of(&fp)?,"source_inventory_file":"fingerprint.json","config_file":"config.json","config_file_digest":hex::encode(hash(b"distributed-role-config-file-v1", &[raw_config])),"peer_roster_file_digest":roster_digest,"role_public":key.public_key(),"genesis_time":c.genesis_time,"evaluation_policy":c.evaluation_policy,"task_profile":c.task_profile,"pattern":c.pattern,"data_blocks":c.data_blocks,"transactions_per_block":c.transactions_per_block,"drain_blocks":c.drain_blocks,"pace_ms":c.pace_ms,"session_generation":c.session_generation,"lan_requested":c.scope=="lan-development","physical_host_verified":false,"public_network_ready":false,"production_activation":false,"independent_accepted":false,"work_profile_qualified":false});
        if !resume {
            fs::create_dir(&c.run_root)?;
            fs::set_permissions(&c.run_root, fs::Permissions::from_mode(0o700))?;
            fs::create_dir(c.run_root.join("packets"))?;
            save_new(
                &c.run_root.join("fingerprint.json"),
                &serde_json::to_vec(&fp)?,
            )?;
            save_new(&c.run_root.join("config.json"), raw_config)?;
        } else {
            let meta = fs::symlink_metadata(&c.run_root)?;
            ensure(
                meta.is_dir() && !meta.file_type().is_symlink() && meta.mode() & 0o077 == 0,
                "RESUME_ROOT",
            )?;
            ensure(
                owned_read(&c.run_root.join("config.json"), 65536, true)? == raw_config,
                "RESUME_CONFIG_BYTES",
            )?;
            ensure(
                owned_read(&c.run_root.join("fingerprint.json"), 4_194_304, true)?
                    == serde_json::to_vec(&fp)?,
                "RESUME_SOURCE_BYTES",
            )?;
            for name in ["store", "packets"] {
                let meta = fs::symlink_metadata(c.run_root.join(name))?;
                ensure(
                    meta.is_dir() && !meta.file_type().is_symlink(),
                    "RESUME_STORE_REQUIRED",
                )?;
            }
        }
        let path = c.run_root.join("receipts.jsonl");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        if !resume {
            options.create_new(true).mode(0o600);
        }
        let mut file = options.open(&path)?;
        let meta = file.metadata()?;
        ensure(
            meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
            "RECEIPT_FILE",
        )?;
        FileExt::try_lock_exclusive(&file)?;
        let mut sequence = 0u64;
        let mut previous = "00".repeat(32);
        if resume {
            let mut raw = Vec::new();
            (&mut file).take(268_435_457).read_to_end(&mut raw)?;
            ensure(raw.len() <= 268_435_456, "RECEIPT_LIMIT")?;
            let committed = raw.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            for terminated in raw[..committed].split_inclusive(|b| *b == b'\n') {
                let line = &terminated[..terminated.len() - 1];
                ensure(
                    !line.is_empty() && line.len() <= 8_388_608,
                    "RECEIPT_ROW_LENGTH",
                )?;
                let row: Value = serde_json::from_slice(line)?;
                let map = row.as_object().ok_or("RECEIPT_ROW")?;
                ensure(
                    map.len() == 3
                        && map.contains_key("body")
                        && map.contains_key("receipt_digest")
                        && map.contains_key("signature"),
                    "RECEIPT_FIELDS",
                )?;
                let body = &row["body"];
                ensure(
                    body.as_object().is_some_and(|m| m.len() == 7)
                        && body["event"].as_str().is_some_and(|s| !s.is_empty())
                        && body["observed_utc"].as_u64().is_some(),
                    "RECEIPT_BODY",
                )?;
                ensure(
                    body["schema"] == "pon-distributed-receipt-v1"
                        && body["sequence"] == sequence
                        && body["previous"] == previous
                        && body["run"] == common,
                    "RECEIPT_CHAIN",
                )?;
                let id = hash(b"distributed-receipt-v1", &[&serde_json::to_vec(body)?]);
                ensure(
                    row["receipt_digest"] == hex::encode(id) && serde_json::to_vec(&row)? == line,
                    "RECEIPT_DIGEST_CANONICAL",
                )?;
                verify_hex_strict(
                    key.public_key(),
                    &id,
                    row["signature"].as_str().ok_or("RECEIPT_SIGNATURE")?,
                )
                .map_err(|_| "RECEIPT_SIGNATURE")?;
                ensure(
                    body["event"] != format!("{}-complete", c.role),
                    "RESUME_ALREADY_COMPLETE",
                )?;
                previous = hex::encode(id);
                sequence += 1;
            }
            if committed != raw.len() {
                // Only an unterminated final row is uncommitted. Every completed row
                // was verified first; never normalize a signed or corrupt full row.
                let id = hex::encode(hash(b"distributed-recovery-original-v1", &[&raw]));
                retain_exact(
                    &c.run_root
                        .join(format!("receipts-before-tail-recovery-{id}.jsonl")),
                    &raw,
                )?;
                retain_exact(
                    &c.run_root
                        .join(format!("receipt-uncommitted-tail-{id}.bin")),
                    &raw[committed..],
                )?;
                let current = fs::symlink_metadata(&path)?;
                ensure(
                    current.dev() == meta.dev()
                        && current.ino() == meta.ino()
                        && current.len() == raw.len() as u64,
                    "RECEIPT_PATH_CHANGED",
                )?;
                file.set_len(committed as u64)?;
                file.sync_all()?;
            }
        }
        file.seek(SeekFrom::End(0))?;
        let mut result = Self {
            file,
            secret,
            sequence,
            previous,
            common,
        };
        if resume {
            result.emit("role-resumed", json!({"pid":std::process::id(),"prior_committed_rows":sequence,"same_config_source_and_identity":true,"duration_scope":"new process segment only; no clock subtraction across restarts"}))?;
        }
        Ok(result)
    }
    fn emit(&mut self, event: &str, payload: Value) -> Result<()> {
        let body = json!({"schema":"pon-distributed-receipt-v1","sequence":self.sequence,"previous":self.previous,"event":event,"run":self.common,"observed_utc":ingress::now()?,"payload":payload});
        let bytes = serde_json::to_vec(&body)?;
        let id = hash(b"distributed-receipt-v1", &[&bytes]);
        let key = signing_key_from_hex(&self.secret).map_err(|_| "AUTH_KEY")?;
        let row =
            json!({"body":body,"receipt_digest":hex::encode(id),"signature":sign_hex(&key,&id)});
        serde_json::to_writer(&mut self.file, &row)?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        println!(
            "{}",
            json!({"event":event,"sequence":self.sequence,"receipt_digest":hex::encode(id),"payload_summary":if matches!(event,"validator-listening"|"producer-complete"|"validator-complete"|"confirmer-complete"|"role-failed"){payload.clone()}else{Value::Null}})
        );
        std::io::stdout().flush()?;
        self.sequence += 1;
        self.previous = hex::encode(id);
        Ok(())
    }
}
fn transactions_inner(
    c: &Config,
    s: &Settings,
    height: usize,
    signed: bool,
) -> Result<Vec<Vec<u8>>> {
    if height > c.data_blocks {
        return Ok(Vec::new());
    }
    let mut counts = BTreeMap::<u64, u64>::new();
    for prior in 1..height {
        for offset in 0..c.transactions_per_block {
            let i = if c.pattern == "hot" {
                0
            } else {
                ((prior - 1 + offset) % 4) as u64
            };
            *counts.entry(i).or_default() += 1;
        }
    }
    let mut result = Vec::new();
    for offset in 0..c.transactions_per_block {
        let i = if c.pattern == "hot" {
            0
        } else {
            ((height - 1 + offset) % 4) as u64
        };
        let nonce = counts.entry(i).or_default();
        *nonce += 1;
        let recipient = hash(
            b"distributed-receiver-v1",
            &[c.run_id.as_bytes(), &i.to_le_bytes()],
        );
        let mut payload = recipient.to_vec();
        payload.extend(1u64.to_le_bytes());
        let mut tx = Envelope {
            network: s.network(),
            sender: development_public(i)?,
            nonce: *nonce,
            expiry: (c.data_blocks + c.drain_blocks + 128) as u64,
            fee_limit: 1_000_000,
            tag: 1,
            payload,
            signature: [0; 64],
        };
        if signed {
            let key =
                signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&i.to_le_bytes()])))
                    .map_err(|_| "TRANSACTION_KEY")?;
            tx.signature =
                hex::decode(sign_hex(&key, &tx.signing_digest().map_err(|_| "TX_SIGN")?))
                    .map_err(|_| "TX_SIGN")?
                    .try_into()
                    .map_err(|_| "TX_SIGN")?;
            result.push(tx.encode().map_err(|_| "TX_ENCODING")?);
        } else {
            result.push(tx.unsigned().map_err(|_| "TX_ENCODING")?);
        }
    }
    Ok(result)
}
fn transactions(c: &Config, s: &Settings, height: usize) -> Result<Vec<Vec<u8>>> {
    transactions_inner(c, s, height, true)
}
fn make(c: &Config, node: &Node, height: usize, timestamp: u64) -> Result<Packet> {
    let s = node.settings();
    let signed = s.bootstrap_task_statement()?;
    let wire = signed.encode().map_err(|_| "TASK_WIRE")?;
    let (model, input, a, b) = s.bootstrap_task_material()?;
    let context = s.qualified_task_context(signed.manifest.demand_id, height as u64)?;
    let admitted = verify_development_admission(
        &wire,
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &context,
    )
    .map_err(|_| "TASK_ADMISSION")?;
    node.make_with_task(
        node.active()?.0,
        transactions(c, s, height)?,
        development_public(0)?,
        timestamp,
        4096,
        &admitted,
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
    )
}
fn ancestry(node: &Node, tip: [u8; 32]) -> Result<Vec<Packet>> {
    let mut result = Vec::new();
    let mut cursor = tip;
    while cursor != node.settings().genesis() {
        let packet = node.packet(cursor)?;
        ensure(packet.id()? == cursor, "PACKET_ID")?;
        cursor = packet.header.parent;
        result.push(packet);
        ensure(result.len() <= 1000, "HISTORY_BOUNDS")?;
    }
    result.reverse();
    Ok(result)
}
type TransactionMembership = ([u8; 32], [u8; 32]);
type BlockConfirmationQueries = Vec<TransactionMembership>;
fn checked_workload(c: &Config, node: &Node) -> Result<Vec<BlockConfirmationQueries>> {
    let packets = ancestry(node, node.active()?.0)?;
    ensure(
        packets.len() <= c.data_blocks + c.drain_blocks,
        "UNEXPECTED_HEIGHT",
    )?;
    let mut groups = Vec::new();
    for (index, packet) in packets.iter().enumerate() {
        let planned = transactions_inner(c, node.settings(), index + 1, false)?;
        ensure(
            packet.header.height == (index + 1) as u64
                && packet.transactions.len() == planned.len(),
            "BUSINESS_CONTENT",
        )?;
        for (raw, expected) in packet.transactions.iter().zip(&planned) {
            let tx = Envelope::decode(raw).map_err(|_| "BUSINESS_ENCODING")?;
            ensure(
                tx.unsigned().map_err(|_| "BUSINESS_ENCODING")? == *expected,
                "BUSINESS_CONTENT",
            )?;
            // Native admission already performed strict signature verification;
            // this stage checks planned business fields, not a second signature pass.
        }
        if !packet.transactions.is_empty() {
            let id = packet.id()?;
            groups.push(
                packet
                    .transactions
                    .iter()
                    .map(|raw| (hash(b"tx-id", &[raw]), id))
                    .collect(),
            );
        }
    }
    Ok(groups)
}
fn context_matches(s: &Settings, value: &Value) -> Result<()> {
    ensure(
        value["network"] == hex::encode(s.network())
            && value["parameters"] == hex::encode(s.parameters())
            && value["genesis"] == hex::encode(s.genesis()),
        "HEAD_CONTEXT",
    )
}
fn retain_packet(c: &Config, packet: &Packet) -> Result<()> {
    let id = hex::encode(packet.id()?);
    let path = c.run_root.join("packets").join(format!("{id}.pnk1"));
    let expected = packet.encode()?;
    if path.exists() {
        let raw = owned_read(&path, 8_388_608, true)?;
        if raw != expected {
            let damaged = hex::encode(hash(b"distributed-damaged-packet-v1", &[&raw]));
            retain_exact(
                &c.run_root
                    .join(format!("damaged-packet-{id}-{damaged}.bin")),
                &raw,
            )?;
            fs::rename(
                &path,
                c.run_root
                    .join(format!("damaged-packet-original-{id}-{damaged}.pnk1")),
            )?;
        } else {
            return Ok(());
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(c.run_root.join("packets"))?;
    temporary.write_all(&expected)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(&path).map_err(|e| e.error)?;
    File::open(c.run_root.join("packets"))?.sync_all()?;
    Ok(())
}
fn retain_packets(c: &Config, node: &Node) -> Result<()> {
    for packet in ancestry(node, node.active()?.0)? {
        retain_packet(c, &packet)?;
    }
    Ok(())
}
fn submit_packet(
    c: &Config,
    node: &mut Node,
    auth: &AuthenticatedClient,
    packet: &Packet,
    receipts: &mut Receipts,
    recovered: bool,
) -> Result<()> {
    let id = packet.id()?;
    let request = Request::Submit {
        packet: hex::encode(packet.encode()?),
    };
    for attempt in 0..8 {
        let attempted = Instant::now();
        match ingress::call_authenticated_durable_protected(
            node,
            c.peer.ok_or("PEER")?,
            &request,
            auth,
        ) {
            Ok(response) => {
                ensure(
                    response["block"] == hex::encode(id)
                        && response["active"]
                            .as_str()
                            .is_some_and(|s| fixed_hex(s, 64))
                        && (recovered || response["active"] == hex::encode(id)),
                    "SUBMIT_ACK",
                )?;
                receipts.emit("submit-attempt",json!({"height":packet.header.height,"block":hex::encode(id),"attempt":attempt,"recovery_replay":recovered,"success":true,"elapsed_ns":attempted.elapsed().as_nanos(),"response":response}))?;
                return Ok(());
            }
            Err(error) => {
                receipts.emit("submit-attempt",json!({"height":packet.header.height,"block":hex::encode(id),"attempt":attempt,"recovery_replay":recovered,"success":false,"elapsed_ns":attempted.elapsed().as_nanos(),"error":error.to_string()}))?;
                thread::sleep(Duration::from_millis(c.poll_ms));
            }
        }
    }
    Err("SUBMIT_ATTEMPTS_EXHAUSTED".into())
}
fn prepared_next(c: &Config, node: &Node) -> Result<Option<Packet>> {
    let next = node.parent_height(node.active()?.0)? + 1;
    let mut result = None;
    for item in fs::read_dir(c.run_root.join("packets"))? {
        let path = item?.path();
        if path.extension().is_some_and(|s| s == "pnk1") {
            let packet = Packet::decode(&owned_read(&path, 8_388_608, true)?)?;
            ensure(
                path.file_stem().and_then(|s| s.to_str()) == Some(&hex::encode(packet.id()?)),
                "PACKET_FILENAME",
            )?;
            if packet.header.height == next {
                ensure(
                    result.is_none() && packet.header.parent == node.active()?.0,
                    "PREPARED_PACKET_CONFLICT",
                )?;
                result = Some(packet);
            }
        }
    }
    Ok(result)
}
fn producer(c: &Config, receipts: &mut Receipts, secret: &str, resume: bool) -> Result<()> {
    let mut node = Node::open(&c.run_root.join("store"), settings(c)?, c.workers)?;
    let auth = client(c, secret)?;
    if !resume {
        receipts.emit("producer-start",json!({"pid":std::process::id(),"state":node.stats()?,"clock_scope":"live-local-wall; durations same-process monotonic","task_scope":"explicit genesis maintenance, zero model utility"}))?;
    }
    let started = Instant::now();
    if resume {
        checked_workload(c, &node)?;
        retain_packets(c, &node)?;
        if let Some(request) = ingress::pending_authenticated_request(&node, &auth)? {
            let Request::Submit { packet } = request else {
                return Err("PRODUCER_PENDING_OPERATION".into());
            };
            let packet = Packet::decode(&hex::decode(packet).map_err(|_| "PENDING_PACKET")?)?;
            ensure(
                node.packet(packet.id()?)?.encode()? == packet.encode()?,
                "PENDING_STORED_PACKET",
            )?;
            ensure(
                ancestry(&node, node.active()?.0)?
                    .iter()
                    .any(|p| p.id().ok() == packet.id().ok()),
                "PENDING_ACTIVE_ANCESTRY",
            )?;
            submit_packet(c, &mut node, &auth, &packet, receipts, true)?;
        }
        // Replay retained active packets, never mine replacements for these heights.
        // Authenticated duplicates are idempotent; receipt history is not rewound.
        for packet in ancestry(&node, node.active()?.0)? {
            submit_packet(c, &mut node, &auth, &packet, receipts, true)?;
        }
    }
    let first = node.parent_height(node.active()?.0)? as usize + 1;
    let mut last = if first == 1 {
        c.genesis_time
    } else {
        node.packet(node.active()?.0)?.header.timestamp
    };
    for height in first..=c.data_blocks + c.drain_blocks {
        let scheduled = started + Duration::from_millis((height - first) as u64 * c.pace_ms);
        if let Some(wait) = scheduled.checked_duration_since(Instant::now()) {
            thread::sleep(wait);
        }
        let start = Instant::now();
        let packet = if let Some(packet) = prepared_next(c, &node)? {
            packet
        } else {
            make(c, &node, height, ingress::now()?.max(last + 1))?
        };
        last = packet.header.timestamp;
        let made = Instant::now();
        // Durable exact packet is retained before admission/activation. Restart can
        // reuse a constructed packet even when its admission receipt was not written.
        retain_packet(c, &packet)?;
        let id = node.admit(&packet, ingress::now()?)?;
        node.activate_observed(id, ingress::now()?)?;
        checked_workload(c, &node)?;
        let local = Instant::now();
        submit_packet(c, &mut node, &auth, &packet, receipts, false)?;
        receipts.emit("producer-block",json!({"height":height,"block":hex::encode(id),"transaction_count":packet.transactions.len(),"packet_bytes":packet.encode()?.len(),"construct_execute_mine_ns":made.duration_since(start).as_nanos(),"local_verify_store_activate_ns":local.duration_since(made).as_nanos(),"producer_intake_to_remote_ack_ns":start.elapsed().as_nanos(),"state":node.stats()?}))?;
    }
    receipts.emit("producer-complete",json!({"state":node.stats()?,"elapsed_ns":started.elapsed().as_nanos(),"duration_scope":"current process segment only","submitted_transfers":c.data_blocks*c.transactions_per_block,"data_blocks":c.data_blocks,"drain_blocks":c.drain_blocks,"task_height_limit":1000,"gpu_used":false}))
}
fn validator(c: &Config, receipts: &mut Receipts, secret: &str) -> Result<()> {
    let peers: Vec<String> = serde_json::from_slice(&owned_read(
        c.peer_roster.as_ref().ok_or("ROSTER")?,
        16384,
        false,
    )?)?;
    let auth = AuthenticatedServer::new(
        DevelopmentIdentity::from_secret_hex(secret)?,
        peers,
        c.session_generation,
    )?;
    let node = Node::open(&c.run_root.join("store"), settings(c)?, c.workers)?;
    let listener = TcpListener::bind(c.listen.ok_or("LISTEN")?)?;
    receipts.emit("validator-listening",json!({"pid":std::process::id(),"address":listener.local_addr()?.to_string(),"state":node.stats()?,"server_public":auth.public_key(),"admission_profile":"connection-work-v1","admission_bits":16,"admission_ttl_ms":2000,"confidentiality":false}))?;
    let started = Instant::now();
    let metrics = ingress::serve_authenticated_protected(
        listener,
        node,
        Duration::from_secs(c.server_seconds),
        Arc::new(AtomicBool::new(false)),
        auth,
        ingress::AdmissionPolicy::development(),
    )?;
    let node = Node::open(&c.run_root.join("store"), settings(c)?, c.workers)?;
    retain_packets(c, &node)?;
    receipts.emit(
        "validator-stopped",
        json!({"state":node.stats()?,"metrics":metrics,"elapsed_ns":started.elapsed().as_nanos()}),
    )?;
    let groups = checked_workload(c, &node)?;
    ensure(
        node.parent_height(node.active()?.0)? == (c.data_blocks + c.drain_blocks) as u64
            && groups.len() == c.data_blocks
            && groups.iter().map(Vec::len).sum::<usize>()
                == c.data_blocks * c.transactions_per_block,
        "VALIDATOR_INCOMPLETE_WORKLOAD",
    )?;
    receipts.emit("validator-complete",json!({"state":node.stats()?,"metrics":metrics,"elapsed_ns":started.elapsed().as_nanos(),"verified_planned_transfers":groups.iter().map(Vec::len).sum::<usize>()}))
}
fn read_call(
    c: &Config,
    node: &mut Node,
    auth: &AuthenticatedClient,
    request: &Request,
    receipts: &mut Receipts,
) -> Result<Value> {
    for attempt in 0..8 {
        let started = Instant::now();
        match ingress::call_authenticated_durable(node, c.peer.ok_or("PEER")?, request, auth) {
            Ok(value) => {
                receipts.emit("read-attempt",json!({"request":request,"attempt":attempt,"success":true,"elapsed_ns":started.elapsed().as_nanos()}))?;
                return Ok(value);
            }
            Err(error) => {
                receipts.emit("read-attempt",json!({"request":request,"attempt":attempt,"success":false,"elapsed_ns":started.elapsed().as_nanos(),"error":error.to_string()}))?;
                thread::sleep(Duration::from_millis(c.poll_ms));
            }
        }
    }
    Err("READ_ATTEMPTS_EXHAUSTED_EXACT_PENDING_REQUEST_RETAINED".into())
}
fn sync_checked(
    c: &Config,
    node: &mut Node,
    auth: &AuthenticatedClient,
    tip: [u8; 32],
    mut after: [u8; 32],
    receipts: &mut Receipts,
) -> Result<()> {
    for _ in 0..64 {
        let request = Request::History {
            tip: hex::encode(tip),
            after: hex::encode(after),
        };
        // Retry this exact request before allocating another nonce; a partial prefix
        // never substitutes a different Head for the durable pending History request.
        let value = read_call(c, node, auth, &request, receipts)?;
        let page: ingress::Page = serde_json::from_value(value)?;
        let complete = page.complete;
        after = ingress::receive_page(node, page, tip, after, ingress::now()?)?;
        if complete {
            return Ok(());
        }
    }
    Err("SYNC_PAGE_BUDGET".into())
}
fn confirmer(c: &Config, receipts: &mut Receipts, secret: &str, resume: bool) -> Result<()> {
    let mut node = Node::open(&c.run_root.join("store"), settings(c)?, c.workers)?;
    let auth = client(c, secret)?;
    let started = Instant::now();
    let mut attempt = 0u64;
    let mut last_observation: Option<([u8; 32], usize, bool)> = None;
    if !resume {
        receipts.emit("confirmer-start",json!({"pid":std::process::id(),"state":node.stats()?,"clock_scope":"own monotonic time from observation start, never cross-host subtraction"}))?;
    }
    if resume {
        checked_workload(c, &node)?;
        retain_packets(c, &node)?;
        if let Some(request) = ingress::pending_authenticated_request(&node, &auth)? {
            ensure(
                matches!(request, Request::Head | Request::History { .. }),
                "CONFIRMER_PENDING_OPERATION",
            )?;
            let value = read_call(c, &mut node, &auth, &request, receipts)?;
            match request {
                Request::Head => context_matches(node.settings(), &value)?,
                Request::History { tip, after } => {
                    let tip = digest(&tip)?;
                    let after = digest(&after)?;
                    let page: ingress::Page = serde_json::from_value(value)?;
                    let complete = page.complete;
                    let next = ingress::receive_page(&mut node, page, tip, after, ingress::now()?)?;
                    if !complete {
                        sync_checked(c, &mut node, &auth, tip, next, receipts)?;
                    }
                }
                _ => unreachable!(),
            }
            receipts.emit("pending-read-recovered", json!({"state":node.stats()?}))?;
        }
    }
    while started.elapsed() < Duration::from_secs(c.timeout_seconds) {
        let iteration = Instant::now();
        attempt += 1;
        let observed = (|| -> Result<(Value, Vec<Value>, usize, bool)> {
            let head = read_call(c, &mut node, &auth, &Request::Head, receipts)?;
            context_matches(node.settings(), &head)?;
            let tip = digest(head["tip"].as_str().ok_or("HEAD_TIP")?)?;
            let after = node.active()?.0;
            if tip != after {
                sync_checked(c, &mut node, &auth, tip, after, receipts)?;
            }
            let local = node.stats()?;
            for key in [
                "tip",
                "height",
                "state_root",
                "chainwork_hex",
                "network",
                "parameters",
                "genesis",
            ] {
                ensure(local[key] == head[key], "INDEPENDENT_HEAD_MISMATCH")?;
            }
            if let Some((previous, count, done)) = last_observation {
                if previous == tip {
                    return Ok((local, Vec::new(), count, done));
                }
            }
            let groups = checked_workload(c, &node)?;
            let mut batches = Vec::new();
            let mut confirmed = 0usize;
            for queries in groups {
                let result = node.confirmations(&queries, ingress::now()?)?;
                ensure(
                    result.observations.len() == queries.len(),
                    "CONFIRMATION_LENGTH",
                )?;
                for (obs, (tx, block)) in result.observations.iter().zip(&queries) {
                    ensure(
                        obs.transaction == hex::encode(tx)
                            && obs.included_block == hex::encode(block)
                            && !obs.finalized
                            && !obs.execution_authority,
                        "CONFIRMATION_IDENTITY",
                    )?;
                    if obs.confirmed && !obs.reorged {
                        confirmed += 1;
                    }
                }
                batches.push(serde_json::to_value(result)?);
            }
            let done = local["height"] == (c.data_blocks + c.drain_blocks) as u64
                && confirmed == c.data_blocks * c.transactions_per_block;
            last_observation = Some((tip, confirmed, done));
            Ok((local, batches, confirmed, done))
        })();
        match observed {
            Ok((state, batches, confirmed, done)) => {
                retain_packets(c, &node)?;
                receipts.emit("confirmer-observation",json!({"attempt":attempt,"success":true,"elapsed_ns":iteration.elapsed().as_nanos(),"state":state,"unchanged_tip":batches.is_empty() && state["height"] != 0,"local_confirmation_batches":batches,"local_confirmed_transfers":confirmed,"complete":done}))?;
                if done {
                    return receipts.emit("confirmer-complete",json!({"state":node.stats()?,"confirmed_transfers":confirmed,"client_start_to_full_verified_confirmation_ns":started.elapsed().as_nanos(),"latency_scope":"single client monotonic from observer startup, not per-transaction submission latency","independent_store_full_verification":true,"independent_operator":false}));
                }
            }
            Err(error) => {
                receipts.emit("confirmer-observation",json!({"attempt":attempt,"success":false,"elapsed_ns":iteration.elapsed().as_nanos(),"error":error.to_string()}))?;
                return Err(error);
            }
        }
        thread::sleep(Duration::from_millis(c.poll_ms));
    }
    Err("CONFIRMATION_TIMEOUT".into())
}
fn run(c: Config, fp: Value, raw_config: &[u8], resume: bool) -> Result<()> {
    validate_config(&c, &pin_of(&fp)?)?;
    let secret = secret(&c)?;
    let mut receipts = Receipts::open(&c, fp, secret.clone(), raw_config, resume)?;
    let outcome = match c.role.as_str() {
        "producer" => producer(&c, &mut receipts, &secret, resume),
        "validator" => validator(&c, &mut receipts, &secret),
        "confirmer" => confirmer(&c, &mut receipts, &secret, resume),
        _ => Err("ROLE".into()),
    };
    if let Err(ref error) = outcome {
        receipts.emit(
            "role-failed",
            json!({"error":error.to_string(),"observed_failure_preserved":true}),
        )?;
    }
    outcome
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let outcome = (|| -> Result<()> {
        let fp = fingerprint()?;
        match args.as_slice() {
            [op] if op == "fingerprint" => println!("{fp}"),
            [op, path] if op == "run" || op == "resume" => {
                let raw = bounded_read(Path::new(path), 65536)?;
                let c: Config = serde_json::from_slice(&raw)?;
                run(c, fp, &raw, op == "resume")?;
            }
            _ => {
                return Err(
                    "usage: distributed_pipeline fingerprint | run PRIVATE_CONFIG_JSON | resume SAME_PRIVATE_CONFIG_JSON".into(),
                )
            }
        }
        Ok(())
    })();
    if let Err(error) = outcome {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(root: &Path) -> Config {
        Config {
            schema: "pon-distributed-role-config-v1".into(),
            role: "producer".into(),
            scope: "local-process-test".into(),
            run_id: "unit-campaign".into(),
            run_root: root.join("role"),
            source_pin: SourcePin {
                commit: None,
                tree: None,
                inventory_digest: "aa".repeat(32),
                binary_digest: "bb".repeat(32),
            },
            genesis_time: ingress::now().unwrap() - 100,
            workers: 1,
            evaluation_policy: "closed-round-all-eligible-min-v1".into(),
            task_profile: "signed-task-dev-v1".into(),
            pattern: "hot".into(),
            data_blocks: 2,
            transactions_per_block: 4,
            drain_blocks: 6,
            pace_ms: 0,
            server_seconds: 60,
            poll_ms: 20,
            timeout_seconds: 50,
            listen: None,
            peer: Some("127.0.0.1:12345".parse().unwrap()),
            auth_secret: root.join("secret"),
            peer_roster: None,
            server_public: Some("11".repeat(32)),
            session_generation: 1,
        }
    }
    #[test]
    fn source_scope_and_campaign_bounds_reject() {
        let d = tempfile::tempdir().unwrap();
        let mut c = config(d.path());
        assert!(validate_config(&c, &c.source_pin).is_ok());
        let mut wrong = c.source_pin.clone();
        wrong.binary_digest = "cc".repeat(32);
        assert!(validate_config(&c, &wrong).is_err());
        c.scope = "lan-development".into();
        assert!(validate_config(&c, &c.source_pin).is_err());
        c.source_pin.commit = Some("11".repeat(20));
        c.source_pin.tree = Some("22".repeat(20));
        assert!(validate_config(&c, &c.source_pin).is_err());
        c.scope = "local-process-test".into();
        c.data_blocks = 995;
        assert!(validate_config(&c, &c.source_pin).is_err());
    }
    #[test]
    fn actual_local_packet_content_is_checked_after_full_admission() {
        let d = tempfile::tempdir().unwrap();
        let c = config(d.path());
        let mut node = Node::open(&d.path().join("node"), settings(&c).unwrap(), 1).unwrap();
        let packet = make(&c, &node, 1, ingress::now().unwrap()).unwrap();
        let id = node.admit(&packet, ingress::now().unwrap()).unwrap();
        node.activate_observed(id, ingress::now().unwrap()).unwrap();
        assert_eq!(checked_workload(&c, &node).unwrap()[0].len(), 4);
        let mut wrong = c.clone();
        wrong.run_id = "another-run".into();
        assert!(checked_workload(&wrong, &node).is_err());
    }
    #[test]
    fn secret_symlink_and_public_permissions_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let c = config(d.path());
        fs::write(&c.auth_secret, "11".repeat(32)).unwrap();
        fs::set_permissions(&c.auth_secret, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(secret(&c).is_err());
        fs::set_permissions(&c.auth_secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(secret(&c).is_ok());
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&c.auth_secret, &link).unwrap();
        let mut x = c.clone();
        x.auth_secret = link;
        assert!(secret(&x).is_err());
    }
    fn receipt_fixture(c: &Config) -> (Value, Vec<u8>, String) {
        (
            serde_json::to_value(&c.source_pin).unwrap(),
            serde_json::to_vec(c).unwrap(),
            "11".repeat(32),
        )
    }
    #[test]
    fn explicit_resume_preserves_exact_uncommitted_tail_and_signed_prefix() {
        let d = tempfile::tempdir().unwrap();
        let c = config(d.path());
        let (fp, raw, key) = receipt_fixture(&c);
        let mut r = Receipts::open(&c, fp.clone(), key.clone(), &raw, false).unwrap();
        fs::create_dir(c.run_root.join("store")).unwrap();
        r.emit("producer-start", json!({"attempt":1})).unwrap();
        r.emit("submit-attempt", json!({"success":false})).unwrap();
        drop(r);
        let path = c.run_root.join("receipts.jsonl");
        let prefix = fs::read(&path).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"body\":unfinished")
            .unwrap();
        let original = fs::read(&path).unwrap();
        let mut r = Receipts::open(&c, fp, key, &raw, true).unwrap();
        assert_eq!(r.sequence, 3);
        r.emit("recovery-tested", json!({})).unwrap();
        drop(r);
        assert!(fs::read(&path).unwrap().starts_with(&prefix));
        let id = hex::encode(hash(b"distributed-recovery-original-v1", &[&original]));
        assert_eq!(
            fs::read(
                c.run_root
                    .join(format!("receipts-before-tail-recovery-{id}.jsonl"))
            )
            .unwrap(),
            original
        );
        assert_eq!(
            fs::read(
                c.run_root
                    .join(format!("receipt-uncommitted-tail-{id}.bin"))
            )
            .unwrap(),
            b"{\"body\":unfinished"
        );
        let rows: Vec<Value> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(rows[2]["body"]["event"], "role-resumed");
        assert_eq!(rows[3]["body"]["previous"], rows[2]["receipt_digest"]);
    }
    #[test]
    fn resume_rejects_committed_corruption_without_changing_any_bytes() {
        for blank in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let c = config(d.path());
            let (fp, raw, key) = receipt_fixture(&c);
            let mut r = Receipts::open(&c, fp.clone(), key.clone(), &raw, false).unwrap();
            fs::create_dir(c.run_root.join("store")).unwrap();
            r.emit("producer-start", json!({})).unwrap();
            drop(r);
            let path = c.run_root.join("receipts.jsonl");
            let mut original = fs::read(&path).unwrap();
            if blank {
                original.push(b'\n');
            } else {
                let mut row: Value = serde_json::from_slice(&original).unwrap();
                row["body"]["event"] = json!("tampered");
                original = serde_json::to_vec(&row).unwrap();
                original.push(b'\n');
            }
            fs::write(&path, &original).unwrap();
            assert!(Receipts::open(&c, fp, key, &raw, true).is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(fs::read_dir(&c.run_root).unwrap().count(), 5);
        }
    }
    #[test]
    fn resume_requires_exact_source_config_identity_and_exclusive_owner() {
        let d = tempfile::tempdir().unwrap();
        let c = config(d.path());
        let (fp, raw, key) = receipt_fixture(&c);
        let mut r = Receipts::open(&c, fp.clone(), key.clone(), &raw, false).unwrap();
        fs::create_dir(c.run_root.join("store")).unwrap();
        r.emit("producer-start", json!({})).unwrap();
        assert!(Receipts::open(&c, fp.clone(), key.clone(), &raw, true).is_err());
        drop(r);
        let before = fs::read(c.run_root.join("receipts.jsonl")).unwrap();
        let mut altered = raw.clone();
        altered.push(b'\n');
        assert!(Receipts::open(&c, fp.clone(), key.clone(), &altered, true).is_err());
        let mut wrong = fp.clone();
        wrong["binary_digest"] = json!("cc".repeat(32));
        assert!(Receipts::open(&c, wrong, key.clone(), &raw, true).is_err());
        assert!(Receipts::open(&c, fp, "22".repeat(32), &raw, true).is_err());
        assert_eq!(fs::read(c.run_root.join("receipts.jsonl")).unwrap(), before);
    }
    #[test]
    fn reopened_producer_retries_the_exact_durable_authenticated_submit() {
        let d = tempfile::tempdir().unwrap();
        let mut c = config(d.path());
        let server_key = "22".repeat(32);
        let server_identity = DevelopmentIdentity::from_secret_hex(&server_key).unwrap();
        c.server_public = Some(server_identity.public_key().to_owned());
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = first.local_addr().unwrap();
        drop(first);
        c.peer = Some(address);
        let (fp, raw, key) = receipt_fixture(&c);
        let mut receipts = Receipts::open(&c, fp, key.clone(), &raw, false).unwrap();
        let auth = client(&c, &key).unwrap();
        let mut node = Node::open(&c.run_root.join("store"), settings(&c).unwrap(), 1).unwrap();
        let packet = make(&c, &node, 1, ingress::now().unwrap()).unwrap();
        let id = node.admit(&packet, ingress::now().unwrap()).unwrap();
        node.activate_observed(id, ingress::now().unwrap()).unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        assert!(
            ingress::call_authenticated_durable_protected(&mut node, address, &request, &auth)
                .is_err()
        );
        drop(node);
        let mut node = Node::open(&c.run_root.join("store"), settings(&c).unwrap(), 1).unwrap();
        assert_eq!(
            ingress::pending_authenticated_request(&node, &auth).unwrap(),
            Some(request)
        );
        let listener = TcpListener::bind(address).unwrap();
        let server_root = d.path().join("server");
        let server = Node::open(&server_root, settings(&c).unwrap(), 1).unwrap();
        let identity = DevelopmentIdentity::from_secret_hex(&key).unwrap();
        let authority =
            AuthenticatedServer::new(server_identity, vec![identity.public_key().to_owned()], 1)
                .unwrap();
        let worker = thread::spawn(move || {
            ingress::serve_authenticated_protected(
                listener,
                server,
                Duration::from_secs(2),
                Arc::new(AtomicBool::new(false)),
                authority,
                ingress::AdmissionPolicy::development(),
            )
        });
        submit_packet(&c, &mut node, &auth, &packet, &mut receipts, true).unwrap();
        assert!(ingress::pending_authenticated_request(&node, &auth)
            .unwrap()
            .is_none());
        assert_eq!(node.active().unwrap().0, id);
        assert_eq!(
            node.packet(id).unwrap().encode().unwrap(),
            packet.encode().unwrap()
        );
        worker.join().unwrap().unwrap();
        let server = Node::open(&server_root, settings(&c).unwrap(), 1).unwrap();
        assert_eq!(server.active().unwrap().0, id);
    }
    #[test]
    fn retained_partial_packet_is_preserved_then_recovered_from_native_owner() {
        let d = tempfile::tempdir().unwrap();
        let c = config(d.path());
        fs::create_dir_all(c.run_root.join("packets")).unwrap();
        let mut node = Node::open(&c.run_root.join("store"), settings(&c).unwrap(), 1).unwrap();
        let packet = make(&c, &node, 1, ingress::now().unwrap()).unwrap();
        let id = node.admit(&packet, ingress::now().unwrap()).unwrap();
        node.activate_observed(id, ingress::now().unwrap()).unwrap();
        retain_packet(&c, &packet).unwrap();
        let path = c
            .run_root
            .join("packets")
            .join(format!("{}.pnk1", hex::encode(id)));
        let partial = &packet.encode().unwrap()[..101];
        fs::write(&path, partial).unwrap();
        retain_packets(&c, &node).unwrap();
        assert_eq!(fs::read(&path).unwrap(), packet.encode().unwrap());
        let h = hex::encode(hash(b"distributed-damaged-packet-v1", &[partial]));
        assert_eq!(
            fs::read(
                c.run_root
                    .join(format!("damaged-packet-{}-{h}.bin", hex::encode(id)))
            )
            .unwrap(),
            partial
        );
    }
    #[test]
    fn strict_config_rejects_unknown_fields() {
        let d = tempfile::tempdir().unwrap();
        let c = config(d.path());
        let mut value = serde_json::to_value(&c).unwrap();
        value["public_network_ready"] = json!(true);
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
}
