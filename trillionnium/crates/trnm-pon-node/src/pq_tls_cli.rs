//! Explicit ordinary-binary consumer of the experimental loopback TLS owner.
//! It neither provisions production roots nor enables the public reactor.
use super::{need, number};
use openssl::{pkey::PKey, x509::X509};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_pon_node::{
    digest,
    ingress::pq_network::{
        tls::{serve_pq_tls13, PqTlsIdentity, PqTlsServer},
        PqNetworkPolicy, PqTlsPins, TLS_PROFILE,
    },
    Node, Result, Settings,
};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
#[path = "pq_application_local.rs"]
pub(super) mod local;
#[cfg(target_os = "linux")]
#[path = "pq_parent_cli.rs"]
pub(super) mod parent;
#[path = "pq_tls_cli_witness.rs"]
mod witness;

fn ensure(value: bool, error: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(error.into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    genesis_time: u64,
    network: String,
    parameters: String,
    genesis: String,
    generation: u64,
    server_spki: String,
    peer_spkis: Vec<String>,
    ca_certificate_sha256: String,
    server_name: String,
    #[serde(default, deserialize_with = "witness::present_configuration")]
    witness: Option<witness::Configuration>,
}

// Fixed upper bounds and one inspected descriptor. Configuration is additionally
// committed by the explicit caller-supplied SHA; CA and SPKI pins are checked
// independently. Secret parse failures never include the input bytes.
fn input(path: &str, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "PQ_TLS_INPUT_FILE")?;
    let metadata = file.metadata().map_err(|_| "PQ_TLS_INPUT_FILE")?;
    let uid = rustix::process::geteuid().as_raw();
    ensure(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid() == 0 || metadata.uid() == uid)
            && metadata.mode() & (if private { 0o077 } else { 0o022 }) == 0,
        "PQ_TLS_INPUT_FILE",
    )?;
    ensure((1..=limit).contains(&metadata.len()), "PQ_TLS_INPUT_LENGTH")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "PQ_TLS_INPUT_FILE")?;
    ensure(bytes.len() as u64 == metadata.len(), "PQ_TLS_INPUT_LENGTH")?;
    Ok(bytes)
}

fn spki(text: &str) -> Result<Vec<u8>> {
    let raw = hex::decode(text).map_err(|_| "PQ_TLS_SPKI")?;
    ensure(hex::encode(&raw) == text, "PQ_TLS_SPKI")?;
    Ok(raw)
}

pub(super) fn run(args: &BTreeMap<String, String>) -> Result<Value> {
    const ALLOWED: &[&str] = &[
        "--development",
        "--store",
        "--listen",
        "--seconds",
        "--workers",
        "--tls-config",
        "--tls-config-sha256",
        "--tls-cert",
        "--tls-key",
        "--tls-ca",
        "--witness-writer-key",
    ];
    ensure(
        args.keys().all(|key| ALLOWED.contains(&key.as_str())),
        "PQ_TLS_OPTION",
    )?;
    ensure(
        args.get("--development").map(String::as_str) == Some("true"),
        "EXPLICIT_DEVELOPMENT_REQUIRED",
    )?;
    let address: SocketAddr = need(args, "--listen")?
        .parse()
        .map_err(|_| "PQ_TLS_LISTEN")?;
    ensure(address.ip().is_loopback(), "PQ_NETWORK_LOOPBACK_ONLY")?;
    let seconds = number(args, "--seconds", 30)?;
    ensure((1..=3600).contains(&seconds), "PQ_NETWORK_SERVER_BUDGET")?;
    let workers = usize::try_from(number(args, "--workers", 1)?).map_err(|_| "PQ_TLS_WORKERS")?;
    ensure((1..=64).contains(&workers), "PQ_TLS_WORKERS")?;
    let bytes = input(need(args, "--tls-config")?, 262_144, false)?;
    let expected = digest(need(args, "--tls-config-sha256")?)?;
    let actual: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    ensure(actual == expected, "PQ_TLS_CONFIG_PIN")?;
    let config: Configuration = serde_json::from_slice(&bytes)?;
    let witness_key = match config.schema.as_str() {
        "native-pq-tls-loopback-config-v1"
            if config.witness.is_none() && !args.contains_key("--witness-writer-key") =>
        {
            None
        }
        "native-pq-tls-loopback-config-v2" => {
            ensure(config.witness.is_some(), "PQ_TLS_WITNESS_CONFIG_REQUIRED")?;
            Some(need(args, "--witness-writer-key")?)
        }
        _ => return Err("PQ_TLS_CONFIG_SCHEMA".into()),
    };
    let settings = Settings::development(Some(config.genesis_time))?;
    ensure(
        digest(&config.network)? == settings.network()
            && digest(&config.parameters)? == settings.parameters()
            && digest(&config.genesis)? == settings.genesis(),
        "PQ_NETWORK_CONTEXT",
    )?;
    let server_spki = spki(&config.server_spki)?;
    let peers = config
        .peer_spkis
        .iter()
        .map(|s| spki(s))
        .collect::<Result<Vec<_>>>()?;
    let policy = Arc::new(PqNetworkPolicy::new_tls13(
        &settings,
        &server_spki,
        config.generation,
        peers,
        PqTlsPins::new(digest(&config.ca_certificate_sha256)?, config.server_name)?,
    )?);
    let key_bytes = input(need(args, "--tls-key")?, 32_768, true)?;
    let key = PKey::private_key_from_pem(&key_bytes).map_err(|_| "PQ_TLS_LOCAL_KEY")?;
    let certificate = X509::from_pem(&input(need(args, "--tls-cert")?, 32_768, false)?)
        .map_err(|_| "PQ_TLS_LOCAL_CERTIFICATE")?;
    let ca = X509::from_pem(&input(need(args, "--tls-ca")?, 32_768, false)?)
        .map_err(|_| "PQ_TLS_CA_CERTIFICATE")?;
    let identity = PqTlsIdentity::new(certificate, key.clone(), ca)?;
    let signer = PqNativeSigningKey::from_owned_key(key, policy.server_key_id())
        .map_err(|_| "PQ_TLS_LOCAL_KEY")?;
    let server = PqTlsServer::new(policy.clone(), signer, identity)?;
    // Validate all input and cryptographic configuration before creating/opening
    // the actual owner or binding the listener. No other backend is selected.
    let witness_selected = config.witness.is_some();
    let store = Path::new(need(args, "--store")?);
    let node = match config.witness {
        Some(config) => config.open_node(
            store,
            settings,
            workers,
            &policy,
            witness_key.ok_or("PQ_TLS_WITNESS_CONFIG_REQUIRED")?,
        )?,
        None => Node::open_with_pq_network(store, settings, workers, &policy)?,
    };
    let listener = TcpListener::bind(address)?;
    println!(
        "{}",
        json!({"event":"pq-tls-ready","listen":listener.local_addr()?.to_string(),
        "profile":TLS_PROFILE,"policy":hex::encode(policy.id()),
        "configured_group":"X25519MLKEM768","group_evidence":"single-configured-group-inference",
        "public_history_tls":false,"private_task_qualification":false,
        "pnq2_rollback_witness_selected":witness_selected,"whole_node_rollback_protection":false,
        "production_activation":false,"consensus_authority":false})
    );
    std::io::stdout().flush()?;
    let metrics = serve_pq_tls13(
        listener,
        node,
        Duration::from_secs(seconds),
        Arc::new(AtomicBool::new(false)),
        server,
    )?;
    Ok(
        json!({"profile":TLS_PROFILE,"metrics":metrics,"production_activation":false,
        "consensus_authority":false,"public_history_tls":false,
        "pnq2_rollback_witness_selected":witness_selected,"whole_node_rollback_protection":false}),
    )
}
