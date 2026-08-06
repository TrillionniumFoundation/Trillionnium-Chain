use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use trnm_node::live::{
    crypto::public_key_hex,
    http::{get_json, post_json},
    node::{
        now_unix_ms, verify_finality_receipt, AuthorizedSignerV1, LiveChainConfig, SubmitOutcome,
    },
    protocol::{FinalityReceiptV1, SignedCommandEnvelopeV1, ValidatorDescriptorV1, ValidatorSetV1},
    validator::{load_signing_key_file, ValidatorConfig},
};
use trnm_research_protocol::{AuthorityRole, CanonicalCbor, SignedResearchCommandV1};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-chain-cli",
    version,
    about = "TRNM live devnet operator, transaction and receipt verification CLI"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Operator {
        #[command(subcommand)]
        command: OperatorCommand,
    },
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    Sign {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        command_id: String,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        signer_role: String,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        payload_type: String,
        #[arg(long)]
        payload_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
    },
    WrapResearch {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signed_command: PathBuf,
        #[arg(long)]
        outer_command_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
    },
    Submit {
        #[arg(long)]
        node_url: String,
        #[arg(long)]
        envelope: PathBuf,
    },
    Finalize {
        #[arg(long)]
        node_url: String,
    },
    QueryReceipt {
        #[arg(long)]
        node_url: String,
        #[arg(long)]
        command_id: String,
    },
    VerifyReceipt {
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
    Benchmark {
        #[arg(long)]
        node_url: String,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        signer_role: String,
        #[arg(long, default_value_t = 100)]
        transactions: u64,
        #[arg(long, default_value_t = 256)]
        payload_bytes: usize,
    },
}

#[derive(Debug, Subcommand)]
enum OperatorCommand {
    InitDevnet {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "trnm-local-devnet-1")]
        chain_id: String,
        #[arg(long, default_value_t = 28545)]
        node_port: u16,
        #[arg(long, default_value_t = 28600)]
        validator_base_port: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevnetGenesisV1 {
    schema: String,
    scope: String,
    development_only: bool,
    chain_id: String,
    genesis_hash_hex: String,
    validator_set: ValidatorSetV1,
    authorized_signers: Vec<AuthorizedSignerV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedSignerV1 {
    signer_id: String,
    signer_role: String,
    public_key_hex: String,
    private_key_path: PathBuf,
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Operator { command } => match command {
            OperatorCommand::InitDevnet {
                output_dir,
                chain_id,
                node_port,
                validator_base_port,
            } => init_devnet(&output_dir, &chain_id, node_port, validator_base_port),
        },
        Command::Keygen { output } => {
            let key = generate_signing_key();
            write_key_new(&output, &key)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "private_key_path": output,
                    "public_key_hex": public_key_hex(&key)
                }))?
            );
            Ok(())
        }
        Command::Sign {
            private_key,
            chain_id,
            command_id,
            signer_id,
            signer_role,
            nonce,
            payload_type,
            payload_file,
            output,
            ttl_seconds,
        } => {
            ensure!(
                (1..=86_400).contains(&ttl_seconds),
                "ttl_seconds out of range"
            );
            let key = load_signing_key_file(&private_key)?;
            let payload = fs::read(&payload_file)
                .with_context(|| format!("read payload {}", payload_file.display()))?;
            ensure!(payload.len() <= 1024 * 1024, "payload exceeds 1 MiB");
            let issued_at = now_unix_ms()?;
            let expires_at = issued_at
                .checked_add(ttl_seconds.saturating_mul(1_000))
                .ok_or_else(|| anyhow!("expiry timestamp overflow"))?;
            let envelope = SignedCommandEnvelopeV1::sign(
                chain_id,
                command_id,
                signer_id,
                signer_role,
                nonce,
                issued_at,
                expires_at,
                payload_type,
                &payload,
                &key,
            )?;
            write_envelope_new(&output, &envelope)?;
            println!("{}", serde_json::to_string_pretty(&envelope)?);
            Ok(())
        }
        Command::WrapResearch {
            private_key,
            signed_command,
            outer_command_id,
            output,
            ttl_seconds,
        } => {
            ensure!(
                (1..=86_400).contains(&ttl_seconds),
                "ttl_seconds out of range"
            );
            let key = load_signing_key_file(&private_key)?;
            let document: serde_json::Value = read_json(&signed_command)?;
            let signed_value = document.get("signed_command").cloned().unwrap_or(document);
            let signed: SignedResearchCommandV1 =
                serde_json::from_value(signed_value).context("decode SignedResearchCommandV1")?;
            signed
                .validate()
                .map_err(|error| anyhow!("invalid signed research command: {error}"))?;
            ensure!(
                signed.public_key == key.verifying_key().to_bytes(),
                "outer private key does not match inner research signer"
            );
            let signer_role = match signed.signer_role {
                AuthorityRole::NakamaAuthority => "nakama",
                AuthorityRole::HeptaAuthority => "hepta",
            };
            let issued_at = now_unix_ms()?;
            let expires_at = issued_at
                .checked_add(ttl_seconds.saturating_mul(1_000))
                .ok_or_else(|| anyhow!("expiry timestamp overflow"))?;
            let envelope = SignedCommandEnvelopeV1::sign(
                signed.chain_id.clone(),
                outer_command_id,
                signed.signer_did.clone(),
                signer_role,
                signed.nonce,
                issued_at,
                expires_at,
                trnm_node::live::node::RESEARCH_COMMAND_PAYLOAD_TYPE_V1,
                &signed.canonical_bytes(),
                &key,
            )?;
            write_envelope_new(&output, &envelope)?;
            println!("{}", serde_json::to_string_pretty(&envelope)?);
            Ok(())
        }
        Command::Submit { node_url, envelope } => {
            let envelope: SignedCommandEnvelopeV1 = read_json(&envelope)?;
            let endpoint = format!("{}/v1/transactions", trim_url(&node_url)?);
            let response = post_json::<_, SubmitOutcome>(
                &endpoint,
                &envelope,
                Duration::from_secs(5),
                2 * 1024 * 1024,
            )?;
            ensure!(response.status == 202, "node rejected transaction");
            println!("{}", serde_json::to_string_pretty(&response.value)?);
            Ok(())
        }
        Command::Finalize { node_url } => {
            let endpoint = format!("{}/v1/admin/finalize", trim_url(&node_url)?);
            let response = post_json::<_, Vec<FinalityReceiptV1>>(
                &endpoint,
                &serde_json::json!({}),
                Duration::from_secs(30),
                4 * 1024 * 1024,
            )?;
            ensure!(response.status == 200, "node finalization failed");
            println!("{}", serde_json::to_string_pretty(&response.value)?);
            Ok(())
        }
        Command::QueryReceipt {
            node_url,
            command_id,
        } => {
            ensure!(
                !command_id.is_empty()
                    && command_id.len() <= 160
                    && !command_id.contains(['/', '?', '#', '\0']),
                "command_id is not URL-safe canonical text"
            );
            let endpoint = format!("{}/v1/finality/{}", trim_url(&node_url)?, command_id);
            let response =
                get_json::<FinalityReceiptV1>(&endpoint, Duration::from_secs(5), 4 * 1024 * 1024)?;
            ensure!(response.status == 200, "receipt not found");
            println!("{}", serde_json::to_string_pretty(&response.value)?);
            Ok(())
        }
        Command::VerifyReceipt { genesis, receipt } => {
            let genesis: DevnetGenesisV1 = read_json(&genesis)?;
            let receipt: FinalityReceiptV1 = read_json(&receipt)?;
            ensure!(
                genesis.schema == "trnm_chain_devnet_genesis_v1"
                    && genesis.scope == "loopback-local-devnet"
                    && genesis.development_only,
                "unsupported or unsafe genesis document"
            );
            ensure!(
                receipt.chain_id == genesis.chain_id,
                "receipt chain_id does not match genesis"
            );
            verify_finality_receipt(&receipt, &genesis.validator_set)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "verified": true,
                    "chain_id": receipt.chain_id,
                    "command_id": receipt.command_id,
                    "block_height": receipt.block_height,
                    "receipt_hash_hex": receipt.receipt_hash_hex
                }))?
            );
            Ok(())
        }
        Command::Benchmark {
            node_url,
            private_key,
            chain_id,
            signer_id,
            signer_role,
            transactions,
            payload_bytes,
        } => benchmark_live_path(
            &node_url,
            &private_key,
            &chain_id,
            &signer_id,
            &signer_role,
            transactions,
            payload_bytes,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn benchmark_live_path(
    node_url: &str,
    private_key: &Path,
    chain_id: &str,
    signer_id: &str,
    signer_role: &str,
    transactions: u64,
    payload_bytes: usize,
) -> Result<()> {
    ensure!(
        (1..=10_000).contains(&transactions),
        "transactions out of range"
    );
    ensure!(
        (1..=1024 * 1024).contains(&payload_bytes),
        "payload_bytes out of range"
    );
    let key = load_signing_key_file(private_key)?;
    let base_url = trim_url(node_url)?;
    let submit_endpoint = format!("{base_url}/v1/transactions");
    let finalize_endpoint = format!("{base_url}/v1/admin/finalize");
    let run_id = now_unix_ms()?;
    let mut latencies_micros = Vec::with_capacity(transactions as usize);
    let started = Instant::now();
    let mut last_command_id = String::new();

    for index in 0..transactions {
        let issued_at = now_unix_ms()?;
        let command_id = format!("bench:{run_id}:{index}");
        let payload = vec![(index % 251) as u8; payload_bytes];
        let envelope = SignedCommandEnvelopeV1::sign(
            chain_id,
            command_id.clone(),
            signer_id,
            signer_role,
            index + 1,
            issued_at,
            issued_at.saturating_add(300_000),
            "benchmark_payload_v1",
            &payload,
            &key,
        )?;
        let request_started = Instant::now();
        let response = post_json::<_, SubmitOutcome>(
            &submit_endpoint,
            &envelope,
            Duration::from_secs(5),
            2 * 1024 * 1024,
        )?;
        ensure!(response.status == 202, "benchmark transaction rejected");
        latencies_micros.push(request_started.elapsed().as_micros() as u64);
        last_command_id = command_id;
    }
    let submission_elapsed = started.elapsed();
    let finalize_started = Instant::now();
    let mut finalized_by_benchmark = 0usize;
    loop {
        let response = post_json::<_, Vec<FinalityReceiptV1>>(
            &finalize_endpoint,
            &serde_json::json!({}),
            Duration::from_secs(30),
            16 * 1024 * 1024,
        )?;
        ensure!(response.status == 200, "benchmark finalization failed");
        if response.value.is_empty() {
            break;
        }
        finalized_by_benchmark = finalized_by_benchmark.saturating_add(response.value.len());
    }
    let receipt_endpoint = format!("{base_url}/v1/finality/{last_command_id}");
    let receipt =
        get_json::<FinalityReceiptV1>(&receipt_endpoint, Duration::from_secs(5), 4 * 1024 * 1024)?;
    ensure!(
        receipt.status == 200,
        "benchmark last receipt is not finalized"
    );
    let finality_elapsed = finalize_started.elapsed();
    latencies_micros.sort_unstable();
    let percentile = |percent: usize| {
        let index = (latencies_micros.len() - 1) * percent / 100;
        latencies_micros[index]
    };
    let elapsed_seconds = submission_elapsed.as_secs_f64();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "trnm_live_path_benchmark_v1",
            "transactions": transactions,
            "payload_bytes": payload_bytes,
            "submission_elapsed_ms": submission_elapsed.as_millis(),
            "submission_tps": transactions as f64 / elapsed_seconds.max(f64::EPSILON),
            "submission_p50_micros": percentile(50),
            "submission_p95_micros": percentile(95),
            "finality_elapsed_ms": finality_elapsed.as_millis(),
            "finalized_by_benchmark": finalized_by_benchmark,
            "last_command_id": last_command_id,
        }))?
    );
    Ok(())
}

fn init_devnet(
    output_dir: &Path,
    chain_id: &str,
    node_port: u16,
    validator_base_port: u16,
) -> Result<()> {
    ensure!(
        !chain_id.is_empty()
            && chain_id.len() <= 128
            && chain_id == chain_id.trim()
            && chain_id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            }),
        "chain_id is not canonical"
    );
    ensure!(
        node_port > 1024 && validator_base_port > 1024,
        "devnet ports must be above 1024"
    );
    ensure!(
        validator_base_port <= u16::MAX - 3,
        "validator_base_port range overflows"
    );
    if output_dir.exists() {
        let mut entries = fs::read_dir(output_dir)
            .with_context(|| format!("read output directory {}", output_dir.display()))?;
        ensure!(
            entries.next().is_none(),
            "output_dir must not contain existing files"
        );
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;
    ensure!(
        !fs::symlink_metadata(output_dir)?.file_type().is_symlink(),
        "output_dir must not be a symlink"
    );
    let output_dir = output_dir
        .canonicalize()
        .with_context(|| format!("canonicalize output directory {}", output_dir.display()))?;
    for directory in ["genesis", "config", "secrets", "data"] {
        fs::create_dir(output_dir.join(directory))
            .with_context(|| format!("create devnet {directory} directory"))?;
    }
    fs::set_permissions(
        output_dir.join("secrets"),
        fs::Permissions::from_mode(0o700),
    )?;

    let mut validator_keys = Vec::new();
    let mut validators = Vec::new();
    for index in 1..=4u16 {
        let key = generate_signing_key();
        let key_path = output_dir
            .join("secrets")
            .join(format!("validator-{index}.key"));
        write_key_new(&key_path, &key)?;
        let port = validator_base_port + index - 1;
        validators.push(ValidatorDescriptorV1 {
            validator_id: format!("validator-{index}"),
            public_key_hex: public_key_hex(&key),
            vote_endpoint: format!("http://127.0.0.1:{port}/v1/vote"),
            voting_power: 1,
        });
        validator_keys.push((key_path, port));
    }
    let validator_set = ValidatorSetV1 {
        validator_set_id: "devnet-validators-v1".to_string(),
        validators,
        quorum_power: 3,
    };

    let mut authorized_signers = Vec::new();
    let mut generated_signers = Vec::new();
    for (name, role) in [
        ("hepta", "hepta"),
        ("nakama", "nakama"),
        ("operator", "operator"),
    ] {
        let key = generate_signing_key();
        let key_path = output_dir.join("secrets").join(format!("{name}.key"));
        write_key_new(&key_path, &key)?;
        let signer = AuthorizedSignerV1 {
            signer_id: format!("did:key:trnm-local-{name}"),
            signer_role: role.to_string(),
            public_key_hex: public_key_hex(&key),
        };
        generated_signers.push(GeneratedSignerV1 {
            signer_id: signer.signer_id.clone(),
            signer_role: signer.signer_role.clone(),
            public_key_hex: signer.public_key_hex.clone(),
            private_key_path: key_path,
        });
        authorized_signers.push(signer);
    }

    let node_config = LiveChainConfig {
        schema: "trnm_chain_node_config_v1".to_string(),
        scope: "loopback-local-devnet".to_string(),
        development_only: true,
        chain_id: chain_id.to_string(),
        listen_addr: SocketAddr::from(([127, 0, 0, 1], node_port)),
        database_path: output_dir.join("data").join("chain.sqlite"),
        block_interval_ms: 1_000,
        max_transactions_per_block: 64,
        validator_request_timeout_ms: 2_000,
        validator_set: validator_set.clone(),
        authorized_signers: authorized_signers.clone(),
    };
    node_config.validate()?;
    let genesis_hash_hex = node_config.genesis_hash_hex()?;
    let genesis = DevnetGenesisV1 {
        schema: "trnm_chain_devnet_genesis_v1".to_string(),
        scope: "loopback-local-devnet".to_string(),
        development_only: true,
        chain_id: chain_id.to_string(),
        genesis_hash_hex: genesis_hash_hex.clone(),
        validator_set: validator_set.clone(),
        authorized_signers: authorized_signers.clone(),
    };
    write_json_new(
        &output_dir.join("genesis").join("devnet-genesis.json"),
        &genesis,
    )?;
    write_json_new(&output_dir.join("config").join("node.json"), &node_config)?;
    write_json_new(
        &output_dir.join("config").join("signers.json"),
        &generated_signers,
    )?;
    for (index, ((key_path, port), validator)) in validator_keys
        .into_iter()
        .zip(validator_set.validators.iter())
        .enumerate()
    {
        let config = ValidatorConfig {
            chain_id: chain_id.to_string(),
            validator_id: validator.validator_id.clone(),
            validator_set_id: validator_set.validator_set_id.clone(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            private_key_path: key_path,
            database_path: output_dir
                .join("data")
                .join(format!("validator-{}.sqlite", index + 1)),
            genesis_block_hash_hex: genesis_hash_hex.clone(),
            authorized_signers: authorized_signers.clone(),
            max_transactions_per_block: node_config.max_transactions_per_block,
        };
        write_json_new(
            &output_dir
                .join("config")
                .join(format!("validator-{}.json", index + 1)),
            &config,
        )?;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "initialized": true,
            "scope": "loopback-local-devnet",
            "development_only": true,
            "output_dir": output_dir,
            "chain_id": chain_id,
            "genesis_hash_hex": genesis_hash_hex,
            "node_config": output_dir.join("config/node.json"),
            "genesis": output_dir.join("genesis/devnet-genesis.json")
        }))?
    );
    Ok(())
}

fn generate_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

fn write_key_new(path: &Path, key: &SigningKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create private key {}", path.display()))?;
    writeln!(file, "{}", hex::encode(key.to_bytes()))?;
    file.sync_all()?;
    Ok(())
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create JSON document {}", path.display()))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn write_envelope_new(path: &Path, envelope: &SignedCommandEnvelopeV1) -> Result<()> {
    let bytes = envelope.to_wire_bytes()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create canonical envelope {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read JSON {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON {}", path.display()))
}

fn trim_url(value: &str) -> Result<&str> {
    ensure!(
        value == value.trim() && !value.ends_with('/'),
        "node_url must be canonical and omit trailing slash"
    );
    ensure!(
        value.starts_with("http://127.0.0.1:") || value.starts_with("http://[::1]:"),
        "node_url must be explicit loopback HTTP"
    );
    Ok(value)
}
