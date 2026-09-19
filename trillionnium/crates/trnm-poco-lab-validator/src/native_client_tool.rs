//! Explicit isolated-campaign client. No automatic load or key generation.
use crate::{
    config::PublicReportVerifierContext,
    native_client_profile::{NativeClientProfileV1, NativeClientSignerV1},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use trnm_application_tx_builder_v0::{
    build_signed_canonical_tx_v0, ApplicationSignerV0, BuiltCanonicalTxV0,
    CanonicalTxBuildContextV0, TxBuilderLimitsV0,
};
const RESPONSE_LIMIT: usize = 8 * 1024 * 1024 + 16 * 1024;
const REQUEST_LIMIT: usize = 528_384;
const USAGE: &str = "native-client sync <observer-public-root> <config> <manifest-sha256> <private-socket> <replica-directory> <target-height> <profile-sha256> | sign <profile> <profile-sha256> <chain-id> <signer-id> <private-key> <nonce> <ttl-ms> <max-gas> <fee-limit> <command-json> <outer-output> | request <private-socket> <request-json> <response-output> <profile-sha256> <genesis-hash> | verify <observer-public-root> <config> <manifest-sha256> <response-json> <native-tx-hash> <exact-outer-file> <profile-sha256>";

fn text(value: &OsString) -> Result<&str> {
    value.to_str().context("client argument is not UTF-8")
}
fn hex32(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected lowercase 32-byte hex"
    );
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow!("hash length"))
}
fn bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= limit as u64,
        "client input is not one bounded regular file"
    );
    let mut result = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut result)?;
    ensure!(result.len() <= limit, "client input grew beyond limit");
    Ok(result)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn number(value: &OsString) -> Result<u64> {
    let s = text(value)?;
    ensure!(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0')),
        "noncanonical unsigned decimal"
    );
    Ok(s.parse()?)
}
struct CampaignSigner {
    identity: NativeClientSignerV1,
    key: SigningKey,
}
impl ApplicationSignerV0 for CampaignSigner {
    fn signer_id(&self) -> &str {
        &self.identity.signer_id
    }
    fn signer_role(&self) -> &str {
        &self.identity.signer_role
    }
    fn public_key_hex(&self) -> &str {
        &self.identity.public_key_hex
    }
    fn sign(&self, preimage: &[u8]) -> Result<[u8; 64]> {
        Ok(self.key.sign(preimage).to_bytes())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response<T> {
    schema: String,
    request_id: String,
    candidate_only: bool,
    chain_id: String,
    genesis_hash: String,
    profile_sha256: String,
    ok: bool,
    data: Option<T>,
    error: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofData {
    parent_header_hex: String,
    native_tx_hash: String,
    proof_class: String,
    package_hex: String,
    proof_verified: bool,
    m05_intent_binding: bool,
}
fn decode_lower_hex(value: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= max * 2
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical bounded proof hex"
    );
    Ok(hex::decode(value)?)
}
/// Verify against independently pinned trust and the exact bytes the client signed.
/// The server's proof_verified flag is parsed but never used as authority.
pub fn verify_response_v1(
    response_bytes: &[u8],
    set: &trnm_consensus_types::ValidatorSet,
    profile: &NativeClientProfileV1,
    expected_hash: [u8; 32],
    expected_outer: &[u8],
) -> Result<trnm_tx_lifecycle_v0::VerifiedNativeTxInclusionV1> {
    ensure!(
        response_bytes.len() <= RESPONSE_LIMIT,
        "client response bound"
    );
    let response: Response<ProofData> = serde_json::from_slice(response_bytes)?;
    ensure!(
        response.schema == "trnm.native-client.response.v1"
            && response.candidate_only
            && response.ok
            && response.error.is_none()
            && !response.request_id.is_empty()
            && response.request_id.len() <= 64
            && response.chain_id == set.chain_id().as_str()
            && response.genesis_hash == hex::encode(set.genesis_hash().as_bytes())
            && response.profile_sha256 == hex::encode(profile.digest_v1()?),
        "proof response differs from independent client context"
    );
    let data = response.data.context("proof response lacks data")?;
    ensure!(
        !data.m05_intent_binding
            && data.proof_class == "poco-three-chain-v0"
            && hex32(&data.native_tx_hash)? == expected_hash,
        "unsupported proof class or requested native hash mismatch"
    );
    let _untrusted_server_claim = data.proof_verified;
    let package = decode_lower_hex(&data.package_hex, 4 * 1024 * 1024)?;
    let parent = decode_lower_hex(&data.parent_header_hex, 16 * 1024)?;
    let parameters = trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0();
    let verified = trnm_tx_lifecycle_v0::verify_native_tx_inclusion_with_parent_header_v1(
        &package,
        &parent,
        trnm_tx_lifecycle_v0::NativeTxParentHeaderContextV1 {
            trusted_validator_set: set,
            trusted_parameters: &parameters,
            maximum_transactions: profile.maximum_batch_transactions as u32,
            maximum_proof_bytes: 4 * 1024 * 1024,
        },
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_validator_set(&parameters, set),
    )?;
    ensure!(
        verified.native_transaction_bytes() == expected_outer,
        "proved native bytes differ from the client's signed request"
    );
    let built = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(verified.native_transaction_bytes())?;
    ensure!(
        built.envelope().tx_hash()? == expected_hash,
        "proved native hash mismatch"
    );
    Ok(verified)
}

fn exchange_json(
    socket: &Path,
    request: &Value,
    chain_id: &str,
    profile: [u8; 32],
    genesis: [u8; 32],
) -> Result<Value> {
    let metadata = std::fs::symlink_metadata(socket)?;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o600,
        "native endpoint must be owner-private socket"
    );
    let encoded = serde_json::to_vec(request)?;
    ensure!(encoded.len() <= REQUEST_LIMIT, "native request frame bound");
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut stream = connect_until(socket, deadline)?;
    write_until(&mut stream, &(encoded.len() as u32).to_be_bytes(), deadline)?;
    write_until(&mut stream, &encoded, deadline)?;
    let mut prefix = [0u8; 4];
    read_until(&mut stream, &mut prefix, deadline)?;
    let count = u32::from_be_bytes(prefix) as usize;
    ensure!(
        count > 0
            && count
                <= if request["op"] == "sync_manifest" {
                    crate::native_replay_sync_v1::MAX_MANIFEST_BYTES + 16 * 1024
                } else {
                    2 * crate::native_replay_sync_v1::CHUNK_BYTES + 16 * 1024
                },
        "native response frame bound"
    );
    let mut response = vec![0; count];
    read_until(&mut stream, &mut response, deadline)?;
    trnm_application_tx_builder_v0::validate_strict_json_structure_v0(&response)?;
    let decoded: Response<Value> = serde_json::from_slice(&response)?;
    validate_exchange_response_context_v1(&decoded, request, chain_id, profile, genesis)?;
    decoded.data.context("native sync response lacks data")
}

fn validate_exchange_response_context_v1(
    decoded: &Response<Value>,
    request: &Value,
    chain_id: &str,
    profile: [u8; 32],
    genesis: [u8; 32],
) -> Result<()> {
    ensure!(
        decoded.schema == "trnm.native-client.response.v1"
            && Some(decoded.request_id.as_str()) == request["request_id"].as_str()
            && decoded.candidate_only
            && decoded.chain_id == chain_id
            && hex32(&decoded.profile_sha256)? == profile
            && hex32(&decoded.genesis_hash)? == genesis
            && decoded.ok
            && decoded.error.is_none(),
        "native sync transport response context/error"
    );
    Ok(())
}

fn run_sync_v1(args: &[OsString]) -> Result<()> {
    use crate::native_replay_sync_v1::{NativeReplayReceiverV1, ReplayManifestV1, CHUNK_BYTES};
    let root = PathBuf::from(&args[1]);
    let config_path = PathBuf::from(&args[2]);
    let context = PublicReportVerifierContext::load(&root, &config_path, text(&args[3])?)?;
    let profile_hash = hex32(text(&args[7])?)?;
    ensure!(
        context.native_client_profile_sha256_v1() == Some(profile_hash),
        "sync profile differs from independent manifest"
    );
    let consensus = context
        .validator_set()
        .validators()
        .iter()
        .map(|v| v.consensus_key().into_bytes())
        .collect::<Vec<_>>();
    let profile = NativeClientProfileV1::load_v1(
        &root.join("public/native-client-profile.json"),
        profile_hash,
        context.validator_set().chain_id().as_str(),
        &consensus,
    )?;
    let configuration = || -> Result<trnm_native_execution_v0::NativeApplicationConfigV0> {
        trnm_native_execution_v0::NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
            trnm_native_execution_v0::CanonicalLabNativeApplicationConfigInputsV0::new(
                context.run_id(),
                context.coordinator_manifest_sha256(),
                context.topology_sha256(),
                context.validator_set_sha256(),
                context.candidate_source_sha256(),
                context.local_validator(),
                context.validator_set().clone(),
                trnm_consensus_types::ConsensusParametersV0::reference_shadow_v0(),
                profile.authorized_signers_v1()?,
                profile.governance_signer_id.clone(),
            )?,
        )
    };
    let target = number(&args[6])?;
    ensure!(
        (1..=crate::native_replay_sync_v1::MAX_RECORDS).contains(&target),
        "sync candidate target bound"
    );
    let socket = Path::new(&args[4]);
    let destination = Path::new(&args[5]);
    let chain_id = context.validator_set().chain_id().as_str().to_owned();
    let genesis = *context.validator_set().genesis_hash().as_bytes();
    let deadline = Instant::now() + Duration::from_secs(600);
    let response = exchange_json(
        socket,
        &json!({"schema":"trnm.native-client.request.v1","request_id":"sync-manifest","op":"sync_manifest","data":{"target_height":target}}),
        &chain_id,
        profile_hash,
        genesis,
    )?;
    let manifest: ReplayManifestV1 = serde_json::from_value(response)?;
    let mut receiver = NativeReplayReceiverV1::open(
        destination,
        configuration()?,
        profile_hash,
        target,
        manifest.clone(),
    )?;
    for (offset, record) in manifest.records.iter().enumerate() {
        let height = offset as u64 + 1;
        for index in 0..(record.bytes as usize).div_ceil(CHUNK_BYTES) {
            remaining(deadline)?;
            if receiver.has_chunk(height, index)? {
                continue;
            }
            let response = exchange_json(
                socket,
                &json!({"schema":"trnm.native-client.request.v1","request_id":format!("sync-{height}-{index}"),"op":"sync_chunk","data":{"height":height,"index":index,"record_sha256":record.sha256}}),
                &chain_id,
                profile_hash,
                genesis,
            )?;
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Chunk {
                height: u64,
                index: usize,
                record_sha256: String,
                bytes_hex: String,
            }
            let chunk: Chunk = serde_json::from_value(response)?;
            ensure!(
                chunk.height == height
                    && chunk.index == index
                    && chunk.record_sha256 == record.sha256,
                "sync returned chunk coordinate differs"
            );
            receiver.accept_chunk(
                height,
                index,
                &decode_lower_hex(&chunk.bytes_hex, CHUNK_BYTES)?,
            )?;
        }
    }
    remaining(deadline)?;
    let head = receiver.replay_and_publish(configuration()?)?;
    println!(
        "{}",
        json!({"candidate_only":true,"application_only":true,"signing_authority":false,"height":head.height().get(),"block_id":hex::encode(head.block_id().as_bytes()),"state_root":hex::encode(head.state_root().as_bytes()),"manifest_sha256":hex::encode(manifest.digest()?)})
    );
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .context("native client absolute operation deadline expired")
}
fn wait_io(stream: &UnixStream, flags: rustix::event::PollFlags, deadline: Instant) -> Result<()> {
    loop {
        let timeout = rustix::event::Timespec::try_from(remaining(deadline)?)?;
        let mut fds = [rustix::event::PollFd::new(stream, flags)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) => bail!("native client absolute operation deadline expired"),
            Ok(_) => return Ok(()),
            Err(e) if e == rustix::io::Errno::INTR => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
fn connect_until(path: &Path, deadline: Instant) -> Result<UnixStream> {
    remaining(deadline)?;
    let descriptor = rustix::net::socket(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        None,
    )?;
    rustix::io::fcntl_setfd(&descriptor, rustix::io::FdFlags::CLOEXEC)?;
    let stream = UnixStream::from(descriptor);
    stream.set_nonblocking(true)?;
    let address = rustix::net::SocketAddrUnix::new(path)?;
    loop {
        remaining(deadline)?;
        match rustix::net::connect(&stream, &address) {
            Ok(()) => return Ok(stream),
            Err(e) if e == rustix::io::Errno::INTR => continue,
            Err(e)
                if [
                    rustix::io::Errno::INPROGRESS,
                    rustix::io::Errno::ALREADY,
                    rustix::io::Errno::AGAIN,
                ]
                .contains(&e) =>
            {
                wait_io(&stream, rustix::event::PollFlags::OUT, deadline)?;
                rustix::net::sockopt::socket_error(&stream)??;
                return Ok(stream);
            }
            Err(e) => return Err(e.into()),
        }
    }
}
fn write_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.write(bytes) {
            Ok(0) => bail!("native client socket closed during write"),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait_io(stream, rustix::event::PollFlags::OUT, deadline)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn read_until(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.read(bytes) {
            Ok(0) => bail!("native client socket closed before complete frame"),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait_io(stream, rustix::event::PollFlags::IN, deadline)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn run_cli_v1(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let args = arguments.collect::<Vec<_>>();
    let command = args.first().map(text).transpose()?.context(USAGE)?;
    match command {
        "sign" if args.len() == 12 => {
            let digest = hex32(text(&args[2])?)?;
            let profile =
                NativeClientProfileV1::load_v1(Path::new(&args[1]), digest, text(&args[3])?, &[])?;
            let identity = profile
                .signers
                .iter()
                .find(|s| s.signer_id == text(&args[4]).unwrap_or(""))
                .cloned()
                .context("selected client signer absent from pinned profile")?;
            let key_path = Path::new(&args[5]);
            let key_file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(key_path)?;
            let metadata = key_file.metadata()?;
            ensure!(
                metadata.is_file()
                    && metadata.mode() & 0o777 == 0o600
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.nlink() == 1
                    && metadata.len() == 64,
                "campaign key must be one owner-private exact seed file"
            );
            let mut seed_text = String::new();
            key_file.take(65).read_to_string(&mut seed_text)?;
            let key = SigningKey::from_bytes(&hex32(&seed_text)?);
            ensure!(
                hex::encode(key.verifying_key().to_bytes()) == identity.public_key_hex,
                "client private key differs from pinned public identity"
            );
            let nonce = number(&args[6])?;
            let ttl = number(&args[7])?;
            ensure!(
                (1..=300_000).contains(&ttl),
                "candidate signing TTL outside 1..300000 ms"
            );
            let command_bytes = bytes(Path::new(&args[10]), 256 * 1024)?;
            trnm_application_tx_builder_v0::validate_strict_json_structure_v0(&command_bytes)?;
            let command: trnm_protocol::CanonicalCommandV1 =
                serde_json::from_slice(&command_bytes)?;
            ensure!(
                serde_json::to_value(&command)? == serde_json::from_slice::<Value>(&command_bytes)?,
                "command contains unknown or normalized fields"
            );
            let now = profile.chain_now_ms_v1()?;
            let signer = CampaignSigner { identity, key };
            let built = build_signed_canonical_tx_v0(
                CanonicalTxBuildContextV0 {
                    chain_id: profile.chain_id,
                    sender: signer.identity.signer_id.clone(),
                    command_id: None,
                    transaction_sequence: nonce,
                    issued_at_unix_ms: now,
                    expires_at_unix_ms: now.checked_add(ttl).context("client TTL overflow")?,
                    max_gas: number(&args[8])?,
                    fee_limit: number(&args[9])? as u128,
                    limits: TxBuilderLimitsV0::candidate_v0(),
                },
                command,
                &signer,
            )?;
            ensure!(
                built.exact_outer_bytes().len() <= profile.maximum_outer_bytes,
                "signed native body exceeds pinned profile"
            );
            write_new(Path::new(&args[11]), built.exact_outer_bytes())?;
            println!(
                "{}",
                json!({"native_tx_hash":hex::encode(built.envelope().tx_hash()?),"signed_outer_bytes":built.exact_outer_bytes().len(),"candidate_only":true,"m05_intent_binding":false})
            );
        }
        "request" if args.len() == 6 => {
            let socket = Path::new(&args[1]);
            let metadata = std::fs::symlink_metadata(socket)?;
            ensure!(
                metadata.file_type().is_socket()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.mode() & 0o777 == 0o600,
                "native endpoint must be owner-private socket"
            );
            let request = bytes(Path::new(&args[2]), REQUEST_LIMIT)?;
            trnm_application_tx_builder_v0::validate_strict_json_structure_v0(&request)?;
            let request_value: Value = serde_json::from_slice(&request)?;
            let request_id = request_value
                .get("request_id")
                .and_then(Value::as_str)
                .context("request ID missing")?;
            let profile = hex32(text(&args[4])?)?;
            let genesis = hex32(text(&args[5])?)?;
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut stream = connect_until(socket, deadline)?;
            write_until(&mut stream, &(request.len() as u32).to_be_bytes(), deadline)?;
            write_until(&mut stream, &request, deadline)?;
            let mut prefix = [0u8; 4];
            read_until(&mut stream, &mut prefix, deadline)?;
            let count = u32::from_be_bytes(prefix) as usize;
            ensure!(
                count > 0 && count <= RESPONSE_LIMIT,
                "native response frame bound"
            );
            let mut response = vec![0; count];
            read_until(&mut stream, &mut response, deadline)?;
            let decoded: Response<Value> = serde_json::from_slice(&response)?;
            ensure!(
                decoded.schema == "trnm.native-client.response.v1"
                    && decoded.request_id == request_id
                    && decoded.candidate_only
                    && hex32(&decoded.profile_sha256)? == profile
                    && hex32(&decoded.genesis_hash)? == genesis,
                "native transport response context mismatch"
            );
            write_new(Path::new(&args[3]), &response)?;
            println!(
                "{}",
                json!({"transport_response_received":true,"ok":decoded.ok,"proof_verified_by_client":false})
            );
        }
        "sync" if args.len() == 8 => run_sync_v1(&args)?,
        "verify" if args.len() == 8 => {
            let root = PathBuf::from(&args[1]);
            let config = PathBuf::from(&args[2]);
            let context = PublicReportVerifierContext::load(&root, &config, text(&args[3])?)?;
            let config_bytes = bytes(&root.join(&config), 64 * 1024)?;
            ensure!(
                <[u8; 32]>::from(Sha256::digest(&config_bytes)) == context.config_sha256(),
                "observer config changed after pinning"
            );
            let config_json: Value = serde_json::from_slice(&config_bytes)?;
            let expected_profile = hex32(text(&args[7])?)?;
            ensure!(
                config_json
                    .get("native_client_profile_sha256")
                    .and_then(Value::as_str)
                    == Some(text(&args[7])?),
                "observer manifest does not select requested native profile"
            );
            let consensus = context
                .validator_set()
                .validators()
                .iter()
                .map(|v| v.consensus_key().into_bytes())
                .collect::<Vec<_>>();
            let profile = NativeClientProfileV1::load_v1(
                &root.join("public/native-client-profile.json"),
                expected_profile,
                context.validator_set().chain_id().as_str(),
                &consensus,
            )?;
            let expected = hex32(text(&args[5])?)?;
            let verified = verify_response_v1(
                &bytes(Path::new(&args[4]), RESPONSE_LIMIT)?,
                context.validator_set(),
                &profile,
                expected,
                &bytes(Path::new(&args[6]), profile.maximum_outer_bytes)?,
            )?;
            println!(
                "{}",
                json!({"native_tx_hash":hex::encode(expected),"proof_verified_by_client":true,"height":verified.header().height().get().to_string(),"index":verified.transaction_index(),"candidate_only":true,"m05_intent_binding":false})
            );
        }
        _ => bail!(USAGE),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn native_client_sign_command_pins_key_profile_nonce_and_exact_output_v1() {
        let temp = tempfile::tempdir().unwrap();
        let keys = temp.path().join("isolated-client");
        let profile = crate::native_client_profile::generate_isolated_native_client_profile_v1(
            &keys,
            "client-tool-test",
        )
        .unwrap();
        let command = temp.path().join("command.json");
        std::fs::write(
            &command,
            serde_json::to_vec(&trnm_protocol::CanonicalCommandV1::CreditAccount {
                account: profile.signers[1].signer_id.clone(),
                amount: 100,
            })
            .unwrap(),
        )
        .unwrap();
        let output = temp.path().join("outer.json");
        let mut args = vec![
            OsString::from("sign"),
            keys.join("native-client-profile.json").into_os_string(),
            hex::encode(profile.digest_v1().unwrap()).into(),
            profile.chain_id.clone().into(),
            profile.signers[0].signer_id.clone().into(),
            keys.join("operator.key").into_os_string(),
            "1".into(),
            "300000".into(),
            "100000".into(),
            "1000000".into(),
            command.clone().into_os_string(),
            output.clone().into_os_string(),
        ];
        run_cli_v1(args.clone().into_iter()).unwrap();
        let exact = std::fs::read(&output).unwrap();
        let tx = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&exact).unwrap();
        assert_eq!(tx.envelope().signer_id, profile.signers[0].signer_id);
        assert_eq!(tx.exact_outer_bytes(), exact);
        assert!(run_cli_v1(args.clone().into_iter()).is_err());
        args[11] = temp.path().join("different.json").into_os_string();
        args[5] = keys.join("client.key").into_os_string();
        assert!(run_cli_v1(args.clone().into_iter()).is_err());
        args[5] = keys.join("operator.key").into_os_string();
        args[6] = "01".into();
        assert!(run_cli_v1(args.clone().into_iter()).is_err());
        args[6] = "1".into();
        let mut unknown: Value = serde_json::from_slice(&std::fs::read(&command).unwrap()).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown_field".into(), json!(true));
        std::fs::write(&command, serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert!(run_cli_v1(args.clone().into_iter()).is_err());
        std::fs::set_permissions(
            keys.join("operator.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(run_cli_v1(args.into_iter()).is_err());
        assert!(!temp.path().join("different.json").exists());
    }
    #[test]
    fn native_client_absolute_deadline_rejects_slow_partial_frame_v1() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let peer = std::thread::spawn(move || {
            for _ in 0..8 {
                std::thread::sleep(Duration::from_millis(10));
                if writer.write_all(&[1]).is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        let mut buffer = [0u8; 8];
        assert!(read_until(&mut reader, &mut buffer, start + Duration::from_millis(25)).is_err());
        assert!(start.elapsed() < Duration::from_millis(200));
        drop(reader);
        peer.join().unwrap();
        assert!(connect_until(
            Path::new("/unused"),
            Instant::now() - Duration::from_millis(1)
        )
        .is_err());
    }
    #[test]
    fn native_sync_transport_rejects_wrong_chain_context_v1() {
        let request = json!({
            "schema": "trnm.native-client.request.v1",
            "request_id": "sync-context",
            "op": "sync_manifest",
            "data": {"target_height": 1}
        });
        let profile = [0x11; 32];
        let genesis = [0x22; 32];
        let mut response = Response {
            schema: "trnm.native-client.response.v1".into(),
            request_id: "sync-context".into(),
            candidate_only: true,
            chain_id: "wrong-chain".into(),
            genesis_hash: hex::encode(genesis),
            profile_sha256: hex::encode(profile),
            ok: true,
            data: Some(json!({})),
            error: None,
        };
        assert!(validate_exchange_response_context_v1(
            &response,
            &request,
            "expected-chain",
            profile,
            genesis
        )
        .is_err());
        response.chain_id = "expected-chain".into();
        validate_exchange_response_context_v1(
            &response,
            &request,
            "expected-chain",
            profile,
            genesis,
        )
        .unwrap();
    }
}
