#![forbid(unsafe_code)]
//! Candidate-only persistent host entrypoint for the first durable authority cut.
//!
//! This process intentionally has no listener, peer authentication, pacemaker,
//! signer, finality, checkpoint publication, state-sync download, or production
//! activation path. It proves only exact-source recovery plus
//! `BoundIngressV0 -> Prepared` persistence through the reviewed file adapter.

use std::{
    env,
    error::Error,
    fmt,
    path::{Path, PathBuf},
    process,
};
use trnm_durable_file_adapters_v0::FileAuthorityCoordinatorV0;
use trnm_node_boundary_v0::{
    BoundIngressV0, Digest32V0, HostReadinessV0, IngressFrameV0, IoPollV0,
    IoRuntimeV0, NodeIdentityV0, OutboundFrameV0, PersistentValidatorHostV0,
    StepBudgetV0,
};

const ACK: &str = "--acknowledge-candidate-only";
const SCHEMA: &str = "trnm_candidate_persistent_host_v0";

#[derive(Debug)]
struct CandidateIoError;

impl fmt::Display for CandidateIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("candidate persistent host has no outbound I/O authority")
    }
}

impl Error for CandidateIoError {}

struct CandidateInertIo;

impl IoRuntimeV0 for CandidateInertIo {
    type Error = CandidateIoError;

    fn poll_ingress(&mut self, _budget: StepBudgetV0) -> Result<IoPollV0, Self::Error> {
        Ok(IoPollV0::Idle)
    }

    fn publish(
        &mut self,
        _frame: OutboundFrameV0,
        _budget: StepBudgetV0,
    ) -> Result<(), Self::Error> {
        Err(CandidateIoError)
    }
}

fn usage() -> &'static str {
    "usage:\n  trnm-candidate-persistent-host --acknowledge-candidate-only status \
<absolute-root> <chain-id-hex> <validator-id-hex> <application-id-hex> <generation>\n  \
trnm-candidate-persistent-host --acknowledge-candidate-only prepare <absolute-root> \
<chain-id-hex> <validator-id-hex> <application-id-hex> <generation> <height> <view> \
<block-id-hex> <parent-id-hex> <peer-id-hex> <profile-digest-hex> <replay-nonce> \
<payload-utf8>"
}

fn parse_digest(label: &str, value: &str) -> Result<Digest32V0, String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{label} must be exactly 64 lowercase hexadecimal characters"));
    }
    if value.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte)) {
        return Err(format!("{label} must use lowercase hexadecimal characters only"));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| format!("{label} is not UTF-8"))?;
        output[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("{label} is not hexadecimal"))?;
    }
    let digest = Digest32V0(output);
    if digest == Digest32V0([0; 32]) {
        return Err(format!("{label} may not be the zero digest"));
    }
    Ok(digest)
}

fn parse_u64(label: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{label} must be an unsigned 64-bit integer"))
}

fn parse_nonzero_u64(label: &str, value: &str) -> Result<u64, String> {
    let parsed = parse_u64(label, value)?;
    if parsed == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(parsed)
}

fn parse_root(value: &str) -> Result<PathBuf, String> {
    let root = PathBuf::from(value);
    if !root.is_absolute() {
        return Err("candidate root must be absolute".to_string());
    }
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|error| format!("candidate root is not accessible: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("candidate root must be an existing non-symlink directory".to_string());
    }
    Ok(root)
}

fn parse_identity(arguments: &[String]) -> Result<NodeIdentityV0, String> {
    if arguments.len() < 4 {
        return Err("identity arguments are incomplete".to_string());
    }
    NodeIdentityV0 {
        chain_id: parse_digest("chain-id", &arguments[0])?,
        validator_id: parse_digest("validator-id", &arguments[1])?,
        application_id: parse_digest("application-id", &arguments[2])?,
        generation: parse_nonzero_u64("generation", &arguments[3])?,
    }
    .validate()
    .map_err(|error| error.to_string())
}

fn digest_hex(digest: Digest32V0) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest.0 {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn readiness_label(readiness: HostReadinessV0) -> &'static str {
    match readiness {
        HostReadinessV0::Recovering => "recovering",
        HostReadinessV0::Ready => "ready",
        HostReadinessV0::Quarantined(_) => "quarantined",
    }
}

fn open_host(
    root: &Path,
    identity: NodeIdentityV0,
) -> Result<
    PersistentValidatorHostV0<FileAuthorityCoordinatorV0, CandidateInertIo>,
    Box<dyn Error>,
> {
    let coordinator = FileAuthorityCoordinatorV0::open(root, identity)?;
    Ok(PersistentValidatorHostV0::new(
        coordinator,
        CandidateInertIo,
        StepBudgetV0::default(),
    )?)
}

fn run_status(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    if arguments.len() != 5 {
        return Err(usage().into());
    }
    let root = parse_root(&arguments[0])?;
    let identity = parse_identity(&arguments[1..5])?;
    let mut host = open_host(&root, identity)?;
    let readiness = host.recover()?;
    let quarantine_reason = match readiness {
        HostReadinessV0::Quarantined(reason) => format!("\"{}\"", digest_hex(reason)),
        _ => "null".to_string(),
    };
    println!(
        "{{\"schema\":\"{SCHEMA}\",\"command\":\"status\",\"readiness\":\"{}\",\"quarantine_reason\":{},\"persistent_authority\":true,\"authenticated_network\":false,\"pacemaker\":false,\"signing\":false,\"finality\":false,\"state_sync_download\":false,\"production_candidate\":false,\"production_activation\":false,\"start_permitted\":false}}",
        readiness_label(readiness),
        quarantine_reason,
    );
    if matches!(readiness, HostReadinessV0::Quarantined(_)) {
        return Err("candidate authority is quarantined".into());
    }
    Ok(())
}

fn run_prepare(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    if arguments.len() != 13 {
        return Err(usage().into());
    }
    let root = parse_root(&arguments[0])?;
    let identity = parse_identity(&arguments[1..5])?;
    let height = parse_nonzero_u64("height", &arguments[5])?;
    let view = parse_u64("view", &arguments[6])?;
    let block_id = parse_digest("block-id", &arguments[7])?;
    let parent_id = parse_digest("parent-id", &arguments[8])?;
    let peer_id = parse_digest("peer-id", &arguments[9])?;
    let profile_digest = parse_digest("profile-digest", &arguments[10])?;
    let replay_nonce = parse_nonzero_u64("replay-nonce", &arguments[11])?;
    let payload = arguments[12].as_bytes().to_vec();
    let frame = IngressFrameV0::new(peer_id, profile_digest, replay_nonce, payload)?;
    let ingress = BoundIngressV0::derive(
        identity,
        height,
        view,
        block_id,
        parent_id,
        frame,
    )?;

    let mut host = open_host(&root, identity)?;
    let readiness = host.recover()?;
    if readiness != HostReadinessV0::Ready {
        return Err("candidate authority is not ready".into());
    }
    let receipt = host.prepare_bound_ingress(&ingress)?;
    println!(
        "{{\"schema\":\"{SCHEMA}\",\"command\":\"prepare\",\"operation_id\":\"{}\",\"height\":{},\"view\":{},\"stage\":\"Prepared\",\"durable_sequence\":{},\"facts_digest\":\"{}\",\"record_digest\":\"{}\",\"exact_replay_safe\":true,\"authenticated_network\":false,\"signing\":false,\"finality\":false,\"production_candidate\":false,\"production_activation\":false}}",
        digest_hex(receipt.binding.operation_id),
        receipt.binding.height,
        receipt.binding.view,
        receipt.durable_sequence,
        digest_hex(receipt.facts_digest),
        digest_hex(receipt.record_digest),
    );
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.first().map(String::as_str) != Some(ACK) {
        return Err(format!("explicit {ACK} is required\n{}", usage()).into());
    }
    let command = arguments.get(1).map(String::as_str).ok_or_else(|| usage())?;
    match command {
        "status" => run_status(&arguments[2..]),
        "prepare" => run_prepare(&arguments[2..]),
        _ => Err(usage().into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("candidate persistent host refused operation: {error}");
        process::exit(2);
    }
}
