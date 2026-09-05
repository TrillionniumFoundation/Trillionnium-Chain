#![forbid(unsafe_code)]
//! Candidate-only persistent host entrypoint for bounded authority-journal cuts.
//!
//! This process intentionally has no listener, peer authentication, pacemaker,
//! signer, finality decision, checkpoint publication, state-sync download, or
//! production activation path. It can persist an exact bound ingress as
//! `Prepared` and append externally supplied, opaque fact digests through the
//! frozen authority-stage sequence. It never creates or interprets those facts.

use std::{
    env,
    error::Error,
    fmt,
    path::{Path, PathBuf},
    process,
};
use trnm_durable_file_adapters_v0::FileAuthorityCoordinatorV0;
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0,
    BoundIngressV0, Digest32V0, HostReadinessV0, IngressFrameV0, IoPollV0, IoRuntimeV0,
    NodeIdentityV0, OutboundFrameV0, PersistentValidatorHostV0, RecoveryDispositionV0,
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
<payload-utf8>\n  \
trnm-candidate-persistent-host --acknowledge-candidate-only advance <absolute-root> \
<chain-id-hex> <validator-id-hex> <application-id-hex> <generation> <next-stage> \
<facts-digest-hex>\n\nnext-stage: ApplicationSealed | SafetyPersisted | SignIntentPersisted | \
SignatureConfirmed | FinalityApplied | CheckpointConfirmed | OutboundPublished"
}

fn parse_digest(label: &str, value: &str) -> Result<Digest32V0, String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!(
            "{label} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    if value
        .bytes()
        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must use lowercase hexadecimal characters only"
        ));
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

fn parse_stage(value: &str) -> Result<AuthorityStageV0, String> {
    match value {
        "ApplicationSealed" => Ok(AuthorityStageV0::ApplicationSealed),
        "SafetyPersisted" => Ok(AuthorityStageV0::SafetyPersisted),
        "SignIntentPersisted" => Ok(AuthorityStageV0::SignIntentPersisted),
        "SignatureConfirmed" => Ok(AuthorityStageV0::SignatureConfirmed),
        "FinalityApplied" => Ok(AuthorityStageV0::FinalityApplied),
        "CheckpointConfirmed" => Ok(AuthorityStageV0::CheckpointConfirmed),
        "OutboundPublished" => Ok(AuthorityStageV0::OutboundPublished),
        _ => Err("next-stage is not a supported exact authority successor".to_string()),
    }
}

const fn stage_label(stage: AuthorityStageV0) -> &'static str {
    match stage {
        AuthorityStageV0::Prepared => "Prepared",
        AuthorityStageV0::ApplicationSealed => "ApplicationSealed",
        AuthorityStageV0::SafetyPersisted => "SafetyPersisted",
        AuthorityStageV0::SignIntentPersisted => "SignIntentPersisted",
        AuthorityStageV0::SignatureConfirmed => "SignatureConfirmed",
        AuthorityStageV0::FinalityApplied => "FinalityApplied",
        AuthorityStageV0::CheckpointConfirmed => "CheckpointConfirmed",
        AuthorityStageV0::OutboundPublished => "OutboundPublished",
    }
}

const fn predecessor(stage: AuthorityStageV0) -> Option<AuthorityStageV0> {
    match stage {
        AuthorityStageV0::Prepared => None,
        AuthorityStageV0::ApplicationSealed => Some(AuthorityStageV0::Prepared),
        AuthorityStageV0::SafetyPersisted => Some(AuthorityStageV0::ApplicationSealed),
        AuthorityStageV0::SignIntentPersisted => Some(AuthorityStageV0::SafetyPersisted),
        AuthorityStageV0::SignatureConfirmed => Some(AuthorityStageV0::SignIntentPersisted),
        AuthorityStageV0::FinalityApplied => Some(AuthorityStageV0::SignatureConfirmed),
        AuthorityStageV0::CheckpointConfirmed => Some(AuthorityStageV0::FinalityApplied),
        AuthorityStageV0::OutboundPublished => Some(AuthorityStageV0::CheckpointConfirmed),
    }
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
) -> Result<PersistentValidatorHostV0<FileAuthorityCoordinatorV0, CandidateInertIo>, Box<dyn Error>>
{
    let coordinator = FileAuthorityCoordinatorV0::open(root, identity)?;
    Ok(PersistentValidatorHostV0::new(
        coordinator,
        CandidateInertIo,
        StepBudgetV0::default(),
    )?)
}

fn validate_recovery(
    identity: NodeIdentityV0,
    disposition: RecoveryDispositionV0,
    current: Option<AuthorityReceiptV0>,
) -> Result<Option<AuthorityReceiptV0>, String> {
    match (disposition, current) {
        (RecoveryDispositionV0::Clean, None) => Ok(None),
        (
            RecoveryDispositionV0::Resume {
                binding,
                durable_stage,
                durable_sequence,
            },
            Some(receipt),
        ) => {
            binding
                .validate(identity)
                .map_err(|error| error.to_string())?;
            if receipt.binding != binding
                || receipt.durable_stage != durable_stage
                || receipt.durable_sequence != durable_sequence
                || receipt.facts_digest == Digest32V0([0; 32])
                || receipt.record_digest == Digest32V0([0; 32])
            {
                return Err("recovery summary does not match the exact current receipt".to_string());
            }
            Ok(Some(receipt))
        }
        (RecoveryDispositionV0::Quarantine { .. }, _) => {
            Err("candidate authority is quarantined".to_string())
        }
        _ => Err("recovery summary/current receipt cardinality mismatch".to_string()),
    }
}

fn recover_coordinator(
    coordinator: &mut FileAuthorityCoordinatorV0,
    identity: NodeIdentityV0,
) -> Result<Option<AuthorityReceiptV0>, Box<dyn Error>> {
    let disposition = coordinator.recover()?;
    Ok(validate_recovery(
        identity,
        disposition,
        coordinator.current_receipt(),
    )?)
}

fn verify_fresh_readback(
    root: &Path,
    identity: NodeIdentityV0,
    expected: AuthorityReceiptV0,
) -> Result<(), Box<dyn Error>> {
    let mut reopened = FileAuthorityCoordinatorV0::open(root, identity)?;
    let current = recover_coordinator(&mut reopened, identity)?
        .ok_or("fresh readback lost the just-persisted authority receipt")?;
    if current != expected {
        return Err("fresh readback returned a substituted authority receipt".into());
    }
    Ok(())
}

fn print_receipt(command: &str, receipt: AuthorityReceiptV0, replay: bool) {
    println!(
        "{{\"schema\":\"{SCHEMA}\",\"command\":\"{command}\",\"operation_id\":\"{}\",\"height\":{},\"view\":{},\"stage\":\"{}\",\"durable_sequence\":{},\"facts_digest\":\"{}\",\"record_digest\":\"{}\",\"exact_replay_safe\":true,\"exact_replay\":{},\"fresh_readback\":true,\"authenticated_network\":false,\"pacemaker\":false,\"signing\":false,\"finality_authority\":false,\"checkpoint_authority\":false,\"production_candidate\":false,\"production_activation\":false}}",
        digest_hex(receipt.binding.operation_id),
        receipt.binding.height,
        receipt.binding.view,
        stage_label(receipt.durable_stage),
        receipt.durable_sequence,
        digest_hex(receipt.facts_digest),
        digest_hex(receipt.record_digest),
        replay,
    );
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
    let (coordinator, _) = host.into_parts();
    let current = coordinator.current_receipt();
    let stage = current.map_or_else(
        || "null".to_string(),
        |receipt| format!("\"{}\"", stage_label(receipt.durable_stage)),
    );
    let sequence = current.map_or_else(
        || "null".to_string(),
        |receipt| receipt.durable_sequence.to_string(),
    );
    println!(
        "{{\"schema\":\"{SCHEMA}\",\"command\":\"status\",\"readiness\":\"{}\",\"quarantine_reason\":{},\"stage\":{},\"durable_sequence\":{},\"fresh_readback\":true,\"persistent_authority\":true,\"authenticated_network\":false,\"pacemaker\":false,\"signing\":false,\"finality_authority\":false,\"checkpoint_authority\":false,\"state_sync_download\":false,\"production_candidate\":false,\"production_activation\":false,\"start_permitted\":false}}",
        readiness_label(readiness),
        quarantine_reason,
        stage,
        sequence,
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
    let ingress = BoundIngressV0::derive(identity, height, view, block_id, parent_id, frame)?;

    let mut host = open_host(&root, identity)?;
    let readiness = host.recover()?;
    if readiness != HostReadinessV0::Ready {
        return Err("candidate authority is not ready".into());
    }
    let receipt = host.prepare_bound_ingress(&ingress)?;
    drop(host);
    verify_fresh_readback(&root, identity, receipt)?;
    print_receipt("prepare", receipt, false);
    Ok(())
}

fn run_advance(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    if arguments.len() != 7 {
        return Err(usage().into());
    }
    let root = parse_root(&arguments[0])?;
    let identity = parse_identity(&arguments[1..5])?;
    let next_stage = parse_stage(&arguments[5])?;
    let facts_digest = parse_digest("facts-digest", &arguments[6])?;

    let mut coordinator = FileAuthorityCoordinatorV0::open(&root, identity)?;
    let current = recover_coordinator(&mut coordinator, identity)?
        .ok_or("advance requires an existing Prepared authority receipt")?;

    let replay = current.durable_stage == next_stage;
    let expected_stage = if replay {
        predecessor(next_stage).ok_or("Prepared must be replayed with prepare, not advance")?
    } else {
        if current.durable_stage.successor() != Some(next_stage) {
            return Err("requested stage is not the exact durable successor".into());
        }
        current.durable_stage
    };
    let expected_sequence = if replay {
        current.durable_sequence
    } else {
        current
            .durable_sequence
            .checked_add(1)
            .ok_or("durable authority sequence overflow")?
    };
    let expected_record_digest = if replay {
        None
    } else {
        Some(Digest32V0::hash(
            b"trnm.node.authority-record.v0",
            &[
                &identity.digest().0,
                &current.binding.operation_id.0,
                &[next_stage as u8],
                &expected_sequence.to_be_bytes(),
                &facts_digest.0,
                &current.record_digest.0,
            ],
        ))
    };

    let receipt = coordinator.apply(AuthorityCommandV0::Advance {
        binding: current.binding,
        expected_stage,
        next_stage,
        facts_digest,
    })?;
    if receipt.binding != current.binding
        || receipt.durable_stage != next_stage
        || receipt.durable_sequence != expected_sequence
        || receipt.facts_digest != facts_digest
        || receipt.record_digest == Digest32V0([0; 32])
        || expected_record_digest.is_some_and(|expected| expected != receipt.record_digest)
        || (replay && receipt != current)
    {
        return Err("authority adapter returned a substituted stage receipt".into());
    }
    drop(coordinator);
    verify_fresh_readback(&root, identity, receipt)?;
    print_receipt("advance", receipt, replay);
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.first().map(String::as_str) != Some(ACK) {
        return Err(format!("explicit {ACK} is required\n{}", usage()).into());
    }
    let command = match arguments.get(1) {
        Some(command) => command.as_str(),
        None => return Err(usage().into()),
    };
    match command {
        "status" => run_status(&arguments[2..]),
        "prepare" => run_prepare(&arguments[2..]),
        "advance" => run_advance(&arguments[2..]),
        _ => Err(usage().into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("candidate persistent host refused operation: {error}");
        process::exit(2);
    }
}
