//! One-shot actual process launch. CAS is not atomic with entering the kernel.
use super::execution_wire::{Contract, LaunchAttempt};
use super::frontier::{invalid, Digest32, Result};
use super::owner::Owner;
use super::process_identity::{self, WorkingDirectory};
use super::records::Record;
use super::sealed::{DataBuilder, Sealed};
use serde::{Deserialize, Serialize};
use std::ffi::CString;

pub(super) const MAX_CONFIGURATION: usize = 4 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handoff {
    pub schema_version: u32,
    pub namespace: Digest32,
    pub attempt: Digest32,
}

pub(super) fn configuration_digest(value: &str) -> Result<Digest32> {
    let bytes = hex::decode(value).map_err(std::io::Error::other)?;
    if bytes.len() != 32 || hex::encode(&bytes) != value {
        return Err(invalid("M15 configuration digest encoding"));
    }
    bytes
        .try_into()
        .map_err(|_| invalid("M15 configuration digest length"))
}
pub(super) fn check_inputs(contract: &Contract, raw: &[u8], expected: Digest32) -> Result<()> {
    let actual = crate::operator_continuous_controller::validate_m15_configuration(
        &contract.outside.borrowed(),
        raw,
    )
    .map_err(std::io::Error::other)?;
    if actual != expected {
        return Err(invalid(
            "M15 actual protected inputs differ from current signed policy",
        ));
    }
    Ok(())
}

/// The CLI does not choose a root, executable path, argv or environment. All are
/// selected by the currently signed policy under the fixed OS deployment root.
pub(super) fn execute() -> Result<()> {
    let mut owner = Owner::open()?;
    let state = owner.reload()?;
    let policy = state
        .configuration
        .as_ref()
        .ok_or_else(|| invalid("M15 current policy missing"))?
        .clone();
    let contract = policy.contract.clone();
    owner.revalidate_current(&state, &contract)?;
    let (installation_id, installation) = state
        .installations
        .iter()
        .rev()
        .find(|(_, i)| {
            i.bundle == contract.node_bundle
                && i.artifact_name == contract.artifact_name
                && i.program_sha256 == contract.program_sha256
        })
        .ok_or_else(|| invalid("M15 policy artifact has no authenticated installation"))?;
    let image = super::catalog::load(
        &owner,
        installation,
        contract.program_size,
        contract.platform_digest,
    )?;
    let meta = std::fs::symlink_metadata(&contract.outside.path)?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_CONFIGURATION as u64 {
        return Err(invalid("M15 launch configuration size/type"));
    }
    let (configuration, _) = Sealed::from_path(
        &contract.outside.path,
        configuration_digest(&contract.outside.sha256)?,
        meta.len(),
        false,
    )?;
    check_inputs(
        &contract,
        &configuration.read(MAX_CONFIGURATION)?,
        policy.inputs_digest,
    )?;
    let working = WorkingDirectory::open(&contract.working_directory, &contract.working_identity)?;
    let handoff = DataBuilder::new()?;
    let process = process_identity::actual()?;
    let mut nonce = [0; 32];
    let count = rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::NONBLOCK)?;
    if count != nonce.len() || nonce == [0; 32] {
        return Err(invalid("M15 launch nonce unavailable"));
    }
    let observed_at = owner.now()?;
    let window = state.current_contract(&contract, observed_at)?;
    let launch_fd: u32 = configuration
        .raw_fd()
        .try_into()
        .map_err(std::io::Error::other)?;
    let handoff_fd: u32 = handoff.raw_fd().try_into().map_err(std::io::Error::other)?;
    let mut actual_arguments = contract.arguments.clone();
    actual_arguments.extend([
        "--m15-launch-fd".into(),
        launch_fd.to_string(),
        "--m15-handoff-fd".into(),
        handoff_fd.to_string(),
    ]);
    let attempt = LaunchAttempt {
        schema_version: 1,
        nonce,
        process: process.clone(),
        installation: *installation_id,
        contract: contract.clone(),
        policy_digest: policy.digest()?,
        kernel_checkpoint: state.authority.checkpoint(),
        root_digest: state.authority.root_digest(),
        root_generation: state.authority.root_generation(),
        actual_arguments: actual_arguments.clone(),
        launch_fd,
        handoff_fd,
        observed_at,
        expires_at: window.expires_at,
    };
    let digest = owner.append(Record::LaunchAttempt(Box::new(attempt)), |_, _| {
        image.recheck()?;
        configuration.recheck()?;
        working.recheck()?;
        if process_identity::actual()? != process {
            return Err(invalid("M15 launcher process changed"));
        }
        Ok(())
    })?;
    let raw = super::codec::encode(
        &Handoff {
            schema_version: 1,
            namespace: owner.context.namespace,
            attempt: digest,
        },
        4096,
    )?;
    let handoff = handoff.finish(&raw, 4096)?;
    let args = actual_arguments
        .iter()
        .map(|v| CString::new(v.as_bytes()).map_err(std::io::Error::other))
        .collect::<Result<Vec<_>>>()?;
    let env = contract
        .environment
        .iter()
        .map(|(key, value)| CString::new(format!("{key}={value}")).map_err(std::io::Error::other))
        .collect::<Result<Vec<_>>>()?;
    // Allocate, parse, copy, seal, and change directory before the last fresh
    // authority observation. No pathname is reopened as an executable afterward.
    working.enter()?;
    configuration.pass_to_exec()?;
    handoff.pass_to_exec()?;
    image.recheck()?;
    working.require_current()?;
    let current = owner.reload()?;
    let final_window = owner.revalidate_current(&current, &contract)?;
    current.pending_attempt(digest, final_window.not_before)?;
    owner.finish_observation(final_window)?;
    // The same sealed file reaches execveat through the safe library API.
    // Any error retains the attempt as unknown; there is no path fallback/retry.
    nix::unistd::execveat(
        image.file(),
        c"",
        &args,
        &env,
        nix::fcntl::AtFlags::AT_EMPTY_PATH,
    )
    .map(|never| match never {})
    .map_err(std::io::Error::other)
}
