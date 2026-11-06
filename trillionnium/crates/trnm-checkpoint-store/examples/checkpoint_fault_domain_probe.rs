//! Isolated recovery exercise using the real checkpoint owner.
//!
//! Every checkpoint field below is synthetic test data. This program neither
//! imports Node state nor supplies business authorization or key-custody proof.
//! A second host must actually retain and return the fresh pin to establish the
//! limited two-host observation; two local directories alone do not do that.

use std::{
    env,
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

use trnm_checkpoint_store::{
    read_external_journal_checkpoint_v1, write_new_external_journal_checkpoint_v1,
    ExternalCheckpointAuthorityV2,
};
use trnm_checkpoint_types::{
    BlockId, EffectWatermarkV2, ExternalCheckpointFieldsV2, ExternalCheckpointV2, StateRoot,
};

type ProbeResult<T> = Result<T, Box<dyn Error>>;

fn checkpoint(
    generation: u64,
    previous: [u8; 32],
    state_root: [u8; 32],
) -> ProbeResult<ExternalCheckpointV2> {
    Ok(ExternalCheckpointV2::new(ExternalCheckpointFieldsV2 {
        scope: [1; 32],
        generation,
        predecessor_checksum: previous,
        authority_journal_id: [2; 32],
        authority_verifier_profile_ref: [3; 32],
        authority_revision: generation + 1,
        authority_state_record_checksum: [4; 32],
        authority_record_chain_checksum: [5; 32],
        application_host_config_ref: [6; 32],
        application_projection_profile_ref: [7; 32],
        application_authority_binding_manifest_checksum: [8; 32],
        application_committed_head_row_checksum: [9; 32],
        application_recovery_closure_checksum: [10; 32],
        application_block_id: BlockId::new([11; 32]),
        application_height: generation + 1,
        application_state_root: StateRoot::new(state_root),
        application_generation: generation + 1,
        application_timestamp_ms: 100 + generation,
        effect_journal_id: [13; 32],
        effect_profile_checksum: [14; 32],
        effect_exact_watermark: EffectWatermarkV2::from_persisted_parts(
            [1; 32], [13; 32], generation, [15; 32],
        )?,
    })?)
}

fn new_private_directory(path: &Path) -> ProbeResult<()> {
    // Deliberately no create_dir_all and no overwrite of an existing namespace.
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn prepare(root: &Path, state_root: [u8; 32]) -> ProbeResult<()> {
    if !root.is_absolute() {
        return Err("probe directory must be absolute".into());
    }
    new_private_directory(root)?;
    let current = root.join("node");
    let old = root.join("old-node");
    new_private_directory(&current)?;
    new_private_directory(&old)?;
    let first = checkpoint(0, [0; 32], state_root)?;
    let second = checkpoint(1, first.checkpoint_checksum(), state_root)?;
    let mut owner = ExternalCheckpointAuthorityV2::register_new(current.join("checkpoint.log"))?;
    owner.compare_and_advance_checked(None, first)?;
    let old_pin = owner.journal_checkpoint_v1()?;
    // Preserve the complete first-generation namespace, including its local pin.
    write_new_external_journal_checkpoint_v1(old.join("local-pin.bin"), old_pin)?;
    for name in [
        "checkpoint.log",
        ".checkpoint.log.head-v2",
        ".checkpoint.log.lock-v2",
    ] {
        fs::copy(current.join(name), old.join(name))?;
    }
    owner.compare_and_advance_checked(Some(first), second)?;
    let fresh_pin = owner.journal_checkpoint_v1()?;
    write_new_external_journal_checkpoint_v1(current.join("local-pin.bin"), fresh_pin)?;
    write_new_external_journal_checkpoint_v1(root.join("fresh-export.bin"), fresh_pin)?;
    println!(
        "checkpoint_fault_domain_probe status=prepared old_count={} fresh_count={} synthetic=true production_qualified=false",
        old_pin.record_count(),
        fresh_pin.record_count()
    );
    Ok(())
}

fn verify(log: &Path, pin: &Path) -> ProbeResult<()> {
    let expected = read_external_journal_checkpoint_v1(pin)?;
    let owner = ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(log, expected)?;
    let observed = owner.journal_checkpoint_v1()?;
    if observed != expected || owner.load_checked([1; 32])?.is_none() {
        return Err("probe recovered the wrong complete checkpoint".into());
    }
    println!(
        "checkpoint_fault_domain_probe status=accepted record_count={} synthetic=true production_qualified=false",
        observed.record_count()
    );
    Ok(())
}

fn run() -> ProbeResult<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [command, root] if command == "prepare" => prepare(&PathBuf::from(root), [12; 32]),
        [command, root] if command == "prepare-alternate" => {
            prepare(&PathBuf::from(root), [99; 32])
        }
        [command, log, pin] if command == "verify" => {
            verify(&PathBuf::from(log), &PathBuf::from(pin))
        }
        _ => Err("usage: checkpoint_fault_domain_probe prepare|prepare-alternate <new-absolute-directory> | verify <log-path> <independently-retained-pin>".into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("checkpoint_fault_domain_probe status=refused error={error}");
            ExitCode::FAILURE
        }
    }
}
