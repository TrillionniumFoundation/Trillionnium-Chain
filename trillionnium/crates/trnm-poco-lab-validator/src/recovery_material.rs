//! Candidate-only operational materialization for the direct-seven process-2
//! RecoveryReady/RecoveryStart barrier.
//!
//! Each validator signs only its own statement with its locally loaded test
//! consensus key.  The coordinator may move the bounded canonical statement
//! files, but never receives a private key.  Only the target validator may
//! aggregate and create-new persist the ReadySet and Start certificate under
//! its authenticated run root.  These commands do not arm a timer, open
//! consensus ingress, change production flags, or bypass the process-host
//! transition.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_recovery_context_v1_exact, decode_recovery_ready_set_v1_exact,
    decode_signed_recovery_ready_v1_exact, decode_signed_recovery_start_v1_exact,
    RecoveryContextV1, RecoveryReadySetV1, SignedRecoveryReadyV1, SignedRecoveryStartV1,
    ValidatorId, ValidatorSet, DIRECT7_RECOVERY_VALIDATOR_COUNT_V1, MAX_RECOVERY_CONTEXT_BYTES_V1,
    MAX_RECOVERY_READY_SET_BYTES_V1, MAX_SIGNED_RECOVERY_READY_BYTES_V1,
    MAX_SIGNED_RECOVERY_START_BYTES_V1,
};

use crate::{
    config::LoadedValidatorConfig,
    consensus_runtime::{
        FleetSignatureProducerV1, FleetSignaturePurposeV1, FleetSignatureRequestV1,
    },
    recovery_barrier::{
        issue_external_recovery_ready_v1, issue_external_recovery_start_v1,
        RecoveryBarrierAdmissionV1, RecoveryBarrierRoundV1,
    },
    recovery_barrier_store::{
        load_recovery_ready_set_v1, persist_recovery_ready_set_v1,
        persist_recovery_start_certificate_v1,
    },
    recovery_zero_delta_store::read_recovery_zero_delta_material_v1,
};

pub const RECOVERY_MATERIAL_COMMANDS_V1: [&str; 5] = [
    "recovery-context",
    "recovery-ready",
    "recovery-ready-set",
    "recovery-start",
    "recovery-start-certificate",
];

pub fn is_recovery_material_command_v1(command: &str) -> bool {
    RECOVERY_MATERIAL_COMMANDS_V1.contains(&command)
}

struct LocalRecoveryFleetProducerV1 {
    signing_key: SigningKey,
    origin: ValidatorId,
    validator_set_id: [u8; 32],
    purpose: FleetSignaturePurposeV1,
}

impl LocalRecoveryFleetProducerV1 {
    fn new(config: &LoadedValidatorConfig, purpose: FleetSignaturePurposeV1) -> Self {
        Self {
            signing_key: config.consensus_signing_key().clone(),
            origin: config.local_validator(),
            validator_set_id: *config.validator_set().id().as_bytes(),
            purpose,
        }
    }
}

impl FleetSignatureProducerV1 for LocalRecoveryFleetProducerV1 {
    fn sign_fleet_v1(&mut self, request: FleetSignatureRequestV1) -> Result<[u8; 64]> {
        ensure!(
            request.purpose() == self.purpose
                && request.origin() == self.origin
                && request.validator_set_id() == self.validator_set_id,
            "local recovery signer request differs from its exact purpose/origin/set"
        );
        ensure!(
            request.signing_root() != [0; 32],
            "local recovery signer received a zero signing root"
        );
        Ok(self.signing_key.sign(&request.signing_root()).to_bytes())
    }
}

pub fn run_recovery_material_command_v1<I>(
    command: &str,
    run_root: PathBuf,
    config_path: PathBuf,
    binary_path: &Path,
    arguments: I,
) -> Result<()>
where
    I: IntoIterator<Item = OsString>,
{
    ensure!(
        is_recovery_material_command_v1(command),
        "unknown recovery material command"
    );
    let config = LoadedValidatorConfig::load(&run_root, &config_path, binary_path)
        .context("load manifest-bound recovery material configuration")?;
    ensure!(
        config.has_local_consensus_secret(),
        "recovery material command requires the local candidate consensus key"
    );
    ensure!(
        config.validator_set().validators().len() == DIRECT7_RECOVERY_VALIDATOR_COUNT_V1,
        "recovery material command is frozen to direct-seven"
    );
    let mut arguments = arguments.into_iter();
    match command {
        "recovery-context" => {
            let output = next_absolute_path_v1(&mut arguments, "context output")?;
            require_end_v1(&mut arguments)?;
            let (_cut, context, zero_delta_sha256) =
                read_recovery_zero_delta_material_v1(config.run_root(), config.validator_set())
                    .context("read exact process2 zero-delta material")?;
            ensure!(
                context.target_validator() == config.local_validator(),
                "recovery context command must run on the target validator"
            );
            let bytes = context
                .try_cev1_bytes()
                .map_err(|error| anyhow!("encode recovery context: {error}"))?;
            publish_create_new_v1(&output, &bytes, MAX_RECOVERY_CONTEXT_BYTES_V1)?;
            print_material_result_v1(
                command,
                &config,
                &output,
                sha256_v1(&bytes),
                Some(context.digest()),
                Some(zero_delta_sha256),
            )
        }
        "recovery-ready" => {
            let context_path = next_absolute_path_v1(&mut arguments, "context input")?;
            let output = next_absolute_path_v1(&mut arguments, "Ready output")?;
            require_end_v1(&mut arguments)?;
            let context = load_context_v1(&context_path, config.validator_set())?;
            let statement = sign_ready_v1(&config, context)?;
            let bytes = statement
                .try_cev1_bytes()
                .map_err(|error| anyhow!("encode RecoveryReady statement: {error}"))?;
            publish_create_new_v1(&output, &bytes, MAX_SIGNED_RECOVERY_READY_BYTES_V1)?;
            print_material_result_v1(
                command,
                &config,
                &output,
                sha256_v1(&bytes),
                Some(context.digest()),
                None,
            )
        }
        "recovery-ready-set" => {
            let context_path = next_absolute_path_v1(&mut arguments, "context input")?;
            let statement_paths = exact_direct7_paths_v1(&mut arguments, "Ready statement")?;
            require_end_v1(&mut arguments)?;
            let context = load_context_v1(&context_path, config.validator_set())?;
            ensure!(
                context.target_validator() == config.local_validator(),
                "RecoveryReady aggregation must run on the target validator"
            );
            let ready_set =
                collect_ready_set_v1(&statement_paths, context, config.validator_set())?;
            let stored =
                persist_recovery_ready_set_v1(config.run_root(), ready_set, config.validator_set())
                    .context("persist target RecoveryReady set")?;
            stored
                .revalidate_fresh_v1(config.validator_set())
                .context("freshly revalidate target RecoveryReady set")?;
            let path = stored.path_v1().to_path_buf();
            print_material_result_v1(
                command,
                &config,
                &path,
                stored.artifact_sha256_v1(),
                Some(stored.context_v1().digest()),
                None,
            )
        }
        "recovery-start" => {
            let ready_path = next_absolute_path_v1(&mut arguments, "ReadySet input")?;
            let output = next_absolute_path_v1(&mut arguments, "Start output")?;
            require_end_v1(&mut arguments)?;
            let ready_set = load_ready_set_v1(&ready_path, config.validator_set())?;
            let statement = sign_start_v1(&config, &ready_set)?;
            let bytes = statement
                .try_cev1_bytes()
                .map_err(|error| anyhow!("encode RecoveryStart statement: {error}"))?;
            publish_create_new_v1(&output, &bytes, MAX_SIGNED_RECOVERY_START_BYTES_V1)?;
            print_material_result_v1(
                command,
                &config,
                &output,
                sha256_v1(&bytes),
                Some(ready_set.context().digest()),
                None,
            )
        }
        "recovery-start-certificate" => {
            let ready_path = next_absolute_path_v1(&mut arguments, "ReadySet input")?;
            let statement_paths = exact_direct7_paths_v1(&mut arguments, "Start statement")?;
            require_end_v1(&mut arguments)?;
            let ready_bytes = read_regular_bounded_v1(
                &ready_path,
                MAX_RECOVERY_READY_SET_BYTES_V1,
                "RecoveryReady set",
            )?;
            let ready_set = decode_recovery_ready_set_v1_exact(
                &ready_bytes,
                config.validator_set(),
                &StrictEd25519Verifier,
            )
            .map_err(|error| anyhow!("decode RecoveryReady set: {error}"))?;
            ensure!(
                ready_set.context().target_validator() == config.local_validator(),
                "RecoveryStart aggregation must run on the target validator"
            );
            let certificate =
                collect_start_certificate_v1(&statement_paths, &ready_set, config.validator_set())?;
            let ready_sha256 = sha256_v1(&ready_bytes);
            let ready_owner = load_recovery_ready_set_v1(
                config.run_root(),
                ready_sha256,
                ready_set.context(),
                config.validator_set(),
            )
            .context("reopen target RecoveryReady set before Start persistence")?;
            let stored = persist_recovery_start_certificate_v1(
                config.run_root(),
                certificate,
                ready_owner,
                config.validator_set(),
            )
            .context("persist target RecoveryStart certificate")?;
            stored
                .revalidate_fresh_v1(config.validator_set())
                .context("freshly revalidate target RecoveryStart certificate")?;
            let path = stored.path_v1().to_path_buf();
            print_material_result_v1(
                command,
                &config,
                &path,
                stored.artifact_sha256_v1(),
                Some(stored.context_v1().digest()),
                Some(stored.ready_set_artifact_sha256_v1()),
            )
        }
        _ => unreachable!("command membership checked above"),
    }
}

fn sign_ready_v1(
    config: &LoadedValidatorConfig,
    context: RecoveryContextV1,
) -> Result<SignedRecoveryReadyV1> {
    let mut producer =
        LocalRecoveryFleetProducerV1::new(config, FleetSignaturePurposeV1::RecoveryReady);
    issue_external_recovery_ready_v1(
        context,
        config.local_validator(),
        config.validator_set(),
        &mut producer,
    )
}

fn sign_start_v1(
    config: &LoadedValidatorConfig,
    ready_set: &RecoveryReadySetV1,
) -> Result<SignedRecoveryStartV1> {
    let mut producer =
        LocalRecoveryFleetProducerV1::new(config, FleetSignaturePurposeV1::RecoveryStart);
    issue_external_recovery_start_v1(
        ready_set,
        config.local_validator(),
        config.validator_set(),
        &mut producer,
    )
}

fn load_context_v1(path: &Path, validator_set: &ValidatorSet) -> Result<RecoveryContextV1> {
    let bytes = read_regular_bounded_v1(path, MAX_RECOVERY_CONTEXT_BYTES_V1, "recovery context")?;
    decode_recovery_context_v1_exact(&bytes, validator_set)
        .map_err(|error| anyhow!("decode recovery context: {error}"))
}

fn load_ready_set_v1(path: &Path, validator_set: &ValidatorSet) -> Result<RecoveryReadySetV1> {
    let bytes =
        read_regular_bounded_v1(path, MAX_RECOVERY_READY_SET_BYTES_V1, "RecoveryReady set")?;
    decode_recovery_ready_set_v1_exact(&bytes, validator_set, &StrictEd25519Verifier)
        .map_err(|error| anyhow!("decode RecoveryReady set: {error}"))
}

fn collect_ready_set_v1(
    paths: &[PathBuf],
    context: RecoveryContextV1,
    validator_set: &ValidatorSet,
) -> Result<RecoveryReadySetV1> {
    let mut round = RecoveryBarrierRoundV1::new(context, validator_set.clone())
        .map_err(|error| anyhow!("initialize RecoveryReady collector: {error}"))?;
    ensure!(
        round.context_v1() == &context,
        "RecoveryReady collector changed its context"
    );
    for path in paths {
        let bytes = read_regular_bounded_v1(
            path,
            MAX_SIGNED_RECOVERY_READY_BYTES_V1,
            "RecoveryReady statement",
        )?;
        let decoded =
            decode_signed_recovery_ready_v1_exact(&bytes, validator_set, &StrictEd25519Verifier)
                .map_err(|error| anyhow!("decode RecoveryReady statement: {error}"))?;
        let admitted = round
            .admit_ready_bytes_v1(decoded.origin(), &bytes)
            .map_err(|error| anyhow!("admit RecoveryReady statement: {error}"))?;
        ensure!(
            admitted == RecoveryBarrierAdmissionV1::New,
            "RecoveryReady input repeats an existing validator slot"
        );
    }
    ensure!(
        round.ready_count_v1() == DIRECT7_RECOVERY_VALIDATOR_COUNT_V1
            && round.buffered_start_count_v1() == 0
            && !round.is_poisoned_v1(),
        "RecoveryReady collector did not close one exact direct-seven set"
    );
    round
        .ready_set_v1()
        .map_err(|error| anyhow!("construct direct-seven RecoveryReady set: {error}"))
}

fn collect_start_certificate_v1(
    paths: &[PathBuf],
    ready_set: &RecoveryReadySetV1,
    validator_set: &ValidatorSet,
) -> Result<trnm_consensus_types::RecoveryStartCertificateV1> {
    let mut round = RecoveryBarrierRoundV1::new(*ready_set.context(), validator_set.clone())
        .map_err(|error| anyhow!("initialize RecoveryStart collector: {error}"))?;
    for statement in ready_set.statements() {
        let admitted = round
            .admit_ready_v1(statement.clone())
            .map_err(|error| anyhow!("re-admit RecoveryReady predecessor: {error}"))?;
        ensure!(
            admitted == RecoveryBarrierAdmissionV1::New,
            "RecoveryReady predecessor repeats a validator slot"
        );
    }
    for path in paths {
        let bytes = read_regular_bounded_v1(
            path,
            MAX_SIGNED_RECOVERY_START_BYTES_V1,
            "RecoveryStart statement",
        )?;
        let decoded = decode_signed_recovery_start_v1_exact(
            &bytes,
            ready_set,
            validator_set,
            &StrictEd25519Verifier,
        )
        .map_err(|error| anyhow!("decode RecoveryStart statement: {error}"))?;
        let admitted = round
            .admit_start_bytes_v1(decoded.origin(), &bytes)
            .map_err(|error| anyhow!("admit RecoveryStart statement: {error}"))?;
        ensure!(
            admitted == RecoveryBarrierAdmissionV1::New,
            "RecoveryStart input repeats an existing validator slot"
        );
    }
    ensure!(
        round.ready_count_v1() == DIRECT7_RECOVERY_VALIDATOR_COUNT_V1
            && round.start_count_v1() == DIRECT7_RECOVERY_VALIDATOR_COUNT_V1
            && round.buffered_start_count_v1() == 0
            && !round.is_poisoned_v1(),
        "RecoveryStart collector did not close one exact direct-seven certificate"
    );
    round
        .start_certificate_v1()
        .map_err(|error| anyhow!("construct direct-seven RecoveryStart certificate: {error}"))
}

fn exact_direct7_paths_v1<I>(arguments: &mut I, label: &str) -> Result<Vec<PathBuf>>
where
    I: Iterator<Item = OsString>,
{
    (0..DIRECT7_RECOVERY_VALIDATOR_COUNT_V1)
        .map(|_| next_absolute_path_v1(arguments, label))
        .collect()
}

fn next_absolute_path_v1<I>(arguments: &mut I, label: &str) -> Result<PathBuf>
where
    I: Iterator<Item = OsString>,
{
    let path = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| anyhow!("missing {label} path"))?,
    );
    validate_clean_absolute_path_v1(&path, label)?;
    Ok(path)
}

fn require_end_v1<I>(arguments: &mut I) -> Result<()>
where
    I: Iterator<Item = OsString>,
{
    ensure!(
        arguments.next().is_none(),
        "unexpected recovery material argument"
    );
    Ok(())
}

fn validate_clean_absolute_path_v1(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} path must be absolute");
    ensure!(
        path.components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)),
        "{label} path must not contain . or .."
    );
    ensure!(path.file_name().is_some(), "{label} path lacks a file name");
    Ok(())
}

fn read_regular_bounded_v1(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>> {
    validate_clean_absolute_path_v1(path, label)?;
    let parent = path
        .parent()
        .context("recovery material path has no parent")?;
    ensure!(
        fs::canonicalize(parent).with_context(|| format!("canonicalize {label} parent"))? == parent,
        "{label} parent contains a symlink or lexical alias"
    );
    let before = fs::symlink_metadata(path).with_context(|| format!("stat {label}"))?;
    ensure!(
        before.file_type().is_file() && !before.file_type().is_symlink() && before.nlink() == 1,
        "{label} is not one regular non-symlink file"
    );
    let length = usize::try_from(before.len()).context("recovery material length overflows")?;
    ensure!(
        length > 0 && length <= maximum,
        "{label} length is out of bounds"
    );
    let mut file = File::open(path).with_context(|| format!("open {label}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("stat open {label}"))?;
    ensure!(
        (opened.dev(), opened.ino(), opened.len()) == (before.dev(), before.ino(), before.len()),
        "{label} changed while opening"
    );
    let mut bytes = Vec::with_capacity(length);
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum + 1).context("recovery read bound overflows")?)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    ensure!(bytes.len() == length, "{label} changed while reading");
    let after = fs::symlink_metadata(path).with_context(|| format!("restat {label}"))?;
    ensure!(
        (after.dev(), after.ino(), after.len()) == (before.dev(), before.ino(), before.len()),
        "{label} was replaced while reading"
    );
    Ok(bytes)
}

fn publish_create_new_v1(path: &Path, bytes: &[u8], maximum: usize) -> Result<()> {
    validate_clean_absolute_path_v1(path, "recovery material output")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "output length is out of bounds"
    );
    let parent = path
        .parent()
        .context("recovery material output has no parent")?;
    ensure!(
        fs::canonicalize(parent).context("canonicalize recovery material output parent")? == parent,
        "recovery material output parent contains a symlink or lexical alias"
    );
    let parent_metadata = fs::metadata(parent).context("stat recovery material output parent")?;
    ensure!(
        parent_metadata.is_dir() && parent_metadata.permissions().mode() & 0o077 == 0,
        "recovery material output parent must be a private directory"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("create recovery material output")?;
    file.write_all(bytes)
        .context("write recovery material output")?;
    file.sync_all().context("sync recovery material output")?;
    drop(file);
    File::open(parent)
        .context("open recovery material output parent")?
        .sync_all()
        .context("sync recovery material output parent")?;
    let metadata = fs::symlink_metadata(path).context("restat recovery material output")?;
    ensure!(
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.len() == u64::try_from(bytes.len()).context("output length overflows")?
            && metadata.permissions().mode() & 0o177 == 0,
        "recovery material output identity or permissions differ"
    );
    Ok(())
}

fn print_material_result_v1(
    command: &str,
    config: &LoadedValidatorConfig,
    path: &Path,
    artifact_sha256: [u8; 32],
    context_digest: Option<[u8; 32]>,
    predecessor_sha256: Option<[u8; 32]>,
) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema_version": 1,
            "status": command,
            "run_id": config.run_id(),
            "validator_id": hex::encode(config.local_validator().as_bytes()),
            "validator_set_id": hex::encode(config.validator_set().id().as_bytes()),
            "path": path,
            "artifact_sha256": hex::encode(artifact_sha256),
            "context_digest": context_digest.map(hex::encode),
            "predecessor_artifact_sha256": predecessor_sha256.map(hex::encode),
            "candidate_only": true,
            "production_activation": false,
        }))?
    );
    Ok(())
}

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
