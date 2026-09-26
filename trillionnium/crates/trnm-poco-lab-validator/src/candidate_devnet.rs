//! Explicit candidate-only CLI composition for the bounded Native PoCO devnet.
//!
//! This module does not alter the fail-closed `trnm-poco-node` production
//! entrypoint. It exposes one operator-visible composition of the already
//! bounded laboratory runtime with a separately running durable Unix peer-lease
//! authority. The external authority is preflighted before the manifest-bound
//! validator configuration opens any local test key or creates a runtime
//! authority namespace.
//!
//! The command remains single-LAN, bounded, local-test-key evidence. It does
//! not provide an HSM, external monotonic signer watermark, host attestation,
//! cross-platform peer authentication, production state sync, public-testnet
//! readiness, release authority, or consensus activation.

use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, ensure, Context, Result};

use crate::{
    config::LoadedValidatorConfig,
    consensus_report::{MAX_CONSENSUS_RUN_BLOCKS_V1, MAX_CONSENSUS_RUN_DURATION_SECONDS_V1},
    consensus_runtime::{
        run_bounded_consensus_with_external_fence_v1,
        run_recovered_process2_consensus_with_external_fence_v1, BoundedConsensusRunOutcomeV1,
        ConsensusRunRequestV1, Process2RecoveryContinuationRequestV1,
        MINIMUM_CONSENSUS_RUN_BLOCKS_V1,
    },
    p2p_admission::{ExternalPeerLeaseAuthorityV1, UnixExternalPeerLeaseAuthorityV1},
};

pub const CANDIDATE_DEVNET_VALIDATOR_CLI_V1: bool = true;
pub const CANDIDATE_DEVNET_EXTERNAL_FENCE_REQUIRED_V1: bool = true;
pub const CANDIDATE_DEVNET_LOCAL_TEST_KEYS_V1: bool = true;
pub const CANDIDATE_DEVNET_HSM_AUTHORITY_V1: bool = false;
pub const CANDIDATE_DEVNET_HOST_ATTESTATION_V1: bool = false;
pub const CANDIDATE_DEVNET_PRODUCTION_ACTIVATION_V1: bool = false;
pub const CANDIDATE_DEVNET_PUBLIC_TESTNET_READY_V1: bool = false;
pub const DEFAULT_CANDIDATE_DEVNET_LEASE_TIMEOUT_MILLIS_V1: u64 = 5_000;
pub const MINIMUM_CANDIDATE_DEVNET_LEASE_TIMEOUT_MILLIS_V1: u64 = 100;
pub const MAXIMUM_CANDIDATE_DEVNET_LEASE_TIMEOUT_MILLIS_V1: u64 = 30_000;

pub const CANDIDATE_DEVNET_USAGE_V1: &str = concat!(
    "usage: trnm-poco-candidate-devnet-validator ",
    "--acknowledge-candidate-only ",
    "--run-root ABSOLUTE_PATH ",
    "--config ABSOLUTE_PATH ",
    "--peer-lease-socket ABSOLUTE_PATH ",
    "--report ABSOLUTE_PATH ",
    "--duration-seconds N ",
    "--max-blocks N ",
    "[--lease-timeout-millis N] ",
    "[--resume-process2 ",
    "--recovery-ready-set-sha256 HEX64 ",
    "--recovery-start-certificate-sha256 HEX64 ",
    "--recovery-fence-token-sha256 HEX64]\n",
    "\n",
    "This command is bounded single-LAN candidate evidence. ",
    "It is not a production validator or activation surface.\n",
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateDevnetProcessModeV1 {
    Initial,
    ResumeProcess2 {
        ready_set_artifact_sha256: [u8; 32],
        start_certificate_artifact_sha256: [u8; 32],
        fence_token_digest: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateDevnetRunArgsV1 {
    run_root: PathBuf,
    config_path: PathBuf,
    peer_lease_socket: PathBuf,
    report_path: PathBuf,
    duration_seconds: u64,
    max_blocks: u64,
    lease_timeout_millis: u64,
    process_mode: CandidateDevnetProcessModeV1,
}

impl CandidateDevnetRunArgsV1 {
    pub fn run_root(&self) -> &Path {
        &self.run_root
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn peer_lease_socket(&self) -> &Path {
        &self.peer_lease_socket
    }

    pub fn report_path(&self) -> &Path {
        &self.report_path
    }

    pub const fn duration_seconds(&self) -> u64 {
        self.duration_seconds
    }

    pub const fn max_blocks(&self) -> u64 {
        self.max_blocks
    }

    pub const fn lease_timeout_millis(&self) -> u64 {
        self.lease_timeout_millis
    }

    pub const fn process_mode(&self) -> CandidateDevnetProcessModeV1 {
        self.process_mode
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateDevnetCliActionV1 {
    Help,
    Run(Box<CandidateDevnetRunArgsV1>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateDevnetRunOutcomeV1 {
    CompletedReport(PathBuf),
    RecoveredProcess2CompletedReport(PathBuf),
    Process1TargetParked(String),
}

pub fn parse_candidate_devnet_args_v1<I>(arguments: I) -> Result<CandidateDevnetCliActionV1>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let mut acknowledge_candidate_only = false;
    let mut run_root = None;
    let mut config_path = None;
    let mut peer_lease_socket = None;
    let mut report_path = None;
    let mut duration_seconds = None;
    let mut max_blocks = None;
    let mut lease_timeout_millis = None;
    let mut resume_process2 = false;
    let mut recovery_ready_set_sha256 = None;
    let mut recovery_start_certificate_sha256 = None;
    let mut recovery_fence_token_sha256 = None;
    let mut saw_any = false;

    while let Some(raw_argument) = arguments.next() {
        saw_any = true;
        let argument = raw_argument
            .to_str()
            .ok_or_else(|| anyhow!("option name is not valid UTF-8"))?;
        match argument {
            "--help" | "-h" => {
                ensure!(
                    run_root.is_none()
                        && config_path.is_none()
                        && peer_lease_socket.is_none()
                        && report_path.is_none()
                        && duration_seconds.is_none()
                        && max_blocks.is_none()
                        && lease_timeout_millis.is_none()
                        && !resume_process2
                        && recovery_ready_set_sha256.is_none()
                        && recovery_start_certificate_sha256.is_none()
                        && recovery_fence_token_sha256.is_none()
                        && !acknowledge_candidate_only
                        && arguments.next().is_none(),
                    "--help must be the only argument"
                );
                return Ok(CandidateDevnetCliActionV1::Help);
            }
            "--acknowledge-candidate-only" => {
                ensure!(
                    !acknowledge_candidate_only,
                    "--acknowledge-candidate-only was supplied more than once"
                );
                acknowledge_candidate_only = true;
            }
            "--resume-process2" => {
                ensure!(
                    !resume_process2,
                    "--resume-process2 was supplied more than once"
                );
                resume_process2 = true;
            }
            "--recovery-ready-set-sha256" => set_hex32_option(
                &mut recovery_ready_set_sha256,
                next_value(&mut arguments, "--recovery-ready-set-sha256")?,
                "--recovery-ready-set-sha256",
            )?,
            "--recovery-start-certificate-sha256" => set_hex32_option(
                &mut recovery_start_certificate_sha256,
                next_value(&mut arguments, "--recovery-start-certificate-sha256")?,
                "--recovery-start-certificate-sha256",
            )?,
            "--recovery-fence-token-sha256" => set_hex32_option(
                &mut recovery_fence_token_sha256,
                next_value(&mut arguments, "--recovery-fence-token-sha256")?,
                "--recovery-fence-token-sha256",
            )?,
            "--run-root" => set_path_option(
                &mut run_root,
                next_value(&mut arguments, "--run-root")?,
                "--run-root",
            )?,
            "--config" => set_path_option(
                &mut config_path,
                next_value(&mut arguments, "--config")?,
                "--config",
            )?,
            "--peer-lease-socket" => set_path_option(
                &mut peer_lease_socket,
                next_value(&mut arguments, "--peer-lease-socket")?,
                "--peer-lease-socket",
            )?,
            "--report" => set_path_option(
                &mut report_path,
                next_value(&mut arguments, "--report")?,
                "--report",
            )?,
            "--duration-seconds" => set_u64_option(
                &mut duration_seconds,
                next_value(&mut arguments, "--duration-seconds")?,
                "--duration-seconds",
            )?,
            "--max-blocks" => set_u64_option(
                &mut max_blocks,
                next_value(&mut arguments, "--max-blocks")?,
                "--max-blocks",
            )?,
            "--lease-timeout-millis" => set_u64_option(
                &mut lease_timeout_millis,
                next_value(&mut arguments, "--lease-timeout-millis")?,
                "--lease-timeout-millis",
            )?,
            _ => bail!("unknown candidate-devnet option: {argument}"),
        }
    }

    ensure!(saw_any, "candidate-devnet arguments are required");
    ensure!(
        acknowledge_candidate_only,
        "--acknowledge-candidate-only is required"
    );

    let process_mode = match (
        resume_process2,
        recovery_ready_set_sha256,
        recovery_start_certificate_sha256,
        recovery_fence_token_sha256,
    ) {
        (false, None, None, None) => CandidateDevnetProcessModeV1::Initial,
        (true, Some(ready), Some(start), Some(fence)) => {
            CandidateDevnetProcessModeV1::ResumeProcess2 {
                ready_set_artifact_sha256: ready,
                start_certificate_artifact_sha256: start,
                fence_token_digest: fence,
            }
        }
        (true, _, _, _) => bail!("--resume-process2 requires all three recovery SHA-256 options"),
        (false, _, _, _) => bail!("recovery SHA-256 options require --resume-process2"),
    };

    let parsed = CandidateDevnetRunArgsV1 {
        run_root: run_root.ok_or_else(|| anyhow!("--run-root is required"))?,
        config_path: config_path.ok_or_else(|| anyhow!("--config is required"))?,
        peer_lease_socket: peer_lease_socket
            .ok_or_else(|| anyhow!("--peer-lease-socket is required"))?,
        report_path: report_path.ok_or_else(|| anyhow!("--report is required"))?,
        duration_seconds: duration_seconds
            .ok_or_else(|| anyhow!("--duration-seconds is required"))?,
        max_blocks: max_blocks.ok_or_else(|| anyhow!("--max-blocks is required"))?,
        lease_timeout_millis: lease_timeout_millis
            .unwrap_or(DEFAULT_CANDIDATE_DEVNET_LEASE_TIMEOUT_MILLIS_V1),
        process_mode,
    };
    validate_candidate_devnet_args_v1(&parsed)?;
    Ok(CandidateDevnetCliActionV1::Run(Box::new(parsed)))
}

pub fn run_candidate_devnet_v1(
    arguments: CandidateDevnetRunArgsV1,
) -> Result<CandidateDevnetRunOutcomeV1> {
    validate_candidate_devnet_args_v1(&arguments)?;

    // Prove the external fencing service is reachable before config loading can
    // open any manifest-bound local test key or create the runtime namespace.
    let external_fence = UnixExternalPeerLeaseAuthorityV1::connect(arguments.peer_lease_socket())
        .with_timeout(Duration::from_millis(arguments.lease_timeout_millis()));
    external_fence
        .preflight()
        .map_err(|error| anyhow!("candidate peer-lease preflight failed: {error}"))?;

    let binary_path = std::env::current_exe().context("resolve candidate validator executable")?;
    let config =
        LoadedValidatorConfig::load(arguments.run_root(), arguments.config_path(), &binary_path)
            .context("load manifest-bound candidate validator configuration")?;
    ensure!(
        config.has_local_consensus_secret()
            && config.has_local_p2p_identity_secret()
            && config.has_local_operator_recovery_secret(),
        "candidate local-key composition did not load all three role secrets"
    );

    let process_mode = arguments.process_mode();
    let consensus = ConsensusRunRequestV1 {
        config,
        duration: Duration::from_secs(arguments.duration_seconds()),
        max_blocks: arguments.max_blocks(),
        report_path: arguments.report_path().to_path_buf(),
    };
    let outcome = match process_mode {
        CandidateDevnetProcessModeV1::Initial => run_bounded_consensus_with_external_fence_v1(
            consensus,
            Arc::new(external_fence),
            |config, _signer_lifetime| config.commission_deployed_ordinary_runtime_v1(),
        )
        .context("run externally fenced initial candidate validator")?,
        CandidateDevnetProcessModeV1::ResumeProcess2 {
            ready_set_artifact_sha256,
            start_certificate_artifact_sha256,
            fence_token_digest,
        } => run_recovered_process2_consensus_with_external_fence_v1(
            Process2RecoveryContinuationRequestV1 {
                consensus,
                ready_set_artifact_sha256,
                start_certificate_artifact_sha256,
                fence_token_digest,
            },
            Arc::new(external_fence),
            None,
        )
        .context("resume externally fenced candidate validator as process2")?,
    };

    match (process_mode, outcome) {
        (
            CandidateDevnetProcessModeV1::Initial,
            BoundedConsensusRunOutcomeV1::CompletedReport(path),
        ) => Ok(CandidateDevnetRunOutcomeV1::CompletedReport(path)),
        (
            CandidateDevnetProcessModeV1::ResumeProcess2 { .. },
            BoundedConsensusRunOutcomeV1::CompletedReport(path),
        ) => Ok(CandidateDevnetRunOutcomeV1::RecoveredProcess2CompletedReport(path)),
        (
            CandidateDevnetProcessModeV1::Initial,
            BoundedConsensusRunOutcomeV1::Process1TargetParked(handoff),
        ) => {
            let encoded = serde_json::to_string(&handoff)
                .context("encode candidate process-1 parked handoff")?;
            Ok(CandidateDevnetRunOutcomeV1::Process1TargetParked(encoded))
        }
        (
            CandidateDevnetProcessModeV1::ResumeProcess2 { .. },
            BoundedConsensusRunOutcomeV1::Process1TargetParked(_),
        ) => bail!("process2 continuation attempted a forbidden second restart/process3"),
    }
}

fn validate_candidate_devnet_args_v1(arguments: &CandidateDevnetRunArgsV1) -> Result<()> {
    validate_clean_absolute_path(arguments.run_root(), "run root")?;
    validate_clean_absolute_path(arguments.config_path(), "validator config")?;
    validate_clean_absolute_path(arguments.peer_lease_socket(), "peer-lease socket")?;
    validate_clean_absolute_path(arguments.report_path(), "report path")?;
    ensure!(
        arguments.run_root() != Path::new("/"),
        "run root must not be /"
    );

    require_lexical_descendant(
        arguments.run_root(),
        arguments.config_path(),
        "validator config",
    )?;
    let report_relative =
        require_lexical_descendant(arguments.run_root(), arguments.report_path(), "report path")?;
    ensure!(
        arguments.report_path() != arguments.config_path(),
        "report path aliases the validator config"
    );
    ensure!(
        arguments.report_path() != arguments.peer_lease_socket(),
        "report path aliases the peer-lease socket"
    );
    ensure!(
        report_relative
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            .is_some_and(|component| !matches!(component, "public" | "secret")),
        "report path must not be inside immutable public/secret deployment inputs"
    );
    ensure!(
        (1..=MAX_CONSENSUS_RUN_DURATION_SECONDS_V1).contains(&arguments.duration_seconds()),
        "duration is outside the bounded consensus profile"
    );
    ensure!(
        (MINIMUM_CONSENSUS_RUN_BLOCKS_V1..=MAX_CONSENSUS_RUN_BLOCKS_V1)
            .contains(&arguments.max_blocks()),
        "max-blocks is outside the bounded consensus profile"
    );
    ensure!(
        (MINIMUM_CANDIDATE_DEVNET_LEASE_TIMEOUT_MILLIS_V1
            ..=MAXIMUM_CANDIDATE_DEVNET_LEASE_TIMEOUT_MILLIS_V1)
            .contains(&arguments.lease_timeout_millis()),
        "lease timeout is outside the candidate transport profile"
    );
    if let CandidateDevnetProcessModeV1::ResumeProcess2 {
        ready_set_artifact_sha256,
        start_certificate_artifact_sha256,
        fence_token_digest,
    } = arguments.process_mode()
    {
        ensure!(
            ready_set_artifact_sha256 != [0; 32]
                && start_certificate_artifact_sha256 != [0; 32]
                && fence_token_digest != [0; 32],
            "process2 recovery digests must be nonzero"
        );
    }
    Ok(())
}

fn next_value<I>(arguments: &mut I, option: &str) -> Result<OsString>
where
    I: Iterator<Item = OsString>,
{
    arguments
        .next()
        .ok_or_else(|| anyhow!("{option} requires one value"))
}

fn set_path_option(slot: &mut Option<PathBuf>, value: OsString, option: &str) -> Result<()> {
    ensure!(slot.is_none(), "{option} was supplied more than once");
    *slot = Some(PathBuf::from(value));
    Ok(())
}

fn set_u64_option(slot: &mut Option<u64>, value: OsString, option: &str) -> Result<()> {
    ensure!(slot.is_none(), "{option} was supplied more than once");
    let value = value
        .to_str()
        .ok_or_else(|| anyhow!("{option} value is not valid UTF-8"))?
        .parse::<u64>()
        .with_context(|| format!("{option} value is not an unsigned integer"))?;
    *slot = Some(value);
    Ok(())
}

fn set_hex32_option(slot: &mut Option<[u8; 32]>, value: OsString, option: &str) -> Result<()> {
    ensure!(slot.is_none(), "{option} was supplied more than once");
    let value = value
        .to_str()
        .ok_or_else(|| anyhow!("{option} value is not valid UTF-8"))?;
    ensure!(
        value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "{option} must be exactly 64 lower-case hexadecimal characters"
    );
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .with_context(|| format!("decode {option} as SHA-256"))?;
    ensure!(decoded != [0; 32], "{option} must be nonzero");
    *slot = Some(decoded);
    Ok(())
}

fn validate_clean_absolute_path(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} must be absolute");
    ensure!(
        path.components()
            .all(|component| { !matches!(component, Component::CurDir | Component::ParentDir) }),
        "{label} must not contain . or .. components"
    );
    Ok(())
}

fn require_lexical_descendant<'a>(root: &'a Path, path: &'a Path, label: &str) -> Result<&'a Path> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{label} must be below the run root"))?;
    ensure!(
        !relative.as_os_str().is_empty(),
        "{label} aliases the run root"
    );
    Ok(relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_arguments() -> Vec<OsString> {
        [
            "--acknowledge-candidate-only",
            "--run-root",
            "/tmp/trnm-candidate-run",
            "--config",
            "/tmp/trnm-candidate-run/public/configs/validator.json",
            "--peer-lease-socket",
            "/tmp/trnm-fence/peer-lease.sock",
            "--report",
            "/tmp/trnm-candidate-run/candidate-report.json",
            "--duration-seconds",
            "30",
            "--max-blocks",
            "12",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    fn valid_process2_arguments() -> Vec<OsString> {
        let mut arguments = valid_arguments();
        arguments.extend([
            OsString::from("--resume-process2"),
            OsString::from("--recovery-ready-set-sha256"),
            OsString::from("11".repeat(32)),
            OsString::from("--recovery-start-certificate-sha256"),
            OsString::from("22".repeat(32)),
            OsString::from("--recovery-fence-token-sha256"),
            OsString::from("33".repeat(32)),
        ]);
        arguments
    }

    #[test]
    fn candidate_cli_requires_explicit_nonproduction_acknowledgement() {
        let mut arguments = valid_arguments();
        arguments.remove(0);
        let error = parse_candidate_devnet_args_v1(arguments)
            .expect_err("missing acknowledgement must fail closed");
        assert!(error.to_string().contains("acknowledge-candidate-only"));
    }

    #[test]
    fn candidate_cli_parses_bounded_absolute_paths() {
        let parsed = parse_candidate_devnet_args_v1(valid_arguments())
            .expect("valid candidate arguments parse");
        let CandidateDevnetCliActionV1::Run(parsed) = parsed else {
            panic!("expected run action");
        };
        assert_eq!(parsed.duration_seconds(), 30);
        assert_eq!(parsed.max_blocks(), 12);
        assert_eq!(
            parsed.lease_timeout_millis(),
            DEFAULT_CANDIDATE_DEVNET_LEASE_TIMEOUT_MILLIS_V1
        );
        assert_eq!(
            parsed.report_path(),
            Path::new("/tmp/trnm-candidate-run/candidate-report.json")
        );
    }

    #[test]
    fn candidate_cli_requires_complete_explicit_process2_authority() {
        let parsed = parse_candidate_devnet_args_v1(valid_process2_arguments())
            .expect("complete process2 authority parses");
        let CandidateDevnetCliActionV1::Run(parsed) = parsed else {
            panic!("expected process2 run action");
        };
        assert_eq!(
            parsed.process_mode(),
            CandidateDevnetProcessModeV1::ResumeProcess2 {
                ready_set_artifact_sha256: [0x11; 32],
                start_certificate_artifact_sha256: [0x22; 32],
                fence_token_digest: [0x33; 32],
            }
        );

        let mut missing = valid_process2_arguments();
        missing.truncate(missing.len() - 2);
        let error = parse_candidate_devnet_args_v1(missing)
            .expect_err("partial process2 authority must reject");
        assert!(error.to_string().contains("requires all three"));

        let mut without_mode = valid_process2_arguments();
        let flag = without_mode
            .iter()
            .position(|argument| argument == "--resume-process2")
            .expect("resume flag");
        without_mode.remove(flag);
        let error = parse_candidate_devnet_args_v1(without_mode)
            .expect_err("recovery digests without explicit mode must reject");
        assert!(error.to_string().contains("require --resume-process2"));
    }

    #[test]
    fn candidate_cli_rejects_noncanonical_or_zero_process2_digests() {
        let mut uppercase = valid_process2_arguments();
        let option = uppercase
            .iter()
            .position(|argument| argument == "--recovery-ready-set-sha256")
            .expect("ready-set option");
        uppercase[option + 1] = OsString::from("AA".repeat(32));
        let error = parse_candidate_devnet_args_v1(uppercase)
            .expect_err("uppercase recovery digest must reject");
        assert!(error.to_string().contains("lower-case hexadecimal"));

        let mut zero = valid_process2_arguments();
        let option = zero
            .iter()
            .position(|argument| argument == "--recovery-fence-token-sha256")
            .expect("fence option");
        zero[option + 1] = OsString::from("00".repeat(32));
        let error =
            parse_candidate_devnet_args_v1(zero).expect_err("zero fence digest must reject");
        assert!(error.to_string().contains("must be nonzero"));
    }

    #[test]
    fn candidate_cli_rejects_relative_and_immutable_report_paths() {
        let mut relative = valid_arguments();
        relative[2] = OsString::from("relative-run");
        assert!(parse_candidate_devnet_args_v1(relative).is_err());

        let mut immutable = valid_arguments();
        immutable[8] = OsString::from("/tmp/trnm-candidate-run/public/candidate-report.json");
        assert!(parse_candidate_devnet_args_v1(immutable).is_err());
    }

    #[test]
    fn candidate_cli_rejects_duplicate_and_out_of_bounds_values() {
        let mut duplicate = valid_arguments();
        duplicate.extend([OsString::from("--max-blocks"), OsString::from("13")]);
        assert!(parse_candidate_devnet_args_v1(duplicate).is_err());

        let mut too_few_blocks = valid_arguments();
        too_few_blocks[12] = OsString::from("2");
        assert!(parse_candidate_devnet_args_v1(too_few_blocks).is_err());

        let mut zero_duration = valid_arguments();
        zero_duration[10] = OsString::from("0");
        assert!(parse_candidate_devnet_args_v1(zero_duration).is_err());
    }

    #[test]
    fn candidate_cli_help_is_standalone_and_preserves_nonclaims() {
        assert_eq!(
            parse_candidate_devnet_args_v1([OsString::from("--help")])
                .expect("standalone help parses"),
            CandidateDevnetCliActionV1::Help
        );
        assert!(parse_candidate_devnet_args_v1([
            OsString::from("--help"),
            OsString::from("--acknowledge-candidate-only"),
        ])
        .is_err());
        const {
            assert!(CANDIDATE_DEVNET_VALIDATOR_CLI_V1);
            assert!(CANDIDATE_DEVNET_EXTERNAL_FENCE_REQUIRED_V1);
            assert!(CANDIDATE_DEVNET_LOCAL_TEST_KEYS_V1);
            assert!(!CANDIDATE_DEVNET_HSM_AUTHORITY_V1);
            assert!(!CANDIDATE_DEVNET_HOST_ATTESTATION_V1);
            assert!(!CANDIDATE_DEVNET_PRODUCTION_ACTIVATION_V1);
            assert!(!CANDIDATE_DEVNET_PUBLIC_TESTNET_READY_V1);
        }
    }
}
