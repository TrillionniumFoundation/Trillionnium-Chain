//! A current ProtocolConfiguration signs this complete, versioned launch contract.
use super::frontier::{hash, invalid, Digest32, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(super) const LEGACY_PROFILE: &str = "trnm-operator-m15-sealed-native-elf-v1";
pub(super) const PROFILE: &str = "trnm-operator-m15-sealed-native-elf-v2";
pub(super) const MAX_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_LAUNCH_RECORDS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Outside {
    pub path: PathBuf,
    pub sha256: String,
    pub registry_key: String,
    pub task_key: String,
    pub source_commit: String,
    pub node_policy_source: String,
    pub registry2_package: String,
}

impl Outside {
    pub fn borrowed(&self) -> crate::operator_continuous_controller::OutsideLaunch<'_> {
        crate::operator_continuous_controller::OutsideLaunch {
            path: &self.path,
            sha256: &self.sha256,
            registry_key: &self.registry_key,
            task_key: &self.task_key,
            source_commit: &self.source_commit,
            node_policy_source: &self.node_policy_source,
            registry2_package: &self.registry2_package,
        }
    }

    pub fn arguments(&self) -> Result<Vec<String>> {
        let path = self
            .path
            .to_str()
            .ok_or_else(|| invalid("M15 launch path encoding"))?;
        Ok(vec![
            "trnm-pon-node".into(),
            "operator-continuous-m15-v1".into(),
            "--launch".into(),
            path.into(),
            "--launch-sha256".into(),
            self.sha256.clone(),
            "--registry-key".into(),
            self.registry_key.clone(),
            "--task-key".into(),
            self.task_key.clone(),
            "--source-commit".into(),
            self.source_commit.clone(),
            "--policy-source".into(),
            self.node_policy_source.clone(),
            "--registry2-package".into(),
            self.registry2_package.clone(),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Contract {
    pub schema_version: u32,
    pub profile: String,
    pub namespace: Digest32,
    pub protected_trust_sha256: Digest32,
    pub node_bundle: Digest32,
    pub artifact_name: String,
    pub program_sha256: Digest32,
    pub program_size: u64,
    pub platform_digest: Digest32,
    pub working_directory: PathBuf,
    pub working_identity: DirectoryIdentity,
    pub environment: BTreeMap<String, String>,
    pub outside: Outside,
    pub arguments: Vec<String>,
}

impl Contract {
    pub fn validate(&self) -> Result<()> {
        // Preserve old signed records byte-for-byte for historical replay.
        // Only require_closed_execution may turn a profile into current use.
        let exact_environment = match self.profile.as_str() {
            LEGACY_PROFILE => super::execution_environment::legacy_environment(),
            PROFILE => super::execution_environment::restricted_environment(),
            _ => return Err(invalid("M15 static execution profile unsupported")),
        };
        if self.schema_version != 1
            || self.namespace == [0; 32]
            || self.protected_trust_sha256 == [0; 32]
            || self.node_bundle == [0; 32]
            || self.program_sha256 == [0; 32]
            || self.platform_digest == [0; 32]
            || self.artifact_name.is_empty()
            || self.artifact_name.len() > trnm_release_bundle::MAX_NAME_BYTES_V0
            || self.program_size == 0
            || self.program_size > MAX_PROGRAM_BYTES
            || !self.working_directory.is_absolute()
            || self.working_identity.inode == 0
            || self.working_identity.mode & 0o7777 != 0o700
            || !self.outside.path.is_absolute()
            || self.environment != exact_environment
            || self.arguments != self.outside.arguments()?
            || self
                .arguments
                .iter()
                .any(|v| v.len() > 4096 || v.as_bytes().contains(&0))
        {
            return Err(invalid("M15 complete sealed execution contract rejected"));
        }
        Ok(())
    }

    pub fn require_closed_execution(&self) -> Result<()> {
        self.validate()?;
        if self.profile != PROFILE {
            return Err(invalid(
                "M15 V2 closed execution requires a new current signed configuration",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfigurationPolicy {
    pub schema_version: u32,
    pub contract: Contract,
    pub inputs_digest: Digest32,
}

impl ConfigurationPolicy {
    pub fn digest(&self) -> Result<Digest32> {
        self.contract.validate()?;
        if self.schema_version != 1 || self.inputs_digest == [0; 32] {
            return Err(invalid("M15 configuration policy shape"));
        }
        Ok(hash(
            b"TRNM/M15/OperatorConfigurationPolicy/v1\0",
            &super::codec::encode(self, 131072)?,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessIdentity {
    pub pid: u32,
    pub uid: u32,
    pub start_ticks: u64,
    pub boot_id: Digest32,
    pub pid_namespace_device: u64,
    pub pid_namespace_inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub uid: u32,
    pub mode: u32,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installation {
    pub schema_version: u32,
    pub bundle: Digest32,
    pub artifact_name: String,
    pub program_sha256: Digest32,
    pub source_identity: FileIdentity,
    pub kernel_checkpoint: Digest32,
    pub observed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchAttempt {
    pub schema_version: u32,
    pub nonce: Digest32,
    pub process: ProcessIdentity,
    pub installation: Digest32,
    pub contract: Contract,
    pub policy_digest: Digest32,
    pub kernel_checkpoint: Digest32,
    pub root_digest: Digest32,
    pub root_generation: u64,
    pub actual_arguments: Vec<String>,
    pub launch_fd: u32,
    pub handoff_fd: u32,
    pub observed_at: u64,
    pub expires_at: u64,
}

impl LaunchAttempt {
    pub fn validate_arguments(&self) -> Result<()> {
        self.contract.validate()?;
        let mut expected = self.contract.arguments.clone();
        expected.extend([
            "--m15-launch-fd".into(),
            self.launch_fd.to_string(),
            "--m15-handoff-fd".into(),
            self.handoff_fd.to_string(),
        ]);
        if self.schema_version != 1
            || self.nonce == [0; 32]
            || self.process.pid == 0
            || self.process.uid == 0
            || self.process.uid != self.contract.working_identity.uid
            || self.process.start_ticks == 0
            || self.process.boot_id == [0; 32]
            || self.process.pid_namespace_inode == 0
            || self.installation == [0; 32]
            || self.launch_fd < 3
            || self.handoff_fd < 3
            || self.launch_fd == self.handoff_fd
            || self.actual_arguments != expected
            || self.observed_at >= self.expires_at
        {
            return Err(invalid(
                "M15 launch attempt process/descriptor/argv binding",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claim {
    pub schema_version: u32,
    pub attempt: Digest32,
    pub process: ProcessIdentity,
    pub observed_at: u64,
    pub kernel_checkpoint: Digest32,
}
