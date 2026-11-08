//! Native-suite build input and real PQ publication construction. No product
//! root override, source placeholders or claim of independent builder custody.
use super::bundle_wire::{Artifact, Bundle, Input, Package, Provenance, Source};
use super::execution_wire::{ConfigurationPolicy, Contract, DirectoryIdentity, Outside};
use super::frontier::{invalid, Digest32, Result};
use super::proof_wire::{Metadata, Publication, Root, Signature};
use super::records::Index;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;

pub(super) fn sha(raw: &[u8]) -> Digest32 {
    Sha256::digest(raw).into()
}
pub(super) fn hex_digest(text: &str) -> Result<Digest32> {
    let raw = hex::decode(text).map_err(std::io::Error::other)?;
    if raw.len() != 32 || hex::encode(&raw) != text {
        return Err(invalid("exact SHA-256 encoding"));
    }
    raw.try_into().map_err(|_| invalid("SHA-256 size"))
}
pub(super) fn bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = super::sealed::identity(&file)?;
    if !file.metadata()?.is_file()
        || file.metadata()?.nlink() != 1
        || before.size == 0
        || before.size > maximum
    {
        return Err(invalid("native fixture bounded single regular input"));
    }
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 != before.size || before != super::sealed::identity(&file)? {
        return Err(invalid("native fixture input changed"));
    }
    Ok(raw)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Build {
    pub schema: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source: Source,
    pub packages: Vec<Package>,
    pub build_inputs: Vec<Input>,
    pub builder_identity: Digest32,
    pub workflow: Digest32,
    pub run_identity: Digest32,
    pub isolated_environment: Digest32,
    pub program: PathBuf,
    pub program_sha256: Digest32,
    pub program_bytes: u64,
}
impl Build {
    pub fn read(path: &Path, expected: Digest32) -> Result<Self> {
        let raw = bounded(path, super::records::MAX_RECORD_BYTES as u64)?;
        if sha(&raw) != expected {
            return Err(invalid("native complete build-input pin"));
        }
        let value: Self = serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
        if value.schema != "trnm-m15-static-node-build-input-v1"
            || value.source_commit.len() != 40
            || value.source_tree.len() != 40
            || !value
                .source_commit
                .bytes()
                .chain(value.source_tree.bytes())
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || value.source.commit_digest != sha(value.source_commit.as_bytes())
            || value.source.tree_digest != sha(value.source_tree.as_bytes())
            || value.source.dirty
            || value.packages.is_empty()
            || value.build_inputs.is_empty()
        {
            return Err(invalid("native source/tree/full-closure input"));
        }
        // This is the actual copied static Node binary, not a minimal stub.
        let (image, _) = super::sealed::Sealed::from_path(
            &value.program,
            value.program_sha256,
            value.program_bytes,
            true,
        )?;
        image.verify_elf(super::elf::platform()?)?;
        Ok(value)
    }

    pub fn bundle(
        &self,
        signer: &PqNativeSigningKey,
        version: &str,
        previous: Option<Digest32>,
    ) -> Result<Bundle> {
        let mut value = Bundle {
            bundle_name: "trnm-m15-isolated-native-node".into(),
            release_version: version.into(),
            protocol_digest: sha(b"trnm-m15-existing-operator-continuous-native-suite-v1"),
            exact_source: self.source.clone(),
            artifacts: vec![Artifact {
                logical_name: "trnm-pon-node".into(),
                media_type: "application/vnd.trnm.elf".into(),
                size_bytes: self.program_bytes,
                content_digest: self.program_sha256,
                executable: true,
                platform_digest: super::elf::platform()?,
                source_path_digest: sha(b"trillionnium/crates/trnm-pon-node/src/main.rs"),
            }],
            sbom_packages: self.packages.clone(),
            provenance: Provenance {
                builder_identity_digest: self.builder_identity,
                workflow_digest: self.workflow,
                run_identity_digest: self.run_identity,
                isolated_environment_digest: self.isolated_environment,
                exact_source_digest: [0; 32],
                build_inputs: self.build_inputs.clone(),
                artifact_set_digest: [0; 32],
                sbom_digest: [0; 32],
                provenance_digest: [0; 32],
            },
            previous_bundle_digest: previous,
            signer_identity_digest: signer.public_key_id(),
            signature_digest: [0; 32],
            bundle_digest: [0; 32],
        };
        // These are only intermediate construction slots. Every emitted field
        // is derived and the original full V0 + actual M15 signatures validate it.
        let kernel = value.kernel();
        kernel
            .exact_source
            .validate()
            .map_err(std::io::Error::other)?;
        value.provenance.exact_source_digest = kernel.exact_source.canonical_digest().0;
        value.provenance.artifact_set_digest = kernel.artifact_set_digest().0;
        value.provenance.sbom_digest = kernel.sbom_digest().0;
        value.provenance.provenance_digest = value.kernel().provenance.canonical_digest().0;
        value.bundle_digest = value.kernel().canonical_digest().0;
        value.signature_digest = sha(&signer
            .sign_exact_message(&value.bundle_digest)
            .map_err(std::io::Error::other)?);
        value
            .kernel()
            .provenance
            .validate()
            .map_err(std::io::Error::other)?;
        Ok(value)
    }
    pub fn required_packages(&self) -> Vec<(String, String)> {
        let mut names: Vec<_> = self
            .packages
            .iter()
            .map(|p| (p.package_name.clone(), p.package_version.clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

pub(super) struct ReleaseInput {
    pub role: u8,
    pub version: u64,
    pub previous: Option<Digest32>,
    pub content: Digest32,
    pub bundle: Option<Bundle>,
    pub configuration: Option<ConfigurationPolicy>,
}

pub(super) fn publication(
    root: &Root,
    index: &Index,
    key: &PqNativeSigningKey,
    input: ReleaseInput,
) -> Result<Publication> {
    let ReleaseInput {
        role,
        version,
        previous,
        content,
        bundle,
        configuration,
    } = input;
    let metadata = Metadata {
        network_id: root.network_id,
        role,
        root_generation: root.generation,
        role_version: version,
        expires_at: root.expires_at,
        expected_checkpoint: index.kernel_checkpoint,
        previous_content: previous,
        content,
        approved_content_rollback: false,
    };
    let signature = key
        .sign_exact_message(&metadata.kernel()?.signing_message())
        .map_err(std::io::Error::other)?
        .to_vec();
    Ok(Publication::Release {
        metadata,
        signatures: vec![Signature {
            key_id: key.public_key_id(),
            signature,
        }],
        bundle: bundle.map(Box::new),
        configuration: configuration.map(Box::new),
    })
}

pub(super) fn contract(
    build: &Build,
    bundle: Digest32,
    namespace: Digest32,
    protected_pin: Digest32,
    exported: &serde_json::Value,
    working: &Path,
) -> Result<Contract> {
    let field = |name| {
        exported["identity"][name]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| invalid("native original outside identity"))
    };
    let outside = Outside {
        path: exported["path"]
            .as_str()
            .ok_or_else(|| invalid("native launch path"))?
            .into(),
        sha256: exported["sha256"]
            .as_str()
            .ok_or_else(|| invalid("native launch SHA"))?
            .into(),
        registry_key: field("registry_key")?,
        task_key: field("task_key")?,
        source_commit: field("source_commit")?,
        node_policy_source: field("node_policy_source")?,
        registry2_package: field("registry2_package")?,
    };
    let metadata = File::open(working)?.metadata()?;
    let value = Contract {
        schema_version: 1,
        profile: super::execution_wire::PROFILE.into(),
        namespace,
        protected_trust_sha256: protected_pin,
        node_bundle: bundle,
        artifact_name: "trnm-pon-node".into(),
        program_sha256: build.program_sha256,
        program_size: build.program_bytes,
        platform_digest: super::elf::platform()?,
        working_directory: working.into(),
        working_identity: DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        },
        environment: super::execution_environment::restricted_environment(),
        arguments: outside.arguments()?,
        outside,
    };
    value.validate()?;
    Ok(value)
}
