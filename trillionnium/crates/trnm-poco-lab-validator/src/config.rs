use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use trnm_consensus_core::CoreConfig;
use trnm_consensus_types::{
    ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, ProtocolVersion, Validator,
    ValidatorId, ValidatorSet, VotingPower,
};
use trnm_native_execution_v0::{
    derive_canonical_lab_genesis_hash_v0, CanonicalLabNativeApplicationConfigInputsV0,
    NativeApplicationConfigV0,
};
use trnm_poco_node::{
    commission_deployed_lab_ordinary_runtime_v0, recover_deployed_lab_process2_v0,
    reopen_deployed_lab_ordinary_cut_v0, PocoNodeDeployedLabBootstrapV0,
    PocoNodeDeployedLabOrdinaryRecoveryOwnerV0, PocoNodeDeployedLabProcess2RecoveryOwnerV0,
    PocoNodeDeployedLabRecoveryErrorV0, PocoNodeDeployedLabSignedReplayEntryV0,
    PocoNodeLabOrdinaryProposalRuntimeV0,
};

use crate::{
    bootstrap_material::{
        verify_public_zero_comet_bootstrap_v1, VerifiedPublicBootstrapInitialCutV1,
        VerifiedPublicZeroCometBootstrapV1,
    },
    crypto::LabFileWatermark,
    workload_corpus::VerifiedWorkloadCorpusV1,
};

const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const MAX_CORE_BLOCKS: usize = 131_072;
const OBSERVED_MESSAGES_PER_VALIDATOR: usize = 64;
const MAX_FROZEN_INPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorRecordJson {
    validator_id: String,
    consensus_public_key: String,
    voting_power: u64,
    key_pop_signature: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorSetJson {
    schema_version: u32,
    run_id: String,
    chain_id: String,
    genesis_hash: String,
    protocol_version: u32,
    epoch: u64,
    consensus_parameters_profile: String,
    candidate_source_sha256: String,
    production_activation: bool,
    validators: Vec<ValidatorRecordJson>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateJson {
    source_tree_sha256: String,
    linux_x86_64_sha256: String,
    macos_arm64_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialAuthorJson {
    binary_sha256: String,
    runtime_deployed: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRefJson {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestJson {
    schema_version: u32,
    deployment_validator_id: Option<String>,
    coordinator_manifest_sha256: Option<String>,
    run_id: String,
    fleet_id: String,
    validator_count: usize,
    weight_profile: String,
    network_scope: String,
    geo_wan_evidence: bool,
    candidate: CandidateJson,
    material_author: MaterialAuthorJson,
    validator_set_sha256: String,
    public_files: Vec<FileRefJson>,
    secret_files: Vec<FileRefJson>,
    production_activation: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverManifestJson {
    schema_version: u32,
    coordinator_manifest_sha256: String,
    run_id: String,
    fleet_id: String,
    validator_count: usize,
    weight_profile: String,
    network_scope: String,
    geo_wan_evidence: bool,
    candidate: CandidateJson,
    material_author: MaterialAuthorJson,
    validator_set_sha256: String,
    public_files: Vec<FileRefJson>,
    production_activation: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverEndpointJson {
    validator_id: String,
    lan_ip: String,
    p2p_port: u16,
    metrics_port: u16,
    consensus_public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverConfigJson {
    schema_version: u32,
    run_id: String,
    host_id: String,
    lan_ip: String,
    os: String,
    arch: String,
    run_roles: Vec<String>,
    binary_sha256: String,
    candidate_source_sha256: String,
    validator_set_sha256: String,
    validator_endpoints: Vec<ObserverEndpointJson>,
    network_scope: String,
    geo_wan_evidence: bool,
    production_activation: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TopologyValidatorJson {
    index: usize,
    validator_id: String,
    host_id: String,
    management: String,
    lan_ip: String,
    host_local_index: usize,
    p2p_port: u16,
    metrics_port: u16,
    weight: u64,
    peers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TopologyJson {
    schema_version: u32,
    fleet_id: String,
    network_scope: String,
    geo_wan_evidence: bool,
    validator_count: usize,
    weight_profile: String,
    peer_degree: usize,
    test_keys_included: bool,
    participants: Vec<ParticipantJson>,
    validators: Vec<TopologyValidatorJson>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParticipantJson {
    host_id: String,
    management: String,
    lan_ip: String,
    os: String,
    arch: String,
    validator_eligible: bool,
    run_roles: Vec<String>,
}

struct ExpectedParticipant {
    host_id: &'static str,
    management: &'static str,
    lan_ip: &'static str,
    os: &'static str,
    arch: &'static str,
    validator_eligible: bool,
    run_roles: &'static [&'static str],
}

fn expected_participants() -> [ExpectedParticipant; 6] {
    [
        ExpectedParticipant {
            host_id: "local",
            management: "local",
            lan_ip: "192.168.0.9",
            os: "linux",
            arch: "x86_64",
            validator_eligible: true,
            run_roles: &["validator"],
        },
        ExpectedParticipant {
            host_id: "x230",
            management: "p4-x230",
            lan_ip: "192.168.0.3",
            os: "linux",
            arch: "x86_64",
            validator_eligible: true,
            run_roles: &["validator"],
        },
        ExpectedParticipant {
            host_id: "desktop",
            management: "p4-desktop",
            lan_ip: "192.168.0.4",
            os: "linux",
            arch: "x86_64",
            validator_eligible: true,
            run_roles: &["validator"],
        },
        ExpectedParticipant {
            host_id: "rog",
            management: "p4-rog",
            lan_ip: "192.168.0.6",
            os: "linux",
            arch: "x86_64",
            validator_eligible: true,
            run_roles: &["validator"],
        },
        ExpectedParticipant {
            host_id: "j3160",
            management: "p4-j3160",
            lan_ip: "192.168.0.8",
            os: "linux",
            arch: "x86_64",
            validator_eligible: true,
            run_roles: &["validator"],
        },
        ExpectedParticipant {
            host_id: "mac",
            management: "p4-mac",
            lan_ip: "192.168.0.5",
            os: "macos",
            arch: "arm64",
            validator_eligible: false,
            run_roles: &[
                "load-generator",
                "evidence-collector",
                "crypto-cross-verifier",
            ],
        },
    ]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub validator_id: String,
    pub lan_ip: String,
    pub p2p_port: u16,
    pub consensus_public_key: String,
}

impl PeerConfig {
    pub fn validator_id(&self) -> Result<ValidatorId> {
        Ok(ValidatorId::new(decode_hex32(
            &self.validator_id,
            "peer.validator_id",
        )?))
    }

    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let ip = self
            .lan_ip
            .parse::<IpAddr>()
            .with_context(|| format!("invalid peer IP for {}", self.validator_id))?;
        Ok(SocketAddr::new(ip, self.p2p_port))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorConfigJson {
    schema_version: u32,
    run_id: String,
    validator_id: String,
    host_id: String,
    lan_ip: String,
    p2p_port: u16,
    metrics_port: u16,
    weight: u64,
    consensus_public_key: String,
    validator_set_sha256: String,
    binary_sha256: String,
    ordinary_start_height: u64,
    workload_corpus_sha256: String,
    workload_policy_sha256: String,
    secret_key_path: String,
    peers: Vec<PeerConfig>,
    network_scope: String,
    geo_wan_evidence: bool,
    production_activation: bool,
}

#[derive(Debug)]
pub struct LoadedValidatorConfig {
    run_root: PathBuf,
    config_path: PathBuf,
    run_id: String,
    host_id: String,
    local_ip: IpAddr,
    p2p_port: u16,
    metrics_port: u16,
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    peers: Vec<PeerConfig>,
    incoming_peers: Vec<PeerConfig>,
    signing_key: SigningKey,
    validator_set_sha256: [u8; 32],
    topology_sha256: [u8; 32],
    config_sha256: [u8; 32],
    coordinator_manifest_sha256: [u8; 32],
    binary_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    ordinary_start_height: u64,
    workload_corpus_sha256: [u8; 32],
    workload_policy_sha256: [u8; 32],
    workload_corpus: VerifiedWorkloadCorpusV1,
    verified_public_bootstrap: Option<VerifiedPublicZeroCometBootstrapV1>,
}

/// Secret-free verifier context for independently checking one validator's
/// signed network-smoke report.
///
/// This context consumes the closed observer-public bundle plus an out-of-band
/// coordinator-manifest digest. It never opens a validator secret and never
/// compares the observer's executable inode with the reported Linux binary.
#[derive(Debug)]
pub struct PublicReportVerifierContext {
    run_id: String,
    host_id: String,
    local_ip: IpAddr,
    p2p_port: u16,
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    peers: Vec<PeerConfig>,
    incoming_peers: Vec<PeerConfig>,
    validator_set_sha256: [u8; 32],
    topology_sha256: [u8; 32],
    config_sha256: [u8; 32],
    coordinator_manifest_sha256: [u8; 32],
    binary_sha256: [u8; 32],
    candidate_source_sha256: [u8; 32],
    ordinary_start_height: u64,
    workload_corpus_sha256: [u8; 32],
    workload_policy_sha256: [u8; 32],
    validator_config_sha256: BTreeMap<ValidatorId, [u8; 32]>,
    expected_outgoing_peers: BTreeMap<ValidatorId, BTreeSet<ValidatorId>>,
    bootstrap_initial_cut: VerifiedPublicBootstrapInitialCutV1,
}

impl LoadedValidatorConfig {
    pub fn load(
        run_root: impl AsRef<Path>,
        config_path: impl AsRef<Path>,
        binary_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let run_root = canonical_private_directory(run_root.as_ref())?;
        let config_path = canonical_regular_file(config_path.as_ref())?;
        require_descendant(&run_root, &config_path, "validator config")?;
        let config_bytes = read_regular_file_pinned(&config_path, "validator config")?;
        let config_sha256 = sha256(&config_bytes);
        let config: ValidatorConfigJson =
            serde_json::from_slice(&config_bytes).context("decode validator config JSON")?;
        validate_fixed_config_fields(&config)?;
        let expected_config_path = canonical_regular_file(
            &run_root.join(format!("public/configs/{}.json", config.validator_id)),
        )?;
        if config_path != expected_config_path {
            bail!("validator config path differs from the closed per-validator layout");
        }

        let manifest_path = canonical_regular_file(&run_root.join("manifest.json"))?;
        let manifest_bytes = read_regular_file_pinned(&manifest_path, "run manifest")?;
        let manifest: ManifestJson =
            serde_json::from_slice(&manifest_bytes).context("decode run manifest JSON")?;
        let coordinator_manifest_sha256 = decode_hex32(
            manifest
                .coordinator_manifest_sha256
                .as_deref()
                .ok_or_else(|| anyhow!("deployment manifest lacks coordinator hash"))?,
            "manifest.coordinator_manifest_sha256",
        )?;
        validate_manifest(&manifest, &config.run_id, &config.validator_id, &run_root)?;
        let expected_count = run_id_validator_count(&config.run_id)?;
        if manifest.validator_count != expected_count {
            bail!("manifest cardinality differs from run ID");
        }
        require_manifest_bytes(
            &manifest,
            &format!("public/configs/{}.json", config.validator_id),
            &config_bytes,
            false,
        )?;

        let topology_path = canonical_regular_file(&run_root.join("topology.json"))?;
        let topology_bytes = read_regular_file_pinned(&topology_path, "run topology")?;
        let topology_sha256 = sha256(&topology_bytes);
        require_manifest_bytes(&manifest, "topology.json", &topology_bytes, false)?;
        let topology: TopologyJson =
            serde_json::from_slice(&topology_bytes).context("decode run topology JSON")?;
        validate_topology(&topology, &manifest, expected_count)?;

        let validator_set_path = run_root.join("public/validator-set.json");
        let validator_set_path = canonical_regular_file(&validator_set_path)?;
        let validator_set_bytes = read_regular_file_pinned(&validator_set_path, "validator set")?;
        let validator_set_sha256 = sha256(&validator_set_bytes);
        require_manifest_bytes(
            &manifest,
            "public/validator-set.json",
            &validator_set_bytes,
            false,
        )?;
        let configured_set_hash =
            decode_hex32(&config.validator_set_sha256, "config.validator_set_sha256")?;
        if validator_set_sha256 != configured_set_hash {
            bail!("validator-set content hash differs from config");
        }
        let descriptor: ValidatorSetJson =
            serde_json::from_slice(&validator_set_bytes).context("decode validator set JSON")?;
        validate_set_fixed_fields(&descriptor, &config.run_id)?;
        if descriptor.validators.len() != expected_count {
            bail!("validator-set cardinality differs from run ID");
        }
        validate_manifest_binding(&manifest, &config, validator_set_sha256, &descriptor)?;
        validate_topology_binding(&topology, &config, &descriptor)?;
        let consensus_parameters = ConsensusParametersV0::reference_shadow_v0();
        let (validator_set, candidate_source_sha256) =
            build_validator_set(&descriptor, &consensus_parameters)?;

        let workload_corpus_sha256 = decode_hex32(
            &config.workload_corpus_sha256,
            "config.workload_corpus_sha256",
        )?;
        let workload_policy_sha256 = decode_hex32(
            &config.workload_policy_sha256,
            "config.workload_policy_sha256",
        )?;
        require_manifest_hash(
            &manifest,
            "public/workload.corpus",
            workload_corpus_sha256,
            false,
        )?;
        require_manifest_hash(
            &manifest,
            "public/workload-policy.json",
            workload_policy_sha256,
            false,
        )?;
        let workload_corpus_path =
            canonical_regular_file(&run_root.join("public/workload.corpus"))?;
        let workload_policy_path =
            canonical_regular_file(&run_root.join("public/workload-policy.json"))?;
        require_descendant(&run_root, &workload_corpus_path, "workload corpus")?;
        require_descendant(&run_root, &workload_policy_path, "workload policy")?;
        let consensus_public_keys = validator_set
            .validators()
            .iter()
            .map(|validator| validator.consensus_key().into_bytes())
            .collect::<Vec<_>>();
        let workload_corpus = VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
            workload_corpus_path,
            workload_policy_path,
            workload_corpus_sha256,
            workload_policy_sha256,
            validator_set.chain_id().as_str(),
            config.ordinary_start_height,
            &consensus_public_keys,
        )?;
        let verified_public_bootstrap = verify_public_zero_comet_bootstrap_v1(
            &run_root,
            &validator_set,
            &consensus_parameters,
            &workload_corpus,
        )?;

        let local_validator =
            ValidatorId::new(decode_hex32(&config.validator_id, "config.validator_id")?);
        let local = validator_set
            .validator(local_validator)
            .ok_or_else(|| anyhow!("local validator is absent from validator set"))?;
        if local.consensus_key().as_bytes()
            != &decode_hex32(&config.consensus_public_key, "config.consensus_public_key")?
            || local.voting_power().get() != config.weight
        {
            bail!("local config key/weight differs from validator set");
        }

        let local_ip = config
            .lan_ip
            .parse::<IpAddr>()
            .context("config.lan_ip is invalid")?;
        if !local_ip.is_ipv4() || !is_private_lan(local_ip) {
            bail!("validator bind address must be one private IPv4 LAN address");
        }
        if config.p2p_port == 0
            || config.metrics_port == 0
            || config.p2p_port == config.metrics_port
        {
            bail!("validator ports must be positive and distinct");
        }
        validate_peers(&config, &validator_set, local_validator)?;
        let incoming_peers =
            derive_incoming_peers(&topology, &descriptor, config.validator_id.as_str())?;

        let secret_relative = strict_relative_path(&config.secret_key_path)?;
        let expected_secret = PathBuf::from("secrets").join(format!("{}.pk8", config.validator_id));
        if secret_relative != expected_secret {
            bail!("config.secret_key_path differs from the closed per-validator layout");
        }
        let secret_path = canonical_regular_file(&run_root.join(&secret_relative))?;
        require_descendant(&run_root, &secret_path, "validator secret")?;
        let metadata = fs::metadata(&secret_path).context("stat validator secret")?;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("validator secret mode must be exactly 0600");
        }
        let secret_bytes = read_regular_file_pinned(&secret_path, "validator secret")?;
        require_manifest_bytes(
            &manifest,
            &secret_relative.to_string_lossy(),
            &secret_bytes,
            true,
        )?;
        let signing_key = load_pkcs8_ed25519_seed(&secret_bytes)?;
        if signing_key.verifying_key().to_bytes() != local.consensus_key().into_bytes() {
            bail!("validator secret does not match the committed public key");
        }

        let binary_path = canonical_regular_file(binary_path.as_ref())?;
        let binary_sha256 = sha256_running_image(&binary_path)?;
        if binary_sha256 != decode_hex32(&config.binary_sha256, "config.binary_sha256")? {
            bail!("running binary hash differs from validator config");
        }

        Ok(Self {
            run_root,
            config_path,
            run_id: config.run_id,
            host_id: config.host_id,
            local_ip,
            p2p_port: config.p2p_port,
            metrics_port: config.metrics_port,
            local_validator,
            validator_set,
            consensus_parameters,
            peers: config.peers,
            incoming_peers,
            signing_key,
            validator_set_sha256,
            topology_sha256,
            config_sha256,
            coordinator_manifest_sha256,
            binary_sha256,
            candidate_source_sha256,
            ordinary_start_height: config.ordinary_start_height,
            workload_corpus_sha256,
            workload_policy_sha256,
            workload_corpus,
            verified_public_bootstrap: Some(verified_public_bootstrap),
        })
    }

    pub fn core_config(&self) -> Result<CoreConfig> {
        let observed = self
            .validator_set
            .validators()
            .len()
            .checked_mul(OBSERVED_MESSAGES_PER_VALIDATOR)
            .ok_or_else(|| anyhow!("observed-message bound overflow"))?;
        CoreConfig::new(
            self.local_validator,
            self.validator_set.clone(),
            self.consensus_parameters,
            0,
            MAX_CORE_BLOCKS,
            observed,
        )
        .map_err(|error| anyhow!("invalid Core config: {error}"))
    }

    pub fn run_root(&self) -> &Path {
        &self.run_root
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.consensus_parameters
    }

    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.local_ip, self.p2p_port)
    }

    pub fn metrics_addr(&self) -> SocketAddr {
        SocketAddr::new(self.local_ip, self.metrics_port)
    }

    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    pub fn incoming_peers(&self) -> &[PeerConfig] {
        &self.incoming_peers
    }

    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub const fn validator_set_sha256(&self) -> [u8; 32] {
        self.validator_set_sha256
    }

    pub const fn topology_sha256(&self) -> [u8; 32] {
        self.topology_sha256
    }

    pub const fn config_sha256(&self) -> [u8; 32] {
        self.config_sha256
    }

    pub const fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        self.coordinator_manifest_sha256
    }

    pub const fn binary_sha256(&self) -> [u8; 32] {
        self.binary_sha256
    }

    pub const fn candidate_source_sha256(&self) -> [u8; 32] {
        self.candidate_source_sha256
    }

    pub const fn ordinary_start_height(&self) -> u64 {
        self.ordinary_start_height
    }

    pub const fn workload_corpus_sha256(&self) -> [u8; 32] {
        self.workload_corpus_sha256
    }

    pub const fn workload_policy_sha256(&self) -> [u8; 32] {
        self.workload_policy_sha256
    }

    pub const fn workload_corpus(&self) -> &VerifiedWorkloadCorpusV1 {
        &self.workload_corpus
    }

    /// Read-only public projection of the already authenticated bootstrap cut.
    /// This copies no proposal, proof, signer, or commissioning authority and
    /// is available only before the one-way commissioning owner is consumed.
    pub(crate) fn verified_public_bootstrap_initial_cut_v1(
        &self,
    ) -> Result<VerifiedPublicBootstrapInitialCutV1> {
        self.verified_public_bootstrap
            .as_ref()
            .map(VerifiedPublicZeroCometBootstrapV1::initial_ordinary_cut_v1)
            .ok_or_else(|| anyhow!("verified public bootstrap was already consumed"))
    }

    pub fn workload_corpus_mut(&mut self) -> &mut VerifiedWorkloadCorpusV1 {
        &mut self.workload_corpus
    }

    /// Derives the exact native application configuration from manifest-bound
    /// deployment facts and the public, independently verified workload
    /// signer policy. No application private key is accepted or opened.
    pub fn native_application_config_v0(&self) -> Result<NativeApplicationConfigV0> {
        let inputs = CanonicalLabNativeApplicationConfigInputsV0::new(
            self.run_id.clone(),
            self.coordinator_manifest_sha256,
            self.topology_sha256,
            self.validator_set_sha256,
            self.candidate_source_sha256,
            self.local_validator,
            self.validator_set.clone(),
            self.consensus_parameters,
            self.workload_corpus.authorized_signers_v0()?,
            self.workload_corpus.header().governance_signer_id.clone(),
        )?;
        NativeApplicationConfigV0::from_canonical_lab_inputs_v0(inputs)
    }

    /// Fresh-only, one-way join from the manifest-bound public h1-h3 bundle
    /// into Node's ordinary laboratory runtime.  The verified bootstrap is
    /// consumed exactly once.  Any existing or partial runtime namespace is
    /// rejected; recovery is an explicit later tranche.
    pub(crate) fn commission_deployed_ordinary_runtime_v1(
        &mut self,
    ) -> Result<PocoNodeLabOrdinaryProposalRuntimeV0<LabFileWatermark>> {
        let core_config = self.core_config()?;
        let application_config = self.native_application_config_v0()?;
        let verified = self
            .verified_public_bootstrap
            .take()
            .ok_or_else(|| anyhow!("verified public bootstrap was already consumed"))?;
        let (proposals, proof) = verified.into_node_parts_v1();
        let bootstrap = PocoNodeDeployedLabBootstrapV0::admit_exact_v0(
            &core_config,
            &application_config,
            proposals,
            proof,
        )
        .map_err(|error| anyhow!("admit public bootstrap into Node owner: {error}"))?;

        let authority_root = self.run_root.join("runtime-authority-v1");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&authority_root).with_context(|| {
            format!(
                "create fresh runtime authority {}",
                authority_root.display()
            )
        })?;
        let authority_root = authority_root
            .canonicalize()
            .context("canonicalize fresh runtime authority")?;
        require_descendant(&self.run_root, &authority_root, "runtime authority")?;
        let metadata =
            fs::symlink_metadata(&authority_root).context("inspect fresh runtime authority")?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            bail!("fresh runtime authority is not one exact 0700 directory");
        }

        commission_deployed_lab_ordinary_runtime_v0(
            authority_root,
            core_config,
            application_config,
            bootstrap,
            |record_path| LabFileWatermark::open(record_path),
        )
        .map_err(|error| anyhow!("commission deployed ordinary runtime: {error}"))
    }

    /// Reopens one exact deployed anchored-ordinary Ready root as a
    /// replay-fenced owner.
    ///
    /// This does not consume the public bootstrap and cannot release a live
    /// consensus runtime. It exists so a restarted process can authenticate
    /// the exact Safety/App/signer/checkpoint/P/K cut before recording a
    /// fail-closed recovery outcome. Revision>5 returns an explicit signed
    /// Proposal/QC ancestry replay challenge; replay activation and catch-up
    /// remain separate tranches.
    pub fn reopen_deployed_ordinary_cut_v1(
        &self,
    ) -> Result<PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<LabFileWatermark>> {
        let core_config = self.core_config()?;
        let application_config = self.native_application_config_v0()?;
        reopen_deployed_lab_ordinary_cut_v0(
            self.run_root.join("runtime-authority-v1"),
            core_config,
            application_config,
            |path: &Path| LabFileWatermark::open(path),
        )
        .map_err(|error| anyhow!("reopen deployed ordinary cut: {error}"))
    }

    /// Reopens the complete process-2 durable graph from already authenticated
    /// signed replay material and returns only Node's still-inert owner.
    /// This seam does not activate Core, signer, timer, ingress, or network
    /// authority.
    pub(crate) fn recover_deployed_process2_inert_v1(
        &self,
        entries: Vec<PocoNodeDeployedLabSignedReplayEntryV0>,
    ) -> Result<PocoNodeDeployedLabProcess2RecoveryOwnerV0<LabFileWatermark>> {
        let core_config = self.core_config()?;
        let application_config = self.native_application_config_v0()?;
        recover_deployed_lab_process2_v0(
            self.run_root.join("runtime-authority-v1"),
            core_config,
            application_config,
            entries,
            |path: &Path| LabFileWatermark::open(path),
        )
        .map_err(|error| anyhow!("recover inert deployed process2 owner: {error}"))
    }

    /// Executes the same typed Node reopen against a caller-supplied isolated
    /// authority root.  The startup-rejection protocol is the only caller: it
    /// authenticates the root inventory and proves that the primary root and
    /// process journal did not change around this read-only attempt.
    pub(crate) fn attempt_isolated_deployed_ordinary_reopen_v1(
        &self,
        isolated_authority_root: &Path,
    ) -> Result<
        Result<
            PocoNodeDeployedLabOrdinaryRecoveryOwnerV0<LabFileWatermark>,
            PocoNodeDeployedLabRecoveryErrorV0,
        >,
    > {
        let core_config = self.core_config()?;
        let application_config = self.native_application_config_v0()?;
        Ok(reopen_deployed_lab_ordinary_cut_v0(
            isolated_authority_root,
            core_config,
            application_config,
            |path: &Path| LabFileWatermark::open(path),
        ))
    }
}

impl PublicReportVerifierContext {
    /// Minimal secret-free projection for replay-archive verifier tests.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_replay_archive_test_parts_v1(
        run_id: String,
        validator_set: ValidatorSet,
        local_validator: ValidatorId,
        validator_set_sha256: [u8; 32],
        topology_sha256: [u8; 32],
        config_sha256: [u8; 32],
        coordinator_manifest_sha256: [u8; 32],
        binary_sha256: [u8; 32],
        candidate_source_sha256: [u8; 32],
        ordinary_start_height: u64,
        workload_corpus_sha256: [u8; 32],
        workload_policy_sha256: [u8; 32],
        bootstrap_initial_cut: VerifiedPublicBootstrapInitialCutV1,
    ) -> Self {
        let mut validator_config_sha256 = BTreeMap::new();
        validator_config_sha256.insert(local_validator, config_sha256);
        Self {
            run_id,
            host_id: "replay-archive-test".to_owned(),
            local_ip: "127.0.0.1".parse().expect("loopback parses"),
            p2p_port: 1,
            local_validator,
            validator_set,
            peers: Vec::new(),
            incoming_peers: Vec::new(),
            validator_set_sha256,
            topology_sha256,
            config_sha256,
            coordinator_manifest_sha256,
            binary_sha256,
            candidate_source_sha256,
            ordinary_start_height,
            workload_corpus_sha256,
            workload_policy_sha256,
            validator_config_sha256,
            expected_outgoing_peers: BTreeMap::new(),
            bootstrap_initial_cut,
        }
    }

    /// Builds the minimum secret-free observer projection needed by the
    /// fleet-certificate verifier's focused tests. Production callers must
    /// always use `load`, which derives these facts from observer-public.
    #[cfg(test)]
    pub(crate) fn from_fleet_barrier_test_parts_v1(
        validator_set: ValidatorSet,
        local_validator: ValidatorId,
        campaign: &crate::fleet_barrier::CommonCampaignContextV1,
        validator_config_sha256: BTreeMap<ValidatorId, [u8; 32]>,
        expected_outgoing_peers: BTreeMap<ValidatorId, BTreeSet<ValidatorId>>,
        bootstrap_initial_cut: VerifiedPublicBootstrapInitialCutV1,
    ) -> Self {
        let identity = campaign.identity();
        let config_sha256 = *validator_config_sha256
            .get(&local_validator)
            .expect("selected test validator has a config digest");
        Self {
            run_id: identity.run_id().to_owned(),
            host_id: "observer-test".to_owned(),
            local_ip: "127.0.0.1".parse().expect("loopback parses"),
            p2p_port: 1,
            local_validator,
            validator_set,
            peers: Vec::new(),
            incoming_peers: Vec::new(),
            validator_set_sha256: identity.validator_set_sha256(),
            topology_sha256: identity.topology_sha256(),
            config_sha256,
            coordinator_manifest_sha256: identity.coordinator_manifest_sha256(),
            binary_sha256: identity.binary_sha256(),
            candidate_source_sha256: identity.candidate_source_sha256(),
            ordinary_start_height: campaign.request().ordinary_start_height(),
            workload_corpus_sha256: identity.workload_corpus_sha256(),
            workload_policy_sha256: identity.workload_policy_sha256(),
            validator_config_sha256,
            expected_outgoing_peers,
            bootstrap_initial_cut,
        }
    }

    pub fn load(
        observer_root: impl AsRef<Path>,
        config_path: impl AsRef<Path>,
        expected_coordinator_manifest_sha256: &str,
    ) -> Result<Self> {
        let observer_root = canonical_private_directory(observer_root.as_ref())?;
        if fs::metadata(&observer_root)
            .context("stat observer-public root")?
            .permissions()
            .mode()
            & 0o777
            != 0o700
        {
            bail!("observer-public root mode must be exactly 0700");
        }
        let expected_coordinator_manifest_sha256 = decode_hex32(
            expected_coordinator_manifest_sha256,
            "expected coordinator manifest sha256",
        )?;
        if expected_coordinator_manifest_sha256 == [0; 32] {
            bail!("expected coordinator manifest sha256 must not be zero");
        }

        let manifest_path = canonical_regular_file(&observer_root.join("manifest.json"))?;
        if fs::metadata(&manifest_path)
            .context("stat observer-public manifest")?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            bail!("observer-public manifest mode must be exactly 0600");
        }
        let manifest_bytes = read_regular_file_pinned(&manifest_path, "observer-public manifest")?;
        let manifest: ObserverManifestJson = serde_json::from_slice(&manifest_bytes)
            .context("decode observer-public manifest JSON")?;
        if manifest.schema_version != 4
            || decode_hex32(
                &manifest.coordinator_manifest_sha256,
                "observer coordinator manifest sha256",
            )? != expected_coordinator_manifest_sha256
            || manifest.fleet_id != "trnm-poco-lan-six-host-2026-08-13"
            || !matches!(manifest.validator_count, 7 | 31 | 100)
            || !matches!(
                manifest.weight_profile.as_str(),
                "equal" | "bounded-unequal"
            )
            || manifest.network_scope != "single-lan"
            || manifest.geo_wan_evidence
            || manifest.production_activation
        {
            bail!("observer-public manifest differs from the frozen G3 contract");
        }
        validate_run_id(&manifest.run_id)?;
        if run_id_validator_count(&manifest.run_id)? != manifest.validator_count {
            bail!("observer-public run ID cardinality differs from manifest");
        }
        let source = decode_hex32(
            &manifest.candidate.source_tree_sha256,
            "observer candidate source sha256",
        )?;
        let linux_binary = decode_hex32(
            &manifest.candidate.linux_x86_64_sha256,
            "observer Linux binary sha256",
        )?;
        let macos_binary = decode_hex32(
            &manifest.candidate.macos_arm64_sha256,
            "observer macOS binary sha256",
        )?;
        validate_material_author(
            &manifest.material_author,
            &manifest.candidate,
            "observer material_author",
        )?;
        let declared_set_sha256 = decode_hex32(
            &manifest.validator_set_sha256,
            "observer validator-set sha256",
        )?;
        if source == [0; 32]
            || linux_binary == [0; 32]
            || macos_binary == [0; 32]
            || declared_set_sha256 == [0; 32]
        {
            bail!("observer-public candidate digests must not be zero");
        }

        let coordinator_manifest_path =
            canonical_regular_file(&observer_root.join("coordinator-manifest.json"))?;
        if fs::metadata(&coordinator_manifest_path)
            .context("stat frozen coordinator manifest")?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            bail!("frozen coordinator manifest mode must be exactly 0600");
        }
        let coordinator_manifest_bytes =
            read_regular_file_pinned(&coordinator_manifest_path, "frozen coordinator manifest")?;
        if sha256(&coordinator_manifest_bytes) != expected_coordinator_manifest_sha256 {
            bail!("frozen coordinator manifest differs from its out-of-band trust anchor");
        }
        let coordinator: ManifestJson = serde_json::from_slice(&coordinator_manifest_bytes)
            .context("decode frozen coordinator manifest JSON")?;
        if coordinator.schema_version != 2
            || coordinator.deployment_validator_id.is_some()
            || coordinator.coordinator_manifest_sha256.is_some()
            || coordinator.run_id != manifest.run_id
            || coordinator.fleet_id != manifest.fleet_id
            || coordinator.validator_count != manifest.validator_count
            || coordinator.weight_profile != manifest.weight_profile
            || coordinator.network_scope != manifest.network_scope
            || coordinator.geo_wan_evidence != manifest.geo_wan_evidence
            || coordinator.production_activation != manifest.production_activation
            || coordinator.candidate.source_tree_sha256 != manifest.candidate.source_tree_sha256
            || coordinator.candidate.linux_x86_64_sha256 != manifest.candidate.linux_x86_64_sha256
            || coordinator.candidate.macos_arm64_sha256 != manifest.candidate.macos_arm64_sha256
            || coordinator.material_author.binary_sha256 != manifest.material_author.binary_sha256
            || coordinator.material_author.runtime_deployed
                != manifest.material_author.runtime_deployed
            || coordinator.validator_set_sha256 != manifest.validator_set_sha256
        {
            bail!("frozen coordinator manifest disagrees with observer-public manifest");
        }
        validate_material_author(
            &coordinator.material_author,
            &coordinator.candidate,
            "coordinator material_author",
        )?;
        let mut coordinator_paths = BTreeSet::new();
        for record in coordinator
            .public_files
            .iter()
            .chain(coordinator.secret_files.iter())
        {
            let relative = strict_relative_path(&record.path)?;
            if !coordinator_paths.insert(relative)
                || record.bytes == 0
                || decode_hex32(&record.sha256, "coordinator manifest file sha256")? == [0; 32]
            {
                bail!("frozen coordinator manifest contains an invalid file reference");
            }
        }

        let mut frozen_files = BTreeMap::<PathBuf, Vec<u8>>::new();
        for record in &manifest.public_files {
            let relative = strict_relative_path(&record.path)?;
            if relative == Path::new("manifest.json")
                || frozen_files.contains_key(&relative)
                || record.bytes == 0
            {
                bail!("observer-public manifest contains duplicate or invalid file reference");
            }
            frozen_files.insert(relative.clone(), Vec::new());
            let path = canonical_regular_file(&observer_root.join(&relative))?;
            require_descendant(&observer_root, &path, "observer-public file")?;
            if fs::metadata(&path)
                .with_context(|| format!("stat observer-public file {}", relative.display()))?
                .permissions()
                .mode()
                & 0o777
                != 0o644
            {
                bail!("observer-public file mode must be exactly 0644");
            }
            let bytes = read_regular_file_pinned(&path, "observer-public file")?;
            let length = u64::try_from(bytes.len()).context("observer-public length overflow")?;
            if length != record.bytes
                || sha256(&bytes) != decode_hex32(&record.sha256, "observer-public file sha256")?
            {
                bail!("observer-public file content address mismatch");
            }
            frozen_files.insert(relative, bytes);
        }
        let mut actual_paths = BTreeSet::new();
        collect_closed_file_inventory(&observer_root, &observer_root, &mut actual_paths)?;
        actual_paths.remove(Path::new("manifest.json"));
        actual_paths.remove(Path::new("coordinator-manifest.json"));
        if actual_paths != frozen_files.keys().cloned().collect() {
            bail!("observer-public root contains an extra or missing file");
        }

        let topology_bytes = frozen_files
            .get(Path::new("topology.json"))
            .ok_or_else(|| anyhow!("observer-public bundle lacks topology"))?;
        let topology_sha256 = sha256(topology_bytes);
        let topology: TopologyJson =
            serde_json::from_slice(topology_bytes).context("decode observer topology JSON")?;
        let shim = ManifestJson {
            schema_version: 4,
            deployment_validator_id: None,
            coordinator_manifest_sha256: Some(manifest.coordinator_manifest_sha256.clone()),
            run_id: manifest.run_id.clone(),
            fleet_id: manifest.fleet_id.clone(),
            validator_count: manifest.validator_count,
            weight_profile: manifest.weight_profile.clone(),
            network_scope: manifest.network_scope.clone(),
            geo_wan_evidence: manifest.geo_wan_evidence,
            candidate: manifest.candidate.clone(),
            material_author: manifest.material_author.clone(),
            validator_set_sha256: manifest.validator_set_sha256.clone(),
            public_files: manifest.public_files.clone(),
            secret_files: Vec::new(),
            production_activation: manifest.production_activation,
        };
        validate_topology(&topology, &shim, manifest.validator_count)?;

        let expected_public = topology
            .validators
            .iter()
            .map(|validator| {
                PathBuf::from(format!("public/configs/{}.json", validator.validator_id))
            })
            .chain([
                PathBuf::from("topology.json"),
                PathBuf::from("public/validator-set.json"),
                PathBuf::from("public/workload.corpus"),
                PathBuf::from("public/workload-policy.json"),
                PathBuf::from("public/bootstrap/h1.proposal"),
                PathBuf::from("public/bootstrap/h2.proposal"),
                PathBuf::from("public/bootstrap/h3.proposal"),
                PathBuf::from("public/bootstrap/finality-proof.cev0"),
                PathBuf::from("public/bootstrap/bootstrap.json"),
                PathBuf::from("public/observer-configs/mac.json"),
            ])
            .collect::<BTreeSet<_>>();
        if expected_public != frozen_files.keys().cloned().collect() {
            bail!("observer-public file inventory differs from topology");
        }
        let coordinator_public = coordinator
            .public_files
            .iter()
            .map(|record| (record.path.as_str(), record))
            .collect::<BTreeMap<_, _>>();
        for record in &manifest.public_files {
            let original = coordinator_public
                .get(record.path.as_str())
                .ok_or_else(|| {
                    anyhow!("observer file is absent from frozen coordinator manifest")
                })?;
            if original.sha256 != record.sha256 || original.bytes != record.bytes {
                bail!("observer file reference differs from frozen coordinator manifest");
            }
        }
        let expected_coordinator_public = expected_public.clone();
        let actual_coordinator_public = coordinator
            .public_files
            .iter()
            .map(|record| strict_relative_path(&record.path))
            .collect::<Result<BTreeSet<_>>>()?;
        if actual_coordinator_public != expected_coordinator_public {
            bail!("frozen coordinator public inventory differs from the six-host run contract");
        }
        let expected_coordinator_secrets = topology
            .validators
            .iter()
            .map(|validator| PathBuf::from(format!("secrets/{}.pk8", validator.validator_id)))
            .collect::<BTreeSet<_>>();
        let actual_coordinator_secrets = coordinator
            .secret_files
            .iter()
            .map(|record| strict_relative_path(&record.path))
            .collect::<Result<BTreeSet<_>>>()?;
        if actual_coordinator_secrets != expected_coordinator_secrets {
            bail!("frozen coordinator secret-reference inventory differs from validator set");
        }

        let validator_set_bytes = frozen_files
            .get(Path::new("public/validator-set.json"))
            .ok_or_else(|| anyhow!("observer-public bundle lacks validator set"))?;
        let validator_set_sha256 = sha256(validator_set_bytes);
        if validator_set_sha256 != declared_set_sha256 {
            bail!("observer-public validator-set hash differs from manifest");
        }
        let descriptor: ValidatorSetJson = serde_json::from_slice(validator_set_bytes)
            .context("decode observer validator-set JSON")?;
        validate_set_fixed_fields(&descriptor, &manifest.run_id)?;
        if descriptor.validators.len() != manifest.validator_count {
            bail!("observer-public validator set cardinality differs from run");
        }
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let (validator_set, candidate_source_sha256) =
            build_validator_set(&descriptor, &parameters)?;
        if candidate_source_sha256 != source {
            bail!("observer-public source digest differs across manifest and validator set");
        }

        let observer_bytes = frozen_files
            .get(Path::new("public/observer-configs/mac.json"))
            .ok_or_else(|| anyhow!("observer-public bundle lacks macOS observer config"))?;
        let observer: ObserverConfigJson = serde_json::from_slice(observer_bytes)
            .context("decode frozen macOS observer config JSON")?;
        if observer.schema_version != 1
            || observer.run_id != manifest.run_id
            || observer.host_id != "mac"
            || observer.lan_ip != "192.168.0.5"
            || observer.os != "macos"
            || observer.arch != "arm64"
            || observer.run_roles
                != [
                    "load-generator".to_owned(),
                    "evidence-collector".to_owned(),
                    "crypto-cross-verifier".to_owned(),
                ]
            || decode_hex32(&observer.binary_sha256, "observer binary sha256")?
                != decode_hex32(
                    &manifest.candidate.macos_arm64_sha256,
                    "manifest macOS binary sha256",
                )?
            || decode_hex32(&observer.candidate_source_sha256, "observer source sha256")? != source
            || decode_hex32(
                &observer.validator_set_sha256,
                "observer validator-set sha256",
            )? != validator_set_sha256
            || observer.network_scope != "single-lan"
            || observer.geo_wan_evidence
            || observer.production_activation
            || observer.validator_endpoints.len() != topology.validators.len()
        {
            bail!("macOS observer config differs from the frozen six-host contract");
        }
        let descriptor_by_id = descriptor
            .validators
            .iter()
            .map(|record| (record.validator_id.as_str(), record))
            .collect::<BTreeMap<_, _>>();
        for (actual, planned) in observer
            .validator_endpoints
            .iter()
            .zip(&topology.validators)
        {
            let set_record = descriptor_by_id
                .get(planned.validator_id.as_str())
                .ok_or_else(|| anyhow!("observer endpoint is absent from validator set"))?;
            if actual.validator_id != planned.validator_id
                || actual.lan_ip != planned.lan_ip
                || actual.p2p_port != planned.p2p_port
                || actual.metrics_port != planned.metrics_port
                || actual.consensus_public_key != set_record.consensus_public_key
            {
                bail!("observer endpoint inventory differs from topology/validator set");
            }
        }

        let requested_config_path = canonical_regular_file(config_path.as_ref())?;
        require_descendant(
            &observer_root,
            &requested_config_path,
            "observer selected validator config",
        )?;
        let relative_config = requested_config_path
            .strip_prefix(&observer_root)
            .map_err(|_| anyhow!("observer selected config escapes public root"))?;
        let config_bytes = frozen_files
            .get(relative_config)
            .ok_or_else(|| anyhow!("observer selected config is not manifest-bound"))?;
        let config_sha256 = sha256(config_bytes);
        let config: ValidatorConfigJson = serde_json::from_slice(config_bytes)
            .context("decode observer selected validator config JSON")?;
        validate_fixed_config_fields(&config)?;
        let secret_relative = strict_relative_path(&config.secret_key_path)?;
        let expected_secret = format!("secrets/{}.pk8", config.validator_id);
        if secret_relative != Path::new(&expected_secret) {
            bail!("observer config secret reference differs from closed validator layout");
        }
        let expected_config = PathBuf::from(format!("public/configs/{}.json", config.validator_id));
        if config.run_id != manifest.run_id || relative_config != expected_config {
            bail!("observer selected config path or run differs from manifest");
        }
        validate_manifest_binding(&shim, &config, validator_set_sha256, &descriptor)?;
        validate_topology_binding(&topology, &config, &descriptor)?;
        if decode_hex32(&config.binary_sha256, "config.binary_sha256")? != linux_binary {
            bail!("observer selected config binary differs from candidate");
        }
        let workload_corpus_sha256 = decode_hex32(
            &config.workload_corpus_sha256,
            "observer config.workload_corpus_sha256",
        )?;
        let workload_policy_sha256 = decode_hex32(
            &config.workload_policy_sha256,
            "observer config.workload_policy_sha256",
        )?;
        let consensus_public_keys = validator_set
            .validators()
            .iter()
            .map(|validator| validator.consensus_key().into_bytes())
            .collect::<Vec<_>>();
        let verified_public_workload = VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
            observer_root.join("public/workload.corpus"),
            observer_root.join("public/workload-policy.json"),
            workload_corpus_sha256,
            workload_policy_sha256,
            validator_set.chain_id().as_str(),
            config.ordinary_start_height,
            &consensus_public_keys,
        )?;
        let verified_public_bootstrap = verify_public_zero_comet_bootstrap_v1(
            &observer_root,
            &validator_set,
            &parameters,
            &verified_public_workload,
        )?;
        let bootstrap_initial_cut = verified_public_bootstrap.initial_ordinary_cut_v1();

        let local_validator =
            ValidatorId::new(decode_hex32(&config.validator_id, "config.validator_id")?);
        let local = validator_set
            .validator(local_validator)
            .ok_or_else(|| anyhow!("observer report author is absent from validator set"))?;
        if local.consensus_key().as_bytes()
            != &decode_hex32(&config.consensus_public_key, "config.consensus_public_key")?
            || local.voting_power().get() != config.weight
        {
            bail!("observer config key/weight differs from validator set");
        }
        let local_ip = config
            .lan_ip
            .parse::<IpAddr>()
            .context("observer config LAN IP is invalid")?;
        if !local_ip.is_ipv4()
            || !is_private_lan(local_ip)
            || config.p2p_port == 0
            || config.metrics_port == 0
            || config.p2p_port == config.metrics_port
        {
            bail!("observer config endpoints cross the frozen private-LAN profile");
        }
        validate_peers(&config, &validator_set, local_validator)?;
        let incoming_peers =
            derive_incoming_peers(&topology, &descriptor, config.validator_id.as_str())?;
        let mut validator_config_sha256 = BTreeMap::new();
        let mut expected_outgoing_peers = BTreeMap::new();
        for planned in &topology.validators {
            let validator_id = ValidatorId::new(decode_hex32(
                &planned.validator_id,
                "observer topology validator ID",
            )?);
            let config_relative =
                PathBuf::from(format!("public/configs/{}.json", planned.validator_id));
            let config_bytes = frozen_files
                .get(&config_relative)
                .ok_or_else(|| anyhow!("observer topology config is absent from public bundle"))?;
            if validator_config_sha256
                .insert(validator_id, sha256(config_bytes))
                .is_some()
            {
                bail!("observer topology contains a duplicate validator config");
            }
            let peers = planned
                .peers
                .iter()
                .map(|peer| decode_hex32(peer, "observer topology peer ID").map(ValidatorId::new))
                .collect::<Result<BTreeSet<_>>>()?;
            if peers.len() != planned.peers.len()
                || expected_outgoing_peers
                    .insert(validator_id, peers)
                    .is_some()
            {
                bail!("observer topology contains duplicate directed peers");
            }
        }

        Ok(Self {
            run_id: config.run_id,
            host_id: config.host_id,
            local_ip,
            p2p_port: config.p2p_port,
            local_validator,
            validator_set,
            peers: config.peers,
            incoming_peers,
            validator_set_sha256,
            topology_sha256,
            config_sha256,
            coordinator_manifest_sha256: expected_coordinator_manifest_sha256,
            binary_sha256: linux_binary,
            candidate_source_sha256,
            ordinary_start_height: config.ordinary_start_height,
            workload_corpus_sha256,
            workload_policy_sha256,
            validator_config_sha256,
            expected_outgoing_peers,
            bootstrap_initial_cut,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.local_ip, self.p2p_port)
    }

    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    pub fn incoming_peers(&self) -> &[PeerConfig] {
        &self.incoming_peers
    }

    pub const fn validator_set_sha256(&self) -> [u8; 32] {
        self.validator_set_sha256
    }

    pub const fn topology_sha256(&self) -> [u8; 32] {
        self.topology_sha256
    }

    pub const fn config_sha256(&self) -> [u8; 32] {
        self.config_sha256
    }

    pub const fn coordinator_manifest_sha256(&self) -> [u8; 32] {
        self.coordinator_manifest_sha256
    }

    pub const fn binary_sha256(&self) -> [u8; 32] {
        self.binary_sha256
    }

    pub const fn candidate_source_sha256(&self) -> [u8; 32] {
        self.candidate_source_sha256
    }

    /// Exact first ordinary height committed by the independently verified
    /// config/workload/bootstrap bundle.
    pub const fn ordinary_start_height(&self) -> u64 {
        self.ordinary_start_height
    }

    pub const fn workload_corpus_sha256(&self) -> [u8; 32] {
        self.workload_corpus_sha256
    }

    pub const fn workload_policy_sha256(&self) -> [u8; 32] {
        self.workload_policy_sha256
    }

    pub fn validator_config_sha256(&self) -> &BTreeMap<ValidatorId, [u8; 32]> {
        &self.validator_config_sha256
    }

    pub fn expected_outgoing_peers(&self) -> &BTreeMap<ValidatorId, BTreeSet<ValidatorId>> {
        &self.expected_outgoing_peers
    }

    pub const fn bootstrap_initial_cut(&self) -> VerifiedPublicBootstrapInitialCutV1 {
        self.bootstrap_initial_cut
    }
}

fn validate_fixed_config_fields(config: &ValidatorConfigJson) -> Result<()> {
    if config.schema_version != 1
        || config.network_scope != "single-lan"
        || config.geo_wan_evidence
        || config.production_activation
    {
        bail!("validator config crosses the lab-only single-LAN boundary");
    }
    validate_run_id(&config.run_id)?;
    if config.host_id.is_empty()
        || config.host_id.len() > 32
        || !config
            .host_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("config.host_id is non-canonical");
    }
    decode_hex32(&config.validator_id, "config.validator_id")?;
    decode_hex32(&config.consensus_public_key, "config.consensus_public_key")?;
    decode_hex32(&config.validator_set_sha256, "config.validator_set_sha256")?;
    decode_hex32(&config.binary_sha256, "config.binary_sha256")?;
    decode_hex32(
        &config.workload_corpus_sha256,
        "config.workload_corpus_sha256",
    )?;
    decode_hex32(
        &config.workload_policy_sha256,
        "config.workload_policy_sha256",
    )?;
    if config.weight == 0 || config.ordinary_start_height != 4 {
        bail!("config weight/ordinary_start_height differs from the fixed h1-h3 bootstrap profile");
    }
    Ok(())
}

fn validate_set_fixed_fields(descriptor: &ValidatorSetJson, run_id: &str) -> Result<()> {
    if descriptor.schema_version != 1
        || descriptor.run_id != run_id
        || descriptor.chain_id != "trnm-poco-g3-lab-v0"
        || descriptor.protocol_version != 0
        || descriptor.epoch != 0
        || descriptor.consensus_parameters_profile != "reference-shadow-v0"
        || descriptor.production_activation
    {
        bail!("validator-set descriptor differs from the lab v0 contract");
    }
    decode_hex32(&descriptor.genesis_hash, "validator_set.genesis_hash")?;
    decode_hex32(
        &descriptor.candidate_source_sha256,
        "validator_set.candidate_source_sha256",
    )?;
    Ok(())
}

fn run_id_validator_count(run_id: &str) -> Result<usize> {
    validate_run_id(run_id)?;
    run_id
        .split('-')
        .nth(2)
        .ok_or_else(|| anyhow!("run ID lacks validator cardinality"))?
        .parse::<usize>()
        .context("run ID cardinality is invalid")
}

fn validate_material_author(
    author: &MaterialAuthorJson,
    candidate: &CandidateJson,
    field: &str,
) -> Result<[u8; 32]> {
    let author_hash = decode_hex32(&author.binary_sha256, &format!("{field}.binary_sha256"))?;
    let candidate_hashes = [
        decode_hex32(
            &candidate.source_tree_sha256,
            &format!("{field}.candidate.source_tree_sha256"),
        )?,
        decode_hex32(
            &candidate.linux_x86_64_sha256,
            &format!("{field}.candidate.linux_x86_64_sha256"),
        )?,
        decode_hex32(
            &candidate.macos_arm64_sha256,
            &format!("{field}.candidate.macos_arm64_sha256"),
        )?,
    ];
    if author_hash == [0; 32] || candidate_hashes.contains(&author_hash) || author.runtime_deployed
    {
        bail!("{field} must bind one distinct non-deployed author binary");
    }
    Ok(author_hash)
}

fn validate_manifest(
    manifest: &ManifestJson,
    run_id: &str,
    validator_id: &str,
    root: &Path,
) -> Result<()> {
    if manifest.schema_version != 3
        || manifest.deployment_validator_id.as_deref() != Some(validator_id)
        || manifest
            .coordinator_manifest_sha256
            .as_deref()
            .map(|value| decode_hex32(value, "manifest.coordinator_manifest_sha256"))
            .transpose()?
            .is_none()
        || manifest.run_id != run_id
        || manifest.fleet_id != "trnm-poco-lan-six-host-2026-08-13"
        || !matches!(manifest.validator_count, 7 | 31 | 100)
        || !matches!(
            manifest.weight_profile.as_str(),
            "equal" | "bounded-unequal"
        )
        || manifest.network_scope != "single-lan"
        || manifest.geo_wan_evidence
        || manifest.production_activation
    {
        bail!("run manifest differs from the frozen G3 laboratory contract");
    }
    let source = decode_hex32(
        &manifest.candidate.source_tree_sha256,
        "manifest.candidate.source_tree_sha256",
    )?;
    decode_hex32(
        &manifest.candidate.linux_x86_64_sha256,
        "manifest.candidate.linux_x86_64_sha256",
    )?;
    decode_hex32(
        &manifest.candidate.macos_arm64_sha256,
        "manifest.candidate.macos_arm64_sha256",
    )?;
    validate_material_author(
        &manifest.material_author,
        &manifest.candidate,
        "manifest.material_author",
    )?;
    decode_hex32(
        &manifest.validator_set_sha256,
        "manifest.validator_set_sha256",
    )?;
    let mut paths = BTreeSet::new();
    for (record, secret) in manifest
        .public_files
        .iter()
        .map(|record| (record, false))
        .chain(manifest.secret_files.iter().map(|record| (record, true)))
    {
        let relative = strict_relative_path(&record.path)?;
        if !paths.insert(relative.clone()) || record.bytes == 0 {
            bail!("manifest contains duplicate or empty file reference");
        }
        let path = canonical_regular_file(&root.join(&relative))?;
        require_descendant(root, &path, "manifest file")?;
        let metadata = fs::metadata(&path).context("stat manifest file")?;
        if metadata.len() != record.bytes
            || sha256_file(&path)? != decode_hex32(&record.sha256, "manifest file sha256")?
            || (secret && metadata.permissions().mode() & 0o777 != 0o600)
            || (!secret && metadata.permissions().mode() & 0o022 != 0)
        {
            bail!("manifest file content address or permissions mismatch");
        }
    }
    let mut actual_paths = BTreeSet::new();
    collect_closed_file_inventory(root, root, &mut actual_paths)?;
    actual_paths.remove(Path::new("manifest.json"));
    if actual_paths != paths {
        bail!("run root contains an unreferenced or missing manifest file");
    }
    let expected_public = BTreeSet::from([
        PathBuf::from("topology.json"),
        PathBuf::from("public/validator-set.json"),
        PathBuf::from(format!("public/configs/{validator_id}.json")),
        PathBuf::from("public/workload.corpus"),
        PathBuf::from("public/workload-policy.json"),
        PathBuf::from("public/bootstrap/h1.proposal"),
        PathBuf::from("public/bootstrap/h2.proposal"),
        PathBuf::from("public/bootstrap/h3.proposal"),
        PathBuf::from("public/bootstrap/finality-proof.cev0"),
        PathBuf::from("public/bootstrap/bootstrap.json"),
    ]);
    let expected_secret = BTreeSet::from([PathBuf::from(format!("secrets/{validator_id}.pk8"))]);
    let actual_public = manifest
        .public_files
        .iter()
        .map(|record| strict_relative_path(&record.path))
        .collect::<Result<BTreeSet<_>>>()?;
    let actual_secret = manifest
        .secret_files
        .iter()
        .map(|record| strict_relative_path(&record.path))
        .collect::<Result<BTreeSet<_>>>()?;
    if actual_public != expected_public || actual_secret != expected_secret {
        bail!("validator deployment must contain exactly one local secret and ten public inputs");
    }
    if source == [0; 32] {
        bail!("manifest source digest must not be zero");
    }
    Ok(())
}

fn require_manifest_bytes(
    manifest: &ManifestJson,
    expected_path: &str,
    bytes: &[u8],
    secret: bool,
) -> Result<()> {
    let records = if secret {
        &manifest.secret_files
    } else {
        &manifest.public_files
    };
    let record = records
        .iter()
        .find(|record| record.path == expected_path)
        .ok_or_else(|| anyhow!("manifest does not bind {expected_path}"))?;
    let length = u64::try_from(bytes.len()).context("manifest-bound byte length overflow")?;
    if record.bytes != length
        || decode_hex32(&record.sha256, "manifest frozen file sha256")? != sha256(bytes)
    {
        bail!("frozen bytes differ from the exact manifest reference for {expected_path}");
    }
    Ok(())
}

fn require_manifest_hash(
    manifest: &ManifestJson,
    expected_path: &str,
    expected_sha256: [u8; 32],
    secret: bool,
) -> Result<()> {
    let records = if secret {
        &manifest.secret_files
    } else {
        &manifest.public_files
    };
    let record = records
        .iter()
        .find(|record| record.path == expected_path)
        .ok_or_else(|| anyhow!("manifest does not bind {expected_path}"))?;
    if record.bytes == 0
        || decode_hex32(&record.sha256, "manifest frozen file sha256")? != expected_sha256
    {
        bail!("manifest hash differs from the exact config reference for {expected_path}");
    }
    Ok(())
}

fn validate_topology(
    topology: &TopologyJson,
    manifest: &ManifestJson,
    expected_count: usize,
) -> Result<()> {
    let expected_degree = if expected_count == 7 { 6 } else { 8 };
    if topology.schema_version != 1
        || topology.fleet_id != manifest.fleet_id
        || topology.network_scope != "single-lan"
        || topology.geo_wan_evidence
        || topology.validator_count != expected_count
        || topology.weight_profile != manifest.weight_profile
        || topology.peer_degree != expected_degree
        || topology.test_keys_included
        || topology.participants.len() != 6
        || topology.validators.len() != expected_count
    {
        bail!("topology differs from the frozen six-host G3 profile");
    }
    let expected_participants = expected_participants();
    for (actual, expected) in topology.participants.iter().zip(expected_participants) {
        if actual.host_id != expected.host_id
            || actual.management != expected.management
            || actual.lan_ip != expected.lan_ip
            || actual.os != expected.os
            || actual.arch != expected.arch
            || actual.validator_eligible != expected.validator_eligible
            || actual
                .run_roles
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != expected.run_roles
        {
            bail!("topology participant differs from the authorized six-host fleet");
        }
    }
    let expected_allocations: [usize; 5] = match expected_count {
        7 => [2, 1, 1, 2, 1],
        31 => [5, 2, 10, 13, 1],
        100 => [20, 3, 36, 38, 3],
        _ => unreachable!("validated topology cardinality"),
    };
    let mut allocations = BTreeMap::<&str, Vec<usize>>::new();
    let mut ids = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for (expected_index, validator) in topology.validators.iter().enumerate() {
        let participant = topology
            .participants
            .iter()
            .find(|value| value.host_id == validator.host_id)
            .ok_or_else(|| anyhow!("topology validator names an unknown participant"))?;
        if validator.index != expected_index
            || !participant.validator_eligible
            || validator.management != participant.management
            || validator.lan_ip != participant.lan_ip
            || validator.weight == 0
            || validator.peers.len() != expected_degree
            || !ids.insert(validator.validator_id.as_str())
        {
            bail!("topology validator record is non-canonical");
        }
        decode_hex32(&validator.validator_id, "topology.validator_id")?;
        let ip = validator
            .lan_ip
            .parse::<IpAddr>()
            .context("topology validator IP is invalid")?;
        if !ip.is_ipv4()
            || !is_private_lan(ip)
            || validator.p2p_port == 0
            || validator.metrics_port == 0
            || validator.p2p_port == validator.metrics_port
            || !endpoints.insert((ip, validator.p2p_port))
            || !endpoints.insert((ip, validator.metrics_port))
        {
            bail!("topology validator endpoints are invalid or duplicated");
        }
        allocations
            .entry(validator.host_id.as_str())
            .or_default()
            .push(validator.host_local_index);
    }
    for (index, participant) in topology.participants[..5].iter().enumerate() {
        let actual = allocations
            .get(participant.host_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let expected: Vec<_> = (0..expected_allocations[index]).collect();
        if actual != expected {
            bail!("topology host-local validator allocation is non-canonical");
        }
    }
    for validator in &topology.validators {
        let expected: Vec<_> = (1..=expected_degree)
            .map(|offset| {
                topology.validators[(validator.index + offset) % expected_count]
                    .validator_id
                    .as_str()
            })
            .collect();
        if validator
            .peers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected
        {
            bail!("topology peer ring differs from the frozen deterministic order");
        }
    }
    Ok(())
}

fn validate_manifest_binding(
    manifest: &ManifestJson,
    config: &ValidatorConfigJson,
    validator_set_sha256: [u8; 32],
    descriptor: &ValidatorSetJson,
) -> Result<()> {
    if validator_set_sha256
        != decode_hex32(
            &manifest.validator_set_sha256,
            "manifest.validator_set_sha256",
        )?
        || descriptor.candidate_source_sha256 != manifest.candidate.source_tree_sha256
        || config.binary_sha256 != manifest.candidate.linux_x86_64_sha256
    {
        bail!("config/set/candidate hashes differ from manifest");
    }
    let bound = manifest.public_files.iter().any(|record| {
        record.path == "public/validator-set.json"
            && record.sha256 == hex::encode(validator_set_sha256)
    });
    if !bound {
        bail!("manifest does not bind the exact validator-set descriptor");
    }
    let expected_config = format!("public/configs/{}.json", config.validator_id);
    if !manifest
        .public_files
        .iter()
        .any(|record| record.path == expected_config)
    {
        bail!("manifest does not bind the selected validator config");
    }
    require_manifest_hash(
        manifest,
        "public/workload.corpus",
        decode_hex32(
            &config.workload_corpus_sha256,
            "config.workload_corpus_sha256",
        )?,
        false,
    )?;
    require_manifest_hash(
        manifest,
        "public/workload-policy.json",
        decode_hex32(
            &config.workload_policy_sha256,
            "config.workload_policy_sha256",
        )?,
        false,
    )?;
    Ok(())
}

fn validate_topology_binding(
    topology: &TopologyJson,
    config: &ValidatorConfigJson,
    descriptor: &ValidatorSetJson,
) -> Result<()> {
    let by_id: BTreeMap<_, _> = topology
        .validators
        .iter()
        .map(|value| (value.validator_id.as_str(), value))
        .collect();
    let planned = by_id
        .get(config.validator_id.as_str())
        .ok_or_else(|| anyhow!("local config validator is absent from topology"))?;
    if planned.host_id != config.host_id
        || planned.lan_ip != config.lan_ip
        || planned.p2p_port != config.p2p_port
        || planned.metrics_port != config.metrics_port
        || planned.weight != config.weight
    {
        bail!("local config placement differs from topology");
    }
    let set_by_id: BTreeMap<_, _> = descriptor
        .validators
        .iter()
        .map(|value| (value.validator_id.as_str(), value))
        .collect();
    for validator in &topology.validators {
        let set_record = set_by_id
            .get(validator.validator_id.as_str())
            .ok_or_else(|| anyhow!("topology validator is absent from validator set"))?;
        if set_record.voting_power != validator.weight {
            bail!("topology voting power differs from validator set");
        }
    }
    if config.peers.len() != planned.peers.len() {
        bail!("local config peer count differs from topology");
    }
    for (actual, expected_id) in config.peers.iter().zip(&planned.peers) {
        let expected = by_id
            .get(expected_id.as_str())
            .ok_or_else(|| anyhow!("topology peer is absent"))?;
        let set_record = set_by_id
            .get(expected_id.as_str())
            .ok_or_else(|| anyhow!("topology peer is absent from set"))?;
        if actual.validator_id != *expected_id
            || actual.lan_ip != expected.lan_ip
            || actual.p2p_port != expected.p2p_port
            || actual.consensus_public_key != set_record.consensus_public_key
        {
            bail!("local config peer tuple differs from topology/set");
        }
    }
    Ok(())
}

fn derive_incoming_peers(
    topology: &TopologyJson,
    descriptor: &ValidatorSetJson,
    local_validator_id: &str,
) -> Result<Vec<PeerConfig>> {
    let set_by_id: BTreeMap<_, _> = descriptor
        .validators
        .iter()
        .map(|value| (value.validator_id.as_str(), value))
        .collect();
    let mut incoming = Vec::new();
    for validator in &topology.validators {
        if validator
            .peers
            .iter()
            .any(|peer| peer == local_validator_id)
        {
            let record = set_by_id
                .get(validator.validator_id.as_str())
                .ok_or_else(|| anyhow!("incoming topology peer is absent from validator set"))?;
            incoming.push(PeerConfig {
                validator_id: validator.validator_id.clone(),
                lan_ip: validator.lan_ip.clone(),
                p2p_port: validator.p2p_port,
                consensus_public_key: record.consensus_public_key.clone(),
            });
        }
    }
    if incoming.len() != topology.peer_degree {
        bail!("incoming directed peer cardinality differs from frozen topology");
    }
    Ok(incoming)
}

fn pop_challenge(run_id: &str, validator_id: &str) -> Vec<u8> {
    let mut challenge = Vec::new();
    challenge.extend_from_slice(b"TRNM/PoCO/G3/EphemeralKeyPoP/v1\0");
    challenge.extend_from_slice(&(run_id.len() as u32).to_be_bytes());
    challenge.extend_from_slice(run_id.as_bytes());
    challenge.extend_from_slice(&(validator_id.len() as u32).to_be_bytes());
    challenge.extend_from_slice(validator_id.as_bytes());
    challenge
}

fn build_validator_set(
    descriptor: &ValidatorSetJson,
    parameters: &ConsensusParametersV0,
) -> Result<(ValidatorSet, [u8; 32])> {
    if !matches!(descriptor.validators.len(), 7 | 31 | 100) {
        bail!("G3 validator-set cardinality must be 7, 31, or 100");
    }
    let mut previous = None;
    let mut public_keys = BTreeSet::new();
    let mut validators = Vec::with_capacity(descriptor.validators.len());
    for record in &descriptor.validators {
        let id_bytes = decode_hex32(&record.validator_id, "validator.validator_id")?;
        if previous.is_some_and(|value: [u8; 32]| value >= id_bytes) {
            bail!("validator-set records are not strictly ID-sorted");
        }
        previous = Some(id_bytes);
        let public_key = decode_hex32(
            &record.consensus_public_key,
            "validator.consensus_public_key",
        )?;
        if !public_keys.insert(public_key) {
            bail!("validator-set contains a duplicate consensus public key");
        }
        let pop = hex::decode(&record.key_pop_signature)
            .context("validator key PoP is not canonical hex")?;
        if pop.len() != 64 {
            bail!("validator key PoP must be exactly 64 bytes");
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| anyhow!("validator PoP public key is not Ed25519"))?;
        let pop_signature: [u8; 64] = pop.as_slice().try_into().expect("PoP length was checked");
        verifying_key
            .verify_strict(
                &pop_challenge(&descriptor.run_id, &record.validator_id),
                &Signature::from_bytes(&pop_signature),
            )
            .map_err(|_| anyhow!("validator key proof-of-possession is invalid"))?;
        validators.push(
            Validator::new(
                ValidatorId::new(id_bytes),
                ConsensusPublicKey::new(public_key),
                VotingPower::new(record.voting_power).map_err(|error| {
                    anyhow!("validator voting power must be positive: {error:?}")
                })?,
            )
            .map_err(|error| anyhow!("invalid validator record: {error:?}"))?,
        );
    }
    let chain_id = ChainId::new(&descriptor.chain_id)
        .map_err(|error| anyhow!("invalid lab chain ID: {error:?}"))?;
    let canonical_genesis =
        derive_canonical_lab_genesis_hash_v0(chain_id, *parameters, &validators)?;
    if decode_hex32(&descriptor.genesis_hash, "validator_set.genesis_hash")?
        != canonical_genesis.into_bytes()
    {
        bail!("validator-set genesis hash differs from chain-only canonical derivation");
    }
    let validator_set = ValidatorSet::new(
        canonical_genesis,
        chain_id,
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .map_err(|error| anyhow!("invalid validator set: {error:?}"))?;
    validator_set
        .validate_against_parameters(parameters)
        .map_err(|error| anyhow!("validator set violates reference parameters: {error:?}"))?;
    Ok((
        validator_set,
        decode_hex32(
            &descriptor.candidate_source_sha256,
            "validator_set.candidate_source_sha256",
        )?,
    ))
}

fn validate_peers(
    config: &ValidatorConfigJson,
    validator_set: &ValidatorSet,
    local_validator: ValidatorId,
) -> Result<()> {
    let expected_degree = if validator_set.validators().len() == 7 {
        6
    } else {
        8
    };
    if config.peers.len() != expected_degree {
        bail!("config peer degree differs from the frozen topology");
    }
    let mut seen = BTreeSet::new();
    for peer in &config.peers {
        let id = ValidatorId::new(decode_hex32(&peer.validator_id, "peer.validator_id")?);
        if id == local_validator || !seen.insert(id) {
            bail!("config peers contain self or duplicate identity");
        }
        let validator = validator_set
            .validator(id)
            .ok_or_else(|| anyhow!("config names an unknown peer"))?;
        if validator.consensus_key().as_bytes()
            != &decode_hex32(&peer.consensus_public_key, "peer.consensus_public_key")?
        {
            bail!("peer key differs from validator set");
        }
        let address = peer.socket_addr()?;
        if !address.ip().is_ipv4() || !is_private_lan(address.ip()) || address.port() == 0 {
            bail!("peer address is outside the bounded private LAN");
        }
    }
    Ok(())
}

pub(crate) fn validate_run_id(value: &str) -> Result<()> {
    let mut parts = value.split('-');
    if parts.next() != Some("poco")
        || parts.next() != Some("g3")
        || !matches!(parts.next(), Some("7" | "31" | "100"))
    {
        bail!("run_id does not name one G3 topology");
    }
    let timestamp = parts
        .next()
        .ok_or_else(|| anyhow!("run_id lacks timestamp"))?;
    let nonce = parts.next().ok_or_else(|| anyhow!("run_id lacks nonce"))?;
    if parts.next().is_some()
        || timestamp.len() != 16
        || !timestamp.ends_with('Z')
        || !timestamp[..15]
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 8 && byte == b'T' || index != 8 && byte.is_ascii_digit())
        || nonce.len() != 8
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("run_id is non-canonical");
    }
    Ok(())
}

fn collect_closed_file_inventory(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read run-material directory {}", directory.display()))?
    {
        let entry = entry.context("read run-material directory entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("stat run-material entry {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("run-material inventory contains a symlink");
        }
        if metadata.is_dir() {
            collect_closed_file_inventory(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("run-material entry escapes root"))?
                .to_path_buf();
            if !output.insert(relative) {
                bail!("run-material inventory contains a duplicate file");
            }
        } else {
            bail!("run-material inventory contains a non-file entry");
        }
    }
    Ok(())
}

fn canonical_private_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).context("stat run root")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("run root must be one real directory");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("run root must not grant group/world permissions");
    }
    fs::canonicalize(path).context("canonicalize run root")
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.file_type().is_socket()
    {
        bail!("{} must be one regular non-symlink file", path.display());
    }
    fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

fn read_regular_file_pinned(path: &Path, label: &str) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open pinned {label}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat pinned {label}"))?;
    if !metadata.is_file() {
        bail!("{label} must be one pinned regular file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_FROZEN_INPUT_BYTES {
        bail!("{label} size crosses its bounded profile");
    }
    let capacity = usize::try_from(metadata.len()).context("pinned input is too large")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read pinned {label}"))?;
    if u64::try_from(bytes.len()).context("pinned input length overflow")? != metadata.len() {
        bail!("{label} changed length during its pinned read");
    }
    Ok(bytes)
}

fn require_descendant(root: &Path, path: &Path, label: &str) -> Result<()> {
    if !path.starts_with(root) || path == root {
        bail!("{label} escapes the run root");
    }
    Ok(())
}

fn strict_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_)) || component.as_os_str().is_empty()
        })
    {
        bail!("secret path must be one strict relative path");
    }
    Ok(path.to_path_buf())
}

pub(crate) fn load_pkcs8_ed25519_seed(bytes: &[u8]) -> Result<SigningKey> {
    if bytes.len() != PKCS8_ED25519_PREFIX.len() + 32
        || bytes[..PKCS8_ED25519_PREFIX.len()] != PKCS8_ED25519_PREFIX
    {
        bail!("validator secret is not canonical OpenSSL Ed25519 PKCS#8 DER");
    }
    let seed: [u8; 32] = bytes[PKCS8_ED25519_PREFIX.len()..]
        .try_into()
        .expect("exact secret length was checked");
    Ok(SigningKey::from_bytes(&seed))
}

fn decode_hex32(value: &str, field: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{field} must be canonical lowercase 32-byte hex");
    }
    let bytes = hex::decode(value).with_context(|| format!("decode {field}"))?;
    Ok(bytes
        .try_into()
        .expect("64 hex characters decode to exactly 32 bytes"))
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256(&bytes))
}

fn sha256_running_image(requested_path: &Path) -> Result<[u8; 32]> {
    let proc_path = Path::new("/proc/self/exe");
    let mut file = OpenOptions::new()
        .read(true)
        // `/proc/self/exe` is a kernel-owned magic link to this process's
        // executable image.  Opening it obtains the stable inode; O_NOFOLLOW
        // would reject the magic link itself instead of pinning its target.
        .custom_flags(libc::O_CLOEXEC)
        .open(proc_path)
        .context("open pinned /proc/self/exe")?;
    let handle = file.metadata().context("stat pinned running image")?;
    let requested = fs::metadata(requested_path).context("stat requested running image")?;
    if !handle.is_file()
        || handle.dev() != requested.dev()
        || handle.ino() != requested.ino()
        || handle.len() != requested.len()
    {
        bail!("requested binary path does not identify the running image inode");
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .context("read pinned running image")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().context("restat pinned running image")?;
    if after.dev() != handle.dev()
        || after.ino() != handle.ino()
        || after.len() != handle.len()
        || after.mtime() != handle.mtime()
        || after.mtime_nsec() != handle.mtime_nsec()
    {
        bail!("running image changed while hashing");
    }
    Ok(hasher.finalize().into())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn is_private_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.is_private(),
        IpAddr::V6(_) => false,
    }
}
