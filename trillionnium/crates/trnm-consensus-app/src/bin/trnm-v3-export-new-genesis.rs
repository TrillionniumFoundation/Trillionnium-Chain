use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_app::{APP_VERSION, GENESIS_SCHEMA_V3};

const SOURCE_SCHEMA_V3: &str = "trnm_cometbft_app_state_v3";
const VALIDATOR_LIFECYCLE_SCHEMA_V1: &str = "trnm_validator_lifecycle_v1";
const VALIDATOR_GOVERNANCE_SCHEMA_V1: &str = "trnm_validator_governance_v1";
const SOURCE_APP_VERSION: u64 = 3;
const TARGET_APP_VERSION: u64 = APP_VERSION;
const TARGET_GENESIS_SCHEMA: &str = GENESIS_SCHEMA_V3;
const MAX_TOTAL_VOTING_POWER: u64 = (i64::MAX as u64) / 8;

type Hash32 = [u8; 32];

#[derive(Debug, Parser)]
#[command(
    name = "trnm-v3-export-new-genesis",
    about = "Validate an offline v3 JSON state and export a review-only current-version new-genesis bundle"
)]
struct Cli {
    /// Offline trnm_cometbft_app_state_v3 JSON. Live SQLite/status files are unsupported.
    #[arg(long)]
    source_v3: PathBuf,

    /// New chain ID. It must be canonical and different from the source lifecycle chain ID.
    #[arg(long)]
    target_chain_id: String,

    /// New, non-existent directory that will receive the atomically published review bundle.
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV3State {
    schema: String,
    height: u64,
    app_hash_hex: String,
    objects: Vec<LegacyObject>,
    command_ids: Vec<String>,
    signer_nonces: Vec<(String, u64)>,
    validator_lifecycle: LegacyValidatorLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyObject {
    object_key_hex: String,
    object_type: String,
    version: u64,
    value_hash_hex: String,
    value_hex: String,
}

impl LegacyObject {
    fn leaf_hash(&self) -> Hash32 {
        hash_domain(
            "trnm.state.object.leaf.v1",
            &[
                self.object_key_hex.as_bytes(),
                self.object_type.as_bytes(),
                &self.version.to_be_bytes(),
                self.value_hash_hex.as_bytes(),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyValidatorGovernance {
    schema: String,
    signer_id: String,
    min_activation_delay_blocks: u64,
    unsafe_allow_single_validator_genesis: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyConsensusValidator {
    public_key_hex: String,
    voting_power: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyScheduledValidatorTransition {
    transition_id: String,
    base_validator_set_hash_hex: String,
    accepted_height: u64,
    activation_height: u64,
    target_validators: Vec<LegacyConsensusValidator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyValidatorLifecycle {
    schema: String,
    chain_id: String,
    app_version: u64,
    authorized_signers_hash_hex: String,
    governance: LegacyValidatorGovernance,
    active_validators: Vec<LegacyConsensusValidator>,
    pending_transition: Option<LegacyScheduledValidatorTransition>,
    last_applied_transition_id: Option<String>,
}

#[derive(Debug)]
struct ValidatedV3State {
    height: u64,
    app_hash_hex: String,
    objects: BTreeMap<String, LegacyObject>,
    command_ids: BTreeSet<String>,
    signer_nonces: BTreeSet<(String, u64)>,
    validator_lifecycle: LegacyValidatorLifecycle,
}

#[derive(Debug, Serialize)]
struct CanonicalObjectsExport {
    schema: &'static str,
    source_height: u64,
    source_app_hash_hex: String,
    objects: Vec<LegacyObject>,
}

#[derive(Debug, Serialize)]
struct ReplayIndexesExport {
    schema: &'static str,
    source_height: u64,
    source_app_hash_hex: String,
    command_ids: Vec<String>,
    signer_nonces: Vec<(String, u64)>,
    automatic_target_import_supported: bool,
}

#[derive(Debug, Serialize)]
struct ValidatorLifecycleExport {
    schema: &'static str,
    source_chain_id: String,
    target_chain_id: String,
    source_app_version: u64,
    target_app_version: u64,
    source_lifecycle: LegacyValidatorLifecycle,
    proposed_target_genesis: ProposedTargetGenesis,
}

#[derive(Debug, Serialize)]
struct ProposedTargetGenesis {
    schema: &'static str,
    app_version: u64,
    initial_validators: Vec<LegacyConsensusValidator>,
    governance: LegacyValidatorGovernance,
    source_pending_transition: Option<LegacyScheduledValidatorTransition>,
    carry_pending_transition_automatically: bool,
    authorized_signers_must_be_supplied_and_reviewed: bool,
    research_authorities_must_be_supplied_and_reviewed: bool,
}

#[derive(Debug, Serialize)]
struct ExportManifest {
    schema: &'static str,
    migration_mode: &'static str,
    source: SourceManifest,
    target: TargetManifest,
    artifacts: Vec<ArtifactManifest>,
    source_app_hash_verified: bool,
    source_file_mutated: bool,
    old_height_app_hash_mutated: bool,
    direct_node_start_supported: bool,
    requires_manual_review_and_signature: bool,
    warnings: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct SourceManifest {
    file_name: String,
    sha256_hex: String,
    schema: &'static str,
    chain_id: String,
    app_version: u64,
    height: u64,
    app_hash_hex: String,
    object_count: u64,
    command_id_count: u64,
    signer_nonce_count: u64,
    pending_validator_transition: bool,
}

#[derive(Debug, Serialize)]
struct TargetManifest {
    chain_id: String,
    genesis_schema: &'static str,
    app_version: u64,
    app_hash_hex: Option<String>,
    genesis_height_policy: &'static str,
}

#[derive(Debug, Serialize)]
struct ArtifactManifest {
    path: String,
    sha256_hex: String,
}

#[derive(Debug)]
struct ExportReport {
    source_height: u64,
    source_app_hash_hex: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = export_new_genesis(&cli.source_v3, &cli.target_chain_id, &cli.output_dir)?;
    println!(
        "TRNM_V3_EXPORT_NEW_GENESIS_OK source_height={} source_app_hash={} target_chain_id={} bundle={} review_required=true",
        report.source_height,
        report.source_app_hash_hex,
        cli.target_chain_id,
        cli.output_dir.display()
    );
    Ok(())
}

fn export_new_genesis(
    source_path: &Path,
    target_chain_id: &str,
    output_dir: &Path,
) -> Result<ExportReport> {
    validate_chain_id("target chain_id", target_chain_id)?;

    let source_metadata = fs::symlink_metadata(source_path)
        .with_context(|| format!("inspect source v3 state {}", source_path.display()))?;
    ensure!(
        source_metadata.file_type().is_file() && !source_metadata.file_type().is_symlink(),
        "source_v3 must be a regular, non-symlink file"
    );
    let source_bytes = fs::read(source_path)
        .with_context(|| format!("read source v3 state {}", source_path.display()))?;
    let source_sha256_hex = plain_sha256_hex(&source_bytes);
    let state = validate_v3_state(&source_bytes)?;
    ensure!(
        target_chain_id != state.validator_lifecycle.chain_id,
        "target chain_id must differ from the source chain_id"
    );
    ensure!(
        !output_dir.exists(),
        "output_dir already exists; refusing to overwrite a review bundle"
    );

    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create output parent {}", parent.display()))?;
    let output_name = output_dir
        .file_name()
        .and_then(|value| value.to_str())
        .context("output_dir must have a UTF-8 final component")?;
    let temporary_dir = parent.join(format!(".{output_name}.tmp-{}", std::process::id()));
    ensure!(
        !temporary_dir.exists(),
        "temporary export directory already exists: {}",
        temporary_dir.display()
    );
    fs::create_dir(&temporary_dir)
        .with_context(|| format!("create temporary bundle {}", temporary_dir.display()))?;

    let result = build_and_publish_bundle(
        source_path,
        &source_bytes,
        &source_sha256_hex,
        &state,
        target_chain_id,
        output_dir,
        &temporary_dir,
        parent,
    );
    if result.is_err() && temporary_dir.exists() {
        let _ = fs::remove_dir_all(&temporary_dir);
    }
    result?;

    Ok(ExportReport {
        source_height: state.height,
        source_app_hash_hex: state.app_hash_hex,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_and_publish_bundle(
    source_path: &Path,
    original_source_bytes: &[u8],
    source_sha256_hex: &str,
    state: &ValidatedV3State,
    target_chain_id: &str,
    output_dir: &Path,
    temporary_dir: &Path,
    parent: &Path,
) -> Result<()> {
    let objects = CanonicalObjectsExport {
        schema: "trnm_v3_export_canonical_objects_v1",
        source_height: state.height,
        source_app_hash_hex: state.app_hash_hex.clone(),
        objects: state.objects.values().cloned().collect(),
    };
    let replay = ReplayIndexesExport {
        schema: "trnm_v3_export_replay_indexes_v2",
        source_height: state.height,
        source_app_hash_hex: state.app_hash_hex.clone(),
        command_ids: state.command_ids.iter().cloned().collect(),
        signer_nonces: state.signer_nonces.iter().cloned().collect(),
        automatic_target_import_supported: false,
    };
    let lifecycle = ValidatorLifecycleExport {
        schema: "trnm_v3_export_validator_lifecycle_review_v2",
        source_chain_id: state.validator_lifecycle.chain_id.clone(),
        target_chain_id: target_chain_id.to_string(),
        source_app_version: SOURCE_APP_VERSION,
        target_app_version: TARGET_APP_VERSION,
        source_lifecycle: state.validator_lifecycle.clone(),
        proposed_target_genesis: ProposedTargetGenesis {
            schema: TARGET_GENESIS_SCHEMA,
            app_version: TARGET_APP_VERSION,
            initial_validators: state.validator_lifecycle.active_validators.clone(),
            governance: state.validator_lifecycle.governance.clone(),
            source_pending_transition: state.validator_lifecycle.pending_transition.clone(),
            carry_pending_transition_automatically: false,
            authorized_signers_must_be_supplied_and_reviewed: true,
            research_authorities_must_be_supplied_and_reviewed: true,
        },
    };

    let objects_bytes = pretty_json_bytes(&objects)?;
    let replay_bytes = pretty_json_bytes(&replay)?;
    let lifecycle_bytes = pretty_json_bytes(&lifecycle)?;
    let readme_bytes = review_readme(state, source_sha256_hex, target_chain_id).into_bytes();
    let rollback_bytes = rollback_readme(state, target_chain_id).into_bytes();

    let artifact_bytes = [
        ("canonical-objects.json", objects_bytes),
        ("legacy-replay-indexes.json", replay_bytes),
        ("validator-lifecycle.json", lifecycle_bytes),
        ("README.md", readme_bytes),
        ("ROLLBACK.md", rollback_bytes),
    ];
    let mut artifacts = Vec::with_capacity(artifact_bytes.len());
    for (name, bytes) in artifact_bytes {
        write_new_synced_file(&temporary_dir.join(name), &bytes)?;
        artifacts.push(ArtifactManifest {
            path: name.to_string(),
            sha256_hex: plain_sha256_hex(&bytes),
        });
    }

    let source_file_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("source-v3.json")
        .to_string();
    let manifest = ExportManifest {
        schema: "trnm_v3_export_new_genesis_manifest_v2",
        migration_mode: "offline-export-new-genesis-review-only",
        source: SourceManifest {
            file_name: source_file_name,
            sha256_hex: source_sha256_hex.to_string(),
            schema: SOURCE_SCHEMA_V3,
            chain_id: state.validator_lifecycle.chain_id.clone(),
            app_version: SOURCE_APP_VERSION,
            height: state.height,
            app_hash_hex: state.app_hash_hex.clone(),
            object_count: usize_to_u64(state.objects.len(), "object count")?,
            command_id_count: usize_to_u64(state.command_ids.len(), "command ID count")?,
            signer_nonce_count: usize_to_u64(state.signer_nonces.len(), "signer nonce count")?,
            pending_validator_transition: state
                .validator_lifecycle
                .pending_transition
                .is_some(),
        },
        target: TargetManifest {
            chain_id: target_chain_id.to_string(),
            genesis_schema: TARGET_GENESIS_SCHEMA,
            app_version: TARGET_APP_VERSION,
            app_hash_hex: None,
            genesis_height_policy: "fresh-new-chain-only; source height is evidence, not target live height",
        },
        artifacts,
        source_app_hash_verified: true,
        source_file_mutated: false,
        old_height_app_hash_mutated: false,
        direct_node_start_supported: false,
        requires_manual_review_and_signature: true,
        warnings: vec![
            "This bundle is not a target application database, snapshot, or CometBFT genesis file.",
            "Do not reuse the source CometBFT data directory or claim in-place migration.",
            "The v3 state contains only an authorized-signer commitment; target signer identities and keys require separate reviewed input.",
            "The v3 state contains no Research authority set; target Nakama and Hepta authorities require separate reviewed input.",
            "Pending validator transitions are exported for review and are never carried automatically.",
            "A separate reviewed genesis ceremony must construct, sign, and independently verify the target current-version genesis.",
        ],
    };
    write_new_synced_file(
        &temporary_dir.join("manifest.json"),
        &pretty_json_bytes(&manifest)?,
    )?;

    sync_directory(temporary_dir)?;
    let source_after = fs::read(source_path)
        .with_context(|| format!("re-read source v3 state {}", source_path.display()))?;
    ensure!(
        source_after == original_source_bytes,
        "source_v3 changed while export was running"
    );
    fs::rename(temporary_dir, output_dir).with_context(|| {
        format!(
            "atomically publish review bundle {} from {}",
            output_dir.display(),
            temporary_dir.display()
        )
    })?;
    sync_directory(parent)?;
    Ok(())
}

fn validate_v3_state(bytes: &[u8]) -> Result<ValidatedV3State> {
    let persisted: LegacyV3State =
        serde_json::from_slice(bytes).context("decode strict v3 application state JSON")?;
    ensure!(
        persisted.schema == SOURCE_SCHEMA_V3,
        "unsupported source state schema"
    );
    let committed_app_hash = decode_hash32("source app_hash_hex", &persisted.app_hash_hex)?;
    validate_lifecycle(&persisted.validator_lifecycle)?;
    ensure!(
        persisted.validator_lifecycle.app_version == SOURCE_APP_VERSION,
        "source validator lifecycle app_version must be 3"
    );

    let mut objects = BTreeMap::new();
    for object in persisted.objects {
        validate_object(&object)?;
        ensure!(
            objects
                .insert(object.object_key_hex.clone(), object)
                .is_none(),
            "duplicate source object_key_hex"
        );
    }

    let mut command_ids = BTreeSet::new();
    for command_id in persisted.command_ids {
        validate_identifier("source command_id", &command_id, 256)?;
        ensure!(
            command_ids.insert(command_id),
            "duplicate source command_id"
        );
    }

    let mut signer_nonces = BTreeSet::new();
    for (signer_id, nonce) in persisted.signer_nonces {
        validate_identifier("source signer_id", &signer_id, 256)?;
        ensure!(
            signer_nonces.insert((signer_id, nonce)),
            "duplicate source signer nonce"
        );
    }

    let recomputed = compute_legacy_app_hash(
        &objects,
        &command_ids,
        &signer_nonces,
        &persisted.validator_lifecycle,
    )?;
    ensure!(
        recomputed == committed_app_hash,
        "source v3 application hash mismatch"
    );

    Ok(ValidatedV3State {
        height: persisted.height,
        app_hash_hex: persisted.app_hash_hex,
        objects,
        command_ids,
        signer_nonces,
        validator_lifecycle: persisted.validator_lifecycle,
    })
}

fn validate_object(object: &LegacyObject) -> Result<()> {
    let _ = decode_hash32("source object_key_hex", &object.object_key_hex)?;
    validate_identifier("source object_type", &object.object_type, 256)?;
    ensure!(object.version > 0, "source object version must be positive");
    let value_bytes =
        hex::decode(&object.value_hex).context("source object value_hex must be hex")?;
    ensure!(
        hex::encode(&value_bytes) == object.value_hex,
        "source object value_hex must use canonical lowercase hex"
    );
    let expected_value_hash =
        hex::encode(hash_domain("trnm.state.object.value.v1", &[&value_bytes]));
    ensure!(
        object.value_hash_hex == expected_value_hash,
        "source object value hash mismatch"
    );
    Ok(())
}

fn validate_lifecycle(lifecycle: &LegacyValidatorLifecycle) -> Result<()> {
    ensure!(
        lifecycle.schema == VALIDATOR_LIFECYCLE_SCHEMA_V1,
        "unsupported validator lifecycle schema"
    );
    validate_chain_id("source validator lifecycle chain_id", &lifecycle.chain_id)?;
    ensure!(
        lifecycle.app_version > 0,
        "source validator lifecycle app_version must be positive"
    );
    let _ = decode_hash32(
        "source authorized_signers_hash_hex",
        &lifecycle.authorized_signers_hash_hex,
    )?;
    validate_governance(&lifecycle.governance)?;

    let active = canonicalize_validators(lifecycle.active_validators.clone())?;
    ensure!(
        active == lifecycle.active_validators,
        "source active validator set is not canonical"
    );
    validate_active_set_for_governance(&lifecycle.governance, &active)?;

    if let Some(pending) = &lifecycle.pending_transition {
        validate_identifier(
            "source pending validator transition_id",
            &pending.transition_id,
            256,
        )?;
        let _ = decode_hash32(
            "source pending base_validator_set_hash_hex",
            &pending.base_validator_set_hash_hex,
        )?;
        ensure!(
            pending.accepted_height > 0
                && pending.activation_height
                    >= pending
                        .accepted_height
                        .saturating_add(lifecycle.governance.min_activation_delay_blocks),
            "source pending validator activation height violates governance delay"
        );
        let target = canonicalize_validators(pending.target_validators.clone())?;
        ensure!(
            target == pending.target_validators,
            "source pending target validator set is not canonical"
        );
        validate_transition_target(&target)?;
        ensure!(
            pending.base_validator_set_hash_hex == validator_set_hash_hex(&active)?,
            "source pending transition base validator set hash is stale"
        );
        validate_overlap(&active, &target)?;
    }
    Ok(())
}

fn validate_governance(governance: &LegacyValidatorGovernance) -> Result<()> {
    ensure!(
        governance.schema == VALIDATOR_GOVERNANCE_SCHEMA_V1,
        "unsupported validator governance schema"
    );
    validate_identifier(
        "source validator governance signer_id",
        &governance.signer_id,
        256,
    )?;
    ensure!(
        governance.min_activation_delay_blocks >= 2,
        "source validator activation delay must be at least two blocks"
    );
    Ok(())
}

fn canonicalize_validators(
    mut validators: Vec<LegacyConsensusValidator>,
) -> Result<Vec<LegacyConsensusValidator>> {
    validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut total = 0u64;
    for validator in &validators {
        let key = decode_hash32("source validator public key", &validator.public_key_hex)?;
        ensure!(
            keys.insert(validator.public_key_hex.clone()),
            "duplicate source validator public key"
        );
        ensure!(
            addresses.insert(comet_address(&key)),
            "duplicate source CometBFT validator address"
        );
        ensure!(
            validator.voting_power > 0,
            "source validator voting power must be positive"
        );
        ensure!(
            validator.voting_power <= MAX_TOTAL_VOTING_POWER,
            "source validator voting power exceeds CometBFT maximum"
        );
        total = total
            .checked_add(validator.voting_power)
            .context("source validator total voting power overflow")?;
        ensure!(
            total <= MAX_TOTAL_VOTING_POWER,
            "source validator total voting power exceeds CometBFT maximum"
        );
    }
    Ok(validators)
}

fn validate_active_set_for_governance(
    governance: &LegacyValidatorGovernance,
    validators: &[LegacyConsensusValidator],
) -> Result<()> {
    if governance.unsafe_allow_single_validator_genesis {
        ensure!(
            validators.len() == 1,
            "unsafe source genesis mode must contain exactly one validator"
        );
        return Ok(());
    }
    validate_transition_target(validators)
}

fn validate_transition_target(validators: &[LegacyConsensusValidator]) -> Result<()> {
    ensure!(
        validators.len() >= 4,
        "source validator set must contain at least four validators"
    );
    let total = validators
        .iter()
        .map(|validator| validator.voting_power as u128)
        .sum::<u128>();
    let max = validators
        .iter()
        .map(|validator| validator.voting_power as u128)
        .max()
        .unwrap_or(0);
    ensure!(
        max.saturating_mul(3) < total,
        "source validator set gives one validator quorum-blocking power"
    );
    Ok(())
}

fn validate_overlap(
    current: &[LegacyConsensusValidator],
    target: &[LegacyConsensusValidator],
) -> Result<()> {
    let current_by_key = current
        .iter()
        .map(|validator| (&validator.public_key_hex, validator.voting_power as u128))
        .collect::<BTreeMap<_, _>>();
    let target_by_key = target
        .iter()
        .map(|validator| (&validator.public_key_hex, validator.voting_power as u128))
        .collect::<BTreeMap<_, _>>();
    let current_total = current_by_key.values().copied().sum::<u128>();
    let target_total = target_by_key.values().copied().sum::<u128>();
    let retained_current = current_by_key
        .iter()
        .filter(|(key, _)| target_by_key.contains_key(*key))
        .map(|(_, power)| *power)
        .sum::<u128>();
    let retained_target = target_by_key
        .iter()
        .filter(|(key, _)| current_by_key.contains_key(*key))
        .map(|(_, power)| *power)
        .sum::<u128>();
    ensure!(
        retained_current.saturating_mul(3) > current_total.saturating_mul(2),
        "source validator transition retains at most two-thirds of current voting power"
    );
    ensure!(
        retained_target.saturating_mul(3) > target_total.saturating_mul(2),
        "source validator transition gives at least one-third of target power to new keys"
    );
    Ok(())
}

fn validator_set_hash_hex(validators: &[LegacyConsensusValidator]) -> Result<String> {
    let canonical = canonicalize_validators(validators.to_vec())?;
    Ok(hex::encode(hash_domain(
        "trnm.cometbft.validator-set.v1",
        &[&serde_json::to_vec(&canonical)?],
    )))
}

fn comet_address(public_key: &Hash32) -> Vec<u8> {
    Sha256::digest(public_key)[..20].to_vec()
}

fn compute_legacy_app_hash(
    objects: &BTreeMap<String, LegacyObject>,
    command_ids: &BTreeSet<String>,
    signer_nonces: &BTreeSet<(String, u64)>,
    lifecycle: &LegacyValidatorLifecycle,
) -> Result<Hash32> {
    let object_root = root_only(
        "trnm.state.objects.v1",
        objects.values().map(LegacyObject::leaf_hash),
    );
    let command_root = root_only(
        "trnm.state.command-ids.v1",
        command_ids
            .iter()
            .map(|command_id| hash_domain("trnm.state.command-id.v1", &[command_id.as_bytes()])),
    );
    let nonce_root = root_only(
        "trnm.state.signer-nonces.v1",
        signer_nonces.iter().map(|(signer_id, nonce)| {
            hash_domain(
                "trnm.state.signer-nonce.v1",
                &[signer_id.as_bytes(), &nonce.to_be_bytes()],
            )
        }),
    );
    let lifecycle_root = hash_domain(
        "trnm.cometbft.validator-lifecycle.v1",
        &[&serde_json::to_vec(lifecycle)?],
    );
    Ok(hash_domain(
        "trnm.cometbft.application.v3",
        &[&object_root, &command_root, &nonce_root, &lifecycle_root],
    ))
}

fn root_only<I>(tree_domain: &str, leaves: I) -> Hash32
where
    I: IntoIterator<Item = Hash32>,
{
    let mut current = leaves.into_iter().collect::<Vec<_>>();
    if current.is_empty() {
        return hash_domain("trnm.merkle.empty.v1", &[tree_domain.as_bytes()]);
    }
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(hash_domain(
                "trnm.merkle.parent.v1",
                &[tree_domain.as_bytes(), &left, &right],
            ));
        }
        current = next;
    }
    current[0]
}

fn hash_domain(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    put_len_prefixed(&mut hasher, domain.as_bytes());
    for part in parts {
        put_len_prefixed(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn put_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn decode_hash32(label: &str, value: &str) -> Result<Hash32> {
    let bytes = hex::decode(value).with_context(|| format!("{label} must be lowercase hex"))?;
    ensure!(bytes.len() == 32, "{label} must encode exactly 32 bytes");
    ensure!(
        hex::encode(&bytes) == value,
        "{label} must use canonical lowercase hex"
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn validate_chain_id(label: &str, value: &str) -> Result<()> {
    validate_identifier(label, value, 128)
}

fn validate_identifier(label: &str, value: &str, maximum_len: usize) -> Result<()> {
    ensure!(
        !value.is_empty() && value == value.trim() && value.len() <= maximum_len,
        "{label} is not canonical"
    );
    ensure!(
        !value.chars().any(char::is_control),
        "{label} contains control characters"
    );
    Ok(())
}

fn plain_sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn pretty_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_new_synced_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("create review artifact {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write review artifact {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync review artifact {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory for sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

fn usize_to_u64(value: usize, label: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{label} exceeds u64"))
}

fn review_readme(
    state: &ValidatedV3State,
    source_sha256_hex: &str,
    target_chain_id: &str,
) -> String {
    format!(
        "# TRNM v3 → v{TARGET_APP_VERSION} Export-New-Genesis Review Bundle\n\
\n\
Status: **REVIEW REQUIRED — NOT A MIGRATED NODE, DATABASE, SNAPSHOT, OR GENESIS**\n\
\n\
This bundle was produced from an offline, strictly validated v3 JSON state. The\n\
source file SHA-256 is `{source_sha256_hex}`, source height is `{}`, and the\n\
verified legacy AppHash is `{}`.\n\
\n\
The proposed target chain ID is `{target_chain_id}`, target application version\n\
is {TARGET_APP_VERSION}, and target genesis schema is `{TARGET_GENESIS_SCHEMA}`. The target chain ID\n\
intentionally differs from the source chain ID `{}`. No target AppHash has been\n\
calculated by this exporter.\n\
\n\
## Mandatory review before any target genesis\n\
\n\
1. Independently verify the source SHA-256, source height, and legacy AppHash.\n\
2. Review every object and the legacy replay indexes; do not silently discard replay protection.\n\
3. Supply and review the complete authorized-signer identities and public keys; v3 stores only their commitment.\n\
4. Supply and review the complete Nakama and Hepta Research authority sets; v3 stores neither.\n\
5. Review the active validators, governance policy, and any pending transition. Pending transitions are not carried automatically.\n\
6. Decide how chain-ID-bearing object values and economic state are transformed for the new chain.\n\
7. Construct a separate application-version-{TARGET_APP_VERSION} `{TARGET_GENESIS_SCHEMA}` genesis through a reviewed ceremony.\n\
8. Obtain the required human approvals/signatures and independently reproduce all artifact hashes.\n\
9. Start from fresh CometBFT and application data directories. Never reuse source chain data.\n\
\n\
`manifest.json` deliberately sets `direct_node_start_supported=false` and leaves\n\
the target AppHash null. Treat any tooling that bypasses those boundaries as unsafe.\n",
        state.height,
        state.app_hash_hex,
        state.validator_lifecycle.chain_id
    )
}

fn rollback_readme(state: &ValidatedV3State, target_chain_id: &str) -> String {
    format!(
        "# Rollback and Abort Procedure\n\
\n\
This exporter never mutates source state, source height, or source AppHash. Before\n\
the new genesis ceremony, rollback means quarantining or deleting this review\n\
bundle and continuing to preserve the source `{}` evidence unchanged.\n\
\n\
If a `{target_chain_id}` network has already been started, there is no in-place\n\
database rollback to application version 3. Stop the new network, preserve all\n\
evidence, and make an explicit governance/operations decision. Resume the source\n\
chain only from its independently verified original data and only if doing so is\n\
safe for clients; never copy target state into the v3 store or reuse validator signing\n\
state across the two chain IDs.\n",
        state.validator_lifecycle.chain_id
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "trnm-v3-export-new-genesis-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> LegacyV3State {
        let governance = LegacyValidatorGovernance {
            schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
            signer_id: "did:operator:fixture".to_string(),
            min_activation_delay_blocks: 2,
            unsafe_allow_single_validator_genesis: false,
        };
        let active_validators = (1u8..=4)
            .map(|seed| LegacyConsensusValidator {
                public_key_hex: hex::encode([seed; 32]),
                voting_power: 10,
            })
            .collect::<Vec<_>>();
        let lifecycle = LegacyValidatorLifecycle {
            schema: VALIDATOR_LIFECYCLE_SCHEMA_V1.to_string(),
            chain_id: "trnm-v3-fixture".to_string(),
            app_version: SOURCE_APP_VERSION,
            authorized_signers_hash_hex: hex::encode([7u8; 32]),
            governance,
            active_validators,
            pending_transition: None,
            last_applied_transition_id: None,
        };
        let value_bytes = br#"{"balance":"10"}"#;
        let object = LegacyObject {
            object_key_hex: hex::encode([9u8; 32]),
            object_type: "trnm_account_v1".to_string(),
            version: 1,
            value_hash_hex: hex::encode(hash_domain("trnm.state.object.value.v1", &[value_bytes])),
            value_hex: hex::encode(value_bytes),
        };
        let objects = BTreeMap::from([(object.object_key_hex.clone(), object.clone())]);
        let command_ids = BTreeSet::from(["command-1".to_string()]);
        let signer_nonces = BTreeSet::from([("did:operator:fixture".to_string(), 1)]);
        let app_hash =
            compute_legacy_app_hash(&objects, &command_ids, &signer_nonces, &lifecycle).unwrap();
        LegacyV3State {
            schema: SOURCE_SCHEMA_V3.to_string(),
            height: 17,
            app_hash_hex: hex::encode(app_hash),
            objects: vec![object],
            command_ids: command_ids.into_iter().collect(),
            signer_nonces: signer_nonces.into_iter().collect(),
            validator_lifecycle: lifecycle,
        }
    }

    fn write_source(path: &Path, fixture: &LegacyV3State) {
        fs::write(path, pretty_json_bytes(fixture).unwrap()).unwrap();
    }

    #[test]
    fn exports_atomic_review_only_bundle() {
        let root = TestRoot::new();
        let source = root.0.join("source-v3.json");
        let output = root.0.join("review-bundle");
        let fixture = fixture();
        write_source(&source, &fixture);
        let original = fs::read(&source).unwrap();

        let report = export_new_genesis(&source, "trnm-v5-new-chain", &output).unwrap();
        assert_eq!(report.source_height, 17);
        assert_eq!(fs::read(&source).unwrap(), original);
        for name in [
            "manifest.json",
            "canonical-objects.json",
            "legacy-replay-indexes.json",
            "validator-lifecycle.json",
            "README.md",
            "ROLLBACK.md",
        ] {
            assert!(output.join(name).is_file(), "missing {name}");
        }

        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["source"]["height"], 17);
        assert_eq!(manifest["source"]["app_version"], SOURCE_APP_VERSION);
        assert_eq!(manifest["source"]["app_hash_hex"], fixture.app_hash_hex);
        assert_eq!(manifest["schema"], "trnm_v3_export_new_genesis_manifest_v2");
        assert_eq!(manifest["target"]["chain_id"], "trnm-v5-new-chain");
        assert_eq!(manifest["target"]["genesis_schema"], GENESIS_SCHEMA_V3);
        assert_eq!(manifest["target"]["app_version"], APP_VERSION);
        assert!(manifest["target"]["app_hash_hex"].is_null());
        assert_eq!(manifest["direct_node_start_supported"], false);
        assert_eq!(manifest["requires_manual_review_and_signature"], true);
        assert_eq!(manifest["old_height_app_hash_mutated"], false);

        let lifecycle: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("validator-lifecycle.json")).unwrap())
                .unwrap();
        assert_eq!(
            lifecycle["schema"],
            "trnm_v3_export_validator_lifecycle_review_v2"
        );
        assert_eq!(lifecycle["source_app_version"], SOURCE_APP_VERSION);
        assert_eq!(lifecycle["target_app_version"], APP_VERSION);
        assert_eq!(
            lifecycle["proposed_target_genesis"]["schema"],
            GENESIS_SCHEMA_V3
        );
        assert_eq!(
            lifecycle["proposed_target_genesis"]
                ["research_authorities_must_be_supplied_and_reviewed"],
            true
        );

        let replay: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("legacy-replay-indexes.json")).unwrap())
                .unwrap();
        assert_eq!(replay["schema"], "trnm_v3_export_replay_indexes_v2");
        assert_eq!(replay["automatic_target_import_supported"], false);
    }

    #[test]
    fn rejects_same_chain_id_without_partial_bundle() {
        let root = TestRoot::new();
        let source = root.0.join("source-v3.json");
        let output = root.0.join("review-bundle");
        write_source(&source, &fixture());

        let error = export_new_genesis(&source, "trnm-v3-fixture", &output).unwrap_err();
        assert!(error.to_string().contains("must differ"));
        assert!(!output.exists());
    }

    #[test]
    fn preserves_strict_v3_source_boundary() {
        let root = TestRoot::new();
        let source = root.0.join("source-v3.json");
        let output = root.0.join("review-bundle");
        let mut state = fixture();
        state.validator_lifecycle.app_version = APP_VERSION;
        write_source(&source, &state);

        let error = export_new_genesis(&source, "trnm-v5-new-chain", &output).unwrap_err();
        assert!(error
            .to_string()
            .contains("source validator lifecycle app_version must be 3"));
        assert!(!output.exists());
    }

    #[test]
    fn rejects_tampered_object_value_hash_without_partial_bundle() {
        let root = TestRoot::new();
        let source = root.0.join("source-v3.json");
        let output = root.0.join("review-bundle");
        let mut state = fixture();
        state.objects[0].value_hash_hex = hex::encode([0u8; 32]);
        write_source(&source, &state);

        let error = export_new_genesis(&source, "trnm-v5-new-chain", &output).unwrap_err();
        assert!(error.to_string().contains("value hash mismatch"));
        assert!(!output.exists());
    }

    #[test]
    fn rejects_tampered_legacy_app_hash_without_partial_bundle() {
        let root = TestRoot::new();
        let source = root.0.join("source-v3.json");
        let output = root.0.join("review-bundle");
        let mut state = fixture();
        state.app_hash_hex = hex::encode([0u8; 32]);
        write_source(&source, &state);

        let error = export_new_genesis(&source, "trnm-v5-new-chain", &output).unwrap_err();
        assert!(error.to_string().contains("application hash mismatch"));
        assert!(!output.exists());
    }
}
