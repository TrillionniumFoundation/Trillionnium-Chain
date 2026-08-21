//! Public zero-Comet h1-h3 bootstrap material for the G3 laboratory chain.
//!
//! The author is a coordinator-only offline boundary. It admits one exact
//! canonical validator inventory, its strict PKCS#8 keys, the frozen reference
//! parameters, and the already verified public workload signer policy. It
//! emits only existing proposal-wire and CEV0 finality encodings plus a public
//! hash manifest; secret material is neither serialized nor retained.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_core::leader_for;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_finality_proof_v0_exact_with_trusted_genesis, ApplicationPayloadV0, Block, BlockHeader,
    BlockKind, CertifiedHeaderV0, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch,
    FinalityProofV0, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion, QcReferenceV0,
    QuorumCertificate, SignatureBytes, SignedProposalV0, Validator, ValidatorId, ValidatorSet,
    View, Vote, VotingPower,
};
use trnm_native_execution_v0::{
    derive_canonical_lab_genesis_hash_v0, CanonicalLabNativeChainGenesisInputsV0,
    CanonicalLabNativeEmptyBootstrapPrefixV0,
};

use crate::{
    config::load_pkcs8_ed25519_seed,
    wire::UnboundProposalV0,
    workload_corpus::{
        VerifiedWorkloadCorpusV1, WORKLOAD_BLOCK_TIME_STEP_MS_V1, WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
    },
};

const TEMPLATE_MAX_BYTES_V1: u64 = 2 * 1024 * 1024;
const BOOTSTRAP_SCHEMA_V1: &str = "trnm.poco.zero-comet-public-bootstrap.v1";
const VALIDATOR_SET_SCHEMA_VERSION_V1: u32 = 2;
const ORDINARY_START_HEIGHT_V1: u64 = 4;
const CONSENSUS_PARAMETERS_PROFILE_V1: &str = "reference-shadow-v0";
const LAB_CHAIN_ID_V1: &str = "trnm-poco-g3-lab-v0";
const PROPOSAL_PATHS_V1: [&str; 3] = [
    "public/bootstrap/h1.proposal",
    "public/bootstrap/h2.proposal",
    "public/bootstrap/h3.proposal",
];
const FINALITY_PATH_V1: &str = "public/bootstrap/finality-proof.cev0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidatorRecordV1 {
    validator_id: String,
    consensus_public_key: String,
    p2p_identity_public_key: String,
    operator_recovery_public_key: String,
    voting_power: u64,
    key_pop_signature: String,
    p2p_identity_key_pop_signature: String,
    operator_recovery_key_pop_signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidatorSetTemplateV1 {
    schema_version: u32,
    run_id: String,
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    consensus_parameters_profile: String,
    candidate_source_sha256: String,
    production_activation: bool,
    validators: Vec<ValidatorRecordV1>,
}

#[derive(Clone, Debug, Serialize)]
struct ValidatorSetDescriptorV1 {
    schema_version: u32,
    run_id: String,
    chain_id: String,
    genesis_hash: String,
    protocol_version: u32,
    epoch: u64,
    consensus_parameters_profile: String,
    candidate_source_sha256: String,
    production_activation: bool,
    validators: Vec<ValidatorRecordV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapFileRefV1 {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapBlockV1 {
    height: u64,
    view: u64,
    timestamp_ms: u64,
    parent_block_id: String,
    block_id: String,
    proposer_validator_id: String,
    payload_root: String,
    state_root: String,
    receipts_root: String,
    evidence_root: String,
    proposal: BootstrapFileRefV1,
    certifying_qc_id: String,
    qc_signer_validator_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicBootstrapBundleV1 {
    schema_version: u32,
    schema: String,
    chain_id: String,
    genesis_hash: String,
    protocol_version: u32,
    epoch: u64,
    validator_set_id: String,
    consensus_parameters_profile: String,
    consensus_parameters_hash: String,
    genesis_timestamp_ms: u64,
    ordinary_start_height: u64,
    chain_descriptor_hash: String,
    signer_policy_commitment: String,
    initial_block_id: String,
    initial_state_root: String,
    initial_commit_id: String,
    validator_count: usize,
    qc_signer_count: usize,
    all_validator_signers: bool,
    blocks: Vec<BootstrapBlockV1>,
    finality_proof: BootstrapFileRefV1,
    finality_proof_id: String,
    finalized_height: u64,
    private_key_material_emitted: bool,
    production_activation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BuiltPublicBootstrapSummaryV1 {
    pub schema_version: u32,
    pub status: &'static str,
    pub validator_set_sha256: String,
    pub genesis_hash: String,
    pub validator_set_id: String,
    pub bootstrap_sha256: String,
    pub finality_proof_sha256: String,
    pub finality_proof_id: String,
    pub ordinary_start_height: u64,
    pub validator_count: usize,
    pub qc_signer_count: usize,
    pub all_validator_signers: bool,
    pub consensus_private_key_retained: bool,
    pub consensus_private_key_emitted: bool,
    pub production_activation: bool,
}

struct AuthoredPublicBootstrapV1 {
    validator_set: ValidatorSet,
    validator_set_bytes: Vec<u8>,
    proposal_bytes: [Vec<u8>; 3],
    finality_proof_bytes: Vec<u8>,
    bootstrap_bytes: Vec<u8>,
    finality_proof_id: String,
    secret_patterns: Vec<Vec<u8>>,
}

/// One-way typed owner produced only after the complete deployed public
/// bootstrap has passed manifest, canonical-chain, signature, and finality
/// verification.  It is intentionally neither `Clone` nor `Copy`: the normal
/// validator can consume h1-h3 and the proof into Node commissioning exactly
/// once, while observer verification may explicitly discard the owner.
#[derive(Debug)]
pub struct VerifiedPublicZeroCometBootstrapV1 {
    proposals: [SignedProposalV0; 3],
    finality_proof: FinalityProofV0,
}

/// Public, deterministic projection of the exact h1/h2/h3 bootstrap facts
/// consumed by deployed ordinary commissioning. Store-local checksums are
/// intentionally absent; the remaining storage scalars are fixed by the
/// linear commissioning protocol and checked separately by the observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPublicBootstrapInitialCutV1 {
    pub high_qc_certificate_id: [u8; 32],
    pub high_qc_view: u64,
    pub high_qc_height: u64,
    pub high_qc_block_id: [u8; 32],
    pub finalized_height: u64,
    pub finalized_block_id: [u8; 32],
    pub application_height: u64,
    pub application_block_id: [u8; 32],
    pub proposal_parent_height: u64,
    pub proposal_parent_block_id: [u8; 32],
    pub application_state_root: [u8; 32],
}

impl VerifiedPublicZeroCometBootstrapV1 {
    pub(crate) fn into_node_parts_v1(self) -> ([SignedProposalV0; 3], FinalityProofV0) {
        (self.proposals, self.finality_proof)
    }

    pub fn finality_proof_id_v1(&self) -> String {
        hex::encode(self.finality_proof.id().as_bytes())
    }

    pub fn initial_ordinary_cut_v1(&self) -> VerifiedPublicBootstrapInitialCutV1 {
        let finalized = self.proposals[0].block().header();
        let parent = self.proposals[2].block().header();
        let high_qc = self.finality_proof.grandchild().certifying_qc();
        VerifiedPublicBootstrapInitialCutV1 {
            high_qc_certificate_id: *high_qc.id().as_bytes(),
            high_qc_view: high_qc.view().get(),
            high_qc_height: high_qc.height().get(),
            high_qc_block_id: *high_qc.block_id().as_bytes(),
            finalized_height: finalized.height().get(),
            finalized_block_id: *finalized.id().as_bytes(),
            application_height: finalized.height().get(),
            application_block_id: *finalized.id().as_bytes(),
            proposal_parent_height: parent.height().get(),
            proposal_parent_block_id: *parent.id().as_bytes(),
            application_state_root: *parent.state_root().as_bytes(),
        }
    }
}

/// Independently re-admits one deployed public bundle using the existing
/// proposal wire, trusted-genesis CEV0 finality decoder, frozen parameters,
/// and canonical native execution prefix.
pub fn verify_public_zero_comet_bootstrap_v1(
    run_root: impl AsRef<Path>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    workload: &VerifiedWorkloadCorpusV1,
) -> Result<VerifiedPublicZeroCometBootstrapV1> {
    let run_root = run_root
        .as_ref()
        .canonicalize()
        .context("canonicalize bootstrap run root")?;
    ensure!(
        run_root.is_dir(),
        "bootstrap run root is not one real directory"
    );
    let proposal_paths = [
        run_root.join("public/bootstrap/h1.proposal"),
        run_root.join("public/bootstrap/h2.proposal"),
        run_root.join("public/bootstrap/h3.proposal"),
    ];
    let proposal_bytes = proposal_paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            read_bounded_regular_file(path, 6 * 1024 * 1024, &format!("bootstrap h{}", index + 1))
        })
        .collect::<Result<Vec<_>>>()?;
    let finality_bytes = read_bounded_regular_file(
        &run_root.join("public/bootstrap/finality-proof.cev0"),
        64 * 1024 * 1024,
        "bootstrap finality proof",
    )?;
    let bootstrap_bytes = read_bounded_regular_file(
        &run_root.join("public/bootstrap/bootstrap.json"),
        2 * 1024 * 1024,
        "bootstrap public manifest",
    )?;
    let bundle: PublicBootstrapBundleV1 =
        serde_json::from_slice(&bootstrap_bytes).context("decode bootstrap public manifest")?;
    ensure!(
        canonical_json(&bundle)? == bootstrap_bytes,
        "bootstrap public manifest JSON is not canonical"
    );
    ensure!(
        bundle.schema_version == 1
            && bundle.schema == BOOTSTRAP_SCHEMA_V1
            && bundle.chain_id == validator_set.chain_id().as_str()
            && bundle.genesis_hash == hex::encode(validator_set.genesis_hash().as_bytes())
            && bundle.protocol_version == ProtocolVersion::V0.get()
            && bundle.epoch == 0
            && bundle.validator_set_id == hex::encode(validator_set.id().as_bytes())
            && bundle.consensus_parameters_profile == CONSENSUS_PARAMETERS_PROFILE_V1
            && bundle.consensus_parameters_hash == hex::encode(parameters.hash().as_bytes())
            && bundle.genesis_timestamp_ms == WORKLOAD_GENESIS_TIMESTAMP_MS_V1
            && bundle.ordinary_start_height == ORDINARY_START_HEIGHT_V1
            && bundle.validator_count == validator_set.validators().len()
            && bundle.qc_signer_count == validator_set.validators().len()
            && bundle.all_validator_signers
            && bundle.finalized_height == 1
            && !bundle.private_key_material_emitted
            && !bundle.production_activation,
        "bootstrap public manifest differs from its trusted chain context"
    );
    ensure!(
        bundle.blocks.len() == 3,
        "bootstrap public manifest does not contain exactly h1-h3"
    );
    let chain_inputs = CanonicalLabNativeChainGenesisInputsV0::new(
        validator_set.clone(),
        *parameters,
        workload.authorized_signers_v0()?,
        workload.header().governance_signer_id.clone(),
    )?;
    let mut prefix = CanonicalLabNativeEmptyBootstrapPrefixV0::new(chain_inputs)?;
    let chain_facts = prefix.chain_genesis_facts_v0();
    ensure!(
        bundle.chain_descriptor_hash == hex::encode(chain_facts.chain_descriptor_hash_v0())
            && bundle.signer_policy_commitment
                == hex::encode(chain_facts.signer_policy_commitment_v0())
            && bundle.initial_block_id == hex::encode(chain_facts.initial_block_id_v0())
            && bundle.initial_state_root == hex::encode(chain_facts.initial_state_root_v0())
            && bundle.initial_commit_id == hex::encode(chain_facts.initial_commit_id_v0()),
        "bootstrap chain facts differ from canonical native genesis"
    );

    let all_signers = validator_set
        .validators()
        .iter()
        .map(|validator| hex::encode(validator.id().as_bytes()))
        .collect::<Vec<_>>();
    let mut proposals = Vec::with_capacity(3);
    let mut parent_timestamp_ms = WORKLOAD_GENESIS_TIMESTAMP_MS_V1;
    for (index, bytes) in proposal_bytes.iter().enumerate() {
        let height = u64::try_from(index + 1).expect("h1-h3 index fits u64");
        verify_file_ref(
            &bundle.blocks[index].proposal,
            PROPOSAL_PATHS_V1[index],
            bytes,
        )?;
        let proposal = UnboundProposalV0::decode(bytes, validator_set, parameters)
            .map_err(|error| anyhow!("decode deployed bootstrap h{height}: {error}"))?
            .bind_authenticated_parent(validator_set, parameters, parent_timestamp_ms)
            .map_err(|error| anyhow!("bind deployed bootstrap h{height}: {error}"))?;
        let timestamp_ms = WORKLOAD_GENESIS_TIMESTAMP_MS_V1
            .checked_add(
                WORKLOAD_BLOCK_TIME_STEP_MS_V1
                    .checked_mul(height)
                    .context("bootstrap timestamp multiplication overflows")?,
            )
            .context("bootstrap timestamp overflows")?;
        let prepared = prefix.prepare_next_empty_block_v0(timestamp_ms)?;
        let facts = prepared.facts_v0();
        let header = proposal.block().header();
        ensure!(
            header.height() == Height::new(height)
                && header.view() == View::new(height)
                && header.timestamp_ms() == timestamp_ms
                && header.proposer_id() == leader_for(validator_set, View::new(height))
                && header.parent_id() == facts.parent_block_id_v0()
                && header.payload_root() == facts.payload_root_v0()
                && header.state_root() == facts.post_state_root_v0()
                && header.receipts_root() == facts.receipts_root_v0()
                && header.evidence_root() == facts.evidence_root_v0(),
            "deployed bootstrap h{height} differs from the canonical empty prefix"
        );
        let metadata = &bundle.blocks[index];
        ensure!(
            metadata.height == height
                && metadata.view == height
                && metadata.timestamp_ms == timestamp_ms
                && metadata.parent_block_id == hex::encode(header.parent_id().as_bytes())
                && metadata.block_id == hex::encode(proposal.block().id().as_bytes())
                && metadata.proposer_validator_id == hex::encode(header.proposer_id().as_bytes())
                && metadata.payload_root == hex::encode(header.payload_root().as_bytes())
                && metadata.state_root == hex::encode(header.state_root().as_bytes())
                && metadata.receipts_root == hex::encode(header.receipts_root().as_bytes())
                && metadata.evidence_root == hex::encode(header.evidence_root().as_bytes())
                && metadata.qc_signer_validator_ids == all_signers,
            "bootstrap block metadata differs from exact proposal wire"
        );
        prefix = prefix.commit_exact_block_v0(prepared, proposal.block())?;
        parent_timestamp_ms = timestamp_ms;
        proposals.push(proposal);
    }
    ensure!(
        prefix.is_complete_v0(),
        "deployed empty h1-h3 prefix is incomplete"
    );
    verify_file_ref(&bundle.finality_proof, FINALITY_PATH_V1, &finality_bytes)?;
    let proof = decode_finality_proof_v0_exact_with_trusted_genesis(
        &finality_bytes,
        validator_set,
        parameters,
        WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
    )
    .map_err(|error| anyhow!("decode deployed bootstrap finality proof: {error:?}"))?;
    proof
        .verify(
            validator_set,
            None,
            parameters,
            WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
            &StrictEd25519Verifier,
        )
        .map_err(|error| anyhow!("verify deployed bootstrap finality proof: {error:?}"))?;
    ensure!(
        bundle.finality_proof_id == hex::encode(proof.id().as_bytes()),
        "bootstrap finality proof ID differs from exact CEV0"
    );
    let certified = [proof.finalized_block(), proof.child(), proof.grandchild()];
    for (index, (certificate, proposal)) in certified.iter().zip(&proposals).enumerate() {
        ensure!(
            certificate.header() == proposal.block().header()
                && certificate.witness() == proposal.witness()
                && certificate.certifying_qc().votes().len() == validator_set.validators().len()
                && certificate
                    .certifying_qc()
                    .votes()
                    .iter()
                    .zip(validator_set.validators())
                    .all(|(vote, validator)| vote.author() == validator.id())
                && bundle.blocks[index].certifying_qc_id
                    == hex::encode(certificate.certifying_qc().id().as_bytes()),
            "bootstrap finality proof does not carry canonical all-signer q{}",
            index + 1
        );
        if let Some(child) = proposals.get(index + 1) {
            ensure!(
                child.witness().justify_qc().as_ordinary() == Some(certificate.certifying_qc()),
                "bootstrap proposal does not justify with the preceding all-signer QC"
            );
        }
    }
    let proposals: [SignedProposalV0; 3] = proposals
        .try_into()
        .map_err(|_| anyhow!("verified bootstrap proposal cardinality changed"))?;
    Ok(VerifiedPublicZeroCometBootstrapV1 {
        proposals,
        finality_proof: proof,
    })
}

fn verify_file_ref(reference: &BootstrapFileRefV1, path: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        reference.path == path
            && reference.sha256 == hex::encode(sha256(bytes))
            && reference.bytes
                == u64::try_from(bytes.len()).context("bootstrap file exceeds u64")?,
        "bootstrap file reference differs from exact public bytes"
    );
    Ok(())
}

/// Authors and writes one create-new, public, zero-Comet h1-h3 bootstrap
/// bundle. All input and output paths must be absolute. The bootstrap output
/// directory must not exist.
#[allow(clippy::too_many_arguments)]
pub fn build_public_zero_comet_bootstrap_v1(
    validator_set_template_path: impl AsRef<Path>,
    workload_corpus_path: impl AsRef<Path>,
    workload_corpus_sha256: [u8; 32],
    workload_policy_path: impl AsRef<Path>,
    workload_policy_sha256: [u8; 32],
    consensus_secret_directory: impl AsRef<Path>,
    validator_set_output_path: impl AsRef<Path>,
    bootstrap_output_directory: impl AsRef<Path>,
) -> Result<BuiltPublicBootstrapSummaryV1> {
    let validator_set_template_path = require_absolute_existing_file(
        validator_set_template_path.as_ref(),
        "validator-set author template",
    )?;
    let workload_corpus_path =
        require_absolute_existing_file(workload_corpus_path.as_ref(), "workload corpus")?;
    let workload_policy_path =
        require_absolute_existing_file(workload_policy_path.as_ref(), "workload policy")?;
    let consensus_secret_directory =
        require_private_secret_directory(consensus_secret_directory.as_ref())?;
    let validator_set_output_path =
        validate_new_output_file(validator_set_output_path.as_ref(), "validator set output")?;
    let bootstrap_output_directory = validate_new_output_directory(
        bootstrap_output_directory.as_ref(),
        "bootstrap output directory",
    )?;

    let template_bytes = read_bounded_regular_file(
        &validator_set_template_path,
        TEMPLATE_MAX_BYTES_V1,
        "validator-set author template",
    )?;
    let template: ValidatorSetTemplateV1 =
        serde_json::from_slice(&template_bytes).context("decode validator-set author template")?;
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    parameters
        .validate_reference_shadow_profile()
        .map_err(|error| anyhow!("reference consensus parameters changed: {error:?}"))?;
    let (validators, signing_keys, secret_patterns) =
        admit_template_and_keys(&template, &parameters, &consensus_secret_directory)?;
    let chain_id = ChainId::new(&template.chain_id)
        .map_err(|error| anyhow!("invalid lab chain ID: {error:?}"))?;
    let genesis_hash = derive_canonical_lab_genesis_hash_v0(chain_id, parameters, &validators)?;
    let validator_set = ValidatorSet::new(
        genesis_hash,
        chain_id,
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators,
    )
    .map_err(|error| anyhow!("construct canonical validator set: {error:?}"))?;
    validator_set
        .validate_against_parameters(&parameters)
        .map_err(|error| anyhow!("validate canonical validator set: {error:?}"))?;

    let consensus_public_keys = validator_set
        .validators()
        .iter()
        .map(|validator| validator.consensus_key().into_bytes())
        .collect::<Vec<_>>();
    let workload = VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
        &workload_corpus_path,
        &workload_policy_path,
        workload_corpus_sha256,
        workload_policy_sha256,
        validator_set.chain_id().as_str(),
        ORDINARY_START_HEIGHT_V1,
        &consensus_public_keys,
    )?;
    ensure!(
        workload.header().genesis_timestamp_ms == WORKLOAD_GENESIS_TIMESTAMP_MS_V1
            && workload.header().block_time_step_ms == WORKLOAD_BLOCK_TIME_STEP_MS_V1
            && workload.header().ordinary_start_height == ORDINARY_START_HEIGHT_V1,
        "workload policy differs from the fixed empty h1-h3 prefix schedule"
    );

    let validator_set_bytes = canonical_json(&ValidatorSetDescriptorV1 {
        schema_version: template.schema_version,
        run_id: template.run_id.clone(),
        chain_id: template.chain_id.clone(),
        genesis_hash: hex::encode(validator_set.genesis_hash().as_bytes()),
        protocol_version: template.protocol_version,
        epoch: template.epoch,
        consensus_parameters_profile: template.consensus_parameters_profile.clone(),
        candidate_source_sha256: template.candidate_source_sha256.clone(),
        production_activation: template.production_activation,
        validators: template.validators.clone(),
    })?;

    let authored = author_bootstrap(
        validator_set,
        parameters,
        signing_keys,
        workload.authorized_signers_v0()?,
        &workload.header().governance_signer_id,
        validator_set_bytes,
        secret_patterns,
    )?;
    reject_secret_material_in_public_outputs(&authored)?;

    fs::DirBuilder::new()
        .mode(0o700)
        .create(&bootstrap_output_directory)
        .context("create bootstrap output directory")?;
    write_new_synced(&validator_set_output_path, &authored.validator_set_bytes)?;
    for (name, bytes) in ["h1.proposal", "h2.proposal", "h3.proposal"]
        .into_iter()
        .zip(&authored.proposal_bytes)
    {
        write_new_synced(&bootstrap_output_directory.join(name), bytes)?;
    }
    write_new_synced(
        &bootstrap_output_directory.join("finality-proof.cev0"),
        &authored.finality_proof_bytes,
    )?;
    write_new_synced(
        &bootstrap_output_directory.join("bootstrap.json"),
        &authored.bootstrap_bytes,
    )?;
    sync_directory(
        validator_set_output_path
            .parent()
            .expect("validated output has a parent"),
    )?;
    sync_directory(&bootstrap_output_directory)?;

    Ok(BuiltPublicBootstrapSummaryV1 {
        schema_version: 1,
        status: "public-zero-comet-bootstrap-created",
        validator_set_sha256: hex::encode(sha256(&authored.validator_set_bytes)),
        genesis_hash: hex::encode(authored.validator_set.genesis_hash().as_bytes()),
        validator_set_id: hex::encode(authored.validator_set.id().as_bytes()),
        bootstrap_sha256: hex::encode(sha256(&authored.bootstrap_bytes)),
        finality_proof_sha256: hex::encode(sha256(&authored.finality_proof_bytes)),
        finality_proof_id: authored.finality_proof_id,
        ordinary_start_height: ORDINARY_START_HEIGHT_V1,
        validator_count: authored.validator_set.validators().len(),
        qc_signer_count: authored.validator_set.validators().len(),
        all_validator_signers: true,
        consensus_private_key_retained: false,
        consensus_private_key_emitted: false,
        production_activation: false,
    })
}

fn author_bootstrap(
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    signing_keys: BTreeMap<ValidatorId, SigningKey>,
    application_signers: Vec<trnm_native_execution_v0::AuthorizedSignerV0>,
    governance_signer_id: &str,
    validator_set_bytes: Vec<u8>,
    secret_patterns: Vec<Vec<u8>>,
) -> Result<AuthoredPublicBootstrapV1> {
    ensure!(
        signing_keys.len() == validator_set.validators().len()
            && validator_set
                .validators()
                .iter()
                .all(|validator| signing_keys.contains_key(&validator.id())),
        "consensus signing-key inventory is incomplete"
    );
    let chain_inputs = CanonicalLabNativeChainGenesisInputsV0::new(
        validator_set.clone(),
        parameters,
        application_signers,
        governance_signer_id,
    )?;
    let mut prefix = CanonicalLabNativeEmptyBootstrapPrefixV0::new(chain_inputs)?;
    let chain_facts = prefix.chain_genesis_facts_v0();
    let genesis_qc = GenesisQcV0::new(
        validator_set.genesis_hash(),
        validator_set.chain_id(),
        &validator_set,
    )
    .map_err(|error| anyhow!("construct trusted genesis QC: {error:?}"))?;
    let mut justification = QcReferenceV0::genesis_anchor(genesis_qc);
    let mut authenticated_parent_timestamp_ms = WORKLOAD_GENESIS_TIMESTAMP_MS_V1;
    let mut proposals = Vec::with_capacity(3);
    let mut certificates = Vec::with_capacity(3);
    let mut proposal_bytes = Vec::with_capacity(3);
    let mut block_metadata = Vec::with_capacity(3);
    let all_signer_ids = validator_set
        .validators()
        .iter()
        .map(|validator| hex::encode(validator.id().as_bytes()))
        .collect::<Vec<_>>();

    for height in 1..ORDINARY_START_HEIGHT_V1 {
        let timestamp_ms = WORKLOAD_GENESIS_TIMESTAMP_MS_V1
            .checked_add(
                WORKLOAD_BLOCK_TIME_STEP_MS_V1
                    .checked_mul(height)
                    .context("bootstrap timestamp multiplication overflows")?,
            )
            .context("bootstrap timestamp overflows")?;
        let prepared = prefix.prepare_next_empty_block_v0(timestamp_ms)?;
        let facts = prepared.facts_v0();
        let view = View::new(height);
        let proposer = leader_for(&validator_set, view);
        let header = BlockHeader::new(
            validator_set.genesis_hash(),
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            view,
            Height::new(height),
            BlockKind::Regular,
            facts.parent_block_id_v0(),
            proposer,
            validator_set.id(),
            parameters.hash(),
            facts.payload_root_v0(),
            facts.post_state_root_v0(),
            facts.receipts_root_v0(),
            facts.evidence_root_v0(),
            timestamp_ms,
            None,
        )
        .map_err(|error| anyhow!("construct bootstrap h{height} header: {error:?}"))?;
        let payload = ApplicationPayloadV0::new(Vec::new())
            .map_err(|error| anyhow!("construct empty bootstrap payload: {error:?}"))?
            .try_cev0_bytes()
            .map_err(|error| anyhow!("encode empty bootstrap payload: {error:?}"))?;
        let block = Block::new(header, payload, Vec::new())
            .map_err(|error| anyhow!("construct bootstrap h{height} block: {error:?}"))?;
        let proposal_root =
            ProposalWitnessV0::signing_root_for(block.header(), &justification, None, None)
                .map_err(|error| anyhow!("construct bootstrap proposal signing root: {error:?}"))?;
        let proposer_key = signing_keys
            .get(&proposer)
            .ok_or_else(|| anyhow!("scheduled proposer lacks a consensus secret"))?;
        let witness = ProposalWitnessV0::new(
            block.header(),
            justification,
            None,
            None,
            SignatureBytes::from_array(proposer_key.sign(proposal_root.as_bytes()).to_bytes()),
            &validator_set,
            None,
            &parameters,
            authenticated_parent_timestamp_ms,
        )
        .map_err(|error| anyhow!("construct bootstrap proposal witness: {error:?}"))?;
        let proposal = SignedProposalV0::new(
            block,
            witness,
            &validator_set,
            None,
            &parameters,
            authenticated_parent_timestamp_ms,
        )
        .map_err(|error| anyhow!("construct bootstrap signed proposal: {error:?}"))?;
        proposal
            .verify(
                &validator_set,
                None,
                &parameters,
                authenticated_parent_timestamp_ms,
                &StrictEd25519Verifier,
            )
            .map_err(|error| anyhow!("verify bootstrap proposal: {error:?}"))?;

        let wire_bytes = UnboundProposalV0::from_signed(&proposal)
            .map_err(|error| anyhow!("project bootstrap proposal to public wire: {error}"))?
            .encode()
            .map_err(|error| anyhow!("encode bootstrap proposal wire: {error}"))?;
        let rebound = UnboundProposalV0::decode(&wire_bytes, &validator_set, &parameters)
            .map_err(|error| anyhow!("decode bootstrap proposal wire: {error}"))?
            .bind_authenticated_parent(
                &validator_set,
                &parameters,
                authenticated_parent_timestamp_ms,
            )
            .map_err(|error| anyhow!("bind bootstrap proposal parent: {error}"))?;
        ensure!(
            rebound == proposal,
            "bootstrap proposal wire round-trip changed value"
        );

        prefix = prefix.commit_exact_block_v0(prepared, proposal.block())?;
        let vote_root = Vote::signing_root_for_set(
            &validator_set,
            view,
            Height::new(height),
            proposal.block().id(),
        )
        .map_err(|error| anyhow!("construct bootstrap vote signing root: {error:?}"))?;
        let votes = validator_set
            .validators()
            .iter()
            .map(|validator| {
                let key = signing_keys
                    .get(&validator.id())
                    .ok_or_else(|| anyhow!("QC signer lacks a consensus secret"))?;
                Vote::new(
                    validator_set.chain_id(),
                    validator_set.protocol_version(),
                    validator_set.epoch(),
                    view,
                    Height::new(height),
                    proposal.block().id(),
                    validator_set.id(),
                    validator.id(),
                    SignatureBytes::from_array(key.sign(vote_root.as_bytes()).to_bytes()),
                    &validator_set,
                )
                .map_err(|error| anyhow!("construct all-signer bootstrap vote: {error:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            votes.len() == validator_set.validators().len()
                && votes
                    .iter()
                    .zip(validator_set.validators())
                    .all(|(vote, validator)| vote.author() == validator.id()),
            "bootstrap QC signer order is not the complete canonical validator order"
        );
        let certificate = QuorumCertificate::new(
            validator_set.chain_id(),
            validator_set.protocol_version(),
            validator_set.epoch(),
            view,
            Height::new(height),
            proposal.block().id(),
            validator_set.id(),
            votes,
            &validator_set,
        )
        .map_err(|error| anyhow!("construct bootstrap q{height}: {error:?}"))?;
        certificate
            .verify(&validator_set, &StrictEd25519Verifier)
            .map_err(|error| anyhow!("verify bootstrap q{height}: {error:?}"))?;

        let proposal_ref = file_ref(PROPOSAL_PATHS_V1[(height - 1) as usize], &wire_bytes)?;
        let header = proposal.block().header();
        block_metadata.push(BootstrapBlockV1 {
            height,
            view: view.get(),
            timestamp_ms,
            parent_block_id: hex::encode(header.parent_id().as_bytes()),
            block_id: hex::encode(proposal.block().id().as_bytes()),
            proposer_validator_id: hex::encode(proposer.as_bytes()),
            payload_root: hex::encode(header.payload_root().as_bytes()),
            state_root: hex::encode(header.state_root().as_bytes()),
            receipts_root: hex::encode(header.receipts_root().as_bytes()),
            evidence_root: hex::encode(header.evidence_root().as_bytes()),
            proposal: proposal_ref,
            certifying_qc_id: hex::encode(certificate.id().as_bytes()),
            qc_signer_validator_ids: all_signer_ids.clone(),
        });
        authenticated_parent_timestamp_ms = timestamp_ms;
        justification = QcReferenceV0::ordinary(certificate.clone());
        proposal_bytes.push(wire_bytes);
        proposals.push(proposal);
        certificates.push(certificate);
    }
    ensure!(
        prefix.is_complete_v0(),
        "canonical empty h1-h3 prefix is incomplete"
    );

    let certified_h1 = CertifiedHeaderV0::from_signed_proposal(
        proposals[0].clone(),
        certificates[0].clone(),
        &validator_set,
        None,
        &parameters,
        WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
    )
    .map_err(|error| anyhow!("certify bootstrap h1: {error:?}"))?;
    let certified_h2 = CertifiedHeaderV0::from_signed_proposal(
        proposals[1].clone(),
        certificates[1].clone(),
        &validator_set,
        None,
        &parameters,
        proposals[0].block().header().timestamp_ms(),
    )
    .map_err(|error| anyhow!("certify bootstrap h2: {error:?}"))?;
    let certified_h3 = CertifiedHeaderV0::from_signed_proposal(
        proposals[2].clone(),
        certificates[2].clone(),
        &validator_set,
        None,
        &parameters,
        proposals[1].block().header().timestamp_ms(),
    )
    .map_err(|error| anyhow!("certify bootstrap h3: {error:?}"))?;
    let finality_proof = FinalityProofV0::new(
        certified_h1,
        certified_h2,
        certified_h3,
        &validator_set,
        None,
        &parameters,
        WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
    )
    .map_err(|error| anyhow!("construct bootstrap finality proof: {error:?}"))?;
    finality_proof
        .verify(
            &validator_set,
            None,
            &parameters,
            WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
            &StrictEd25519Verifier,
        )
        .map_err(|error| anyhow!("verify bootstrap finality proof: {error:?}"))?;
    let finality_proof_bytes = finality_proof
        .try_cev0_bytes()
        .map_err(|error| anyhow!("encode bootstrap finality proof: {error:?}"))?;
    let decoded_finality = decode_finality_proof_v0_exact_with_trusted_genesis(
        &finality_proof_bytes,
        &validator_set,
        &parameters,
        WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
    )
    .map_err(|error| anyhow!("decode exact bootstrap finality proof: {error:?}"))?;
    decoded_finality
        .verify(
            &validator_set,
            None,
            &parameters,
            WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
            &StrictEd25519Verifier,
        )
        .map_err(|error| anyhow!("verify decoded bootstrap finality proof: {error:?}"))?;
    ensure!(
        decoded_finality == finality_proof
            && decoded_finality
                .try_cev0_bytes()
                .map_err(|error| anyhow!("re-encode bootstrap finality proof: {error:?}"))?
                == finality_proof_bytes,
        "bootstrap finality proof exact round-trip changed value"
    );

    let finality_proof_id = hex::encode(finality_proof.id().as_bytes());
    let bundle = PublicBootstrapBundleV1 {
        schema_version: 1,
        schema: BOOTSTRAP_SCHEMA_V1.to_owned(),
        chain_id: validator_set.chain_id().as_str().to_owned(),
        genesis_hash: hex::encode(validator_set.genesis_hash().as_bytes()),
        protocol_version: validator_set.protocol_version().get(),
        epoch: validator_set.epoch().get(),
        validator_set_id: hex::encode(validator_set.id().as_bytes()),
        consensus_parameters_profile: CONSENSUS_PARAMETERS_PROFILE_V1.to_owned(),
        consensus_parameters_hash: hex::encode(parameters.hash().as_bytes()),
        genesis_timestamp_ms: WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
        ordinary_start_height: ORDINARY_START_HEIGHT_V1,
        chain_descriptor_hash: hex::encode(chain_facts.chain_descriptor_hash_v0()),
        signer_policy_commitment: hex::encode(chain_facts.signer_policy_commitment_v0()),
        initial_block_id: hex::encode(chain_facts.initial_block_id_v0()),
        initial_state_root: hex::encode(chain_facts.initial_state_root_v0()),
        initial_commit_id: hex::encode(chain_facts.initial_commit_id_v0()),
        validator_count: validator_set.validators().len(),
        qc_signer_count: validator_set.validators().len(),
        all_validator_signers: true,
        blocks: block_metadata,
        finality_proof: file_ref(FINALITY_PATH_V1, &finality_proof_bytes)?,
        finality_proof_id: finality_proof_id.clone(),
        finalized_height: 1,
        private_key_material_emitted: false,
        production_activation: false,
    };
    let bootstrap_bytes = canonical_json(&bundle)?;
    let proposal_bytes: [Vec<u8>; 3] = proposal_bytes
        .try_into()
        .map_err(|_| anyhow!("bootstrap proposal count differs from h1-h3"))?;
    Ok(AuthoredPublicBootstrapV1 {
        validator_set,
        validator_set_bytes,
        proposal_bytes,
        finality_proof_bytes,
        bootstrap_bytes,
        finality_proof_id,
        secret_patterns,
    })
}

type AdmittedTemplateAndKeysV1 = (
    Vec<Validator>,
    BTreeMap<ValidatorId, SigningKey>,
    Vec<Vec<u8>>,
);

fn admit_template_and_keys(
    template: &ValidatorSetTemplateV1,
    parameters: &ConsensusParametersV0,
    secret_directory: &Path,
) -> Result<AdmittedTemplateAndKeysV1> {
    ensure!(
        template.schema_version == VALIDATOR_SET_SCHEMA_VERSION_V1
            && template.chain_id == LAB_CHAIN_ID_V1
            && template.protocol_version == ProtocolVersion::V0.get()
            && template.epoch == 0
            && template.consensus_parameters_profile == CONSENSUS_PARAMETERS_PROFILE_V1
            && !template.production_activation,
        "validator-set author template differs from the frozen lab-only v0 contract"
    );
    let run_count = validate_run_id(&template.run_id)?;
    ensure!(
        matches!(template.validators.len(), 7 | 31 | 100) && template.validators.len() == run_count,
        "validator-set template cardinality differs from run ID"
    );
    decode_hex32(&template.candidate_source_sha256, "candidate_source_sha256")?;

    let expected_names = template
        .validators
        .iter()
        .map(|record| format!("{}.pk8", record.validator_id))
        .collect::<BTreeSet<_>>();
    let actual_names = fs::read_dir(secret_directory)
        .context("read consensus secret directory")?
        .map(|entry| {
            let entry = entry.context("read consensus secret directory entry")?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("consensus secret filename is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        actual_names == expected_names,
        "consensus secret inventory differs from the canonical validator inventory"
    );

    let mut previous_id = None;
    let mut role_keys = BTreeSet::new();
    let mut validators = Vec::with_capacity(template.validators.len());
    let mut signing_keys = BTreeMap::new();
    let mut secret_patterns = Vec::with_capacity(template.validators.len() * 2);
    for record in &template.validators {
        let id_bytes = decode_hex32(&record.validator_id, "validator_id")?;
        ensure!(
            previous_id.is_none_or(|previous: [u8; 32]| previous < id_bytes),
            "validator-set template is not in strict canonical ValidatorId order"
        );
        previous_id = Some(id_bytes);
        let public_key = decode_hex32(&record.consensus_public_key, "consensus_public_key")?;
        let p2p_identity_public_key =
            decode_hex32(&record.p2p_identity_public_key, "p2p_identity_public_key")?;
        let operator_recovery_public_key = decode_hex32(
            &record.operator_recovery_public_key,
            "operator_recovery_public_key",
        )?;
        for (role_key, signature, role) in [
            (
                public_key,
                record.key_pop_signature.as_str(),
                LabKeyRoleV1::Consensus,
            ),
            (
                p2p_identity_public_key,
                record.p2p_identity_key_pop_signature.as_str(),
                LabKeyRoleV1::P2pIdentity,
            ),
            (
                operator_recovery_public_key,
                record.operator_recovery_key_pop_signature.as_str(),
                LabKeyRoleV1::OperatorRecovery,
            ),
        ] {
            ensure!(
                role_keys.insert(role_key),
                "validator-set template reuses a public key across roles"
            );
            let verifying_key = VerifyingKey::from_bytes(&role_key)
                .map_err(|_| anyhow!("validator role public key is not Ed25519"))?;
            ensure!(
                !verifying_key.is_weak(),
                "validator role public key is weak"
            );
            let pop_bytes = decode_hex64(signature, "role_key_pop_signature")?;
            verifying_key
                .verify_strict(
                    &pop_challenge(&template.run_id, &record.validator_id, role),
                    &Signature::from_bytes(&pop_bytes),
                )
                .map_err(|_| anyhow!("validator role-key proof-of-possession is invalid"))?;
        }
        let validator_id = ValidatorId::new(id_bytes);
        let secret_path = secret_directory.join(format!("{}.pk8", record.validator_id));
        let secret_bytes = read_strict_secret(&secret_path)?;
        let signing_key = load_pkcs8_ed25519_seed(&secret_bytes)?;
        ensure!(
            signing_key.verifying_key().to_bytes() == public_key,
            "consensus secret differs from validator public key"
        );
        secret_patterns.push(secret_bytes);
        secret_patterns.push(signing_key.to_bytes().to_vec());
        ensure!(
            signing_keys.insert(validator_id, signing_key).is_none(),
            "duplicate consensus signing authority"
        );
        validators.push(
            Validator::new(
                validator_id,
                ConsensusPublicKey::new(public_key),
                VotingPower::new(record.voting_power)
                    .map_err(|error| anyhow!("invalid validator voting power: {error:?}"))?,
            )
            .map_err(|error| anyhow!("invalid validator record: {error:?}"))?,
        );
    }
    let provisional_genesis = derive_canonical_lab_genesis_hash_v0(
        ChainId::new(&template.chain_id)
            .map_err(|error| anyhow!("invalid lab chain ID: {error:?}"))?,
        *parameters,
        &validators,
    )?;
    let provisional = ValidatorSet::new(
        provisional_genesis,
        ChainId::new(&template.chain_id)
            .map_err(|error| anyhow!("invalid lab chain ID: {error:?}"))?,
        ProtocolVersion::V0,
        Epoch::new(0),
        parameters.hash(),
        validators.clone(),
    )
    .map_err(|error| anyhow!("validate template validator set: {error:?}"))?;
    provisional
        .validate_against_parameters(parameters)
        .map_err(|error| anyhow!("template validator set violates frozen parameters: {error:?}"))?;
    Ok((validators, signing_keys, secret_patterns))
}

fn reject_secret_material_in_public_outputs(authored: &AuthoredPublicBootstrapV1) -> Result<()> {
    let outputs = authored.proposal_bytes.iter().map(Vec::as_slice).chain([
        authored.validator_set_bytes.as_slice(),
        authored.finality_proof_bytes.as_slice(),
        authored.bootstrap_bytes.as_slice(),
    ]);
    for output in outputs {
        for secret in &authored.secret_patterns {
            ensure!(
                !secret.is_empty()
                    && !output
                        .windows(secret.len())
                        .any(|window| window == secret.as_slice()),
                "public bootstrap output contains consensus secret material"
            );
        }
    }
    Ok(())
}

fn file_ref(path: &str, bytes: &[u8]) -> Result<BootstrapFileRefV1> {
    Ok(BootstrapFileRefV1 {
        path: path.to_owned(),
        sha256: hex::encode(sha256(bytes)),
        bytes: u64::try_from(bytes.len()).context("bootstrap sidecar size exceeds u64")?,
    })
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Debug, Clone, Copy)]
enum LabKeyRoleV1 {
    Consensus,
    P2pIdentity,
    OperatorRecovery,
}

impl LabKeyRoleV1 {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Consensus => b"consensus",
            Self::P2pIdentity => b"p2p-identity",
            Self::OperatorRecovery => b"operator-recovery",
        }
    }
}

fn pop_challenge(run_id: &str, validator_id: &str, role: LabKeyRoleV1) -> Vec<u8> {
    let mut challenge = Vec::new();
    challenge.extend_from_slice(b"TRNM/PoCO/G3/EphemeralKeyRolePoP/v2\0");
    challenge.extend_from_slice(&(role.label().len() as u32).to_be_bytes());
    challenge.extend_from_slice(role.label());
    challenge.extend_from_slice(&(run_id.len() as u32).to_be_bytes());
    challenge.extend_from_slice(run_id.as_bytes());
    challenge.extend_from_slice(&(validator_id.len() as u32).to_be_bytes());
    challenge.extend_from_slice(validator_id.as_bytes());
    challenge
}

fn validate_run_id(value: &str) -> Result<usize> {
    let parts = value.split('-').collect::<Vec<_>>();
    ensure!(
        parts.len() == 5
            && parts[0] == "poco"
            && parts[1] == "g3"
            && matches!(parts[2], "7" | "31" | "100")
            && parts[3].len() == 16
            && parts[3].as_bytes()[8] == b'T'
            && parts[3].ends_with('Z')
            && parts[3]
                .bytes()
                .enumerate()
                .all(|(index, byte)| matches!(index, 8 | 15) || byte.is_ascii_digit())
            && parts[4].len() == 8
            && parts[4]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "run_id is not canonical"
    );
    parts[2].parse().context("parse run_id validator count")
}

fn decode_hex32(value: &str, label: &str) -> Result<[u8; 32]> {
    let decoded = decode_canonical_hex(value, 32, label)?;
    Ok(decoded
        .try_into()
        .expect("exact 32-byte hex length was checked"))
}

fn decode_hex64(value: &str, label: &str) -> Result<[u8; 64]> {
    let decoded = decode_canonical_hex(value, 64, label)?;
    Ok(decoded
        .try_into()
        .expect("exact 64-byte hex length was checked"))
}

fn decode_canonical_hex(value: &str, bytes: usize, label: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() == bytes * 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not canonical lowercase hex"
    );
    hex::decode(value).with_context(|| format!("decode {label}"))
}

fn require_absolute_existing_file(path: &Path, label: &str) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "{label} path must be absolute");
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("stat {label}"))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{label} is not one regular non-symlink file"
    );
    path.canonicalize()
        .with_context(|| format!("canonicalize {label}"))
}

fn require_private_secret_directory(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "consensus secret directory must be absolute"
    );
    let metadata = path
        .symlink_metadata()
        .context("stat consensus secret directory")?;
    ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0,
        "consensus secret directory must be one private real directory"
    );
    path.canonicalize()
        .context("canonicalize consensus secret directory")
}

fn read_bounded_regular_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {label}"))?;
    let metadata = file.metadata().with_context(|| format!("stat {label}"))?;
    ensure!(
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() > 0
            && metadata.len() <= maximum,
        "{label} is outside its bounded regular-file profile"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "{label} changed while being read"
    );
    Ok(bytes)
}

fn read_strict_secret(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open consensus secret {}", path.display()))?;
    let metadata = file.metadata().context("stat consensus secret")?;
    ensure!(
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.len() == 48,
        "consensus secret is not one private canonical PKCS#8 file"
    );
    let mut bytes = Vec::with_capacity(48);
    file.read_to_end(&mut bytes)
        .context("read consensus secret")?;
    ensure!(
        bytes.len() == 48,
        "consensus secret changed while being read"
    );
    Ok(bytes)
}

fn validate_new_output_file(path: &Path, label: &str) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "{label} must be absolute");
    ensure!(!path.exists(), "{label} already exists");
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{label} has no parent"))?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("canonicalize {label} parent"))?;
    let metadata = parent
        .metadata()
        .with_context(|| format!("stat {label} parent"))?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
        "{label} parent must be one private real directory"
    );
    Ok(parent.join(
        path.file_name()
            .ok_or_else(|| anyhow!("{label} has no filename"))?,
    ))
}

fn validate_new_output_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let output = validate_new_output_file(path, label)?;
    ensure!(!output.exists(), "{label} already exists");
    Ok(output)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("create public bootstrap file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write public bootstrap file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync public bootstrap file {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;

    use tempfile::TempDir;

    use super::*;

    const TEST_PKCS8_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    fn test_template(run_id: &str, source: u8, keys: &[SigningKey]) -> ValidatorSetTemplateV1 {
        ValidatorSetTemplateV1 {
            schema_version: 2,
            run_id: run_id.to_owned(),
            chain_id: LAB_CHAIN_ID_V1.to_owned(),
            protocol_version: 0,
            epoch: 0,
            consensus_parameters_profile: CONSENSUS_PARAMETERS_PROFILE_V1.to_owned(),
            candidate_source_sha256: hex::encode([source; 32]),
            production_activation: false,
            validators: keys
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    let validator_id = hex::encode([u8::try_from(index + 1).unwrap(); 32]);
                    let p2p_identity_key =
                        SigningKey::from_bytes(&[u8::try_from(index + 0x41).unwrap(); 32]);
                    let operator_recovery_key =
                        SigningKey::from_bytes(&[u8::try_from(index + 0x61).unwrap(); 32]);
                    ValidatorRecordV1 {
                        validator_id: validator_id.clone(),
                        consensus_public_key: hex::encode(key.verifying_key().to_bytes()),
                        p2p_identity_public_key: hex::encode(
                            p2p_identity_key.verifying_key().to_bytes(),
                        ),
                        operator_recovery_public_key: hex::encode(
                            operator_recovery_key.verifying_key().to_bytes(),
                        ),
                        voting_power: 1,
                        key_pop_signature: hex::encode(
                            key.sign(&pop_challenge(
                                run_id,
                                &validator_id,
                                LabKeyRoleV1::Consensus,
                            ))
                            .to_bytes(),
                        ),
                        p2p_identity_key_pop_signature: hex::encode(
                            p2p_identity_key
                                .sign(&pop_challenge(
                                    run_id,
                                    &validator_id,
                                    LabKeyRoleV1::P2pIdentity,
                                ))
                                .to_bytes(),
                        ),
                        operator_recovery_key_pop_signature: hex::encode(
                            operator_recovery_key
                                .sign(&pop_challenge(
                                    run_id,
                                    &validator_id,
                                    LabKeyRoleV1::OperatorRecovery,
                                ))
                                .to_bytes(),
                        ),
                    }
                })
                .collect(),
        }
    }

    fn write_test_template(path: &Path, template: &ValidatorSetTemplateV1) {
        fs::write(path, canonical_json(template).unwrap()).unwrap();
    }

    fn write_test_secrets(
        directory: &Path,
        template: &ValidatorSetTemplateV1,
        keys: &[SigningKey],
    ) {
        fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
        for (record, key) in template.validators.iter().zip(keys) {
            let path = directory.join(format!("{}.pk8", record.validator_id));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(&TEST_PKCS8_PREFIX).unwrap();
            file.write_all(&key.to_bytes()).unwrap();
            file.sync_all().unwrap();
        }
    }

    fn test_validator_set(template: &ValidatorSetTemplateV1, genesis_hash: &str) -> ValidatorSet {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = template
            .validators
            .iter()
            .map(|record| {
                Validator::new(
                    ValidatorId::new(decode_hex32(&record.validator_id, "test id").unwrap()),
                    ConsensusPublicKey::new(
                        decode_hex32(&record.consensus_public_key, "test key").unwrap(),
                    ),
                    VotingPower::new(record.voting_power).unwrap(),
                )
                .unwrap()
            })
            .collect();
        ValidatorSet::new(
            trnm_consensus_types::GenesisHash::new(
                decode_hex32(genesis_hash, "test genesis").unwrap(),
            ),
            ChainId::new(&template.chain_id).unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap()
    }

    #[test]
    fn public_bootstrap_schema_has_no_deployment_or_secret_fields_v1() {
        for forbidden in [
            "run_id",
            "coordinator",
            "topology",
            "candidate_source",
            "local_validator",
            "store_id",
            "secret_key",
        ] {
            assert!(!BOOTSTRAP_SCHEMA_V1.contains(forbidden));
        }
        assert_eq!(ORDINARY_START_HEIGHT_V1, 4);
        assert_eq!(PROPOSAL_PATHS_V1.len(), 3);
        assert_eq!(FINALITY_PATH_V1, "public/bootstrap/finality-proof.cev0");
    }

    #[test]
    fn public_h1_h3_bundle_is_exact_verifiable_and_deployment_invariant_v1() {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let keys = (0_u8..7)
            .map(|index| SigningKey::from_bytes(&[index + 31; 32]))
            .collect::<Vec<_>>();
        let template_a = test_template("poco-g3-7-20260814T000000Z-00000001", 0x11, &keys);
        let template_b = test_template("poco-g3-7-20260815T000000Z-00000002", 0x22, &keys);
        let template_a_path = temporary.path().join("template-a.json");
        let template_b_path = temporary.path().join("template-b.json");
        write_test_template(&template_a_path, &template_a);
        write_test_template(&template_b_path, &template_b);
        let secrets = temporary.path().join("secrets");
        write_test_secrets(&secrets, &template_a, &keys);

        let workload = temporary.path().join("workload");
        fs::DirBuilder::new().mode(0o700).create(&workload).unwrap();
        let corpus = workload.join("workload.corpus");
        let policy = workload.join("workload-policy.json");
        let workload_summary = crate::workload_corpus::build_public_workload_corpus_range_v1(
            LAB_CHAIN_ID_V1,
            ORDINARY_START_HEIGHT_V1,
            6,
            &corpus,
            &policy,
        )
        .unwrap();
        let corpus_hash = decode_hex32(&workload_summary.corpus_sha256, "test corpus").unwrap();
        let policy_hash = decode_hex32(&workload_summary.policy_sha256, "test policy").unwrap();

        let mut summaries = Vec::new();
        for (label, template_path) in [
            ("deployment-a", &template_a_path),
            ("deployment-b", &template_b_path),
        ] {
            let public = temporary.path().join(label);
            fs::DirBuilder::new().mode(0o700).create(&public).unwrap();
            let summary = build_public_zero_comet_bootstrap_v1(
                template_path,
                &corpus,
                corpus_hash,
                &policy,
                policy_hash,
                &secrets,
                public.join("validator-set.json"),
                public.join("bootstrap"),
            )
            .unwrap();
            summaries.push((public, summary));
        }
        assert_eq!(summaries[0].1.genesis_hash, summaries[1].1.genesis_hash);
        assert_eq!(
            summaries[0].1.validator_set_id,
            summaries[1].1.validator_set_id
        );
        assert_ne!(
            fs::read(summaries[0].0.join("validator-set.json")).unwrap(),
            fs::read(summaries[1].0.join("validator-set.json")).unwrap()
        );
        for name in [
            "h1.proposal",
            "h2.proposal",
            "h3.proposal",
            "finality-proof.cev0",
            "bootstrap.json",
        ] {
            assert_eq!(
                fs::read(summaries[0].0.join("bootstrap").join(name)).unwrap(),
                fs::read(summaries[1].0.join("bootstrap").join(name)).unwrap(),
                "deployment-only fields changed {name}"
            );
        }

        for (index, (public, summary)) in summaries.iter().enumerate() {
            let template = if index == 0 { &template_a } else { &template_b };
            let set = test_validator_set(template, &summary.genesis_hash);
            let consensus_keys = set
                .validators()
                .iter()
                .map(|validator| validator.consensus_key().into_bytes())
                .collect::<Vec<_>>();
            let verified_workload = VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
                &corpus,
                &policy,
                corpus_hash,
                policy_hash,
                LAB_CHAIN_ID_V1,
                ORDINARY_START_HEIGHT_V1,
                &consensus_keys,
            )
            .unwrap();
            let verifier_root = temporary.path().join(format!("verifier-root-{index}"));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&verifier_root)
                .unwrap();
            fs::create_dir(verifier_root.join("public")).unwrap();
            fs::rename(
                public.join("bootstrap"),
                verifier_root.join("public/bootstrap"),
            )
            .unwrap();
            verify_public_zero_comet_bootstrap_v1(
                &verifier_root,
                &set,
                &ConsensusParametersV0::reference_shadow_v0(),
                &verified_workload,
            )
            .unwrap();
        }
    }
}
