//! Public, pre-signed deterministic non-empty workload for the real LAN lab.
//!
//! The builder creates two independent ephemeral application signing keys in
//! memory.  Every admitted height has exactly two ordered envelopes: an
//! operator credit followed by a client task creation which consumes that
//! credit through the same block overlay. A one-based corpus ordinal supplies
//! the application nonce (the first ordinary block therefore uses nonce 1),
//! while `ordinary_start_height` maps that ordinal to the exact chain height.
//! Only the public corpus and signer policy are persisted. Consensus validators
//! therefore never receive application private-key authority, and a scheduled
//! leader can only select the complete already-signed workload for that exact
//! ordinal/height pair.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_consensus_types::ConsensusParametersV0;
use trnm_finality_types::{hash_domain, SignedCommandEnvelopeV1};
use trnm_native_execution_v0::{
    execute_authenticated_block_candidate_v0, AuthorizedSignerV0, InMemoryNativeExecutionStoreV0,
    NativeExecutionRequestV0,
};
use trnm_protocol::{
    CanonicalCommandV1, CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1, CANONICAL_TX_SCHEMA_V1,
};

pub const WORKLOAD_CORPUS_SCHEMA_V1: &str = "trnm_poco_g3_workload_corpus_v1";
pub const WORKLOAD_POLICY_SCHEMA_V1: &str = "trnm_poco_g3_workload_policy_v1";
pub const WORKLOAD_OPERATOR_ID_V1: &str = "did:trnm:g3:workload-operator";
pub const WORKLOAD_OPERATOR_ROLE_V1: &str = "operator";
pub const WORKLOAD_CLIENT_ID_V1: &str = "did:trnm:g3:workload-client";
pub const WORKLOAD_CLIENT_ROLE_V1: &str = "hepta";
pub const WORKLOAD_GENESIS_TIMESTAMP_MS_V1: u64 = 0;
pub const WORKLOAD_BLOCK_TIME_STEP_MS_V1: u64 = 1_000;
pub const WORKLOAD_VALIDITY_WIDTH_MS_V1: u64 = 1;
pub const WORKLOAD_MAX_GAS_V1: u64 = 100_000;
pub const WORKLOAD_FEE_LIMIT_V1: u128 = 1_000_000;
pub const WORKLOAD_CREDIT_AMOUNT_V1: u128 = 1_000_000;
pub const WORKLOAD_TASK_REWARD_V1: u128 = 1;
pub const WORKLOAD_TASK_WORKER_STAKE_V1: u128 = 1;
pub const WORKLOAD_TASK_DEADLINE_LEAD_V1: u64 = 1_000;
pub const WORKLOAD_TASK_CHALLENGE_WINDOW_V1: u64 = 10;
pub const MAX_WORKLOAD_HEIGHT_V1: u64 = 131_072;
pub const MAX_EXECUTION_PREFLIGHT_HEIGHT_V1: u64 = 1_024;

const CORPUS_MAGIC_V1: &[u8] = b"trnm-poco-g3-workload-corpus-v1\n";
const CORPUS_FOOTER_V1: &[u8] = b"trnm-poco-g3-workload-corpus-end-v1\n";
const ENTRY_CHAIN_DOMAIN_V1: &str = "trnm.poco-g3.workload-entry-chain.v1";
const MAX_CORPUS_BYTES_V1: u64 = 64 * 1024 * 1024;
const MAX_POLICY_BYTES_V1: u64 = 64 * 1024;
const MAX_HEADER_BYTES_V1: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSignerV1 {
    pub signer_id: String,
    pub signer_role: String,
    pub public_key_hex: String,
}

impl WorkloadSignerV1 {
    fn authorized_signer_v0(&self) -> Result<AuthorizedSignerV0> {
        AuthorizedSignerV0::new(
            self.signer_id.clone(),
            self.signer_role.clone(),
            self.public_key_hex.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCorpusHeaderV1 {
    pub schema_version: u32,
    pub schema: String,
    pub chain_id: String,
    pub ordinary_start_height: u64,
    pub max_height: u64,
    pub ordinary_entry_count: u64,
    pub genesis_timestamp_ms: u64,
    pub block_time_step_ms: u64,
    pub validity_width_ms: u64,
    pub operator: WorkloadSignerV1,
    pub client: WorkloadSignerV1,
    pub governance_signer_id: String,
    #[serde(with = "u128_decimal")]
    pub credit_amount: u128,
    #[serde(with = "u128_decimal")]
    pub task_reward: u128,
    #[serde(with = "u128_decimal")]
    pub task_worker_stake: u128,
    pub task_deadline_lead: u64,
    pub task_challenge_window: u64,
    pub max_gas: u64,
    #[serde(with = "u128_decimal")]
    pub fee_limit: u128,
}

impl WorkloadCorpusHeaderV1 {
    fn new(
        chain_id: &str,
        ordinary_start_height: u64,
        max_height: u64,
        operator_public_key_hex: String,
        client_public_key_hex: String,
    ) -> Result<Self> {
        let ordinary_entry_count = max_height
            .checked_sub(ordinary_start_height)
            .and_then(|distance| distance.checked_add(1))
            .context("workload ordinary height range is empty or overflows")?;
        Ok(Self {
            schema_version: 1,
            schema: WORKLOAD_CORPUS_SCHEMA_V1.to_string(),
            chain_id: chain_id.to_string(),
            ordinary_start_height,
            max_height,
            ordinary_entry_count,
            genesis_timestamp_ms: WORKLOAD_GENESIS_TIMESTAMP_MS_V1,
            block_time_step_ms: WORKLOAD_BLOCK_TIME_STEP_MS_V1,
            validity_width_ms: WORKLOAD_VALIDITY_WIDTH_MS_V1,
            operator: WorkloadSignerV1 {
                signer_id: WORKLOAD_OPERATOR_ID_V1.to_string(),
                signer_role: WORKLOAD_OPERATOR_ROLE_V1.to_string(),
                public_key_hex: operator_public_key_hex,
            },
            client: WorkloadSignerV1 {
                signer_id: WORKLOAD_CLIENT_ID_V1.to_string(),
                signer_role: WORKLOAD_CLIENT_ROLE_V1.to_string(),
                public_key_hex: client_public_key_hex,
            },
            governance_signer_id: WORKLOAD_OPERATOR_ID_V1.to_string(),
            credit_amount: WORKLOAD_CREDIT_AMOUNT_V1,
            task_reward: WORKLOAD_TASK_REWARD_V1,
            task_worker_stake: WORKLOAD_TASK_WORKER_STAKE_V1,
            task_deadline_lead: WORKLOAD_TASK_DEADLINE_LEAD_V1,
            task_challenge_window: WORKLOAD_TASK_CHALLENGE_WINDOW_V1,
            max_gas: WORKLOAD_MAX_GAS_V1,
            fee_limit: WORKLOAD_FEE_LIMIT_V1,
        })
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported workload header version"
        );
        ensure!(
            self.schema == WORKLOAD_CORPUS_SCHEMA_V1,
            "unsupported workload corpus schema"
        );
        ensure!(
            !self.chain_id.is_empty() && self.chain_id.len() <= 128,
            "workload chain_id is outside the bounded shape"
        );
        ensure!(
            self.ordinary_start_height > 0
                && self.ordinary_start_height <= self.max_height
                && self.max_height <= MAX_WORKLOAD_HEIGHT_V1,
            "workload ordinary height range is outside the bounded campaign range"
        );
        ensure!(
            self.ordinary_entry_count
                == self
                    .max_height
                    .checked_sub(self.ordinary_start_height)
                    .and_then(|distance| distance.checked_add(1))
                    .context("workload ordinary height range overflows")?,
            "workload ordinary entry count differs from its height range"
        );
        ensure!(
            self.genesis_timestamp_ms == WORKLOAD_GENESIS_TIMESTAMP_MS_V1
                && self.block_time_step_ms == WORKLOAD_BLOCK_TIME_STEP_MS_V1
                && self.validity_width_ms == WORKLOAD_VALIDITY_WIDTH_MS_V1,
            "workload timestamp schedule differs from the frozen campaign schedule"
        );
        ensure!(
            self.operator.signer_id == WORKLOAD_OPERATOR_ID_V1
                && self.operator.signer_role == WORKLOAD_OPERATOR_ROLE_V1
                && self.client.signer_id == WORKLOAD_CLIENT_ID_V1
                && self.client.signer_role == WORKLOAD_CLIENT_ROLE_V1
                && self.governance_signer_id == WORKLOAD_OPERATOR_ID_V1,
            "workload signer policy differs from the least-authority profile"
        );
        ensure!(
            self.credit_amount == WORKLOAD_CREDIT_AMOUNT_V1
                && self.task_reward == WORKLOAD_TASK_REWARD_V1
                && self.task_worker_stake == WORKLOAD_TASK_WORKER_STAKE_V1
                && self.task_deadline_lead == WORKLOAD_TASK_DEADLINE_LEAD_V1
                && self.task_challenge_window == WORKLOAD_TASK_CHALLENGE_WINDOW_V1
                && self.max_gas == WORKLOAD_MAX_GAS_V1
                && self.fee_limit == WORKLOAD_FEE_LIMIT_V1,
            "workload command profile differs from the deterministic campaign profile"
        );
        let operator = self.operator.authorized_signer_v0()?;
        let client = self.client.authorized_signer_v0()?;
        ensure!(
            operator.signer_id() != client.signer_id()
                && operator.public_key_hex() != client.public_key_hex(),
            "workload application signer identities overlap"
        );
        ensure!(
            self.canonical_timestamp_ms(self.max_height).is_some(),
            "workload timestamp schedule overflows"
        );
        Ok(())
    }

    pub fn canonical_timestamp_ms(&self, height: u64) -> Option<u64> {
        self.ordinal_for_height(height)?;
        self.block_time_step_ms
            .checked_mul(height)
            .and_then(|offset| self.genesis_timestamp_ms.checked_add(offset))
    }

    /// Maps the one-based on-disk corpus ordinal to its exact chain height.
    pub fn height_for_ordinal(&self, ordinal: u64) -> Option<u64> {
        if ordinal == 0 || ordinal > self.ordinary_entry_count {
            return None;
        }
        self.ordinary_start_height.checked_add(ordinal - 1)
    }

    /// Maps one admitted chain height back to its one-based corpus ordinal.
    pub fn ordinal_for_height(&self, height: u64) -> Option<u64> {
        if height < self.ordinary_start_height || height > self.max_height {
            return None;
        }
        height
            .checked_sub(self.ordinary_start_height)
            .and_then(|distance| distance.checked_add(1))
    }

    fn execution_preflight_height(&self) -> Option<u64> {
        self.ordinary_start_height
            .checked_add(MAX_EXECUTION_PREFLIGHT_HEIGHT_V1 - 1)
            .map(|bounded_end| bounded_end.min(self.max_height))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadPolicyV1 {
    pub schema_version: u32,
    pub schema: String,
    pub corpus_sha256: String,
    pub entry_chain_root: String,
    pub header: WorkloadCorpusHeaderV1,
    pub execution_preflight_height: u64,
    pub application_private_key_retained: bool,
    pub application_private_key_deployed: bool,
    pub production_activation: bool,
}

impl WorkloadPolicyV1 {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported workload policy version"
        );
        ensure!(
            self.schema == WORKLOAD_POLICY_SCHEMA_V1,
            "unsupported workload policy schema"
        );
        self.header.validate()?;
        let _ = decode_hash32(&self.corpus_sha256, "policy.corpus_sha256")?;
        let _ = decode_hash32(&self.entry_chain_root, "policy.entry_chain_root")?;
        ensure!(
            Some(self.execution_preflight_height) == self.header.execution_preflight_height(),
            "workload execution preflight height differs from the bounded policy"
        );
        ensure!(
            !self.application_private_key_retained
                && !self.application_private_key_deployed
                && !self.production_activation,
            "workload policy attempts to retain authority or activate production"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct EntryIndexV1 {
    ordinal: u64,
    height: u64,
    timestamp_ms: u64,
    signature_offsets: [u64; 2],
    block_root: [u8; 32],
}

struct ScannedCorpusV1 {
    header: WorkloadCorpusHeaderV1,
    entries: Vec<EntryIndexV1>,
    entry_chain_root: [u8; 32],
    corpus_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadBlockV1 {
    pub ordinal: u64,
    pub height: u64,
    pub timestamp_ms: u64,
    pub transactions: [Vec<u8>; 2],
}

/// Fully scanned, manifest-bindable public corpus with O(1) height lookup.
///
/// Only offsets and immutable expected hashes are retained in memory.  The
/// potentially large corpus remains on disk, which keeps 31/100-validator lab
/// profiles from multiplying a 100k-block corpus into unbounded resident RAM.
pub struct VerifiedWorkloadCorpusV1 {
    corpus_path: PathBuf,
    file: File,
    header: WorkloadCorpusHeaderV1,
    policy: WorkloadPolicyV1,
    entries: Vec<EntryIndexV1>,
}

impl std::fmt::Debug for VerifiedWorkloadCorpusV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedWorkloadCorpusV1")
            .field("corpus_path", &self.corpus_path)
            .field("chain_id", &self.header.chain_id)
            .field("ordinary_start_height", &self.header.ordinary_start_height)
            .field("max_height", &self.header.max_height)
            .field("ordinary_entry_count", &self.header.ordinary_entry_count)
            .field(
                "operator_public_key_hex",
                &self.header.operator.public_key_hex,
            )
            .field("client_public_key_hex", &self.header.client.public_key_hex)
            .finish_non_exhaustive()
    }
}

impl VerifiedWorkloadCorpusV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn load_for_ordinary_start_height(
        corpus_path: impl AsRef<Path>,
        policy_path: impl AsRef<Path>,
        expected_corpus_sha256: [u8; 32],
        expected_policy_sha256: [u8; 32],
        expected_chain_id: &str,
        expected_ordinary_start_height: u64,
        consensus_public_keys: &[[u8; 32]],
    ) -> Result<Self> {
        let policy_bytes = read_bounded_regular_file(
            policy_path.as_ref(),
            MAX_POLICY_BYTES_V1,
            "workload policy",
        )?;
        ensure!(
            sha256(&policy_bytes) == expected_policy_sha256,
            "workload policy hash differs from the committed config"
        );
        let policy: WorkloadPolicyV1 =
            serde_json::from_slice(&policy_bytes).context("decode workload policy JSON")?;
        ensure!(
            serde_json::to_vec(&policy)? == policy_bytes,
            "workload policy JSON is not canonical"
        );
        policy.validate()?;
        ensure!(
            policy.header.chain_id == expected_chain_id,
            "workload policy chain_id differs from consensus"
        );
        ensure!(
            policy.header.ordinary_start_height == expected_ordinary_start_height,
            "workload ordinary_start_height differs from the committed config"
        );
        for signer in [&policy.header.operator, &policy.header.client] {
            let application_key =
                decode_hash32(&signer.public_key_hex, "workload application public key")?;
            ensure!(
                !consensus_public_keys.contains(&application_key),
                "workload application key overlaps a consensus key"
            );
        }
        ensure!(
            decode_hash32(&policy.corpus_sha256, "policy.corpus_sha256")? == expected_corpus_sha256,
            "workload policy corpus hash differs from the committed config"
        );

        let corpus_path = corpus_path.as_ref().to_path_buf();
        let mut file = open_regular_readonly(&corpus_path, "workload corpus")?;
        let length = file.metadata().context("stat workload corpus")?.len();
        ensure!(
            length > (CORPUS_MAGIC_V1.len() + CORPUS_FOOTER_V1.len()) as u64
                && length <= MAX_CORPUS_BYTES_V1,
            "workload corpus size is outside the bounded range"
        );
        let scanned = scan_corpus(&mut file, length)?;
        ensure!(
            scanned.corpus_sha256 == expected_corpus_sha256,
            "workload corpus hash differs from the committed config"
        );
        ensure!(
            scanned.header == policy.header,
            "workload corpus/policy header mismatch"
        );
        ensure!(
            hex::encode(scanned.entry_chain_root) == policy.entry_chain_root,
            "workload entry-chain root differs from policy"
        );
        Ok(Self {
            corpus_path,
            file,
            header: scanned.header,
            policy,
            entries: scanned.entries,
        })
    }

    /// Fresh-genesis compatibility for the existing in-crate continuous
    /// runtime harness only. Production loaders must commit and pass the
    /// ordinary start height explicitly through
    /// `load_for_ordinary_start_height`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        corpus_path: impl AsRef<Path>,
        policy_path: impl AsRef<Path>,
        expected_corpus_sha256: [u8; 32],
        expected_policy_sha256: [u8; 32],
        expected_chain_id: &str,
        consensus_public_keys: &[[u8; 32]],
    ) -> Result<Self> {
        Self::load_for_ordinary_start_height(
            corpus_path,
            policy_path,
            expected_corpus_sha256,
            expected_policy_sha256,
            expected_chain_id,
            1,
            consensus_public_keys,
        )
    }

    pub const fn header(&self) -> &WorkloadCorpusHeaderV1 {
        &self.header
    }

    pub const fn policy(&self) -> &WorkloadPolicyV1 {
        &self.policy
    }

    pub fn authorized_signers_v0(&self) -> Result<Vec<AuthorizedSignerV0>> {
        Ok(vec![
            self.header.operator.authorized_signer_v0()?,
            self.header.client.authorized_signer_v0()?,
        ])
    }

    pub fn block_at_height(&mut self, height: u64) -> Result<WorkloadBlockV1> {
        let ordinal = self
            .header
            .ordinal_for_height(height)
            .context("workload height is outside the ordinary corpus range")?;
        let index = self.entries[(ordinal - 1) as usize];
        ensure!(
            index.ordinal == ordinal && index.height == height,
            "workload ordinal/height index changed after admission"
        );
        let mut transactions = [Vec::new(), Vec::new()];
        for (position, signature_offset) in index.signature_offsets.iter().enumerate() {
            self.file
                .seek(SeekFrom::Start(*signature_offset))
                .context("seek workload entry")?;
            let mut signature = [0u8; 64];
            self.file
                .read_exact(&mut signature)
                .context("read workload entry")?;
            let bytes = envelope_from_signature(&self.header, height, position, signature)?;
            validate_envelope(&self.header, height, position, &bytes)?;
            transactions[position] = bytes;
        }
        let envelope_hashes = [sha256(&transactions[0]), sha256(&transactions[1])];
        ensure!(
            workload_block_root(ordinal, height, index.timestamp_ms, envelope_hashes)
                == index.block_root,
            "workload entry changed after corpus admission"
        );
        Ok(WorkloadBlockV1 {
            ordinal,
            height,
            timestamp_ms: index.timestamp_ms,
            transactions,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BuiltWorkloadCorpusSummaryV1 {
    pub schema_version: u32,
    pub status: &'static str,
    pub corpus_sha256: String,
    pub policy_sha256: String,
    pub entry_chain_root: String,
    pub operator_public_key_hex: String,
    pub client_public_key_hex: String,
    pub ordinary_start_height: u64,
    pub max_height: u64,
    pub ordinary_entry_count: u64,
    pub execution_preflight_height: u64,
    pub application_private_key_retained: bool,
    pub application_private_key_deployed: bool,
    pub production_activation: bool,
}

/// Builds one explicitly bounded ordinary-height corpus with fresh
/// in-memory-only keys and atomically durable, create-new public outputs. The
/// secret seeds are never returned or written.
pub fn build_public_workload_corpus_range_v1(
    chain_id: &str,
    ordinary_start_height: u64,
    max_height: u64,
    corpus_output: impl AsRef<Path>,
    policy_output: impl AsRef<Path>,
) -> Result<BuiltWorkloadCorpusSummaryV1> {
    ensure!(
        ordinary_start_height > 0
            && ordinary_start_height <= max_height
            && max_height <= MAX_WORKLOAD_HEIGHT_V1,
        "workload ordinary height range is outside the bounded campaign range"
    );
    let ordinary_entry_count = max_height
        .checked_sub(ordinary_start_height)
        .and_then(|distance| distance.checked_add(1))
        .context("workload ordinary height range overflows")?;
    let execution_preflight_height = ordinary_start_height
        .checked_add(MAX_EXECUTION_PREFLIGHT_HEIGHT_V1 - 1)
        .context("workload execution preflight range overflows")?
        .min(max_height);
    let execution_preflight_count = execution_preflight_height
        .checked_sub(ordinary_start_height)
        .and_then(|distance| distance.checked_add(1))
        .context("workload execution preflight range is empty or overflows")?;
    let operator_key = generate_strong_signing_key()?;
    let client_key = generate_strong_signing_key()?;
    ensure!(
        operator_key.verifying_key() != client_key.verifying_key(),
        "ephemeral application keys unexpectedly overlap"
    );
    let header = WorkloadCorpusHeaderV1::new(
        chain_id,
        ordinary_start_height,
        max_height,
        hex::encode(operator_key.verifying_key().to_bytes()),
        hex::encode(client_key.verifying_key().to_bytes()),
    )?;
    header.validate()?;
    let corpus_output = validate_new_output_path(corpus_output.as_ref(), "corpus output")?;
    let policy_output = validate_new_output_path(policy_output.as_ref(), "policy output")?;
    ensure!(
        corpus_output != policy_output,
        "workload output paths alias"
    );

    let mut corpus = create_new_private_file(&corpus_output, "workload corpus")?;
    let header_bytes = serde_json::to_vec(&header)?;
    ensure!(
        header_bytes.len() <= MAX_HEADER_BYTES_V1,
        "workload header exceeds bound"
    );
    corpus.write_all(CORPUS_MAGIC_V1)?;
    corpus.write_all(&1u32.to_be_bytes())?;
    corpus.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    corpus.write_all(&header_bytes)?;
    corpus.write_all(&ordinary_entry_count.to_be_bytes())?;
    let mut entry_chain_root = [0u8; 32];
    let mut preflight_blocks = Vec::with_capacity(execution_preflight_count as usize);
    for (zero_based_ordinal, height) in (ordinary_start_height..=max_height).enumerate() {
        let ordinal = u64::try_from(zero_based_ordinal)
            .context("workload corpus ordinal exceeds u64")?
            .checked_add(1)
            .context("workload corpus ordinal overflows")?;
        let block = signed_block_at_height(&header, ordinal, height, &operator_key, &client_key)?;
        corpus.write_all(&height.to_be_bytes())?;
        corpus.write_all(&block.timestamp_ms.to_be_bytes())?;
        let mut envelope_hashes = [[0u8; 32]; 2];
        for (position, envelope) in block.transactions.iter().enumerate() {
            let parsed: SignedCommandEnvelopeV1 = serde_json::from_slice(envelope)?;
            let signature = decode_signature64(&parsed.signature_hex)?;
            let envelope_sha256 = sha256(envelope);
            corpus.write_all(&signature)?;
            envelope_hashes[position] = envelope_sha256;
        }
        let block_root = workload_block_root(ordinal, height, block.timestamp_ms, envelope_hashes);
        corpus.write_all(&block_root)?;
        entry_chain_root = next_entry_chain_root(
            entry_chain_root,
            ordinal,
            height,
            block.timestamp_ms,
            block_root,
        );
        if height <= execution_preflight_height {
            preflight_blocks.push(block);
        }
    }
    verify_execution_prefix(&header, &preflight_blocks)?;
    corpus.write_all(&entry_chain_root)?;
    corpus.write_all(CORPUS_FOOTER_V1)?;
    corpus.sync_all().context("sync workload corpus")?;
    sync_parent(&corpus_output)?;
    drop(corpus);
    let corpus_sha256 = sha256_file_bounded(&corpus_output, MAX_CORPUS_BYTES_V1)?;

    let policy = WorkloadPolicyV1 {
        schema_version: 1,
        schema: WORKLOAD_POLICY_SCHEMA_V1.to_string(),
        corpus_sha256: hex::encode(corpus_sha256),
        entry_chain_root: hex::encode(entry_chain_root),
        header,
        execution_preflight_height,
        application_private_key_retained: false,
        application_private_key_deployed: false,
        production_activation: false,
    };
    policy.validate()?;
    let policy_bytes = serde_json::to_vec(&policy)?;
    let mut policy_file = create_new_private_file(&policy_output, "workload policy")?;
    policy_file.write_all(&policy_bytes)?;
    policy_file.sync_all().context("sync workload policy")?;
    sync_parent(&policy_output)?;
    let policy_sha256 = sha256(&policy_bytes);

    Ok(BuiltWorkloadCorpusSummaryV1 {
        schema_version: 1,
        status: "public-pre-signed-workload-corpus-created",
        corpus_sha256: hex::encode(corpus_sha256),
        policy_sha256: hex::encode(policy_sha256),
        entry_chain_root: hex::encode(entry_chain_root),
        operator_public_key_hex: policy.header.operator.public_key_hex,
        client_public_key_hex: policy.header.client.public_key_hex,
        ordinary_start_height,
        max_height,
        ordinary_entry_count,
        execution_preflight_height,
        application_private_key_retained: false,
        application_private_key_deployed: false,
        production_activation: false,
    })
}

/// Fresh-genesis compatibility for the existing in-crate continuous-runtime
/// harness. Real run material must use `build_public_workload_corpus_range_v1`
/// and commit its ordinary start height explicitly.
#[cfg(test)]
pub fn build_public_workload_corpus_v1(
    chain_id: &str,
    max_height: u64,
    corpus_output: impl AsRef<Path>,
    policy_output: impl AsRef<Path>,
) -> Result<BuiltWorkloadCorpusSummaryV1> {
    build_public_workload_corpus_range_v1(chain_id, 1, max_height, corpus_output, policy_output)
}

fn signed_block_at_height(
    header: &WorkloadCorpusHeaderV1,
    ordinal: u64,
    height: u64,
    operator_key: &SigningKey,
    client_key: &SigningKey,
) -> Result<WorkloadBlockV1> {
    let timestamp_ms = header
        .canonical_timestamp_ms(height)
        .context("workload timestamp is outside the canonical schedule")?;
    let operator_tx = CanonicalTxV1 {
        schema: CANONICAL_TX_SCHEMA_V1.to_string(),
        sender: header.operator.signer_id.clone(),
        nonce: ordinal,
        max_gas: header.max_gas,
        fee_limit: header.fee_limit,
        command: CanonicalCommandV1::CreditAccount {
            account: header.client.signer_id.clone(),
            amount: header.credit_amount,
        },
    };
    let client_tx = CanonicalTxV1 {
        schema: CANONICAL_TX_SCHEMA_V1.to_string(),
        sender: header.client.signer_id.clone(),
        nonce: ordinal,
        max_gas: header.max_gas,
        fee_limit: header.fee_limit,
        command: CanonicalCommandV1::CreateTask {
            task_id: task_id(height),
            reward: header.task_reward,
            worker_stake: header.task_worker_stake,
            result_deadline_height: height
                .checked_add(header.task_deadline_lead)
                .context("workload task deadline overflows")?,
            challenge_window_blocks: header.task_challenge_window,
        },
    };
    let operator = sign_transaction(
        header,
        ordinal,
        height,
        timestamp_ms,
        0,
        &operator_tx,
        operator_key,
    )?;
    let client = sign_transaction(
        header,
        ordinal,
        height,
        timestamp_ms,
        1,
        &client_tx,
        client_key,
    )?;
    let block = WorkloadBlockV1 {
        ordinal,
        height,
        timestamp_ms,
        transactions: [operator, client],
    };
    for (position, envelope) in block.transactions.iter().enumerate() {
        validate_envelope(header, height, position, envelope)?;
    }
    Ok(block)
}

fn sign_transaction(
    header: &WorkloadCorpusHeaderV1,
    ordinal: u64,
    height: u64,
    timestamp_ms: u64,
    position: usize,
    transaction: &CanonicalTxV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    ensure!(
        header.ordinal_for_height(height) == Some(ordinal) && transaction.nonce == ordinal,
        "workload signing ordinal differs from its exact chain height"
    );
    transaction.validate()?;
    let payload = serde_json::to_vec(transaction)?;
    let signer = if position == 0 {
        &header.operator
    } else {
        &header.client
    };
    let envelope = SignedCommandEnvelopeV1::sign(
        header.chain_id.clone(),
        command_id(height, position)?,
        signer.signer_id.clone(),
        signer.signer_role.clone(),
        ordinal,
        timestamp_ms,
        timestamp_ms
            .checked_add(header.validity_width_ms)
            .context("workload validity window overflows")?,
        CANONICAL_TX_PAYLOAD_TYPE_V1,
        &payload,
        signing_key,
    )?;
    Ok(serde_json::to_vec(&envelope)?)
}

fn envelope_from_signature(
    header: &WorkloadCorpusHeaderV1,
    height: u64,
    position: usize,
    signature: [u8; 64],
) -> Result<Vec<u8>> {
    let ordinal = header
        .ordinal_for_height(height)
        .context("workload height has no corpus ordinal")?;
    let timestamp_ms = header
        .canonical_timestamp_ms(height)
        .context("workload timestamp is outside the canonical schedule")?;
    let signer = match position {
        0 => &header.operator,
        1 => &header.client,
        _ => bail!("workload envelope position is outside the block"),
    };
    let transaction = expected_transaction(header, height, position)?;
    let payload = serde_json::to_vec(&transaction)?;
    let envelope = SignedCommandEnvelopeV1 {
        schema: trnm_finality_types::SIGNED_COMMAND_SCHEMA_V1.to_string(),
        chain_id: header.chain_id.clone(),
        command_id: command_id(height, position)?,
        signer_id: signer.signer_id.clone(),
        signer_role: signer.signer_role.clone(),
        public_key_hex: signer.public_key_hex.clone(),
        nonce: ordinal,
        issued_at_unix_ms: timestamp_ms,
        expires_at_unix_ms: timestamp_ms
            .checked_add(header.validity_width_ms)
            .context("workload validity window overflows")?,
        payload_type: CANONICAL_TX_PAYLOAD_TYPE_V1.to_string(),
        payload_hex: hex::encode(&payload),
        payload_hash_hex: hex::encode(hash_domain("trnm.command.payload.v1", &[&payload])),
        signature_hex: hex::encode(signature),
    };
    envelope.validate_at_strict(&header.chain_id, timestamp_ms)?;
    Ok(serde_json::to_vec(&envelope)?)
}

fn expected_transaction(
    header: &WorkloadCorpusHeaderV1,
    height: u64,
    position: usize,
) -> Result<CanonicalTxV1> {
    let ordinal = header
        .ordinal_for_height(height)
        .context("workload height has no corpus ordinal")?;
    let (sender, command) = match position {
        0 => (
            header.operator.signer_id.clone(),
            CanonicalCommandV1::CreditAccount {
                account: header.client.signer_id.clone(),
                amount: header.credit_amount,
            },
        ),
        1 => (
            header.client.signer_id.clone(),
            CanonicalCommandV1::CreateTask {
                task_id: task_id(height),
                reward: header.task_reward,
                worker_stake: header.task_worker_stake,
                result_deadline_height: height
                    .checked_add(header.task_deadline_lead)
                    .context("workload task deadline overflows")?,
                challenge_window_blocks: header.task_challenge_window,
            },
        ),
        _ => bail!("workload envelope position is outside the block"),
    };
    let transaction = CanonicalTxV1 {
        schema: CANONICAL_TX_SCHEMA_V1.to_string(),
        sender,
        nonce: ordinal,
        max_gas: header.max_gas,
        fee_limit: header.fee_limit,
        command,
    };
    transaction.validate()?;
    Ok(transaction)
}

fn validate_envelope(
    header: &WorkloadCorpusHeaderV1,
    height: u64,
    position: usize,
    bytes: &[u8],
) -> Result<()> {
    ensure!(
        position < 2,
        "workload envelope position is outside the block"
    );
    let envelope: SignedCommandEnvelopeV1 =
        serde_json::from_slice(bytes).context("decode workload envelope")?;
    ensure!(
        serde_json::to_vec(&envelope)? == bytes,
        "workload envelope JSON is not canonical"
    );
    let timestamp_ms = header
        .canonical_timestamp_ms(height)
        .context("workload timestamp is outside the canonical schedule")?;
    let ordinal = header
        .ordinal_for_height(height)
        .context("workload height has no corpus ordinal")?;
    envelope.validate_at_strict(&header.chain_id, timestamp_ms)?;
    let signer = if position == 0 {
        &header.operator
    } else {
        &header.client
    };
    ensure!(
        envelope.command_id == command_id(height, position)?
            && envelope.signer_id == signer.signer_id
            && envelope.signer_role == signer.signer_role
            && envelope.public_key_hex == signer.public_key_hex
            && envelope.nonce == ordinal
            && envelope.issued_at_unix_ms == timestamp_ms
            && envelope.expires_at_unix_ms
                == timestamp_ms
                    .checked_add(header.validity_width_ms)
                    .context("workload validity window overflows")?
            && envelope.payload_type == CANONICAL_TX_PAYLOAD_TYPE_V1,
        "workload envelope differs from its exact height policy"
    );
    let payload = envelope.payload_bytes()?;
    let transaction: CanonicalTxV1 =
        serde_json::from_slice(&payload).context("decode workload transaction")?;
    ensure!(
        serde_json::to_vec(&transaction)? == payload,
        "workload transaction JSON is not canonical"
    );
    transaction.validate()?;
    let expected_command = if position == 0 {
        CanonicalCommandV1::CreditAccount {
            account: header.client.signer_id.clone(),
            amount: header.credit_amount,
        }
    } else {
        CanonicalCommandV1::CreateTask {
            task_id: task_id(height),
            reward: header.task_reward,
            worker_stake: header.task_worker_stake,
            result_deadline_height: height
                .checked_add(header.task_deadline_lead)
                .context("workload task deadline overflows")?,
            challenge_window_blocks: header.task_challenge_window,
        }
    };
    ensure!(
        transaction.schema == CANONICAL_TX_SCHEMA_V1
            && transaction.sender == signer.signer_id
            && transaction.nonce == ordinal
            && transaction.max_gas == header.max_gas
            && transaction.fee_limit == header.fee_limit
            && transaction.command == expected_command,
        "workload transaction differs from its exact height policy"
    );
    Ok(())
}

fn command_id(height: u64, position: usize) -> Result<String> {
    match position {
        0 => Ok(format!("g3-credit-{height:020}")),
        1 => Ok(format!("g3-task-{height:020}")),
        _ => bail!("workload envelope position is outside the block"),
    }
}

fn task_id(height: u64) -> String {
    format!("g3-task-{height:020}")
}

fn decode_signature64(value: &str) -> Result<[u8; 64]> {
    let bytes = hex::decode(value).context("decode workload signature")?;
    ensure!(
        bytes.len() == 64 && hex::encode(&bytes) == value,
        "workload signature must be canonical lowercase 64-byte hex"
    );
    Ok(bytes.try_into().expect("signature length checked"))
}

fn scan_corpus(file: &mut File, expected_length: u64) -> Result<ScannedCorpusV1> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = HashingReader::new(file);
    let mut magic = vec![0; CORPUS_MAGIC_V1.len()];
    reader.read_exact(&mut magic)?;
    ensure!(magic == CORPUS_MAGIC_V1, "invalid workload corpus magic");
    ensure!(
        reader.read_u32()? == 1,
        "unsupported workload corpus version"
    );
    let header_len = reader.read_u32()? as usize;
    ensure!(
        header_len > 0 && header_len <= MAX_HEADER_BYTES_V1,
        "workload corpus header length is outside the bound"
    );
    let mut header_bytes = vec![0; header_len];
    reader.read_exact(&mut header_bytes)?;
    let header: WorkloadCorpusHeaderV1 =
        serde_json::from_slice(&header_bytes).context("decode workload corpus header")?;
    ensure!(
        serde_json::to_vec(&header)? == header_bytes,
        "workload corpus header JSON is not canonical"
    );
    header.validate()?;
    let entry_count = reader.read_u64()?;
    ensure!(
        entry_count == header.ordinary_entry_count,
        "workload corpus entry count differs from header"
    );
    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut entry_chain_root = [0u8; 32];
    for ordinal in 1..=entry_count {
        let expected_height = header
            .height_for_ordinal(ordinal)
            .context("workload corpus ordinal is outside the header range")?;
        ensure!(
            reader.read_u64()? == expected_height,
            "workload corpus ordinal-to-height mapping is not exact and contiguous"
        );
        let timestamp_ms = reader.read_u64()?;
        ensure!(
            header.canonical_timestamp_ms(expected_height) == Some(timestamp_ms),
            "workload corpus timestamp differs from the canonical schedule"
        );
        let mut signature_offsets = [0u64; 2];
        let mut envelope_hashes = [[0u8; 32]; 2];
        for position in 0..2 {
            signature_offsets[position] = reader.position();
            let mut signature = [0u8; 64];
            reader.read_exact(&mut signature)?;
            let envelope = envelope_from_signature(&header, expected_height, position, signature)?;
            let envelope_sha256 = sha256(&envelope);
            validate_envelope(&header, expected_height, position, &envelope)?;
            envelope_hashes[position] = envelope_sha256;
        }
        let block_root =
            workload_block_root(ordinal, expected_height, timestamp_ms, envelope_hashes);
        ensure!(
            reader.read_hash32()? == block_root,
            "workload block root mismatch"
        );
        entry_chain_root = next_entry_chain_root(
            entry_chain_root,
            ordinal,
            expected_height,
            timestamp_ms,
            block_root,
        );
        entries.push(EntryIndexV1 {
            ordinal,
            height: expected_height,
            timestamp_ms,
            signature_offsets,
            block_root,
        });
    }
    ensure!(
        reader.read_hash32()? == entry_chain_root,
        "workload corpus entry-chain root mismatch"
    );
    let mut footer = vec![0; CORPUS_FOOTER_V1.len()];
    reader.read_exact(&mut footer)?;
    ensure!(footer == CORPUS_FOOTER_V1, "invalid workload corpus footer");
    ensure!(
        reader.position() == expected_length,
        "workload corpus has trailing or truncated bytes"
    );
    let corpus_sha256 = reader.finish();
    Ok(ScannedCorpusV1 {
        header,
        entries,
        entry_chain_root,
        corpus_sha256,
    })
}

struct HashingReader<'a> {
    file: &'a mut File,
    hasher: Sha256,
    position: u64,
}

impl<'a> HashingReader<'a> {
    fn new(file: &'a mut File) -> Self {
        Self {
            file,
            hasher: Sha256::new(),
            position: 0,
        }
    }

    const fn position(&self) -> u64 {
        self.position
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_hash32(&mut self) -> Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Read for HashingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.file.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.position = self
            .position
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("workload corpus position overflow"))?;
        Ok(read)
    }
}

fn workload_block_root(
    ordinal: u64,
    height: u64,
    timestamp_ms: u64,
    envelope_hashes: [[u8; 32]; 2],
) -> [u8; 32] {
    hash_domain(
        "trnm.poco-g3.workload-block.v1",
        &[
            &ordinal.to_be_bytes(),
            &height.to_be_bytes(),
            &timestamp_ms.to_be_bytes(),
            &envelope_hashes[0],
            &envelope_hashes[1],
        ],
    )
}

fn next_entry_chain_root(
    previous: [u8; 32],
    ordinal: u64,
    height: u64,
    timestamp_ms: u64,
    block_root: [u8; 32],
) -> [u8; 32] {
    hash_domain(
        ENTRY_CHAIN_DOMAIN_V1,
        &[
            &previous,
            &ordinal.to_be_bytes(),
            &height.to_be_bytes(),
            &timestamp_ms.to_be_bytes(),
            &block_root,
        ],
    )
}

fn verify_execution_prefix(
    header: &WorkloadCorpusHeaderV1,
    blocks: &[WorkloadBlockV1],
) -> Result<()> {
    ensure!(
        Some(blocks.len() as u64)
            == header
                .execution_preflight_height()
                .and_then(|height| height.checked_sub(header.ordinary_start_height))
                .and_then(|distance| distance.checked_add(1)),
        "workload execution prefix has wrong cardinality"
    );
    let signers = vec![
        header.operator.authorized_signer_v0()?,
        header.client.authorized_signer_v0()?,
    ];
    let mut store = InMemoryNativeExecutionStoreV0::new(
        header.chain_id.clone(),
        signers,
        ConsensusParametersV0::reference_shadow_v0(),
    )?;
    // The public workload preflight models only the empty application-state
    // predecessor supplied by the separate bootstrap/takeover contract. The
    // in-memory JMT still requires every version to be created contiguously;
    // this does not assert that a real bootstrap runtime exists.
    for version in 0..header.ordinary_start_height {
        store.apply_seed_v0(version, Vec::new())?;
    }
    for block in blocks {
        let request = NativeExecutionRequestV0::new_empty_evidence(
            block.height - 1,
            block.height,
            block.timestamp_ms,
            block.transactions.to_vec(),
        )?;
        let candidate = execute_authenticated_block_candidate_v0(&store, request)?;
        ensure!(
            candidate.executed_transactions().len() == 2,
            "workload execution did not execute both transactions"
        );
        store.apply_runtime_object_delta_plan_v0(candidate.into_runtime_object_delta_plan())?;
        store.mark_committed_command_v0(
            command_id(block.height, 0)?,
            header.operator.signer_id.clone(),
            block.ordinal,
        )?;
        store.mark_committed_command_v0(
            command_id(block.height, 1)?,
            header.client.signer_id.clone(),
            block.ordinal,
        )?;
    }
    Ok(())
}

fn generate_strong_signing_key() -> Result<SigningKey> {
    for _ in 0..16 {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|error| anyhow!("obtain application signing entropy: {error}"))?;
        let key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        if !key.verifying_key().is_weak() {
            return Ok(key);
        }
    }
    bail!("failed to generate a strong application signing key")
}

fn validate_new_output_path(path: &Path, label: &str) -> Result<PathBuf> {
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
    ensure!(metadata.is_dir(), "{label} parent is not a directory");
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "{label} parent must deny group/other access"
    );
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{label} lacks a file name"))?;
    Ok(parent.join(name))
}

fn create_new_private_file(path: &Path, label: &str) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("create {label}"))
}

fn open_regular_readonly(path: &Path, label: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {label}"))?;
    let metadata = file.metadata().with_context(|| format!("stat {label}"))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{label} is not a regular file"
    );
    Ok(file)
}

fn read_bounded_regular_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let mut file = open_regular_readonly(path, label)?;
    let length = file.metadata()?.len();
    ensure!(
        length > 0 && length <= maximum,
        "{label} size is outside bound"
    );
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == length,
        "{label} changed while reading"
    );
    Ok(bytes)
}

fn sha256_file_bounded(path: &Path, maximum: u64) -> Result<[u8; 32]> {
    let mut file = open_regular_readonly(path, "workload corpus")?;
    let length = file.metadata()?.len();
    ensure!(
        length > 0 && length <= maximum,
        "workload corpus exceeds bound"
    );
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut read_total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        read_total = read_total
            .checked_add(read as u64)
            .context("workload hash byte count overflow")?;
    }
    ensure!(
        read_total == length,
        "workload corpus changed while hashing"
    );
    Ok(hasher.finalize().into())
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| anyhow!("output has no parent"))?,
    )?
    .sync_all()
    .context("sync workload output parent")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn decode_hash32(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("decode {label}"))?;
    ensure!(
        bytes.len() == 32 && hex::encode(&bytes) == value,
        "{label} must be canonical lowercase 32-byte hex"
    );
    Ok(bytes.try_into().expect("length checked"))
}

mod u128_decimal {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        if raw.is_empty()
            || (raw.len() > 1 && raw.starts_with('0'))
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(D::Error::custom("u128 value is not canonical decimal"));
        }
        raw.parse::<u128>()
            .map_err(|_| D::Error::custom("u128 value is out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const ORDINARY_START_HEIGHT: u64 = 4;
    const MAX_HEIGHT: u64 = 6;

    fn private_temp() -> TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    fn build_campaign(corpus: &Path, policy: &Path) -> BuiltWorkloadCorpusSummaryV1 {
        build_public_workload_corpus_range_v1(
            "trnm-lab-g3-7-equal",
            ORDINARY_START_HEIGHT,
            MAX_HEIGHT,
            corpus,
            policy,
        )
        .unwrap()
    }

    fn load_campaign(
        corpus: &Path,
        policy: &Path,
        summary: &BuiltWorkloadCorpusSummaryV1,
        expected_start_height: u64,
        consensus_public_keys: &[[u8; 32]],
    ) -> Result<VerifiedWorkloadCorpusV1> {
        VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
            corpus,
            policy,
            decode_hash32(&summary.corpus_sha256, "corpus")?,
            decode_hash32(&summary.policy_sha256, "policy")?,
            "trnm-lab-g3-7-equal",
            expected_start_height,
            consensus_public_keys,
        )
    }

    #[test]
    fn public_corpus_round_trips_without_any_secret_artifact() {
        let temp = private_temp();
        let corpus = temp.path().join("workload.corpus");
        let policy = temp.path().join("workload-policy.json");
        let summary = build_campaign(&corpus, &policy);
        assert!(!summary.application_private_key_retained);
        assert!(!summary.application_private_key_deployed);
        assert_eq!(summary.ordinary_start_height, ORDINARY_START_HEIGHT);
        assert_eq!(summary.max_height, MAX_HEIGHT);
        assert_eq!(summary.ordinary_entry_count, 3);
        assert_eq!(summary.execution_preflight_height, MAX_HEIGHT);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
        let mut loaded = load_campaign(
            &corpus,
            &policy,
            &summary,
            ORDINARY_START_HEIGHT,
            &[[0x51; 32]],
        )
        .unwrap();
        let first = loaded.block_at_height(ORDINARY_START_HEIGHT).unwrap();
        let third = loaded.block_at_height(MAX_HEIGHT).unwrap();
        assert_ne!(first, third);
        assert_eq!(first.ordinal, 1);
        assert_eq!(third.ordinal, 3);
        assert_eq!(first.transactions.len(), 2);
        assert_eq!(
            first.timestamp_ms,
            ORDINARY_START_HEIGHT * WORKLOAD_BLOCK_TIME_STEP_MS_V1
        );
        assert!(loaded.block_at_height(ORDINARY_START_HEIGHT - 1).is_err());
        assert!(loaded.block_at_height(MAX_HEIGHT + 1).is_err());
        let signers = loaded.authorized_signers_v0().unwrap();
        assert_eq!(signers[0].signer_role(), "operator");
        assert_eq!(signers[1].signer_role(), "hepta");
    }

    #[test]
    fn corpus_rejects_consensus_key_overlap_and_noncanonical_policy() {
        let temp = private_temp();
        let corpus = temp.path().join("workload.corpus");
        let policy = temp.path().join("workload-policy.json");
        let summary = build_campaign(&corpus, &policy);
        let app_key = decode_hash32(&summary.operator_public_key_hex, "app key").unwrap();
        assert!(VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
            &corpus,
            &policy,
            decode_hash32(&summary.corpus_sha256, "corpus").unwrap(),
            decode_hash32(&summary.policy_sha256, "policy").unwrap(),
            "trnm-lab-g3-7-equal",
            ORDINARY_START_HEIGHT,
            &[app_key],
        )
        .is_err());

        let noncanonical = temp.path().join("noncanonical-policy.json");
        let mut bytes = fs::read(&policy).unwrap();
        bytes.push(b'\n');
        fs::write(&noncanonical, &bytes).unwrap();
        assert!(VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
            &corpus,
            &noncanonical,
            decode_hash32(&summary.corpus_sha256, "corpus").unwrap(),
            sha256(&bytes),
            "trnm-lab-g3-7-equal",
            ORDINARY_START_HEIGHT,
            &[[0x51; 32]],
        )
        .is_err());
    }

    #[test]
    fn post_admission_entry_mutation_is_detected_against_pinned_hash() {
        let temp = private_temp();
        let corpus = temp.path().join("workload.corpus");
        let policy = temp.path().join("workload-policy.json");
        let summary = build_campaign(&corpus, &policy);
        let mut loaded = load_campaign(
            &corpus,
            &policy,
            &summary,
            ORDINARY_START_HEIGHT,
            &[[0x51; 32]],
        )
        .unwrap();
        let index = loaded.entries[0];
        let mut writable = OpenOptions::new().write(true).open(&corpus).unwrap();
        writable
            .seek(SeekFrom::Start(index.signature_offsets[0]))
            .unwrap();
        writable.write_all(b"X").unwrap();
        writable.sync_all().unwrap();
        assert!(loaded.block_at_height(ORDINARY_START_HEIGHT).is_err());
    }

    #[test]
    fn corpus_rejects_wrong_committed_start_and_policy_hash_readdressing() {
        let temp = private_temp();
        let corpus = temp.path().join("workload.corpus");
        let policy = temp.path().join("workload-policy.json");
        let summary = build_campaign(&corpus, &policy);
        assert!(load_campaign(
            &corpus,
            &policy,
            &summary,
            ORDINARY_START_HEIGHT + 1,
            &[[0x51; 32]],
        )
        .is_err());

        let readdressed_policy = temp.path().join("readdressed-policy.json");
        let mut value: WorkloadPolicyV1 =
            serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
        value.header.ordinary_start_height += 1;
        value.header.ordinary_entry_count -= 1;
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&readdressed_policy, &bytes).unwrap();
        assert!(VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
            &corpus,
            &readdressed_policy,
            decode_hash32(&summary.corpus_sha256, "corpus").unwrap(),
            sha256(&bytes),
            "trnm-lab-g3-7-equal",
            ORDINARY_START_HEIGHT + 1,
            &[[0x51; 32]],
        )
        .is_err());
    }

    #[test]
    fn corpus_rejects_fully_readdressed_noncontiguous_height() {
        let temp = private_temp();
        let corpus = temp.path().join("workload.corpus");
        let policy = temp.path().join("workload-policy.json");
        build_campaign(&corpus, &policy);
        let mut corpus_bytes = fs::read(&corpus).unwrap();
        let header_length_offset = CORPUS_MAGIC_V1.len() + 4;
        let header_length = u32::from_be_bytes(
            corpus_bytes[header_length_offset..header_length_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let entries_start = CORPUS_MAGIC_V1.len() + 4 + 4 + header_length + 8;
        let second_height = entries_start + (8 + 8 + 64 + 64 + 32);
        corpus_bytes[second_height..second_height + 8]
            .copy_from_slice(&(ORDINARY_START_HEIGHT + 2).to_be_bytes());
        fs::write(&corpus, &corpus_bytes).unwrap();
        let corpus_sha256 = sha256(&corpus_bytes);

        let mut policy_value: WorkloadPolicyV1 =
            serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
        policy_value.corpus_sha256 = hex::encode(corpus_sha256);
        let policy_bytes = serde_json::to_vec(&policy_value).unwrap();
        fs::write(&policy, &policy_bytes).unwrap();
        assert!(VerifiedWorkloadCorpusV1::load_for_ordinary_start_height(
            &corpus,
            &policy,
            corpus_sha256,
            sha256(&policy_bytes),
            "trnm-lab-g3-7-equal",
            ORDINARY_START_HEIGHT,
            &[[0x51; 32]],
        )
        .is_err());
    }

    #[test]
    fn builder_rejects_empty_or_implicit_ordinary_ranges() {
        let temp = private_temp();
        assert!(build_public_workload_corpus_range_v1(
            "trnm-lab-g3-7-equal",
            0,
            MAX_HEIGHT,
            temp.path().join("zero.corpus"),
            temp.path().join("zero-policy.json"),
        )
        .is_err());
        assert!(build_public_workload_corpus_range_v1(
            "trnm-lab-g3-7-equal",
            ORDINARY_START_HEIGHT,
            ORDINARY_START_HEIGHT - 1,
            temp.path().join("empty.corpus"),
            temp.path().join("empty-policy.json"),
        )
        .is_err());
    }

    #[test]
    fn exact_height_policy_rejects_validly_resigned_height_or_shifted_nonces() {
        let operator_key = SigningKey::from_bytes(&[0x31; 32]);
        let client_key = SigningKey::from_bytes(&[0x32; 32]);
        let header = WorkloadCorpusHeaderV1::new(
            "trnm-lab-g3-7-equal",
            ORDINARY_START_HEIGHT,
            MAX_HEIGHT,
            hex::encode(operator_key.verifying_key().to_bytes()),
            hex::encode(client_key.verifying_key().to_bytes()),
        )
        .unwrap();
        header.validate().unwrap();
        let height = ORDINARY_START_HEIGHT;
        let timestamp_ms = header.canonical_timestamp_ms(height).unwrap();
        for forged_nonce in [height, 2] {
            let transaction = CanonicalTxV1 {
                schema: CANONICAL_TX_SCHEMA_V1.to_string(),
                sender: header.operator.signer_id.clone(),
                nonce: forged_nonce,
                max_gas: header.max_gas,
                fee_limit: header.fee_limit,
                command: CanonicalCommandV1::CreditAccount {
                    account: header.client.signer_id.clone(),
                    amount: header.credit_amount,
                },
            };
            let payload = serde_json::to_vec(&transaction).unwrap();
            let envelope = SignedCommandEnvelopeV1::sign(
                header.chain_id.clone(),
                command_id(height, 0).unwrap(),
                header.operator.signer_id.clone(),
                header.operator.signer_role.clone(),
                forged_nonce,
                timestamp_ms,
                timestamp_ms + header.validity_width_ms,
                CANONICAL_TX_PAYLOAD_TYPE_V1,
                &payload,
                &operator_key,
            )
            .unwrap();
            assert!(
                validate_envelope(&header, height, 0, &serde_json::to_vec(&envelope).unwrap(),)
                    .is_err()
            );
        }
    }
}
