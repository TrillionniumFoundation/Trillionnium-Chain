//! Candidate content observations for complete state and legacy migration material.
//!
//! These adapters hash the actual canonical values, full header and public-key
//! bytes. They never strengthen an old root by hashing that root again. Existing
//! roots, stored schemas, checkpoint admission and migration authorization are
//! unchanged. An observation is neither a `TrustedMigrationAnchor` nor evidence
//! of source finality, historical ownership, source retirement or durable custody.
//!
//! The supported configuration has no opaque task-window or PQ-policy object;
//! those configurations fail closed rather than omit their hidden state. All
//! public configuration values and every State row are included. Embedded old
//! hashes remain literal references: this does not reauthenticate their external
//! objects, reconstruct old history or preserve discarded input-JSON syntax.

use crate::pon_executor::{
    pq_accounts_v2::{CheckpointMaterial, PrecommittedAccount},
    Config, State,
};
use serde_json::Value;
use std::io::{self, Cursor, Read, Write};
use trnm_protocol::{
    content_commitment::{
        observe_reader, ContentCommitmentError, ContentContextV1, ContentKind, ContentReadBudget,
        ObservedContentV1,
    },
    pq_frame::ml_dsa_65_key_id_from_spki,
};

mod history_v2;
pub use history_v2::{
    migration_history_snapshot_size_v2, observe_migration_history_v2,
    observe_migration_history_with_progress_v2, verify_migration_history_v2,
    verify_migration_history_with_progress_v2, MigrationHistoryBlockV2, MigrationHistoryReadbackV2,
    MigrationHistorySourceV2, MAX_MIGRATION_HISTORY_BLOCKS_V2, MAX_MIGRATION_HISTORY_BYTES_V2,
};

pub const MAX_SNAPSHOT_ROWS_V1: usize = 65_536;
pub const MAX_SNAPSHOT_KEY_BYTES_V1: usize = 160;
pub const MAX_SNAPSHOT_VALUE_BYTES_V1: usize = 4096;
pub const MAX_SNAPSHOT_CONFIGURATION_BYTES_V1: usize = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_EVALUATORS: usize = 64;

#[derive(Debug)]
pub enum SnapshotContentErrorV1 {
    Input(&'static str),
    Commitment(ContentCommitmentError),
}
impl std::fmt::Display for SnapshotContentErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot content rejected: {self:?}")
    }
}
impl std::error::Error for SnapshotContentErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Commitment(error) => Some(error),
            Self::Input(_) => None,
        }
    }
}
impl From<ContentCommitmentError> for SnapshotContentErrorV1 {
    fn from(error: ContentCommitmentError) -> Self {
        Self::Commitment(error)
    }
}
type Result<T> = std::result::Result<T, SnapshotContentErrorV1>;
fn require(value: bool, message: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(SnapshotContentErrorV1::Input(message))
    }
}

// Bound traversal before serde allocation. This is the executor's ASCII/integer
// value grammar with explicit candidate-only depth, node and encoded-size caps.
fn check_json(value: &Value, depth: usize, left: &mut usize, maximum: usize) -> Result<()> {
    require(depth <= MAX_JSON_DEPTH && *left > 0, "JSON depth/nodes")?;
    *left -= 1;
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(value) => require(value.is_u64() || value.is_i64(), "JSON integer"),
        Value::String(value) => require(value.len() <= maximum && value.is_ascii(), "JSON string"),
        Value::Array(values) => {
            for value in values {
                check_json(value, depth + 1, left, maximum)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                require(key.len() <= maximum && key.is_ascii(), "JSON object key")?;
                check_json(value, depth + 1, left, maximum)?;
            }
            Ok(())
        }
    }
}
struct BoundedBytes {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum - self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "canonical JSON size",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn json_bytes(value: &Value, maximum: usize) -> Result<Vec<u8>> {
    let mut nodes_left = maximum;
    check_json(value, 0, &mut nodes_left, maximum)?;
    let mut out = BoundedBytes {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut out, value)
        .map_err(|_| SnapshotContentErrorV1::Input("canonical JSON size/encoding"))?;
    Ok(out.bytes)
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    // Every caller checks its fixed bound before this conversion.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn configuration(cfg: &Config) -> Result<Vec<u8>> {
    // Exhaustive destructuring makes any future Config field a compile-time
    // format-review obligation, rather than silently leaving it uncommitted.
    let Config {
        network,
        parameters,
        family,
        plan,
        evaluators,
        fees,
        params,
        model_registry,
        task_windows,
        native_pq_v2,
        #[cfg(feature = "pq-native-openssl")]
        pq_accounts,
    } = cfg;
    require(
        !cfg.is_pq_account_profile()
            && task_windows.is_none()
            && native_pq_v2.is_none()
            && params["account_authorization_profile"].is_null(),
        "opaque source policy unsupported",
    )?;
    #[cfg(feature = "pq-native-openssl")]
    require(pq_accounts.is_none(), "opaque source policy unsupported")?;
    require(evaluators.len() <= MAX_EVALUATORS, "evaluator count")?;
    let params = json_bytes(params, MAX_SNAPSHOT_CONFIGURATION_BYTES_V1)?;
    let registry = json_bytes(model_registry, MAX_SNAPSHOT_CONFIGURATION_BYTES_V1)?;
    let mut out = b"SCF1".to_vec();
    for literal_reference in [network, parameters, family, plan] {
        out.extend_from_slice(literal_reference);
    }
    out.extend_from_slice(&(evaluators.len() as u16).to_be_bytes());
    for evaluator in evaluators {
        require(
            evaluator.len() <= 160 && evaluator.is_ascii(),
            "evaluator bytes",
        )?;
        field(&mut out, evaluator.as_bytes());
    }
    for fee in fees {
        out.extend_from_slice(&fee.to_be_bytes());
    }
    field(&mut out, &params);
    field(&mut out, &registry);
    require(
        out.len() <= MAX_SNAPSHOT_CONFIGURATION_BYTES_V1,
        "configuration size",
    )?;
    Ok(out)
}
fn row(key: &str, value: &Value) -> Result<Vec<u8>> {
    require(key.len() <= MAX_SNAPSHOT_KEY_BYTES_V1, "state key size")?;
    let value = json_bytes(value, MAX_SNAPSHOT_VALUE_BYTES_V1)?;
    let mut out = Vec::with_capacity(6 + key.len() + value.len());
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(key.as_bytes());
    field(&mut out, &value);
    Ok(out)
}

/// Immutable borrowing permits a bounded length pass followed by streaming the
/// same values. Only configuration bytes and one row are retained, not a second
/// full state. The caller's budget charges the final stream plus its EOF probe;
/// the bounded encoding passes are not a CPU/RSS or production-host certificate.
struct SnapshotReader<'a> {
    current: Cursor<Vec<u8>>,
    rows: std::collections::btree_map::Iter<'a, String, Value>,
}
impl<'a> SnapshotReader<'a> {
    fn new(state: &'a State, cfg: &Config, mut prefix: Vec<u8>) -> Result<(Self, u64)> {
        require(state.len() <= MAX_SNAPSHOT_ROWS_V1, "state row count")?;
        let cfg = configuration(cfg)?;
        prefix.extend_from_slice(b"CST1");
        field(&mut prefix, &cfg);
        prefix.extend_from_slice(&(state.len() as u64).to_be_bytes());
        let mut length = prefix.len() as u64;
        for (key, value) in state {
            length = length
                .checked_add(row(key, value)?.len() as u64)
                .ok_or(SnapshotContentErrorV1::Input("snapshot size overflow"))?;
        }
        Ok((
            Self {
                current: Cursor::new(prefix),
                rows: state.iter(),
            },
            length,
        ))
    }
}
impl Read for SnapshotReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let count = self.current.read(bytes)?;
            if count != 0 {
                return Ok(count);
            }
            let Some((key, value)) = self.rows.next() else {
                return Ok(0);
            };
            self.current = Cursor::new(row(key, value).map_err(io::Error::other)?);
        }
    }
}

/// Direct full-state CST1 observation, not a new consensus root or state setter.
pub fn observe_state_snapshot_v1(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    state: &State,
    cfg: &Config,
) -> Result<ObservedContentV1> {
    require(
        context.kind() == ContentKind::StateSnapshot,
        "state content kind",
    )?;
    let (mut input, length) = SnapshotReader::new(state, cfg, Vec::new())?;
    Ok(observe_reader(context, budget, length, &mut input)?)
}

/// Explicit source material; supplying it does not authenticate any field.
pub struct MigrationCheckpointSourceV1<'a> {
    pub material: &'a CheckpointMaterial,
    pub configuration: &'a Config,
    /// Existing independently selected locator, retained only for compatibility.
    pub legacy_checkpoint: [u8; 32],
    /// Full actual public-key registry, strictly ordered by source account.
    /// Timing, ownership and original admission remain independent obligations.
    pub precommitted_accounts: &'a [PrecommittedAccount],
}

/// CMG1 contains the legacy locator, full header/genesis/trace, complete actual
/// precommitment public keys and generations, and the whole CST1 state/config.
/// Source state-root consistency, execution/finality and retirement must still
/// be checked by their original owners. No `TrustedMigrationAnchor` is created.
pub fn observe_migration_checkpoint_v1(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    source: MigrationCheckpointSourceV1<'_>,
) -> Result<ObservedContentV1> {
    require(
        context.kind() == ContentKind::MigrationCheckpoint,
        "migration content kind",
    )?;
    let (material, cfg) = (source.material, source.configuration);
    require(
        source.legacy_checkpoint != [0; 32]
            && material.genesis != [0; 32]
            && material.header.network == cfg.network
            && material.header.parameters == cfg.parameters
            && material.header.block_id(material.trace) == source.legacy_checkpoint,
        "legacy checkpoint locator/context",
    )?;
    require(
        (1..=crate::pon_executor::pq_accounts_v2::migration::MAX_IMPORT_ACCOUNTS)
            .contains(&source.precommitted_accounts.len()),
        "precommitment count",
    )?;
    let mut prefix = b"CMG1".to_vec();
    prefix.extend_from_slice(&source.legacy_checkpoint);
    prefix.extend_from_slice(&material.genesis);
    field(&mut prefix, &material.header.encode());
    prefix.extend_from_slice(&material.trace);
    prefix.extend_from_slice(&(source.precommitted_accounts.len() as u16).to_be_bytes());
    let mut previous = None;
    for account in source.precommitted_accounts {
        require(
            account.source_account != [0; 32]
                && account.generation != 0
                && previous.is_none_or(|id| id < account.source_account),
            "precommitment order/identity/generation",
        )?;
        ml_dsa_65_key_id_from_spki(&account.spki)
            .map_err(|_| SnapshotContentErrorV1::Input("precommitment public key"))?;
        prefix.extend_from_slice(&account.source_account);
        prefix.extend_from_slice(&account.generation.to_be_bytes());
        field(&mut prefix, &account.spki);
        previous = Some(account.source_account);
    }
    let (mut input, length) = SnapshotReader::new(&material.state, cfg, prefix)?;
    Ok(observe_reader(context, budget, length, &mut input)?)
}

#[cfg(test)]
mod tests;
