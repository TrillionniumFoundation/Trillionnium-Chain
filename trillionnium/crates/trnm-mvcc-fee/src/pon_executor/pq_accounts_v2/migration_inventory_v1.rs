//! Read-only inventory of one externally selected complete legacy checkpoint.
//!
//! This module cannot create a genesis, install a key, retire a source chain or
//! authorize a CLAIM. Even `NoLedgerCarryFound` leaves off-chain obligations,
//! source finality and the completeness of the selected source scope unproved.
use super::{field, hash32, require, CheckpointMaterial, Config, Hash, Result};
use serde::Serialize;

pub const MAX_INVENTORY_ROWS: usize = 65_536;
const MAX_UNCLASSIFIED_EXAMPLES: usize = 16;

/// Independently selected identities, not expectations learned from the export.
#[derive(Clone, Copy)]
pub struct SourcePins {
    pub network: Hash,
    pub genesis: Hash,
    pub checkpoint: Hash,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct MonetaryRows {
    pub rows: usize,
    pub nonzero_rows: usize,
    pub units: u64,
}
impl MonetaryRows {
    fn observe(&mut self, amount: u64) -> Result<()> {
        self.rows += 1;
        self.nonzero_rows += usize::from(amount != 0);
        self.units = self.units.checked_add(amount).ok_or("RANGE")?;
        Ok(())
    }
}

/// A data classification, never an activation or ownership verdict.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LedgerDisposition {
    PreservationRequired,
    NoLedgerCarryFound,
}

/// All counts cover the entire root-checked State, including zero-value rows.
/// Opaque rows are counted and require investigation instead of being dropped.
#[derive(Debug, Serialize)]
pub struct CheckpointInventory {
    pub schema: &'static str,
    pub source_network: String,
    pub source_parameters: String,
    pub source_genesis: String,
    pub checkpoint: String,
    pub state_root: String,
    pub source_height: u64,
    pub source_timestamp: u64,
    pub state_rows: usize,
    pub issued_units: u64,
    pub accounts: MonetaryRows,
    pub accounts_with_nonce_floor: usize,
    pub greatest_nonce_floor: u64,
    pub tasks: MonetaryRows,
    pub quotas: MonetaryRows,
    pub releases: MonetaryRows,
    pub rewards: MonetaryRows,
    pub inert_metadata_rows: usize,
    pub unclassified_rows: usize,
    pub unclassified_key_examples: Vec<String>,
    pub disposition: LedgerDisposition,
    /// This API sees one ledger snapshot only; it does not accept a Boolean
    /// that could manufacture evidence for any of these external obligations.
    pub unresolved_scope: [&'static str; 5],
}

/// Rehash the complete state and bind it to independently pinned header identity.
/// A valid header preimage is not a work/finality proof. Obtain material through
/// an admitted source owner and independently establish the source scope first.
pub fn inspect_checkpoint(
    pins: SourcePins,
    material: &CheckpointMaterial,
    source_cfg: &Config,
) -> Result<CheckpointInventory> {
    require(
        !source_cfg.is_pq_account_profile(),
        "PQ_INVENTORY_SOURCE_PROFILE",
    )?;
    let h = &material.header;
    require(
        pins.network != [0; 32]
            && pins.genesis != [0; 32]
            && pins.checkpoint != [0; 32]
            && material.state.len() <= MAX_INVENTORY_ROWS
            && material.genesis == pins.genesis
            && source_cfg.network == pins.network
            && h.network == pins.network
            && h.parameters == source_cfg.parameters
            && h.height > 0
            && h.height < u64::MAX
            && h.timestamp > 0
            && h.block_id(material.trace) == pins.checkpoint,
        "PQ_INVENTORY_CHECKPOINT",
    )?;
    require(
        super::super::root_for_config(&material.state, source_cfg)? == h.state,
        "PQ_INVENTORY_ROOT",
    )?;
    super::super::check_completed_block_state(&material.state, h.height, source_cfg)?;
    let issued = super::super::num(material.state.get("meta:issued").ok_or("STATE")?)?;
    let mut report = CheckpointInventory {
        schema: "trnm-pq-legacy-inventory-v1",
        source_network: hex::encode(pins.network),
        source_parameters: hex::encode(source_cfg.parameters),
        source_genesis: hex::encode(pins.genesis),
        checkpoint: hex::encode(pins.checkpoint),
        state_root: hex::encode(h.state),
        source_height: h.height,
        source_timestamp: h.timestamp,
        state_rows: material.state.len(),
        issued_units: issued,
        accounts: MonetaryRows::default(),
        accounts_with_nonce_floor: 0,
        greatest_nonce_floor: 0,
        tasks: MonetaryRows::default(),
        quotas: MonetaryRows::default(),
        releases: MonetaryRows::default(),
        rewards: MonetaryRows::default(),
        inert_metadata_rows: 0,
        unclassified_rows: 0,
        unclassified_key_examples: Vec::new(),
        disposition: LedgerDisposition::PreservationRequired,
        unresolved_scope: [
            "independent-source-history-and-finality",
            "other-ledgers-debts-and-pending-settlements",
            "in-flight-execution-and-external-dependencies",
            "independent-revocation-and-retirement-records",
            "source-write-retirement-and-read-only-archive",
        ],
    };
    for (key, value) in &material.state {
        if let Some(account) = key.strip_prefix("account:") {
            require(
                hash32(account)? != [0; 32] && value.as_object().is_some_and(|row| row.len() == 2),
                "PQ_INVENTORY_ACCOUNT",
            )?;
            report.accounts.observe(field(value, "balance")?)?;
            let nonce = field(value, "nonce")?;
            report.accounts_with_nonce_floor += usize::from(nonce != 0);
            report.greatest_nonce_floor = report.greatest_nonce_floor.max(nonce);
        } else if key.starts_with("task:") {
            report.tasks.observe(field(value, "remaining")?)?;
        } else if key.starts_with("quota:") {
            report.quotas.observe(field(value, "remaining")?)?;
        } else if key.starts_with("release:") {
            report.releases.observe(field(value, "remaining")?)?;
        } else if key.starts_with("reward:") {
            report.rewards.observe(field(value, "amount")?)?;
        } else if key == "meta:issued"
            || (key == "model:current" && value == &serde_json::json!(hex::encode([0; 32])))
            || (key == crate::continuity_v1::MAINTENANCE_KEY
                && crate::continuity_v1::enabled(source_cfg)
                && value == &crate::continuity_v1::maintenance_record(source_cfg)?)
        {
            report.inert_metadata_rows += 1;
        } else {
            report.unclassified_rows += 1;
            if report.unclassified_key_examples.len() < MAX_UNCLASSIFIED_EXAMPLES {
                report.unclassified_key_examples.push(key.clone());
            }
        }
    }
    // Zero balance is not absence of account identity, a nonce floor, a task
    // obligation, a revocation record or an application dependency.
    if issued == 0 && report.state_rows == report.inert_metadata_rows {
        report.disposition = LedgerDisposition::NoLedgerCarryFound;
    }
    Ok(report)
}

#[cfg(test)]
#[path = "migration_inventory_tests.rs"]
mod tests;
