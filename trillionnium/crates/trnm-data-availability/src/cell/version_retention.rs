//! TCA3: one durable owner for a complete model-and-environment version.
//!
//! The immutable TCV1, independent loader pins, original physical contracts and
//! complete Pending intent are committed together. Pending, Active and expired
//! unretired duties all protect their dependencies. Only explicit retirement
//! removes a reference. Payloads and copy/repair charges belong to the existing
//! TCR1 arena; this catalog neither creates a second CAS nor grants funding.
//!
//! An externally retained catalog anchor detects a restored older catalog. The
//! hash chain is an integrity/replay mechanism, not protection against a party
//! that can replace both this directory and its independently retained anchor.

mod catalog;
mod chunk_read;
mod codec;
mod inventory;
mod owner;
use catalog::*;
use inventory::projection;
#[cfg(test)]
mod tests;

use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use super::{
    require, CellContextV1, CellDigestV1, CellErrorV1, CellFileRoleV1, CellLoaderContextV1,
    CellManifestV1, CellResultV1, CellRetainedVersionEntryV1, CellRetainedVersionSetV1,
    CellRetentionConfigV1, CellRetentionContractV1, CellRetentionReadbackV1, CellRetentionStoreV1,
    CellStoreV1, CellTensorModelManifestV1, CellVersionCommitmentV1, CellVersionLoaderContextV1,
    CellVersionManifestV1,
};

const APPLICATION_ID: i64 = 0x5443_4133;
const MAX_VERSIONS: u32 = 128;
const MAX_PROTECTED_VERSIONS: usize = 16;
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CELL_VERSION_RETENTION_CONTRACT_BYTES_V3: usize = 16 * 1024 * 1024;
const META_SQL: &str = "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id BLOB NOT NULL CHECK(length(store_id)=32),maximum_versions INTEGER NOT NULL CHECK(maximum_versions BETWEEN 1 AND 128),maximum_metadata_bytes INTEGER NOT NULL CHECK(maximum_metadata_bytes BETWEEN 1 AND 67108864),generation INTEGER NOT NULL CHECK(generation BETWEEN 0 AND 384),tip BLOB NOT NULL CHECK(length(tip)=32)) STRICT";
const DUTIES_SQL: &str = "CREATE TABLE version_duties (operation BLOB PRIMARY KEY CHECK(length(operation)=32),funding BLOB NOT NULL UNIQUE CHECK(length(funding)=32),wire BLOB NOT NULL CHECK(length(wire) BETWEEN 1 AND 16777216),status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 2),generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 384),checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT";
const EVENTS_SQL: &str = "CREATE TABLE version_events (generation INTEGER PRIMARY KEY CHECK(generation BETWEEN 1 AND 384),operation BLOB NOT NULL CHECK(length(operation)=32),contract BLOB NOT NULL CHECK(length(contract)=32),status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 2),previous BLOB NOT NULL CHECK(length(previous)=32),checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionRetentionConfigV3 {
    pub retention: CellRetentionConfigV1,
    /// All original identities, including retired duties, count toward this cap.
    pub maximum_versions: u32,
    /// Sum of immutable duty encodings, including retired history.
    pub maximum_metadata_bytes: u64,
}

/// An owned copy of an independently selected loader policy. Recovery must not
/// reconstruct its expected policy from the untrusted version being recovered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionLoaderPinV3 {
    pub closure_id: CellDigestV1,
    pub context: CellContextV1,
    pub selected_generation: u64,
    pub loader_profile: CellDigestV1,
    pub required_roles: Vec<CellFileRoleV1>,
    pub max_payload_bytes: u64,
    pub max_chunks: u64,
}

impl CellVersionLoaderPinV3 {
    pub fn from_context(context: &CellLoaderContextV1) -> Self {
        let mut required_roles = context.required_roles.clone();
        required_roles.sort();
        Self {
            closure_id: context.closure_id,
            context: context.context.clone(),
            selected_generation: context.selected_generation,
            loader_profile: context.loader_profile,
            required_roles,
            max_payload_bytes: context.max_payload_bytes,
            max_chunks: context.max_chunks,
        }
    }

    pub fn loader_context(&self) -> CellLoaderContextV1 {
        CellLoaderContextV1 {
            closure_id: self.closure_id,
            context: self.context.clone(),
            selected_generation: self.selected_generation,
            loader_profile: self.loader_profile,
            required_roles: self.required_roles.clone(),
            max_payload_bytes: self.max_payload_bytes,
            max_chunks: self.max_chunks,
        }
    }

    fn validate(&self) -> CellResultV1<()> {
        self.context.validate()?;
        require(
            !self.required_roles.is_empty()
                && self.required_roles.len() <= 6
                && self.required_roles.windows(2).all(|pair| pair[0] < pair[1])
                && self.max_payload_bytes > 0
                && self.max_chunks > 0,
            "version retention loader policy",
        )
    }
}

/// A physical snapshot duty can refer to its original independently funded
/// predecessor. The scheduler owns cadence/authorization; merely enumerating
/// this link is not evidence that a periodic snapshot has completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionSnapshotLinkV3 {
    pub schedule: CellDigestV1,
    pub ordinal: u64,
    pub due_height: u64,
    pub predecessor_operation: CellDigestV1,
    pub predecessor_contract: CellDigestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionRetentionContractV3 {
    pub operation: CellDigestV1,
    pub funding_operation: CellDigestV1,
    pub responsible_owner: CellDigestV1,
    pub failure_domain: CellDigestV1,
    pub replica_index: u16,
    pub required_replicas: u16,
    pub retain_from_height: u64,
    pub retain_until_height: u64,
    pub repair_deadline_height: u64,
    pub version: CellVersionManifestV1,
    pub model: CellVersionLoaderPinV3,
    pub environment: CellVersionLoaderPinV3,
    /// None explicitly retains opaque bytes; it does not assert tensor validity.
    pub tensor_model: Option<CellTensorModelManifestV1>,
    pub snapshot: Option<CellVersionSnapshotLinkV3>,
    /// Exact canonical TCV manifest order, with original immutable arena terms.
    pub objects: Vec<CellRetentionContractV1>,
}

impl CellVersionRetentionContractV3 {
    pub fn validate(&self, config: &CellVersionRetentionConfigV3) -> CellResultV1<()> {
        validate_config(config)?;
        self.version.validate()?;
        self.model.validate()?;
        self.environment.validate()?;
        let model = self.model.loader_context();
        let environment = self.environment.loader_context();
        self.version
            .verify_for_loader(&CellVersionLoaderContextV1 {
                commitment: self.version.commitment(),
                model: &model,
                environment: &environment,
            })?;
        if let Some(plan) = &self.tensor_model {
            plan.validate()?;
            require(
                plan.root() == self.version.model(),
                "version retention tensor root",
            )?;
        }
        require(
            [
                self.operation,
                self.funding_operation,
                self.responsible_owner,
                self.failure_domain,
            ]
            .iter()
            .all(|id| *id != [0; 32]),
            "version retention identity",
        )?;
        require(
            (1..=16).contains(&self.required_replicas)
                && self.replica_index < self.required_replicas,
            "version retention replica declaration",
        )?;
        require(
            self.retain_from_height < self.retain_until_height
                && self.retain_until_height <= i64::MAX as u64
                && self.repair_deadline_height >= self.retain_from_height
                && self.repair_deadline_height < self.retain_until_height,
            "version retention lease/repair deadline",
        )?;
        if let Some(link) = &self.snapshot {
            require(
                link.schedule != [0; 32]
                    && link.ordinal > 0
                    && link.ordinal <= i64::MAX as u64
                    && link.predecessor_operation != [0; 32]
                    && link.predecessor_operation != self.operation
                    && link.predecessor_contract != [0; 32]
                    && self.retain_from_height <= link.due_height
                    && link.due_height < self.retain_until_height,
                "version retention snapshot link",
            )?;
        }
        require(
            self.objects.len() == self.version.manifests().len(),
            "version retention complete dependency set",
        )?;
        let mut operations = BTreeSet::from([self.operation]);
        let mut funding = BTreeSet::from([self.funding_operation]);
        let mut reserved = 0_u64;
        // The version and optional tensor plan have their own bounded codecs.
        // This length pass never allocates the complete concatenated contract.
        let mut bytes = 4
            + 4 * 32
            + 4
            + 24
            + 4
            + self.version.encode().len()
            + codec::pin_size(&self.model)
            + codec::pin_size(&self.environment)
            + 1
            + 1
            + 2;
        if let Some(plan) = &self.tensor_model {
            bytes = checked_size(bytes, 4 + plan.encode().len())?;
        }
        if self.snapshot.is_some() {
            bytes = checked_size(bytes, 32 + 8 + 8 + 32 + 32)?;
        }
        for (object, manifest) in self.objects.iter().zip(self.version.manifests()) {
            super::retention::validate_contract(object, &config.retention)?;
            require(
                &object.manifest == manifest,
                "version retention canonical object coverage",
            )?;
            require(
                operations.insert(object.operation) && funding.insert(object.funding_operation),
                "version retention object identity alias",
            )?;
            require(
                object.retain_from_height <= self.retain_from_height
                    && object.retain_until_height >= self.retain_until_height
                    && object.maximum_repair_bytes >= object.manifest.size(),
                "version retention object lease coverage",
            )?;
            reserved = reserved
                .checked_add(aligned(object.manifest.size())?)
                .ok_or(CellErrorV1::Invalid("version retention size overflow"))?;
            bytes = checked_size(
                bytes,
                64 + 24
                    + 1
                    + usize::from(object.successor.is_some()) * 64
                    + 4
                    + object.manifest.encode().len(),
            )?;
        }
        require(
            operations.is_disjoint(&funding),
            "version retention operation/funding alias",
        )?;
        require(
            reserved <= config.retention.capacity_bytes,
            "version retention physical capacity",
        )?;
        require(
            bytes <= MAX_CELL_VERSION_RETENTION_CONTRACT_BYTES_V3,
            "version retention contract size",
        )
    }

    pub fn commitment(&self, config: &CellVersionRetentionConfigV3) -> CellResultV1<CellDigestV1> {
        self.validate(config)?;
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-version-retention-contract.v3\0");
        hash.update(config.retention.store_id);
        hash.update(self.encode_wire());
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellVersionCatalogAnchorV3 {
    generation: u64,
    commitment: CellDigestV1,
}

impl CellVersionCatalogAnchorV3 {
    pub fn generation(self) -> u64 {
        self.generation
    }
    pub fn commitment(self) -> CellDigestV1 {
        self.commitment
    }
    pub fn encode(self) -> Vec<u8> {
        let mut out = b"CVA3".to_vec();
        out.extend(self.generation.to_be_bytes());
        out.extend(self.commitment);
        out
    }
    /// Decode an independently retained anchor; decoding is not authentication.
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        let mut input = codec::Input(bytes);
        require(
            input.array::<4>()? == *b"CVA3",
            "version retention anchor namespace",
        )?;
        let result = Self {
            generation: u64::from_be_bytes(input.array()?),
            commitment: input.array()?,
        };
        require(
            input.0.is_empty()
                && result.generation <= 3 * u64::from(MAX_VERSIONS)
                && result.commitment != [0; 32],
            "version retention anchor encoding",
        )?;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellVersionRetentionStateV3 {
    Pending,
    Active,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionRetentionReadbackV3 {
    pub operation: CellDigestV1,
    pub version: CellVersionCommitmentV1,
    pub contract_commitment: CellDigestV1,
    pub anchor: CellVersionCatalogAnchorV3,
    pub acknowledged: bool,
    pub retired: bool,
    pub objects: Vec<CellRetentionReadbackV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionRetentionUsageV3 {
    pub historical_versions: u32,
    pub protected_versions: u32,
    pub pending_versions: u32,
    /// Acknowledged and unretired, including the separately counted expired subset.
    pub active_versions: u32,
    pub expired_unretired_versions: u32,
    pub metadata_bytes: u64,
    pub historical_objects: u32,
    pub occupied_bytes: u64,
    pub promised_unallocated_bytes: u64,
    pub retired_version_occupied_bytes: u64,
    pub initial_copy_bytes_committed: u64,
    pub repair_bytes_committed: u64,
}

#[derive(Clone, Debug)]
pub struct CellVersionRetentionDutyV3 {
    pub contract: CellVersionRetentionContractV3,
    pub state: CellVersionRetentionStateV3,
    pub generation: u64,
}

/// Inventory is obtained from the actual complete catalog. It grants neither GC
/// nor serving authority and is not a physical periodic-snapshot completion.
#[derive(Clone, Debug)]
pub struct CellVersionRetentionInventoryV3 {
    pub anchor: CellVersionCatalogAnchorV3,
    pub protected: Vec<CellVersionRetentionDutyV3>,
    pub usage: CellVersionRetentionUsageV3,
}

#[derive(Clone)]
struct DutyRow {
    contract: CellVersionRetentionContractV3,
    status: u8,
    generation: u64,
}

struct AuditedCatalog {
    rows: Vec<DutyRow>,
    anchor: CellVersionCatalogAnchorV3,
    metadata_bytes: u64,
}

/// Exclusive TCR1 arena plus a fresh complete-version catalog. No mutable arena
/// reference is exposed; every physical retirement scans the complete owner R.
pub struct CellVersionRetentionStoreV3 {
    directory: PathBuf,
    config: CellVersionRetentionConfigV3,
    catalog: Connection,
    retention: CellRetentionStoreV1,
    observed: Cell<CellVersionCatalogAnchorV3>,
}

fn checked_size(previous: usize, add: usize) -> CellResultV1<usize> {
    let result = previous
        .checked_add(add)
        .ok_or(CellErrorV1::Invalid("version retention contract size"))?;
    require(
        result <= MAX_CELL_VERSION_RETENTION_CONTRACT_BYTES_V3,
        "version retention contract size",
    )?;
    Ok(result)
}

fn aligned(size: u64) -> CellResultV1<u64> {
    size.checked_add(4095)
        .map(|value| value / 4096 * 4096)
        .ok_or(CellErrorV1::Invalid("version retention size overflow"))
}

fn validate_config(config: &CellVersionRetentionConfigV3) -> CellResultV1<()> {
    super::retention::validate_config(&config.retention)?;
    require(
        (1..=MAX_VERSIONS).contains(&config.maximum_versions)
            && (1..=MAX_METADATA_BYTES).contains(&config.maximum_metadata_bytes),
        "version retention configuration",
    )
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(
        Instant::now() <= deadline,
        "version retention operation deadline",
    )
}
