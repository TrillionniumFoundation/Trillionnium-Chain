//! Release-wide obligations composed with the original physical retention owner.
//!
//! TCA2 is a fresh catalog namespace, incompatible with the archived TCA1.
//! It stores complete immutable model roots, optional typed tensor plans,
//! and their exact original per-manifest contracts; payloads remain in the
//! existing retention arena. An incomplete reservation protects every declared
//! dependency. Expiry alone never removes a root or releases a physical slot.
//! Funding, current heights, administrator independence and CURRENT/FinalUse
//! retain their existing external owners. This local catalog proves none of them.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use super::{
    require, CellDigestV1, CellErrorV1, CellManifestV1, CellModelReleaseRootV1, CellResultV1,
    CellRetentionConfigV1, CellRetentionContractV1, CellRetentionReadbackV1, CellRetentionStoreV1,
    CellStoreV1, CellTensorModelManifestV1,
};

const APPLICATION_ID: i64 = 0x5443_4132;
const MAX_RELEASES: u32 = 128;
pub const MAX_CELL_ARCHIVE_CONTRACT_BYTES_V2: usize = 4 * 1024 * 1024;
const META_SQL: &str = "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id BLOB NOT NULL CHECK(length(store_id)=32),maximum_releases INTEGER NOT NULL CHECK(maximum_releases BETWEEN 1 AND 128)) STRICT";
const ROOTS_SQL: &str = "CREATE TABLE release_duties (operation BLOB PRIMARY KEY CHECK(length(operation)=32),funding BLOB NOT NULL UNIQUE CHECK(length(funding)=32),wire BLOB NOT NULL CHECK(length(wire) BETWEEN 1 AND 4194304),status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 2),checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseRetentionConfigV2 {
    pub retention: CellRetentionConfigV1,
    /// Includes retired roots; history and replay identities are never erased.
    pub maximum_releases: u32,
}

/// One local complete-replica duty. Replica/failure-domain fields are immutable
/// declarations, not evidence that the other replicas or independent hosts exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseRetentionContractV2 {
    pub operation: CellDigestV1,
    pub funding_operation: CellDigestV1,
    pub responsible_owner: CellDigestV1,
    pub failure_domain: CellDigestV1,
    /// Zero-based slot in the owner's externally admitted complete-replica set.
    pub replica_index: u16,
    pub required_replicas: u16,
    pub retain_from_height: u64,
    pub retain_until_height: u64,
    /// Last admitted height for a new repair. Missed deadlines keep the duty;
    /// they never erase references, manufacture payment, or relax a later retry.
    pub repair_deadline_height: u64,
    pub root: CellModelReleaseRootV1,
    /// The complete TMA1 plan for this exact root, retained in the catalog for
    /// source-free recovery. None explicitly selects opaque byte retention.
    /// A physical ACK does not establish tensor validity or CURRENT/FinalUse.
    pub tensor_model: Option<CellTensorModelManifestV1>,
    /// Canonical manifest-ID order, exactly the complete root closure.
    /// A shared physical object uses the same immutable original contract.
    pub objects: Vec<CellRetentionContractV1>,
}

impl CellReleaseRetentionContractV2 {
    /// Attach the complete immutable owner plan without changing any physical
    /// object or funding terms. Full configuration checks still run at reserve.
    pub fn with_tensor_model(mut self, model: CellTensorModelManifestV1) -> CellResultV1<Self> {
        model.validate()?;
        require(model.root() == &self.root, "archive tensor model root")?;
        self.tensor_model = Some(model);
        Ok(self)
    }

    /// The exact persisted plan; recovery still requires its independent owner
    /// pin and a fresh strict tensor check before any existing use gate.
    pub fn tensor_model(&self) -> Option<&CellTensorModelManifestV1> {
        self.tensor_model.as_ref()
    }

    pub fn validate(&self, config: &CellReleaseRetentionConfigV2) -> CellResultV1<()> {
        validate_config(config)?;
        self.root.validate()?;
        if let Some(model) = &self.tensor_model {
            model.validate()?;
            require(model.root() == &self.root, "archive tensor model root")?;
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
            "archive duty identity",
        )?;
        require(
            (1..=16).contains(&self.required_replicas)
                && self.replica_index < self.required_replicas,
            "archive replica declaration",
        )?;
        require(
            self.retain_from_height < self.retain_until_height
                && self.retain_until_height <= i64::MAX as u64
                && self.repair_deadline_height >= self.retain_from_height
                && self.repair_deadline_height < self.retain_until_height,
            "archive lease/repair deadline",
        )?;
        let closure = self.root.closure();
        require(
            self.objects.len() == closure.release().cells().len(),
            "archive complete dependency set",
        )?;
        let mut operations = BTreeSet::new();
        let mut funding = BTreeSet::new();
        let mut total = 0_u64;
        // Bound encoding before allocating the complete contract. Only one
        // bounded manifest encoding exists at a time during this length pass.
        let mut wire_bytes = 4_usize + 4 * 32 + 2 * 2 + 3 * 8 + 4 + 1 + 2;
        wire_bytes = wire_bytes
            .checked_add(self.root.encode().len())
            .ok_or(CellErrorV1::Invalid("archive contract size"))?;
        if let Some(model) = &self.tensor_model {
            wire_bytes = wire_bytes
                .checked_add(4)
                .and_then(|size| size.checked_add(model.encode().len()))
                .ok_or(CellErrorV1::Invalid("archive contract size"))?;
        }
        require(
            wire_bytes <= MAX_CELL_ARCHIVE_CONTRACT_BYTES_V2,
            "archive contract size",
        )?;
        for (object, expected) in self.objects.iter().zip(closure.release().cells()) {
            super::retention::validate_contract(object, &config.retention)?;
            closure.verify_manifest(&object.manifest)?;
            require(
                object.manifest.id() == *expected,
                "archive canonical object order",
            )?;
            require(
                operations.insert(object.operation) && funding.insert(object.funding_operation),
                "archive object operation/funding alias",
            )?;
            require(
                object.retain_from_height <= self.retain_from_height
                    && object.retain_until_height >= self.retain_until_height
                    && object.maximum_repair_bytes >= object.manifest.size(),
                "archive object lease coverage",
            )?;
            total = total
                .checked_add(object.manifest.size())
                .ok_or(CellErrorV1::Invalid("archive payload capacity"))?;
            wire_bytes = wire_bytes
                .checked_add(32 + 32 + 3 * 8 + 1 + usize::from(object.successor.is_some()) * 64 + 4)
                .and_then(|size| size.checked_add(object.manifest.encode().len()))
                .ok_or(CellErrorV1::Invalid("archive contract size"))?;
            require(
                wire_bytes <= MAX_CELL_ARCHIVE_CONTRACT_BYTES_V2,
                "archive contract size",
            )?;
        }
        require(
            total <= config.retention.capacity_bytes,
            "archive payload capacity",
        )
    }

    /// Binds the target, root, optional tensor plan, funding identity and all
    /// physical object terms.
    /// The caller's original monetary owner must admit this subject separately.
    pub fn commitment(&self, config: &CellReleaseRetentionConfigV2) -> CellResultV1<CellDigestV1> {
        self.validate(config)?;
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-release-retention-contract.v2\0");
        hash.update(config.retention.store_id);
        hash.update(self.encode());
        Ok(hash.finalize().into())
    }

    fn encode(&self) -> Vec<u8> {
        let root = self.root.encode();
        let mut out = b"TCA2".to_vec();
        for id in [
            self.operation,
            self.funding_operation,
            self.responsible_owner,
            self.failure_domain,
        ] {
            out.extend(id);
        }
        out.extend(self.replica_index.to_be_bytes());
        out.extend(self.required_replicas.to_be_bytes());
        for n in [
            self.retain_from_height,
            self.retain_until_height,
            self.repair_deadline_height,
        ] {
            out.extend(n.to_be_bytes());
        }
        out.extend((root.len() as u32).to_be_bytes());
        out.extend(root);
        if let Some(model) = &self.tensor_model {
            let plan = model.encode();
            out.push(1);
            out.extend((plan.len() as u32).to_be_bytes());
            out.extend(plan);
        } else {
            out.push(0);
        }
        out.extend((self.objects.len() as u16).to_be_bytes());
        for object in &self.objects {
            out.extend(object.operation);
            out.extend(object.funding_operation);
            for n in [
                object.retain_from_height,
                object.retain_until_height,
                object.maximum_repair_bytes,
            ] {
                out.extend(n.to_be_bytes());
            }
            if let Some((store, operation)) = object.successor {
                out.push(1);
                out.extend(store);
                out.extend(operation);
            } else {
                out.push(0);
            }
            let manifest = object.manifest.encode();
            out.extend((manifest.len() as u32).to_be_bytes());
            out.extend(manifest);
        }
        out
    }

    fn decode(wire: &[u8], config: &CellReleaseRetentionConfigV2) -> CellResultV1<Self> {
        require(
            wire.len() <= MAX_CELL_ARCHIVE_CONTRACT_BYTES_V2,
            "archive contract size",
        )?;
        let mut input = Input(wire);
        require(input.array::<4>()? == *b"TCA2", "archive contract version")?;
        let operation = input.array()?;
        let funding_operation = input.array()?;
        let responsible_owner = input.array()?;
        let failure_domain = input.array()?;
        let replica_index = u16::from_be_bytes(input.array()?);
        let required_replicas = u16::from_be_bytes(input.array()?);
        let retain_from_height = u64::from_be_bytes(input.array()?);
        let retain_until_height = u64::from_be_bytes(input.array()?);
        let repair_deadline_height = u64::from_be_bytes(input.array()?);
        let root = CellModelReleaseRootV1::decode(input.sized()?)?;
        let tensor_model = match input.array::<1>()?[0] {
            0 => None,
            1 => Some(CellTensorModelManifestV1::decode(input.sized()?)?),
            _ => return Err(CellErrorV1::Invalid("archive tensor model encoding")),
        };
        let count = usize::from(u16::from_be_bytes(input.array()?));
        require(
            count == root.closure().files().len(),
            "archive object count",
        )?;
        let mut objects = Vec::with_capacity(count);
        for _ in 0..count {
            let operation = input.array()?;
            let funding_operation = input.array()?;
            let retain_from_height = u64::from_be_bytes(input.array()?);
            let retain_until_height = u64::from_be_bytes(input.array()?);
            let maximum_repair_bytes = u64::from_be_bytes(input.array()?);
            let successor = match input.array::<1>()?[0] {
                0 => None,
                1 => Some((input.array()?, input.array()?)),
                _ => return Err(CellErrorV1::Invalid("archive successor encoding")),
            };
            let manifest = CellManifestV1::decode(input.sized()?)?;
            objects.push(CellRetentionContractV1 {
                operation,
                funding_operation,
                manifest,
                retain_from_height,
                retain_until_height,
                maximum_repair_bytes,
                successor,
            });
        }
        require(input.0.is_empty(), "archive trailing bytes")?;
        let value = Self {
            operation,
            funding_operation,
            responsible_owner,
            failure_domain,
            replica_index,
            required_replicas,
            retain_from_height,
            retain_until_height,
            repair_deadline_height,
            root,
            tensor_model,
            objects,
        };
        value.validate(config)?;
        require(value.encode() == wire, "archive canonical contract")?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseRetentionReadbackV2 {
    pub operation: CellDigestV1,
    pub release_root: CellDigestV1,
    pub contract_commitment: CellDigestV1,
    pub acknowledged: bool,
    pub retired: bool,
    pub objects: Vec<CellRetentionReadbackV1>,
}

struct DutyRow {
    contract: CellReleaseRetentionContractV2,
    status: u8,
}

/// One exclusive physical owner with a release-aware catalog. No mutable arena
/// handle is exposed: all physical retirement passes the complete live-root scan.
pub struct CellReleaseRetentionStoreV2 {
    directory: PathBuf,
    config: CellReleaseRetentionConfigV2,
    catalog: Connection,
    retention: CellRetentionStoreV1,
}

impl CellReleaseRetentionStoreV2 {
    pub fn store_id(&self) -> CellDigestV1 {
        self.config.retention.store_id
    }

    /// Bind externally admitted funding to this actual catalog configuration.
    /// This validates immutable terms but neither reserves nor acknowledges.
    pub fn contract_commitment(
        &self,
        contract: &CellReleaseRetentionContractV2,
    ) -> CellResultV1<CellDigestV1> {
        contract.commitment(&self.config)
    }

    pub fn create(directory: &Path, config: CellReleaseRetentionConfigV2) -> CellResultV1<Self> {
        validate_config(&config)?;
        fs::create_dir(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let retention =
            CellRetentionStoreV1::create(&directory.join("objects"), config.retention.clone())?;
        let mut catalog = Connection::open_with_flags(
            directory.join("archive.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure(&catalog)?;
        let tx = catalog.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(META_SQL)?;
        tx.execute_batch(ROOTS_SQL)?;
        tx.execute(
            "INSERT INTO metadata VALUES (1,?1,?2)",
            params![
                config.retention.store_id.as_slice(),
                config.maximum_releases
            ],
        )?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
        File::open(directory)?.sync_all()?;
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            config,
            catalog,
            retention,
        })
    }

    pub fn open(directory: &Path, config: CellReleaseRetentionConfigV2) -> CellResultV1<Self> {
        validate_config(&config)?;
        check_directory(directory)?;
        let retention =
            CellRetentionStoreV1::open(&directory.join("objects"), config.retention.clone())?;
        let catalog = Connection::open_with_flags(
            directory.join("archive.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        // Never change an unknown catalog's journal mode before validating its
        // exact version and schema. Opening cannot migrate or erase roots.
        catalog.pragma_update(None, "trusted_schema", false)?;
        audit(&catalog, &config, Instant::now() + Duration::from_secs(10))?;
        configure(&catalog)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            config,
            catalog,
            retention,
        })
    }

    /// Persist the complete intent before any member reservation. Partial
    /// capacity/IO failure leaves a pending root protecting the entire closure.
    /// Repeating the same immutable contract resumes reservations idempotently.
    pub fn reserve_release(
        &mut self,
        contract: CellReleaseRetentionContractV2,
        deadline: Instant,
    ) -> CellResultV1<CellReleaseRetentionReadbackV2> {
        self.check(deadline)?;
        contract.validate(&self.config)?;
        check_deadline(deadline)?;
        write_catalog_until(&mut self.catalog, deadline, |tx| {
            let ids = audit(tx, &self.config, deadline)?;
            if let Some(prior) = read_row(tx, &self.config, contract.operation)? {
                require(
                    prior.contract == contract,
                    "archive operation contract changed",
                )?;
                require(prior.status != 2, "archive retired duty")?;
            } else {
                require(
                    ids.len() < self.config.maximum_releases as usize,
                    "archive root capacity",
                )?;
                let new_terms: BTreeMap<_, _> = contract
                    .objects
                    .iter()
                    .map(|object| {
                        (
                            object.operation,
                            object.commitment(self.config.retention.store_id),
                        )
                    })
                    .collect();
                let new_manifests: BTreeMap<_, _> = contract
                    .objects
                    .iter()
                    .map(|object| (object.manifest.id(), object.operation))
                    .collect();
                let new_funding: BTreeMap<_, _> = contract
                    .objects
                    .iter()
                    .map(|object| (object.funding_operation, object.operation))
                    .collect();
                let mut all_operations: BTreeSet<_> = new_terms.keys().copied().collect();
                for id in ids {
                    check_deadline(deadline)?;
                    let prior = required_row(tx, &self.config, id)?;
                    for old in &prior.contract.objects {
                        all_operations.insert(old.operation);
                        if let Some(commitment) = new_terms.get(&old.operation) {
                            require(
                                *commitment == old.commitment(self.config.retention.store_id),
                                "archive shared object contract changed",
                            )?;
                        }
                        if let Some(operation) = new_funding.get(&old.funding_operation) {
                            require(*operation == old.operation, "archive object funding alias")?;
                        }
                        if prior.status != 2 {
                            if let Some(operation) = new_manifests.get(&old.manifest.id()) {
                                require(
                                    *operation == old.operation,
                                    "archive shared object operation alias",
                                )?;
                            }
                        }
                    }
                }
                // Pending roots also reserve future immutable row identities.
                // Retired history cannot create new record capacity. Check only
                // NEW intents: older pending rows remain readable/protected and
                // exact retry never rewrites their original terms or status.
                require(
                    all_operations.len() <= self.config.retention.maximum_obligations as usize,
                    "archive physical record capacity",
                )?;
                self.retention
                    .check_reservation_set(&contract.objects, deadline)?;
                write_row(
                    tx,
                    &DutyRow {
                        contract: contract.clone(),
                        status: 0,
                    },
                    true,
                )?;
            }
            audit(tx, &self.config, deadline)?;
            let durable = required_row(tx, &self.config, contract.operation)?;
            require(
                durable.contract == contract && durable.status != 2,
                "archive intent readback",
            )
        })?;
        self.check(deadline)?;
        let durable = required_row(&self.catalog, &self.config, contract.operation)?;
        require(
            durable.contract == contract && durable.status != 2,
            "archive intent readback",
        )?;
        let mut objects = Vec::with_capacity(contract.objects.len());
        for object in &contract.objects {
            check_deadline(deadline)?;
            let readback = self.retention.reserve_until(object.clone(), deadline)?;
            require(!readback.retired, "archive physical object retired")?;
            objects.push(readback);
        }
        let result = self.readback(&durable, objects)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Complete each original copy and independently reread every dependency
    /// before sealing the release ACK. Individual interrupted copies retain the
    /// existing target-only reconciliation and separate repair identity rules.
    /// This attests physical bytes only, including when a tensor plan is retained.
    pub fn acknowledge_release(
        &mut self,
        operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellReleaseRetentionReadbackV2> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "archive retired duty")?;
        for object in &row.contract.objects {
            check_deadline(deadline)?;
            require(
                self.retention.contract(object.operation)? == *object,
                "archive physical contract changed",
            )?;
            self.retention
                .acknowledge(object.operation, cache, deadline)?;
        }
        let objects = self.verify_objects(&row, deadline)?;
        self.seal_ack(row, objects, deadline)
    }

    /// Admit one member's original initial copy through the complete root.
    /// The funding owner must choose this only for its new member intent;
    /// pending/done effects use reconcile_member, which has no source handle.
    pub fn acknowledge_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check_member(operation, object_operation, deadline)?;
        let result = self
            .retention
            .acknowledge(object_operation, cache, deadline)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Recover one original member from its retained target only. A complete
    /// root intent cannot turn an unknown member effect into another copy.
    pub fn reconcile_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check_member(operation, object_operation, deadline)?;
        let result = self
            .retention
            .reconcile_acknowledgement(object_operation, deadline)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    fn check_member(
        &self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "archive retired duty")?;
        let object = row
            .contract
            .objects
            .iter()
            .find(|object| object.operation == object_operation)
            .ok_or(CellErrorV1::Invalid("archive member dependency"))?;
        require(
            self.retention.contract(object_operation)? == *object,
            "archive physical contract changed",
        )?;
        check_deadline(deadline)
    }

    /// Read the exact persisted terms for recovery without caller reconstruction
    /// or changing any original operation, funding, dependency or lease identity.
    pub fn contract(
        &self,
        operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellReleaseRetentionContractV2> {
        self.check(deadline)?;
        let result = required_row(&self.catalog, &self.config, operation)?.contract;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Resolve a lost release ACK from actual targets only. The absence of a
    /// source/cache parameter prevents this recovery entry point from copying
    /// bytes. Missing/partial targets remain pending until a distinct repair.
    pub fn reconcile_release(
        &mut self,
        operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellReleaseRetentionReadbackV2> {
        checkpoint()?;
        self.check(deadline)?;
        checkpoint()?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "archive retired duty")?;
        let mut objects = Vec::with_capacity(row.contract.objects.len());
        for object in &row.contract.objects {
            checkpoint()?;
            require(
                self.retention.contract(object.operation)? == *object,
                "archive physical contract changed",
            )?;
            objects.push(self.retention.reconcile_acknowledgement_controlled(
                object.operation,
                deadline,
                checkpoint,
            )?);
        }
        checkpoint()?;
        let readback = self.seal_ack(row, objects, deadline)?;
        checkpoint()?;
        Ok(readback)
    }

    fn seal_ack(
        &mut self,
        mut row: DutyRow,
        objects: Vec<CellRetentionReadbackV1>,
        deadline: Instant,
    ) -> CellResultV1<CellReleaseRetentionReadbackV2> {
        let operation = row.contract.operation;
        write_catalog_until(&mut self.catalog, deadline, |tx| {
            audit(tx, &self.config, deadline)?;
            let current = required_row(tx, &self.config, operation)?;
            require(
                current.contract == row.contract && current.status != 2,
                "archive ACK prior changed",
            )?;
            row.status = 1;
            write_row(tx, &row, false)?;
            audit(tx, &self.config, deadline)?;
            Ok(())
        })?;
        self.check(deadline)?;
        let durable = required_row(&self.catalog, &self.config, operation)?;
        require(
            durable.status == 1 && durable.contract == row.contract,
            "archive ACK readback",
        )?;
        let result = self.readback(&durable, objects)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// A historical ACK is not fresh availability. Every call hashes actual
    /// retained payloads through the original arena owner under one deadline.
    pub fn verify_release(
        &mut self,
        operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellReleaseRetentionReadbackV2> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status == 1, "archive release unavailable")?;
        let objects = self.verify_objects(&row, deadline)?;
        let result = self.readback(&row, objects)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Repair one exact dependency with the original retention byte accounting.
    /// The caller supplies the current verified height and separately admitted
    /// repair operation. A late attempt refuses without freeing the duty.
    #[allow(clippy::too_many_arguments)]
    pub fn repair_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        repair_operation: CellDigestV1,
        current_height: u64,
        cache: &CellStoreV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check(deadline)?;
        checkpoint()?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "archive retired duty")?;
        require(
            current_height >= row.contract.retain_from_height
                && current_height <= row.contract.repair_deadline_height,
            "archive repair height deadline",
        )?;
        let object = row
            .contract
            .objects
            .iter()
            .find(|object| object.operation == object_operation)
            .ok_or(CellErrorV1::Invalid("archive repair dependency"))?;
        require(
            self.retention.contract(object_operation)? == *object,
            "archive physical contract changed",
        )?;
        let result = self.retention.repair_controlled(
            object_operation,
            repair_operation,
            cache,
            deadline,
            checkpoint,
        )?;
        checkpoint()?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Resolve an original repair from its actual physical target, including
    /// after the immutable dispatch deadline. No source/cache, replacement
    /// operation or new copy is permitted through this recovery entry point.
    pub fn reconcile_repair_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        repair_operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        checkpoint()?;
        self.check(deadline)?;
        checkpoint()?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "archive retired duty")?;
        let object = row
            .contract
            .objects
            .iter()
            .find(|object| object.operation == object_operation)
            .ok_or(CellErrorV1::Invalid("archive repair dependency"))?;
        require(
            self.retention.contract(object_operation)? == *object,
            "archive physical contract changed",
        )?;
        let result = self.retention.reconcile_repair_controlled(
            object_operation,
            repair_operation,
            deadline,
            checkpoint,
        )?;
        checkpoint()?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Rehydrate the existing disposable chunk cache; no new serving/CAS path.
    pub fn populate_cache(
        &mut self,
        operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellReleaseRetentionReadbackV2> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status == 1, "archive release unavailable")?;
        let mut objects = Vec::with_capacity(row.contract.objects.len());
        for object in &row.contract.objects {
            check_deadline(deadline)?;
            require(
                self.retention.contract(object.operation)? == *object,
                "archive physical contract changed",
            )?;
            objects.push(
                self.retention
                    .populate_cache(object.operation, cache, deadline)?,
            );
        }
        let result = self.readback(&row, objects)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Remove one expired, acknowledged root from the live reachability set.
    /// Pending/unknown or corrupt duties cannot be retired by this operation.
    /// Physical reclamation is separate and rechecks all other roots atomically.
    pub fn retire_release(
        &mut self,
        operation: CellDigestV1,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.check(deadline)?;
        let mut row = required_row(&self.catalog, &self.config, operation)?;
        if row.status == 2 {
            return check_deadline(deadline);
        }
        require(row.status == 1, "archive pending duty")?;
        require(
            current_height >= row.contract.retain_until_height,
            "archive lease not expired",
        )?;
        self.verify_objects(&row, deadline)?;
        write_catalog_until(&mut self.catalog, deadline, |tx| {
            audit(tx, &self.config, deadline)?;
            let current = required_row(tx, &self.config, operation)?;
            require(
                current.contract == row.contract && current.status == 1,
                "archive retirement prior changed",
            )?;
            // A pre-lock read cannot authorize reclamation. An unsettled original
            // repair keeps the root reachable even when its payload hashes match.
            for object in &current.contract.objects {
                self.retention
                    .require_settled_repairs(object.operation, deadline)?;
            }
            row.status = 2;
            write_row(tx, &row, false)?;
            audit(tx, &self.config, deadline)?;
            Ok(())
        })?;
        self.check(deadline)?;
        let durable = required_row(&self.catalog, &self.config, operation)?;
        require(
            durable.status == 2 && durable.contract == row.contract,
            "archive retirement readback",
        )?;
        check_deadline(deadline)
    }

    /// GC of one physical object. Hold the catalog writer transaction through
    /// the original arena retirement so a new root cannot race the decision.
    /// All active roots, including pending/expired roots, protect their objects.
    pub fn retire_object(
        &mut self,
        object_operation: CellDigestV1,
        current_height: u64,
        mut successor: Option<&mut CellReleaseRetentionStoreV2>,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check(deadline)?;
        if let Some(next) = successor.as_mut() {
            next.check(deadline)?;
        }
        let result = write_catalog_until(&mut self.catalog, deadline, |tx| {
            let ids = audit(tx, &self.config, deadline)?;
            let mut expected = None;
            for id in ids {
                check_deadline(deadline)?;
                let row = required_row(tx, &self.config, id)?;
                if let Some(object) = row
                    .contract
                    .objects
                    .iter()
                    .find(|object| object.operation == object_operation)
                {
                    require(row.status == 2, "archive object reachable from live duty")?;
                    expected = Some(object.clone());
                }
            }
            let expected = expected.ok_or(CellErrorV1::Invalid("archive unknown object"))?;
            require(
                self.retention.contract(object_operation)? == expected,
                "archive physical contract changed",
            )?;
            let next = successor.map(|store| &mut store.retention);
            let result = self
                .retention
                .retire(object_operation, current_height, next, deadline)?;
            check_deadline(deadline)?;
            audit(tx, &self.config, deadline)?;
            Ok(result)
        })?;
        self.check(deadline)?;
        Ok(result)
    }

    fn check(&self, deadline: Instant) -> CellResultV1<()> {
        check_deadline(deadline)?;
        check_directory(&self.directory)?;
        audit(&self.catalog, &self.config, deadline)?;
        Ok(())
    }

    fn verify_objects(
        &mut self,
        row: &DutyRow,
        deadline: Instant,
    ) -> CellResultV1<Vec<CellRetentionReadbackV1>> {
        let mut objects = Vec::with_capacity(row.contract.objects.len());
        for object in &row.contract.objects {
            check_deadline(deadline)?;
            require(
                self.retention.contract(object.operation)? == *object,
                "archive physical contract changed",
            )?;
            objects.push(self.retention.verify(object.operation, deadline)?);
        }
        Ok(objects)
    }

    fn readback(
        &self,
        row: &DutyRow,
        objects: Vec<CellRetentionReadbackV1>,
    ) -> CellResultV1<CellReleaseRetentionReadbackV2> {
        Ok(CellReleaseRetentionReadbackV2 {
            operation: row.contract.operation,
            release_root: row.contract.root.id(),
            contract_commitment: row.contract.commitment(&self.config)?,
            acknowledged: row.status == 1,
            retired: row.status == 2,
            objects,
        })
    }
}

fn validate_config(config: &CellReleaseRetentionConfigV2) -> CellResultV1<()> {
    super::retention::validate_config(&config.retention)?;
    require(
        (1..=MAX_RELEASES).contains(&config.maximum_releases),
        "archive configuration",
    )
}

fn configure(connection: &Connection) -> CellResultV1<()> {
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

/// Every catalog writer uses the caller's original absolute deadline, including
/// writer contention and final commit. A refusal after commit is an unknown
/// caller outcome; the exact next call observes the durable intent/ACK/retire.
fn write_catalog_until<T>(
    connection: &mut Connection,
    deadline: Instant,
    write: impl FnOnce(&Connection) -> CellResultV1<T>,
) -> CellResultV1<T> {
    check_deadline(deadline)?;
    let original_busy_ms: u64 =
        connection.pragma_query_value(None, "busy_timeout", |value| value.get(0))?;
    let original_busy = Duration::from_millis(original_busy_ms);
    connection
        .busy_timeout(original_busy.min(deadline.saturating_duration_since(Instant::now())))?;
    let result = (|| {
        check_deadline(deadline)?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        check_deadline(deadline)?;
        let result = write(&transaction)?;
        check_deadline(deadline)?;
        transaction
            .busy_timeout(original_busy.min(deadline.saturating_duration_since(Instant::now())))?;
        check_deadline(deadline)?;
        transaction.commit()?;
        check_deadline(deadline)?;
        Ok(result)
    })();
    connection.busy_timeout(original_busy)?;
    result
}

fn check_directory(directory: &Path) -> CellResultV1<()> {
    let metadata = fs::symlink_metadata(directory)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "archive directory",
    )?;
    let metadata = fs::symlink_metadata(directory.join("archive.sqlite"))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "archive database",
    )
}

fn audit(
    connection: &Connection,
    config: &CellReleaseRetentionConfigV2,
    deadline: Instant,
) -> CellResultV1<Vec<CellDigestV1>> {
    check_deadline(deadline)?;
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    require(
        application == APPLICATION_ID && version == 2,
        "archive namespace",
    )?;
    for (name, expected) in [("metadata", META_SQL), ("release_duties", ROOTS_SQL)] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        require(actual.as_deref() == Some(expected), "archive schema")?;
    }
    let objects: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
        [],
        |row| row.get(0),
    )?;
    require(objects == 2, "archive schema")?;
    let (store_id, maximum): (Vec<u8>, u32) = connection.query_row(
        "SELECT store_id,maximum_releases FROM metadata WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    require(
        store_id.as_slice() == config.retention.store_id && maximum == config.maximum_releases,
        "archive stored configuration",
    )?;
    let count: u64 =
        connection.query_row("SELECT count(*) FROM release_duties", [], |row| row.get(0))?;
    require(
        count <= u64::from(config.maximum_releases),
        "archive root capacity",
    )?;
    let mut statement =
        connection.prepare("SELECT operation FROM release_duties ORDER BY operation")?;
    let mut query = statement.query([])?;
    let mut ids = Vec::with_capacity(count as usize);
    let mut object_terms = BTreeMap::new();
    let mut manifest_operations = BTreeMap::new();
    while let Some(row) = query.next()? {
        check_deadline(deadline)?;
        let id = digest(row.get(0)?)?;
        let duty = required_row(connection, config, id)?;
        for object in duty.contract.objects {
            let commitment = object.commitment(config.retention.store_id);
            if let Some(previous) = object_terms.insert(object.operation, commitment) {
                require(
                    previous == commitment,
                    "archive shared object contract changed",
                )?;
            }
            if duty.status != 2 {
                if let Some(previous) =
                    manifest_operations.insert(object.manifest.id(), object.operation)
                {
                    require(
                        previous == object.operation,
                        "archive shared object operation alias",
                    )?;
                }
            }
        }
        ids.push(id);
    }
    check_deadline(deadline)?;
    Ok(ids)
}

fn read_row(
    connection: &Connection,
    config: &CellReleaseRetentionConfigV2,
    operation: CellDigestV1,
) -> CellResultV1<Option<DutyRow>> {
    let raw = connection.query_row(
        "SELECT funding,CASE WHEN length(wire) BETWEEN 1 AND 4194304 THEN wire ELSE NULL END,status,checksum FROM release_duties WHERE operation=?1",
        [operation.as_slice()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, u8>(2)?, row.get::<_, Vec<u8>>(3)?)),
    ).optional()?;
    let Some((funding, wire, status, checksum)) = raw else {
        return Ok(None);
    };
    let wire = wire.ok_or(CellErrorV1::Invalid("archive contract size"))?;
    let contract = CellReleaseRetentionContractV2::decode(&wire, config)?;
    require(
        contract.operation == operation
            && contract.funding_operation.as_slice() == funding
            && status <= 2
            && checksum == row_checksum(&wire, status),
        "archive row integrity",
    )?;
    Ok(Some(DutyRow { contract, status }))
}

fn required_row(
    connection: &Connection,
    config: &CellReleaseRetentionConfigV2,
    operation: CellDigestV1,
) -> CellResultV1<DutyRow> {
    read_row(connection, config, operation)?.ok_or(CellErrorV1::Invalid("archive unknown duty"))
}

fn write_row(connection: &Connection, row: &DutyRow, insert: bool) -> CellResultV1<()> {
    let wire = row.contract.encode();
    let checksum = row_checksum(&wire, row.status);
    let changed = if insert {
        connection.execute(
            "INSERT INTO release_duties VALUES (?1,?2,?3,?4,?5)",
            params![
                row.contract.operation.as_slice(),
                row.contract.funding_operation.as_slice(),
                wire,
                row.status,
                checksum
            ],
        )?
    } else {
        connection.execute(
            "UPDATE release_duties SET status=?2,checksum=?3 WHERE operation=?1 AND wire=?4",
            params![
                row.contract.operation.as_slice(),
                row.status,
                checksum,
                wire
            ],
        )?
    };
    require(changed == 1, "archive catalog write")?;
    let actual: (Vec<u8>, Vec<u8>, u8, Vec<u8>) = connection.query_row(
        "SELECT funding,wire,status,checksum FROM release_duties WHERE operation=?1",
        [row.contract.operation.as_slice()],
        |value| Ok((value.get(0)?, value.get(1)?, value.get(2)?, value.get(3)?)),
    )?;
    require(
        actual.0 == row.contract.funding_operation
            && actual.1 == wire
            && actual.2 == row.status
            && actual.3 == row_checksum(&wire, row.status),
        "archive catalog write readback",
    )
}

fn row_checksum(wire: &[u8], status: u8) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-release-retention-row.v2\0");
    hash.update([status]);
    hash.update(wire);
    hash.finalize().to_vec()
}

fn digest(bytes: Vec<u8>) -> CellResultV1<CellDigestV1> {
    bytes
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("archive digest"))
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() <= deadline, "archive operation deadline")
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> CellResultV1<&'a [u8]> {
        require(count <= self.0.len(), "archive truncated contract")?;
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("archive field"))
    }
    fn sized(&mut self) -> CellResultV1<&'a [u8]> {
        let count = u32::from_be_bytes(self.array()?) as usize;
        self.take(count)
    }
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
