//! Local physical CRS1 storage with immutable CSP1 metadata and actual readback.
//!
//! Each provider namespace has one fixed declared identity and generation. The
//! existing retention arena owns allocation, irreversible initial/repair debits,
//! unknown outcomes and retirement; this adapter adds no second operation log.
//! A CSP1 is durably stored before its arena reservation. Reopening still needs
//! an independent operation pin and original TCM1 binding. Distinct local store
//! IDs do not establish independent operators, failure domains or WAN custody.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use sha2::{Digest, Sha256};

use super::{
    CellRs46ChunkBindingV1, CellRs46CodewordV1, CellRs46PlacementPolicyV1,
    CellRs46ShardPlacementV1, CellRs46ShardV1, CELL_RS46_CODEWORD_WIRE_BYTES_V1,
    CELL_RS46_TOTAL_SHARDS_V1, SHARD_HEADER_BYTES,
};
use crate::cell::{
    digest_hex, require, store::verify_chunk, CellDigestV1, CellErrorV1, CellResultV1,
    CellRetentionConfigV1, CellRetentionContractV1, CellRetentionReadbackV1, CellRetentionStoreV1,
    CellStoreV1,
};

mod admission;
mod contract;
pub use contract::{
    CellRs46ShardContractV1, CellRs46ShardOwnerV1, MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1,
};

const DESCRIPTORS: &str = "slot-descriptors-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46ShardProviderConfigV1 {
    pub placement: CellRs46ShardPlacementV1,
    pub owner_generation: u64,
    pub capacity_bytes: u64,
    /// Includes terminal arena rows and immutable descriptors of interrupted
    /// preparations. Failed attempts never create unbounded metadata capacity.
    pub maximum_obligations: u32,
}

impl CellRs46ShardProviderConfigV1 {
    pub fn store_id(&self) -> CellResultV1<CellDigestV1> {
        let identities = contract::placement_identities(&self.placement);
        require(
            self.owner_generation > 0 && identities.iter().all(|id| *id != [0; 32]),
            "RS46 provider identity",
        )?;
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-rs46-provider-store.v1\0");
        hash.update(self.owner_generation.to_be_bytes());
        for identity in identities {
            hash.update(identity);
        }
        Ok(hash.finalize().into())
    }

    fn retention_config(&self) -> CellResultV1<CellRetentionConfigV1> {
        Ok(CellRetentionConfigV1 {
            store_id: self.store_id()?,
            capacity_bytes: self.capacity_bytes,
            maximum_obligations: self.maximum_obligations,
        })
    }
}

/// Sealed observation of exact bytes read from an acknowledged physical arena.
/// It records this read, not a promise that the provider remains available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellRs46StoredShardV1 {
    operation: CellDigestV1,
    provider_store: CellDigestV1,
    codeword: CellDigestV1,
    placement: CellDigestV1,
    shard: CellRs46ShardV1,
}

impl CellRs46StoredShardV1 {
    pub fn operation(&self) -> CellDigestV1 {
        self.operation
    }
    pub fn provider_store(&self) -> CellDigestV1 {
        self.provider_store
    }
    pub fn codeword(&self) -> CellDigestV1 {
        self.codeword
    }
    pub fn placement(&self) -> CellDigestV1 {
        self.placement
    }
    pub fn shard(&self) -> &CellRs46ShardV1 {
        &self.shard
    }
}

/// Arguments for one explicitly admitted physical repair. Source preparation
/// and RS reconstruction have their own original budgets; this does not reset
/// them or infer funding from a digest. Unknown repair IDs use reconcile_repair.
pub struct CellRs46ShardRepairRequestV1<'a> {
    pub binding: &'a CellRs46ChunkBindingV1,
    pub operation: CellDigestV1,
    pub repair_operation: CellDigestV1,
    pub cache: &'a CellStoreV1,
    pub deadline: Instant,
}

pub struct CellRs46ShardProviderV1 {
    config: CellRs46ShardProviderConfigV1,
    arena: CellRetentionStoreV1,
    descriptors_path: PathBuf,
    descriptors: File,
}

impl CellRs46ShardProviderV1 {
    pub fn create(directory: &Path, config: CellRs46ShardProviderConfigV1) -> CellResultV1<Self> {
        let arena = CellRetentionStoreV1::create(directory, config.retention_config()?)?;
        let descriptors_path = directory.join(DESCRIPTORS);
        fs::create_dir(&descriptors_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&descriptors_path, fs::Permissions::from_mode(0o700))?;
        }
        let descriptors = open_directory(&descriptors_path)?;
        descriptors.sync_all()?;
        File::open(directory)?.sync_all()?;
        let value = Self {
            config,
            arena,
            descriptors_path,
            descriptors,
        };
        value.descriptor_count(None)?;
        Ok(value)
    }

    pub fn open(directory: &Path, config: CellRs46ShardProviderConfigV1) -> CellResultV1<Self> {
        let arena = CellRetentionStoreV1::open(directory, config.retention_config()?)?;
        let descriptors_path = directory.join(DESCRIPTORS);
        let descriptors = open_directory(&descriptors_path)?;
        let value = Self {
            config,
            arena,
            descriptors_path,
            descriptors,
        };
        value.descriptor_count(None)?;
        Ok(value)
    }

    pub fn store_id(&self) -> CellDigestV1 {
        self.arena.store_id()
    }

    /// Stage only the exact independently pinned CRS1 payload in an existing
    /// bounded CAS. This does not ACK physical retention or create a provider.
    pub fn cache_shard(
        contract: &CellRs46ShardContractV1,
        expected_operation: CellDigestV1,
        wire: &[u8],
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        check(deadline)?;
        contract.verify_pin(expected_operation)?;
        contract.verify_wire(wire)?;
        check(deadline)?;
        cache.put_manifest_with_deadline(
            contract.manifest().id(),
            &contract.manifest().encode(),
            Some(deadline),
        )?;
        cache.put_chunk_with_deadline(&contract.manifest().chunks()[0], wire, Some(deadline))?;
        check(deadline)
    }

    /// Prepare at most one six-slot plan chunk. This stages disposable CAS
    /// bytes only; it neither reserves a provider nor acknowledges retention.
    pub(super) fn cache_shards(
        shards: &[(&CellRs46ShardContractV1, CellDigestV1, &[u8])],
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        check(deadline)?;
        require(
            !shards.is_empty() && shards.len() <= CELL_RS46_TOTAL_SHARDS_V1,
            "RS46 provider cache batch bound",
        )?;
        let mut manifests = Vec::with_capacity(shards.len());
        for (contract, expected, wire) in shards {
            check(deadline)?;
            contract.verify_pin(*expected)?;
            contract.verify_wire(wire)?;
            check(deadline)?;
            manifests.push((contract.manifest().id(), contract.manifest().encode()));
        }
        let entries: Vec<_> = shards
            .iter()
            .zip(&manifests)
            .map(|((_, _, wire), (pinned, manifest))| (*pinned, manifest.as_slice(), *wire))
            .collect();
        cache.put_single_chunk_manifests_with_deadline(&entries, deadline)?;
        check(deadline)
    }

    /// Persist full metadata, reserve real arena space, copy at most once, then
    /// read the actual target back. The arena's initial attempt is charged before
    /// its first write. A failed or lost result is unknown, never a refund.
    /// This entry retains the wall deadline; funded CPU admission is external.
    pub fn publish(
        &mut self,
        contract: &CellRs46ShardContractV1,
        expected_operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<(CellRetentionReadbackV1, CellRs46StoredShardV1)> {
        self.publish_controlled(
            contract,
            expected_operation,
            cache,
            deadline,
            &mut || Ok(()),
        )
    }

    /// Cancellation checkpoints surround metadata and the bounded one-shard
    /// initial copy. The underlying initial-copy loop retains its wall deadline;
    /// this wrapper does not claim kernel preemption or measured CPU admission.
    pub fn publish_controlled(
        &mut self,
        contract: &CellRs46ShardContractV1,
        expected_operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<(CellRetentionReadbackV1, CellRs46StoredShardV1)> {
        controlled(deadline, checkpoint)?;
        self.check_contract(contract, expected_operation)?;
        Self::verify_cache(contract, cache, deadline, checkpoint)?;
        self.persist_descriptor(contract, expected_operation, deadline)?;
        controlled(deadline, checkpoint)?;
        self.arena
            .reserve_until(contract.retention_contract(), deadline)?;
        controlled(deadline, checkpoint)?;
        let readback = self
            .arena
            .acknowledge(expected_operation, cache, deadline)?;
        controlled(deadline, checkpoint)?;
        let actual = self.read_contract(contract, expected_operation, deadline, checkpoint)?;
        controlled(deadline, checkpoint)?;
        Ok((readback, actual))
    }

    pub fn descriptor(
        &self,
        binding: &CellRs46ChunkBindingV1,
        expected_operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellRs46ShardContractV1> {
        check(deadline)?;
        self.descriptor_count(Some(deadline))?;
        let path = self.descriptors_path.join(digest_hex(expected_operation));
        let mut file = open_descriptor(&path, false)?;
        check_descriptor_identity(&path, &file)?;
        let length = file.metadata()?.len();
        require(
            length <= MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1 as u64,
            "RS46 provider descriptor size",
        )?;
        let mut bytes = Vec::with_capacity(length as usize);
        (&mut file)
            .take(MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1 as u64 + 1)
            .read_to_end(&mut bytes)?;
        check(deadline)?;
        require(
            bytes.len() as u64 == length,
            "RS46 provider descriptor readback length",
        )?;
        check_descriptor_identity(&path, &file)?;
        self.check_descriptor_directory()?;
        let contract = CellRs46ShardContractV1::decode_pinned(&bytes, binding, expected_operation)?;
        self.check_contract(&contract, expected_operation)?;
        check(deadline)?;
        Ok(contract)
    }

    pub fn read(
        &mut self,
        binding: &CellRs46ChunkBindingV1,
        expected_operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRs46StoredShardV1> {
        controlled(deadline, checkpoint)?;
        let contract = self.descriptor(binding, expected_operation, deadline)?;
        controlled(deadline, checkpoint)?;
        self.read_contract(&contract, expected_operation, deadline, checkpoint)
    }

    /// Rewrites only this immutable slot under the original cumulative arena
    /// repair limit. A previous partial intent cannot dispatch another write.
    pub fn repair(
        &mut self,
        request: CellRs46ShardRepairRequestV1<'_>,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<(CellRetentionReadbackV1, CellRs46StoredShardV1)> {
        controlled(request.deadline, checkpoint)?;
        let contract = self.descriptor(request.binding, request.operation, request.deadline)?;
        self.check_reserved_contract(&contract)?;
        Self::verify_cache(&contract, request.cache, request.deadline, checkpoint)?;
        let readback = self.arena.repair_controlled(
            request.operation,
            request.repair_operation,
            request.cache,
            request.deadline,
            checkpoint,
        )?;
        let actual =
            self.read_contract(&contract, request.operation, request.deadline, checkpoint)?;
        controlled(request.deadline, checkpoint)?;
        Ok((readback, actual))
    }

    /// Target-only unknown recovery. There is intentionally no source/cache
    /// parameter, no new operation identity and no physical byte redispatch.
    pub fn reconcile_acknowledgement(
        &mut self,
        binding: &CellRs46ChunkBindingV1,
        expected_operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<(CellRetentionReadbackV1, CellRs46StoredShardV1)> {
        controlled(deadline, checkpoint)?;
        let contract = self.descriptor(binding, expected_operation, deadline)?;
        self.check_reserved_contract(&contract)?;
        let readback = self.arena.reconcile_acknowledgement_controlled(
            expected_operation,
            deadline,
            checkpoint,
        )?;
        let actual = self.read_contract(&contract, expected_operation, deadline, checkpoint)?;
        controlled(deadline, checkpoint)?;
        Ok((readback, actual))
    }

    pub fn reconcile_repair(
        &mut self,
        binding: &CellRs46ChunkBindingV1,
        expected_operation: CellDigestV1,
        repair_operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<(CellRetentionReadbackV1, CellRs46StoredShardV1)> {
        controlled(deadline, checkpoint)?;
        let contract = self.descriptor(binding, expected_operation, deadline)?;
        self.check_reserved_contract(&contract)?;
        let readback = self.arena.reconcile_repair_controlled(
            expected_operation,
            repair_operation,
            deadline,
            checkpoint,
        )?;
        let actual = self.read_contract(&contract, expected_operation, deadline, checkpoint)?;
        controlled(deadline, checkpoint)?;
        Ok((readback, actual))
    }

    /// Explicit owner-driven retirement after the admitted interval. No timer
    /// or chain rollback erases the immutable descriptor or physical history.
    pub fn retire(
        &mut self,
        binding: &CellRs46ChunkBindingV1,
        expected_operation: CellDigestV1,
        current_height: u64,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        controlled(deadline, checkpoint)?;
        let contract = self.descriptor(binding, expected_operation, deadline)?;
        self.check_reserved_contract(&contract)?;
        let result = self.arena.retire_controlled(
            expected_operation,
            current_height,
            None,
            deadline,
            checkpoint,
        )?;
        controlled(deadline, checkpoint)?;
        Ok(result)
    }

    fn check_contract(
        &self,
        contract: &CellRs46ShardContractV1,
        expected: CellDigestV1,
    ) -> CellResultV1<()> {
        contract.verify_pin(expected)?;
        require(
            contract.owner().provider_store == self.arena.store_id()
                && contract.owner().owner_generation == self.config.owner_generation
                && contract.placement().placements[usize::from(contract.owner().slot)]
                    == self.config.placement,
            "RS46 provider owner binding",
        )
    }

    fn check_reserved_contract(&self, contract: &CellRs46ShardContractV1) -> CellResultV1<()> {
        require(
            self.arena.contract(contract.operation())? == contract.retention_contract(),
            "RS46 provider retained contract changed",
        )
    }

    fn read_contract(
        &mut self,
        contract: &CellRs46ShardContractV1,
        expected: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRs46StoredShardV1> {
        controlled(deadline, checkpoint)?;
        self.check_contract(contract, expected)?;
        self.check_reserved_contract(contract)?;
        let bytes = self.arena.read_payload_controlled(
            expected,
            contract.manifest().size(),
            deadline,
            checkpoint,
        )?;
        controlled(deadline, checkpoint)?;
        let shard = contract.verify_wire(&bytes)?;
        controlled(deadline, checkpoint)?;
        self.check_reserved_contract(contract)?;
        // Re-read canonical metadata too: an in-flight file substitution cannot
        // turn this source-bound target observation into a different duty.
        require(
            self.descriptor(contract.binding(), expected, deadline)? == *contract,
            "RS46 provider descriptor changed",
        )?;
        controlled(deadline, checkpoint)?;
        Ok(CellRs46StoredShardV1 {
            operation: expected,
            provider_store: self.arena.store_id(),
            codeword: contract.owner().codeword,
            placement: contract.owner().placement,
            shard,
        })
    }

    fn verify_cache(
        contract: &CellRs46ShardContractV1,
        cache: &CellStoreV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<()> {
        controlled(deadline, checkpoint)?;
        let expected = &contract.manifest().chunks()[0];
        let bytes = cache
            .chunk_with_deadline(expected.sha256, Some(deadline))?
            .ok_or(CellErrorV1::Unavailable)?;
        controlled(deadline, checkpoint)?;
        verify_chunk(expected, &bytes)?;
        contract.verify_wire(&bytes)?;
        controlled(deadline, checkpoint)
    }

    fn persist_descriptor(
        &self,
        contract: &CellRs46ShardContractV1,
        expected: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        check(deadline)?;
        let count = self.descriptor_count(Some(deadline))?;
        let path = self.descriptors_path.join(digest_hex(expected));
        // Reject a new identity before create_new. Otherwise a refused entry
        // would itself push the namespace beyond its lifetime metadata bound.
        let exists = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        require(
            exists || count < self.config.maximum_obligations,
            "RS46 provider descriptor capacity",
        )?;
        check(deadline)?;
        match open_descriptor(&path, true) {
            Ok(mut file) => {
                // Check before payload work; the fixed owner lock serializes
                // legitimate writers. Preserve the created file on any error.
                check(deadline)?;
                file.write_all(&contract.encode())?;
                check(deadline)?;
                file.sync_all()?;
                check_descriptor_identity(&path, &file)?;
            }
            Err(CellErrorV1::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A lost metadata ACK may be completed from the unchanged
                // target only. A partial/corrupt file is never overwritten.
                require(
                    self.descriptor(contract.binding(), expected, deadline)? == *contract,
                    "RS46 provider descriptor changed",
                )?;
                let file = open_descriptor(&path, false)?;
                check_descriptor_identity(&path, &file)?;
                file.sync_all()?;
            }
            Err(error) => return Err(error),
        }
        self.descriptors.sync_all()?;
        check(deadline)?;
        require(
            self.descriptor(contract.binding(), expected, deadline)? == *contract,
            "RS46 provider descriptor readback",
        )?;
        check(deadline)
    }

    fn descriptor_count(&self, deadline: Option<Instant>) -> CellResultV1<u32> {
        if let Some(deadline) = deadline {
            check(deadline)?;
        }
        self.check_descriptor_directory()?;
        let mut count = 0_u32;
        for entry in fs::read_dir(&self.descriptors_path)? {
            if let Some(deadline) = deadline {
                check(deadline)?;
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or(CellErrorV1::Invalid("RS46 provider descriptor name"))?;
            require(
                name.len() == 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "RS46 provider descriptor name",
            )?;
            let metadata = fs::symlink_metadata(entry.path())?;
            require(
                metadata.is_file()
                    && metadata.len() <= MAX_CELL_RS46_PROVIDER_DESCRIPTOR_BYTES_V1 as u64,
                "RS46 provider descriptor entry",
            )?;
            count = count
                .checked_add(1)
                .ok_or(CellErrorV1::Invalid("RS46 provider descriptor capacity"))?;
            require(
                count <= self.config.maximum_obligations,
                "RS46 provider descriptor capacity",
            )?;
        }
        self.check_descriptor_directory()?;
        if let Some(deadline) = deadline {
            check(deadline)?;
        }
        Ok(count)
    }

    fn check_descriptor_directory(&self) -> CellResultV1<()> {
        let path = fs::symlink_metadata(&self.descriptors_path)?;
        let fd = self.descriptors.metadata()?;
        require(
            path.is_dir() && fd.is_dir(),
            "RS46 provider descriptor directory",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            require(
                path.dev() == fd.dev() && path.ino() == fd.ino(),
                "RS46 provider descriptor directory identity",
            )?;
        }
        Ok(())
    }
}

fn check(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() <= deadline, "RS46 provider deadline")
}

fn controlled(
    deadline: Instant,
    checkpoint: &mut impl FnMut() -> CellResultV1<()>,
) -> CellResultV1<()> {
    check(deadline)?;
    checkpoint()?;
    check(deadline)
}

fn open_descriptor(path: &Path, create: bool) -> CellResultV1<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    if create {
        options.write(true).create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    Ok(options.open(path)?)
}

fn open_directory(path: &Path) -> CellResultV1<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    Ok(options.open(path)?)
}

fn check_descriptor_identity(path: &Path, file: &File) -> CellResultV1<()> {
    let entry = fs::symlink_metadata(path)?;
    let fd = file.metadata()?;
    require(
        entry.is_file() && fd.is_file(),
        "RS46 provider descriptor regular file",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            entry.dev() == fd.dev() && entry.ino() == fd.ino() && fd.nlink() == 1,
            "RS46 provider descriptor identity",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
