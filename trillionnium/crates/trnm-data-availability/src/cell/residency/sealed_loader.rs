//! Linux immutable data descriptors for an already admitted declared closure.
//!
//! A loader can consume these exact descriptors without reopening mutable
//! payload paths. This does not sandbox the loader or stop it opening other
//! files, and conveys neither CURRENT selection nor FinalUse authority.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::{FileExt, PermissionsExt},
    },
    sync::atomic::AtomicBool,
    time::Instant,
};

use rustix::fs::{
    fchmod, fcntl_add_seals, fcntl_get_seals, memfd_create, MemfdFlags, Mode, SealFlags,
};
use sha2::{Digest, Sha256, Sha512};

use super::{checkpoint, CellResidencyV1, ResidentClosure};
use crate::cell::{
    require, CellClosureFileV1, CellDigestV1, CellErrorV1, CellFileRoleV1, CellLoaderContextV1,
    CellReleaseClosureV1, CellResultV1, MAX_CELL_BYTES, MAX_CELL_CLOSURE_FILES_V1,
};

const COPY_BYTES: usize = 65_536;
const CONTENT_DOMAIN_V2: &[u8] = b"TRNM/Cell/PayloadContent/v2\0";

/// Bounds the additional copied payload for one complete snapshot, including
/// duplicate files/chunks. This is separate from the resident pool's deduped
/// bytes and excludes metadata, kernel overhead, reader mappings and device
/// allocations. The execution owner must account for concurrent bundles and
/// any descriptors or mappings it retains outside this bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellSealedLoaderLimitsV1 {
    pub max_snapshot_bytes: u64,
    pub max_files: usize,
}

impl CellSealedLoaderLimitsV1 {
    fn validate(self) -> CellResultV1<()> {
        require(
            (1..=MAX_CELL_BYTES).contains(&self.max_snapshot_bytes)
                && (1..=MAX_CELL_CLOSURE_FILES_V1).contains(&self.max_files),
            "sealed loader finite limits",
        )
    }
}

/// A complete all-or-nothing snapshot of an independently pinned resident
/// closure. Every member is an anonymous, non-executable, sealed kernel file;
/// no source path, store or network capability is retained. The original
/// resident borrow prevents switching or eviction through safe Rust while the
/// bundle is live. No payload `Arc` escapes.
///
/// Native descriptors remain CLOEXEC. The real process owner must explicitly
/// arrange any cross-process handoff and retain its original deadline,
/// cancellation, generation, resource and FinalUse gates. An explicit `dup` or
/// mapping can outlive a borrowed descriptor, so dropping this bundle does not
/// certify reclamation of every downstream reference or authorize a refund.
///
/// ```compile_fail
/// # #[cfg(target_os = "linux")]
/// # fn example() {
/// use std::{sync::atomic::AtomicBool, time::Instant};
/// use trnm_data_availability::cell::*;
/// fn evict_during_handoff(
///     pool: &mut CellResidencyV1, expected: &CellLoaderContextV1,
///     limits: CellSealedLoaderLimitsV1, deadline: Instant, cancelled: &AtomicBool,
/// ) {
///     let bundle = pool.seal_declared_loader(expected, limits, deadline, cancelled).unwrap();
///     pool.evict(expected.closure_id).unwrap();
///     let _file = bundle.file("base.bin", CellFileRoleV1::Base).unwrap();
/// }
/// # }
/// ```
pub struct CellSealedLoaderBundleV1<'a> {
    resident: &'a ResidentClosure,
    files: Vec<SealedMember>,
    snapshot_bytes: u64,
}

struct SealedMember {
    file: File,
    payload_sha512: [u8; 64],
}

impl CellSealedLoaderBundleV1<'_> {
    pub fn closure_id(&self) -> CellDigestV1 {
        self.resident.id
    }

    /// The complete admitted declaration, for comparison with an independently
    /// authenticated full version. A SHA-256 closure ID alone is not promoted
    /// to a stronger content binding by this accessor.
    pub fn closure(&self) -> &CellReleaseClosureV1 {
        &self.resident.closure
    }

    pub fn selected_generation(&self) -> u64 {
        self.resident.closure.selected_generation()
    }

    pub fn loader_profile(&self) -> CellDigestV1 {
        self.resident.closure.loader_profile()
    }

    pub fn snapshot_bytes(&self) -> u64 {
        self.snapshot_bytes
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Match the exact declared portable name and role. There is no path
    /// normalization, directory traversal, current-working-directory lookup,
    /// case-fold fallback, download or partial-bundle fallback.
    pub fn file(
        &self,
        path: &str,
        role: CellFileRoleV1,
    ) -> CellResultV1<CellSealedLoaderFileV1<'_>> {
        let index = self
            .resident
            .closure
            .files()
            .binary_search_by(|declared| declared.path.as_str().cmp(path))
            .map_err(|_| CellErrorV1::Invalid("sealed loader undeclared path"))?;
        let declared = &self.resident.closure.files()[index];
        require(declared.role == role, "sealed loader declared role")?;
        Ok(CellSealedLoaderFileV1 {
            file: &self.files[index].file,
            payload_sha512: self.files[index].payload_sha512,
            declared,
            position: 0,
        })
    }
}

/// Borrowed exact data plus a reader-local cursor. `Read` uses positional I/O,
/// so multiple readers do not share or race the kernel descriptor's offset.
/// Native consumers may use `AsFd`; their descriptor offsets, duplication,
/// mappings, computation and authority remain the real loader owner's work.
/// The constructor's deadline bounds snapshot preparation, not later inference.
pub struct CellSealedLoaderFileV1<'a> {
    file: &'a File,
    payload_sha512: [u8; 64],
    declared: &'a CellClosureFileV1,
    position: u64,
}

impl CellSealedLoaderFileV1<'_> {
    pub fn path(&self) -> &str {
        &self.declared.path
    }

    pub fn role(&self) -> CellFileRoleV1 {
        self.declared.role
    }

    pub fn manifest_id(&self) -> CellDigestV1 {
        self.declared.manifest
    }

    pub fn payload_sha256(&self) -> CellDigestV1 {
        self.declared.payload_sha256
    }

    pub fn payload_bytes(&self) -> u64 {
        self.declared.payload_bytes
    }

    /// Observed SHA-512 of the sealed bytes in the v2 content namespace:
    /// domain || exact u64 big-endian length || complete payload. The full
    /// version verifier must compare this observation with its independently
    /// authenticated pin; the observation itself creates no authority.
    pub fn payload_sha512(&self) -> [u8; 64] {
        self.payload_sha512
    }
}

impl AsFd for CellSealedLoaderFileV1<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl Read for CellSealedLoaderFileV1<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.declared.payload_bytes || output.is_empty() {
            return Ok(0);
        }
        let length =
            (self.declared.payload_bytes - self.position).min(output.len() as u64) as usize;
        let read = self.file.read_at(&mut output[..length], self.position)?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for CellSealedLoaderFileV1<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.declared.payload_bytes) + i128::from(offset),
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sealed loader seek"))?;
        Ok(self.position)
    }
}

impl CellResidencyV1 {
    /// Copy and seal every member of the exact resident closure under one
    /// original absolute deadline and cancellation token. Check the entire
    /// additional payload/file bound before creating the first descriptor.
    /// Re-read and SHA-256 each sealed kernel object before returning any
    /// bundle. Any failure drops all unpublished descriptors and leaves the
    /// resident pool, selection and usage untouched. No mutable file fallback
    /// is provided when NOEXEC_SEAL or immutable seals are unavailable.
    pub fn seal_declared_loader<'a>(
        &'a self,
        expected: &CellLoaderContextV1,
        limits: CellSealedLoaderLimitsV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<CellSealedLoaderBundleV1<'a>> {
        checkpoint(deadline, cancelled)?;
        limits.validate()?;
        let resident = self.resident(expected)?;
        require(
            resident.payload_bytes <= limits.max_snapshot_bytes
                && resident.files.len() <= limits.max_files
                && resident.files.len() == resident.closure.files().len(),
            "sealed loader snapshot budget",
        )?;
        checkpoint(deadline, cancelled)?;
        let mut files = Vec::with_capacity(resident.files.len());
        for (source, declared) in resident.files.iter().zip(resident.closure.files()) {
            checkpoint(deadline, cancelled)?;
            require(
                source.path == declared.path
                    && source.role == declared.role
                    && source.manifest_id == declared.manifest
                    && source.payload_sha256 == declared.payload_sha256,
                "sealed loader resident declaration",
            )?;
            let mut file = File::from(
                memfd_create(
                    "trnm-cell-declared-data-v1",
                    MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL,
                )
                .map_err(io::Error::from)?,
            );
            let mut written = 0u64;
            for chunk in &source.chunks {
                for block in chunk.chunks(COPY_BYTES) {
                    checkpoint(deadline, cancelled)?;
                    require(
                        block.len() as u64 <= declared.payload_bytes.saturating_sub(written),
                        "sealed loader payload length",
                    )?;
                    file.write_all(block)?;
                    written += block.len() as u64;
                    checkpoint(deadline, cancelled)?;
                }
            }
            require(
                written == declared.payload_bytes,
                "sealed loader payload length",
            )?;
            #[cfg(test)]
            tests::at_stage(files.len(), tests::Stage::BeforeSeal, &file);
            checkpoint(deadline, cancelled)?;
            fchmod(&file, Mode::RUSR).map_err(io::Error::from)?;
            fcntl_add_seals(&file, required_seals()).map_err(io::Error::from)?;
            checkpoint(deadline, cancelled)?;
            let payload_sha512 = verify_sealed_member(&file, declared, deadline, cancelled)?;
            // Positional readback did not move the original write cursor.
            // Begin at zero for an explicit first native FD handoff.
            file.rewind()?;
            #[cfg(test)]
            tests::at_stage(files.len(), tests::Stage::Verified, &file);
            checkpoint(deadline, cancelled)?;
            files.push(SealedMember {
                file,
                payload_sha512,
            });
        }
        checkpoint(deadline, cancelled)?;
        Ok(CellSealedLoaderBundleV1 {
            resident,
            files,
            snapshot_bytes: resident.payload_bytes,
        })
    }
}

fn required_seals() -> SealFlags {
    SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL | SealFlags::EXEC
}

fn verify_sealed_member(
    file: &File,
    declared: &CellClosureFileV1,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> CellResultV1<[u8; 64]> {
    let metadata = file.metadata()?;
    require(
        metadata.is_file()
            && metadata.len() == declared.payload_bytes
            && metadata.permissions().mode() & 0o7777 == 0o400
            && fcntl_get_seals(file)
                .map_err(io::Error::from)?
                .contains(required_seals()),
        "sealed loader kernel seals/length",
    )?;
    let mut full = Sha256::new();
    let mut content = Sha512::new();
    content.update(CONTENT_DOMAIN_V2);
    content.update(declared.payload_bytes.to_be_bytes());
    let mut buffer = [0u8; COPY_BYTES];
    let mut offset = 0u64;
    while offset < declared.payload_bytes {
        checkpoint(deadline, cancelled)?;
        let length = (declared.payload_bytes - offset).min(COPY_BYTES as u64) as usize;
        file.read_exact_at(&mut buffer[..length], offset)?;
        full.update(&buffer[..length]);
        content.update(&buffer[..length]);
        offset += length as u64;
        checkpoint(deadline, cancelled)?;
    }
    require(
        <[u8; 32]>::from(full.finalize()) == declared.payload_sha256,
        "sealed loader complete payload digest",
    )?;
    let observed = content.finalize().into();
    checkpoint(deadline, cancelled)?;
    Ok(observed)
}

#[cfg(test)]
mod tests;
