//! TCV2 binds actual payload and chunk bytes in addition to complete TCV1
//! metadata. The old 32-byte IDs remain locators, never the only content check.
//! This is a local observation, not a loader sandbox, authority or availability
//! certificate. Hashing and SQLite calls are cooperatively deadline bounded.

use std::time::Instant;

use sha2::{Digest, Sha256, Sha512};

use super::{
    require, CellDigestV1, CellErrorV1, CellReleaseLimitsV1, CellResultV1, CellStoreV1,
    CellVersionLoaderContextV1, CellVersionManifestV1, MAX_CELL_VERSION_MANIFESTS_V1,
};

pub const MAX_CELL_VERSION_CONTENT_BYTES_V2: usize = 24 * 1024 * 1024;
pub type CellContentDigestV2 = [u8; 64];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellFileContentV2 {
    manifest: CellDigestV1,
    payload_sha512: CellContentDigestV2,
    chunks_sha512: Vec<CellContentDigestV2>,
}

impl CellFileContentV2 {
    pub fn manifest(&self) -> CellDigestV1 {
        self.manifest
    }
    pub fn payload_sha512(&self) -> CellContentDigestV2 {
        self.payload_sha512
    }
    pub fn chunks_sha512(&self) -> &[CellContentDigestV2] {
        &self.chunks_sha512
    }
}

/// Canonical metadata. Decoding this public value proves no actual readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionContentV2 {
    version: CellVersionManifestV1,
    contents: Vec<CellFileContentV2>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellContentReadUsageV2 {
    pub attempted_scans: u32,
    /// Conservative complete-scan reservations, including failed reads. These
    /// are not physical disk, RSS, device or wall-clock billing measurements.
    pub reserved_payload_bytes: u64,
    pub reserved_chunks: u64,
}

/// One immutable original deadline and cumulative reservation across retries.
/// A failed/corrupt/unavailable read never refunds its complete-scan allowance.
pub struct CellContentReadSessionV2 {
    limits: CellReleaseLimitsV1,
    max_scans: u32,
    usage: CellContentReadUsageV2,
}

impl CellContentReadSessionV2 {
    pub fn new(limits: CellReleaseLimitsV1, max_scans: u32) -> CellResultV1<Self> {
        require(
            limits.max_payload_bytes > 0
                && limits.max_chunks > 0
                && (1..=1024).contains(&max_scans),
            "content finite read budget",
        )?;
        check_deadline(limits.deadline)?;
        Ok(Self {
            limits,
            max_scans,
            usage: CellContentReadUsageV2::default(),
        })
    }
    pub fn usage(&self) -> CellContentReadUsageV2 {
        self.usage
    }
    pub fn deadline(&self) -> Instant {
        self.limits.deadline
    }

    fn reserve(&mut self, version: &CellVersionManifestV1) -> CellResultV1<()> {
        check_deadline(self.limits.deadline)?;
        require(
            self.usage.attempted_scans < self.max_scans,
            "content scan budget",
        )?;
        self.usage.attempted_scans += 1;
        let mut bytes = self.usage.reserved_payload_bytes;
        let mut chunks = self.usage.reserved_chunks;
        for manifest in version.manifests() {
            bytes = bytes
                .checked_add(manifest.size())
                .ok_or(CellErrorV1::Invalid("content byte overflow"))?;
            chunks = chunks
                .checked_add(manifest.chunks().len() as u64)
                .ok_or(CellErrorV1::Invalid("content chunk overflow"))?;
        }
        require(
            bytes <= self.limits.max_payload_bytes && chunks <= self.limits.max_chunks,
            "content cumulative read budget",
        )?;
        self.usage.reserved_payload_bytes = bytes;
        self.usage.reserved_chunks = chunks;
        Ok(())
    }
}

impl CellVersionContentV2 {
    pub fn version(&self) -> &CellVersionManifestV1 {
        &self.version
    }
    pub fn contents(&self) -> &[CellFileContentV2] {
        &self.contents
    }
    pub fn file(&self, manifest: CellDigestV1) -> CellResultV1<&CellFileContentV2> {
        self.contents
            .binary_search_by_key(&manifest, |f| f.manifest)
            .map(|i| &self.contents[i])
            .map_err(|_| CellErrorV1::Invalid("content undeclared file"))
    }

    /// Publisher-side capture, with independently supplied complete metadata
    /// pins. The resulting record must still be independently pinned/signed by
    /// its owner; an untrusted cache cannot choose a consumer's expected root.
    pub fn capture_cached(
        version: &CellVersionManifestV1,
        store: &CellStoreV1,
        expected: &CellVersionLoaderContextV1<'_>,
        session: &mut CellContentReadSessionV2,
    ) -> CellResultV1<Self> {
        check_deadline(session.deadline())?;
        version.verify_for_loader(expected)?;
        session.reserve(version)?;
        let contents = scan(version, store, session.deadline())?;
        let value = Self {
            version: version.clone(),
            contents,
        };
        value.validate()?;
        check_deadline(session.deadline())?;
        Ok(value)
    }

    pub fn validate(&self) -> CellResultV1<()> {
        self.version.validate()?;
        require(
            self.contents.len() == self.version.manifests().len(),
            "content manifest coverage",
        )?;
        let mut size = 10usize
            .checked_add(self.version.encode().len())
            .ok_or(CellErrorV1::Invalid("content wire overflow"))?;
        for (content, manifest) in self.contents.iter().zip(self.version.manifests()) {
            require(
                content.manifest == manifest.id()
                    && content.payload_sha512 != [0; 64]
                    && content.chunks_sha512.len() == manifest.chunks().len()
                    && content.chunks_sha512.iter().all(|x| *x != [0; 64]),
                "content manifest binding",
            )?;
            size = size
                .checked_add(100 + content.chunks_sha512.len() * 64)
                .ok_or(CellErrorV1::Invalid("content wire overflow"))?;
            require(
                size <= MAX_CELL_VERSION_CONTENT_BYTES_V2,
                "content wire bound",
            )?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let metadata = self.version.encode();
        let mut out = b"TCV2".to_vec();
        out.extend((metadata.len() as u32).to_be_bytes());
        out.extend(metadata);
        out.extend((self.contents.len() as u16).to_be_bytes());
        for file in &self.contents {
            out.extend(file.manifest);
            out.extend(file.payload_sha512);
            out.extend((file.chunks_sha512.len() as u32).to_be_bytes());
            for chunk in &file.chunks_sha512 {
                out.extend(chunk);
            }
        }
        out
    }

    pub fn commitment(&self) -> CellContentDigestV2 {
        let mut hash = Sha512::new();
        hash.update(b"TRNM/Cell/CompleteVersionContent/v2\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() <= MAX_CELL_VERSION_CONTENT_BYTES_V2,
            "content wire bound",
        )?;
        let mut input = Input(bytes);
        require(input.take(4)? == b"TCV2", "content wire namespace")?;
        let metadata_len = u32::from_be_bytes(input.array()?) as usize;
        let version = CellVersionManifestV1::decode(input.take(metadata_len)?)?;
        let count = u16::from_be_bytes(input.array()?) as usize;
        require(
            count == version.manifests().len()
                && (1..=MAX_CELL_VERSION_MANIFESTS_V1).contains(&count),
            "content manifest coverage",
        )?;
        let mut contents = Vec::with_capacity(count);
        for manifest in version.manifests() {
            let id = input.array()?;
            let payload_sha512 = input.array()?;
            let chunks = u32::from_be_bytes(input.array()?) as usize;
            require(
                id == manifest.id() && chunks == manifest.chunks().len(),
                "content manifest binding",
            )?;
            require(input.0.len() >= chunks * 64, "content truncated chunks")?;
            let mut chunks_sha512 = Vec::with_capacity(chunks);
            for _ in 0..chunks {
                chunks_sha512.push(input.array()?);
            }
            contents.push(CellFileContentV2 {
                manifest: id,
                payload_sha512,
                chunks_sha512,
            });
        }
        require(input.0.is_empty(), "content trailing bytes")?;
        let value = Self { version, contents };
        value.validate()?;
        require(value.encode() == bytes, "content canonical wire")?;
        Ok(value)
    }

    /// Bind metadata before receive-side chunk checks. This metadata-only view
    /// is distinct from complete actual-byte observations and execution rights.
    pub fn pin_for_owner<'a>(
        &'a self,
        expected: &CellVersionLoaderContextV1<'_>,
        content_pin: CellContentDigestV2,
    ) -> CellResultV1<PinnedCellVersionContentV2<'a>> {
        self.validate()?;
        self.version.verify_for_loader(expected)?;
        require(
            content_pin != [0; 64] && self.commitment() == content_pin,
            "content owner commitment",
        )?;
        Ok(PinnedCellVersionContentV2 { content: self })
    }

    fn verify_chunk(&self, manifest: CellDigestV1, index: usize, bytes: &[u8]) -> CellResultV1<()> {
        let position = self
            .contents
            .binary_search_by_key(&manifest, |f| f.manifest)
            .map_err(|_| CellErrorV1::Invalid("content undeclared file"))?;
        let declared = self.version.manifests()[position]
            .chunks()
            .get(index)
            .ok_or(CellErrorV1::Invalid("content chunk index"))?;
        require(
            bytes.len() == declared.size as usize,
            "content chunk length",
        )?;
        require(
            chunk_digest(bytes) == self.contents[position].chunks_sha512[index],
            "content SHA512 chunk",
        )?;
        super::store::verify_chunk(declared, bytes)
    }

    /// Complete actual readback against an independent 64-byte content pin.
    /// A successful observation is tied to this scan, not future cache bytes.
    pub fn verify_cached<'a>(
        &'a self,
        store: &CellStoreV1,
        expected: &CellVersionLoaderContextV1<'_>,
        content_pin: CellContentDigestV2,
        session: &mut CellContentReadSessionV2,
    ) -> CellResultV1<VerifiedCellVersionContentV2<'a>> {
        self.verify_cached_controlled(store, expected, content_pin, session, &mut || Ok(()))
    }

    /// Keep the original execution owner's checkpoint around each manifest,
    /// chunk read and bounded hashing step. Refusal retains the complete-scan
    /// reservation and returns no verified-content observation. The owner
    /// retains responsibility for cancellation state across separate calls.
    pub fn verify_cached_controlled<'a>(
        &'a self,
        store: &CellStoreV1,
        expected: &CellVersionLoaderContextV1<'_>,
        content_pin: CellContentDigestV2,
        session: &mut CellContentReadSessionV2,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<VerifiedCellVersionContentV2<'a>> {
        content_checkpoint(session.deadline(), checkpoint)?;
        self.validate()?;
        self.version.verify_for_loader(expected)?;
        require(
            content_pin != [0; 64] && self.commitment() == content_pin,
            "content owner commitment",
        )?;
        content_checkpoint(session.deadline(), checkpoint)?;
        session.reserve(&self.version)?;
        content_checkpoint(session.deadline(), checkpoint)?;
        let actual = scan_controlled(&self.version, store, session.deadline(), checkpoint)?;
        require(actual == self.contents, "content actual byte commitments")?;
        content_checkpoint(session.deadline(), checkpoint)?;
        Ok(VerifiedCellVersionContentV2 {
            content: self,
            usage: session.usage(),
        })
    }

    /// Join the independent full content root to the exact sealed objects a
    /// loader will consume. The full closure structure, every file and its
    /// post-seal SHA-512 readback must agree. This avoids a cache-check followed
    /// by an unrelated path reopen. The returned borrow retains those objects;
    /// the real execution owner still supplies its current FinalUse decision.
    #[cfg(target_os = "linux")]
    pub fn verify_sealed_loader<'a, 'pool>(
        &'a self,
        bundle: &'a super::CellSealedLoaderBundleV1<'pool>,
        expected: &CellVersionLoaderContextV1<'_>,
        content_pin: CellContentDigestV2,
        deadline: Instant,
    ) -> CellResultV1<VerifiedCellSealedContentV2<'a, 'pool>> {
        check_deadline(deadline)?;
        self.validate()?;
        self.version.verify_for_loader(expected)?;
        require(
            content_pin != [0; 64] && self.commitment() == content_pin,
            "content owner commitment",
        )?;
        let closure = bundle.closure();
        let scope = if closure == self.version.model().closure() {
            CellSealedContentScopeV2::Model
        } else if closure == self.version.environment() {
            CellSealedContentScopeV2::Environment
        } else {
            return Err(CellErrorV1::Invalid("content sealed full closure"));
        };
        require(
            bundle.file_count() == closure.files().len(),
            "content sealed complete files",
        )?;
        for declared in closure.files() {
            check_deadline(deadline)?;
            let sealed = bundle.file(&declared.path, declared.role)?;
            let content = self.file(declared.manifest)?;
            require(
                sealed.manifest_id() == declared.manifest
                    && sealed.payload_bytes() == declared.payload_bytes
                    && sealed.payload_sha512() == content.payload_sha512,
                "content sealed actual SHA512",
            )?;
        }
        check_deadline(deadline)?;
        Ok(VerifiedCellSealedContentV2 {
            bundle,
            content: self,
            scope,
        })
    }

    /// Both closures are required: one environment bundle or two copies of a
    /// model cannot stand in for the complete declared version.
    #[cfg(target_os = "linux")]
    pub fn verify_sealed_version<'a, 'model, 'environment>(
        &'a self,
        model: &'a super::CellSealedLoaderBundleV1<'model>,
        environment: &'a super::CellSealedLoaderBundleV1<'environment>,
        expected: &CellVersionLoaderContextV1<'_>,
        content_pin: CellContentDigestV2,
        deadline: Instant,
    ) -> CellResultV1<VerifiedCellSealedVersionContentV2<'a, 'model, 'environment>> {
        let model = self.verify_sealed_loader(model, expected, content_pin, deadline)?;
        let environment =
            self.verify_sealed_loader(environment, expected, content_pin, deadline)?;
        require(
            model.scope == CellSealedContentScopeV2::Model
                && environment.scope == CellSealedContentScopeV2::Environment,
            "content complete sealed version scopes",
        )?;
        check_deadline(deadline)?;
        Ok(VerifiedCellSealedVersionContentV2 { model, environment })
    }
}

/// Independently pinned metadata, not a signature or execution grant.
pub struct PinnedCellVersionContentV2<'a> {
    content: &'a CellVersionContentV2,
}
impl PinnedCellVersionContentV2<'_> {
    /// Check the entire original manifest, not only its legacy locator, before
    /// admitting a per-file transfer under this independently selected root.
    pub fn verify_manifest(&self, manifest: &super::CellManifestV1) -> CellResultV1<()> {
        let position = self
            .content
            .version
            .manifests()
            .binary_search_by_key(&manifest.id(), |value| value.id())
            .map_err(|_| CellErrorV1::Invalid("content undeclared file"))?;
        require(
            self.content.version.manifests()[position] == *manifest,
            "content exact pinned manifest",
        )
    }

    /// The owner's expected digest, not an actual-byte observation. Transport
    /// must hash its own complete ordered payload using the TCV2 domain.
    pub fn payload_sha512(&self, manifest: CellDigestV1) -> CellResultV1<CellContentDigestV2> {
        Ok(self.content.file(manifest)?.payload_sha512())
    }

    pub fn verify_chunk(
        &self,
        manifest: CellDigestV1,
        index: usize,
        bytes: &[u8],
    ) -> CellResultV1<()> {
        self.content.verify_chunk(manifest, index, bytes)
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellSealedContentScopeV2 {
    Model,
    Environment,
}

/// Exactly one declared model or environment closure; inspect `scope()`.
#[cfg(target_os = "linux")]
pub struct VerifiedCellSealedContentV2<'a, 'pool> {
    bundle: &'a super::CellSealedLoaderBundleV1<'pool>,
    content: &'a CellVersionContentV2,
    scope: CellSealedContentScopeV2,
}
#[cfg(target_os = "linux")]
impl<'a, 'pool> VerifiedCellSealedContentV2<'a, 'pool> {
    pub fn bundle(&self) -> &'a super::CellSealedLoaderBundleV1<'pool> {
        self.bundle
    }
    pub fn content(&self) -> &'a CellVersionContentV2 {
        self.content
    }
    pub fn scope(&self) -> CellSealedContentScopeV2 {
        self.scope
    }
}

#[cfg(target_os = "linux")]
pub struct VerifiedCellSealedVersionContentV2<'a, 'model, 'environment> {
    model: VerifiedCellSealedContentV2<'a, 'model>,
    environment: VerifiedCellSealedContentV2<'a, 'environment>,
}
#[cfg(target_os = "linux")]
impl<'a, 'model, 'environment> VerifiedCellSealedVersionContentV2<'a, 'model, 'environment> {
    pub fn model(&self) -> &VerifiedCellSealedContentV2<'a, 'model> {
        &self.model
    }
    pub fn environment(&self) -> &VerifiedCellSealedContentV2<'a, 'environment> {
        &self.environment
    }
}

/// Only actual complete byte verification constructs this observation.
pub struct VerifiedCellVersionContentV2<'a> {
    content: &'a CellVersionContentV2,
    usage: CellContentReadUsageV2,
}
impl<'a> VerifiedCellVersionContentV2<'a> {
    pub fn content(&self) -> &'a CellVersionContentV2 {
        self.content
    }
    pub fn usage(&self) -> CellContentReadUsageV2 {
        self.usage
    }
}

fn chunk_digest(bytes: &[u8]) -> CellContentDigestV2 {
    let mut hash = Sha512::new();
    hash.update(b"TRNM/Cell/ChunkContent/v2\0");
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

fn scan(
    version: &CellVersionManifestV1,
    store: &CellStoreV1,
    deadline: Instant,
) -> CellResultV1<Vec<CellFileContentV2>> {
    scan_controlled(version, store, deadline, &mut || Ok(()))
}

fn scan_controlled(
    version: &CellVersionManifestV1,
    store: &CellStoreV1,
    deadline: Instant,
    checkpoint: &mut impl FnMut() -> CellResultV1<()>,
) -> CellResultV1<Vec<CellFileContentV2>> {
    let mut contents = Vec::with_capacity(version.manifests().len());
    for declared in version.manifests() {
        content_checkpoint(deadline, checkpoint)?;
        let actual = store
            .manifest_with_deadline(declared.id(), Some(deadline))?
            .ok_or(CellErrorV1::Unavailable)?;
        content_checkpoint(deadline, checkpoint)?;
        require(actual == *declared, "content actual manifest")?;
        let mut whole = Sha512::new();
        whole.update(b"TRNM/Cell/PayloadContent/v2\0");
        whole.update(declared.size().to_be_bytes());
        let mut legacy = Sha256::new();
        let mut chunks_sha512 = Vec::with_capacity(declared.chunks().len());
        for chunk in declared.chunks() {
            content_checkpoint(deadline, checkpoint)?;
            let bytes = store
                .chunk_with_deadline(chunk.sha256, Some(deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            content_checkpoint(deadline, checkpoint)?;
            require(
                bytes.len() == chunk.size as usize,
                "content actual chunk length",
            )?;
            chunks_sha512.push(chunk_digest(&bytes));
            whole.update(&bytes);
            legacy.update(&bytes);
            content_checkpoint(deadline, checkpoint)?;
        }
        require(
            <[u8; 32]>::from(legacy.finalize()) == declared.payload_sha256(),
            "content legacy full payload",
        )?;
        contents.push(CellFileContentV2 {
            manifest: declared.id(),
            payload_sha512: whole.finalize().into(),
            chunks_sha512,
        });
    }
    content_checkpoint(deadline, checkpoint)?;
    Ok(contents)
}

fn content_checkpoint(
    deadline: Instant,
    checkpoint: &mut impl FnMut() -> CellResultV1<()>,
) -> CellResultV1<()> {
    check_deadline(deadline)?;
    checkpoint()?;
    check_deadline(deadline)
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "content original deadline")
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, n: usize) -> CellResultV1<&'a [u8]> {
        require(n <= self.0.len(), "content truncated field")?;
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
}

#[cfg(test)]
pub(super) mod tests;
