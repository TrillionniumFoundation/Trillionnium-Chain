//! A complete, explicitly declared model/environment byte plan. This does not
//! discover undeclared runtime dependencies or authorize execution of any file.

pub(in crate::cell) mod network;
pub use network::{
    fetch_complete_version, CellVersionFetchFailureV1, CellVersionFetchObservationV1,
    CellVersionFetchTransportReportV1,
};

use std::{collections::BTreeSet, time::Instant};

use sha2::{Digest, Sha512};

use super::{
    require, CellDigestV1, CellErrorV1, CellFileRoleV1, CellLoaderContextV1, CellManifestV1,
    CellModelReleaseRootV1, CellReleaseClosureV1, CellReleaseLimitsV1, CellResultV1, CellStoreV1,
};

pub const MAX_CELL_VERSION_BYTES_V1: usize = 8 * 1024 * 1024;
pub const MAX_CELL_VERSION_MANIFESTS_V1: usize = 512;
pub type CellVersionCommitmentV1 = [u8; 64];

/// TCV1 includes the full TMR1 model root, a TCD1 environment inventory, and
/// every original TCM1 (including its chunk list). The model runtime pin must
/// equal the environment closure ID. Environment members are opaque data under
/// the Configuration role; their presence never requests a dynamic loader.
///
/// The owner must inventory the actual executable, libraries, configuration,
/// device/ABI requirements and their dependency edges. Hashes cannot detect a
/// dependency that the owner omitted from both its manifest and expected view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionManifestV1 {
    model: CellModelReleaseRootV1,
    environment: CellReleaseClosureV1,
    manifests: Vec<CellManifestV1>,
}

/// Independent owner pins, not values learned from a provider's advertisement.
pub struct CellVersionLoaderContextV1<'a> {
    pub commitment: CellVersionCommitmentV1,
    pub model: &'a CellLoaderContextV1,
    pub environment: &'a CellLoaderContextV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionReadbackV1 {
    pub commitment: CellVersionCommitmentV1,
    pub model_root: CellDigestV1,
    pub environment_closure: CellDigestV1,
    pub manifests: usize,
    /// Actual complete scans, including repeated chunks in different files.
    pub payload_bytes: u64,
    pub chunks: u64,
}

impl CellVersionManifestV1 {
    /// The caller supplies canonical increasing TCM1 ID order. No silent sort,
    /// deduplication or addition of dependencies is performed.
    pub fn new(
        model: CellModelReleaseRootV1,
        environment: CellReleaseClosureV1,
        manifests: Vec<CellManifestV1>,
    ) -> CellResultV1<Self> {
        let value = Self {
            model,
            environment,
            manifests,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn model(&self) -> &CellModelReleaseRootV1 {
        &self.model
    }
    pub fn environment(&self) -> &CellReleaseClosureV1 {
        &self.environment
    }
    pub fn manifests(&self) -> &[CellManifestV1] {
        &self.manifests
    }

    pub fn validate(&self) -> CellResultV1<()> {
        self.model.validate()?;
        self.environment.validate()?;
        require(
            self.model.closure().release().context().runtime == self.environment.id()
                && self.model.closure().release().context().family
                    == self.environment.release().context().family,
            "version environment binding",
        )?;
        require(
            self.environment
                .files()
                .iter()
                .all(|f| f.role == CellFileRoleV1::Configuration),
            "version environment data role",
        )?;
        require(
            !self.manifests.is_empty() && self.manifests.len() <= MAX_CELL_VERSION_MANIFESTS_V1,
            "version manifest count",
        )?;
        let expected: BTreeSet<_> = self
            .model
            .closure()
            .release()
            .cells()
            .iter()
            .chain(self.environment.release().cells())
            .copied()
            .collect();
        require(
            expected.len() == self.manifests.len(),
            "version manifest coverage",
        )?;
        let mut previous = None;
        let mut wire_bytes = 14usize
            .checked_add(self.model.encode().len())
            .and_then(|n| n.checked_add(self.environment.encode().len()))
            .ok_or(CellErrorV1::Invalid("version length"))?;
        for (manifest, id) in self.manifests.iter().zip(expected) {
            manifest.validate()?;
            let actual = manifest.id();
            require(
                actual == id && previous.is_none_or(|p| p < actual),
                "version canonical manifests",
            )?;
            previous = Some(actual);
            let mut matched = false;
            for closure in [self.model.closure(), &self.environment] {
                if closure.release().cells().binary_search(&id).is_ok() {
                    closure.verify_manifest(manifest)?;
                    matched = true;
                }
            }
            require(matched, "version undeclared manifest")?;
            wire_bytes = wire_bytes
                .checked_add(4 + manifest.encode().len())
                .ok_or(CellErrorV1::Invalid("version length"))?;
            require(wire_bytes <= MAX_CELL_VERSION_BYTES_V1, "version length")?;
        }
        Ok(())
    }

    pub fn verify_for_loader(&self, expected: &CellVersionLoaderContextV1<'_>) -> CellResultV1<()> {
        self.validate()?;
        require(
            self.commitment() == expected.commitment,
            "version owner commitment",
        )?;
        self.model.closure().verify_for_loader(expected.model)?;
        self.environment.verify_for_loader(expected.environment)?;
        for (closure, owner) in [
            (self.model.closure(), expected.model),
            (&self.environment, expected.environment),
        ] {
            let count: u64 = self
                .manifests
                .iter()
                .filter(|m| closure.release().cells().binary_search(&m.id()).is_ok())
                .map(|m| m.chunks().len() as u64)
                .sum();
            require(count <= owner.max_chunks, "version owner chunk budget")?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"TCV1".to_vec();
        for value in [self.model.encode(), self.environment.encode()] {
            out.extend((value.len() as u32).to_be_bytes());
            out.extend(value);
        }
        out.extend((self.manifests.len() as u16).to_be_bytes());
        for manifest in &self.manifests {
            let wire = manifest.encode();
            out.extend((wire.len() as u32).to_be_bytes());
            out.extend(wire);
        }
        out
    }

    /// SHA-512 of the entire canonical metadata. Existing TCM1 payload/chunk
    /// digests remain SHA-256. This does not upgrade their collision security or
    /// replace the separate CPQ1 full-content qualification work.
    pub fn commitment(&self) -> CellVersionCommitmentV1 {
        let mut hash = Sha512::new();
        hash.update(b"TRNM/Cell/CompleteVersion/v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(bytes.len() <= MAX_CELL_VERSION_BYTES_V1, "version length")?;
        let mut input = VersionInput(bytes);
        require(input.take(4)? == b"TCV1", "version magic")?;
        let model = CellModelReleaseRootV1::decode(input.framed()?)?;
        let environment = CellReleaseClosureV1::decode(input.framed()?)?;
        let count = u16::from_be_bytes(input.take(2)?.try_into().unwrap()) as usize;
        require(
            (1..=MAX_CELL_VERSION_MANIFESTS_V1).contains(&count),
            "version manifest count",
        )?;
        let mut manifests = Vec::with_capacity(count);
        for _ in 0..count {
            manifests.push(CellManifestV1::decode(input.framed()?)?);
        }
        require(input.0.is_empty(), "version trailing bytes")?;
        let value = Self::new(model, environment, manifests)?;
        require(value.encode() == bytes, "version canonical encoding")?;
        Ok(value)
    }

    /// Re-read every declared manifest and every complete payload from the
    /// actual cache under one aggregate reservation and original deadline.
    /// A metadata match, a completion marker or a set of chunk ACKs is not used
    /// as a substitute. No network, device allocation or execution occurs.
    pub fn verify_cached(
        &self,
        store: &CellStoreV1,
        expected: &CellVersionLoaderContextV1<'_>,
        limits: CellReleaseLimitsV1,
    ) -> CellResultV1<CellVersionReadbackV1> {
        deadline(limits.deadline)?;
        self.verify_for_loader(expected)?;
        let (payload_bytes, chunks) =
            self.manifests
                .iter()
                .try_fold((0u64, 0u64), |(bytes, chunks), m| {
                    Ok::<_, CellErrorV1>((
                        bytes
                            .checked_add(m.size())
                            .ok_or(CellErrorV1::Invalid("version byte overflow"))?,
                        chunks
                            .checked_add(m.chunks().len() as u64)
                            .ok_or(CellErrorV1::Invalid("version chunk overflow"))?,
                    ))
                })?;
        require(
            payload_bytes <= limits.max_payload_bytes && chunks <= limits.max_chunks,
            "version aggregate read budget",
        )?;
        for declared in &self.manifests {
            deadline(limits.deadline)?;
            let actual = store
                .manifest_with_deadline(declared.id(), Some(limits.deadline))?
                .ok_or(CellErrorV1::Unavailable)?;
            require(actual == *declared, "version actual manifest")?;
            store.verify_complete_until(&actual, limits.deadline)?;
            deadline(limits.deadline)?;
        }
        let report = CellVersionReadbackV1 {
            commitment: self.commitment(),
            model_root: self.model.id(),
            environment_closure: self.environment.id(),
            manifests: self.manifests.len(),
            payload_bytes,
            chunks,
        };
        deadline(limits.deadline)?;
        Ok(report)
    }
}

fn deadline(value: Instant) -> CellResultV1<()> {
    require(Instant::now() < value, "version deadline")
}

struct VersionInput<'a>(&'a [u8]);
impl<'a> VersionInput<'a> {
    fn take(&mut self, size: usize) -> CellResultV1<&'a [u8]> {
        require(size <= self.0.len(), "version truncated field")?;
        let (value, tail) = self.0.split_at(size);
        self.0 = tail;
        Ok(value)
    }
    fn framed(&mut self) -> CellResultV1<&'a [u8]> {
        let size = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
        self.take(size)
    }
}

#[cfg(test)]
pub(super) mod tests;
