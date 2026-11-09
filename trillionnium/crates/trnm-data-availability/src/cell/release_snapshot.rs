//! A single immutable pin for complete version bytes, dense tensor schema and
//! the actual declared composition-rules file. CTS1 is a data plan, not a
//! compatibility proof, loader implementation, CURRENT selection or FinalUse.
//!
//! The real loader must implement the independently selected composition and
//! loader profiles. No opaque profile hash is interpreted as successful
//! composition. Only the existing TMT1 dense safetensors profile is admitted;
//! unknown tensor codecs, quantization and dynamic-loader fallbacks are absent.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use sha2::{Digest, Sha512};

use super::{
    require, CellDigestV1, CellFileRoleV1, CellResidencyConfigV1, CellResidencyUsageV1,
    CellResidencyV1, CellResidentFileV1, CellResidentTensorModelV1, CellResidentVersionV1,
    CellResidentVersionViewV1, CellResultV1, CellTensorModelManifestV1, CellVersionCommitmentV1,
    CellVersionLoaderContextV1, CellVersionManifestV1, MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1,
    MAX_CELL_VERSION_BYTES_V1,
};

pub const MAX_CELL_RELEASE_SNAPSHOT_BYTES_V1: usize =
    46 + MAX_CELL_VERSION_BYTES_V1 + MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1;
pub type CellReleaseSnapshotCommitmentV1 = [u8; 64];

/// Mandatory TMA1 is paired with exactly the same TMR1 already inside TCV1.
/// `composition_file` names a Configuration file in that model closure, so its
/// real bytes, portable path, dependencies and payload digest share this pin.
/// The profile identifies the owner's interpretation of those rules; CTS1 does
/// not execute that interpretation or infer missing tensor/ABI dependencies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseSnapshotV1 {
    version: CellVersionManifestV1,
    tensors: CellTensorModelManifestV1,
    composition_file: u16,
    composition_profile: CellDigestV1,
}

/// Independent current owner expectations. They must not be copied from a
/// provider's `latest` announcement or constructed by trusting received CTS1.
pub struct CellReleaseSnapshotLoaderContextV1<'a> {
    pub snapshot: CellReleaseSnapshotCommitmentV1,
    pub composition_profile: CellDigestV1,
    pub version: CellVersionLoaderContextV1<'a>,
}

impl CellReleaseSnapshotV1 {
    pub fn new(
        version: CellVersionManifestV1,
        tensors: CellTensorModelManifestV1,
        composition_file: u16,
        composition_profile: CellDigestV1,
    ) -> CellResultV1<Self> {
        let value = Self {
            version,
            tensors,
            composition_file,
            composition_profile,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn version(&self) -> &CellVersionManifestV1 {
        &self.version
    }

    pub fn tensors(&self) -> &CellTensorModelManifestV1 {
        &self.tensors
    }

    pub fn composition_file(&self) -> u16 {
        self.composition_file
    }

    pub fn composition_profile(&self) -> CellDigestV1 {
        self.composition_profile
    }

    pub fn validate(&self) -> CellResultV1<()> {
        self.version.validate()?;
        self.tensors.validate()?;
        require(
            self.tensors.root() == self.version.model(),
            "snapshot exact tensor/version model",
        )?;
        require(
            self.composition_profile != [0; 32],
            "snapshot composition profile",
        )?;
        require(
            self.version
                .model()
                .closure()
                .files()
                .get(usize::from(self.composition_file))
                .is_some_and(|file| file.role == CellFileRoleV1::Configuration),
            "snapshot composition rules file",
        )
    }

    pub fn verify_for_loader(
        &self,
        expected: &CellReleaseSnapshotLoaderContextV1<'_>,
    ) -> CellResultV1<()> {
        self.validate()?;
        require(
            self.commitment() == expected.snapshot
                && self.composition_profile == expected.composition_profile,
            "snapshot independent owner pins",
        )?;
        self.version.verify_for_loader(&expected.version)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = b"CTS1".to_vec();
        for bytes in [self.version.encode(), self.tensors.encode()] {
            wire.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            wire.extend_from_slice(&bytes);
        }
        wire.extend_from_slice(&self.composition_file.to_be_bytes());
        wire.extend_from_slice(&self.composition_profile);
        wire
    }

    /// The outer SHA-512 pin does not change the existing inner SHA-256 leaf
    /// commitments or establish system-wide post-quantum collision security.
    pub fn commitment(&self) -> CellReleaseSnapshotCommitmentV1 {
        wire_commitment(&self.encode())
    }

    pub fn decode_pinned(
        wire: &[u8],
        expected: CellReleaseSnapshotCommitmentV1,
    ) -> CellResultV1<Self> {
        require(
            (46..=MAX_CELL_RELEASE_SNAPSHOT_BYTES_V1).contains(&wire.len()),
            "snapshot wire length",
        )?;
        require(
            expected != [0; 64] && wire_commitment(wire) == expected,
            "snapshot wire pin",
        )?;
        let mut input = Input(wire);
        require(input.take(4)? == b"CTS1", "snapshot wire version")?;
        let version = CellVersionManifestV1::decode(input.frame(MAX_CELL_VERSION_BYTES_V1)?)?;
        let tensors = CellTensorModelManifestV1::decode(
            input.frame(MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1)?,
        )?;
        let composition_file = u16::from_be_bytes(input.take(2)?.try_into().unwrap());
        let composition_profile = input.take(32)?.try_into().unwrap();
        require(input.0.is_empty(), "snapshot trailing bytes")?;
        let value = Self::new(version, tensors, composition_file, composition_profile)?;
        require(value.encode() == wire, "snapshot canonical encoding")?;
        Ok(value)
    }
}

/// A complete borrowed task snapshot. Immutable resident allocations and the
/// supplied CTS1 stay borrowed while this handle is live. Data is exposed only
/// through the original task's expiry/cancellation and exact current pins.
/// This is not a host execution or publication capability.
pub struct CellResidentReleaseSnapshotV1<'a> {
    snapshot: &'a CellReleaseSnapshotV1,
    commitment: CellReleaseSnapshotCommitmentV1,
    version: CellResidentVersionV1<'a>,
    tensors: CellResidentTensorModelV1<'a>,
}

/// Paired immutable data from one admitted release, never independently
/// selected model, schema or composition-rule components.
pub struct CellResidentReleaseSnapshotViewV1<'a, 'view> {
    version: CellResidentVersionViewV1<'a>,
    tensors: &'view CellResidentTensorModelV1<'a>,
    composition: &'a CellResidentFileV1,
}

impl<'a, 'view> CellResidentReleaseSnapshotViewV1<'a, 'view> {
    pub fn version(&self) -> CellResidentVersionViewV1<'a> {
        self.version
    }

    pub fn tensors(&self) -> &'view CellResidentTensorModelV1<'a> {
        self.tensors
    }

    pub fn composition(&self) -> &'a CellResidentFileV1 {
        self.composition
    }
}

impl<'a> CellResidentReleaseSnapshotV1<'a> {
    pub fn task_id(&self) -> CellDigestV1 {
        self.version.task_id()
    }

    pub fn commitment(&self) -> CellReleaseSnapshotCommitmentV1 {
        self.commitment
    }

    pub fn version_commitment(&self) -> CellVersionCommitmentV1 {
        self.version.commitment()
    }

    pub fn usage(&self) -> CellResidencyUsageV1 {
        self.version.usage()
    }

    pub fn with_local<'view, T>(
        &'view self,
        task: CellDigestV1,
        current: &CellReleaseSnapshotLoaderContextV1<'_>,
        consume: impl FnOnce(CellResidentReleaseSnapshotViewV1<'a, 'view>) -> T,
    ) -> CellResultV1<T> {
        // Enter the existing owner first: observed expiry/cancellation latches
        // even when a caller simultaneously presents a mismatching CTS1 pin.
        self.version.with_local(task, &current.version, |version| {
            require(
                current.snapshot == self.commitment
                    && current.composition_profile == self.snapshot.composition_profile,
                "snapshot current owner pins",
            )?;
            let composition = &version.model().files()[usize::from(self.snapshot.composition_file)];
            Ok(consume(CellResidentReleaseSnapshotViewV1 {
                version,
                tensors: &self.tensors,
                composition,
            }))
        })?
    }
}

impl CellResidencyV1 {
    /// Admit complete model/environment bytes and parse every declared tensor
    /// container under the same task deadline. Task RAM/reference limits cover
    /// both closures before tensor parsing. No disk/network/device capability
    /// or fresh retry allowance is introduced. Any failure returns no handle
    /// and leaves the resident pool and local selection unchanged.
    pub fn admit_local_release_snapshot<'a>(
        &'a self,
        task: CellDigestV1,
        snapshot: &'a CellReleaseSnapshotV1,
        expected: &CellReleaseSnapshotLoaderContextV1<'_>,
        limits: CellResidencyConfigV1,
        deadline: Instant,
        cancelled: &'a AtomicBool,
    ) -> CellResultV1<CellResidentReleaseSnapshotV1<'a>> {
        require(Instant::now() < deadline, "snapshot admission deadline")?;
        require(
            !cancelled.load(Ordering::Acquire),
            "snapshot admission cancelled",
        )?;
        snapshot.verify_for_loader(expected)?;
        let version = self.admit_local_version(
            task,
            snapshot.version(),
            &expected.version,
            limits,
            deadline,
            cancelled,
        )?;
        // The nested TMA1 pin is derived only after the independent CTS1 pin
        // has checked these exact bytes, never from a peer-selected TMA1.
        let tensors = self.admit_local_tensor_model(
            snapshot.tensors(),
            snapshot.tensors().id(),
            expected.version.model,
            deadline,
            cancelled,
        )?;
        version.with_local(task, &expected.version, |_| ())?;
        Ok(CellResidentReleaseSnapshotV1 {
            snapshot,
            commitment: expected.snapshot,
            version,
            tensors,
        })
    }
}

fn wire_commitment(wire: &[u8]) -> CellReleaseSnapshotCommitmentV1 {
    let mut hash = Sha512::new();
    hash.update(b"TRNM/Cell/TensorReleaseSnapshot/v1\0");
    hash.update(wire);
    hash.finalize().into()
}

struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn take(&mut self, size: usize) -> CellResultV1<&'a [u8]> {
        require(size <= self.0.len(), "snapshot truncated field")?;
        let (value, tail) = self.0.split_at(size);
        self.0 = tail;
        Ok(value)
    }

    fn frame(&mut self, maximum: usize) -> CellResultV1<&'a [u8]> {
        let size = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
        require(size <= maximum, "snapshot frame bound")?;
        self.take(size)
    }
}

#[cfg(test)]
pub(in crate::cell) mod tests;
