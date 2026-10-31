//! Opt-in XOR recovery for *verified* Cell Swarm chunks. This is local byte
//! recovery only: not networking, independent custody, PQ identity, license,
//! model installation, FinalUse, or production consensus.
//! Both the base manifest and this parity plan require independent owner pins.
use sha2::{Digest, Sha256};

use crate::{
    CellSwarmAssemblerV0, CellSwarmDigestV0, CellSwarmErrorV0, CellSwarmManifestV0,
    VerifiedCellSwarmBytesV0,
};

pub const MAX_CELL_SWARM_XOR_WIDTH_V0: u16 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellSwarmXorErrorV0 {
    InvalidPlan,
    IncorrectPin,
    InvalidParity,
    MissingParity,
    TooManyMissing,
    Chunk(CellSwarmErrorV0),
}

impl From<CellSwarmErrorV0> for CellSwarmXorErrorV0 {
    fn from(error: CellSwarmErrorV0) -> Self {
        Self::Chunk(error)
    }
}

fn digest(tag: &[u8], parts: &[&[u8]]) -> CellSwarmDigestV0 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-swarm.xor.v0\0");
    hash.update((tag.len() as u32).to_be_bytes());
    hash.update(tag);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn parity_digest(
    manifest_id: CellSwarmDigestV0,
    group: usize,
    bytes: &[u8],
) -> CellSwarmDigestV0 {
    digest(
        b"parity-shard",
        &[&manifest_id, &(group as u32).to_be_bytes(), bytes],
    )
}

/// The parity plan commits to the original immutable manifest and *ordered*
/// parity-shard identities. It does not provide a storage-provider signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellSwarmXorDescriptorV0 {
    pub manifest_id: CellSwarmDigestV0,
    pub group_width: u16,
    pub parity_hashes: Vec<CellSwarmDigestV0>,
}

fn descriptor_id(descriptor: &CellSwarmXorDescriptorV0) -> CellSwarmDigestV0 {
    let mut hashes = Vec::with_capacity(descriptor.parity_hashes.len() * 32);
    for hash in &descriptor.parity_hashes {
        hashes.extend_from_slice(hash);
    }
    digest(
        b"parity-plan",
        &[
            &descriptor.manifest_id,
            &descriptor.group_width.to_be_bytes(),
            &(descriptor.parity_hashes.len() as u32).to_be_bytes(),
            &hashes,
        ],
    )
}

fn check_descriptor(
    manifest: &CellSwarmManifestV0,
    descriptor: &CellSwarmXorDescriptorV0,
) -> Result<(), CellSwarmXorErrorV0> {
    let width = usize::from(descriptor.group_width);
    if width < 2
        || descriptor.group_width > MAX_CELL_SWARM_XOR_WIDTH_V0
        || descriptor.manifest_id != manifest.id()
        || descriptor.manifest_id == [0; 32]
    {
        return Err(CellSwarmXorErrorV0::InvalidPlan);
    }
    let expected = manifest.descriptor().chunk_hashes.len().div_ceil(width);
    if descriptor.parity_hashes.len() != expected
        || descriptor.parity_hashes.iter().any(|hash| *hash == [0; 32])
    {
        return Err(CellSwarmXorErrorV0::InvalidPlan);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct CellSwarmXorPlanV0 {
    descriptor: CellSwarmXorDescriptorV0,
    id: CellSwarmDigestV0,
}

impl CellSwarmXorPlanV0 {
    /// Producer-only helper: creates parity from a previously verified full
    /// Cell. The returned ID is not itself an authorized publication or pin.
    pub fn from_verified_bytes(
        manifest: &CellSwarmManifestV0,
        verified: &VerifiedCellSwarmBytesV0,
        group_width: u16,
    ) -> Result<(Self, Vec<Vec<u8>>), CellSwarmXorErrorV0> {
        if manifest.id() == [0; 32] || verified.manifest_id() != manifest.id() {
            return Err(CellSwarmXorErrorV0::IncorrectPin);
        }
        if !(2..=MAX_CELL_SWARM_XOR_WIDTH_V0).contains(&group_width) {
            return Err(CellSwarmXorErrorV0::InvalidPlan);
        }
        let chunk_size = manifest.descriptor().chunk_bytes as usize;
        let chunks: Vec<&[u8]> = verified.bytes().chunks(chunk_size).collect();
        if chunks.len() != manifest.descriptor().chunk_hashes.len() {
            return Err(CellSwarmXorErrorV0::InvalidPlan);
        }
        let mut parity_hashes = Vec::new();
        let mut parity_chunks = Vec::new();
        for (group, stripe) in chunks.chunks(usize::from(group_width)).enumerate() {
            let size = stripe.iter().map(|part| part.len()).max().unwrap_or(0);
            let mut parity = vec![0u8; size];
            for part in stripe {
                for (dst, byte) in parity.iter_mut().zip(part.iter()) {
                    *dst ^= *byte;
                }
            }
            parity_hashes.push(parity_digest(manifest.id(), group, &parity));
            parity_chunks.push(parity);
        }
        let descriptor = CellSwarmXorDescriptorV0 {
            manifest_id: manifest.id(),
            group_width,
            parity_hashes,
        };
        check_descriptor(manifest, &descriptor)?;
        let id = descriptor_id(&descriptor);
        Ok((Self { descriptor, id }, parity_chunks))
    }

    /// Consumer-side parse: BOTH expected identifiers must be supplied from
    /// independently trusted owners. Hash matching is not authorization.
    pub fn from_descriptor(
        manifest: &CellSwarmManifestV0,
        independently_pinned_manifest_id: CellSwarmDigestV0,
        descriptor: CellSwarmXorDescriptorV0,
        independently_pinned_plan_id: CellSwarmDigestV0,
    ) -> Result<Self, CellSwarmXorErrorV0> {
        if independently_pinned_manifest_id == [0; 32]
            || independently_pinned_plan_id == [0; 32]
            || independently_pinned_manifest_id != manifest.id()
        {
            return Err(CellSwarmXorErrorV0::IncorrectPin);
        }
        check_descriptor(manifest, &descriptor)?;
        let id = descriptor_id(&descriptor);
        if id != independently_pinned_plan_id {
            return Err(CellSwarmXorErrorV0::IncorrectPin);
        }
        Ok(Self { descriptor, id })
    }

    pub fn id(&self) -> CellSwarmDigestV0 {
        self.id
    }

    pub fn descriptor(&self) -> &CellSwarmXorDescriptorV0 {
        &self.descriptor
    }

    /// Rebuild at most ONE missing chunk per XOR stripe. Every supplied chunk
    /// is checked by the original assembler; every supplied parity has an
    /// independently pinned digest; reconstructed chunks must match the
    /// ORIGINAL content-addressed manifest and the final full-content hash.
    /// Neither provider count nor operator independence is inferred.
    pub fn recover(
        &self,
        manifest: CellSwarmManifestV0,
        independently_pinned_manifest_id: CellSwarmDigestV0,
        independently_pinned_plan_id: CellSwarmDigestV0,
        chunks: &[Option<&[u8]>],
        parity: &[Option<&[u8]>],
    ) -> Result<VerifiedCellSwarmBytesV0, CellSwarmXorErrorV0> {
        if independently_pinned_manifest_id == [0; 32]
            || independently_pinned_plan_id == [0; 32]
            || independently_pinned_manifest_id != manifest.id()
            || self.descriptor.manifest_id != manifest.id()
            || independently_pinned_plan_id != self.id
        {
            return Err(CellSwarmXorErrorV0::IncorrectPin);
        }
        check_descriptor(&manifest, &self.descriptor)?;
        let count = manifest.descriptor().chunk_hashes.len();
        if chunks.len() != count || parity.len() != self.descriptor.parity_hashes.len() {
            return Err(CellSwarmXorErrorV0::InvalidPlan);
        }

        let chunk_width = manifest.descriptor().chunk_bytes as usize;
        let total = manifest.descriptor().total_bytes as usize;
        let group_width = usize::from(self.descriptor.group_width);
        let expected_len = |index: usize| (total - index * chunk_width).min(chunk_width);
        let mut assembler =
            CellSwarmAssemblerV0::new(manifest, independently_pinned_manifest_id)?;

        // Reject corrupt already-present data first. Missing data never
        // upgrades the authenticated manifest into an untrusted source.
        for (index, data) in chunks.iter().enumerate() {
            if let Some(data) = data {
                assembler.offer(index, data)?;
            }
        }
        for group in 0..parity.len() {
            let start = group * group_width;
            let end = (start + group_width).min(count);
            let expected_parity_len = (start..end).map(&expected_len).max().unwrap_or(0);
            if let Some(bytes) = parity[group] {
                if bytes.len() != expected_parity_len
                    || parity_digest(independently_pinned_manifest_id, group, bytes)
                        != self.descriptor.parity_hashes[group]
                {
                    return Err(CellSwarmXorErrorV0::InvalidParity);
                }
            }
            let missing: Vec<usize> = (start..end).filter(|index| chunks[*index].is_none()).collect();
            if missing.len() > 1 {
                return Err(CellSwarmXorErrorV0::TooManyMissing);
            }
            if let Some(&missing_index) = missing.first() {
                let parity_bytes = parity[group].ok_or(CellSwarmXorErrorV0::MissingParity)?;
                let mut recovered = parity_bytes.to_vec();
                for original in chunks.iter().take(end).skip(start).flatten() {
                    for (dst, byte) in recovered.iter_mut().zip(original.iter()) {
                        *dst ^= *byte;
                    }
                }
                let size = expected_len(missing_index);
                if recovered[size..].iter().any(|byte| *byte != 0) {
                    return Err(CellSwarmXorErrorV0::InvalidParity);
                }
                assembler.offer(missing_index, &recovered[..size])?;
            }
        }
        Ok(assembler.finish()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        CellSwarmManifestV0,
        VerifiedCellSwarmBytesV0,
        CellSwarmXorPlanV0,
        Vec<Vec<u8>>,
    ) {
        let data = b"abcdefghijklmnopqrstuvwxy";
        let manifest =
            CellSwarmManifestV0::from_bytes([1; 32], [2; 32], [3; 32], 4, data).unwrap();
        let mut assembler = CellSwarmAssemblerV0::new(manifest.clone(), manifest.id()).unwrap();
        for (index, part) in data.chunks(4).enumerate() {
            assembler.offer(index, part).unwrap();
        }
        let verified = assembler.finish().unwrap();
        let (plan, parity) =
            CellSwarmXorPlanV0::from_verified_bytes(&manifest, &verified, 3).unwrap();
        (manifest, verified, plan, parity)
    }

    #[test]
    fn one_missing_per_stripe_recovers_even_short_tail() {
        let (manifest, verified, plan, parity) = fixture();
        let pinned_plan = CellSwarmXorPlanV0::from_descriptor(
            &manifest,
            manifest.id(),
            plan.descriptor().clone(),
            plan.id(),
        ).unwrap();
        let mut chunks: Vec<Option<&[u8]>> = verified.bytes().chunks(4).map(Some).collect();
        chunks[1] = None;
        chunks[4] = None;
        chunks[6] = None;
        let supplied: Vec<Option<&[u8]>> = parity.iter().map(|part| Some(part.as_slice())).collect();
        let recovered = pinned_plan.recover(manifest.clone(), manifest.id(), plan.id(), &chunks, &supplied).unwrap();
        assert_eq!(recovered.bytes(), verified.bytes());
        assert_eq!(recovered.manifest_id(), manifest.id());
    }

    #[test]
    fn wrong_owner_pin_and_cross_release_substitution_reject() {
        let (manifest, verified, plan, parity) = fixture();
        let chunks: Vec<Option<&[u8]>> = verified.bytes().chunks(4).map(Some).collect();
        let supplied: Vec<Option<&[u8]>> = parity.iter().map(|part| Some(part.as_slice())).collect();
        let mut other_pin = plan.id();
        other_pin[0] ^= 1;
        assert!(matches!(
            plan.recover(manifest.clone(), manifest.id(), other_pin, &chunks, &supplied),
            Err(CellSwarmXorErrorV0::IncorrectPin)
        ));
        let different = CellSwarmManifestV0::from_bytes(
            [9; 32], [2; 32], [3; 32], 4, verified.bytes()
        ).unwrap();
        assert!(matches!(
            plan.recover(different.clone(), different.id(), plan.id(), &chunks, &supplied),
            Err(CellSwarmXorErrorV0::IncorrectPin)
        ));
        assert!(matches!(
            CellSwarmXorPlanV0::from_descriptor(&manifest, manifest.id(), plan.descriptor().clone(), other_pin),
            Err(CellSwarmXorErrorV0::IncorrectPin)
        ));
    }

    #[test]
    fn bad_or_missing_parity_and_corrupt_known_chunk_fail_closed() {
        let (manifest, verified, plan, parity) = fixture();
        let mut chunks: Vec<Option<&[u8]>> = verified.bytes().chunks(4).map(Some).collect();
        chunks[1] = None;
        let mut supplied: Vec<Option<&[u8]>> = parity.iter().map(|part| Some(part.as_slice())).collect();
        supplied[0] = None;
        assert!(matches!(
            plan.recover(manifest.clone(), manifest.id(), plan.id(), &chunks, &supplied),
            Err(CellSwarmXorErrorV0::MissingParity)
        ));
        let poisoned = vec![9u8; parity[0].len()];
        supplied[0] = Some(poisoned.as_slice());
        assert!(matches!(
            plan.recover(manifest.clone(), manifest.id(), plan.id(), &chunks, &supplied),
            Err(CellSwarmXorErrorV0::InvalidParity)
        ));
        chunks[0] = Some(b"xxxx");
        assert!(matches!(
            plan.recover(manifest.clone(), manifest.id(), plan.id(), &chunks, &supplied),
            Err(CellSwarmXorErrorV0::Chunk(CellSwarmErrorV0::BadChunk))
        ));
    }

    #[test]
    fn two_missing_in_one_stripe_never_confer_verified_bytes() {
        let (manifest, verified, plan, parity) = fixture();
        let mut chunks: Vec<Option<&[u8]>> = verified.bytes().chunks(4).map(Some).collect();
        chunks[0] = None;
        chunks[1] = None;
        let supplied: Vec<Option<&[u8]>> = parity.iter().map(|part| Some(part.as_slice())).collect();
        assert!(matches!(
            plan.recover(manifest.clone(), manifest.id(), plan.id(), &chunks, &supplied),
            Err(CellSwarmXorErrorV0::TooManyMissing)
        ));
    }

    #[test]
    fn malformed_plan_shape_and_missing_external_pins_reject() {
        let (manifest, verified, plan, _parity) = fixture();
        for width in [0, 1, 17, u16::MAX] {
            assert!(matches!(
                CellSwarmXorPlanV0::from_verified_bytes(&manifest, &verified, width),
                Err(CellSwarmXorErrorV0::InvalidPlan)
            ));
        }
        let mut malformed = plan.descriptor().clone();
        malformed.parity_hashes.pop();
        assert!(matches!(
            CellSwarmXorPlanV0::from_descriptor(&manifest, manifest.id(), malformed, plan.id()),
            Err(CellSwarmXorErrorV0::InvalidPlan)
        ));
        assert!(matches!(
            CellSwarmXorPlanV0::from_descriptor(&manifest, [0; 32], plan.descriptor().clone(), plan.id()),
            Err(CellSwarmXorErrorV0::IncorrectPin)
        ));
    }
}
