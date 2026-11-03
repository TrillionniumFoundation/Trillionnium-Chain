//! Immutable model identity around the existing, unchanged TCD1 byte plan.
//! A root is pinned by the release owner. Neither its hash nor a successful
//! fetch supplies publisher authentication, CURRENT selection or FinalUse.

use std::io::{Cursor, Read};

use sha2::{Digest, Sha256};

use super::{
    require, CellDigestV1, CellErrorV1, CellFileRoleV1, CellLoaderContextV1, CellReleaseClosureV1,
    CellResultV1, MAX_CELL_CLOSURE_BYTES_V1,
};

const MAX_PARENTS: usize = 16;
pub const MAX_MODEL_RELEASE_ROOT_BYTES_V1: usize =
    MAX_CELL_CLOSURE_BYTES_V1 + 4 + 4 + 32 + 1 + MAX_PARENTS * 32;

/// TMR1 commits the entire TCD1 closure, an explicit router-roster commitment
/// (including the empty roster), and canonical direct parent release roots.
/// Family, base, parent model, tokenizer, layout, runtime, loader profile and
/// generation remain bound by the embedded original closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellModelReleaseRootV1 {
    closure: CellReleaseClosureV1,
    router: CellDigestV1,
    lineage: Vec<CellDigestV1>,
}

impl CellModelReleaseRootV1 {
    /// Lineage order is canonical. Do not silently sort or deduplicate inputs.
    pub fn new(closure: CellReleaseClosureV1, lineage: Vec<CellDigestV1>) -> CellResultV1<Self> {
        let value = Self {
            router: router_commitment(&closure),
            closure,
            lineage,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn closure(&self) -> &CellReleaseClosureV1 {
        &self.closure
    }

    pub fn router_commitment(&self) -> CellDigestV1 {
        self.router
    }

    pub fn lineage(&self) -> &[CellDigestV1] {
        &self.lineage
    }

    pub fn validate(&self) -> CellResultV1<()> {
        self.closure.validate()?;
        require(
            self.lineage.len() <= MAX_PARENTS,
            "model root lineage count",
        )?;
        require(
            self.lineage.iter().all(|id| *id != [0; 32])
                && self.lineage.windows(2).all(|pair| pair[0] < pair[1]),
            "model root canonical lineage",
        )?;
        require(
            self.router == router_commitment(&self.closure),
            "model root router roster",
        )?;
        require(
            self.encode().len() <= MAX_MODEL_RELEASE_ROOT_BYTES_V1,
            "model root length",
        )
    }

    /// Validate every declared direct parent against actual parent root bytes.
    /// Empty lineage explicitly declares an origin. Transitive ancestry and
    /// authorization still belong to the caller's release/lineage owner.
    pub fn verify_parent_roots(&self, parents: &[Self]) -> CellResultV1<()> {
        self.validate()?;
        require(
            parents.len() == self.lineage.len(),
            "model root parent coverage",
        )?;
        for (expected, parent) in self.lineage.iter().zip(parents) {
            parent.validate()?;
            require(
                parent.id() == *expected
                    && parent.closure.release().context().family
                        == self.closure.release().context().family
                    && parent.closure.selected_generation() < self.closure.selected_generation(),
                "model root parent identity/generation",
            )?;
        }
        Ok(())
    }

    /// Admission of a declared byte plan only. The independent root pin and
    /// original loader context must both match; no use token is returned.
    pub fn verify_for_loader(
        &self,
        pinned: CellDigestV1,
        expected: &CellLoaderContextV1,
    ) -> CellResultV1<()> {
        self.validate()?;
        require(self.id() == pinned, "model root pin")?;
        self.closure.verify_for_loader(expected)
    }

    pub fn encode(&self) -> Vec<u8> {
        let closure = self.closure.encode();
        let mut out = Vec::with_capacity(41 + closure.len() + 32 * self.lineage.len());
        out.extend_from_slice(b"TMR1");
        out.extend_from_slice(&(closure.len() as u32).to_be_bytes());
        out.extend_from_slice(&closure);
        out.extend_from_slice(&self.router);
        out.push(self.lineage.len() as u8);
        for parent in &self.lineage {
            out.extend_from_slice(parent);
        }
        out
    }

    pub fn id(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-model-release-root.v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() <= MAX_MODEL_RELEASE_ROOT_BYTES_V1,
            "model root length",
        )?;
        let mut input = Cursor::new(bytes);
        require(read::<4>(&mut input)? == *b"TMR1", "model root version")?;
        let count = u32::from_be_bytes(read(&mut input)?) as usize;
        require(
            count <= MAX_CELL_CLOSURE_BYTES_V1
                && bytes
                    .len()
                    .checked_sub(8)
                    .is_some_and(|left| left >= count + 33),
            "model root closure length",
        )?;
        let closure = CellReleaseClosureV1::decode(&bytes[8..8 + count])?;
        input.set_position((8 + count) as u64);
        let router = read(&mut input)?;
        let count = usize::from(read::<1>(&mut input)?[0]);
        require(
            count <= MAX_PARENTS
                && (bytes.len() as u64).checked_sub(input.position()) == Some(count as u64 * 32),
            "model root lineage length",
        )?;
        let mut lineage = Vec::with_capacity(count);
        for _ in 0..count {
            lineage.push(read(&mut input)?);
        }
        let value = Self {
            closure,
            router,
            lineage,
        };
        value.validate()?;
        require(value.encode() == bytes, "model root canonical encoding")?;
        Ok(value)
    }
}

fn router_commitment(closure: &CellReleaseClosureV1) -> CellDigestV1 {
    let routers: Vec<_> = closure
        .files()
        .iter()
        .filter(|file| file.role == CellFileRoleV1::Router)
        .collect();
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-model-router-roster.v1\0");
    hash.update((routers.len() as u16).to_be_bytes());
    for router in routers {
        hash.update((router.path.len() as u16).to_be_bytes());
        hash.update(router.path.as_bytes());
        hash.update(router.manifest);
        hash.update(router.payload_sha256);
        hash.update(router.payload_bytes.to_be_bytes());
    }
    hash.finalize().into()
}

fn read<const N: usize>(input: &mut Cursor<&[u8]>) -> CellResultV1<[u8; N]> {
    let mut value = [0; N];
    input.read_exact(&mut value).map_err(CellErrorV1::Io)?;
    Ok(value)
}
