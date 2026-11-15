//! TCV3 binds a finite, fully expanded declared model lineage to actual TCV2
//! content. Each old model ID is only a unique lookup inside the independently
//! pinned complete byte table. A missing parent is never an implicit origin.
//!
//! This is a sequential cache observation. It does not authenticate old history,
//! infer undeclared semantic dependencies, select CURRENT, authorize collection,
//! or grant FinalUse. Existing TCV1/TCV2 formats and owners keep their meanings.

use std::{collections::BTreeMap, time::Instant};

use sha2::{Digest, Sha512};

use super::{
    require, CellContentDigestV2, CellContentReadSessionV2, CellContentReadUsageV2, CellErrorV1,
    CellResultV1, CellRetainedSetOwnerV1, CellRetainedVersionSetV1, CellStoreV1,
    CellVersionCommitmentV1, CellVersionContentV2, MAX_CELL_VERSION_CONTENT_BYTES_V2,
};

pub const MAX_CELL_CONTENT_LINEAGE_BYTES_V3: usize = 32 * 1024 * 1024;
pub const MAX_CELL_CONTENT_LINEAGE_VERSIONS_V3: usize = 16;
const MAX_DEPTH: usize = 16;
const DOMAIN: &[u8] = b"TRNM/Cell/ContentLineageClosure/v3\0";

/// Complete canonical declarations, not evidence of actual bytes or authority.
/// Nodes are in increasing full TCV2 commitment order; roots are strictly
/// increasing indices in that table. Constructors never sort or deduplicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellVersionContentClosureV3 {
    roots: Vec<u16>,
    versions: Vec<CellVersionContentV2>,
}

/// Supplied independently by the current release/retention owner, never copied
/// from untrusted fetched metadata. Roots are the exact selected TCV2 content
/// commitments, in increasing order. All declared ancestry must reach origins;
/// V3 has no implicit external frontier or metadata-only parent exemption.
pub struct CellContentLineagePinV3<'a> {
    pub commitment: CellContentDigestV2,
    pub roots: &'a [CellContentDigestV2],
}

impl CellVersionContentClosureV3 {
    pub fn new(roots: Vec<u16>, versions: Vec<CellVersionContentV2>) -> CellResultV1<Self> {
        let value = Self { roots, versions };
        value.validate()?;
        Ok(value)
    }

    pub fn roots(&self) -> &[u16] {
        &self.roots
    }

    pub fn versions(&self) -> &[CellVersionContentV2] {
        &self.versions
    }

    pub fn root_commitments(&self) -> Vec<CellContentDigestV2> {
        self.roots
            .iter()
            .map(|index| self.versions[usize::from(*index)].commitment())
            .collect()
    }

    pub fn validate(&self) -> CellResultV1<()> {
        require(
            (1..=MAX_CELL_CONTENT_LINEAGE_VERSIONS_V3).contains(&self.versions.len()),
            "content lineage version count",
        )?;
        require(
            !self.roots.is_empty()
                && self.roots.len() <= self.versions.len()
                && self
                    .roots
                    .iter()
                    .all(|r| usize::from(*r) < self.versions.len())
                && self.roots.windows(2).all(|r| r[0] < r[1]),
            "content lineage canonical roots",
        )?;
        let mut previous = None;
        let mut aliases = BTreeMap::new();
        let mut bytes = 8 + self.roots.len() * 2;
        for (index, content) in self.versions.iter().enumerate() {
            content.validate()?;
            let commitment = content.commitment();
            require(
                previous.is_none_or(|old| old < commitment),
                "content lineage canonical versions",
            )?;
            previous = Some(commitment);
            require(
                aliases
                    .insert(content.version().model().id(), index)
                    .is_none(),
                "content lineage ambiguous legacy model alias",
            )?;
            bytes = bytes
                .checked_add(4 + content.encode().len())
                .ok_or(CellErrorV1::Invalid("content lineage wire overflow"))?;
            require(
                bytes <= MAX_CELL_CONTENT_LINEAGE_BYTES_V3,
                "content lineage wire bound",
            )?;
        }
        let mut parents = Vec::with_capacity(self.versions.len());
        for content in &self.versions {
            let model = content.version().model();
            let mut row = Vec::with_capacity(model.lineage().len());
            for alias in model.lineage() {
                let parent = *aliases
                    .get(alias)
                    .ok_or(CellErrorV1::Invalid("content lineage missing parent"))?;
                let actual = self.versions[parent].version().model();
                require(
                    actual.closure().release().context().family
                        == model.closure().release().context().family
                        && actual.closure().selected_generation()
                            < model.closure().selected_generation(),
                    "content lineage parent family/generation",
                )?;
                row.push(parent);
            }
            parents.push(row);
        }
        validate_graph(&parents, &self.roots)
    }

    /// TCV3, BE16 node count, BE16 root count, BE16 root indices, then each
    /// BE32 length and its complete canonical TCV2. The outer SHA-512 binds
    /// actual metadata and every strong payload/chunk claim, not old IDs alone.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"TCV3".to_vec();
        out.extend((self.versions.len() as u16).to_be_bytes());
        out.extend((self.roots.len() as u16).to_be_bytes());
        for root in &self.roots {
            out.extend(root.to_be_bytes());
        }
        for content in &self.versions {
            let bytes = content.encode();
            out.extend((bytes.len() as u32).to_be_bytes());
            out.extend(bytes);
        }
        out
    }

    pub fn commitment(&self) -> CellContentDigestV2 {
        let mut hash = Sha512::new();
        hash.update(DOMAIN);
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() <= MAX_CELL_CONTENT_LINEAGE_BYTES_V3,
            "content lineage wire bound",
        )?;
        let mut input = Input(bytes);
        require(input.take(4)? == b"TCV3", "content lineage namespace")?;
        let count = usize::from(u16::from_be_bytes(input.array()?));
        let roots_count = usize::from(u16::from_be_bytes(input.array()?));
        require(
            (1..=MAX_CELL_CONTENT_LINEAGE_VERSIONS_V3).contains(&count)
                && (1..=count).contains(&roots_count),
            "content lineage declared counts",
        )?;
        let mut roots = Vec::with_capacity(roots_count);
        for _ in 0..roots_count {
            roots.push(u16::from_be_bytes(input.array()?));
        }
        let mut versions = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_be_bytes(input.array()?) as usize;
            require(
                len <= MAX_CELL_VERSION_CONTENT_BYTES_V2,
                "content lineage member bound",
            )?;
            versions.push(CellVersionContentV2::decode(input.take(len)?)?);
        }
        require(input.0.is_empty(), "content lineage trailing bytes")?;
        let value = Self::new(roots, versions)?;
        require(value.encode() == bytes, "content lineage canonical wire")?;
        Ok(value)
    }

    fn check_pin(&self, pin: &CellContentLineagePinV3<'_>) -> CellResultV1<()> {
        require(
            pin.commitment != [0; 64] && self.commitment() == pin.commitment,
            "content lineage independent commitment",
        )?;
        require(
            !pin.roots.is_empty()
                && pin.roots.len() <= MAX_CELL_CONTENT_LINEAGE_VERSIONS_V3
                && pin.roots.iter().all(|root| *root != [0; 64])
                && pin.roots.windows(2).all(|pair| pair[0] < pair[1])
                && self.root_commitments().as_slice() == pin.roots,
            "content lineage independent selected roots",
        )
    }
}

impl CellRetainedVersionSetV1 {
    /// Read every declared ancestor's model and environment through the actual
    /// existing cache and TCV2 verifier. The original retained owner roster and
    /// window, a separate full TCV3 pin, and exact selected roots must all agree
    /// before the first content scan. No expected owner is derived from input.
    ///
    /// Every member and repeated call uses the same caller-owned session. A
    /// failed member keeps prior reservations; no partial successful aggregate
    /// escapes. Repeated files in distinct versions are conservatively scanned
    /// and charged again. The original deadline is cooperative, not preemption.
    pub fn verify_content_lineage_cached<'a>(
        &self,
        content: &'a CellVersionContentClosureV3,
        store: &CellStoreV1,
        owner: &CellRetainedSetOwnerV1<'_>,
        pin: &CellContentLineagePinV3<'_>,
        session: &mut CellContentReadSessionV2,
    ) -> CellResultV1<CellContentLineageReadbackV3<'a>> {
        let started = Instant::now();
        check_deadline(session.deadline())?;
        self.verify_for_owner(owner)?;
        content.validate()?;
        content.check_pin(pin)?;
        require(
            self.entries().len() == content.versions.len(),
            "content lineage exact retained set",
        )?;
        let mut positions = Vec::with_capacity(content.versions.len());
        for member in &content.versions {
            check_deadline(session.deadline())?;
            let position = self
                .entries()
                .binary_search_by_key(&member.version().commitment(), |entry| {
                    entry.version.commitment()
                })
                .map_err(|_| CellErrorV1::Invalid("content lineage unretained version"))?;
            require(
                self.entries()[position].version == *member.version(),
                "content lineage full retained metadata",
            )?;
            positions.push(position);
        }
        for (member, position) in content.versions.iter().zip(positions) {
            member.verify_cached(
                store,
                &owner.versions[position],
                member.commitment(),
                session,
            )?;
        }
        check_deadline(session.deadline())?;
        Ok(CellContentLineageReadbackV3 {
            content,
            retained_commitment: self.commitment(),
            epoch: self.epoch(),
            current_height: owner.current_height,
            usage: session.usage(),
            started,
            finished: Instant::now(),
        })
    }
}

/// All supplied explicit ancestors and their actual TCV2 payload/chunk bytes
/// matched in this sequential observation. No public constructor/deserializer,
/// execution token or persistent-state transition is exposed.
#[derive(Debug)]
pub struct CellContentLineageReadbackV3<'a> {
    content: &'a CellVersionContentClosureV3,
    retained_commitment: CellVersionCommitmentV1,
    epoch: u64,
    current_height: u64,
    usage: CellContentReadUsageV2,
    started: Instant,
    finished: Instant,
}

impl<'a> CellContentLineageReadbackV3<'a> {
    pub fn content(&self) -> &'a CellVersionContentClosureV3 {
        self.content
    }
    pub fn retained_commitment(&self) -> CellVersionCommitmentV1 {
        self.retained_commitment
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn current_height(&self) -> u64 {
        self.current_height
    }
    /// Cumulative reservations in the original caller-owned session.
    pub fn usage(&self) -> CellContentReadUsageV2 {
        self.usage
    }
    pub fn observation_window(&self) -> (Instant, Instant) {
        (self.started, self.finished)
    }
}

fn validate_graph(parents: &[Vec<usize>], roots: &[u16]) -> CellResultV1<()> {
    fn visit(
        index: usize,
        parents: &[Vec<usize>],
        states: &mut [u8],
        heights: &mut [usize],
    ) -> CellResultV1<usize> {
        require(index < parents.len(), "content lineage parent index")?;
        require(states[index] != 1, "content lineage cycle")?;
        if states[index] == 2 {
            return Ok(heights[index]);
        }
        states[index] = 1;
        let mut height = 1;
        for parent in &parents[index] {
            height = height.max(1 + visit(*parent, parents, states, heights)?);
        }
        require(height <= MAX_DEPTH, "content lineage depth")?;
        states[index] = 2;
        heights[index] = height;
        Ok(height)
    }
    let mut states = vec![0; parents.len()];
    let mut heights = vec![0; parents.len()];
    for root in roots {
        visit(usize::from(*root), parents, &mut states, &mut heights)?;
    }
    require(
        states.iter().all(|state| *state == 2),
        "content lineage unreachable version",
    )
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(
        Instant::now() < deadline,
        "content lineage original deadline",
    )
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> CellResultV1<&'a [u8]> {
        require(count <= self.0.len(), "content lineage truncated field")?;
        let (bytes, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("checked field length"))
    }
}

#[cfg(test)]
mod tests;
