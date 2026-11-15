//! TCC2 is the candidate direct-dependency closure for a TCM2 payload.
//!
//! The top-level ModelManifest commitment covers the entire canonical TCM2 and
//! five explicitly ordered, tagged CCH1 dependency claims. Each dependency is
//! observed from its actual complete bytes under ModelPayload; its role is bound
//! by its fixed slot in TCC2. Old locator aliases are never verification keys.
//!
//! This format requires all five nonempty dependency objects. It does not claim
//! that their declarations exhaust transitive dependencies, establish provenance
//! or ancestry, satisfy a loader, or confer installation/CURRENT/FinalUse rights.

use std::io::Read;

use trnm_protocol::content_commitment::{
    observe_bytes, observe_reader, ContentClaimV1, ContentContextV1, ContentKind,
    ContentReadBudget, ObservedContentV1, CONTENT_CLAIM_BYTES,
};

use super::{
    require, CellContentErrorV2, CellContentManifestV2, CellContextV1, FIXED_BYTES, MAX_CELL_BYTES,
    MAX_CELL_CONTENT_MANIFEST_BYTES_V2,
};

const MAGIC: &[u8; 4] = b"TCC2";
pub const CELL_CONTENT_DEPENDENCY_COUNT_V2: usize = 5;
const SLOT_BYTES: usize = 1 + CONTENT_CLAIM_BYTES;
const OUTSIDE_MANIFEST_BYTES: usize = 8 + CELL_CONTENT_DEPENDENCY_COUNT_V2 * SLOT_BYTES;
pub const MAX_CELL_CONTENT_CLOSURE_BYTES_V2: usize =
    OUTSIDE_MANIFEST_BYTES + MAX_CELL_CONTENT_MANIFEST_BYTES_V2;

/// Canonical dependency positions. All five are required, without silent
/// sorting, omission, duplicate elimination, or a legacy-locator fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CellContentDependencyV2 {
    Base = 1,
    Parent = 2,
    Tokenizer = 3,
    Layout = 4,
    Runtime = 5,
}

impl CellContentDependencyV2 {
    pub const ALL: [Self; CELL_CONTENT_DEPENDENCY_COUNT_V2] = [
        Self::Base,
        Self::Parent,
        Self::Tokenizer,
        Self::Layout,
        Self::Runtime,
    ];

    fn index(self) -> usize {
        self as usize - 1
    }
}

/// An untrusted, canonical direct-dependency declaration until all actual
/// contents pass `verify_readers` under an independently pinned closure claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellContentClosureV2 {
    manifest: CellContentManifestV2,
    dependencies: [ContentClaimV1; CELL_CONTENT_DEPENDENCY_COUNT_V2],
}

impl CellContentClosureV2 {
    /// Construct from actual complete observations in Base, Parent, Tokenizer,
    /// Layout, Runtime order. Claims cannot be substituted for observations.
    /// The caller remains responsible for the declared dependency relationships.
    pub fn from_observed_contents(
        legacy_metadata: CellContextV1,
        payload: &ObservedContentV1,
        dependencies: [&ObservedContentV1; CELL_CONTENT_DEPENDENCY_COUNT_V2],
    ) -> Result<Self, CellContentErrorV2> {
        let value = Self {
            manifest: CellContentManifestV2::from_observed_payload(legacy_metadata, payload)?,
            dependencies: dependencies.map(|observation| observation.claim().clone()),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn manifest(&self) -> &CellContentManifestV2 {
        &self.manifest
    }

    pub fn dependency_claim(&self, role: CellContentDependencyV2) -> &ContentClaimV1 {
        &self.dependencies[role.index()]
    }

    pub fn validate(&self) -> Result<(), CellContentErrorV2> {
        self.manifest.validate()?;
        let expected_profile = self.manifest.payload_claim().context().profile_id();
        for dependency in &self.dependencies {
            require(
                dependency.context().kind() == ContentKind::ModelPayload,
                "dependency purpose",
            )?;
            require(
                dependency.context().profile_id() == expected_profile,
                "dependency profile",
            )?;
            require(
                (1..=MAX_CELL_BYTES).contains(&dependency.content_len()),
                "dependency size",
            )?;
        }
        Ok(())
    }

    /// Exact wire: TCC2, BE32 TCM2 length, complete TCM2 bytes, five fixed
    /// (U8 role, 213-byte CCH1) slots. No trailing bytes or absent slots exist.
    pub fn encode(&self) -> Vec<u8> {
        let manifest = self.manifest.encode();
        let mut out = Vec::with_capacity(OUTSIDE_MANIFEST_BYTES + manifest.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        out.extend_from_slice(&manifest);
        for role in CellContentDependencyV2::ALL {
            out.push(role as u8);
            out.extend_from_slice(&self.dependency_claim(role).encode());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellContentErrorV2> {
        require(
            (OUTSIDE_MANIFEST_BYTES + FIXED_BYTES + 1..=MAX_CELL_CONTENT_CLOSURE_BYTES_V2)
                .contains(&bytes.len()),
            "closure length",
        )?;
        require(&bytes[..4] == MAGIC, "closure version")?;
        let manifest_len = u32::from_be_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| CellContentErrorV2::Invalid("closure manifest length"))?,
        ) as usize;
        require(
            (FIXED_BYTES + 1..=MAX_CELL_CONTENT_MANIFEST_BYTES_V2).contains(&manifest_len)
                && bytes.len() == OUTSIDE_MANIFEST_BYTES + manifest_len,
            "closure exact coverage",
        )?;
        let manifest = CellContentManifestV2::decode(&bytes[8..8 + manifest_len])?;
        let mut dependencies = Vec::with_capacity(CELL_CONTENT_DEPENDENCY_COUNT_V2);
        let mut at = 8 + manifest_len;
        for role in CellContentDependencyV2::ALL {
            require(bytes[at] == role as u8, "closure canonical role order")?;
            at += 1;
            dependencies.push(ContentClaimV1::decode(
                &bytes[at..at + CONTENT_CLAIM_BYTES],
            )?);
            at += CONTENT_CLAIM_BYTES;
        }
        let value = Self {
            manifest,
            dependencies: dependencies
                .try_into()
                .map_err(|_| CellContentErrorV2::Invalid("closure dependency coverage"))?,
        };
        value.validate()?;
        require(value.encode() == bytes, "canonical closure encoding")?;
        Ok(value)
    }

    /// Observe the complete closure *declaration* under the independently
    /// selected ModelManifest context. This alone never re-reads its contents
    /// and cannot create a `CellContentClosureReadbackV2`.
    pub fn observe_closure(
        &self,
        context: &ContentContextV1,
        budget: &mut ContentReadBudget,
    ) -> Result<ObservedContentV1, CellContentErrorV2> {
        self.validate()?;
        self.manifest.check_manifest_context(context)?;
        Ok(observe_bytes(context, budget, &self.encode())?)
    }

    /// Verify an independently pinned full closure claim, the actual complete
    /// model payload, then Base/Parent/Tokenizer/Layout/Runtime actual bytes.
    /// Every read shares one reservation budget; any failure returns no closure
    /// readback and refunds none of the earlier reservations.
    ///
    /// Each dependency has its own complete, top-level-pinned instance and
    /// generation. Role changes require a different closure claim. Time limits,
    /// source stability, owner freshness, and irreversible effects belong to
    /// their existing owners. No old locator can satisfy any content read.
    pub fn verify_readers<R: Read + ?Sized>(
        &self,
        expected_closure: &ContentClaimV1,
        budget: &mut ContentReadBudget,
        payload_reader: &mut R,
        dependency_readers: [&mut dyn Read; CELL_CONTENT_DEPENDENCY_COUNT_V2],
    ) -> Result<CellContentClosureReadbackV2, CellContentErrorV2> {
        let closure = self.observe_closure(expected_closure.context(), budget)?;
        expected_closure.verify(&closure)?;
        let payload_claim = self.manifest.payload_claim();
        let payload = observe_reader(
            payload_claim.context(),
            budget,
            payload_claim.content_len(),
            payload_reader,
        )?;
        payload_claim.verify(&payload)?;
        let mut dependencies = Vec::with_capacity(CELL_CONTENT_DEPENDENCY_COUNT_V2);
        for (claim, reader) in self.dependencies.iter().zip(dependency_readers) {
            let observation = observe_reader(claim.context(), budget, claim.content_len(), reader)?;
            claim.verify(&observation)?;
            dependencies.push(observation);
        }
        Ok(CellContentClosureReadbackV2 {
            closure,
            payload,
            dependencies: dependencies
                .try_into()
                .map_err(|_| CellContentErrorV2::Invalid("closure readback coverage"))?,
        })
    }
}

/// A pinned closure and all six actual content objects were completely read
/// and matched. Private construction and no deserializer prevent a metadata-only
/// or TCM2-only observation from being promoted to this stronger readback type.
/// The observations can be joined to CPQ1 mathematical signature verification;
/// they still provide no authority to install, execute, or select CURRENT.
///
/// ```compile_fail
/// use trnm_data_availability::cell::{CellContentClosureReadbackV2, CellContentReadbackV2};
/// fn promote_payload_only(value: CellContentReadbackV2) -> CellContentClosureReadbackV2 {
///     value
/// }
/// ```
#[derive(Debug)]
pub struct CellContentClosureReadbackV2 {
    closure: ObservedContentV1,
    payload: ObservedContentV1,
    dependencies: [ObservedContentV1; CELL_CONTENT_DEPENDENCY_COUNT_V2],
}

impl CellContentClosureReadbackV2 {
    pub fn closure_observation(&self) -> &ObservedContentV1 {
        &self.closure
    }

    pub fn payload_observation(&self) -> &ObservedContentV1 {
        &self.payload
    }

    pub fn dependency_observation(&self, role: CellContentDependencyV2) -> &ObservedContentV1 {
        &self.dependencies[role.index()]
    }
}

#[cfg(test)]
mod tests;
