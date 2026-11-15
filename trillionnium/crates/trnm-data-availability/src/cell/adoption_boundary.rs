//! An operator-pinned boundary for model-data choices. It cannot authorize
//! software, protocol, fee or Root changes, or execute a declared environment.

use sha2::{Digest, Sha512};

use super::{
    require, CellDigestV1, CellErrorV1, CellFileRoleV1, CellManifestV1, CellResultV1,
    CellVersionCommitmentV1, CellVersionManifestV1, MAX_CELL_BYTES,
};

/// Independently supplied current execution identities. These are comparison
/// pins, not an attestation of a host. The real execution owner must obtain
/// them from its protected configuration and continue to enforce current
/// authorization, withdrawal and FinalUse at the actual effect boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellExecutionBoundaryV1 {
    pub network: CellDigestV1,
    pub consensus: CellDigestV1,
    pub fees: CellDigestV1,
    pub root_authority: CellDigestV1,
    pub node_software: CellDigestV1,
    pub protocol_configuration: CellDigestV1,
}

impl CellExecutionBoundaryV1 {
    fn pins(&self) -> [CellDigestV1; 6] {
        [
            self.network,
            self.consensus,
            self.fees,
            self.root_authority,
            self.node_software,
            self.protocol_configuration,
        ]
    }

    fn validate(&self) -> CellResultV1<()> {
        require(
            self.pins().iter().all(|pin| *pin != [0; 32]),
            "adoption nonzero execution boundary",
        )
    }
}

/// A fixed model-data surface derived from an independently approved anchor.
/// Candidate bytes cannot expand it. Only explicitly listed Base, Adapter and
/// Router payloads may vary. Tokenizer, preprocessor, configuration, path/role
/// mappings, dependency edges, loader profile and the entire environment stay
/// pinned. A different boundary requires separate operator authorization and
/// a fresh owner namespace; no candidate or decision updates this value.
///
/// The original loader must still parse safe tensor/data formats. This byte
/// contract does not make arbitrary pickle, scripts or model-supplied code
/// safe to execute, nor does a file's declared role authenticate its contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellModelUpdateBoundaryV1 {
    anchor: CellVersionManifestV1,
    mutable_roles: Vec<CellFileRoleV1>,
    execution: CellExecutionBoundaryV1,
    max_model_payload_bytes: u64,
    max_model_chunks: u64,
}

impl CellModelUpdateBoundaryV1 {
    pub fn new(
        anchor: &CellVersionManifestV1,
        mutable_roles: Vec<CellFileRoleV1>,
        execution: CellExecutionBoundaryV1,
        max_model_payload_bytes: u64,
        max_model_chunks: u64,
    ) -> CellResultV1<Self> {
        anchor.validate()?;
        execution.validate()?;
        require(
            mutable_roles.len() <= 3
                && mutable_roles.windows(2).all(|pair| pair[0] < pair[1])
                && mutable_roles.iter().all(|role| {
                    matches!(
                        role,
                        CellFileRoleV1::Base | CellFileRoleV1::Adapter | CellFileRoleV1::Router
                    )
                }),
            "adoption canonical model-data roles",
        )?;
        require(
            (1..=MAX_CELL_BYTES).contains(&max_model_payload_bytes)
                && (1..=8_388_608).contains(&max_model_chunks),
            "adoption finite model budget",
        )?;
        let value = Self {
            anchor: anchor.clone(),
            mutable_roles,
            execution,
            max_model_payload_bytes,
            max_model_chunks,
        };
        value.verify_version(anchor)?;
        Ok(value)
    }

    pub fn digest(&self) -> CellVersionCommitmentV1 {
        let mut hash = Sha512::new();
        hash.update(b"trnm.cell-model-update-boundary.v1\0");
        let anchor = self.anchor.encode();
        hash.update((anchor.len() as u64).to_be_bytes());
        hash.update(anchor);
        hash.update((self.mutable_roles.len() as u64).to_be_bytes());
        for role in &self.mutable_roles {
            hash.update([*role as u8]);
        }
        for pin in self.execution.pins() {
            hash.update(pin);
        }
        hash.update(self.max_model_payload_bytes.to_be_bytes());
        hash.update(self.max_model_chunks.to_be_bytes());
        hash.finalize().into()
    }

    pub fn anchor_commitment(&self) -> CellVersionCommitmentV1 {
        self.anchor.commitment()
    }

    pub fn verify_execution(&self, current: &CellExecutionBoundaryV1) -> CellResultV1<()> {
        current.validate()?;
        require(
            current == &self.execution,
            "adoption execution boundary changed",
        )
    }

    pub fn verify_version(&self, candidate: &CellVersionManifestV1) -> CellResultV1<()> {
        candidate.validate()?;
        require(
            candidate.environment() == self.anchor.environment(),
            "adoption environment change requires separate authorization",
        )?;
        let anchor = self.anchor.model().closure();
        let next = candidate.model().closure();
        let old_context = anchor.release().context();
        let next_context = next.release().context();
        require(
            old_context.family == next_context.family
                && old_context.base == next_context.base
                && old_context.tokenizer == next_context.tokenizer
                && old_context.layout == next_context.layout
                && old_context.runtime == next_context.runtime
                && anchor.loader_profile() == next.loader_profile(),
            "adoption fixed model interface",
        )?;
        require(
            anchor.roots() == next.roots() && anchor.files().len() == next.files().len(),
            "adoption fixed dependency graph",
        )?;
        let mut payload_bytes = 0_u64;
        let mut chunks = 0_u64;
        for (old_file, next_file) in anchor.files().iter().zip(next.files()) {
            require(
                old_file.path == next_file.path
                    && old_file.role == next_file.role
                    && old_file.dependencies == next_file.dependencies,
                "adoption fixed file mapping",
            )?;
            let next_manifest = manifest(candidate, next_file.manifest)?;
            if !self.mutable_roles.contains(&old_file.role) {
                let old_manifest = manifest(&self.anchor, old_file.manifest)?;
                // Manifest locators also bind the model parent. Compare all
                // unchanged payload/chunk identities, not that changing locator.
                require(
                    old_file.payload_sha256 == next_file.payload_sha256
                        && old_file.payload_bytes == next_file.payload_bytes
                        && old_manifest.chunk_bytes() == next_manifest.chunk_bytes()
                        && old_manifest.chunks() == next_manifest.chunks(),
                    "adoption protected data changed",
                )?;
            }
            payload_bytes = payload_bytes
                .checked_add(next_file.payload_bytes)
                .ok_or(CellErrorV1::Invalid("adoption payload overflow"))?;
            chunks = chunks
                .checked_add(next_manifest.chunks().len() as u64)
                .ok_or(CellErrorV1::Invalid("adoption chunk overflow"))?;
        }
        require(
            payload_bytes <= self.max_model_payload_bytes && chunks <= self.max_model_chunks,
            "adoption model budget",
        )
    }
}

fn manifest(version: &CellVersionManifestV1, id: CellDigestV1) -> CellResultV1<&CellManifestV1> {
    version
        .manifests()
        .binary_search_by_key(&id, CellManifestV1::id)
        .map(|index| &version.manifests()[index])
        .map_err(|_| CellErrorV1::Invalid("adoption manifest coverage"))
}

#[cfg(test)]
pub(crate) mod tests;
