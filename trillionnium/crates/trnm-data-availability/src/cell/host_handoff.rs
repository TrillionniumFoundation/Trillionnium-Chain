//! Fresh CHB1 data handoff between two deliberately distinct runtime contexts.
//!
//! A worker context keeps runtime = worker source SHA-256. A TCV1/TCV2 model
//! context keeps runtime = environment closure ID. This bridge never rewrites
//! either meaning or converts an old CPR2/TCR1 into a CPV4 authorization.
//! It connects current CPV4 authority to actual sealed model/environment data
//! descriptors. Installation, restricted execution, monotone owner state,
//! memory admission, nonce consumption and next-task FinalUse remain owners'
//! responsibilities; a successful binding is not evidence that they executed.

mod fd_handoff;
pub use fd_handoff::{
    CellHostResearchExecutionV1, CellHostResearchParentV1, CellHostResearchQueryV1,
    MAX_CELL_RESEARCH_FD_FILES_V1, MAX_CELL_RESEARCH_FD_HEADER_V1,
};

use std::{
    io::{Cursor, Read},
    time::Instant,
};

use sha2::{Digest, Sha512};

use crate::cell::{
    pq::{CellPqContentExpectationV4, VerifiedCellPqContentV4},
    require, CellContentDigestV2, CellContextV1, CellDigestV1, CellErrorV1, CellFileRoleV1,
    CellResultV1, CellSealedLoaderBundleV1, CellSealedLoaderFileV1, CellVersionCommitmentV1,
    VerifiedCellSealedVersionContentV2,
};

pub const MAX_CELL_HOST_HANDOFF_DESCRIPTOR_BYTES_V1: usize = 2048;

/// Independent host-owner inputs. No field is learned from a discovery reply.
/// The host generation is independent of both declared content generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellHostHandoffDescriptorV1 {
    pub operation: CellDigestV1,
    pub owner_generation: u64,
    pub content: CellContentDigestV2,
    pub version: CellVersionCommitmentV1,
    pub model_closure: CellDigestV1,
    pub environment_closure: CellDigestV1,
    pub model_generation: u64,
    pub environment_generation: u64,
    pub worker_context: CellContextV1,
    pub worker_path: String,
    pub runtime_snapshot_path: String,
    pub runtime_snapshot_sha256: CellDigestV1,
}

impl CellHostHandoffDescriptorV1 {
    pub fn encode(&self) -> CellResultV1<Vec<u8>> {
        self.validate()?;
        let mut wire = Vec::with_capacity(1024);
        wire.extend_from_slice(b"CHB1");
        wire.extend_from_slice(&self.operation);
        wire.extend_from_slice(&self.owner_generation.to_be_bytes());
        wire.extend_from_slice(&self.content);
        wire.extend_from_slice(&self.version);
        wire.extend_from_slice(&self.model_closure);
        wire.extend_from_slice(&self.environment_closure);
        wire.extend_from_slice(&self.model_generation.to_be_bytes());
        wire.extend_from_slice(&self.environment_generation.to_be_bytes());
        wire.push(self.worker_context.family.len() as u8);
        wire.extend_from_slice(self.worker_context.family.as_bytes());
        for digest in [
            self.worker_context.base,
            self.worker_context.parent,
            self.worker_context.tokenizer,
            self.worker_context.layout,
            self.worker_context.runtime,
        ] {
            wire.extend_from_slice(&digest);
        }
        for path in [&self.worker_path, &self.runtime_snapshot_path] {
            wire.extend_from_slice(&(path.len() as u16).to_be_bytes());
            wire.extend_from_slice(path.as_bytes());
        }
        wire.extend_from_slice(&self.runtime_snapshot_sha256);
        require(
            wire.len() <= MAX_CELL_HOST_HANDOFF_DESCRIPTOR_BYTES_V1,
            "host handoff descriptor size",
        )?;
        Ok(wire)
    }

    pub fn commitment(&self) -> CellResultV1<CellContentDigestV2> {
        Ok(descriptor_id(&self.encode()?))
    }

    pub fn decode_pinned(wire: &[u8], expected: CellContentDigestV2) -> CellResultV1<Self> {
        require(
            wire.len() <= MAX_CELL_HOST_HANDOFF_DESCRIPTOR_BYTES_V1,
            "host handoff descriptor size",
        )?;
        require(
            expected != [0; 64] && descriptor_id(wire) == expected,
            "host handoff descriptor pin",
        )?;
        let mut input = Cursor::new(wire);
        require(
            take::<4>(&mut input)? == *b"CHB1",
            "host handoff descriptor version",
        )?;
        let operation = take(&mut input)?;
        let owner_generation = u64::from_be_bytes(take(&mut input)?);
        let content = take(&mut input)?;
        let version = take(&mut input)?;
        let model_closure = take(&mut input)?;
        let environment_closure = take(&mut input)?;
        let model_generation = u64::from_be_bytes(take(&mut input)?);
        let environment_generation = u64::from_be_bytes(take(&mut input)?);
        let family_len = usize::from(take::<1>(&mut input)?[0]);
        require((1..=64).contains(&family_len), "host handoff family size")?;
        let family = text(&mut input, family_len)?;
        let worker_context = CellContextV1 {
            family,
            base: take(&mut input)?,
            parent: take(&mut input)?,
            tokenizer: take(&mut input)?,
            layout: take(&mut input)?,
            runtime: take(&mut input)?,
        };
        let worker_len = usize::from(u16::from_be_bytes(take(&mut input)?));
        require((1..=255).contains(&worker_len), "host handoff path size")?;
        let worker_path = text(&mut input, worker_len)?;
        let snapshot_len = usize::from(u16::from_be_bytes(take(&mut input)?));
        require((1..=255).contains(&snapshot_len), "host handoff path size")?;
        let runtime_snapshot_path = text(&mut input, snapshot_len)?;
        let runtime_snapshot_sha256 = take(&mut input)?;
        require(
            input.position() as usize == wire.len(),
            "host handoff trailing bytes",
        )?;
        let value = Self {
            operation,
            owner_generation,
            content,
            version,
            model_closure,
            environment_closure,
            model_generation,
            environment_generation,
            worker_context,
            worker_path,
            runtime_snapshot_path,
            runtime_snapshot_sha256,
        };
        require(value.encode()? == wire, "host handoff canonical bytes")?;
        Ok(value)
    }

    /// Verify the original current authority and both complete sealed scopes.
    /// No filesystem path is reopened. The caller must admit and seal both
    /// bundles under its existing complete-version RAM and copy reservations.
    pub fn bind_authenticated<'a, 'model, 'environment>(
        &'a self,
        expected_descriptor: CellContentDigestV2,
        authorization: &VerifiedCellPqContentV4<'a>,
        current: &CellPqContentExpectationV4<'_>,
        bundles: (
            &'a CellSealedLoaderBundleV1<'model>,
            &'a CellSealedLoaderBundleV1<'environment>,
        ),
        deadline: Instant,
    ) -> CellResultV1<CellHostHandoffV1<'a, 'model, 'environment>> {
        check(deadline)?;
        require(
            self.commitment()? == expected_descriptor,
            "host handoff descriptor pin",
        )?;
        let content = authorization.content_at(current)?;
        let version = content.version();
        require(
            self.content == content.commitment()
                && self.content == current.content
                && self.version == version.commitment()
                && self.model_closure == version.model().closure().id()
                && self.environment_closure == version.environment().id()
                && self.model_generation == version.model().closure().selected_generation()
                && self.environment_generation == version.environment().selected_generation(),
            "host handoff complete version pins",
        )?;
        let model_context = version.model().closure().release().context();
        require(
            self.worker_context.family == model_context.family
                && self.worker_context.base == model_context.base
                && self.worker_context.parent == model_context.parent
                && self.worker_context.tokenizer == model_context.tokenizer
                && self.worker_context.layout == model_context.layout
                && model_context.runtime == self.environment_closure,
            "host handoff distinct context bindings",
        )?;
        let observed = content.verify_sealed_version(
            bundles.0,
            bundles.1,
            &current.loader,
            self.content,
            deadline,
        )?;
        let worker = observed
            .environment()
            .bundle()
            .file(&self.worker_path, CellFileRoleV1::Configuration)?;
        let snapshot = observed
            .environment()
            .bundle()
            .file(&self.runtime_snapshot_path, CellFileRoleV1::Configuration)?;
        require(
            worker.payload_sha256() == self.worker_context.runtime,
            "host handoff worker source bytes",
        )?;
        require(
            snapshot.payload_sha256() == self.runtime_snapshot_sha256,
            "host handoff runtime snapshot bytes",
        )?;
        check(deadline)?;
        // Recheck the same supplied current view after bounded verification.
        // A fresh monotone view and the real effect boundary remain external.
        authorization.content_at(current)?;
        check(deadline)?;
        Ok(CellHostHandoffV1 {
            descriptor: self,
            observed,
        })
    }

    fn validate(&self) -> CellResultV1<()> {
        self.worker_context.validate()?;
        require(
            [
                self.operation,
                self.model_closure,
                self.environment_closure,
                self.worker_context.runtime,
                self.runtime_snapshot_sha256,
            ]
            .iter()
            .all(|digest| *digest != [0; 32])
                && self.content != [0; 64]
                && self.version != [0; 64]
                && self.owner_generation > 0
                && self.model_generation > 0
                && self.environment_generation > 0,
            "host handoff owner identities",
        )?;
        for path in [&self.worker_path, &self.runtime_snapshot_path] {
            require(
                !path.is_empty()
                    && path.len() <= 255
                    && path
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
                    && path
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != ".."),
                "host handoff portable path",
            )?;
        }
        require(
            self.worker_path != self.runtime_snapshot_path,
            "host handoff distinct runtime inputs",
        )
    }
}

/// Borrowed immutable data descriptors from a specific complete observation.
/// These methods do not start a worker or grant execution/FinalUse authority.
pub struct CellHostHandoffV1<'a, 'model, 'environment> {
    descriptor: &'a CellHostHandoffDescriptorV1,
    observed: VerifiedCellSealedVersionContentV2<'a, 'model, 'environment>,
}

impl CellHostHandoffV1<'_, '_, '_> {
    pub fn descriptor(&self) -> &CellHostHandoffDescriptorV1 {
        self.descriptor
    }

    pub fn worker_source(&self) -> CellResultV1<CellSealedLoaderFileV1<'_>> {
        self.observed
            .environment()
            .bundle()
            .file(&self.descriptor.worker_path, CellFileRoleV1::Configuration)
    }

    pub fn runtime_snapshot(&self) -> CellResultV1<CellSealedLoaderFileV1<'_>> {
        self.observed.environment().bundle().file(
            &self.descriptor.runtime_snapshot_path,
            CellFileRoleV1::Configuration,
        )
    }

    /// Exact declared environment bytes from this authenticated pair. This
    /// grants no permission to execute a script or open an ambient dependency.
    pub fn environment_file(
        &self,
        path: &str,
        role: CellFileRoleV1,
    ) -> CellResultV1<CellSealedLoaderFileV1<'_>> {
        self.observed.environment().bundle().file(path, role)
    }

    pub fn model_file(
        &self,
        path: &str,
        role: CellFileRoleV1,
    ) -> CellResultV1<CellSealedLoaderFileV1<'_>> {
        self.observed.model().bundle().file(path, role)
    }
}

fn check(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "host handoff original deadline")
}

fn descriptor_id(wire: &[u8]) -> CellContentDigestV2 {
    let mut hash = Sha512::new();
    hash.update(b"TRNM/Cell/HostSealedDualContext/v1\0");
    hash.update(wire);
    hash.finalize().into()
}

fn take<const N: usize>(input: &mut Cursor<&[u8]>) -> CellResultV1<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn text(input: &mut Cursor<&[u8]>, length: usize) -> CellResultV1<String> {
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| CellErrorV1::Invalid("host handoff UTF-8"))
}

#[cfg(test)]
mod tests;
