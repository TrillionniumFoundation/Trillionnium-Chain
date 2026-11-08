//! Candidate release artifact binding to metadata AND actual complete bytes.
//! RAC1 is independent of the existing bundle, release authority and checkpoint
//! namespaces. SHA-256 fields are retained as legacy labels/consistency checks;
//! all artifact bytes enter the new SHA-512 directly. Referenced source/platform
//! objects, full SBOM/provenance, signer authority and rollback remain separate.

use crate::ArtifactEntryV0;
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read};
use trnm_protocol::content_commitment::{
    observe_reader, ContentClaimV1, ContentCommitmentError, ContentContextV1, ContentKind,
    ContentReadBudget, ObservedContentV1,
};

#[derive(Debug)]
pub enum ReleaseContentError {
    Content(ContentCommitmentError),
    InvalidArtifact,
    LegacyLocatorMismatch,
    FileIdentity,
    Io(io::Error),
}
impl std::fmt::Display for ReleaseContentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "release full-content rejected: {self:?}")
    }
}
impl std::error::Error for ReleaseContentError {}
impl From<ContentCommitmentError> for ReleaseContentError {
    fn from(error: ContentCommitmentError) -> Self {
        Self::Content(error)
    }
}
impl From<io::Error> for ReleaseContentError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn artifact_header(artifact: &ArtifactEntryV0) -> Result<Vec<u8>, ReleaseContentError> {
    artifact
        .validate()
        .map_err(|_| ReleaseContentError::InvalidArtifact)?;
    let mut header = b"RAC1".to_vec();
    for bytes in [&artifact.logical_name, &artifact.media_type] {
        header.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        header.extend_from_slice(bytes);
    }
    header.extend_from_slice(&artifact.size_bytes.to_be_bytes());
    header.push(u8::from(artifact.executable));
    for alias in [
        artifact.content_digest,
        artifact.platform_digest,
        artifact.source_path_digest,
    ] {
        header.extend_from_slice(&alias.0);
    }
    Ok(header)
}

struct LegacyHashReader<'a, R: Read + ?Sized> {
    inner: &'a mut R,
    hash: Sha256,
}
impl<R: Read + ?Sized> Read for LegacyHashReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(out)?;
        if count > out.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reader count"));
        }
        self.hash.update(&out[..count]);
        Ok(count)
    }
}

/// The complete encoded content is RAC1 || full metadata || raw artifact bytes.
/// The caller supplies an independently selected instance/profile/generation.
/// A matching old locator is only a migration consistency check, never origin
/// authentication. A fresh CPQ1 signature must bind the entire returned claim.
pub fn observe_release_artifact_v1<R: Read + ?Sized>(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    artifact: &ArtifactEntryV0,
    reader: &mut R,
) -> Result<ObservedContentV1, ReleaseContentError> {
    if context.kind() != ContentKind::ReleaseArtifact {
        return Err(ReleaseContentError::InvalidArtifact);
    }
    let header = artifact_header(artifact)?;
    let encoded_len = (header.len() as u64)
        .checked_add(artifact.size_bytes)
        .ok_or(ReleaseContentError::InvalidArtifact)?;
    let mut raw = LegacyHashReader {
        inner: reader,
        hash: Sha256::new(),
    };
    let observed = observe_reader(
        context,
        budget,
        encoded_len,
        &mut Cursor::new(header).chain(&mut raw),
    )?;
    let legacy: [u8; 32] = raw.hash.finalize().into();
    if legacy != artifact.content_digest.0 {
        return Err(ReleaseContentError::LegacyLocatorMismatch);
    }
    Ok(observed)
}

pub fn verify_release_artifact_v1<R: Read + ?Sized>(
    expected: &ContentClaimV1,
    budget: &mut ContentReadBudget,
    artifact: &ArtifactEntryV0,
    reader: &mut R,
) -> Result<ObservedContentV1, ReleaseContentError> {
    let observed = observe_release_artifact_v1(expected.context(), budget, artifact, reader)?;
    expected.verify(&observed)?;
    Ok(observed)
}

/// A retained descriptor avoids pathname substitution. Before/after metadata
/// checks detect observed mutation; they do not prove an atomic snapshot against
/// a privileged/same-owner writer. Production use still needs immutable custody.
#[cfg(unix)]
pub fn observe_release_file_v1(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    artifact: &ArtifactEntryV0,
    file: &mut std::fs::File,
) -> Result<ObservedContentV1, ReleaseContentError> {
    use std::io::Seek;
    use std::os::unix::fs::MetadataExt;
    fn identity(m: &std::fs::Metadata) -> (u64, u64, u32, u64, i64, i64, i64, i64) {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
    let before = file.metadata()?;
    if !before.is_file() || before.len() != artifact.size_bytes || file.stream_position()? != 0 {
        return Err(ReleaseContentError::FileIdentity);
    }
    let observed = observe_release_artifact_v1(context, budget, artifact, file)?;
    if identity(&before) != identity(&file.metadata()?) {
        return Err(ReleaseContentError::FileIdentity);
    }
    Ok(observed)
}

#[cfg(test)]
mod tests;
