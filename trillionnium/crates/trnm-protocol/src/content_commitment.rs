//! Candidate full-content commitments. CCH1 does not change CPQ1 profile IDs,
//! legacy encodings, native work, proof transcripts, or any live authorizer.
//!
//! A claim is untrusted data. An observation is created only after reading the
//! exact declared bytes and EOF; it establishes byte equality, not provenance,
//! freshness, durable custody, or permission to execute. Typed subsystem
//! adapters must supply their actual complete content rather than old digests.

use crate::crypto_profile::{BoundCryptoProfile, CryptoProfileId};
use sha2::{Digest, Sha512};
use std::io::{self, Cursor, Read};

const DOMAIN: &[u8] = b"TRNM/CPQ1/FullContent/SHA512/v1\0";
const MAGIC: &[u8; 4] = b"CCH1";
pub const CONTENT_CLAIM_BYTES: usize = 213;
const HEADER_BYTES: usize = CONTENT_CLAIM_BYTES - 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ContentKind {
    StateSnapshot = 1,
    ReleaseArtifact = 2,
    ModelManifest = 3,
    ModelPayload = 4,
    MigrationCheckpoint = 5,
}
impl ContentKind {
    fn decode(value: u8) -> Result<Self, ContentCommitmentError> {
        match value {
            1 => Ok(Self::StateSnapshot),
            2 => Ok(Self::ReleaseArtifact),
            3 => Ok(Self::ModelManifest),
            4 => Ok(Self::ModelPayload),
            5 => Ok(Self::MigrationCheckpoint),
            _ => Err(ContentCommitmentError::Encoding),
        }
    }
}

#[derive(Debug)]
pub enum ContentCommitmentError {
    CandidateOnly,
    InvalidContext,
    Encoding,
    Budget,
    Truncated,
    TrailingBytes,
    Mismatch,
    Io(io::Error),
}
impl std::fmt::Display for ContentCommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "full-content commitment rejected: {self:?}")
    }
}
impl std::error::Error for ContentCommitmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for ContentCommitmentError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Owner-supplied context; construction does not authenticate the owner. A
/// decoded claim also contains this type, with an untrusted declared profile ID.
/// Observation always uses this fixed SHA-512 suite; an ID never negotiates a
/// verifier. The signature join separately requires an independently pinned
/// candidate profile, and must not trust a context received with its content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentContextV1 {
    profile_id: CryptoProfileId,
    kind: ContentKind,
    instance: [u8; 64],
    generation: u64,
}
impl ContentContextV1 {
    pub fn new(
        profile: &BoundCryptoProfile,
        kind: ContentKind,
        instance: [u8; 64],
        generation: u64,
    ) -> Result<Self, ContentCommitmentError> {
        if !profile.profile().is_candidate() {
            return Err(ContentCommitmentError::CandidateOnly);
        }
        if instance == [0; 64] {
            return Err(ContentCommitmentError::InvalidContext);
        }
        Ok(Self {
            profile_id: profile.id(),
            kind,
            instance,
            generation,
        })
    }
    pub fn profile_id(&self) -> CryptoProfileId {
        self.profile_id
    }
    pub fn kind(&self) -> ContentKind {
        self.kind
    }
    pub fn instance(&self) -> &[u8; 64] {
        &self.instance
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    fn header(&self, content_len: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(self.profile_id.as_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.instance);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&content_len.to_be_bytes());
        out
    }
}

/// An expected or received claim. Decoding alone is never content verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentClaimV1 {
    context: ContentContextV1,
    content_len: u64,
    digest: [u8; 64],
}
impl ContentClaimV1 {
    pub fn context(&self) -> &ContentContextV1 {
        &self.context
    }
    pub fn content_len(&self) -> u64 {
        self.content_len
    }
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.context.header(self.content_len);
        out.extend_from_slice(&self.digest);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ContentCommitmentError> {
        if bytes.len() != CONTENT_CLAIM_BYTES || &bytes[..4] != MAGIC {
            return Err(ContentCommitmentError::Encoding);
        }
        let profile_id = CryptoProfileId::from_hex(&hex::encode(&bytes[4..68]))
            .map_err(|_| ContentCommitmentError::Encoding)?;
        let kind = ContentKind::decode(bytes[68])?;
        let instance: [u8; 64] = bytes[69..133].try_into().expect("fixed context");
        if profile_id.as_bytes() == &[0; 64] || instance == [0; 64] {
            return Err(ContentCommitmentError::InvalidContext);
        }
        Ok(Self {
            context: ContentContextV1 {
                profile_id,
                kind,
                instance,
                generation: u64::from_be_bytes(
                    bytes[133..141].try_into().expect("fixed generation"),
                ),
            },
            content_len: u64::from_be_bytes(bytes[141..149].try_into().expect("fixed length")),
            digest: bytes[149..213].try_into().expect("fixed digest"),
        })
    }
    pub fn verify(&self, observed: &ObservedContentV1) -> Result<(), ContentCommitmentError> {
        if self == observed.claim() {
            Ok(())
        } else {
            Err(ContentCommitmentError::Mismatch)
        }
    }
}

/// The bytes returned by a particular complete read, not an immutable file or
/// current authorization. This type has no public constructor or deserializer.
#[derive(Debug)]
pub struct ObservedContentV1 {
    claim: ContentClaimV1,
}
impl ObservedContentV1 {
    pub fn claim(&self) -> &ContentClaimV1 {
        &self.claim
    }
}

/// A caller-owned cumulative read reservation. Declared length plus one EOF
/// probe is charged before reading; errors are never refunded. It is not a
/// CPU deadline, memory measurement, production resource policy, or attestation.
#[derive(Debug)]
pub struct ContentReadBudget {
    max_reads: u64,
    max_bytes: u64,
    reads: u64,
    bytes: u64,
    exhausted: bool,
}
impl ContentReadBudget {
    pub fn new(max_reads: u64, max_bytes: u64) -> Result<Self, ContentCommitmentError> {
        if max_reads == 0 || max_bytes == 0 {
            return Err(ContentCommitmentError::Budget);
        }
        Ok(Self {
            max_reads,
            max_bytes,
            reads: 0,
            bytes: 0,
            exhausted: false,
        })
    }
    pub fn reads_reserved(&self) -> u64 {
        self.reads
    }
    pub fn bytes_reserved(&self) -> u64 {
        self.bytes
    }
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }
    fn reserve(&mut self, declared_len: u64) -> Result<(), ContentCommitmentError> {
        let reads = self.reads.checked_add(1);
        let bytes = declared_len
            .checked_add(1)
            .and_then(|n| self.bytes.checked_add(n));
        if self.exhausted
            || reads.is_none_or(|n| n > self.max_reads)
            || bytes.is_none_or(|n| n > self.max_bytes)
        {
            self.exhausted = true;
            self.reads = self.max_reads;
            self.bytes = self.max_bytes;
            return Err(ContentCommitmentError::Budget);
        }
        self.reads = reads.expect("checked reservation");
        self.bytes = bytes.expect("checked reservation");
        Ok(())
    }
}

pub fn observe_bytes(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    bytes: &[u8],
) -> Result<ObservedContentV1, ContentCommitmentError> {
    observe_reader(context, budget, bytes.len() as u64, &mut Cursor::new(bytes))
}

/// Hash actual reader bytes directly, with fixed memory. A short read, any I/O
/// error (including Interrupted), or any extra byte refuses the entire result.
/// The owner supplies cancellation/deadline and stable-object/provenance checks.
pub fn observe_reader<R: Read + ?Sized>(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    declared_len: u64,
    reader: &mut R,
) -> Result<ObservedContentV1, ContentCommitmentError> {
    budget.reserve(declared_len)?;
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN);
    hasher.update(context.header(declared_len));
    let mut remaining = declared_len;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let requested = remaining.min(buffer.len() as u64) as usize;
        let count = reader.read(&mut buffer[..requested])?;
        if count == 0 {
            return Err(ContentCommitmentError::Truncated);
        }
        if count > requested {
            return Err(ContentCommitmentError::Encoding);
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if reader.read(&mut buffer[..1])? != 0 {
        return Err(ContentCommitmentError::TrailingBytes);
    }
    Ok(ObservedContentV1 {
        claim: ContentClaimV1 {
            context: *context,
            content_len: declared_len,
            digest: hasher.finalize().into(),
        },
    })
}

#[cfg(test)]
mod tests;
