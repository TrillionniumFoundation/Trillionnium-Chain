//! CPV4 authenticates TCV2 full byte commitments and the full public-key bytes.
//! It does not turn network/parameter locators or the rest of the chain into a
//! whole-system PQ security claim. Current owner views remain external inputs.

use sha2::{Digest, Sha512};

use super::{
    CellPqKeyPinV2, CellPqReleaseExpectationV2, PqInput, PqNativeSigningKey, PqNativeVerifier,
    ML_DSA_65_SIGNATURE_BYTES,
};
use crate::cell::{
    require, CellContentDigestV2, CellContentReadSessionV2, CellContentReadUsageV2, CellDigestV1,
    CellErrorV1, CellResultV1, CellStoreV1, CellVersionContentV2, CellVersionLoaderContextV1,
};

const DOMAIN: &[u8] = b"TRNM/Cell/CompleteVersionContent/ML-DSA-65/v4\0";
pub const CELL_PQ_CONTENT_BYTES_V4: usize = 264 + ML_DSA_65_SIGNATURE_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellPqContentStatementV4 {
    pub network: CellDigestV1,
    pub parameters: CellDigestV1,
    pub content: CellContentDigestV2,
    pub signer_key_id: CellDigestV1,
    pub signer_spki_sha512: CellContentDigestV2,
    pub generation: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub withdrawn: bool,
}
impl CellPqContentStatementV4 {
    pub fn signer_commitment(spki: &[u8]) -> CellContentDigestV2 {
        let mut hash = Sha512::new();
        hash.update(b"TRNM/Cell/ContentSignerSPKI/v4\0");
        hash.update((spki.len() as u64).to_be_bytes());
        hash.update(spki);
        hash.finalize().into()
    }
    fn encode(&self) -> CellResultV1<Vec<u8>> {
        require(
            [self.network, self.parameters, self.signer_key_id]
                .iter()
                .all(|x| *x != [0; 32])
                && self.content != [0; 64]
                && self.signer_spki_sha512 != [0; 64],
            "PQ content identity",
        )?;
        require(
            self.generation > 0 && self.sequence > 0 && self.issued_at < self.expires_at,
            "PQ content lifetime/sequence",
        )?;
        let mut out = vec![b'C', b'P', b'V', b'4', 4, 0x65, u8::from(self.withdrawn), 0];
        out.extend(self.network);
        out.extend(self.parameters);
        out.extend(self.content);
        out.extend(self.signer_key_id);
        out.extend(self.signer_spki_sha512);
        for n in [
            self.generation,
            self.sequence,
            self.issued_at,
            self.expires_at,
        ] {
            out.extend(n.to_be_bytes());
        }
        Ok(out)
    }
    fn message(&self) -> CellResultV1<Vec<u8>> {
        let mut v = DOMAIN.to_vec();
        v.extend(self.encode()?);
        Ok(v)
    }
}

pub struct CellPqContentExpectationV4<'a> {
    pub authority: CellPqReleaseExpectationV2<'a>,
    pub loader: CellVersionLoaderContextV1<'a>,
    /// Chosen independently by the actual owner, never from this response.
    pub content: CellContentDigestV2,
}

#[derive(Clone, Debug)]
pub struct CellPqContentAuthorizationV4 {
    statement: CellPqContentStatementV4,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl CellPqContentAuthorizationV4 {
    pub fn sign(
        statement: CellPqContentStatementV4,
        key: &PqNativeSigningKey,
    ) -> CellResultV1<Self> {
        require(
            statement.signer_key_id == key.public_key_id()
                && statement.signer_spki_sha512
                    == CellPqContentStatementV4::signer_commitment(key.public_spki()),
            "PQ content signing identity",
        )?;
        let signature = key
            .sign_exact_message(&statement.message()?)
            .map_err(|_| CellErrorV1::Invalid("PQ content signing"))?;
        Ok(Self {
            statement,
            signature,
        })
    }
    pub fn statement(&self) -> &CellPqContentStatementV4 {
        &self.statement
    }
    pub fn encode(&self) -> CellResultV1<Vec<u8>> {
        let mut out = self.statement.encode()?;
        out.extend(self.signature);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() == CELL_PQ_CONTENT_BYTES_V4,
            "PQ content wire length",
        )?;
        require(
            bytes[..6] == [b'C', b'P', b'V', b'4', 4, 0x65] && bytes[6] <= 1 && bytes[7] == 0,
            "PQ content namespace",
        )?;
        let mut input = PqInput(&bytes[8..]);
        let statement = CellPqContentStatementV4 {
            network: input.take()?,
            parameters: input.take()?,
            content: input.take()?,
            signer_key_id: input.take()?,
            signer_spki_sha512: input.take()?,
            generation: u64::from_be_bytes(input.take()?),
            sequence: u64::from_be_bytes(input.take()?),
            issued_at: u64::from_be_bytes(input.take()?),
            expires_at: u64::from_be_bytes(input.take()?),
            withdrawn: bytes[6] == 1,
        };
        let value = Self {
            statement,
            signature: input.take()?,
        };
        require(value.encode()? == bytes, "PQ content canonical wire")?;
        Ok(value)
    }

    /// Validates metadata/signature before costly actual bytes. No metadata-only
    /// success type can be passed off as this complete readback observation.
    pub fn verify_cached_at<'a>(
        &self,
        content: &'a CellVersionContentV2,
        store: &CellStoreV1,
        expected: &CellPqContentExpectationV4<'_>,
        session: &mut CellContentReadSessionV2,
    ) -> CellResultV1<VerifiedCellPqContentV4<'a>> {
        require(
            std::time::Instant::now() < session.deadline(),
            "PQ content original deadline",
        )?;
        content.validate()?;
        content.version().verify_for_loader(&expected.loader)?;
        let a = &expected.authority;
        let s = &self.statement;
        a.key.validate()?;
        a.key.live_at(a.now)?;
        check_owner(s, expected)?;
        require(
            s.content == content.commitment(),
            "PQ content actual metadata",
        )?;
        require(
            s.issued_at <= a.now && a.now < s.expires_at,
            "PQ content lifetime",
        )?;
        let verifier = PqNativeVerifier::from_pinned_spki(&a.key.spki, a.key.key_id)
            .map_err(|_| CellErrorV1::Invalid("PQ content key"))?;
        verifier
            .verify_exact_message(&s.message()?, &self.signature)
            .map_err(|_| CellErrorV1::Invalid("PQ content signature"))?;
        require(!s.withdrawn, "PQ content withdrawn")?;
        let observed = content.verify_cached(store, &expected.loader, expected.content, session)?;
        Ok(VerifiedCellPqContentV4 {
            content,
            statement: s.clone(),
            verified_at: a.now,
            expires_at: s
                .expires_at
                .min(a.key.expires_at)
                .min(a.key.revoked_at.unwrap_or(u64::MAX)),
            usage: observed.usage(),
        })
    }
}

/// A time-local complete cache observation. It neither grants FinalUse nor
/// freezes future cache paths; consume bytes through a protected loader and
/// recheck the owner's monotone current state at that owner's effect boundary.
pub struct VerifiedCellPqContentV4<'a> {
    content: &'a CellVersionContentV2,
    statement: CellPqContentStatementV4,
    verified_at: u64,
    expires_at: u64,
    usage: CellContentReadUsageV2,
}
impl<'a> VerifiedCellPqContentV4<'a> {
    pub fn content_at(
        &self,
        current: &CellPqContentExpectationV4<'_>,
    ) -> CellResultV1<&'a CellVersionContentV2> {
        let key: &CellPqKeyPinV2 = current.authority.key;
        key.validate()?;
        key.live_at(current.authority.now)?;
        check_owner(&self.statement, current)?;
        require(
            current.authority.now >= self.verified_at && current.authority.now < self.expires_at,
            "PQ content observed lifetime",
        )?;
        self.content.version().verify_for_loader(&current.loader)?;
        Ok(self.content)
    }
    pub fn usage(&self) -> CellContentReadUsageV2 {
        self.usage
    }
}
fn check_owner(
    s: &CellPqContentStatementV4,
    e: &CellPqContentExpectationV4<'_>,
) -> CellResultV1<()> {
    let a = &e.authority;
    require(
        s.network == a.network
            && s.parameters == a.parameters
            && s.signer_key_id == a.key.key_id
            && s.signer_spki_sha512 == CellPqContentStatementV4::signer_commitment(&a.key.spki)
            && s.generation == a.key.generation
            && s.sequence == a.sequence
            && s.content == e.content,
        "PQ content owner context",
    )
}

#[cfg(test)]
mod tests;
