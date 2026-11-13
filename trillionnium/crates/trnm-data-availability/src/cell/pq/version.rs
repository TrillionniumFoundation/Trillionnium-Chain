//! CPV3 signs one complete version metadata commitment. CP(R)2 cannot be
//! reinterpreted as CPV3. Current views still come from the real authority owner.

use super::{
    verify_publisher_message, CellPqKeyPinV2, CellPqKeyPinsV2, CellPqReleaseExpectationV2, PqInput,
    PqNativeSigningKey, ML_DSA_65_SIGNATURE_BYTES,
};
use crate::cell::{
    require, CellDigestV1, CellErrorV1, CellResultV1, CellVersionCommitmentV1,
    CellVersionLoaderContextV1, CellVersionManifestV1,
};

pub const CELL_PQ_VERSION_BYTES_V3: usize = 200 + ML_DSA_65_SIGNATURE_BYTES;
const DOMAIN: &[u8] = b"TRNM/Cell/CompleteVersion/ML-DSA-65/v3\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellPqVersionStatementV3 {
    pub network: CellDigestV1,
    pub parameters: CellDigestV1,
    pub version: CellVersionCommitmentV1,
    pub signer_key_id: CellDigestV1,
    pub generation: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub withdrawn: bool,
}

impl CellPqVersionStatementV3 {
    fn encode(&self) -> CellResultV1<Vec<u8>> {
        require(
            [self.network, self.parameters, self.signer_key_id]
                .iter()
                .all(|d| *d != [0; 32])
                && self.version != [0; 64],
            "PQ version identity",
        )?;
        require(
            self.generation > 0 && self.sequence > 0 && self.issued_at < self.expires_at,
            "PQ version lifetime/sequence",
        )?;
        let mut out = vec![b'C', b'P', b'V', b'3', 3, 0x65, u8::from(self.withdrawn), 0];
        out.extend(self.network);
        out.extend(self.parameters);
        out.extend(self.version);
        out.extend(self.signer_key_id);
        for value in [
            self.generation,
            self.sequence,
            self.issued_at,
            self.expires_at,
        ] {
            out.extend(value.to_be_bytes());
        }
        Ok(out)
    }
    fn message(&self) -> CellResultV1<Vec<u8>> {
        let mut out = DOMAIN.to_vec();
        out.extend(self.encode()?);
        Ok(out)
    }
}

/// The version pin and both loader views must be independently selected by the
/// owner. Passing an old copied view cannot establish current authorization.
pub struct CellPqVersionExpectationV3<'a> {
    pub authority: CellPqReleaseExpectationV2<'a>,
    pub loader: CellVersionLoaderContextV1<'a>,
}

#[derive(Clone, Debug)]
pub struct CellPqVersionAuthorizationV3 {
    statement: CellPqVersionStatementV3,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl CellPqVersionAuthorizationV3 {
    pub fn sign(
        statement: CellPqVersionStatementV3,
        key: &PqNativeSigningKey,
    ) -> CellResultV1<Self> {
        require(
            statement.signer_key_id == key.public_key_id(),
            "PQ version signing identity",
        )?;
        let signature = key
            .sign_exact_message(&statement.message()?)
            .map_err(|_| CellErrorV1::Invalid("PQ version signing"))?;
        Ok(Self {
            statement,
            signature,
        })
    }
    pub fn statement(&self) -> &CellPqVersionStatementV3 {
        &self.statement
    }
    pub fn encode(&self) -> CellResultV1<Vec<u8>> {
        let mut out = self.statement.encode()?;
        out.extend(self.signature);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() == CELL_PQ_VERSION_BYTES_V3,
            "PQ version wire length",
        )?;
        require(
            bytes[..6] == [b'C', b'P', b'V', b'3', 3, 0x65] && bytes[6] <= 1 && bytes[7] == 0,
            "PQ version profile",
        )?;
        let mut input = PqInput(&bytes[8..]);
        let statement = CellPqVersionStatementV3 {
            network: input.take()?,
            parameters: input.take()?,
            version: input.take()?,
            signer_key_id: input.take()?,
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
        require(value.encode()? == bytes, "PQ version canonical encoding")?;
        Ok(value)
    }
    pub fn verify_at<'a>(
        &self,
        version: &'a CellVersionManifestV1,
        expected: &CellPqVersionExpectationV3<'_>,
    ) -> CellResultV1<VerifiedCellPqVersionV3<'a>> {
        self.verify_with_key_source(version, expected, None)
    }
    /// Reuses only public-key expansion from an independently pinned roster.
    /// A changed expected pin is refused, and each exact signature is rechecked.
    pub fn verify_at_with_pins<'a>(
        &self,
        version: &'a CellVersionManifestV1,
        expected: &CellPqVersionExpectationV3<'_>,
        pins: &CellPqKeyPinsV2,
    ) -> CellResultV1<VerifiedCellPqVersionV3<'a>> {
        self.verify_with_key_source(version, expected, Some(pins))
    }
    fn verify_with_key_source<'a>(
        &self,
        version: &'a CellVersionManifestV1,
        expected: &CellPqVersionExpectationV3<'_>,
        pins: Option<&CellPqKeyPinsV2>,
    ) -> CellResultV1<VerifiedCellPqVersionV3<'a>> {
        version.verify_for_loader(&expected.loader)?;
        let authority = &expected.authority;
        authority.key.validate()?;
        authority.key.live_at(authority.now)?;
        let s = &self.statement;
        require(
            s.network == authority.network
                && s.parameters == authority.parameters
                && s.signer_key_id == authority.key.key_id
                && s.generation == authority.key.generation
                && s.sequence == authority.sequence
                && s.version == expected.loader.commitment,
            "PQ version owner context",
        )?;
        require(
            s.issued_at <= authority.now && authority.now < s.expires_at,
            "PQ version lifetime",
        )?;
        verify_publisher_message(
            authority.key,
            pins,
            &s.message()?,
            &self.signature,
            "PQ version key",
            "PQ version signature",
        )?;
        require(!s.withdrawn, "PQ version withdrawn")?;
        Ok(VerifiedCellPqVersionV3 {
            version,
            statement: s.clone(),
            verified_at: authority.now,
            expires_at: s
                .expires_at
                .min(authority.key.expires_at)
                .min(authority.key.revoked_at.unwrap_or(u64::MAX)),
        })
    }
}

/// A publisher/metadata observation. This does not establish that bytes are
/// resident, issue CURRENT or grant FinalUse. Use `version.verify_cached` for
/// actual byte readback and the real owner guard for each execution boundary.
/// Public plaintext can still be retained by an adversarial former recipient.
pub struct VerifiedCellPqVersionV3<'a> {
    version: &'a CellVersionManifestV1,
    statement: CellPqVersionStatementV3,
    verified_at: u64,
    expires_at: u64,
}
impl<'a> VerifiedCellPqVersionV3<'a> {
    pub fn version_at(
        &self,
        current: &CellPqVersionExpectationV3<'_>,
    ) -> CellResultV1<&'a CellVersionManifestV1> {
        let authority = &current.authority;
        let key: &CellPqKeyPinV2 = authority.key;
        key.validate()?;
        key.live_at(authority.now)?;
        let s = &self.statement;
        require(
            authority.network == s.network
                && authority.parameters == s.parameters
                && key.key_id == s.signer_key_id
                && key.generation == s.generation
                && authority.sequence == s.sequence
                && current.loader.commitment == s.version,
            "PQ version current authority changed",
        )?;
        require(
            authority.now >= self.verified_at && authority.now < self.expires_at,
            "PQ version verified lifetime",
        )?;
        self.version.verify_for_loader(&current.loader)?;
        Ok(self.version)
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[cfg(test)]
mod tests;
