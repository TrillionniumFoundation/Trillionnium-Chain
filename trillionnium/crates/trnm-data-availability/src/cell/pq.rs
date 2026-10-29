//! Versioned PQ publisher authority for a complete content-addressed release.
//! The manifest is signed once; existing chunk digests verify downloaded bytes.
//! These proofs do not establish availability, model quality or FinalUse rights.

use super::{
    discovery::cell_discovery_context_digest, require, CellDigestV1, CellErrorV1,
    CellReleaseManifestV1, CellResultV1,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::{
    ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SPKI_BYTES,
};

pub const CELL_PQ_PROFILE_V2: &str = "cell-pq-v2";
pub const CELL_PQ_RELEASE_BYTES_V2: usize = 200 + ML_DSA_65_SIGNATURE_BYTES;
const RELEASE_DOMAIN: &[u8] = b"TRNM/Cell/Release/ML-DSA-65/v2\0";

/// Supplied by the hosting authority, never learned from the same untrusted
/// advertisement/release. Its lifetime is rechecked for every verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellPqKeyPinV2 {
    pub key_id: CellDigestV1,
    pub generation: u64,
    pub spki: [u8; ML_DSA_65_SPKI_BYTES],
    pub not_before: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}
impl CellPqKeyPinV2 {
    pub fn validate(&self) -> CellResultV1<()> {
        require(
            self.generation > 0 && self.not_before < self.expires_at,
            "PQ Cell key lifetime/generation",
        )?;
        let actual = ml_dsa_65_key_id_from_spki(&self.spki)
            .map_err(|_| CellErrorV1::Invalid("PQ Cell key pin"))?;
        require(actual == self.key_id, "PQ Cell key pin")?;
        Ok(())
    }
    pub fn live_at(&self, now: u64) -> CellResultV1<()> {
        require(
            now >= self.not_before
                && now < self.expires_at
                && self.revoked_at.is_none_or(|at| now < at),
            "PQ Cell key expired/revoked",
        )
    }
}

/// A finite immutable host-pinned authority set, with its digest committed in
/// the new discovery namespace. Reopening with a changed set fails closed;
/// permissionless on-chain key rotation is a separate owner integration gate.
#[derive(Clone)]
pub struct CellPqKeyPinsV2 {
    keys: BTreeMap<CellDigestV1, (CellPqKeyPinV2, Arc<PqNativeVerifier>)>,
    digest: CellDigestV1,
}
impl std::fmt::Debug for CellPqKeyPinsV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellPqKeyPinsV2")
            .field("keys", &self.keys.len())
            .field("digest", &self.digest)
            .finish()
    }
}
impl CellPqKeyPinsV2 {
    pub fn new(pins: Vec<CellPqKeyPinV2>) -> CellResultV1<Self> {
        require(!pins.is_empty() && pins.len() <= 64, "PQ Cell key count")?;
        let mut keys = BTreeMap::new();
        for pin in pins {
            pin.validate()?;
            let verifier = PqNativeVerifier::from_pinned_spki(&pin.spki, pin.key_id)
                .map_err(|_| CellErrorV1::Invalid("PQ Cell key pin"))?;
            require(
                keys.insert(pin.key_id, (pin, Arc::new(verifier))).is_none(),
                "PQ Cell duplicate key",
            )?;
        }
        let mut hash = Sha256::new();
        hash.update(b"TRNM/Cell/PinnedKeys/v2\0");
        hash.update((keys.len() as u32).to_be_bytes());
        for (id, (pin, _)) in &keys {
            hash.update(id);
            hash.update(pin.generation.to_be_bytes());
            hash.update(pin.spki);
            hash.update(pin.not_before.to_be_bytes());
            hash.update(pin.expires_at.to_be_bytes());
            hash.update([u8::from(pin.revoked_at.is_some())]);
            hash.update(pin.revoked_at.unwrap_or(0).to_be_bytes());
        }
        Ok(Self {
            keys,
            digest: hash.finalize().into(),
        })
    }
    /// Canonical bounded public roster, supplied by local authority policy.
    /// This file is never accepted from an advertisement or remote provider.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![b'C', b'P', b'K', b'2', 2, 0x65];
        out.extend((self.keys.len() as u16).to_be_bytes());
        for (pin, _) in self.keys.values() {
            out.extend(pin.key_id);
            out.extend(pin.generation.to_be_bytes());
            out.extend(pin.spki);
            out.extend(pin.not_before.to_be_bytes());
            out.extend(pin.expires_at.to_be_bytes());
            out.push(u8::from(pin.revoked_at.is_some()));
            out.extend(pin.revoked_at.unwrap_or(0).to_be_bytes());
        }
        out
    }
    pub fn decode(wire: &[u8]) -> CellResultV1<Self> {
        require(
            wire.len() >= 8 && wire[..6] == [b'C', b'P', b'K', b'2', 2, 0x65],
            "PQ roster version/algorithm",
        )?;
        let count = usize::from(u16::from_be_bytes([wire[6], wire[7]]));
        require(
            (1..=64).contains(&count) && wire.len() == 8 + 2039 * count,
            "PQ roster count/length",
        )?;
        let mut input = PqInput(&wire[8..]);
        let mut pins = Vec::with_capacity(count);
        for _ in 0..count {
            let key_id = input.take()?;
            let generation = u64::from_be_bytes(input.take()?);
            let spki = input.take()?;
            let not_before = u64::from_be_bytes(input.take()?);
            let expires_at = u64::from_be_bytes(input.take()?);
            let [revoked] = input.take()?;
            let at = u64::from_be_bytes(input.take()?);
            require(
                revoked <= 1 && (revoked == 1 || at == 0),
                "PQ roster revocation encoding",
            )?;
            pins.push(CellPqKeyPinV2 {
                key_id,
                generation,
                spki,
                not_before,
                expires_at,
                revoked_at: (revoked == 1).then_some(at),
            });
        }
        let value = Self::new(pins)?;
        require(value.encode() == wire, "PQ roster canonical order")?;
        Ok(value)
    }
    pub fn pins(&self) -> impl Iterator<Item = &CellPqKeyPinV2> {
        self.keys.values().map(|(pin, _)| pin)
    }
    pub fn digest(&self) -> CellDigestV1 {
        self.digest
    }
    pub(super) fn verify(
        &self,
        key_id: CellDigestV1,
        generation: u64,
        now: u64,
        message: &[u8],
        signature: &[u8],
    ) -> CellResultV1<u64> {
        let (pin, verifier) = self
            .keys
            .get(&key_id)
            .ok_or(CellErrorV1::Invalid("PQ Cell unknown key"))?;
        require(pin.generation == generation, "PQ Cell key generation")?;
        pin.live_at(now)?;
        verifier
            .verify_exact_message(message, signature)
            .map_err(|_| CellErrorV1::Invalid("PQ Cell signature"))?;
        Ok(pin.expires_at.min(pin.revoked_at.unwrap_or(u64::MAX)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellPqReleaseStatementV2 {
    pub network: CellDigestV1,
    pub parameters: CellDigestV1,
    pub release: CellDigestV1,
    pub cell_context: CellDigestV1,
    pub signer_key_id: CellDigestV1,
    pub generation: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub withdrawn: bool,
}
impl CellPqReleaseStatementV2 {
    fn encode(&self) -> CellResultV1<Vec<u8>> {
        require(
            [
                self.network,
                self.parameters,
                self.release,
                self.cell_context,
                self.signer_key_id,
            ]
            .iter()
            .all(|id| *id != [0; 32]),
            "PQ Cell release context",
        )?;
        require(
            self.generation > 0 && self.sequence > 0 && self.issued_at < self.expires_at,
            "PQ Cell release lifetime/sequence",
        )?;
        let mut out = vec![b'C', b'P', b'R', b'2', 2, 0x65, u8::from(self.withdrawn), 0];
        for id in [
            self.network,
            self.parameters,
            self.release,
            self.cell_context,
            self.signer_key_id,
        ] {
            out.extend(id);
        }
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
}

pub struct CellPqReleaseExpectationV2<'a> {
    pub network: CellDigestV1,
    pub parameters: CellDigestV1,
    pub key: &'a CellPqKeyPinV2,
    pub sequence: u64,
    pub now: u64,
}

#[derive(Clone, Debug)]
pub struct CellPqReleaseAuthorizationV2 {
    statement: CellPqReleaseStatementV2,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl CellPqReleaseAuthorizationV2 {
    pub fn sign(
        statement: CellPqReleaseStatementV2,
        key: &PqNativeSigningKey,
    ) -> CellResultV1<Self> {
        require(
            statement.signer_key_id == key.public_key_id(),
            "PQ Cell signing identity",
        )?;
        let signature = key
            .sign_exact_message(&release_message(&statement)?)
            .map_err(|_| CellErrorV1::Invalid("PQ Cell signing"))?;
        Ok(Self {
            statement,
            signature,
        })
    }
    pub fn statement(&self) -> &CellPqReleaseStatementV2 {
        &self.statement
    }
    pub fn encode(&self) -> CellResultV1<Vec<u8>> {
        let mut bytes = self.statement.encode()?;
        bytes.extend(self.signature);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() == CELL_PQ_RELEASE_BYTES_V2,
            "PQ Cell release wire length",
        )?;
        require(
            bytes[..6] == [b'C', b'P', b'R', b'2', 2, 0x65] && bytes[6] <= 1 && bytes[7] == 0,
            "PQ Cell release version/algorithm",
        )?;
        let mut input = PqInput(&bytes[8..]);
        let statement = CellPqReleaseStatementV2 {
            network: input.take()?,
            parameters: input.take()?,
            release: input.take()?,
            cell_context: input.take()?,
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
        require(
            value.encode()? == bytes,
            "PQ Cell release canonical encoding",
        )?;
        Ok(value)
    }
    pub fn verify_at<'a>(
        &self,
        release: &'a CellReleaseManifestV1,
        expected: &CellPqReleaseExpectationV2<'_>,
    ) -> CellResultV1<VerifiedCellPqReleaseV2<'a>> {
        release.validate()?;
        expected.key.validate()?;
        expected.key.live_at(expected.now)?;
        let s = &self.statement;
        require(
            s.network == expected.network
                && s.parameters == expected.parameters
                && s.signer_key_id == expected.key.key_id
                && s.generation == expected.key.generation
                && s.sequence == expected.sequence
                && s.release == release.id()
                && s.cell_context == cell_discovery_context_digest(release.context())?,
            "PQ Cell release owner/context",
        )?;
        require(
            s.issued_at <= expected.now && expected.now < s.expires_at,
            "PQ Cell release expired/future",
        )?;
        let message = release_message(s)?;
        let verifier = PqNativeVerifier::from_pinned_spki(&expected.key.spki, expected.key.key_id)
            .map_err(|_| CellErrorV1::Invalid("PQ Cell release key"))?;
        verifier
            .verify_exact_message(&message, &self.signature)
            .map_err(|_| CellErrorV1::Invalid("PQ Cell release signature"))?;
        require(!s.withdrawn, "PQ Cell release withdrawn")?;
        Ok(VerifiedCellPqReleaseV2 {
            release,
            verified_at: expected.now,
            expires_at: s
                .expires_at
                .min(expected.key.expires_at)
                .min(expected.key.revoked_at.unwrap_or(u64::MAX)),
        })
    }
}

/// Opaque publisher observation. Revalidate its time immediately before use;
/// this does not replace current authority/revocation retrieval by the host.
pub struct VerifiedCellPqReleaseV2<'a> {
    release: &'a CellReleaseManifestV1,
    verified_at: u64,
    expires_at: u64,
}
impl<'a> VerifiedCellPqReleaseV2<'a> {
    pub fn release_at(&self, now: u64) -> CellResultV1<&'a CellReleaseManifestV1> {
        require(
            now >= self.verified_at && now < self.expires_at,
            "PQ Cell verified lifetime",
        )?;
        Ok(self.release)
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
fn release_message(statement: &CellPqReleaseStatementV2) -> CellResultV1<Vec<u8>> {
    let mut message = RELEASE_DOMAIN.to_vec();
    message.extend(statement.encode()?);
    Ok(message)
}
pub(super) struct PqInput<'a>(pub &'a [u8]);
impl PqInput<'_> {
    pub(super) fn take<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        require(self.0.len() >= N, "PQ Cell truncated field")?;
        let result = self.0[..N]
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("PQ Cell field"))?;
        self.0 = &self.0[N..];
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
