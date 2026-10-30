//! Research-only ML-DSA-65 provider advertisement (PCP2).
//!
//! This is a *cryptographic boundary*, not a production discovery service:
//! CDP1/Ed25519 and its durable SQLite directory are unchanged. The receiver
//! supplies a trusted key, the exact request and a monotonic sequence floor
//! independently of the untrusted advertisement. Callers must also enforce
//! network address scope, high-water persistence and endpoint byte checks.
//! Signature verification grants no Cell custody, release or FinalUse authority.

use ml_dsa::{
    EncodedVerifyingKey, KeyExport, Keypair, MlDsa65, Signature, SignatureEncoding, Signer,
    SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

pub const PQ_CELL_PROVIDER_RECORD_V2_BYTES: usize = 3580;
pub const PQ_CELL_PROVIDER_PUBLIC_KEY_BYTES: usize = 1952;
pub const PQ_CELL_PROVIDER_SIGNATURE_BYTES: usize = 3309;
pub const PQ_CELL_PROVIDER_UNSIGNED_BYTES: usize = 271;
const MAGIC: &[u8; 4] = b"PCP2";
const SIGN_DOMAIN: &[u8] = b"trnm.cell-provider-mldsa65-signature.v2\0";
const KEY_DOMAIN: &[u8] = b"trnm.cell-provider-mldsa65-key.v2\0";
const MAX_TTL_SECONDS: u64 = 300;
const FUTURE_SKEW_SECONDS: u64 = 5;

/// The six owner-pinned 32-byte fields are, in order: discovery namespace,
/// network, parameters, genesis, Cell context digest and manifest digest.
/// Endpoint is the canonical existing 19-byte IP-family/IP/port representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PqCellProviderStatementV2 {
    pub pinned_request: [u8; 192],
    pub endpoint: [u8; 19],
    pub sequence: u64,
    pub issued_unix_seconds: u64,
    pub expires_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPqCellProviderRecordV2 {
    pub statement: PqCellProviderStatementV2,
    /// A digest of a key pinned by the receiver, NOT an identity authority.
    pub signer_key_id: [u8; 32],
    signature: Vec<u8>,
}

/// The caller must get these values from an independent authority and durable
/// replay owner. Passing fields copied from the received record defeats pinning.
pub struct PqCellProviderExpectationV2<'a> {
    pub pinned_request: &'a [u8; 192],
    pub trusted_ml_dsa65_public_key: &'a [u8],
    pub last_accepted_sequence: u64,
    pub now_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqCellProviderErrorV2 {
    WireLengthOrVersion,
    MalformedStatement,
    InvalidPublicKey,
    InvalidSignatureEncoding,
    InvalidSignature,
    UntrustedRequest,
    UntrustedSigner,
    Replay,
    ExpiredOrFuture,
}

/// A verified *hint*, never a capability to retrieve from an arbitrary IP,
/// accept malicious weights, install a model or update consensus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPqCellProviderHintV2 {
    endpoint: [u8; 19],
    sequence: u64,
    expires_unix_seconds: u64,
}

impl VerifiedPqCellProviderHintV2 {
    pub fn endpoint_bytes(&self) -> &[u8; 19] {
        &self.endpoint
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn expires_unix_seconds(&self) -> u64 {
        self.expires_unix_seconds
    }
}

/// This stable key *identifier* is never evidence of possession by itself.
pub fn pq_cell_provider_key_id_v2(
    pinned_ml_dsa65_public_key: &[u8],
) -> Result<[u8; 32], PqCellProviderErrorV2> {
    if pinned_ml_dsa65_public_key.len() != PQ_CELL_PROVIDER_PUBLIC_KEY_BYTES {
        return Err(PqCellProviderErrorV2::InvalidPublicKey);
    }
    let mut h = Sha256::new();
    h.update(KEY_DOMAIN);
    h.update(pinned_ml_dsa65_public_key);
    Ok(h.finalize().into())
}

impl SignedPqCellProviderRecordV2 {
    pub fn sign(
        statement: PqCellProviderStatementV2,
        key: &SigningKey<MlDsa65>,
    ) -> Result<Self, PqCellProviderErrorV2> {
        let pk = key.verifying_key().to_bytes();
        let mut item = Self {
            statement,
            signer_key_id: pq_cell_provider_key_id_v2(&pk)?,
            signature: vec![0; PQ_CELL_PROVIDER_SIGNATURE_BYTES],
        };
        item.check_shape()?;
        let signature: Signature<MlDsa65> = key.sign(&item.signing_bytes());
        item.signature = signature.to_vec();
        Ok(item)
    }

    fn check_shape(&self) -> Result<(), PqCellProviderErrorV2> {
        let s = &self.statement;
        if !s
            .pinned_request
            .chunks_exact(32)
            .all(|digest| digest.iter().any(|byte| *byte != 0))
            || s.sequence == 0
            || s.issued_unix_seconds == 0
            || s.expires_unix_seconds
                .checked_sub(s.issued_unix_seconds)
                .is_none_or(|ttl| ttl == 0 || ttl > MAX_TTL_SECONDS)
            || self.signer_key_id == [0; 32]
        {
            return Err(PqCellProviderErrorV2::MalformedStatement);
        }
        let ep = &s.endpoint;
        let ip_canonical = match ep[0] {
            4 => ep[1..13].iter().all(|byte| *byte == 0),
            6 => !(ep[1..11].iter().all(|byte| *byte == 0)
                && ep[11..13] == [255, 255]),
            _ => false,
        };
        if !ip_canonical || ep[17..19] == [0, 0] {
            return Err(PqCellProviderErrorV2::MalformedStatement);
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PQ_CELL_PROVIDER_UNSIGNED_BYTES);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.statement.pinned_request);
        out.extend_from_slice(&self.signer_key_id);
        out.extend_from_slice(&self.statement.endpoint);
        out.extend_from_slice(&self.statement.sequence.to_be_bytes());
        out.extend_from_slice(&self.statement.issued_unix_seconds.to_be_bytes());
        out.extend_from_slice(&self.statement.expires_unix_seconds.to_be_bytes());
        out
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGN_DOMAIN.len() + PQ_CELL_PROVIDER_UNSIGNED_BYTES);
        out.extend_from_slice(SIGN_DOMAIN);
        out.extend_from_slice(&self.unsigned_bytes());
        out
    }

    /// Fixed-size wire. 8 records plus count fit the existing 32 KiB response
    /// envelope (8*3580+1=28641), but CDP1 transport MUST NOT parse PCP2.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Parse is untrusted data. Always call verify_for_pinned_context.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, PqCellProviderErrorV2> {
        if bytes.len() != PQ_CELL_PROVIDER_RECORD_V2_BYTES || &bytes[..4] != MAGIC {
            return Err(PqCellProviderErrorV2::WireLengthOrVersion);
        }
        let record = Self {
            statement: PqCellProviderStatementV2 {
                pinned_request: bytes[4..196].try_into().expect("fixed request"),
                endpoint: bytes[228..247].try_into().expect("fixed endpoint"),
                sequence: u64::from_be_bytes(bytes[247..255].try_into().expect("fixed seq")),
                issued_unix_seconds: u64::from_be_bytes(
                    bytes[255..263].try_into().expect("fixed issue"),
                ),
                expires_unix_seconds: u64::from_be_bytes(
                    bytes[263..271].try_into().expect("fixed expiry"),
                ),
            },
            signer_key_id: bytes[196..228].try_into().expect("fixed signer id"),
            signature: bytes[271..].to_vec(),
        };
        record.check_shape()?;
        Ok(record)
    }

    pub fn verify_for_pinned_context(
        &self,
        expected: &PqCellProviderExpectationV2<'_>,
    ) -> Result<VerifiedPqCellProviderHintV2, PqCellProviderErrorV2> {
        self.check_shape()?;
        if &self.statement.pinned_request != expected.pinned_request {
            return Err(PqCellProviderErrorV2::UntrustedRequest);
        }
        let pinned_id = pq_cell_provider_key_id_v2(expected.trusted_ml_dsa65_public_key)?;
        if self.signer_key_id != pinned_id {
            return Err(PqCellProviderErrorV2::UntrustedSigner);
        }
        if self.statement.sequence <= expected.last_accepted_sequence {
            return Err(PqCellProviderErrorV2::Replay);
        }
        if self.statement.issued_unix_seconds
            > expected.now_unix_seconds.saturating_add(FUTURE_SKEW_SECONDS)
            || expected.now_unix_seconds >= self.statement.expires_unix_seconds
        {
            return Err(PqCellProviderErrorV2::ExpiredOrFuture);
        }
        if self.signature.len() != PQ_CELL_PROVIDER_SIGNATURE_BYTES {
            return Err(PqCellProviderErrorV2::InvalidSignatureEncoding);
        }
        // Decode the signature before expanding the PQ public key. Malformed
        // attacker-controlled signatures must not trigger expensive key work.
        let sig = Signature::<MlDsa65>::try_from(self.signature.as_slice())
            .map_err(|_| PqCellProviderErrorV2::InvalidSignatureEncoding)?;
        let pk = EncodedVerifyingKey::<MlDsa65>::try_from(
            expected.trusted_ml_dsa65_public_key,
        )
        .map_err(|_| PqCellProviderErrorV2::InvalidPublicKey)?;
        if !VerifyingKey::<MlDsa65>::decode(&pk).verify_with_context(
            &self.signing_bytes(),
            &[],
            &sig,
        ) {
            return Err(PqCellProviderErrorV2::InvalidSignature);
        }
        Ok(VerifiedPqCellProviderHintV2 {
            endpoint: self.statement.endpoint,
            sequence: self.statement.sequence,
            expires_unix_seconds: self.statement.expires_unix_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::KeyInit;

    fn key() -> SigningKey<MlDsa65> {
        SigningKey::<MlDsa65>::new_from_slice(&[54; 32]).unwrap()
    }
    fn request() -> [u8; 192] {
        let mut bytes = [0; 192];
        for (index, digest) in bytes.chunks_exact_mut(32).enumerate() {
            digest.fill(index as u8 + 1);
        }
        bytes
    }
    fn statement() -> PqCellProviderStatementV2 {
        let mut endpoint = [0; 19];
        endpoint[0] = 4;
        endpoint[13..17].copy_from_slice(&[127, 0, 0, 1]);
        endpoint[17..19].copy_from_slice(&31234u16.to_be_bytes());
        PqCellProviderStatementV2 {
            pinned_request: request(),
            endpoint,
            sequence: 5,
            issued_unix_seconds: 1000,
            expires_unix_seconds: 1200,
        }
    }
    fn expected<'a>(
        key: &'a [u8],
        pin: &'a [u8; 192],
    ) -> PqCellProviderExpectationV2<'a> {
        PqCellProviderExpectationV2 {
            pinned_request: pin,
            trusted_ml_dsa65_public_key: key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
        }
    }

    #[test]
    fn real_ml_dsa_positive_and_fixed_wire_roundtrip() {
        let sk = key();
        let pk = sk.verifying_key().to_bytes();
        let pin = request();
        let signed = SignedPqCellProviderRecordV2::sign(statement(), &sk).unwrap();
        let wire = signed.to_wire();
        assert_eq!(wire.len(), PQ_CELL_PROVIDER_RECORD_V2_BYTES);
        assert_eq!(PQ_CELL_PROVIDER_RECORD_V2_BYTES * 8 + 1, 28641);
        let received = SignedPqCellProviderRecordV2::from_wire(&wire).unwrap();
        assert_eq!(received, signed);
        let checked = received.verify_for_pinned_context(&expected(&pk, &pin)).unwrap();
        assert_eq!(checked.endpoint_bytes(), &statement().endpoint);
        assert_eq!(checked.sequence(), 5);
    }

    #[test]
    fn untrusted_key_request_and_stale_sequence_fail() {
        let sk = key();
        let pk = sk.verifying_key().to_bytes();
        let signed = SignedPqCellProviderRecordV2::sign(statement(), &sk).unwrap();
        let mut pin = request();
        pin[0] ^= 1;
        assert_eq!(
            signed.verify_for_pinned_context(&expected(&pk, &pin)),
            Err(PqCellProviderErrorV2::UntrustedRequest)
        );
        let pin = request();
        let wrong = SigningKey::<MlDsa65>::new_from_slice(&[55; 32]).unwrap();
        let wrong_pk = wrong.verifying_key().to_bytes();
        assert_eq!(
            signed.verify_for_pinned_context(&expected(&wrong_pk, &pin)),
            Err(PqCellProviderErrorV2::UntrustedSigner)
        );
        let mut e = expected(&pk, &pin);
        e.last_accepted_sequence = 5;
        assert_eq!(
            signed.verify_for_pinned_context(&e),
            Err(PqCellProviderErrorV2::Replay)
        );
        e.last_accepted_sequence = 4;
        e.now_unix_seconds = 1200;
        assert_eq!(
            signed.verify_for_pinned_context(&e),
            Err(PqCellProviderErrorV2::ExpiredOrFuture)
        );
    }

    #[test]
    fn every_signed_region_rejects_mutation_and_wrong_domain() {
        let sk = key();
        let pk = sk.verifying_key().to_bytes();
        let pin = request();
        let signed = SignedPqCellProviderRecordV2::sign(statement(), &sk).unwrap();
        let wire = signed.to_wire();
        for offset in [0, 4, 35, 195, 196, 228, 240, 245, 247, 255, 263, 270, 271, 3579] {
            let mut changed = wire.clone();
            changed[offset] ^= 1;
            assert!(
                SignedPqCellProviderRecordV2::from_wire(&changed)
                    .and_then(|record| record.verify_for_pinned_context(&expected(&pk, &pin)))
                    .is_err(),
                "tamper offset {offset}"
            );
        }
        let mut substituted = signed.clone();
        let wrong_domain: Signature<MlDsa65> = sk.sign(&signed.unsigned_bytes());
        substituted.signature = wrong_domain.to_vec();
        assert!(substituted
            .verify_for_pinned_context(&expected(&pk, &pin))
            .is_err());
    }

    #[test]
    fn v1_and_noncanonical_or_unbounded_wires_are_never_pq() {
        assert_eq!(
            SignedPqCellProviderRecordV2::from_wire(&[0; 335]),
            Err(PqCellProviderErrorV2::WireLengthOrVersion)
        );
        let signed = SignedPqCellProviderRecordV2::sign(statement(), &key()).unwrap();
        let wire = signed.to_wire();
        for size in [0, 1, 335, wire.len() - 1, wire.len() + 1] {
            assert!(SignedPqCellProviderRecordV2::from_wire(&vec![0; size]).is_err());
        }
        let mut changed = wire.clone();
        changed[..4].copy_from_slice(b"CDP1");
        assert_eq!(
            SignedPqCellProviderRecordV2::from_wire(&changed),
            Err(PqCellProviderErrorV2::WireLengthOrVersion)
        );
        let mut shape = statement();
        shape.endpoint[17..19].fill(0);
        assert!(SignedPqCellProviderRecordV2::sign(shape, &key()).is_err());
        shape = statement();
        shape.expires_unix_seconds = shape.issued_unix_seconds + 301;
        assert!(SignedPqCellProviderRecordV2::sign(shape, &key()).is_err());
        shape = statement();
        shape.pinned_request[4..36].fill(0);
        assert!(SignedPqCellProviderRecordV2::sign(shape, &key()).is_err());
    }

    #[test]
    fn out_of_window_and_untrusted_signature_refuse_without_fallback() {
        let sk = key();
        let pk = sk.verifying_key().to_bytes();
        let pin = request();
        let mut e = expected(&pk, &pin);
        let record = SignedPqCellProviderRecordV2::sign(statement(), &sk).unwrap();
        e.now_unix_seconds = 990;
        assert_eq!(
            record.verify_for_pinned_context(&e),
            Err(PqCellProviderErrorV2::ExpiredOrFuture)
        );
        e.now_unix_seconds = 1100;
        let mut forged = record.clone();
        forged.signature.fill(0);
        assert!(forged.verify_for_pinned_context(&e).is_err());
        forged = record;
        forged.signature.truncate(64);
        assert_eq!(
            forged.verify_for_pinned_context(&e),
            Err(PqCellProviderErrorV2::InvalidSignatureEncoding)
        );
    }
}
