//! Strict native TPQ1 research wire preflight; **not** a signature verifier.
//!
//! No value returned by this module is an authenticated identity, a verified
//! transaction, VerifiedWork, authorization, final-use or release capability.
//! A separately reviewed ML-DSA-65 verifier and state/nonce owner MUST follow.
//! This module deliberately does not alter the installed legacy PoN wire.
use sha2::{Digest, Sha384};

pub const TPQ1_UNSIGNED_BYTES: usize = 176;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
pub const TPQ1_SIGNED_BYTES: usize = TPQ1_UNSIGNED_BYTES + 2 + ML_DSA_65_SIGNATURE_BYTES;
pub const TPQ1_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const DOMAIN: &[u8] = b"TRNM/PoN/PQAuth/ML-DSA-65/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqFrameError {
    FrameLength,
    HeaderVersionAlgorithm,
    PurposeOrReserved,
    ContextOrIdentity,
    LifetimeOrSequence,
    Expired,
    PayloadSize,
    PayloadDigest,
    SignatureLength,
}

/// Independently pinned caller expectations. In particular, the key ID does
/// not come from the untrusted frame; the future crypto owner must derive it
/// from a strict ML-DSA-65 SPKI public key before using this preflight.
#[derive(Debug, Clone)]
pub struct PqFrameExpectation<'a> {
    pub purpose: u8,
    pub network: [u8; 32],
    pub owner_context: [u8; 32],
    pub signer_key_id: [u8; 32],
    pub owner_generation: u64,
    pub operation_sequence: u64,
    pub expires_at: u64,
    pub now: u64,
    pub payload: &'a [u8],
}

/// These are UNVERIFIED bytes; never use this as a boolean proof of signature,
/// chain authority, user permission, model quality or state transition.
#[derive(Debug)]
pub struct UnverifiedPqFrame<'a> {
    statement: &'a [u8],
    signature: &'a [u8],
}

impl<'a> UnverifiedPqFrame<'a> {
    pub fn unsigned_statement(&self) -> &'a [u8] {
        self.statement
    }

    pub fn unverified_signature(&self) -> &'a [u8] {
        self.signature
    }
}

fn u64_at(input: &[u8], start: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&input[start..start + 8]);
    u64::from_be_bytes(bytes)
}

/// The exact v1 Python research payload commitment:
/// SHA384(DOMAIN || "payload\0" || BE64(len) || payload).
pub fn payload_commitment(payload: &[u8]) -> Result<[u8; 48], PqFrameError> {
    if payload.len() > TPQ1_MAX_PAYLOAD_BYTES {
        return Err(PqFrameError::PayloadSize);
    }
    let mut h = Sha384::new();
    h.update(DOMAIN);
    h.update(b"payload\0");
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
    Ok(h.finalize().into())
}

/// Reject malformed/unbound TPQ1 before invoking an independently implemented
/// ML-DSA-65 verifier. Success is NEVER signature verification. Keeping this
/// result unverified avoids a forged Boolean being converted to an authority.
pub fn preflight_unverified<'a>(
    bytes: &'a [u8],
    expected: &PqFrameExpectation<'_>,
) -> Result<UnverifiedPqFrame<'a>, PqFrameError> {
    if bytes.len() != TPQ1_SIGNED_BYTES {
        return Err(PqFrameError::FrameLength);
    }
    if &bytes[..4] != b"TPQ1" || bytes[4] != 1 || bytes[5] != 0x65 {
        return Err(PqFrameError::HeaderVersionAlgorithm);
    }
    if !(1..=6).contains(&bytes[6]) || bytes[6] != expected.purpose || bytes[7] != 0 {
        return Err(PqFrameError::PurposeOrReserved);
    }
    if &bytes[8..40] != expected.network.as_slice()
        || &bytes[40..72] != expected.owner_context.as_slice()
        || &bytes[72..104] != expected.signer_key_id.as_slice()
    {
        return Err(PqFrameError::ContextOrIdentity);
    }
    let generation = u64_at(bytes, 104);
    let sequence = u64_at(bytes, 112);
    let expiry = u64_at(bytes, 120);
    if generation == 0
        || sequence == 0
        || expiry == 0
        || generation != expected.owner_generation
        || sequence != expected.operation_sequence
        || expiry != expected.expires_at
    {
        return Err(PqFrameError::LifetimeOrSequence);
    }
    if expected.now > expiry {
        return Err(PqFrameError::Expired);
    }
    if &bytes[128..176] != payload_commitment(expected.payload)?.as_slice() {
        return Err(PqFrameError::PayloadDigest);
    }
    let len = u16::from_be_bytes([bytes[176], bytes[177]]) as usize;
    if len != ML_DSA_65_SIGNATURE_BYTES {
        return Err(PqFrameError::SignatureLength);
    }
    Ok(UnverifiedPqFrame {
        statement: &bytes[..TPQ1_UNSIGNED_BYTES],
        signature: &bytes[TPQ1_UNSIGNED_BYTES + 2..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case<'a>(payload: &'a [u8]) -> (Vec<u8>, PqFrameExpectation<'a>) {
        let e = PqFrameExpectation {
            purpose: 4,
            network: [1; 32],
            owner_context: [2; 32],
            signer_key_id: [3; 32],
            owner_generation: 7,
            operation_sequence: 19,
            expires_at: 4000,
            now: 3999,
            payload,
        };
        let mut v = vec![0xab; TPQ1_SIGNED_BYTES];
        v[..4].copy_from_slice(b"TPQ1");
        v[4] = 1;
        v[5] = 0x65;
        v[6] = e.purpose;
        v[7] = 0;
        v[8..40].copy_from_slice(&e.network);
        v[40..72].copy_from_slice(&e.owner_context);
        v[72..104].copy_from_slice(&e.signer_key_id);
        v[104..112].copy_from_slice(&e.owner_generation.to_be_bytes());
        v[112..120].copy_from_slice(&e.operation_sequence.to_be_bytes());
        v[120..128].copy_from_slice(&e.expires_at.to_be_bytes());
        v[128..176].copy_from_slice(&payload_commitment(payload).unwrap());
        v[176..178].copy_from_slice(&(ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
        (v, e)
    }

    #[test]
    fn entire_statement_has_one_exact_canonical_preflight_binding() {
        let (v, e) = case(b"public Cell release manifest hash and consent");
        let checked = preflight_unverified(&v, &e).unwrap();
        assert_eq!(checked.unsigned_statement().len(), 176);
        assert_eq!(checked.unverified_signature().len(), 3309);
        for idx in 0..TPQ1_UNSIGNED_BYTES {
            let mut mutated = v.clone();
            mutated[idx] ^= 1;
            assert!(preflight_unverified(&mutated, &e).is_err(), "field byte {idx}");
        }
    }

    #[test]
    fn zero_lifetimes_bad_length_and_classical_downgrade_reject() {
        let (v, e) = case(b"test");
        for end in [0, 175, 3486, 3488] {
            let mut bad = v.clone();
            bad.resize(end, 0);
            assert_eq!(preflight_unverified(&bad, &e).unwrap_err(), PqFrameError::FrameLength);
        }
        let mut bad = v.clone();
        bad[5] = 0x19; // Ed25519 is not a PQ signature algorithm.
        assert_eq!(preflight_unverified(&bad, &e).unwrap_err(), PqFrameError::HeaderVersionAlgorithm);
        for range in [104..112, 112..120, 120..128] {
            let mut bad = v.clone();
            bad[range].fill(0);
            assert_eq!(preflight_unverified(&bad, &e).unwrap_err(), PqFrameError::LifetimeOrSequence);
        }
    }

    #[test]
    fn stale_payload_and_signature_size_refuse() {
        let (v, mut e) = case(b"test");
        e.now = 4001;
        assert_eq!(preflight_unverified(&v, &e).unwrap_err(), PqFrameError::Expired);
        e.now = 3999;
        e.payload = b"other";
        assert_eq!(preflight_unverified(&v, &e).unwrap_err(), PqFrameError::PayloadDigest);
        e.payload = b"test";
        let mut bad = v.clone();
        bad[176] = 0;
        assert_eq!(preflight_unverified(&bad, &e).unwrap_err(), PqFrameError::SignatureLength);
    }

    #[test]
    fn unverified_signature_change_never_grants_authority() {
        let (v, e) = case(b"test");
        let mut fake = v.clone();
        fake[178] ^= 1;
        let a = preflight_unverified(&v, &e).unwrap();
        let b = preflight_unverified(&fake, &e).unwrap();
        assert_ne!(a.unverified_signature(), b.unverified_signature());
        // Both are merely unverified frames: no cryptographic success is offered.
    }

    #[test]
    fn old_devnet_transaction_size_cannot_hold_pq_signature() {
        assert!(TPQ1_SIGNED_BYTES > 2048);
        assert!(ML_DSA_65_SIGNATURE_BYTES > 2048);
    }
}
