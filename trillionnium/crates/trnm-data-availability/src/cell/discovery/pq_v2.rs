//! M09 receive-side verification boundary for the compact PCP2 research wire.
//! Does NOT select a network protocol, persist replay floors, change CDP1
//! directory/transport, or authorize Cell bytes, custody, release or FinalUse.
//! Every expected input must come from an independent owner, not from the wire.
use super::{
    decode_endpoint, CellDiscoveryAddressPolicyV1, CellDiscoveryRequestV1,
    MAX_DISCOVERED_PROVIDERS, MAX_DISCOVERY_RESPONSE_BYTES,
};
use crate::cell::{CellErrorV1, CellResultV1};
use std::net::SocketAddr;
use trnm_crypto_primitives::pq_cell_provider::{
    PqCellProviderExpectationV2, SignedPqCellProviderRecordV2, PQ_CELL_PROVIDER_RECORD_V2_BYTES,
};

/// An eight-provider PCP2 reply fits the original 32-KiB envelope.
/// This is arithmetic only: the actual transport still speaks classical CDP1.
const PCP2_MAX_REPLY_BYTES: usize = 1 + MAX_DISCOVERED_PROVIDERS * PQ_CELL_PROVIDER_RECORD_V2_BYTES;
const _: () = assert!(PCP2_MAX_REPLY_BYTES <= MAX_DISCOVERY_RESPONSE_BYTES as usize);

/// Never construct expectations by copying request/key/replay from a peer hint.
pub struct PqCellProviderExpectationM09V2<'a> {
    pub request: CellDiscoveryRequestV1,
    pub trusted_ml_dsa65_public_key: &'a [u8],
    /// Externally maintained monotonic floor; rolled-back SQLite is unsafe.
    pub last_accepted_sequence: u64,
    pub now_unix_seconds: u64,
    pub addresses: &'a CellDiscoveryAddressPolicyV1,
}

/// Inert, verified routing hint, not release or FinalUse authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPqCellProviderHintM09V2 {
    endpoint: SocketAddr,
    sequence: u64,
    expires_unix_seconds: u64,
}

impl VerifiedPqCellProviderHintM09V2 {
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn expires_unix_seconds(&self) -> u64 {
        self.expires_unix_seconds
    }
}

/// Verify canonical PCP2 with independent owner pins and the M09 IP policy.
/// CDP1, competing CDP2, forged keys and malformed records never fall back.
pub fn verify_pcp2_provider_hint_v2(
    wire: &[u8],
    expectation: &PqCellProviderExpectationM09V2<'_>,
) -> CellResultV1<VerifiedPqCellProviderHintM09V2> {
    expectation.request.validate()?;
    expectation.addresses.validate()?;
    let pinned_request: [u8; 192] = expectation
        .request
        .encode()
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("PQ Cell owner request length"))?;
    let record = SignedPqCellProviderRecordV2::from_wire(wire)
        .map_err(|_| CellErrorV1::Invalid("PQ Cell provider wire"))?;
    // A policy-denied endpoint needs no expensive ML-DSA verification. The
    // endpoint is still UNTRUSTED at this stage: this is a refusal-only
    // preflight, never a routing hint or evidence of signed authority.
    let endpoint = decode_endpoint(record.statement.endpoint)?;
    expectation.addresses.check(endpoint)?;
    let verified = record
        .verify_for_pinned_context(&PqCellProviderExpectationV2 {
            pinned_request: &pinned_request,
            trusted_ml_dsa65_public_key: expectation.trusted_ml_dsa65_public_key,
            last_accepted_sequence: expectation.last_accepted_sequence,
            now_unix_seconds: expectation.now_unix_seconds,
        })
        .map_err(|_| CellErrorV1::Invalid("PQ Cell provider authority/signature"))?;
    // The verified bytes are the same fields preflighted above. No endpoint
    // escapes this function until ML-DSA and the independent owner pins pass.
    debug_assert_eq!(*verified.endpoint_bytes(), record.statement.endpoint);
    Ok(VerifiedPqCellProviderHintM09V2 {
        endpoint,
        sequence: verified.sequence(),
        expires_unix_seconds: verified.expires_unix_seconds(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::discovery::CellDiscoveryContextV1;
    use ml_dsa::{KeyExport, KeyInit, Keypair, MlDsa65, SigningKey};
    use trnm_crypto_primitives::pq_cell_provider::PqCellProviderStatementV2;

    fn request() -> CellDiscoveryRequestV1 {
        let mut six = [[0u8; 32]; 6];
        for (i, digest) in six.iter_mut().enumerate() {
            digest.fill((i + 1) as u8);
        }
        CellDiscoveryRequestV1 {
            context: CellDiscoveryContextV1 {
                namespace: six[0],
                network: six[1],
                parameters: six[2],
                genesis: six[3],
            },
            cell_context: six[4],
            manifest: six[5],
        }
    }

    fn signed_wire(request: CellDiscoveryRequestV1) -> (Vec<u8>, Vec<u8>) {
        let signer = SigningKey::<MlDsa65>::new_from_slice(&[54; 32]).unwrap();
        let mut endpoint = [0u8; 19];
        endpoint[0] = 4;
        endpoint[13..17].copy_from_slice(&[127, 0, 0, 1]);
        endpoint[17..19].copy_from_slice(&31234u16.to_be_bytes());
        let record = SignedPqCellProviderRecordV2::sign(
            PqCellProviderStatementV2 {
                pinned_request: request.encode().try_into().unwrap(),
                endpoint,
                sequence: 5,
                issued_unix_seconds: 1000,
                expires_unix_seconds: 1200,
            },
            &signer,
        )
        .unwrap();
        (record.to_wire(), signer.verifying_key().to_bytes().to_vec())
    }

    #[test]
    fn authentic_pcp2_uses_existing_m09_request_and_address_policy() {
        let request = request();
        let (wire, key) = signed_wire(request);
        let addresses = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] };
        let expectation = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &addresses,
        };
        let hint = verify_pcp2_provider_hint_v2(&wire, &expectation).unwrap();
        assert_eq!(hint.endpoint(), "127.0.0.1:31234".parse().unwrap());
        assert_eq!(hint.sequence(), 5);
        assert_eq!(hint.expires_unix_seconds(), 1200);
        assert_eq!(wire.len(), PQ_CELL_PROVIDER_RECORD_V2_BYTES);
        assert_eq!(PCP2_MAX_REPLY_BYTES, 28641);
        assert!(PCP2_MAX_REPLY_BYTES <= MAX_DISCOVERY_RESPONSE_BYTES as usize);
    }

    #[test]
    fn rejects_replay_wrong_request_key_address_and_expired_record() {
        let request = request();
        let (wire, key) = signed_wire(request);
        let addresses = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] };
        let mut expectation = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &addresses,
        };
        expectation.last_accepted_sequence = 5;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.last_accepted_sequence = 4;
        expectation.now_unix_seconds = 1200;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.now_unix_seconds = 1100;
        expectation.request.manifest = [99; 32];
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.request = request;
        let wrong = SigningKey::<MlDsa65>::new_from_slice(&[55; 32]).unwrap();
        let wrong_key = wrong.verifying_key().to_bytes();
        expectation.trusted_ml_dsa65_public_key = &wrong_key;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.trusted_ml_dsa65_public_key = &key;
        let denied = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31235] };
        expectation.addresses = &denied;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
    }

    #[test]
    fn competing_cdp2_classic_cdp1_and_tamper_have_no_fallback() {
        let request = request();
        let (wire, key) = signed_wire(request);
        let addresses = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] };
        let expectation = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &addresses,
        };
        assert!(verify_pcp2_provider_hint_v2(&[0; 335], &expectation).is_err());
        let mut competing = vec![0; 5532];
        competing[..4].copy_from_slice(b"CDP2");
        assert!(verify_pcp2_provider_hint_v2(&competing, &expectation).is_err());
        let mut tampered = wire.clone();
        tampered[3540] ^= 1;
        assert!(verify_pcp2_provider_hint_v2(&tampered, &expectation).is_err());
        let mut extended = wire;
        extended.push(0);
        assert!(verify_pcp2_provider_hint_v2(&extended, &expectation).is_err());
    }

    #[test]
    fn off_policy_malicious_signature_is_rejected_before_pq_key_work() {
        let request = request();
        let (wire, key) = signed_wire(request);
        let permitted = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] };
        let denied = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31235] };
        let mut forged = wire.clone();
        forged[271] ^= 1; // Actual signature bytes, not header or shape.
        let untrusted_key = [0u8; 1];
        let rejected = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &untrusted_key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &denied,
        };
        // Even invalid key bytes do not cause key expansion: policy denial is
        // deterministic, cheap, and strictly refusal-only.
        assert_eq!(
            verify_pcp2_provider_hint_v2(&forged, &rejected)
                .unwrap_err()
                .to_string(),
            "cell: discovery outbound address denied"
        );
        let allowed_bad_signature = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &permitted,
        };
        assert_eq!(
            verify_pcp2_provider_hint_v2(&forged, &allowed_bad_signature)
                .unwrap_err()
                .to_string(),
            "cell: PQ Cell provider authority/signature"
        );
        // An authentic signature is STILL refused when address policy denies.
        let denied_valid_signature = PqCellProviderExpectationM09V2 {
            addresses: &denied,
            ..allowed_bad_signature
        };
        assert_eq!(
            verify_pcp2_provider_hint_v2(&wire, &denied_valid_signature)
                .unwrap_err()
                .to_string(),
            "cell: discovery outbound address denied"
        );
        // The valid, pinned, allowed case remains usable.
        let hint = verify_pcp2_provider_hint_v2(&wire, &allowed_bad_signature).unwrap();
        assert_eq!(hint.endpoint(), "127.0.0.1:31234".parse().unwrap());
        assert_eq!(hint.sequence(), 5);
        // Preflight must not mask a structurally wrong record as a valid PCP2.
        assert_eq!(
            verify_pcp2_provider_hint_v2(&wire[..335], &rejected)
                .unwrap_err()
                .to_string(),
            "cell: PQ Cell provider wire"
        );
    }
}
