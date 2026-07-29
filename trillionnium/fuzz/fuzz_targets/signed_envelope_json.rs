#![no_main]

use libfuzzer_sys::fuzz_target;
use trnm_finality_types::SignedCommandEnvelopeV1;
use trnm_protocol::{CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1};

const MAX_WIRE_BYTES: usize = 2 * 1024 * 1024 + 64 * 1024;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_WIRE_BYTES {
        return;
    }

    let Ok(envelope) = serde_json::from_slice::<SignedCommandEnvelopeV1>(data) else {
        return;
    };
    if envelope.validate_shape().is_err() {
        return;
    }

    let payload = envelope
        .payload_bytes()
        .expect("shape-validated envelope has canonical payload hex");
    assert!(payload.len() <= MAX_PAYLOAD_BYTES);

    let encoded = serde_json::to_vec(&envelope).expect("serialize accepted envelope");
    let decoded: SignedCommandEnvelopeV1 =
        serde_json::from_slice(&encoded).expect("decode serialized accepted envelope");
    assert_eq!(decoded, envelope);
    assert!(decoded.validate_shape().is_ok());

    // These methods frame all security-sensitive fields. Shape validation must
    // make each operation total even if an arbitrary signature is invalid.
    let signing_bytes = decoded
        .signing_bytes()
        .expect("shape-validated envelope has signing bytes");
    assert!(!signing_bytes.is_empty());
    let _ = decoded
        .fingerprint()
        .expect("shape-validated envelope has fingerprint");
    let _ = decoded
        .tx_hash()
        .expect("shape-validated envelope has transaction hash");

    // Signature verification is intentionally exercised without asserting
    // success: most mutated signatures are invalid, and rejection is expected.
    let _ = decoded.validate_at(&decoded.chain_id, decoded.issued_at_unix_ms);

    if decoded.payload_type == CANONICAL_TX_PAYLOAD_TYPE_V1 {
        if let Ok(transaction) = serde_json::from_slice::<CanonicalTxV1>(&payload) {
            if transaction.validate().is_ok() {
                let nested = serde_json::to_vec(&transaction)
                    .expect("serialize accepted nested canonical transaction");
                let reparsed: CanonicalTxV1 =
                    serde_json::from_slice(&nested).expect("reparse accepted nested transaction");
                assert_eq!(reparsed, transaction);
            }
        }
    }
});
