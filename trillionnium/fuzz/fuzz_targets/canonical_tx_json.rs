#![no_main]

use libfuzzer_sys::fuzz_target;
use trnm_protocol::CanonicalTxV1;

const MAX_WIRE_BYTES: usize = 2 * 1024 * 1024 + 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_WIRE_BYTES {
        return;
    }

    let Ok(transaction) = serde_json::from_slice::<CanonicalTxV1>(data) else {
        return;
    };

    // Deserialization alone does not imply protocol validity. Once a public
    // transaction is accepted by both layers, it must remain lossless through
    // the canonical serializer used by clients and tests.
    if transaction.validate().is_ok() {
        let encoded = serde_json::to_vec(&transaction).expect("serialize accepted transaction");
        let decoded: CanonicalTxV1 =
            serde_json::from_slice(&encoded).expect("decode serialized accepted transaction");
        assert_eq!(decoded, transaction);
        assert!(decoded.validate().is_ok());

        // Exercise the per-command gas dispatch for every accepted enum case.
        let _ = decoded.command.operation_gas();
    }
});
