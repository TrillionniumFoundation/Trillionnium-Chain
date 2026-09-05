#![no_main]

use libfuzzer_sys::fuzz_target;
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_consumption_certificate_v0_exact,
    decode_next_epoch_commitment_v0_exact,
};

const MAX_CEV0_BYTES: usize = 8 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_CEV0_BYTES {
        return;
    }

    if let Ok(header) = decode_block_header_v0_exact(data) {
        let encoded = header
            .try_cev0_bytes()
            .expect("exactly decoded header re-encodes");
        assert_eq!(encoded, data);
    }

    if let Ok(commitment) = decode_next_epoch_commitment_v0_exact(data) {
        let encoded = commitment
            .try_cev0_bytes()
            .expect("exactly decoded epoch commitment re-encodes");
        assert_eq!(encoded, data);
    }

    if let Ok(certificate) = decode_consumption_certificate_v0_exact(data) {
        let encoded = certificate
            .try_cev0_bytes()
            .expect("exactly decoded consumption certificate re-encodes");
        assert_eq!(encoded, data);
    }
});
