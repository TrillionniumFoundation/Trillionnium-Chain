#![no_main]

use libfuzzer_sys::fuzz_target;
use trnm_crypto_primitives::pon_work::{self, CELLS, PROOF_BYTES};
use trnm_protocol::pon_wire::Header;

fuzz_target!(|bytes: &[u8]| {
    let header = Header::decode(include_bytes!(
        "../../../formal/pon-nakamoto-v1/vectors/header.bin"
    ))
    .expect("retained canonical header vector");
    // Bind to the supplied matrices when available so mutations explore the
    // transcript/product verifier, not exclusively the task-id rejection.
    let task = if bytes.len() == PROOF_BYTES {
        let matrices: Vec<u32> = bytes[4..4 + 2 * CELLS * 4]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("four-byte word")))
            .collect();
        pon_work::task_id(&matrices[..CELLS], &matrices[CELLS..]).unwrap_or([0; 32])
    } else {
        [0; 32]
    };
    let optimized = pon_work::verify(header.challenge(), task, [255; 32], bytes);
    let reference = pon_work::verify_reference(header.challenge(), task, [255; 32], bytes);
    match (optimized, reference) {
        (Ok(actual), Ok(expected)) => {
            assert_eq!(actual.challenge(), expected.challenge());
            assert_eq!(actual.task(), expected.task());
            assert_eq!(actual.ticket(), expected.ticket());
            assert_eq!(actual.product(), expected.product());
        }
        (Err(actual), Err(expected)) => assert_eq!(actual, expected),
        _ => panic!("independent work kernels disagree on an untrusted certificate"),
    }
});
