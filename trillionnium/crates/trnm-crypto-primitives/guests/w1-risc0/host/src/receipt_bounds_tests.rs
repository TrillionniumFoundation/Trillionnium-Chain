use super::*;
use bincode::Options;

fn u32_word(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn u64_word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

// Deliberately false, syntactically valid SDK data. Never a positive proof.
fn skeleton(segments: usize, po2: u32, open_claim_journal: bool) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::new();
    let mut variable_lengths = vec![4, 12];
    u32_word(&mut out, 0); // Composite.
    u64_word(&mut out, segments as u64);
    for index in 0..segments {
        u64_word(&mut out, MIN_SEAL_WORDS as u64);
        u32_word(&mut out, 2);
        out.extend_from_slice(&[0; OUTPUT_WORDS * 4]);
        u32_word(&mut out, po2);
        u32_word(&mut out, index as u32);
        variable_lengths.push(out.len());
        u64_word(&mut out, 9);
        out.extend_from_slice(b"poseidon2");
        out.extend_from_slice(&[0; 32]);
        for _ in 0..2 {
            u32_word(&mut out, 0); // Value(SystemState).
            out.extend_from_slice(&[0; 4 + 32]);
        }
        u32_word(&mut out, 0); // Halted(0).
        u32_word(&mut out, 0);
        u32_word(&mut out, 1); // Pruned input digest.
        out.extend_from_slice(&[0; 32]);
        u32_word(&mut out, 0); // Value(Some(Output)).
        out.push(1);
        if open_claim_journal {
            u32_word(&mut out, 0);
            variable_lengths.push(out.len());
            u64_word(&mut out, JOURNAL_BYTES as u64);
            out.extend_from_slice(&[0; JOURNAL_BYTES]);
        } else {
            u32_word(&mut out, 1); // Pruned journal digest.
            out.extend_from_slice(&[0; 32]);
        }
        u32_word(&mut out, 0); // Value(empty assumptions).
        variable_lengths.push(out.len());
        u64_word(&mut out, 0);
    }
    variable_lengths.push(out.len());
    u64_word(&mut out, 0); // No nested assumption receipts.
    out.extend_from_slice(&[0; 32]);
    variable_lengths.push(out.len());
    u64_word(&mut out, JOURNAL_BYTES as u64);
    out.extend_from_slice(&[0; JOURNAL_BYTES]);
    out.extend_from_slice(&[0; 32]);
    (out, variable_lengths)
}

#[test]
fn bounded_sdk_shape_does_not_authenticate_a_synthetic_claim() {
    for open_journal in [false, true] {
        let (bytes, _) = skeleton(1, 17, open_journal);
        assert_eq!(preflight(&bytes).unwrap().padded_cycles, 1 << 17);
        let receipt: risc0_zkvm::Receipt = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&bytes)
            .unwrap();
        assert_eq!(bincode::serialize(&receipt).unwrap(), bytes);
        assert!(receipt
            .verify_with_context(
                &risc0_zkvm::VerifierContext::default().with_dev_mode(false),
                [0u32; 8],
            )
            .is_err());
    }
}

#[test]
fn every_variable_length_is_checked_before_sdk_allocation() {
    let (bytes, lengths) = skeleton(1, 17, true);
    for offset in lengths {
        let mut bomb = bytes.clone();
        bomb[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            matches!(preflight(&bomb), Err(BoundaryError::Refused(_))),
            "unbounded length at {offset}"
        );
    }
}

#[test]
fn every_truncation_and_a_trailing_byte_fail_without_sdk_parsing() {
    let (mut bytes, _) = skeleton(1, 17, true);
    for length in 0..bytes.len() {
        assert!(preflight(&bytes[..length]).is_err(), "length {length}");
    }
    bytes.push(0);
    assert_eq!(
        preflight(&bytes),
        Err(BoundaryError::Malformed("trailing certificate bytes"))
    );
}

#[test]
fn empty_seal_is_stopped_before_the_sdk_direct_index() {
    let (mut bytes, _) = skeleton(1, 17, false);
    bytes[12..20].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        preflight(&bytes),
        Err(BoundaryError::Malformed("empty or incomplete seal header"))
    );
    assert!(check_seal(&[]).is_err());
}

#[test]
fn proof_dimensions_and_total_cycle_budget_are_independent_limits() {
    for po2 in [0, 12, 21, u32::MAX] {
        assert!(matches!(
            preflight(&skeleton(1, po2, false).0),
            Err(BoundaryError::Refused(_))
        ));
    }
    assert_eq!(
        preflight(&skeleton(256, 20, false).0)
            .unwrap()
            .padded_cycles,
        MAX_PADDED_CYCLES
    );
    assert_eq!(
        preflight(&skeleton(257, 20, false).0),
        Err(BoundaryError::Refused("total padded proof-cycle budget"))
    );
    assert_eq!(
        preflight(&skeleton(MAX_SEGMENTS + 1, 13, false).0),
        Err(BoundaryError::Refused("segment count budget"))
    );
}

#[test]
fn unsupported_receipt_kinds_never_enter_generic_deserialization() {
    let (bytes, _) = skeleton(1, 17, false);
    for kind in [1u32, 2, 3, u32::MAX] {
        let mut changed = bytes.clone();
        changed[..4].copy_from_slice(&kind.to_le_bytes());
        assert_eq!(
            preflight(&changed),
            Err(BoundaryError::Refused(
                "only Composite receipts are supported"
            ))
        );
    }
}

#[test]
fn independent_segment_and_claim_bounds_do_not_authenticate_partial_data() {
    // Reuse an explicitly false SDK-shape control. Passing either preflight
    // only permits bounded decoding, and never qualifies any STARK or W1.
    let receipt: risc0_zkvm::Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&skeleton(1, 18, true).0)
        .unwrap();
    let risc0_zkvm::InnerReceipt::Composite(composite) = receipt.inner else {
        unreachable!()
    };
    let fields = bincode::serialize(&(
        &composite.segments,
        &composite.assumption_receipts,
        composite.verifier_parameters,
    ))
    .unwrap();
    assert_eq!(fields, bincode::serialize(&composite).unwrap());
    let reconstructed: risc0_zkvm::CompositeReceipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&fields)
        .unwrap();
    assert!(reconstructed
        .verify_integrity_with_context(&risc0_zkvm::VerifierContext::default().with_dev_mode(false))
        .is_err());
    let segment = &composite.segments[0];
    assert!(segment
        .verify_integrity_with_context(&risc0_zkvm::VerifierContext::default().with_dev_mode(false))
        .is_err());
    let encoded = bincode::serialize(segment).unwrap();
    assert_eq!(preflight_segment(&encoded, 0).unwrap(), 1 << 18);
    assert!(preflight_segment(&encoded, 1).is_err());
    for length in 0..encoded.len() {
        assert!(preflight_segment(&encoded[..length], 0).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(preflight_segment(&trailing, 0).is_err());
    let encoded = bincode::serialize(&segment.claim).unwrap();
    assert!(preflight_claim(&encoded).is_ok());
    for length in 0..encoded.len() {
        assert!(preflight_claim(&encoded[..length]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(preflight_claim(&trailing).is_err());
}
