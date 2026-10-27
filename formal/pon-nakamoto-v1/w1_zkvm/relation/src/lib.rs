#![forbid(unsafe_code)]
//! Research statement for the COMPLETE existing PNH1/PNW1 relation.
//!
//! The exact native verifier is a dependency, not an independently weakened
//! circuit. This produces public bytes, never a Node admission capability.
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::{Header, HEADER_BYTES};

pub const DOMAIN: &[u8] = b"TRNM-W1-ZK-JOURNAL1\0";
pub const INPUT_BYTES: usize = HEADER_BYTES + pon_work::PROOF_BYTES;
pub const JOURNAL_BYTES: usize = DOMAIN.len() + HEADER_BYTES + 3 * 32 + pon_work::CELLS * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationError {
    InputLength,
    Header,
    Work(pon_work::WorkError),
    Journal,
    PublicStatement,
}

/// Fixed-length input: exact 318-byte PNH1, then exact 49,188-byte PNW1.
/// Header task/target/challenge are not separate prover-selected public inputs.
pub fn check_complete_relation(input: &[u8]) -> Result<Vec<u8>, RelationError> {
    if input.len() != INPUT_BYTES {
        return Err(RelationError::InputLength);
    }
    let header = Header::decode(&input[..HEADER_BYTES]).map_err(|_| RelationError::Header)?;
    let proof = &input[HEADER_BYTES..];
    // Includes canonical decoding, task commitment, nonzero target, full noise
    // rejection, all transcript prefixes, product reconstruction and ticket.
    // Do not replace this with precheck_proof_statement or sampled openings.
    let verified = pon_work::verify(header.challenge(), header.work_task, header.target, proof)
        .map_err(RelationError::Work)?;
    let trace: [u8; 32] = proof[pon_work::PROOF_BYTES - 32..].try_into().unwrap();
    let mut journal = Vec::with_capacity(JOURNAL_BYTES);
    journal.extend_from_slice(DOMAIN);
    journal.extend_from_slice(&header.encode());
    journal.extend_from_slice(&trace);
    journal.extend_from_slice(&verified.ticket());
    // The only logical work identity is the existing block identity. Receipt
    // randomness, image proofs and compressed encodings never enter it.
    journal.extend_from_slice(&header.block_id(trace));
    for word in verified.product() {
        journal.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(journal.len(), JOURNAL_BYTES);
    Ok(journal)
}

/// Check the public statement AFTER cryptographic receipt verification.
/// This does not replay W1 and cannot be used as cryptographic verification.
pub fn check_public_journal(
    expected_header: &[u8],
    journal: &[u8],
) -> Result<[u8; 32], RelationError> {
    if journal.len() != JOURNAL_BYTES || !journal.starts_with(DOMAIN) {
        return Err(RelationError::Journal);
    }
    let start = DOMAIN.len();
    if expected_header.len() != HEADER_BYTES
        || journal[start..start + HEADER_BYTES] != *expected_header
    {
        return Err(RelationError::PublicStatement);
    }
    let header = Header::decode(expected_header).map_err(|_| RelationError::Header)?;
    let start = start + HEADER_BYTES;
    let trace: [u8; 32] = journal[start..start + 32].try_into().unwrap();
    let ticket: [u8; 32] = journal[start + 32..start + 64].try_into().unwrap();
    let identity: [u8; 32] = journal[start + 64..start + 96].try_into().unwrap();
    if ticket != pon_work::hash(b"ticket", &[&header.challenge(), &trace])
        || header.target == [0; 32]
        || ticket > header.target
        || identity != header.block_id(trace)
        || journal[start + 96..]
            .chunks_exact(4)
            .any(|word| u128::from(u32::from_le_bytes(word.try_into().unwrap())) >= pon_work::Q)
    {
        return Err(RelationError::PublicStatement);
    }
    Ok(identity)
}

/// Reproducible dense fixture, no hidden task preparation in prover timings.
/// This is a controlled maximum-target cost sample, not a production block.
pub fn fixture(seed: u32) -> Vec<u8> {
    fn matrix(seed: u32, label: u8) -> Vec<u32> {
        let mut values = Vec::with_capacity(pon_work::CELLS);
        let mut counter = 0u32;
        while values.len() < pon_work::CELLS {
            let bytes = pon_work::hash(
                b"w1-zk-fixture-matrix-v1",
                &[&seed.to_le_bytes(), &[label], &counter.to_le_bytes()],
            );
            for word in bytes.chunks_exact(4) {
                let value = u32::from_le_bytes(word.try_into().unwrap());
                if u128::from(value) < pon_work::Q {
                    values.push(value);
                    if values.len() == pon_work::CELLS {
                        break;
                    }
                }
            }
            counter = counter
                .checked_add(1)
                .expect("bounded deterministic fixture");
        }
        values
    }
    let a = matrix(seed, 0);
    let b = matrix(seed, 1);
    let header = Header {
        network: pon_work::hash(b"w1-zk-research-network-v1", &[]),
        parameters: pon_work::hash(b"w1-zk-research-parameters-v1", &[]),
        parent: [5; 32],
        height: 1,
        timestamp: 1,
        target: [255; 32],
        miner: [7; 32],
        transactions: [8; 32],
        state: [9; 32],
        receipts: [10; 32],
        work_task: pon_work::task_id(&a, &b).unwrap(),
        nonce: u64::from(seed),
    };
    let mut input = header.encode();
    input.extend(pon_work::prove(header.challenge(), &a, &b).unwrap());
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_native_product_ticket_trace_and_unique_identity_are_public() {
        for seed in [0, 1, u32::MAX] {
            let input = fixture(seed);
            let journal = check_complete_relation(&input).unwrap();
            let header = Header::decode(&input[..HEADER_BYTES]).unwrap();
            let work = pon_work::verify_reference(
                header.challenge(),
                header.work_task,
                header.target,
                &input[HEADER_BYTES..],
            )
            .unwrap();
            let trace = input[input.len() - 32..].try_into().unwrap();
            assert_eq!(
                check_public_journal(&input[..HEADER_BYTES], &journal).unwrap(),
                header.block_id(trace)
            );
            let product: Vec<_> = work
                .product()
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect();
            assert_eq!(&journal[journal.len() - product.len()..], &product);
            assert_eq!(journal, check_complete_relation(&input).unwrap());
        }
    }

    #[test]
    fn rejects_all_omission_classes_before_any_proof_can_be_issued() {
        let input = fixture(1);
        let mut cases = Vec::new();
        cases.push(input[..input.len() - 1].to_vec());
        let mut extra = input.clone();
        extra.push(0);
        cases.push(extra);
        // Header, matrix A, matrix B, C, transcript: no component is omitted.
        for offset in [
            0,
            6,
            310,
            HEADER_BYTES,
            HEADER_BYTES + 4,
            HEADER_BYTES + 4 + pon_work::CELLS * 4,
            HEADER_BYTES + 4 + 2 * pon_work::CELLS * 4,
            input.len() - 1,
        ] {
            let mut bad = input.clone();
            bad[offset] ^= 1;
            cases.push(bad);
        }
        let mut bad_field = input.clone();
        bad_field[HEADER_BYTES + 4..HEADER_BYTES + 8]
            .copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
        cases.push(bad_field);
        let mut zero_target = input.clone();
        zero_target[118..150].fill(0);
        cases.push(zero_target);
        for case in cases {
            assert!(check_complete_relation(&case).is_err());
        }
    }

    #[test]
    fn public_binding_rejects_header_trace_ticket_id_and_noncanonical_product() {
        let input = fixture(2);
        let journal = check_complete_relation(&input).unwrap();
        for offset in [
            0,
            DOMAIN.len(),
            DOMAIN.len() + HEADER_BYTES,
            DOMAIN.len() + HEADER_BYTES + 32,
            DOMAIN.len() + HEADER_BYTES + 64,
        ] {
            let mut bad = journal.clone();
            bad[offset] ^= 1;
            assert!(check_public_journal(&input[..HEADER_BYTES], &bad).is_err());
        }
        let mut bad = journal.clone();
        let offset = DOMAIN.len() + HEADER_BYTES + 96;
        bad[offset..offset + 4].copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
        assert!(check_public_journal(&input[..HEADER_BYTES], &bad).is_err());
        let other = fixture(3);
        assert!(check_public_journal(&other[..HEADER_BYTES], &journal).is_err());
    }
}
