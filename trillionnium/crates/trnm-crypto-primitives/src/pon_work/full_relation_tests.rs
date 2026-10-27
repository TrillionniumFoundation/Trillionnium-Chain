use super::*;
use crate::pon_work as native;
use trnm_protocol::pon_wire::Header;

fn header(a: &[u32], b: &[u32], nonce: u64) -> Header {
    Header {
        network: [1; 32],
        parameters: [2; 32],
        parent: [3; 32],
        height: 17,
        timestamp: 1_234_567,
        target: [255; 32],
        miner: [4; 32],
        transactions: [5; 32],
        state: [6; 32],
        receipts: [7; 32],
        work_task: native::task_id(a, b).unwrap(),
        nonce,
    }
}

fn statement(header: &Header, bytes: &[u8]) -> PublicStatement {
    PublicStatement::bind(&header.encode(), header.work_task, header.target, bytes).unwrap()
}

fn native_result(
    h: &Header,
    bytes: &[u8],
    kernel: usize,
) -> Result<(Hash, Hash, Hash, Vec<u32>), WorkError> {
    let value = match kernel {
        0 => native::verify(h.challenge(), h.work_task, h.target, bytes),
        1 => native::verify_reference(h.challenge(), h.work_task, h.target, bytes),
        2 => native::verify_limb(h.challenge(), h.work_task, h.target, bytes),
        _ => unreachable!(),
    }?;
    Ok((
        value.challenge(),
        value.task(),
        value.ticket(),
        value.product().to_vec(),
    ))
}

fn assert_native_parity(h: &Header, bytes: &[u8]) -> Result<LocalExecution, RelationError> {
    let actual = execute(&statement(h, bytes), bytes);
    for kernel in 0..3 {
        match (&actual, native_result(h, bytes, kernel)) {
            (Ok(local), Ok((challenge, task, ticket, product))) => {
                assert_eq!(local.challenge(), challenge);
                assert_eq!(local.task(), task);
                assert_eq!(local.ticket(), ticket);
                assert_eq!(local.product(), product);
                assert_eq!(local.block_id(), h.block_id(local.trace()));
            }
            (Err(RelationError::Work(actual)), Err(expected)) => assert_eq!(*actual, expected),
            (actual, expected) => {
                panic!("kernel {kernel}: relation={actual:?}, native={expected:?}")
            }
        }
    }
    actual
}

fn dense(seed: u64) -> (Vec<u32>, Vec<u32>) {
    let mut state = seed | 1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (u128::from(state) % Q) as u32
    };
    (
        (0..CELLS).map(|_| next()).collect(),
        (0..CELLS).map(|_| next()).collect(),
    )
}

#[test]
fn complete_guest_relation_matches_all_native_kernels_and_structural_materials() {
    let zero = vec![0; CELLS];
    let one = vec![1; CELLS];
    let high = vec![(Q - 1) as u32; CELLS];
    let identity: Vec<_> = (0..CELLS).map(|i| u32::from(i / N == i % N)).collect();
    let sparse: Vec<_> = (0..CELLS)
        .map(|i| if i % 127 == 0 { (i + 1) as u32 } else { 0 })
        .collect();
    let rank_one: Vec<_> = (0..CELLS)
        .map(|i| ((i / N + 1) * (i % N + 1)) as u32)
        .collect();
    let mut cases = vec![
        (zero.clone(), zero.clone()),
        (zero.clone(), high.clone()),
        (high.clone(), zero),
        (one.clone(), one),
        (high.clone(), high),
        (identity, rank_one.clone()),
        (sparse, rank_one),
    ];
    cases.extend((1..=12).map(dense));
    for (case, (a, b)) in cases.into_iter().enumerate() {
        let h = header(&a, &b, case as u64);
        let bytes = native::prove(h.challenge(), &a, &b).unwrap();
        let observed = assert_native_parity(&h, &bytes).unwrap();
        assert_eq!(observed.product(), matrix_product(&a, &b, N, N, N));
        assert_eq!(observed.trace(), array(&bytes[PROOF_BYTES - 32..]));
    }
}

#[test]
fn every_header_field_is_bound_to_the_full_work_attempt() {
    let (a, b) = dense(91);
    let h = header(&a, &b, 77);
    let bytes = native::prove(h.challenge(), &a, &b).unwrap();
    let original = execute(&statement(&h, &bytes), &bytes).unwrap();
    // One byte in each of all twelve header fields, after its fixed prefix.
    for offset in [6, 38, 70, 102, 110, 118, 150, 182, 214, 246, 278, 310] {
        let mut changed = h.encode();
        changed[offset] ^= 1;
        let changed_header = Header::decode(&changed).unwrap();
        let stale_context = PublicStatement::bind(&changed, h.work_task, h.target, &bytes).unwrap();
        assert_ne!(stale_context.statement_id(), original.statement_id());
        assert!(
            execute(&stale_context, &bytes).is_err(),
            "header offset {offset}"
        );
        // Updating the claimed external context still cannot reuse old work.
        let refreshed_context = statement(&changed_header, &bytes);
        assert!(
            execute(&refreshed_context, &bytes).is_err(),
            "updated context {offset}"
        );
    }
}

#[test]
fn public_task_and_target_must_match_the_bound_header() {
    let (a, b) = dense(19);
    let h = header(&a, &b, 2);
    let bytes = native::prove(h.challenge(), &a, &b).unwrap();
    let wrong_task = PublicStatement::bind(&h.encode(), [91; 32], h.target, &bytes).unwrap();
    assert_eq!(execute(&wrong_task, &bytes), Err(RelationError::HeaderTask));
    let wrong_target = PublicStatement::bind(&h.encode(), h.work_task, [127; 32], &bytes).unwrap();
    assert_eq!(
        execute(&wrong_target, &bytes),
        Err(RelationError::HeaderTarget)
    );
}

#[test]
fn committed_first_middle_and_last_prefix_fraud_rejects_even_with_correct_product() {
    let (a, b) = dense(31);
    let h = header(&a, &b, 99);
    let original = native::prove(h.challenge(), &a, &b).unwrap();
    let mut prefixes = Vec::new();
    replay(h.challenge(), &a, &b, |position, value| {
        assert_eq!(position, prefixes.len());
        prefixes.push(value);
    })
    .unwrap();
    assert_eq!(prefixes.len(), 512 * R * R);
    for position in [0, prefixes.len() / 2, prefixes.len() - 1] {
        let mut forged_hash = Sha256::new();
        forged_hash.update(b"TRNM-PON-TRACE1\0");
        forged_hash.update(h.challenge());
        for (index, value) in prefixes.iter().enumerate() {
            let value = if index == position {
                ((u128::from(*value) + 1) % Q) as u32
            } else {
                *value
            };
            forged_hash.update(value.to_le_bytes());
        }
        let mut forged = original.clone();
        forged[PROOF_BYTES - 32..].copy_from_slice(&forged_hash.finalize());
        assert_ne!(forged, original);
        // A complete hash commitment and original cheap ticket both pass.
        assert_eq!(
            native::precheck_proof_statement(h.challenge(), h.work_task, h.target, &forged),
            Ok(())
        );
        assert_eq!(
            assert_native_parity(&h, &forged),
            Err(RelationError::Work(WorkError::Transcript))
        );
    }
}

#[test]
fn a_witness_hash_is_only_a_commitment_and_never_complete_work() {
    let (a, b) = dense(57);
    let h = header(&a, &b, 1);
    let mut bytes = native::prove(h.challenge(), &a, &b).unwrap();
    let bound = statement(&h, &bytes);
    bytes[PROOF_BYTES - 1] ^= 1;
    assert_eq!(
        execute(&bound, &bytes),
        Err(RelationError::WitnessCommitment)
    );
    let rebound = statement(&h, &bytes);
    assert_eq!(
        execute(&rebound, &bytes),
        Err(RelationError::Work(WorkError::Transcript))
    );
    let mut false_input = rebound.encode().to_vec();
    false_input.extend_from_slice(&bytes);
    // The expected public output is cheap to construct even for a false claim;
    // only a real computation proof may authenticate it.
    assert!(unverified_claimed_journal(&false_input).is_ok());
}

#[test]
fn malformed_wrong_product_wrong_task_and_missed_ticket_match_native_errors() {
    let (a, b) = dense(71);
    let h = header(&a, &b, 8);
    let original = native::prove(h.challenge(), &a, &b).unwrap();
    let mut bad_magic = original.clone();
    bad_magic[0] ^= 1;
    assert_eq!(
        assert_native_parity(&h, &bad_magic),
        Err(WorkError::Version.into())
    );
    for matrix in 0..3 {
        let mut noncanonical = original.clone();
        let start = 4 + matrix * MATRIX_BYTES;
        noncanonical[start..start + 4].copy_from_slice(&(Q as u32).to_le_bytes());
        assert_eq!(
            assert_native_parity(&h, &noncanonical),
            Err(WorkError::Field.into())
        );
    }
    let mut wrong_product = original.clone();
    let offset = 4 + 2 * MATRIX_BYTES;
    let value = u32::from_le_bytes(wrong_product[offset..offset + 4].try_into().unwrap());
    wrong_product[offset..offset + 4]
        .copy_from_slice(&(((u128::from(value) + 1) % Q) as u32).to_le_bytes());
    assert_eq!(
        assert_native_parity(&h, &wrong_product),
        Err(WorkError::Product.into())
    );
    let mut wrong_task = h.clone();
    wrong_task.work_task = [91; 32];
    assert_eq!(
        assert_native_parity(&wrong_task, &original),
        Err(WorkError::Task.into())
    );
    let mut zero_target = h.clone();
    zero_target.target = [0; 32];
    assert_eq!(
        assert_native_parity(&zero_target, &original),
        Err(WorkError::Target.into())
    );
    let mut tiny_target = zero_target;
    tiny_target.target[31] = 1;
    let missed = native::prove(tiny_target.challenge(), &a, &b).unwrap();
    assert_eq!(
        assert_native_parity(&tiny_target, &missed),
        Err(WorkError::Target.into())
    );
    let bound = statement(&h, &original);
    for length in [0, 1, 4, PROOF_BYTES - 1] {
        assert_eq!(
            execute(&bound, &original[..length]),
            Err(WorkError::Length.into())
        );
    }
    let mut extended = original;
    extended.push(0);
    assert_eq!(execute(&bound, &extended), Err(WorkError::Length.into()));
}

#[test]
fn statement_and_input_are_exact_versioned_encodings_with_no_proof_nonce() {
    let (a, b) = dense(43);
    let h = header(&a, &b, 5);
    let bytes = native::prove(h.challenge(), &a, &b).unwrap();
    let bound = statement(&h, &bytes);
    let encoded = bound.encode();
    assert_eq!(PublicStatement::decode(&encoded), Ok(bound.clone()));
    assert_eq!(bound.header_bytes().as_slice(), h.encode());
    assert_eq!(bound.expected_task(), h.work_task);
    assert_eq!(bound.expected_target(), h.target);
    assert_eq!(bound.witness_commitment(), witness_commitment(&bytes));
    for length in [0, 1, 6, STATEMENT_BYTES - 1] {
        assert_eq!(
            PublicStatement::decode(&encoded[..length]),
            Err(RelationError::StatementLength)
        );
    }
    for offset in [0, 4] {
        let mut changed = encoded;
        changed[offset] ^= 1;
        assert_eq!(
            PublicStatement::decode(&changed),
            Err(RelationError::StatementVersion)
        );
    }
    let mut wrong_profile = encoded;
    wrong_profile[6] ^= 1;
    assert_eq!(
        PublicStatement::decode(&wrong_profile),
        Err(RelationError::Profile)
    );
    let mut wrong_header = encoded;
    wrong_header[38] ^= 1;
    assert_eq!(
        PublicStatement::decode(&wrong_header),
        Err(RelationError::HeaderEncoding)
    );
    let mut input = encoded.to_vec();
    input.extend_from_slice(&bytes);
    assert_eq!(input.len(), INPUT_BYTES);
    let first = execute_input(&input).unwrap();
    let second = execute_input(&input).unwrap();
    assert_eq!(first.block_id(), second.block_id());
    assert_eq!(first.ticket(), second.ticket());
    assert_eq!(first.journal(), second.journal());
    assert_eq!(unverified_claimed_journal(&input).unwrap(), first.journal());
    input.push(0); // No attacker-chosen proof randomness is a work input.
    assert_eq!(execute_input(&input), Err(RelationError::StatementLength));
}

#[test]
fn task_and_challenge_hashes_match_the_existing_canonical_domains() {
    let (a, b) = dense(123);
    let h = header(&a, &b, 54);
    assert_eq!(HEADER_BYTES, trnm_protocol::pon_wire::HEADER_BYTES);
    assert_eq!(domain_hash(b"challenge", &[&h.encode()]), h.challenge());
    assert_eq!(
        domain_hash(b"task", &[&field_bytes(&a), &field_bytes(&b)]),
        native::task_id(&a, &b).unwrap()
    );
    for header_bytes in [&[][..], &h.encode()[..HEADER_BYTES - 1]] {
        assert_eq!(
            parse_header(header_bytes),
            Err(RelationError::HeaderEncoding)
        );
    }
}
