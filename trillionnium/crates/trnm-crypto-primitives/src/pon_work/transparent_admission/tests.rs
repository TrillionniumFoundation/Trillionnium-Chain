use super::*;
use sha2::{Digest as _, Sha256};

const ORIGINAL: &[u8] = include_bytes!("complete-w1-succinct.bin");

fn sample() -> (Vec<u8>, PublicStatement) {
    assert_eq!(ORIGINAL.len(), 273_338);
    assert_eq!(
        hex::encode(Sha256::digest(ORIGINAL)),
        "9c370089ba5203b9a8559b900c975778425839f4ccfa171387bdfb0853a3e5c9"
    );
    assert_eq!(&ORIGINAL[..8], b"PWSR0001");
    let mut wire = ORIGINAL.to_vec();
    wire[..8].copy_from_slice(MAGIC);
    let (input, _) = parts(&wire).unwrap();
    let expected = PublicStatement::decode(&input[..STATEMENT_BYTES]).unwrap();
    (wire, expected)
}

fn frame(input: &[u8], receipt: &[u8]) -> Vec<u8> {
    let mut wire = MAGIC.to_vec();
    wire.extend((input.len() as u32).to_le_bytes());
    wire.extend((receipt.len() as u32).to_le_bytes());
    wire.extend(input);
    wire.extend(receipt);
    wire
}

#[test]
fn actual_transparent_proof_verifies_complete_original_statement() {
    let (wire, expected) = sample();
    let actual = verify_bound(&wire, &expected).unwrap();
    assert_eq!(actual.statement_id(), expected.statement_id());
    assert_eq!(actual.certificate_bytes(), wire.len());
    // This is a real SDK verification of the retained proof, not a freshly
    // generated proof, an input allowlist or an execution-only substitute.
}

#[test]
fn every_header_byte_and_external_task_target_and_witness_are_bound() {
    let (wire, expected) = sample();
    let input = parts(&wire).unwrap().0;
    let pnw1 = &input[STATEMENT_BYTES..];
    for offset in 0..full_relation::HEADER_BYTES {
        let mut header = *expected.header_bytes();
        header[offset] ^= 1;
        if let Ok(foreign) = PublicStatement::bind(
            &header,
            expected.expected_task(),
            expected.expected_target(),
            pnw1,
        ) {
            assert!(
                verify_bound(&wire, &foreign).is_err(),
                "header byte {offset}"
            );
        }
    }
    let mut task = expected.expected_task();
    task[0] ^= 1;
    let mut target = expected.expected_target();
    target[0] ^= 1;
    let mut witness = pnw1.to_vec();
    witness[100] ^= 1;
    for foreign in [
        PublicStatement::bind(
            expected.header_bytes(),
            task,
            expected.expected_target(),
            pnw1,
        ),
        PublicStatement::bind(
            expected.header_bytes(),
            expected.expected_task(),
            target,
            pnw1,
        ),
        PublicStatement::bind(
            expected.header_bytes(),
            expected.expected_task(),
            expected.expected_target(),
            &witness,
        ),
    ] {
        assert!(verify_bound(&wire, &foreign.unwrap()).is_err());
    }
}

#[test]
fn inconsistent_header_task_and_target_refuse_before_receipt_processing() {
    let (wire, expected) = sample();
    let (input, raw) = parts(&wire).unwrap();
    let pnw1 = &input[STATEMENT_BYTES..];
    let invalid_receipt = 0u32.to_le_bytes();
    // This control reaches the receipt grammar, while the impossible statements
    // below must refuse even earlier, independently of the supplied receipt.
    assert_eq!(
        verify_bound(&frame(input, &invalid_receipt), &expected)
            .unwrap_err()
            .to_string(),
        "only actual Succinct receipts"
    );
    for (bad_task, bad_target, error, relation_error) in [
        (
            true,
            false,
            "W1_CERTIFICATE_HEADER_TASK",
            full_relation::RelationError::HeaderTask,
        ),
        (
            false,
            true,
            "W1_CERTIFICATE_HEADER_TARGET",
            full_relation::RelationError::HeaderTarget,
        ),
        (
            true,
            true,
            "W1_CERTIFICATE_HEADER_TASK",
            full_relation::RelationError::HeaderTask,
        ),
    ] {
        let mut header = Header::decode(expected.header_bytes()).unwrap();
        if bad_task {
            header.work_task[0] ^= 1;
        }
        if bad_target {
            header.target[0] ^= 1;
        }
        let inconsistent = PublicStatement::bind(
            &header.encode(),
            expected.expected_task(),
            expected.expected_target(),
            pnw1,
        )
        .unwrap();
        let mut forged_input = input.to_vec();
        forged_input[..STATEMENT_BYTES].copy_from_slice(&inconsistent.encode());
        // The previously available cheap proof filter accepts these inputs;
        // the complete guest relation nevertheless rejects before W1 replay.
        super::super::precheck_proof_statement(
            header.challenge(),
            inconsistent.expected_task(),
            inconsistent.expected_target(),
            pnw1,
        )
        .unwrap();
        assert_eq!(
            full_relation::execute_input(&forged_input).unwrap_err(),
            relation_error
        );
        // External context mismatch still takes precedence over the new check.
        assert_eq!(
            verify_bound(&wire, &inconsistent).unwrap_err().to_string(),
            "W1_CERTIFICATE_CONTEXT"
        );
        let mut rebound: Receipt = bounds::decode(raw).unwrap();
        rebound.journal.bytes = full_relation::unverified_claimed_journal(&forged_input).unwrap();
        let rebound_raw = bounds::encode(&rebound).unwrap();
        bounds::preflight(&rebound_raw).unwrap();
        for receipt in [invalid_receipt.as_slice(), rebound_raw.as_slice()] {
            assert_eq!(
                verify_bound(&frame(&forged_input, receipt), &inconsistent)
                    .unwrap_err()
                    .to_string(),
                error
            );
        }
    }
}

#[test]
fn false_received_claim_cannot_reuse_a_valid_proof_even_with_rebound_journal() {
    let (wire, expected) = sample();
    let (input, raw) = parts(&wire).unwrap();
    let mut forged_input = input.to_vec();
    // A caller changes the complete canonical PNW1 trace, then updates its
    // commitment, expected context and public journal. No native W1 is run.
    let last = forged_input.len() - 1;
    forged_input[last] ^= 1;
    let forged_expected = PublicStatement::bind(
        expected.header_bytes(),
        expected.expected_task(),
        expected.expected_target(),
        &forged_input[STATEMENT_BYTES..],
    )
    .unwrap();
    forged_input[..STATEMENT_BYTES].copy_from_slice(&forged_expected.encode());
    let mut receipt: Receipt = bounds::decode(raw).unwrap();
    receipt.journal.bytes = full_relation::unverified_claimed_journal(&forged_input).unwrap();
    let forged = frame(&forged_input, &bounds::encode(&receipt).unwrap());
    assert_eq!(
        verify_bound(&forged, &forged_expected)
            .unwrap_err()
            .to_string(),
        "W1_CERTIFICATE_PROOF"
    );
}

#[test]
fn actual_seal_corruption_is_rejected_by_the_cryptographic_verifier() {
    let (wire, expected) = sample();
    let (input, raw) = parts(&wire).unwrap();
    let mut receipt: Receipt = bounds::decode(raw).unwrap();
    let InnerReceipt::Succinct(proof) = &mut receipt.inner else {
        panic!("actual Succinct")
    };
    proof.seal[40] ^= 1;
    let corrupted = frame(input, &bounds::encode(&receipt).unwrap());
    // Encoding is still in the fixed bounded grammar; cryptography must reject.
    bounds::preflight(parts(&corrupted).unwrap().1).unwrap();
    assert_eq!(
        verify_bound(&corrupted, &expected).unwrap_err().to_string(),
        "W1_CERTIFICATE_PROOF"
    );
}

#[test]
fn ambient_development_mode_is_refused_in_separate_processes_without_panic() {
    for mode in ["1", "0", "true", "false"] {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pon_work::transparent_admission::tests::ambient_dev_mode_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("RISC0_DEV_MODE", mode)
            .env("TRNM_W1_CERTIFICATE_DEV_MODE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "mode={mode} stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(stdout.contains("running 1 test"));
        assert!(stdout.contains("1 passed; 0 failed; 0 ignored;"));
    }
}

#[test]
#[ignore = "subprocess invoked explicitly by ambient mode test"]
fn ambient_dev_mode_child() {
    assert_eq!(
        std::env::var("TRNM_W1_CERTIFICATE_DEV_MODE_CHILD").as_deref(),
        Ok("1")
    );
    let (wire, expected) = sample();
    assert_eq!(
        verify_bound(&wire, &expected).unwrap_err().to_string(),
        "W1_CERTIFICATE_DEV_MODE"
    );
}

#[test]
fn allocation_prefixes_foreign_kinds_parameters_and_trailing_data_refuse() {
    let (wire, expected) = sample();
    for mut bad in [
        Vec::new(),
        vec![0; 16],
        vec![0; MAX_CERTIFICATE_BYTES + 1],
        wire.clone(),
    ] {
        if bad.len() == wire.len() {
            bad[..8].copy_from_slice(b"PWSR0001");
        }
        assert!(verify_bound(&bad, &expected).is_err());
    }
    for offset in [8, 12] {
        let mut bad = wire.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(verify_bound(&bad, &expected).is_err());
    }
    let (input, raw) = parts(&wire).unwrap();
    for kind in [0u32, 2, 3, u32::MAX] {
        let mut bad = raw.to_vec();
        bad[..4].copy_from_slice(&kind.to_le_bytes());
        assert!(verify_bound(&frame(input, &bad), &expected).is_err());
    }
    let mut allocation = raw.to_vec();
    allocation[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(verify_bound(&frame(input, &allocation), &expected).is_err());
    for po2 in [0u32, 17, 19, 31, u32::MAX] {
        let mut bad = raw.to_vec();
        bad[12 + 128..12 + 132].copy_from_slice(&po2.to_le_bytes());
        assert!(verify_bound(&frame(input, &bad), &expected).is_err());
    }
    for keep in [0, 8, 16, 16 + INPUT_BYTES, wire.len() - 1] {
        assert!(verify_bound(&wire[..keep], &expected).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(verify_bound(&trailing, &expected).is_err());
    let mut receipt: Receipt = bounds::decode(raw).unwrap();
    let InnerReceipt::Succinct(proof) = &mut receipt.inner else {
        panic!("actual Succinct")
    };
    proof.verifier_parameters = Digest::ZERO;
    assert!(verify_bound(&frame(input, &bounds::encode(&receipt).unwrap()), &expected).is_err());
}
