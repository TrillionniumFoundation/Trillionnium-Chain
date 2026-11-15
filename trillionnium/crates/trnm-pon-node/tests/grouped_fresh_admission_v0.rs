//! Real native signatures and branch targets over controlled research requests.
//! These fixture identities are public; no independent external demand is claimed.
use trnm_crypto_primitives::{
    pon_grouped_fresh_seal_v0 as seal, public_key_hex, sign_hex, signing_key_from_hex,
};
use trnm_pon_node::{development_public, grouped_fresh_admission_v0::*, Node, Settings};
use trnm_protocol::pon_wire::hash;

fn fixture() -> (tempfile::TempDir, Node, PinnedAuthority, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(
        &directory.path().join("node.sqlite"),
        Settings::development(Some(1_700_000_000)).unwrap(),
        1,
    )
    .unwrap();
    let intent = CapsuleIntent {
        registry_id: [1; 32],
        registry_digest: [2; 32],
        previous_registry_digest: [0; 32],
        demand_id: [3; 32],
        source_record: [4; 32],
        authorization_scope: [5; 32],
        withdrawal_head: [6; 32],
        model_commitment: [7; 32],
        request_precommitment: [8; 32],
        batch_id: [9; 32],
        transactions_commitment: [10; 32],
        payee: [11; 32],
        operation_id: [12; 32],
        registry_sequence: 1,
        model_generation: 1,
        timestamp_ms: 1500,
        not_before_ns: 1_000_000_000,
        expires_ns: 2_000_000_000,
        available_until_ns: 3_000_000_000,
        nonce_first: 1,
        nonce_count: 64,
    };
    let body = CapsuleBody::from_node(&node, intent).unwrap();
    let (external, raw) = sign(body);
    (directory, node, external, raw)
}
fn sign(body: CapsuleBody) -> (PinnedAuthority, Vec<u8>) {
    let requester = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&40_u64.to_le_bytes()],
    )))
    .unwrap();
    let source = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&41_u64.to_le_bytes()],
    )))
    .unwrap();
    let rs: [u8; 64] = hex::decode(sign_hex(
        &requester,
        &signing_message(&body, SigningRole::Requester),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let ss: [u8; 64] = hex::decode(sign_hex(
        &source,
        &signing_message(&body, SigningRole::Source),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let raw = signed_capsule(&body, rs, ss);
    let external = PinnedAuthority {
        requester_key: hex::decode(public_key_hex(&requester))
            .unwrap()
            .try_into()
            .unwrap(),
        source_key: hex::decode(public_key_hex(&source))
            .unwrap()
            .try_into()
            .unwrap(),
        latest_sequence: body.intent().registry_sequence,
        latest_digest: body.intent().registry_digest,
        expected_capsule_sha256: sha256(&raw),
        expected: body,
    };
    (external, raw)
}

fn record_permit(
    journal: &mut ResearchLedger,
    verified: &VerifiedAdmission,
    nonce: u64,
    statement: [u8; 32],
    proof: &[u8],
    node: &Node,
) -> ClaimedVerification {
    let request = VerificationRequest::from_digests(
        nonce,
        statement,
        sha256(proof),
        verified.capsule_sha256(),
        VerificationMode::Record,
    );
    let permit = journal
        .reserve_verification(verified, &request, node, 1_500_000_000)
        .unwrap();
    journal
        .claim_verification(verified, permit.id(), &request)
        .unwrap()
}

#[test]
fn exact_external_body_real_native_signatures_and_branch_target_are_required() {
    let (_directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    assert_eq!(raw.len(), CAPSULE_BYTES);
    assert_eq!(external.expected.encode().len(), BODY_BYTES);
    assert_eq!(verified.candidate_bytes(1).unwrap().len(), CANDIDATE_BYTES);
    assert_eq!(
        verified.body().branch().target(),
        node.expected_target(node.active().unwrap().0).unwrap()
    );
    assert_eq!(
        verified.challenge_for_nonce(1).unwrap(),
        hash(
            b"pon-grouped-fresh-challenge-v0",
            &[&verified.candidate_bytes(1).unwrap()]
        )
    );
    assert_ne!(
        verified.challenge_for_nonce(1).unwrap(),
        verified.challenge_for_nonce(2).unwrap()
    );
    assert_ne!(verified.work_id(1).unwrap(), verified.work_id(2).unwrap());
    assert_eq!(verified.chainwork_awarded(), 0);
    let mut wrong = external.clone();
    wrong.source_key = wrong.requester_key;
    assert_eq!(
        verify_capsule(&raw, &wrong, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::ExternalPin
    );
    let mut wrong = external.clone();
    wrong.latest_sequence += 1;
    assert_eq!(
        verify_capsule(&raw, &wrong, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::ExternalPin
    );
    let mut wrong = external.clone();
    wrong.expected_capsule_sha256[0] ^= 1;
    assert_eq!(
        verify_capsule(&raw, &wrong, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::ExternalPin
    );
    let mut changed = raw.clone();
    changed[6 + BODY_BYTES] ^= 1;
    let mut pinned_changed = external.clone();
    pinned_changed.expected_capsule_sha256 = sha256(&changed);
    assert_eq!(
        verify_capsule(&changed, &pinned_changed, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::Signature
    );
    let mut swapped = raw.clone();
    swapped[6 + BODY_BYTES..6 + BODY_BYTES + 64].copy_from_slice(&raw[6 + BODY_BYTES + 64..]);
    swapped[6 + BODY_BYTES + 64..].copy_from_slice(&raw[6 + BODY_BYTES..6 + BODY_BYTES + 64]);
    let mut pinned_swapped = external.clone();
    pinned_swapped.expected_capsule_sha256 = sha256(&swapped);
    assert_eq!(
        verify_capsule(&swapped, &pinned_swapped, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::Signature
    );
}

#[test]
fn every_body_byte_is_exact_and_no_caller_profile_target_or_nonce_window_is_selected() {
    let (_directory, node, external, raw) = fixture();
    for index in 6..6 + BODY_BYTES {
        let mut changed = raw.clone();
        changed[index] ^= 1;
        let mut pinned_changed = external.clone();
        pinned_changed.expected_capsule_sha256 = sha256(&changed);
        assert_eq!(
            verify_capsule(&changed, &pinned_changed, &node, 1_500_000_000).unwrap_err(),
            AdmissionError::ExpectedBody,
            "byte {index}"
        );
    }
    let mut longer = raw.clone();
    longer.push(0);
    assert_eq!(
        verify_capsule(&longer, &external, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::Shape
    );
    assert_eq!(
        verify_capsule(&raw[..raw.len() - 1], &external, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::Shape
    );
    let verified = verify_capsule(&raw, &external, &node, 1_000_000_000).unwrap();
    assert_eq!(
        verified.candidate_bytes(0).unwrap_err(),
        AdmissionError::Nonce
    );
    assert_eq!(
        verified.candidate_bytes(65).unwrap_err(),
        AdmissionError::Nonce
    );
    assert_eq!(
        verify_capsule(&raw, &external, &node, 999_999_999).unwrap_err(),
        AdmissionError::Window
    );
    assert_eq!(
        verify_capsule(&raw, &external, &node, 2_000_000_000).unwrap_err(),
        AdmissionError::Window
    );
    let mut intent = external.expected.intent().clone();
    intent.nonce_first = u64::MAX;
    intent.nonce_count = 2;
    assert_eq!(
        CapsuleBody::from_node(&node, intent).unwrap_err(),
        AdmissionError::Nonce
    );
}

#[test]
fn signed_alternative_material_cannot_replace_external_expectation() {
    let (_directory, node, external, raw) = fixture();
    let mut intent = external.expected.intent().clone();
    intent.model_commitment[0] ^= 1;
    let (_, changed) = sign(CapsuleBody::from_node(&node, intent).unwrap());
    assert_eq!(
        verify_capsule(&changed, &external, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::ExpectedBody
    );
    let foreign_dir = tempfile::tempdir().unwrap();
    let foreign = Node::open(
        &foreign_dir.path().join("foreign.sqlite"),
        Settings::development(Some(1_700_000_001)).unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(
        verify_capsule(&raw, &external, &foreign, 1_500_000_000).unwrap_err(),
        AdmissionError::NativeContext
    );
}

#[test]
fn native_parent_change_invalidates_prepared_authority_before_reuse() {
    let (_directory, mut node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let packet = node
        .make(
            node.active().unwrap().0,
            vec![],
            development_public(0).unwrap(),
            1_700_000_001,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 1_700_000_001).unwrap();
    node.activate(id).unwrap();
    assert_eq!(
        verified.recheck(&node, 1_500_000_000).unwrap_err(),
        AdmissionError::NativeContext
    );
    assert_eq!(
        verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap_err(),
        AdmissionError::NativeContext
    );
}

#[test]
fn durable_reserved_unknown_and_completed_work_survive_reopen_without_credit() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let path = directory.path().join("research.sqlite");
    let mut journal = ResearchLedger::create(&path, &verified).unwrap();
    journal.reserve(&verified, 1, &node, 1_500_000_000).unwrap();
    drop(journal);
    let mut journal = ResearchLedger::open(&path, &verified).unwrap();
    assert_eq!(
        journal
            .reserve(&verified, 1, &node, 1_500_000_000)
            .unwrap_err(),
        AdmissionError::Replay
    );
    let statement = [17; 32];
    let proof = seal::prove(verified.challenge_for_nonce(1).unwrap(), statement);
    journal.produced(&verified, 1, statement, &proof).unwrap();
    let claimed = record_permit(&mut journal, &verified, 1, statement, &proof, &node);
    let first = journal
        .verify_and_record(claimed, &verified, 1, statement, &proof, &node, || {
            Ok(1_500_000_000)
        })
        .unwrap();
    assert!(first.first_record);
    assert_eq!(first.chainwork_awarded, 0);
    assert!(!first.grouped_arithmetic_verified_by_this_api);
    assert!(!first.external_demand_authenticated);
    drop(journal);
    let mut journal = ResearchLedger::open(&path, &verified).unwrap();
    let claimed = record_permit(&mut journal, &verified, 1, statement, &proof, &node);
    let repeated = journal
        .verify_and_record(claimed, &verified, 1, statement, &proof, &node, || {
            Ok(1_500_000_000)
        })
        .unwrap();
    assert!(!repeated.first_record);
    assert_eq!(first.work_id, repeated.work_id);
    assert_eq!(
        journal.observation().unwrap()["attempts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        journal
            .reserve(&verified, 2, &node, 2_000_000_000)
            .unwrap_err(),
        AdmissionError::Window
    );
    assert_eq!(
        journal.observation().unwrap()["attempts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn copied_endpoint_or_wrong_statement_cannot_complete_reserved_work() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let mut journal =
        ResearchLedger::create(&directory.path().join("ledger.sqlite"), &verified).unwrap();
    let statement = [13; 32];
    let original = seal::prove(verified.challenge_for_nonce(1).unwrap(), statement);
    journal.reserve(&verified, 2, &node, 1_500_000_000).unwrap();
    journal
        .produced(&verified, 2, statement, &original)
        .unwrap();
    let claimed = record_permit(&mut journal, &verified, 2, statement, &original, &node);
    assert_eq!(
        journal
            .verify_and_record(claimed, &verified, 2, statement, &original, &node, || Ok(
                1_500_000_000
            ))
            .unwrap_err(),
        AdmissionError::Seal(seal::SealError::Challenge)
    );
    assert_eq!(
        journal.observation().unwrap()["attempts"][0]["status"],
        "produced"
    );
    let altered = seal::prove(verified.challenge_for_nonce(2).unwrap(), statement);
    let claimed = record_permit(&mut journal, &verified, 2, statement, &altered, &node);
    assert_eq!(
        journal
            .verify_and_record(claimed, &verified, 2, statement, &altered, &node, || Ok(
                1_500_000_000
            ))
            .unwrap_err(),
        AdmissionError::ProductionBinding
    );
    assert_eq!(
        journal
            .reserve(&verified, 2, &node, 1_500_000_000)
            .unwrap_err(),
        AdmissionError::Replay
    );
}

#[test]
fn changed_policy_never_reopens_or_resets_an_existing_research_ledger() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let path = directory.path().join("ledger.sqlite");
    let journal = ResearchLedger::create(&path, &verified).unwrap();
    drop(journal);
    let mut intent = external.expected.intent().clone();
    intent.authorization_scope[0] ^= 1;
    let (different, other_raw) = sign(CapsuleBody::from_node(&node, intent).unwrap());
    let other = verify_capsule(&other_raw, &different, &node, 1_500_000_000).unwrap();
    assert!(matches!(
        ResearchLedger::open(&path, &other),
        Err(AdmissionError::JournalContext)
    ));
    assert!(ResearchLedger::create(&path, &other).is_err());
}

#[test]
fn expiry_after_full_replay_or_before_commit_never_consumes_completed_credit() {
    for expire_at_check in [2, 3] {
        let (directory, node, external, raw) = fixture();
        let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
        let mut journal =
            ResearchLedger::create(&directory.path().join("ledger.sqlite"), &verified).unwrap();
        journal.reserve(&verified, 1, &node, 1_500_000_000).unwrap();
        let statement = [19; 32];
        let proof = seal::prove(verified.challenge_for_nonce(1).unwrap(), statement);
        journal.produced(&verified, 1, statement, &proof).unwrap();
        let claimed = record_permit(&mut journal, &verified, 1, statement, &proof, &node);
        let mut calls = 0;
        let result =
            journal.verify_and_record(claimed, &verified, 1, statement, &proof, &node, || {
                calls += 1;
                Ok(if calls >= expire_at_check {
                    2_000_000_000
                } else {
                    1_500_000_000
                })
            });
        assert_eq!(result.unwrap_err(), AdmissionError::Window);
        assert_eq!(calls, expire_at_check);
        assert_eq!(
            journal.observation().unwrap()["attempts"][0]["status"],
            "produced"
        );
        assert_eq!(
            journal
                .reserve(&verified, 1, &node, 1_500_000_000)
                .unwrap_err(),
            AdmissionError::Replay
        );
    }
}

#[test]
fn a_cancelled_17_step_prefix_leaves_no_witness_and_no_refundable_reservation() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let path = directory.path().join("ledger.sqlite");
    let mut journal = ResearchLedger::create(&path, &verified).unwrap();
    journal.reserve(&verified, 1, &node, 1_500_000_000).unwrap();
    let mut steps = 0;
    let proof =
        seal::prove_with_progress(verified.challenge_for_nonce(1).unwrap(), [20; 32], |p| {
            if let seal::Progress::Step(index) = p {
                steps = index;
                if index == 17 {
                    return Err(());
                }
            }
            Ok(())
        });
    assert_eq!(steps, 17);
    assert_eq!(proof, Err(()));
    assert_eq!(
        journal.observation().unwrap()["attempts"][0]["status"],
        "reserved"
    );
    drop(journal);
    let mut journal = ResearchLedger::open(&path, &verified).unwrap();
    assert_eq!(
        journal
            .reserve(&verified, 1, &node, 1_500_000_000)
            .unwrap_err(),
        AdmissionError::Replay
    );
}

#[test]
fn untrusted_full_seal_replay_needs_no_producer_journal_and_rejects_a_forged_low_endpoint() {
    let (_directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let statement = [21; 32];
    let proof = seal::prove(verified.challenge_for_nonce(1).unwrap(), statement);
    let observed = verified
        .verify_untrusted_seal(1, statement, &proof, &node, || Ok(1_500_000_000))
        .unwrap();
    assert!(!observed.journal_recorded);
    assert!(!observed.first_record);
    assert_eq!(observed.chainwork_awarded, 0);
    let mut false_low = proof.clone();
    false_low[seal::PROOF_BYTES - 32..].fill(0);
    assert_eq!(
        verified
            .verify_untrusted_seal(1, statement, &false_low, &node, || Ok(1_500_000_000))
            .unwrap_err(),
        AdmissionError::Seal(seal::SealError::Endpoint)
    );
    let mut readings = 0;
    assert_eq!(
        verified
            .verify_untrusted_seal(1, statement, &proof, &node, || {
                readings += 1;
                Ok(1_500_000_000 - readings)
            })
            .unwrap_err(),
        AdmissionError::Window
    );
}

#[test]
fn fixed_verifier_budget_counts_repeated_and_abandoned_submissions_after_reopen() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let path = directory.path().join("ledger.sqlite");
    let mut journal = ResearchLedger::create(&path, &verified).unwrap();
    let request = VerificationRequest::from_digests(
        1,
        [22; 32],
        [23; 32],
        sha256(&raw),
        VerificationMode::Untrusted,
    );
    for index in 1..=MAX_VERIFICATION_SUBMISSIONS {
        let permit = journal
            .reserve_verification(&verified, &request, &node, 1_500_000_000)
            .unwrap();
        assert_eq!(permit.observation()["sequence"], index);
    }
    assert_eq!(
        journal
            .reserve_verification(&verified, &request, &node, 1_500_000_000)
            .unwrap_err(),
        AdmissionError::VerificationBudget
    );
    let before = journal.observation().unwrap();
    assert_eq!(before["verification_budget"]["reserved"], 256);
    assert_eq!(before["verification_budget"]["spent"], 0);
    assert_eq!(before["verification_budget"]["remaining"], 0);
    assert_eq!(before["attempts"].as_array().unwrap().len(), 0);
    drop(journal);
    let mut journal = ResearchLedger::open(&path, &verified).unwrap();
    assert_eq!(
        journal.observation().unwrap()["verification_budget"],
        before["verification_budget"]
    );
    assert_eq!(
        journal
            .reserve_verification(&verified, &request, &node, 1_500_000_000)
            .unwrap_err(),
        AdmissionError::VerificationBudget
    );
}

#[test]
fn wrong_proof_capsule_or_mode_burns_the_bound_permit_without_a_refund() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let path = directory.path().join("ledger.sqlite");
    let mut journal = ResearchLedger::create(&path, &verified).unwrap();
    let request = VerificationRequest::from_digests(
        1,
        [22; 32],
        [23; 32],
        sha256(&raw),
        VerificationMode::Untrusted,
    );
    let wrong = [
        VerificationRequest::from_digests(
            1,
            [22; 32],
            [24; 32],
            sha256(&raw),
            VerificationMode::Untrusted,
        ),
        VerificationRequest::from_digests(
            1,
            [22; 32],
            [23; 32],
            [25; 32],
            VerificationMode::Untrusted,
        ),
        VerificationRequest::from_digests(
            1,
            [22; 32],
            [23; 32],
            sha256(&raw),
            VerificationMode::Record,
        ),
    ];
    let mut last = [0; 32];
    for other in wrong {
        let permit = journal
            .reserve_verification(&verified, &request, &node, 1_500_000_000)
            .unwrap();
        last = permit.id();
        assert_eq!(
            journal
                .claim_verification(&verified, last, &other)
                .unwrap_err(),
            AdmissionError::VerificationBinding
        );
        assert_eq!(
            journal
                .claim_verification(&verified, last, &request)
                .unwrap_err(),
            AdmissionError::VerificationPermit
        );
    }
    assert_eq!(
        journal
            .claim_verification(&verified, [255; 32], &request)
            .unwrap_err(),
        AdmissionError::VerificationPermit
    );
    drop(journal);
    let mut journal = ResearchLedger::open(&path, &verified).unwrap();
    assert_eq!(
        journal
            .claim_verification(&verified, last, &request)
            .unwrap_err(),
        AdmissionError::VerificationPermit
    );
    assert_eq!(
        journal.observation().unwrap()["verification_budget"]["reserved"],
        3
    );
    assert_eq!(
        journal.observation().unwrap()["verification_budget"]["spent"],
        3
    );
}

#[test]
fn metered_untrusted_replay_needs_no_producer_record_but_rejections_consume_budget() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let mut journal =
        ResearchLedger::create(&directory.path().join("ledger.sqlite"), &verified).unwrap();
    let statement = [26; 32];
    let proof = seal::prove(verified.challenge_for_nonce(1).unwrap(), statement);
    let mut forged = proof.clone();
    forged[seal::PROOF_BYTES - 32..].fill(0);
    for (input, valid) in [(&proof, true), (&forged, false)] {
        let request = VerificationRequest::from_digests(
            1,
            statement,
            sha256(input),
            sha256(&raw),
            VerificationMode::Untrusted,
        );
        let permit = journal
            .reserve_verification(&verified, &request, &node, 1_500_000_000)
            .unwrap();
        let claimed = journal
            .claim_verification(&verified, permit.id(), &request)
            .unwrap();
        let result = journal.verify_untrusted_with_permit(
            claimed,
            &verified,
            1,
            statement,
            input,
            &node,
            || Ok(1_500_000_000),
        );
        if valid {
            let observed = result.unwrap();
            assert_eq!(observed.chainwork_awarded, 0);
            assert!(!observed.journal_recorded);
            assert!(!observed.grouped_arithmetic_verified_by_this_api);
        } else {
            assert_eq!(
                result.unwrap_err(),
                AdmissionError::Seal(seal::SealError::Endpoint)
            );
        }
        assert_eq!(
            journal
                .claim_verification(&verified, permit.id(), &request)
                .unwrap_err(),
            AdmissionError::VerificationPermit
        );
    }
    // The opaque consumed token must still match the actual native replay input.
    let request = VerificationRequest::from_digests(
        1,
        statement,
        sha256(&proof),
        sha256(&raw),
        VerificationMode::Untrusted,
    );
    let permit = journal
        .reserve_verification(&verified, &request, &node, 1_500_000_000)
        .unwrap();
    let claimed = journal
        .claim_verification(&verified, permit.id(), &request)
        .unwrap();
    let mut replay_clock_calls = 0;
    assert_eq!(
        journal
            .verify_untrusted_with_permit(claimed, &verified, 1, statement, &forged, &node, || {
                replay_clock_calls += 1;
                Ok(1_500_000_000)
            })
            .unwrap_err(),
        AdmissionError::VerificationBinding
    );
    assert_eq!(replay_clock_calls, 0);
    let observed = journal.observation().unwrap();
    assert_eq!(observed["verification_budget"]["reserved"], 3);
    assert_eq!(observed["verification_budget"]["spent"], 3);
    assert_eq!(observed["attempts"].as_array().unwrap().len(), 0);
}

#[test]
fn claimed_tokens_cannot_move_between_same_policy_journals_or_across_reopen() {
    let (directory, node, external, raw) = fixture();
    let verified = verify_capsule(&raw, &external, &node, 1_500_000_000).unwrap();
    let first_path = directory.path().join("first.sqlite");
    let mut first = ResearchLedger::create(&first_path, &verified).unwrap();
    let second =
        ResearchLedger::create(&directory.path().join("second.sqlite"), &verified).unwrap();
    let statement = [27; 32];
    let proof = seal::prove(verified.challenge_for_nonce(1).unwrap(), statement);
    let request = VerificationRequest::from_digests(
        1,
        statement,
        sha256(&proof),
        sha256(&raw),
        VerificationMode::Untrusted,
    );
    let permit = first
        .reserve_verification(&verified, &request, &node, 1_500_000_000)
        .unwrap();
    let claimed = first
        .claim_verification(&verified, permit.id(), &request)
        .unwrap();
    let mut clocks = 0;
    assert_eq!(
        second
            .verify_untrusted_with_permit(claimed, &verified, 1, statement, &proof, &node, || {
                clocks += 1;
                Ok(1_500_000_000)
            })
            .unwrap_err(),
        AdmissionError::VerificationBinding
    );
    assert_eq!(clocks, 0);
    assert_eq!(
        second.observation().unwrap()["verification_budget"]["reserved"],
        0
    );

    let permit = first
        .reserve_verification(&verified, &request, &node, 1_500_000_000)
        .unwrap();
    let old_claimed = first
        .claim_verification(&verified, permit.id(), &request)
        .unwrap();
    let still_unclaimed = first
        .reserve_verification(&verified, &request, &node, 1_500_000_000)
        .unwrap();
    drop(first);
    let mut reopened = ResearchLedger::open(&first_path, &verified).unwrap();
    assert_eq!(
        reopened
            .verify_untrusted_with_permit(
                old_claimed,
                &verified,
                1,
                statement,
                &proof,
                &node,
                || {
                    clocks += 1;
                    Ok(1_500_000_000)
                }
            )
            .unwrap_err(),
        AdmissionError::VerificationBinding
    );
    assert_eq!(clocks, 0);
    assert_eq!(
        reopened.observation().unwrap()["verification_budget"]["reserved"],
        3
    );
    assert_eq!(
        reopened.observation().unwrap()["verification_budget"]["spent"],
        2
    );
    let claimed = reopened
        .claim_verification(&verified, still_unclaimed.id(), &request)
        .unwrap();
    let observed = reopened
        .verify_untrusted_with_permit(claimed, &verified, 1, statement, &proof, &node, || {
            Ok(1_500_000_000)
        })
        .unwrap();
    assert_eq!(observed.chainwork_awarded, 0);
    assert_eq!(
        reopened.observation().unwrap()["verification_budget"]["spent"],
        3
    );
}
