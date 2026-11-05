use super::*;

#[test]
fn unbound_state_and_unbound_snapshot_cannot_accept_commands() {
    let command = sign(0, fixture_commands()[0].clone()).unwrap();
    let mut state = ResearchProtocolState::with_authorities(test_authorities()).unwrap();
    let before = state.clone();
    assert_eq!(
        state.apply(&command),
        Err(ProtocolStateError::MissingChainBinding)
    );
    assert_eq!(state, before);
    let mut restored = ResearchProtocolState::from_snapshot(state.export_snapshot()).unwrap();
    assert_eq!(
        restored.apply(&command),
        Err(ProtocolStateError::MissingChainBinding)
    );
}

#[test]
fn oversized_collections_refuse_from_the_header_before_reading_elements() {
    let commands = fixture_commands();
    let mut cases = Vec::new();
    let ResearchCommandV1::IssueWorkloadReceipt(workload) = &commands[2] else {
        unreachable!()
    };
    let mut e = Encoder::default();
    e.array(3);
    e.uint(1);
    e.uint(3);
    e.array(7);
    e.uint(1);
    workload.receipt_id.encode_canonical(&mut e);
    workload.evaluation_ref.encode_canonical(&mut e);
    e.array(129);
    cases.push((128, 129, e.finish()));

    let ResearchCommandV1::CreateResearchClaim(claim) = &commands[3] else {
        unreachable!()
    };
    for excessive_evidence in [true, false] {
        let mut e = Encoder::default();
        e.array(3);
        e.uint(1);
        e.uint(4);
        e.array(8);
        e.uint(1);
        claim.claim_id.encode_canonical(&mut e);
        claim.workload_receipt_ref.encode_canonical(&mut e);
        if excessive_evidence {
            e.array(65);
            cases.push((64, 65, e.finish()));
        } else {
            e.array(0);
            e.bytes(&claim.artifact_hash);
            e.bytes(&claim.claim_scope_hash);
            e.array(129);
            cases.push((128, 129, e.finish()));
        }
    }

    let ResearchCommandV1::ResolveResearchClaim(resolution) = &commands[6] else {
        unreachable!()
    };
    let mut e = Encoder::default();
    e.array(3);
    e.uint(1);
    e.uint(7);
    e.array(7);
    e.uint(1);
    resolution.resolution_id.encode_canonical(&mut e);
    resolution.challenge_ref.encode_canonical(&mut e);
    e.uint(3);
    e.bytes(&resolution.resolution_hash);
    e.array(129);
    cases.push((128, 129, e.finish()));

    for (expected, got, bytes) in cases {
        assert_eq!(
            ResearchCommandV1::from_canonical_bytes(&bytes),
            Err(ResearchCommandDecodeError::Canonical(
                CanonicalDecodeError::ArrayLengthMismatch { expected, got }
            ))
        );
    }
}

#[test]
fn signed_envelope_rejects_wrong_signature_length_in_decoder() {
    let mut command = sign(0, fixture_commands()[0].clone()).unwrap();
    for size in [0, 63, 65, 4096] {
        command.signature = vec![0; size];
        assert_eq!(
            SignedResearchCommandV1::from_canonical_bytes(&command.canonical_bytes()),
            Err(SignedResearchCommandValidationError::CanonicalDecode(
                CanonicalDecodeError::ByteLengthMismatch {
                    expected: 64,
                    got: size
                }
            ))
        );
    }
}

fn snapshot_after(command_count: usize) -> ResearchProtocolSnapshotV1 {
    let mut state = test_state();
    for (index, command) in fixture_commands()
        .into_iter()
        .take(command_count)
        .enumerate()
    {
        state.apply(&sign(index, command).unwrap()).unwrap();
    }
    state.export_snapshot()
}

#[test]
fn snapshot_rejects_broken_open_challenge_links_and_overflow() {
    let snapshot = snapshot_after(6);
    for attack in 0..4 {
        let mut changed = snapshot.clone();
        match attack {
            0 => changed.claims[0].active_challenge = Some(key("hepta.claim-challenge", "absent")),
            1 => changed.challenges[0].challenge.claim_ref.key = key("hepta.claim", "absent"),
            2 => changed.challenges[0].challenge.claim_ref.object_version = u64::MAX,
            3 => {
                changed.claims[0].status = ClaimStatus::Active;
                changed.claims[0].active_challenge = None;
            }
            _ => unreachable!(),
        }
        assert!(ResearchProtocolState::from_snapshot_for_chain("trnm-devnet-v1", changed).is_err());
    }
}

#[test]
fn snapshot_rejects_broken_resolution_links_and_future_historical_refs() {
    let snapshot = snapshot_after(7);
    for attack in 0..4 {
        let mut changed = snapshot.clone();
        match attack {
            0 => {
                changed.challenges[0].resolution_ref.as_mut().unwrap().key =
                    key("hepta.claim-resolution", "absent")
            }
            1 => {
                changed.resolutions[0]
                    .resolution
                    .challenge_ref
                    .object_version = 2
            }
            2 => changed.licenses[0].declaration.claim_ref.object_version = u64::MAX,
            3 => {
                changed.applied_commands[0]
                    .primary_object_ref
                    .object_version = u64::MAX
            }
            _ => unreachable!(),
        }
        assert!(
            ResearchProtocolState::from_snapshot_for_chain("trnm-devnet-v1", changed).is_err(),
            "attack {attack}"
        );
    }
}

#[test]
fn exhausted_claim_version_refuses_challenge_without_partial_mutation_or_panic() {
    let mut snapshot = snapshot_after(4);
    snapshot.claims[0].object_ref.object_version = u64::MAX;
    let mut command = fixture_commands()[5].clone();
    let ResearchCommandV1::ChallengeResearchClaim(challenge) = &mut command else {
        unreachable!()
    };
    challenge.claim_ref = snapshot.claims[0].object_ref;
    let mut state =
        ResearchProtocolState::from_snapshot_for_chain("trnm-devnet-v1", snapshot).unwrap();
    let before = state.clone();
    let signed = sign(5, command).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.apply(&signed)));
    assert!(result.is_ok(), "exhausted version must be a normal refusal");
    assert!(result.unwrap().is_err());
    assert_eq!(state, before);
}

#[test]
fn exhausted_claim_version_refuses_resolution_without_partial_mutation_or_panic() {
    let mut snapshot = snapshot_after(6);
    snapshot.claims[0].object_ref.object_version = u64::MAX;
    snapshot.challenges[0].challenge.claim_ref.object_version = u64::MAX - 1;
    let mut state =
        ResearchProtocolState::from_snapshot_for_chain("trnm-devnet-v1", snapshot).unwrap();
    let before = state.clone();
    let signed = sign(6, fixture_commands()[6].clone()).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.apply(&signed)));
    assert!(result.is_ok(), "exhausted version must be a normal refusal");
    assert!(result.unwrap().is_err());
    assert_eq!(state, before);
}
