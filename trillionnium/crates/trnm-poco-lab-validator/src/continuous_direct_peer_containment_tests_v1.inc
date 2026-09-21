fn containment_frame_v1(
    sender: ValidatorId,
    kind: crate::frame::FrameKind,
    payload: Vec<u8>,
) -> AuthenticatedFrame {
    AuthenticatedFrame {
        sender,
        session: [0x5a; 32],
        sequence: 1,
        kind,
        payload,
    }
}

#[test]
fn direct_peer_containment_real_signatures_preserve_honest_quorum_and_fatal_errors_v1() {
    on_bounded_takeover_owner_stack_v0(|| {
        use crate::consensus_runtime::route_contained_direct_frame_v1;
        use crate::frame::FrameKind;
        let mut harness = takeover_phase_harness_v0(7);
        let proposal = proposal_for_takeover_v0(&harness);
        let votes = harness
            .authorities
            .iter_mut()
            .map(|owner| owner.vote_proposal_v0(proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let qc = quorum_certificate_from_votes_v0(
            &harness.validator_set,
            &proposal,
            votes[..5].iter().cloned(),
        );
        let peer = harness.validator_set.validators()[6].id();
        let mut bad_vote = crate::wire::encode_vote(&votes[6]);
        let signature_start = bad_vote.len() - 64;
        bad_vote[signature_start..].fill(0);
        let mut bad_qc = crate::wire::encode_quorum_certificate(&qc).unwrap();
        let signature_start = bad_qc.len() - 64;
        bad_qc[signature_start..].fill(0);
        let bad_proposal = UnboundProposalV0::from_signed(&proposal)
            .unwrap()
            .with_proposer_signature_for_test(SignatureBytes::from_array([0; 64]))
            .encode()
            .unwrap();
        let cases = [
            containment_frame_v1(peer, FrameKind::Vote, bad_vote),
            containment_frame_v1(peer, FrameKind::QuorumCertificate, bad_qc),
            containment_frame_v1(
                proposal.block().header().proposer_id(),
                FrameKind::Proposal,
                bad_proposal,
            ),
        ];
        for (index, frame) in cases.iter().enumerate() {
            let owner = &mut harness.authorities[index];
            let before = owner.facts_v0().unwrap();
            let violations = owner.protocol_violations;
            // The existing strict API still rejects the same input. The new
            // runtime boundary classifies only this first pure failure.
            assert!(owner.admit_authenticated_consensus_frame_v0(frame).is_err());
            assert!(route_contained_direct_frame_v1(owner, frame)
                .unwrap()
                .is_none());
            assert_eq!(owner.facts_v0().unwrap(), before);
            assert_eq!(owner.protocol_violations, violations);
            assert!(owner.consensus_windows.direct_proposals.is_empty());
            assert!(owner
                .consensus_windows
                .ingress
                .collector()
                .canonical_quorum_certificate(
                    proposal.block().header().view(),
                    proposal.block().header().height(),
                    proposal.block().id()
                )
                .is_none());
            let first = owner.consensus_windows.direct_peer_rejections[&frame.sender];
            assert_eq!(first.remote, frame.sender);
            assert_eq!(first.kind, frame.kind);
            assert_eq!(first.reason, DirectPeerRejectionReasonV1::InvalidStatement);
            assert_eq!(
                first.payload_sha256,
                <[u8; 32]>::from(Sha256::digest(&frame.payload))
            );
            assert_eq!(first.dropped_frames, 1);
            let mut reconnected = containment_frame_v1(
                frame.sender,
                FrameKind::QuorumCertificate,
                crate::wire::encode_quorum_certificate(&qc).unwrap(),
            );
            reconnected.session = [0x6b; 32];
            assert!(route_contained_direct_frame_v1(owner, &reconnected)
                .unwrap()
                .is_none());
            assert_eq!(
                owner.consensus_windows.direct_peer_rejections[&frame.sender],
                DirectPeerRejectionFactsV1 {
                    dropped_frames: 2,
                    ..first
                }
            );
            assert_eq!(owner.facts_v0().unwrap(), before);
        }
        // One Byzantine peer's invalid Vote never counts. The exact local
        // signer output plus four genuine independent Votes still reaches
        // quorum five through the helper used by the actual direct runtime.
        let owner = &mut harness.authorities[0];
        assert!(owner
            .admit_local_vote_v0(votes[0].clone())
            .unwrap()
            .is_none());
        let mut formed = None;
        for (index, vote) in votes.iter().enumerate().take(5).skip(1) {
            let action = route_contained_direct_frame_v1(
                owner,
                &containment_frame_v1(
                    vote.author(),
                    FrameKind::Vote,
                    crate::wire::encode_vote(vote),
                ),
            )
            .unwrap()
            .unwrap();
            let RoutedConsensusActionV0::Vote { formed_qc, .. } = action else {
                panic!("real Vote route")
            };
            assert_eq!(formed_qc.is_some(), index == 4);
            formed = formed_qc.or(formed);
        }
        let before = owner.facts_v0().unwrap();
        let advanced = owner
            .advance_quorum_certificate_v0(*formed.unwrap())
            .unwrap();
        assert!(advanced.current_view_v0() > before.current_view_v0());
        assert_eq!(advanced.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
        assert_eq!(
            advanced.signed_vote_intents_v0(),
            before.signed_vote_intents_v0()
        );

        // A collector-level conflicting signed Vote remains fatal and keeps
        // the original equivocation counter. It is not a pure decode error.
        let owner = &mut harness.authorities[3];
        let original = &votes[1];
        route_contained_direct_frame_v1(
            owner,
            &containment_frame_v1(
                original.author(),
                FrameKind::Vote,
                crate::wire::encode_vote(original),
            ),
        )
        .unwrap();
        let conflict_id = BlockId::new([0xc1; 32]);
        assert_ne!(conflict_id, original.block_id());
        let root = Vote::signing_root_for_set(
            &harness.validator_set,
            original.view(),
            original.height(),
            conflict_id,
        )
        .unwrap();
        let conflict = Vote::new(
            harness.validator_set.chain_id(),
            harness.validator_set.protocol_version(),
            harness.validator_set.epoch(),
            original.view(),
            original.height(),
            conflict_id,
            harness.validator_set.id(),
            original.author(),
            SignatureBytes::from_array(harness.keys[1].sign(root.as_bytes()).to_bytes()),
            &harness.validator_set,
        )
        .unwrap();
        let error = route_contained_direct_frame_v1(
            owner,
            &containment_frame_v1(
                conflict.author(),
                FrameKind::Vote,
                crate::wire::encode_vote(&conflict),
            ),
        )
        .unwrap_err();
        assert!(error.chain().any(|e| matches!(
            e.downcast_ref::<ConsensusIngressErrorV0>(),
            Some(ConsensusIngressErrorV0::VoteEquivocation)
        )));
        assert_eq!(owner.protocol_violations.double_vote_count_v0(), 1);
        assert!(owner.consensus_windows.direct_peer_rejections.is_empty());

        // Local session/identity joins remain errors, even for a quarantined
        // identity; this cannot hide a broken authenticated-mesh boundary.
        let owner = &mut harness.authorities[1];
        let mut frame = containment_frame_v1(peer, FrameKind::Vote, vec![]);
        frame.session = [0; 32];
        assert!(route_contained_direct_frame_v1(owner, &frame).is_err());
        frame.session = [1; 32];
        frame.sender = ValidatorId::new([0xee; 32]);
        assert!(route_contained_direct_frame_v1(owner, &frame).is_err());
        assert_eq!(owner.consensus_windows.direct_peer_rejections.len(), 1);

        // After a valid frame passed admission, a displaced durable namespace
        // must still fail the real Core/Safety transition; no global catch.
        let frame = containment_frame_v1(
            votes[5].author(),
            FrameKind::QuorumCertificate,
            crate::wire::encode_quorum_certificate(&qc).unwrap(),
        );
        let Some(RoutedConsensusActionV0::QuorumCertificate(accepted)) =
            route_contained_direct_frame_v1(owner, &frame).unwrap()
        else {
            panic!("real QC route")
        };
        let checkpoint = harness
            ._temp
            .path()
            .join("takeover-authority-001/checkpoint/checkpoint.sqlite3");
        fs::rename(&checkpoint, checkpoint.with_extension("displaced")).unwrap();
        assert!(owner.advance_quorum_certificate_v0(*accepted).is_err());
        assert!(owner.phase.is_none());
    });
}

#[test]
fn direct_peer_containment_bounded_rejections_keep_first_facts_and_checked_counts_v1() {
    on_bounded_takeover_owner_stack_v0(|| {
        use crate::consensus_runtime::route_contained_direct_frame_v1;
        use crate::frame::FrameKind;
        let mut harness = takeover_phase_harness_v0(4);
        let proposal = proposal_for_takeover_v0(&harness);
        let owner = &mut harness.authorities[0];
        let cases = [
            (
                FrameKind::Vote,
                vec![],
                DirectPeerRejectionReasonV1::Malformed,
            ),
            (
                FrameKind::ConsensusRelay,
                vec![],
                DirectPeerRejectionReasonV1::UnsupportedKind,
            ),
            (
                FrameKind::Proposal,
                UnboundProposalV0::from_signed(&proposal)
                    .unwrap()
                    .encode()
                    .unwrap(),
                DirectPeerRejectionReasonV1::AuthorMismatch,
            ),
        ];
        for (index, (kind, payload, reason)) in cases.into_iter().enumerate() {
            let sender = harness.validator_set.validators()[index].id();
            assert_ne!(
                sender,
                proposal.block().header().proposer_id(),
                "the fourth validator is the actual view-four leader"
            );
            let frame = containment_frame_v1(sender, kind, payload);
            assert!(route_contained_direct_frame_v1(owner, &frame)
                .unwrap()
                .is_none());
            assert_eq!(
                owner.consensus_windows.direct_peer_rejections[&sender].reason,
                reason
            );
        }
        let sender = harness.validator_set.validators()[3].id();
        assert!(route_contained_direct_frame_v1(
            owner,
            &containment_frame_v1(sender, FrameKind::Vote, vec![])
        )
        .unwrap()
        .is_none());
        assert_eq!(owner.consensus_windows.direct_peer_rejections.len(), 4);
        let before = owner.facts_v0().unwrap();
        // Only the process-local diagnostic counter is altered for the
        // overflow boundary; no Core, signer or SQL state is fabricated.
        owner
            .consensus_windows
            .direct_peer_rejections
            .get_mut(&sender)
            .unwrap()
            .dropped_frames = u64::MAX;
        assert!(route_contained_direct_frame_v1(
            owner,
            &containment_frame_v1(sender, FrameKind::Vote, vec![])
        )
        .is_err());
        assert_eq!(
            owner.consensus_windows.direct_peer_rejections[&sender].dropped_frames,
            u64::MAX
        );
        assert_eq!(owner.facts_v0().unwrap(), before);
    });
}

#[test]
fn direct_peer_containment_ingress_tick_is_finite_and_rejection_is_not_progress_v1() {
    use crate::consensus_runtime::drain_remaining_ingress_tick_v1;
    let mut count = 0;
    assert!(!drain_remaining_ingress_tick_v1(|| {
        count += 1;
        Ok(Some(false))
    })
    .unwrap());
    assert_eq!(
        count, 63,
        "one already received event plus this drain is at most 64"
    );
    let mut count = 0;
    assert!(drain_remaining_ingress_tick_v1(|| {
        count += 1;
        Ok(Some(count == 2))
    })
    .unwrap());
    assert_eq!(count, 63);
    let mut count = 0;
    assert!(drain_remaining_ingress_tick_v1(|| {
        count += 1;
        if count == 3 {
            bail!("real ingress failure");
        }
        Ok(Some(false))
    })
    .is_err());
    assert_eq!(count, 3);
    let mut count = 0;
    assert!(!drain_remaining_ingress_tick_v1(|| {
        count += 1;
        Ok(None)
    })
    .unwrap());
    assert_eq!(count, 1);
}
