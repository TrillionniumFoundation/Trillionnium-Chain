#[test]
fn same_parent_lower_subset_body_reaches_ready_vote_and_late_timeout_sync_v1() {
    on_consensus_owner_stack_v1(|| {
        let mut fixture = real_takeover_fixture_with_lifetime_v1(
            7,
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(2, 2, 4, 2).unwrap(),
        );
        let view = fixture.authorities[0].facts_v0().unwrap().current_view_v0();
        let leader_index = |view| {
            fixture
                .validator_set
                .validators()
                .iter()
                .position(|v| v.id() == leader_for(&fixture.validator_set, view))
                .unwrap()
        };
        let proposer = leader_index(view);
        let next_proposer = leader_index(View::new(view.get() + 1));
        assert!(next_proposer > 1);
        let parent = fixture.authorities[proposer]
            .proposal_preimage_for_test_v0(
                fixture.ordinary_start_height,
                fixture.parent_timestamp_ms,
                fixture.parent_transactions.clone(),
            )
            .unwrap()
            .seal_with_key_v0(&fixture.keys[proposer])
            .unwrap();
        let votes = fixture
            .authorities
            .iter_mut()
            .map(|owner| owner.vote_proposal_v0(parent.clone()).unwrap())
            .collect::<Vec<_>>();
        let first =
            quorum_certificate_v1(&fixture.validator_set, &parent, votes[..5].iter().cloned());
        let second =
            quorum_certificate_v1(&fixture.validator_set, &parent, votes[2..].iter().cloned());
        let (low, high) = if first.id() < second.id() {
            (first, second)
        } else {
            (second, first)
        };
        assert_ne!(low.id(), high.id());
        for (index, owner) in fixture.authorities.iter_mut().enumerate() {
            owner
                .advance_quorum_certificate_v0(if index < 2 { high.clone() } else { low.clone() })
                .unwrap();
        }
        let child = fixture.authorities[next_proposer]
            .proposal_preimage_for_test_v0(
                fixture.ordinary_start_height + 1,
                fixture.child_timestamp_ms,
                fixture.child_transactions.clone(),
            )
            .unwrap()
            .seal_with_key_v0(&fixture.keys[next_proposer])
            .unwrap();
        assert_eq!(child.witness().justify_qc().qc_ref(), QcRef::from(&low));
        // The two receiver owners retained the higher digest for the same
        // genuinely executed parent. One remains Ready; the other has already
        // persisted and signed its local timeout when the body arrives.
        let timeout = fixture.authorities[1].begin_local_timeout_v0().unwrap();
        let mut child_votes = Vec::new();
        for index in 0..2 {
            let owner = &mut fixture.authorities[index];
            let before = owner.facts_v0().unwrap();
            assert_eq!(before.high_qc_v0(), QcRef::from(&high));
            let frame = AuthenticatedFrame {
                sender: child.block().header().proposer_id(),
                session: [0x51; 32],
                sequence: 1,
                kind: FrameKind::Proposal,
                payload: UnboundProposalV0::from_signed(&child)
                    .unwrap()
                    .encode()
                    .unwrap(),
            };
            let Some(RoutedConsensusActionV0::Proposal(wire)) = owner
                .admit_authenticated_consensus_frame_v0(&frame)
                .unwrap()
            else {
                panic!("strict genuine proposal route")
            };
            let mut buffer = PendingProposalBufferV1::default();
            let known = BTreeSet::from([(
                parent.block().header().height().get(),
                *parent.block().id().as_bytes(),
            )]);
            let admission = buffer
                .admit_v1(
                    *wire,
                    before.high_qc_v0(),
                    &known,
                    before.finalized_height_v0(),
                    before.finalized_block_id_v0(),
                    before.finalized_view_v0(),
                )
                .unwrap();
            let PendingProposalAdmissionV1::Vote(body) = admission else {
                panic!("same certified parent with a lower quorum-subset digest must not lose its body: {admission:?}");
            };
            let sync = body.clone();
            let vote = owner.receive_unbound_proposal_v1(*body).unwrap();
            if index == 0 {
                let vote = vote.expect("Ready takes the actual P/Core Valid/Safety/sign path");
                assert_eq!(vote.block_id(), child.block().id());
                child_votes.push(vote);
            } else {
                assert!(vote.is_none());
                assert!(owner.sync_late_proposal_v1(*sync).unwrap());
                // This public owner method compares the supplied bytes with
                // its still-owned original signed outbound before collection.
                assert!(owner
                    .admit_local_timeout_vote_v0(timeout.clone())
                    .unwrap()
                    .is_none());
                assert_eq!(
                    owner.facts_v0().unwrap().last_timeout_view_v1(),
                    Some(timeout.view())
                );
                assert_eq!(
                    owner.facts_v0().unwrap().signed_timeout_intents_v0(),
                    before.signed_timeout_intents_v0()
                );
                assert_eq!(
                    owner.facts_v0().unwrap().signed_vote_intents_v0(),
                    before.signed_vote_intents_v0()
                );
                assert_eq!(
                    owner.facts_v0().unwrap().phase_v0(),
                    trnm_poco_node::PocoNodeLabAuthorityPhaseV0::TimeoutSigned
                );
                assert!(owner.begin_local_timeout_v0().is_err());
            }
            assert_eq!(
                owner.facts_v0().unwrap().high_qc_v0(),
                QcRef::from(&high),
                "body admission cannot downgrade Core QC"
            );
            assert!(buffer.is_empty());
        }
        for index in 2..6 {
            child_votes.push(
                fixture.authorities[index]
                    .vote_proposal_v0(child.clone())
                    .unwrap(),
            );
        }
        assert_eq!(child_votes.len(), 5);
        let child_qc = quorum_certificate_v1(&fixture.validator_set, &child, child_votes);
        let before = fixture.authorities[1].facts_v0().unwrap();
        let after = fixture.authorities[1]
            .advance_quorum_certificate_v0(child_qc)
            .unwrap();
        assert!(after.current_view_v0() > before.current_view_v0());
        assert_eq!(
            after.phase_v0(),
            trnm_poco_node::PocoNodeLabAuthorityPhaseV0::Ready
        );
        assert_eq!(
            after.signed_vote_intents_v0(),
            before.signed_vote_intents_v0()
        );
        assert_eq!(
            after.signed_timeout_intents_v0(),
            before.signed_timeout_intents_v0()
        );
    });
}
