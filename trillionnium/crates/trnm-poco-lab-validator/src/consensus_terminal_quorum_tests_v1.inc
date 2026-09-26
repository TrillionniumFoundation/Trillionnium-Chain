// A bounded tail can be terminal even though its last submitted proposals
// cannot themselves finalize without additional, unrequested heights.
#[test]
fn post_timeout_direct_qc_releases_real_terminal_cut_below_submitted_tail_v1() {
    on_consensus_owner_stack_v1(|| {
        let mut fixture = real_takeover_fixture_with_lifetime_v1(
            4,
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(4, 1, 5, 1).unwrap(),
        );
        let start = fixture.ordinary_start_height;
        let mut high_qc = None;
        for height in start..start + 3 {
            let proposal = terminal_tail_proposal_v1(
                &fixture,
                height,
                fixture.parent_timestamp_ms + (height - start) * 2,
            );
            let votes = fixture
                .authorities
                .iter_mut()
                .map(|authority| authority.vote_proposal_v0(proposal.clone()).unwrap())
                .collect::<Vec<_>>();
            let certificate = quorum_certificate_v1(&fixture.validator_set, &proposal, votes);
            for authority in &mut fixture.authorities {
                authority
                    .advance_quorum_certificate_v0(certificate.clone())
                    .unwrap();
            }
            high_qc = Some(certificate);
        }
        for authority in &fixture.authorities {
            let ready = authority.facts_v0().unwrap();
            assert!(!bounded_stop_ready_v1(start + 3, false, ready));
            assert!(bounded_stop_ready_v1(start + 3, true, ready));
        }
        // All four owners persist and sign the final permitted height, but
        // delivery omits its QC. They then genuinely persist TimeoutVotes.
        let tail_height = start + 3;
        let timed_out =
            terminal_tail_proposal_v1(&fixture, tail_height, fixture.parent_timestamp_ms + 6);
        let timeout_view = timed_out.block().header().view();
        for authority in &mut fixture.authorities {
            authority.vote_proposal_v0(timed_out.clone()).unwrap();
            let signed = authority.facts_v0().unwrap();
            assert!(!bounded_stop_ready_v1(tail_height, false, signed));
            assert!(!bounded_stop_ready_v1(tail_height, true, signed));
        }
        let mut collector = ConsensusCertificateCollectorV0::new(
            fixture.validator_set.clone(),
            MAXIMUM_PENDING_CERTIFICATES_V1,
        )
        .unwrap();
        collector
            .register_qc_reference(QcReferenceV0::ordinary(high_qc.unwrap()))
            .unwrap();
        for authority in &mut fixture.authorities {
            collector
                .admit_timeout_vote(authority.begin_local_timeout_v0().unwrap())
                .unwrap();
        }
        let timeout = collector
            .try_timeout_certificate(timeout_view)
            .unwrap()
            .unwrap();
        let required_view = timeout_view.get() + 1;
        for authority in &mut fixture.authorities {
            let after = authority
                .advance_timeout_certificate_v0(timeout.clone())
                .unwrap();
            assert_eq!(after.current_view_v0().get(), required_view);
            assert_eq!(after.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
            assert!(after.pending_timeout_certificate_id_v0().is_some());
            assert!(!post_timeout_direct_qc_ready_v1(required_view, after));
            assert!(!bounded_stop_ready_v1(tail_height, false, after));
            assert!(!bounded_stop_ready_v1(tail_height, true, after));
        }
        // A different proposal at the SAME bounded height follows the real
        // TC witness. Only its genuinely adopted QC can clear the obligation.
        let replacement =
            terminal_tail_proposal_v1(&fixture, tail_height, fixture.parent_timestamp_ms + 7);
        assert_ne!(replacement.block().id(), timed_out.block().id());
        assert_eq!(replacement.block().header().view().get(), required_view);
        let votes = fixture
            .authorities
            .iter_mut()
            .map(|authority| {
                let vote = authority.vote_proposal_v0(replacement.clone()).unwrap();
                assert!(!post_timeout_direct_qc_ready_v1(
                    required_view,
                    authority.facts_v0().unwrap()
                ));
                vote
            })
            .collect::<Vec<_>>();
        let direct_qc = quorum_certificate_v1(&fixture.validator_set, &replacement, votes);
        for authority in &mut fixture.authorities {
            let ready = authority
                .advance_quorum_certificate_v0(direct_qc.clone())
                .unwrap();
            assert_eq!(ready.high_qc_v0(), QcRef::from(&direct_qc));
            assert!(ready.finalized_height_v0() < tail_height);
            assert_eq!(
                ready.application_applied_height_v0(),
                ready.finalized_height_v0()
            );
            assert!(post_timeout_direct_qc_ready_v1(required_view, ready));
            assert!(bounded_stop_ready_v1(tail_height, false, ready));
            assert!(!post_timeout_direct_qc_ready_v1(required_view + 1, ready));
        }
        // This is the actual consuming terminal audit: all P/K records,
        // committed native state, Safety, checkpoint, and signer inventory
        // must agree. No synthetic facts or terminal constructors are used.
        for authority in fixture.authorities {
            let terminal = authority.into_terminal_owner_v0().unwrap();
            let facts = terminal.facts_v0();
            assert_eq!(facts.submitted_height_v0(), tail_height);
            assert_eq!(facts.node_v0().high_qc_v0(), QcRef::from(&direct_qc));
            assert!(facts.node_v0().finalized_height_v0() < facts.submitted_height_v0());
            assert_eq!(facts.signed_vote_intents_v0(), 5);
            assert_eq!(facts.signed_timeout_intents_v0(), 1);
        }
    });
}

fn terminal_tail_proposal_v1(
    fixture: &RealTakeoverFixtureV1,
    height: u64,
    timestamp_ms: u64,
) -> SignedProposalV0 {
    let view = fixture.authorities[0].facts_v0().unwrap().current_view_v0();
    let leader = leader_for(&fixture.validator_set, view);
    let proposer = fixture
        .validator_set
        .validators()
        .iter()
        .position(|v| v.id() == leader)
        .unwrap();
    fixture.authorities[proposer]
        .proposal_preimage_for_test_v0(
            height,
            timestamp_ms,
            if height == fixture.ordinary_start_height {
                fixture.parent_transactions.clone()
            } else {
                Vec::new()
            },
        )
        .unwrap()
        .seal_with_key_v0(&fixture.keys[proposer])
        .unwrap()
}
