#[test]
fn timeout_same_view_qc_then_late_vote_keeps_original_timer_fence_v1() {
    on_bounded_takeover_owner_stack_v0(|| {
        use crate::consensus_runtime::{
            arm_pacemaker_for_facts_v1, update_pacemaker_after_progress_v1,
        };
        use crate::pacemaker::GenerationAwarePacemakerV0;
        use std::time::{Duration, Instant};

        let lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(2, 2, 4, 2).unwrap();
        let mut harness = takeover_phase_harness_with_profile_v0(4, lifetime, 2);
        let proposal = proposal_for_takeover_v0(&harness);
        let votes = harness
            .authorities
            .iter_mut()
            .map(|authority| authority.vote_proposal_v0(proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let a = quorum_certificate_from_votes_v0(
            &harness.validator_set,
            &proposal,
            votes[..3].iter().cloned(),
        );
        let b = quorum_certificate_from_votes_v0(
            &harness.validator_set,
            &proposal,
            votes[1..].iter().cloned(),
        );
        let (low, high) = if a.id() < b.id() { (a, b) } else { (b, a) };
        assert_ne!(low.id(), high.id());
        for authority in &mut harness.authorities {
            authority
                .advance_quorum_certificate_v0(low.clone())
                .unwrap();
        }
        // The next leader's genuine proposal is in flight when our local
        // timer expires. No fabricated application or Core state is used.
        let late = proposal_for_takeover_v0(&harness);
        let epoch = harness.validator_set.epoch();
        let before = harness.authorities[0].facts_v0().unwrap();
        let now = Instant::now();
        let mut pacemaker =
            GenerationAwarePacemakerV0::new(Duration::from_millis(100), Duration::from_secs(1))
                .unwrap();
        arm_pacemaker_for_facts_v1(&mut pacemaker, epoch, before, now).unwrap();
        let expiry = pacemaker.poll(now + Duration::from_millis(100)).unwrap();
        let original_timeouts = harness
            .authorities
            .iter_mut()
            .map(|authority| authority.begin_local_timeout_v0().unwrap())
            .collect::<Vec<_>>();
        pacemaker.confirm_timeout_emitted(expiry).unwrap();
        let timed = harness.authorities[0].facts_v0().unwrap();
        assert_eq!(timed.last_timeout_view_v1(), Some(timed.current_view_v0()));
        assert_eq!(timed.signed_timeout_intents_v0(), 1);
        assert_eq!(
            original_timeouts[0].high_qc().qc_digest(),
            low.id(),
            "the original timeout binds the original quorum subset"
        );

        // A different, genuinely signed quorum subset changes the Core high
        // QC digest, restores Ready, but does NOT advance its current view.
        let ready = harness.authorities[0]
            .advance_quorum_certificate_v0(high.clone())
            .unwrap();
        assert_eq!(ready.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
        assert_eq!(ready.current_view_v0(), timed.current_view_v0());
        assert_eq!(ready.high_qc_v0().qc_digest(), high.id());
        assert_eq!(ready.last_timeout_view_v1(), timed.last_timeout_view_v1());
        update_pacemaker_after_progress_v1(&mut pacemaker, timed, ready).unwrap();
        arm_pacemaker_for_facts_v1(&mut pacemaker, epoch, ready, now).unwrap();
        assert!(pacemaker.poll(now + Duration::from_secs(30)).is_none());
        assert!(harness.authorities[0].begin_local_timeout_v0().is_err());
        assert_eq!(harness.authorities[0].facts_v0().unwrap(), ready);

        let vote = harness.authorities[0]
            .receive_unbound_proposal_v1(UnboundProposalV0::from_signed(&late).unwrap())
            .unwrap()
            .expect("same-view late proposal still executes the genuine Vote path");
        assert_eq!(vote.block_id(), late.block().id());
        let voted = harness.authorities[0].facts_v0().unwrap();
        assert_eq!(voted.phase_v0(), PocoNodeLabAuthorityPhaseV0::VoteSigned);
        assert_eq!(voted.current_view_v0(), ready.current_view_v0());
        assert_eq!(voted.last_timeout_view_v1(), ready.last_timeout_view_v1());
        assert_eq!(voted.signed_vote_intents_v0(), 2);
        assert_eq!(voted.signed_timeout_intents_v0(), 1);

        let key_calls = Arc::new(AtomicUsize::new(0));
        let producer = std::mem::replace(
            &mut harness.authorities[0].producer,
            ContinuousSignatureProducerV0(Box::new(ForbiddenSyncedSignatureProducerV1(
                Arc::clone(&key_calls),
            ))),
        );
        // Exercise the same helper used for initial/cold installation on a
        // fresh process-local pacemaker. Its fence comes from owned Core.
        let mut fresh_pacemaker =
            GenerationAwarePacemakerV0::new(Duration::from_millis(100), Duration::from_secs(1))
                .unwrap();
        arm_pacemaker_for_facts_v1(&mut fresh_pacemaker, epoch, voted, now).unwrap();
        assert!(fresh_pacemaker
            .poll(now + Duration::from_secs(30))
            .is_none());
        for _ in 0..2 {
            let error = harness.authorities[0].begin_local_timeout_v0().unwrap_err();
            assert!(
                error.to_string().contains("Core already retains"),
                "{error:#}"
            );
            assert_eq!(harness.authorities[0].facts_v0().unwrap(), voted);
        }
        assert_eq!(key_calls.load(Ordering::SeqCst), 0);
        harness.authorities[0].producer = producer;

        let mut collector = ConsensusCertificateCollectorV0::new(
            harness.validator_set.clone(),
            MAXIMUM_COLLECTOR_COORDINATES_V0,
        )
        .unwrap();
        collector
            .register_qc_reference(QcReferenceV0::ordinary(low.clone()))
            .unwrap();
        for timeout in &original_timeouts {
            collector.admit_timeout_vote(timeout.clone()).unwrap();
        }
        let tc = collector
            .try_timeout_certificate(original_timeouts[0].view())
            .unwrap()
            .unwrap();
        let advanced = harness.authorities[0]
            .advance_timeout_certificate_v0(tc)
            .unwrap();
        assert_eq!(advanced.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
        assert!(advanced.current_view_v0() > original_timeouts[0].view());
        assert_eq!(
            advanced.last_timeout_view_v1(),
            voted.last_timeout_view_v1()
        );
        assert_eq!(advanced.signed_timeout_intents_v0(), 1);
        update_pacemaker_after_progress_v1(&mut pacemaker, voted, advanced).unwrap();
        arm_pacemaker_for_facts_v1(&mut pacemaker, epoch, advanced, now).unwrap();
        let next_expiry = pacemaker.poll(now + Duration::from_secs(30)).unwrap();
        let next_timeout = harness.authorities[0].begin_local_timeout_v0().unwrap();
        assert_eq!(next_timeout.view(), advanced.current_view_v0());
        assert_eq!(next_timeout.high_qc().qc_digest(), high.id());
        pacemaker.confirm_timeout_emitted(next_expiry).unwrap();
        let next_signed = harness.authorities[0].facts_v0().unwrap();
        assert_eq!(next_signed.signed_timeout_intents_v0(), 2);
        assert!(next_signed.safety_revision_v0() > advanced.safety_revision_v0());
        assert!(
            next_signed.signer_watermark_sequence_v0() > advanced.signer_watermark_sequence_v0()
        );
        assert!(harness.authorities[0].begin_local_timeout_v0().is_err());
        assert_eq!(harness.authorities[0].facts_v0().unwrap(), next_signed);
    });
}
