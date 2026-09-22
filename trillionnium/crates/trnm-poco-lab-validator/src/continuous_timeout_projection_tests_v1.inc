// Included only in continuous_runtime::tests. Owners and accepted evidence are
// produced by the real native/Core/Safety/signer fixture; the negative quorum
// below deliberately signs conflicting messages with the fixture's real keys.
#[test]
fn lower_timeout_projection_cannot_hide_a_core_known_conflicting_qc_v1() {
    on_bounded_takeover_owner_stack_v0(|| {
        let lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(2, 1, 3, 1).unwrap();
        let mut harness = takeover_phase_harness_with_profile_v0(4, lifetime, 2);
        let mut actual_qcs = Vec::new();
        for _ in 0..2 {
            let proposal = proposal_for_takeover_v0(&harness);
            let votes = harness
                .authorities
                .iter_mut()
                .map(|authority| authority.vote_proposal_v0(proposal.clone()).unwrap())
                .collect::<Vec<_>>();
            let qc = quorum_certificate_from_votes_v0(
                &harness.validator_set,
                &proposal,
                votes[..3].iter().cloned(),
            );
            for authority in &mut harness.authorities {
                authority.advance_quorum_certificate_v0(qc.clone()).unwrap();
            }
            actual_qcs.push(qc);
        }
        let observed = &actual_qcs[0];
        let authoritative = &actual_qcs[1];
        let timeouts = harness
            .authorities
            .iter_mut()
            .map(|authority| authority.begin_local_timeout_v0().unwrap())
            .collect::<Vec<_>>();
        let mut collector = ConsensusCertificateCollectorV0::new(
            harness.validator_set.clone(),
            MAXIMUM_COLLECTOR_COORDINATES_V0,
        )
        .unwrap();
        collector
            .register_qc_reference(QcReferenceV0::ordinary(authoritative.clone()))
            .unwrap();
        for timeout in &timeouts[..3] {
            collector.admit_timeout_vote(timeout.clone()).unwrap();
        }
        let accepted = collector
            .try_timeout_certificate(timeouts[0].view())
            .unwrap()
            .unwrap();
        assert_eq!(accepted.referenced_qcs().len(), 1);
        assert!(!accepted
            .referenced_qcs()
            .iter()
            .any(|reference| reference.id() == observed.id()));
        for authority in &mut harness.authorities {
            authority
                .advance_timeout_certificate_v0(accepted.clone())
                .unwrap();
        }

        // All three signatures are genuine. This is intentionally Byzantine
        // evidence at an already observed view, not a claimed application P.
        let conflicting_block = BlockId::new([0xc7; 32]);
        assert_ne!(conflicting_block, observed.block_id());
        let vote_root = Vote::signing_root_for_set(
            &harness.validator_set,
            observed.view(),
            observed.height(),
            conflicting_block,
        )
        .unwrap();
        let mut malicious = ConsensusCertificateCollectorV0::new(
            harness.validator_set.clone(),
            MAXIMUM_COLLECTOR_COORDINATES_V0,
        )
        .unwrap();
        for index in 0..3 {
            let vote = Vote::new(
                harness.validator_set.chain_id(),
                harness.validator_set.protocol_version(),
                harness.validator_set.epoch(),
                observed.view(),
                observed.height(),
                conflicting_block,
                harness.validator_set.id(),
                harness.validator_set.validators()[index].id(),
                SignatureBytes::from_array(
                    harness.keys[index].sign(vote_root.as_bytes()).to_bytes(),
                ),
                &harness.validator_set,
            )
            .unwrap();
            malicious.admit_vote(vote).unwrap();
        }
        let conflicting = malicious
            .try_quorum_certificate(observed.view(), observed.height(), conflicting_block)
            .unwrap()
            .unwrap();
        conflicting
            .verify(&harness.validator_set, &StrictEd25519Verifier)
            .unwrap();
        let high = QcRef::from(&conflicting);
        let timeout_root = TimeoutVote::signing_root_for_set(
            &harness.validator_set,
            accepted.timed_out_view(),
            high,
        )
        .unwrap();
        for index in 0..3 {
            let timeout = TimeoutVote::new(
                harness.validator_set.chain_id(),
                harness.validator_set.protocol_version(),
                harness.validator_set.epoch(),
                accepted.timed_out_view(),
                harness.validator_set.id(),
                high,
                harness.validator_set.validators()[index].id(),
                SignatureBytes::from_array(
                    harness.keys[index].sign(timeout_root.as_bytes()).to_bytes(),
                ),
                &harness.validator_set,
            )
            .unwrap();
            malicious.admit_timeout_vote(timeout).unwrap();
        }
        let hidden = malicious
            .try_timeout_certificate(accepted.timed_out_view())
            .unwrap()
            .unwrap();
        hidden
            .verify(&harness.validator_set, None, &StrictEd25519Verifier)
            .unwrap();
        assert_eq!(hidden.selected_high_qc_digest(), conflicting.id());
        assert!(conflicting.view() < authoritative.view());
        assert!(crate::collector::timeout_certificates_compatible_v0(
            &accepted, &hidden
        ));
        let target = &mut harness.authorities[0];
        let before = target.facts_v0().unwrap();
        assert_eq!(before.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
        assert_eq!(before.high_qc_v0().qc_digest(), authoritative.id());
        // The complete Core preview sees the earlier observed QC even though
        // the retained TC does not. It cannot classify this as a no-effect TC.
        let Some(ContinuousAuthorityPhaseV0::Ready(runtime)) = target.phase.as_mut() else {
            panic!("genuine accepted TC must leave Ready")
        };
        assert!(!runtime
            .reconfirm_certificate_no_effect_v0(Input::TimeoutCertificate(hidden.clone()))
            .unwrap());
        assert_eq!(target.facts_v0().unwrap(), before);
        let error = target
            .advance_timeout_certificate_v0(hidden)
            .expect_err("lower TC containing a new conflicting QC must reach Core");
        assert!(
            error.to_string().contains("advance Ready TC:"),
            "must reach the genuine consuming conflict path: {error}"
        );
        assert!(
            target.facts_v0().is_err(),
            "unsupported conflict effects must fence the owner, not return unchanged Ready"
        );
    });
}
