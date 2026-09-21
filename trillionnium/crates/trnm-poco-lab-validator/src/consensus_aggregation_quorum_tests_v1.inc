// Real native/Core/Safety/signers, with delivery omissions rather than a claim
// about disconnected TCP peers. The queue is the production shared queue; the
// small observer below records only P identities after the real Vote path.

#[test]
fn seven_validator_quorum_publishes_certificates_without_designated_aggregators_v1() {
    on_consensus_owner_stack_v1(|| {
        let mut fixture = quorum_fallback_fixture_v1();
        let initial = fixture.authorities[0].facts_v0().unwrap();
        let proposal_view = initial.current_view_v0();
        let qc_next = View::new(proposal_view.get() + 1);
        let tc_next = View::new(qc_next.get() + 1);
        let index_of = |id| {
            fixture
                .validator_set
                .validators()
                .iter()
                .position(|validator| validator.id() == id)
                .unwrap()
        };
        let proposer = index_of(leader_for(&fixture.validator_set, proposal_view));
        let qc_aggregator = index_of(leader_for(&fixture.validator_set, qc_next));
        let tc_aggregator = index_of(leader_for(&fixture.validator_set, tc_next));
        assert_ne!(qc_aggregator, tc_aggregator);
        assert_ne!(proposer, qc_aggregator);
        assert_ne!(proposer, tc_aggregator);
        let active = (0..7)
            .filter(|index| *index != qc_aggregator && *index != tc_aggregator)
            .collect::<Vec<_>>();
        assert_eq!(active.len(), 5);
        assert_eq!(fixture.validator_set.quorum_power(), 5);

        let before = fixture
            .authorities
            .iter()
            .map(|authority| authority.facts_v0().unwrap())
            .collect::<Vec<_>>();
        let mut observers = before
            .iter()
            .enumerate()
            .map(|(index, facts)| QuorumDeliveryObserverV1::new(&fixture, index, *facts))
            .collect::<Vec<_>>();
        let proposal = fixture.authorities[proposer]
            .proposal_preimage_for_test_v0(
                fixture.ordinary_start_height,
                fixture.parent_timestamp_ms,
                fixture.parent_transactions.clone(),
            )
            .unwrap()
            .seal_with_key_v0(&fixture.keys[proposer])
            .unwrap();
        let mut votes = Vec::new();
        for &index in &active {
            // This call executes and freshly confirms the real native P,
            // persists Safety and the signer intent, then returns a Vote.
            let vote = fixture.authorities[index]
                .vote_proposal_v0(proposal.clone())
                .unwrap();
            observers[index]
                .known
                .insert((vote.height().get(), *vote.block_id().as_bytes()));
            votes.push(vote);
        }
        let mut formed_qcs = Vec::new();
        for (index, observer) in observers.iter_mut().enumerate() {
            let mut formed = None;
            for vote in &votes {
                let candidate = quorum_admit_vote_v1(&mut fixture.authorities[index], vote);
                if let Some(certificate) = candidate {
                    certificate
                        .verify(
                            &fixture.validator_set,
                            &trnm_consensus_crypto::StrictEd25519Verifier,
                        )
                        .unwrap();
                    observer.queue_local(PendingCertificateV1::Quorum {
                        certificate: certificate.clone(),
                        publish: false,
                    });
                    formed = Some(certificate);
                }
            }
            let certificate = formed.expect("five genuine votes form a QC on every collector");
            assert_eq!(observer.pending.len(), 1);
            assert!(observer.pending[0].publish_v1());
            // A byte-exact duplicate cannot enqueue or publish a second QC.
            observer.queue_local(PendingCertificateV1::Quorum {
                certificate: certificate.clone(),
                publish: false,
            });
            assert_eq!(observer.pending.len(), 1);
            let progressed = observer.drain_actual(&mut fixture.authorities[index]);
            assert_eq!(progressed, active.contains(&index));
            if active.contains(&index) {
                assert_eq!(
                    fixture.authorities[index]
                        .facts_v0()
                        .unwrap()
                        .current_view_v0(),
                    qc_next
                );
                assert_eq!(observer.outbox.pending.len(), 1);
                let frame = observer.outbox.pending.front().unwrap();
                assert_eq!(frame.kind, FrameKind::QuorumCertificate);
                assert_eq!(
                    frame.payload.as_ref(),
                    encode_quorum_certificate(&certificate).unwrap()
                );
            } else {
                // The two scheduled aggregators received every signed vote,
                // but not the Proposal/P. They remain pending and unchanged.
                assert_eq!(
                    fixture.authorities[index].facts_v0().unwrap(),
                    before[index]
                );
                assert!(observer.outbox.is_empty());
            }
            formed_qcs.push(certificate);
        }
        assert!(formed_qcs.windows(2).all(|pair| pair[0] == pair[1]));

        let timeout_votes = active
            .iter()
            .map(|&index| fixture.authorities[index].begin_local_timeout_v0().unwrap())
            .collect::<Vec<_>>();
        assert!(timeout_votes.iter().all(|vote| {
            vote.view() == qc_next && vote.high_qc().qc_digest() == formed_qcs[0].id()
        }));
        for (index, observer) in observers.iter_mut().enumerate() {
            let mut formed = None;
            for vote in &timeout_votes {
                if let Some(certificate) =
                    quorum_admit_timeout_v1(&mut fixture.authorities[index], vote)
                {
                    certificate
                        .verify(
                            &fixture.validator_set,
                            None,
                            &trnm_consensus_crypto::StrictEd25519Verifier,
                        )
                        .unwrap();
                    observer.queue_local(PendingCertificateV1::Timeout {
                        certificate: certificate.clone(),
                        publish: false,
                    });
                    formed = Some(certificate);
                }
            }
            let certificate =
                formed.expect("five actual TimeoutVotes form a TC without either aggregator P");
            assert_eq!(certificate.timed_out_view(), qc_next);
            assert_eq!(
                certificate.selected_high_qc_digest(),
                formed_qcs[index].id()
            );
            let progressed = observer.drain_actual(&mut fixture.authorities[index]);
            assert_eq!(progressed, active.contains(&index));
            if active.contains(&index) {
                let after = fixture.authorities[index].facts_v0().unwrap();
                assert_eq!(after.current_view_v0(), tc_next);
                assert_eq!(after.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
                assert_eq!(after.high_qc_v0(), QcRef::from(&formed_qcs[index]));
                assert_eq!(after.signed_timeout_intents_v0(), 1);
                assert_eq!(observer.outbox.pending.len(), 2);
                let frame = observer.outbox.pending.back().unwrap();
                assert_eq!(frame.kind, FrameKind::TimeoutCertificate);
                assert_eq!(
                    frame.payload.as_ref(),
                    encode_timeout_certificate(&certificate).unwrap()
                );
                assert_eq!(frame.remaining_peers.len(), 6);
                // Replaying the original quorum preserves the first TC and
                // does not sign, consume a live owner, or publish again.
                for vote in &timeout_votes {
                    // Local output was admitted while TimeoutSigned. After
                    // Ready only remote retransmissions use ingress; never
                    // manufacture an authenticated self frame.
                    if vote.author() == fixture.authorities[index].local_validator_v0() {
                        continue;
                    }
                    let replay = quorum_admit_timeout_v1(&mut fixture.authorities[index], vote)
                        .expect("collector retains the original completed TC");
                    assert_eq!(replay, certificate);
                    observer.queue_local(PendingCertificateV1::Timeout {
                        certificate: replay,
                        publish: false,
                    });
                }
                assert!(observer.pending.is_empty());
                assert_eq!(observer.outbox.pending.len(), 2);
                assert_eq!(fixture.authorities[index].facts_v0().unwrap(), after);
            } else {
                assert_eq!(observer.pending.len(), 2);
                assert!(observer
                    .pending
                    .iter()
                    .all(PendingCertificateV1::publish_v1));
                assert!(observer.outbox.is_empty());
                assert_eq!(
                    fixture.authorities[index].facts_v0().unwrap(),
                    before[index]
                );
            }
        }
    });
}

struct QuorumDeliveryObserverV1 {
    pending: VecDeque<PendingCertificateV1>,
    applied_qcs: BTreeSet<[u8; 32]>,
    applied_tcs: BTreeSet<[u8; 32]>,
    accepted: BTreeMap<u64, TimeoutCertificateV0>,
    known: BTreeSet<(u64, [u8; 32])>,
    outbox: OrderedConsensusOutboxV1,
}

impl QuorumDeliveryObserverV1 {
    fn new(fixture: &RealTakeoverFixtureV1, local: usize, facts: ContinuousRuntimeFactsV0) -> Self {
        Self {
            pending: VecDeque::new(),
            applied_qcs: BTreeSet::new(),
            applied_tcs: BTreeSet::new(),
            accepted: BTreeMap::new(),
            known: BTreeSet::from([(
                facts.high_qc_v0().height().get(),
                *facts.high_qc_v0().block_id().as_bytes(),
            )]),
            outbox: OrderedConsensusOutboxV1::new(
                fixture
                    .validator_set
                    .validators()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, validator)| (index != local).then_some(validator.id()))
                    .collect(),
            ),
        }
    }

    fn queue_local(&mut self, candidate: PendingCertificateV1) {
        queue_locally_formed_certificate_into_v1(
            &mut self.pending,
            &self.applied_qcs,
            &self.applied_tcs,
            &self.accepted,
            candidate,
        )
        .unwrap();
    }

    fn drain_actual(&mut self, authority: &mut ContinuousValidatorAuthorityV0) -> bool {
        let facts = authority.facts_v0().unwrap();
        let mut progressed = false;
        while self
            .pending
            .front()
            .is_some_and(|candidate| match candidate {
                PendingCertificateV1::Quorum { certificate, .. } => ordinary_qc_execution_ready_v1(
                    certificate,
                    &self.known,
                    facts.finalized_height_v0(),
                    facts.finalized_block_id_v0(),
                    facts.finalized_view_v0(),
                ),
                PendingCertificateV1::Timeout { certificate, .. } => {
                    certificate.referenced_qcs().iter().all(|reference| {
                        qc_reference_execution_ready_v1(
                            reference,
                            &self.known,
                            facts.finalized_height_v0(),
                            facts.finalized_block_id_v0(),
                            facts.finalized_view_v0(),
                        )
                    })
                }
            })
        {
            match self.pending.pop_front().unwrap() {
                PendingCertificateV1::Quorum {
                    certificate,
                    publish,
                } => {
                    assert!(publish);
                    self.outbox
                        .enqueue(
                            FrameKind::QuorumCertificate,
                            encode_quorum_certificate(&certificate).unwrap(),
                        )
                        .unwrap();
                    authority
                        .advance_quorum_certificate_v0(certificate.clone())
                        .unwrap();
                    self.applied_qcs.insert(*certificate.id().as_bytes());
                }
                PendingCertificateV1::Timeout {
                    certificate,
                    publish,
                } => {
                    assert!(publish);
                    self.outbox
                        .enqueue(
                            FrameKind::TimeoutCertificate,
                            encode_timeout_certificate(&certificate).unwrap(),
                        )
                        .unwrap();
                    authority
                        .advance_timeout_certificate_v0(certificate.clone())
                        .unwrap();
                    self.applied_tcs.insert(*certificate.id().as_bytes());
                    self.accepted
                        .insert(certificate.timed_out_view().get(), certificate);
                }
            }
            progressed = true;
        }
        progressed
    }
}

fn quorum_admit_vote_v1(
    authority: &mut ContinuousValidatorAuthorityV0,
    vote: &Vote,
) -> Option<QuorumCertificate> {
    if vote.author() == authority.local_validator_v0() {
        return authority.admit_local_vote_v0(vote.clone()).unwrap();
    }
    let frame = AuthenticatedFrame {
        sender: vote.author(),
        session: [0xa1; 32],
        sequence: 0,
        kind: FrameKind::Vote,
        payload: encode_vote(vote),
    };
    match authority
        .admit_authenticated_consensus_frame_v0(&frame)
        .unwrap()
    {
        Some(RoutedConsensusActionV0::Vote { formed_qc, .. }) => {
            formed_qc.map(|certificate| *certificate)
        }
        _ => panic!("actual Vote must enter the strict collector"),
    }
}

fn quorum_admit_timeout_v1(
    authority: &mut ContinuousValidatorAuthorityV0,
    vote: &TimeoutVote,
) -> Option<TimeoutCertificateV0> {
    if vote.author() == authority.local_validator_v0() {
        return authority.admit_local_timeout_vote_v0(vote.clone()).unwrap();
    }
    let frame = AuthenticatedFrame {
        sender: vote.author(),
        session: [0xa2; 32],
        sequence: 0,
        kind: FrameKind::TimeoutVote,
        payload: encode_timeout_vote(vote),
    };
    match authority
        .admit_authenticated_consensus_frame_v0(&frame)
        .unwrap()
    {
        Some(RoutedConsensusActionV0::TimeoutVote { formed_tc, .. }) => {
            formed_tc.map(|certificate| *certificate)
        }
        _ => panic!("actual TimeoutVote must enter the strict collector"),
    }
}

#[inline(never)]
fn quorum_fallback_fixture_v1() -> RealTakeoverFixtureV1 {
    real_takeover_fixture_with_lifetime_v1(
        7,
        ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(2, 2, 4, 2).unwrap(),
    )
}
