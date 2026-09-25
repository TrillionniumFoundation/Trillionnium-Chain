#[test]
fn terminal_prepare_rejects_obligations_and_binds_independent_durable_heads_v1() {
    let mut clean = restart_quiescence_fixture_v1();
    clean.restart_requested = false;
    clean.normal_stop_in_progress = true;
    let original = terminal_prepare_from_snapshot_v1(&clean).unwrap();
    let mut mutants = Vec::new();
    let mut m = clean;
    m.pending_certificate_count = 1;
    mutants.push(m);
    let mut m = clean;
    m.pending_proposal_count = 1;
    mutants.push(m);
    let mut m = clean;
    m.unavailable_session_count = 1;
    mutants.push(m);
    let mut m = clean;
    m.expected_control_fault = true;
    mutants.push(m);
    let mut m = clean;
    m.active_journal_fault_count = 1;
    mutants.push(m);
    let mut m = clean;
    m.pending_timeout_certificate = true;
    mutants.push(m);
    let mut m = clean;
    m.post_timeout_rebase_pending = true;
    mutants.push(m);
    let mut m = clean;
    m.signer_inventory_digest[0] ^= 1;
    mutants.push(m);
    let mut m = clean;
    m.checkpoint_canonical_sha256[0] ^= 1;
    mutants.push(m);
    let mut m = clean;
    m.journal_safety_halted = true;
    mutants.push(m);
    let mut m = clean;
    m.normal_stop_in_progress = false;
    mutants.push(m);
    for mutant in mutants {
        assert!(terminal_prepare_from_snapshot_v1(&mutant).is_err());
    }
    clean.replay_archive_head_sha256[0] ^= 1;
    assert_ne!(
        original.local_cut,
        terminal_prepare_from_snapshot_v1(&clean).unwrap().local_cut
    );
    clean = restart_quiescence_fixture_v1();
    clean.restart_requested = false;
    clean.normal_stop_in_progress = true;
    clean.journal_head_sha256[0] ^= 1;
    assert_ne!(
        original.local_cut,
        terminal_prepare_from_snapshot_v1(&clean).unwrap().local_cut
    );
}

#[test]
fn terminal_seven_real_owners_park_only_after_every_prepare_then_validate_residuals_v1() {
    on_consensus_owner_stack_v1(|| {
        use crate::frame::AuthenticatedFrame;
        use crate::terminal_barrier_v1::{
            TerminalBarrierV1, TerminalCommonCutV1, TerminalPrepareV1,
        };
        let mut fixture = real_takeover_fixture_with_lifetime_v1(
            7,
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(3, 0, 3, 0).unwrap(),
        );
        let start = fixture.ordinary_start_height;
        for height in start..start + 3 {
            let proposal = terminal_tail_proposal_v1(
                &fixture,
                height,
                fixture.parent_timestamp_ms + (height - start) * 2,
            );
            let votes: Vec<_> = fixture
                .authorities
                .iter_mut()
                .map(|a| a.vote_proposal_v0(proposal.clone()).unwrap())
                .collect();
            let qc = quorum_certificate_v1(&fixture.validator_set, &proposal, votes);
            for a in &mut fixture.authorities {
                a.advance_quorum_certificate_v0(qc.clone()).unwrap();
            }
        }
        let mut terminals = fixture
            .authorities
            .into_iter()
            .map(|a| a.into_terminal_owner_v0().unwrap())
            .collect::<Vec<_>>();
        let ids = terminals
            .iter()
            .map(|t| t.facts_v0().local_validator_v0())
            .collect::<BTreeSet<_>>();
        let sessions = |local: ValidatorId| {
            ids.iter()
                .copied()
                .filter(|v| *v != local)
                .flat_map(|remote| {
                    [PeerDirectionV0::Inbound, PeerDirectionV0::Outbound].map(move |direction| {
                        PeerSessionFactsV0::for_test(
                            remote,
                            direction,
                            remote.as_bytes().try_into().unwrap(),
                            1,
                        )
                    })
                })
                .collect::<Vec<_>>()
        };
        let frame = |local: ValidatorId, origin: ValidatorId, payload: Vec<u8>| {
            let session = sessions(local)
                .into_iter()
                .find(|s| s.remote() == origin && s.direction() == PeerDirectionV0::Inbound)
                .unwrap();
            MeshInboundFrameV0::for_test(
                session,
                AuthenticatedFrame {
                    sender: origin,
                    session: session.session_id(),
                    sequence: 1,
                    kind: FrameKind::TerminalBarrier,
                    payload,
                },
            )
        };
        let mut barriers = terminals
            .iter()
            .map(|t| {
                TerminalBarrierV1::new(
                    [72; 32],
                    t.facts_v0().local_validator_v0(),
                    ids.clone(),
                    &sessions(t.facts_v0().local_validator_v0()),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let drains = barriers.iter_mut().zip(&terminals).map(|(barrier, terminal)| {
            barrier.drain_local(terminal.facts_v0().node_v0().finalized_height_v0(), 0).unwrap()
        }).collect::<Vec<_>>();
        for i in 0..7 {
            for j in 0..7 {
                if i != j {
                    barriers[i].admit(&frame(
                        terminals[i].facts_v0().local_validator_v0(),
                        terminals[j].facts_v0().local_validator_v0(), drains[j].clone(),
                    )).unwrap();
                }
            }
        }
        let mut prepares = Vec::new();
        for (barrier, terminal) in barriers.iter_mut().zip(&terminals) {
            let f = terminal.facts_v0();
            let n = f.node_v0();
            prepares.push(
                barrier
                    .prepare_local(TerminalPrepareV1 {
                        common: TerminalCommonCutV1 {
                            height: n.finalized_height_v0(),
                            block: *n.finalized_block_id_v0().as_bytes(),
                            state: n.application_state_root_v0(),
                            chain: n.finalized_chain_root_v0(),
                        },
                        checkpoint: n.checkpoint_canonical_sha256_v0(),
                        local_cut: n.checkpoint_canonical_sha256_v0(),
                    })
                    .unwrap(),
            );
        }
        // Stagger the last Prepare. Every owner exists but none can publish
        // Park from quorum-only or nominal-horizon readiness.
        for i in 0..7 {
            for j in 0..6 {
                if i != j {
                    barriers[i]
                        .admit(&frame(
                            terminals[i].facts_v0().local_validator_v0(),
                            terminals[j].facts_v0().local_validator_v0(),
                            prepares[j].clone(),
                        ))
                        .unwrap();
                }
            }
            if i != 6 {
                assert!(barriers[i].park_local(&mut terminals[i]).is_err());
            }
            assert!(!barriers[i].complete().unwrap());
        }
        for i in 0..6 {
            barriers[i]
                .admit(&frame(
                    terminals[i].facts_v0().local_validator_v0(),
                    terminals[6].facts_v0().local_validator_v0(),
                    prepares[6].clone(),
                ))
                .unwrap();
        }
        let common_set = barriers[0].prepare_set().unwrap();
        assert!(barriers
            .iter()
            .all(|b| b.prepare_set().unwrap() == common_set));
        let mut parks = Vec::new();
        for (b, t) in barriers.iter_mut().zip(&mut terminals) {
            parks.push(b.park_local(t).unwrap());
        }
        for i in 0..7 {
            for j in 0..7 {
                if i != j {
                    barriers[i]
                        .admit(&frame(
                            terminals[i].facts_v0().local_validator_v0(),
                            terminals[j].facts_v0().local_validator_v0(),
                            parks[j].clone(),
                        ))
                        .unwrap();
                }
            }
            assert!(barriers[i].complete().unwrap());
            let peer = (i + 1) % 7;
            barriers[i]
                .validate_residual(MeshIngressEventV0::Frame(Box::new(frame(
                    terminals[i].facts_v0().local_validator_v0(),
                    terminals[peer].facts_v0().local_validator_v0(),
                    parks[peer].clone(),
                ))))
                .unwrap();
            terminals[i].confirm_terminal_cut_v1().unwrap();
        }
    });
}
