use crate::{consensus_mesh::MeshIngressEventV0, frame::AuthenticatedFrame};

fn members() -> BTreeSet<ValidatorId> {
    (1..=7).map(|v| ValidatorId::new([v; 32])).collect()
}
fn sessions(local: ValidatorId) -> Vec<PeerSessionFactsV0> {
    members()
        .into_iter()
        .filter(|v| *v != local)
        .flat_map(|v| {
            [PeerDirectionV0::Inbound, PeerDirectionV0::Outbound].map(|d| {
                PeerSessionFactsV0::for_test(v, d, [*v.as_bytes().first().unwrap() + 16; 32], 1)
            })
        })
        .collect()
}
fn prepare(origin: ValidatorId) -> TerminalPrepareV1 {
    TerminalPrepareV1 {
        common: TerminalCommonCutV1 {
            height: 9,
            block: [31; 32],
            state: [32; 32],
            chain: [33; 32],
        },
        checkpoint: origin.as_bytes().try_into().unwrap(),
        local_cut: [49; 32],
    }
}
fn inbound(local: ValidatorId, origin: ValidatorId, body: BodyV1) -> MeshInboundFrameV0 {
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
            payload: MessageV1 {
                start: [77; 32],
                origin,
                body,
            }
            .encode(),
        },
    )
}
fn seed_drains(barrier: &mut TerminalBarrierV1) {
    // State-machine fixture only; authenticated ingress is tested separately.
    for origin in members() {
        barrier.insert(MessageV1 {
            start: barrier.start, origin,
            body: BodyV1::AdmissionDrained { finalized: 9, business: 0 },
        }).unwrap();
    }
}
fn initialized() -> TerminalBarrierV1 {
    let local = ValidatorId::new([1; 32]);
    let mut barrier = TerminalBarrierV1::new([77; 32], local, members(), &sessions(local)).unwrap();
    seed_drains(&mut barrier);
    barrier.prepare_local(prepare(local)).unwrap();
    barrier
}
fn full_prepared() -> TerminalBarrierV1 {
    let mut barrier = initialized();
    for remote in members()
        .into_iter()
        .filter(|v| *v != barrier.local)
        .collect::<Vec<_>>()
    {
        barrier
            .admit(&inbound(
                barrier.local,
                remote,
                BodyV1::Prepare(prepare(remote)),
            ))
            .unwrap();
    }
    barrier
}

#[test]
fn terminal_codec_rejects_open_lengths_phases_zero_fields_and_other_contexts_v1() {
    let local = ValidatorId::new([1; 32]);
    let remote = ValidatorId::new([2; 32]);
    let bytes = MessageV1 {
        start: [77; 32],
        origin: remote,
        body: BodyV1::Prepare(prepare(remote)),
    }
    .encode();
    assert_eq!(bytes.len(), PREPARE_BYTES);
    assert_eq!(MessageV1::decode(&bytes).unwrap().encode(), bytes);
    for n in 0..bytes.len() {
        assert!(MessageV1::decode(&bytes[..n]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(MessageV1::decode(&extra).is_err());
    for phase in [0, 2, 3, 255] {
        let mut mutant = bytes.clone();
        mutant[8] = phase;
        assert!(MessageV1::decode(&mutant).is_err());
    }
    for (start, end) in [
        (9, 41),
        (41, 73),
        (73, 81),
        (81, 113),
        (113, 145),
        (145, 177),
        (177, 209),
        (209, 241),
    ] {
        let mut mutant = bytes.clone();
        mutant[start..end].fill(0);
        assert!(MessageV1::decode(&mutant).is_err());
    }
    let mut wrong_start = inbound(local, remote, BodyV1::Prepare(prepare(remote))).into_frame();
    wrong_start.payload[9] ^= 1;
    let session = sessions(local)[0];
    assert!(initialized()
        .admit(&MeshInboundFrameV0::for_test(session, wrong_start))
        .is_err());
    let mut wrong_sender = inbound(local, remote, BodyV1::Prepare(prepare(remote))).into_frame();
    wrong_sender.sender = local;
    assert!(initialized()
        .admit(&MeshInboundFrameV0::for_test(session, wrong_sender))
        .is_err());
    let mut wrong_origin = inbound(local, remote, BodyV1::Prepare(prepare(remote))).into_frame();
    wrong_origin.payload[41] ^= 1;
    assert!(initialized()
        .admit(&MeshInboundFrameV0::for_test(session, wrong_origin))
        .is_err());
    let mut wrong_session = inbound(local, remote, BodyV1::Prepare(prepare(remote))).into_frame();
    wrong_session.session[0] ^= 1;
    assert!(initialized()
        .admit(&MeshInboundFrameV0::for_test(session, wrong_session))
        .is_err());
}

#[test]
fn terminal_sets_are_order_independent_and_exact_retries_cannot_change_cuts_v1() {
    let mut first = full_prepared();
    let mut second = initialized();
    for remote in members()
        .into_iter()
        .rev()
        .filter(|v| *v != second.local)
        .collect::<Vec<_>>()
    {
        let inbound = inbound(second.local, remote, BodyV1::Prepare(prepare(remote)));
        second.admit(&inbound).unwrap();
        second.admit(&inbound).unwrap();
    }
    assert_eq!(first.prepare_set().unwrap(), second.prepare_set().unwrap());
    assert_eq!(second.prepares.len(), 7);
    let remote = ValidatorId::new([2; 32]);
    let mut changed = prepare(remote);
    changed.local_cut[0] ^= 1;
    assert!(first
        .admit(&inbound(first.local, remote, BodyV1::Prepare(changed)))
        .is_err());
    let mut different_root = initialized();
    changed = prepare(remote);
    changed.common.chain[0] ^= 1;
    assert!(different_root
        .admit(&inbound(
            different_root.local,
            remote,
            BodyV1::Prepare(changed)
        ))
        .is_err());
    assert!(different_root
        .observe_unavailable(sessions(different_root.local)[0])
        .is_err());
    let newer = PeerSessionFactsV0::for_test(remote, PeerDirectionV0::Inbound, [98; 32], 2);
    assert!(second.observe_session(newer).is_err());
    let local = ValidatorId::new([1; 32]);
    let mut reconnected =
        TerminalBarrierV1::new([77; 32], local, members(), &sessions(local)).unwrap();
    reconnected.observe_session(newer).unwrap();
    seed_drains(&mut reconnected);
    reconnected.prepare_local(prepare(local)).unwrap();
    let old = sessions(local)
        .into_iter()
        .find(|s| s.remote() == remote && s.direction() == PeerDirectionV0::Inbound)
        .unwrap();
    reconnected.observe_session(old).unwrap();
    assert_eq!(
        reconnected
            .sessions
            .get(&(PeerDirectionV0::Inbound, remote)),
        Some(&(newer.generation(), newer.session_id()))
    );
    assert!(reconnected
        .admit(&inbound(local, remote, BodyV1::Prepare(prepare(remote))))
        .is_err());
}

#[test]
fn terminal_missing_park_wrong_set_and_shutdown_residuals_remain_fail_closed_v1() {
    let mut barrier = full_prepared();
    let set = barrier.prepare_set().unwrap().unwrap();
    // Protocol state machine unit test only; genuine production Park minting
    // is covered with actual consumed owners in consensus_runtime tests.
    barrier
        .insert(MessageV1 {
            start: barrier.start,
            origin: barrier.local,
            body: BodyV1::Park(set),
        })
        .unwrap();
    let peers = members()
        .into_iter()
        .filter(|v| *v != barrier.local)
        .collect::<Vec<_>>();
    for peer in &peers[..5] {
        barrier
            .admit(&inbound(barrier.local, *peer, BodyV1::Park(set)))
            .unwrap();
    }
    let missing = *peers.last().unwrap();
    let unavailable = sessions(barrier.local)
        .into_iter()
        .find(|s| s.remote() == missing)
        .unwrap();
    barrier.observe_unavailable(unavailable).unwrap();
    assert!(!barrier.complete().unwrap());
    assert!(!barrier.explains_unavailable(unavailable).unwrap());
    assert!(barrier
        .validate_residual(MeshIngressEventV0::SessionUnavailable(unavailable))
        .is_err());
    barrier
        .admit(&inbound(barrier.local, missing, BodyV1::Park(set)))
        .unwrap();
    assert!(barrier.complete().unwrap());
    assert!(barrier.explains_unavailable(unavailable).unwrap());
    barrier
        .validate_residual(MeshIngressEventV0::SessionUnavailable(unavailable))
        .unwrap();
    barrier
        .validate_residual(MeshIngressEventV0::Frame(Box::new(inbound(
            barrier.local,
            missing,
            BodyV1::Park(set),
        ))))
        .unwrap();
    let mut ordinary = inbound(barrier.local, missing, BodyV1::Park(set)).into_frame();
    ordinary.kind = FrameKind::Vote;
    assert!(barrier
        .validate_residual(MeshIngressEventV0::Frame(Box::new(MeshInboundFrameV0::for_test(
            unavailable,
            ordinary
        ))))
        .is_err());
    assert!(barrier
        .validate_residual(MeshIngressEventV0::SessionReestablished(unavailable))
        .is_err());
    let stale = PeerSessionFactsV0::for_test(missing, unavailable.direction(), [94; 32], 2);
    assert!(barrier
        .validate_residual(MeshIngressEventV0::SessionUnavailable(stale))
        .is_err());
    assert!(barrier
        .admit(&inbound(barrier.local, missing, BodyV1::Park([99; 32])))
        .is_err());
    let mut early = initialized();
    early
        .admit(&inbound(early.local, missing, BodyV1::Park([99; 32])))
        .unwrap();
    let mut rejected = false;
    for remote in peers {
        rejected |= early
            .admit(&inbound(
                early.local,
                remote,
                BodyV1::Prepare(prepare(remote)),
            ))
            .is_err();
    }
    assert!(rejected);
}


#[test]
fn terminal_local_empty_queue_cannot_prepare_without_peer_admission_drains_v2() {
    let local = ValidatorId::new([1; 32]);
    let mut barrier = TerminalBarrierV1::new([77; 32], local, members(), &sessions(local)).unwrap();
    assert!(barrier.prepare_local(prepare(local)).is_err(),
        "local Ready/empty queue cannot stand in for the six peer admission owners");
    assert!(!barrier.local_prepared());
}


#[test]
fn terminal_drain_requires_all_seven_and_covers_last_business_height_v2() {
    let local = ValidatorId::new([1; 32]);
    let mut barrier = TerminalBarrierV1::new([77; 32], local, members(), &sessions(local)).unwrap();
    barrier.drain_local(9, 7).unwrap();
    for remote in members().into_iter().filter(|v| *v != local).take(5) {
        let message = inbound(local, remote, BodyV1::AdmissionDrained { finalized: 9, business: 0 });
        barrier.admit(&message).unwrap();
        barrier.admit(&message).unwrap();
    }
    assert_eq!(barrier.drains.len(), 6);
    assert!(!barrier.admission_drain_ready(u64::MAX));
    assert!(barrier.prepare_local(prepare(local)).is_err());
    let last = ValidatorId::new([7; 32]);
    barrier.admit(&inbound(local, last, BodyV1::AdmissionDrained { finalized: 11, business: 11 })).unwrap();
    assert!(!barrier.admission_drain_ready(10));
    assert!(barrier.admission_drain_ready(11));
    assert!(barrier.prepare_local(prepare(local)).is_err());
    let mut final_cut = prepare(local);
    final_cut.common.height = 11;
    barrier.prepare_local(final_cut).unwrap();
    let prior = barrier.drains.clone();
    assert!(barrier.admit(&inbound(local, last, BodyV1::AdmissionDrained { finalized: 12, business: 11 })).is_err());
    assert_eq!(barrier.drains, prior);
}

#[test]
fn terminal_drain_is_bounded_context_bound_and_session_fenced_v2() {
    let local = ValidatorId::new([1; 32]);
    let remote = ValidatorId::new([2; 32]);
    let message = MessageV1 { start: [77; 32], origin: remote,
        body: BodyV1::AdmissionDrained { finalized: 9, business: 0 } };
    let bytes = message.encode();
    assert_eq!(bytes.len(), DRAIN_BYTES);
    assert_eq!(MessageV1::decode(&bytes).unwrap(), message);
    for n in 0..bytes.len() { assert!(MessageV1::decode(&bytes[..n]).is_err()); }
    let mut extra = bytes.clone(); extra.push(0);
    assert!(MessageV1::decode(&extra).is_err());
    let mut old = bytes.clone(); old[..8].copy_from_slice(b"TRNMTB01");
    assert!(MessageV1::decode(&old).is_err());
    for (finalized, business) in [(0, 0), (9, 10), (1, u64::MAX)] {
        let bad = MessageV1 { body: BodyV1::AdmissionDrained { finalized, business }, ..message };
        assert!(MessageV1::decode(&bad.encode()).is_err());
    }
    for offset in [9, 41] {
        let mut bad = inbound(local, remote, message.body).into_frame();
        bad.payload[offset] ^= 1;
        let mut barrier = TerminalBarrierV1::new([77; 32], local, members(), &sessions(local)).unwrap();
        assert!(barrier.admit(&MeshInboundFrameV0::for_test(sessions(local)[0], bad)).is_err());
        assert!(barrier.drains.is_empty());
    }
    let mut barrier = TerminalBarrierV1::new([77; 32], local, members(), &sessions(local)).unwrap();
    barrier.admit(&inbound(local, remote, message.body)).unwrap();
    let new_session = PeerSessionFactsV0::for_test(remote, PeerDirectionV0::Inbound, [99; 32], 2);
    assert!(barrier.observe_session(new_session).is_err());
    assert!(!barrier.local_prepared());
}

#[test]
fn terminal_early_prepare_remains_inert_until_every_admission_owner_drains_v2() {
    let local = ValidatorId::new([1; 32]);
    let remote = ValidatorId::new([2; 32]);
    let mut barrier = TerminalBarrierV1::new([77; 32], local, members(), &sessions(local)).unwrap();
    assert!(barrier.admit(&inbound(local, remote, BodyV1::Prepare(prepare(remote)))).is_err());
    barrier.admit(&inbound(local, remote, BodyV1::AdmissionDrained { finalized: 9, business: 8 })).unwrap();
    barrier.admit(&inbound(local, remote, BodyV1::Prepare(prepare(remote)))).unwrap();
    assert_eq!(barrier.prepare_set().unwrap(), None);
    assert!(!barrier.complete().unwrap());
    assert!(barrier.prepare_local(prepare(local)).is_err());
}

#[test]
fn terminal_prepare_set_binds_the_original_admission_drain_records_v2() {
    let first = full_prepared();
    let mut second = TerminalBarrierV1::new(first.start, first.local, members(), &sessions(first.local)).unwrap();
    for origin in members().into_iter().rev() {
        second.insert(MessageV1 { start: first.start, origin,
            body: BodyV1::AdmissionDrained { finalized: 9, business: 1 } }).unwrap();
    }
    for origin in members().into_iter().rev() {
        second.insert(MessageV1 { start: first.start, origin, body: BodyV1::Prepare(prepare(origin)) }).unwrap();
    }
    assert_ne!(first.prepare_set().unwrap(), second.prepare_set().unwrap());
}
