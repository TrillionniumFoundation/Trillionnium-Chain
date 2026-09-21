use super::*;
use crate::consensus_mesh::MeshSendDispositionV0::{Backpressured, Queued};

fn peers_v2() -> [ValidatorId; 2] {
    [ValidatorId::new([1; 32]), ValidatorId::new([2; 32])]
}

#[test]
fn per_peer_outbox_healthy_peer_advances_and_recovered_peer_keeps_fifo() {
    let [slow, fast] = peers_v2();
    let mut outbox = OrderedConsensusOutboxV1::new(vec![slow, fast]);
    for marker in 1..=3 {
        outbox
            .enqueue(FrameKind::Vote, vec![marker; marker as usize])
            .unwrap();
    }
    let mut received = BTreeMap::<ValidatorId, Vec<u8>>::new();
    for expected in 1..=3 {
        let mut attempted = BTreeSet::new();
        let (bytes, frames) = outbox
            .flush_with_v2(|peer, kind, payload| {
                assert!(attempted.insert(peer), "one attempt per peer per flush");
                assert_eq!(kind, FrameKind::Vote);
                if peer == slow {
                    assert_eq!(payload.as_ref(), &[1]);
                    return Ok(Backpressured);
                }
                received.entry(peer).or_default().push(payload[0]);
                Ok(Queued)
            })
            .unwrap();
        assert_eq!((bytes, frames), (expected, 1));
        assert_eq!(outbox.pending_bytes, 6);
    }
    assert_eq!(received.get(&fast).unwrap(), &[1, 2, 3]);
    for expected in 1..=3 {
        let mut attempted = BTreeSet::new();
        let result = outbox
            .flush_with_v2(|peer, _, payload| {
                assert!(attempted.insert(peer));
                assert_eq!(peer, slow);
                received.entry(peer).or_default().push(payload[0]);
                Ok(Queued)
            })
            .unwrap();
        assert_eq!(result, (expected, 1));
    }
    assert_eq!(received.get(&slow).unwrap(), &[1, 2, 3]);
    assert!(outbox.is_empty());
    assert_eq!(
        outbox
            .flush_with_v2(|_, _, _| panic!("empty outbox sends nothing"))
            .unwrap(),
        (0, 0)
    );
}

#[test]
fn per_peer_outbox_excluded_peer_allows_nonfront_row_retirement() {
    let [slow, fast] = peers_v2();
    let mut outbox = OrderedConsensusOutboxV1::new(vec![slow, fast]);
    outbox.enqueue(FrameKind::Vote, vec![1; 3]).unwrap();
    outbox
        .enqueue_except_v1(FrameKind::ConsensusRelay, vec![2; 7], slow)
        .unwrap();
    for (kind, marker, length) in [(FrameKind::Vote, 1, 3), (FrameKind::ConsensusRelay, 2, 7)] {
        let result = outbox
            .flush_with_v2(|peer, actual_kind, payload| {
                if peer == slow {
                    assert_eq!(payload[0], 1);
                    return Ok(Backpressured);
                }
                assert_eq!(actual_kind, kind);
                assert_eq!(payload.as_ref(), vec![marker; length]);
                Ok(Queued)
            })
            .unwrap();
        assert_eq!(result, (length as u64, 1));
    }
    assert_eq!(outbox.pending.len(), 1);
    assert_eq!(outbox.pending_bytes, 3);
    assert_eq!(
        outbox.pending.front().unwrap().remaining_peers,
        BTreeSet::from([slow])
    );
    assert_eq!(
        outbox
            .flush_with_v2(|peer, _, _| {
                assert_eq!(peer, slow);
                Ok(Queued)
            })
            .unwrap(),
        (3, 1)
    );
    assert!(outbox.is_empty());
}

#[test]
fn per_peer_outbox_mesh_error_propagates_without_dropping_unaccepted_frames() {
    let [first, second] = peers_v2();
    let mut outbox = OrderedConsensusOutboxV1::new(vec![first, second]);
    outbox.enqueue(FrameKind::Vote, vec![1; 3]).unwrap();
    outbox.enqueue(FrameKind::Vote, vec![2; 4]).unwrap();
    let error = outbox
        .flush_with_v2(|peer, _, payload| {
            assert_eq!(payload[0], 1);
            if peer == first {
                Ok(Queued)
            } else {
                bail!("actual mesh fence rejected")
            }
        })
        .unwrap_err();
    assert!(error.to_string().contains("actual mesh fence rejected"));
    assert_eq!(outbox.pending_bytes, 7);
    assert_eq!(
        outbox.pending.front().unwrap().remaining_peers,
        BTreeSet::from([second])
    );
    let mut delivered = BTreeMap::new();
    assert_eq!(
        outbox
            .flush_with_v2(|peer, _, payload| {
                assert!(delivered.insert(peer, payload[0]).is_none());
                Ok(Queued)
            })
            .unwrap(),
        (7, 2)
    );
    assert_eq!(delivered, BTreeMap::from([(first, 2), (second, 1)]));
    assert_eq!(outbox.pending_bytes, 4);
    assert_eq!(
        outbox.pending.front().unwrap().remaining_peers,
        BTreeSet::from([second])
    );
}

#[test]
fn per_peer_outbox_empty_destination_refusal_is_atomic() {
    for peers in [Vec::new(), vec![peers_v2()[0]]] {
        let mut outbox = OrderedConsensusOutboxV1::new(peers);
        assert!(outbox
            .enqueue_except_v1(FrameKind::Vote, vec![1; 3], peers_v2()[0])
            .is_err());
        assert!(outbox.is_empty());
        assert_eq!(outbox.pending_bytes, 0);
    }
    let mut outbox = OrderedConsensusOutboxV1::new(peers_v2().to_vec());
    assert!(outbox.enqueue(FrameKind::Vote, Vec::new()).is_err());
    assert!(outbox.is_empty());
}

#[test]
fn per_peer_outbox_message_capacity_is_unchanged_and_refusal_is_atomic() {
    let mut outbox = OrderedConsensusOutboxV1::new(peers_v2().to_vec());
    for _ in 0..MAXIMUM_PENDING_BROADCASTS_V1 {
        outbox.enqueue(FrameKind::Vote, vec![1]).unwrap();
    }
    assert!(outbox.enqueue(FrameKind::Vote, vec![2]).is_err());
    assert_eq!(outbox.pending.len(), MAXIMUM_PENDING_BROADCASTS_V1);
    assert_eq!(outbox.pending_bytes, MAXIMUM_PENDING_BROADCASTS_V1);
    assert_eq!(
        outbox.flush_with_v2(|_, _, _| Ok(Backpressured)).unwrap(),
        (0, 0)
    );
    assert_eq!(outbox.pending.len(), MAXIMUM_PENDING_BROADCASTS_V1);
}

#[test]
fn per_peer_outbox_byte_capacity_is_unchanged_until_last_destination() {
    let [first, second] = peers_v2();
    let mut outbox = OrderedConsensusOutboxV1::new(vec![first, second]);
    let part = 4 * 1024 * 1024;
    assert!(part <= crate::frame::MAX_FRAME_PAYLOAD_BYTES);
    for _ in 0..MAXIMUM_PENDING_BROADCAST_BYTES_V1 / part {
        outbox.enqueue(FrameKind::Vote, vec![1; part]).unwrap();
    }
    assert!(outbox.enqueue(FrameKind::Vote, vec![2]).is_err());
    assert_eq!(outbox.pending_bytes, MAXIMUM_PENDING_BROADCAST_BYTES_V1);
    for _ in 0..MAXIMUM_PENDING_BROADCAST_BYTES_V1 / part {
        outbox
            .flush_with_v2(|peer, _, _| Ok(if peer == first { Queued } else { Backpressured }))
            .unwrap();
        assert_eq!(outbox.pending_bytes, MAXIMUM_PENDING_BROADCAST_BYTES_V1);
    }
    assert!(outbox.enqueue(FrameKind::Vote, vec![2]).is_err());
    assert_eq!(
        outbox
            .flush_with_v2(|peer, _, _| {
                assert_eq!(peer, second);
                Ok(Queued)
            })
            .unwrap(),
        (part as u64, 1)
    );
    assert_eq!(
        outbox.pending_bytes,
        MAXIMUM_PENDING_BROADCAST_BYTES_V1 - part
    );
    outbox.enqueue(FrameKind::Vote, vec![2; part]).unwrap();
    assert_eq!(outbox.pending_bytes, MAXIMUM_PENDING_BROADCAST_BYTES_V1);
    assert!(outbox.enqueue(FrameKind::Vote, vec![3]).is_err());
}
