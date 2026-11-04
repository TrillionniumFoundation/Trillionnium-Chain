//! Ordinary new/duplicate admission controls for deferred packet wire copying.
//! Both profiles retain real signatures, full W1, M06 and durable packet bytes.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

fn new_and_exact_duplicate(node: &mut Node, packet: Packet, clock: u64) {
    let wire = packet.encode_for_settings(node.settings()).unwrap();
    assert_eq!(
        packet
            .checked_wire_length_for_settings(node.settings())
            .unwrap(),
        wire.len()
    );
    let decoded = Packet::decode_for_settings(&wire, node.settings()).unwrap();
    assert_eq!(decoded.encode_for_settings(node.settings()).unwrap(), wire);
    let id = packet.id().unwrap();
    assert_eq!(decoded.id().unwrap(), id);
    assert_eq!(
        node.check_admission_header_context(&packet, clock, None)
            .unwrap(),
        None
    );

    let mut tiles = 0;
    let mut verified_work = false;
    let execution = AtomicUsize::new(0);
    assert_eq!(
        node.admit_with_work_progress(
            &packet,
            clock,
            &mut |point| {
                use pon_work::VerificationProgress;
                if matches!(point, VerificationProgress::TranscriptTile { .. }) {
                    tiles += 1;
                }
                verified_work |= point == VerificationProgress::BeforeVerifiedWork;
                Ok(())
            },
            &|_| {
                execution.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )
        .unwrap(),
        id
    );
    assert_eq!(tiles, 512);
    assert!(verified_work);
    assert!(execution.load(Ordering::Relaxed) > 0);
    assert_eq!(
        node.packet(id)
            .unwrap()
            .encode_for_settings(node.settings())
            .unwrap(),
        wire
    );
    let state = node.state_at(id).unwrap();
    let stats = node.stats().unwrap();
    assert_eq!(
        node.check_admission_header_context(&decoded, clock, None)
            .unwrap(),
        Some(id)
    );
    let mut repeated_work = 0;
    let repeated_execution = AtomicUsize::new(0);
    assert_eq!(
        node.admit_with_work_progress(
            &decoded,
            clock,
            &mut |_| {
                repeated_work += 1;
                Ok(())
            },
            &|_| {
                repeated_execution.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )
        .unwrap(),
        id
    );
    assert_eq!(repeated_work, 0);
    assert_eq!(repeated_execution.load(Ordering::Relaxed), 0);
    assert_eq!(node.state_at(id).unwrap(), state);
    assert_eq!(node.stats().unwrap(), stats);
}

#[test]
fn legacy_new_and_exact_duplicate_keep_wire_and_full_admission() {
    let settings = Settings::development(Some(1)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transfer = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    transfer.signature = hex::decode(sign_hex(&key, &transfer.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![transfer.encode().unwrap()],
            development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    new_and_exact_duplicate(&mut node, packet, 20);
}

#[test]
fn pq_new_and_exact_duplicate_keep_wire_and_full_admission() {
    use crate::ingress::pq_network::canonical_tests::{key, setup, transfer};
    let (settings, policy) = setup();
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let packet = node
        .make_consensus_maintenance(
            settings.genesis(),
            vec![transfer(&settings)],
            key(1).public_key_id(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    new_and_exact_duplicate(&mut node, packet, settings.genesis_time() + 20);
}
