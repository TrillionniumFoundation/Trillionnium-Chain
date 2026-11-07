use super::*;
use crate::ingress::{public_v3, DevelopmentIdentity, Page};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::{hash, Envelope, HEADER_BYTES};

struct Chain {
    owner: Mutex<Node>,
    directory: tempfile::TempDir,
    settings: Settings,
    ids: Vec<Hash>,
    packets: Vec<Packet>,
}

fn chain(count: u64, transactions_per_block: u64) -> Chain {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut ids = vec![settings.genesis()];
    let mut packets = Vec::new();
    for height in 1..=count {
        let transactions = (1..=transactions_per_block)
            .map(|index| {
                let mut payload = crate::development_public(1).unwrap().to_vec();
                payload.extend(1_u64.to_le_bytes());
                let mut transaction = Envelope {
                    network: settings.network(),
                    sender: crate::development_public(0).unwrap(),
                    nonce: (height - 1) * transactions_per_block + index,
                    expiry: 10_000,
                    fee_limit: 1000,
                    tag: 1,
                    payload,
                    signature: [0; 64],
                };
                transaction.signature =
                    hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
                        .unwrap()
                        .try_into()
                        .unwrap();
                transaction.encode().unwrap()
            })
            .collect();
        let packet = node
            .make(
                *ids.last().unwrap(),
                transactions,
                crate::development_public(2).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, CLOCK).unwrap();
        node.activate_observed(id, CLOCK).unwrap();
        ids.push(id);
        packets.push(packet);
    }
    Chain {
        owner: Mutex::new(node),
        directory,
        settings,
        ids,
        packets,
    }
}

fn packet_ids(page: &Page) -> Vec<Hash> {
    page.packets
        .iter()
        .map(|raw| {
            Packet::decode(&hex::decode(raw).unwrap())
                .unwrap()
                .id()
                .unwrap()
        })
        .collect()
}

#[test]
fn public_history_batch_seven_packets_replay_independently_before_depth_six() {
    let f = chain(7, 1);
    let before = f.owner.lock().unwrap().read_active().unwrap();
    let value = dispatch(&f.owner, f.ids[7], f.ids[0]).unwrap();
    let page: Page = serde_json::from_value(value).unwrap();
    assert_eq!(packet_ids(&page), f.ids[1..]);
    assert_eq!(page.after, hex::encode(f.ids[0]));
    assert_eq!(page.next, hex::encode(f.ids[7]));
    assert!(page.complete);

    // This is a native correctness regression, not a Host-qualified timed run.
    // The independent owner executes actual W1 and M06 for all seven bodies;
    // receiving a page or a service ACK supplies no admission authority.
    let directory = tempfile::tempdir().unwrap();
    let mut verifier = Node::open(directory.path(), f.settings.clone(), 1).unwrap();
    let mut after = f.ids[0];
    for (raw, expected) in page.packets.iter().zip(&f.packets) {
        let raw = hex::decode(raw).unwrap();
        assert_eq!(raw, expected.encode().unwrap());
        let packet = Packet::decode(&raw).unwrap();
        assert_eq!(packet.header.parent, after);
        after = verifier.admit(&packet, CLOCK).unwrap();
    }
    assert_eq!(after, f.ids[7]);
    verifier.activate_observed(after, CLOCK).unwrap();
    let transaction = hash(b"tx-id", &[&f.packets[0].transactions[0]]);
    let confirmed = verifier.confirmation(transaction, f.ids[1], CLOCK).unwrap();
    assert!(confirmed.confirmed);
    assert_eq!(confirmed.depth, Some(6));
    assert!(!confirmed.finalized && !confirmed.execution_authority);
    let replayed = verifier.read_active().unwrap();
    assert_eq!(replayed.0, before.0);
    assert_eq!(replayed.2, before.2);
    assert_eq!(f.owner.lock().unwrap().read_active().unwrap(), before);
}

#[test]
fn public_history_batch_sixteen_packet_cap_keeps_exact_cursor_tip_and_v2_singleton() {
    let f = chain(17, 0);
    let first: Page =
        serde_json::from_value(dispatch(&f.owner, f.ids[17], f.ids[0]).unwrap()).unwrap();
    assert_eq!(packet_ids(&first), f.ids[1..=16]);
    assert_eq!(first.next, hex::encode(f.ids[16]));
    assert!(!first.complete);
    let last: Page =
        serde_json::from_value(dispatch(&f.owner, f.ids[17], f.ids[16]).unwrap()).unwrap();
    assert_eq!(packet_ids(&last), vec![f.ids[17]]);
    assert_eq!(last.after, first.next);
    assert_eq!(last.next, hex::encode(f.ids[17]));
    assert!(last.complete);
    let empty: Page =
        serde_json::from_value(dispatch(&f.owner, f.ids[17], f.ids[17]).unwrap()).unwrap();
    assert!(empty.packets.is_empty() && empty.complete);
    assert_eq!(empty.next, empty.after);

    let owner = f.owner.lock().unwrap();
    let original = owner
        .public_history_packet(f.ids[17], f.ids[0], MAX_HISTORY_STEPS, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].id().unwrap(), f.ids[1]);
    drop(owner);
    // A caller's anchor cannot select another retained branch, a later block,
    // or an unknown tip. A fixed earlier tip cannot include newer stored rows.
    assert!(dispatch(&f.owner, f.ids[7], f.ids[8]).is_err());
    assert!(dispatch(&f.owner, [255; 32], f.ids[0]).is_err());
    let earlier: Page =
        serde_json::from_value(dispatch(&f.owner, f.ids[7], f.ids[0]).unwrap()).unwrap();
    assert_eq!(packet_ids(&earlier), f.ids[1..=7]);
    assert!(earlier.complete);
}

#[test]
fn public_history_batch_total_bytes_bound_real_bodies_and_the_signed_response() {
    let f = chain(12, 256);
    let first_length = f.packets[0].encode().unwrap().len();
    let maximum = MAX_PAGE_HEX_BYTES / 2;
    let expected_count = maximum / first_length;
    assert!((2..12).contains(&expected_count));
    let value = dispatch(&f.owner, f.ids[12], f.ids[0]).unwrap();
    let page: Page = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(page.packets.len(), expected_count);
    assert_eq!(packet_ids(&page), f.ids[1..=expected_count]);
    assert_eq!(page.next, hex::encode(f.ids[expected_count]));
    assert!(!page.complete);
    let used = page.packets.iter().map(String::len).sum::<usize>();
    assert!(used <= MAX_PAGE_HEX_BYTES);
    assert!(used + 2 * f.packets[expected_count].encode().unwrap().len() > MAX_PAGE_HEX_BYTES);
    assert!(serde_json::to_vec(&value).unwrap().len() <= crate::ingress::MAX_FRAME);
    let remaining: Page =
        serde_json::from_value(dispatch(&f.owner, f.ids[12], f.ids[expected_count]).unwrap())
            .unwrap();
    assert_eq!(packet_ids(&remaining), f.ids[expected_count + 1..]);
    assert!(remaining.complete);

    let identity = |byte| DevelopmentIdentity::from_secret_hex(&hex::encode([byte; 32])).unwrap();
    let server = public_v3::PublicServer::new(
        identity(71),
        public_v3::PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let cookie = server
        .cookie(
            &f.settings,
            public_v3::Hello {
                op: 3,
                len: 1,
                caller: digest(identity(72).public_key()).unwrap(),
                digest: [3; 32],
                client_nonce: [4; 32],
            },
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap();
    let wire = public_v3::response(&server, &f.settings, &cookie, Ok(value), &|| Ok(())).unwrap();
    assert!(wire.len() <= public_v3::MAX_RESPONSE + 4);
}

#[test]
fn public_history_batch_byte_boundary_returns_one_without_skipping_a_valid_candidate() {
    let f = chain(3, 1);
    let length = f.packets[0].encode().unwrap().len();
    let minimum = HEADER_BYTES + 2 + trnm_crypto_primitives::pon_work::PROOF_BYTES;
    let maximum = length + minimum;
    assert!(maximum < 2 * length);
    let owner = f.owner.lock().unwrap();
    let read = |after| {
        owner
            .public_history_page(f.ids[3], after, MAX_HISTORY_STEPS, maximum, &mut |_| Ok(()))
            .unwrap()
    };
    let first = read(f.ids[0]);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id().unwrap(), f.ids[1]);
    let next = read(f.ids[1]);
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].id().unwrap(), f.ids[2]);
    let last = read(f.ids[2]);
    assert_eq!(last.len(), 1);
    assert_eq!(last[0].id().unwrap(), f.ids[3]);
    assert_eq!(
        owner
            .public_history_page(
                f.ids[3],
                f.ids[0],
                MAX_HISTORY_STEPS,
                length - 1,
                &mut |_| Ok(())
            )
            .unwrap_err()
            .to_string(),
        "PUBLIC_HISTORY_BYTES"
    );
}

#[test]
fn public_history_batch_second_and_last_damage_refuse_the_entire_page() {
    let f = chain(7, 1);
    let before = f.owner.lock().unwrap().read_active().unwrap();
    let foreign = Connection::open(f.directory.path().join("native.sqlite")).unwrap();
    for index in [1, 6] {
        let original = f.packets[index].encode().unwrap();
        let mut damaged = original.clone();
        damaged[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&257_u16.to_le_bytes());
        foreign
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![damaged, f.ids[index + 1].as_slice()],
            )
            .unwrap();
        let error = dispatch(&f.owner, f.ids[7], f.ids[0]).unwrap_err();
        assert_eq!(error.to_string(), "TRANSACTION_LIMIT");
        assert!(error.requires_owner_stop());
        if index == 1 {
            // This second body would not fit the selected page. Its original
            // decoder still runs; byte pressure cannot conceal actual damage.
            let maximum = f.packets[0].encode().unwrap().len()
                + HEADER_BYTES
                + 2
                + trnm_crypto_primitives::pon_work::PROOF_BYTES;
            let error = f
                .owner
                .lock()
                .unwrap()
                .public_history_page(f.ids[7], f.ids[0], MAX_HISTORY_STEPS, maximum, &mut |_| {
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.to_string(), "TRANSACTION_LIMIT");
            assert!(error.requires_owner_stop());
        }
        foreign
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![original, f.ids[index + 1].as_slice()],
            )
            .unwrap();
    }
    // The second oversized BLOB is rejected from its scalar shape; it cannot
    // become a successful one-packet prefix or an unbounded materialization.
    foreign
        .execute(
            "UPDATE blocks SET packet=zeroblob(?) WHERE id=?",
            params![MAX_PACKET + 1, f.ids[2].as_slice()],
        )
        .unwrap();
    let error = dispatch(&f.owner, f.ids[7], f.ids[0]).unwrap_err();
    assert_eq!(error.to_string(), "ANCESTRY_INDEX_PACKET_BYTES");
    assert!(error.requires_owner_stop());
    foreign
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![f.packets[1].encode().unwrap(), f.ids[2].as_slice()],
        )
        .unwrap();
    assert_eq!(f.owner.lock().unwrap().read_active().unwrap(), before);
    let restored: Page =
        serde_json::from_value(dispatch(&f.owner, f.ids[7], f.ids[0]).unwrap()).unwrap();
    assert_eq!(restored.packets.len(), 7);
    assert!(restored.complete);
}

#[test]
fn public_history_batch_cumulative_sql_boundary_and_later_cancellation_publish_no_partial_error() {
    let f = chain(7, 0);
    let owner = f.owner.lock().unwrap();
    let mut single_steps = Vec::new();
    owner
        .public_history_packet(f.ids[7], f.ids[0], MAX_HISTORY_STEPS, &mut |step| {
            single_steps.push(step);
            Ok(())
        })
        .unwrap();
    let first_cost = *single_steps.last().unwrap();
    let mut steps = Vec::new();
    let page = owner
        .public_history_page(
            f.ids[7],
            f.ids[0],
            first_cost,
            MAX_PAGE_HEX_BYTES / 2,
            &mut |step| {
                steps.push(step);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id().unwrap(), f.ids[1]);
    assert_eq!(steps, single_steps);
    let mut last_step = 0;
    let error = owner
        .public_history_page(
            f.ids[7],
            f.ids[0],
            MAX_HISTORY_STEPS,
            MAX_PAGE_HEX_BYTES / 2,
            &mut |step| {
                assert!(step >= last_step);
                last_step = step;
                if step > first_cost {
                    Err("PUBLIC_REQUEST_CANCELLED".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
    assert!(!error.requires_owner_stop());
    let error = owner
        .public_history_page(f.ids[7], f.ids[0], 3, MAX_PAGE_HEX_BYTES / 2, &mut |_| {
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "ANCESTRY_INDEX_BUDGET");
    assert!(!error.requires_owner_stop());
}
