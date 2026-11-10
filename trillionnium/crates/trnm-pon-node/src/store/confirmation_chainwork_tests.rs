//! Retained-storage and callback-race controls using actually admitted W1 blocks.
//! Local row corruption is not a remote valid-work forgery or a finality proof.
use super::*;
use crate::ErrorKind;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

fn open(path: &Path, settings: Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings, 1).unwrap()
    } else {
        Node::open(path, settings, 1).unwrap()
    }
}

fn fixture(authenticated: bool) -> (tempfile::TempDir, Node, Vec<Hash>, Hash) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), settings.clone(), authenticated);
    let sender = development_public(0).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender,
        nonce: node.next_nonce(sender).unwrap(),
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let transaction = envelope.encode().unwrap();
    let transaction_id = hash(b"tx-id", &[&transaction]);
    let mut ids = vec![settings.genesis()];
    for height in 1..=8 {
        let transactions = if height == 1 {
            vec![transaction.clone()]
        } else {
            vec![]
        };
        let packet = node
            .make(
                *ids.last().unwrap(),
                transactions,
                sender,
                1 + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, 1000).unwrap();
        node.activate_observed(id, 1000).unwrap();
        ids.push(id);
    }
    let observed = node.confirmation(transaction_id, ids[1], 1000).unwrap();
    assert!(observed.confirmed);
    assert_eq!(observed.depth, Some(7));
    assert!(!observed.finalized && !observed.execution_authority);
    (directory, node, ids, transaction_id)
}

fn increment(work: Work) -> Work {
    let mut one = [0_u8; 64];
    one[63] = 1;
    work.checked_add(Work::from_bytes(one)).unwrap()
}

fn put_work(db: &Connection, id: Hash, work: Work) {
    assert_eq!(
        db.execute(
            "UPDATE blocks SET chainwork=? WHERE id=?",
            params![work.bytes().as_slice(), id.as_slice()],
        )
        .unwrap(),
        1
    );
}

fn assert_local(error: Error, expected_code: &str) {
    assert_eq!(error.to_string(), expected_code);
    assert_eq!(error.kind(), ErrorKind::LocalStructure);
    assert!(error.requires_owner_stop());
}

#[test]
fn full_width_retained_work_corruption_refuses_tip_inclusion_and_middle() {
    for authenticated in [false, true] {
        let (_directory, node, ids, transaction) = fixture(authenticated);
        let original = node.confirmation(transaction, ids[1], 1000).unwrap();
        let active = node.active().unwrap();
        for height in [8, 1, 4] {
            let work = node.record(ids[height]).unwrap().work;
            put_work(&node.db, ids[height], increment(work));
            // AuthenticatedV1 already checks the active tip/parent edge before
            // this ancestry walk. Preserve that exact earlier refusal contract.
            let expected_code = if authenticated && height == 8 {
                "NATIVE_STATE_PARENT"
            } else {
                "STORAGE_PACKET"
            };
            let error = node
                .confirmation(transaction, ids[1], 1000)
                .expect_err(&format!("authenticated={authenticated}, height={height}"));
            assert_local(error, expected_code);
            assert_eq!(node.active().unwrap(), active);
            assert_eq!(node.record(ids[height]).unwrap().work, increment(work));
            put_work(&node.db, ids[height], work);
            let repaired = node.confirmation(transaction, ids[1], 1000).unwrap();
            assert_eq!(
                serde_json::to_value(&repaired).unwrap(),
                serde_json::to_value(&original).unwrap()
            );
        }
    }
}

#[test]
fn a_common_work_offset_cannot_replace_the_zero_work_genesis_anchor() {
    for authenticated in [false, true] {
        let (_directory, node, ids, transaction) = fixture(authenticated);
        let original: Vec<_> = ids
            .iter()
            .map(|id| node.record(*id).unwrap().work)
            .collect();
        for (id, work) in ids.iter().zip(&original) {
            put_work(&node.db, *id, increment(*work));
        }
        // Every child-parent difference still matches the target. Only a full
        // walk anchored to the exact zero-work genesis detects this damage.
        assert_local(
            node.confirmation(transaction, ids[1], 1000).unwrap_err(),
            "STORAGE_PACKET",
        );
        for (id, work) in ids.iter().zip(original) {
            put_work(&node.db, *id, work);
        }
        assert!(
            node.confirmation(transaction, ids[1], 1000)
                .unwrap()
                .confirmed
        );
    }
}

fn callback_write_refuses(foreign: bool) {
    for authenticated in [false, true] {
        let (directory, node, ids, transaction) = fixture(authenticated);
        let writer = Connection::open(directory.path().join("native.sqlite")).unwrap();
        let original = node.record(ids[8]).unwrap().work;
        let mut changed = false;
        let error = node
            .confirmations_with_progress(&[(transaction, ids[1])], 1000, &mut |checked| {
                if checked == 8 && !changed {
                    put_work(
                        if foreign { &writer } else { &node.db },
                        ids[8],
                        increment(original),
                    );
                    changed = true;
                }
                Ok(())
            })
            .unwrap_err();
        assert!(changed);
        assert_eq!(error.to_string(), "STALE_VIEW");
        assert!(!error.requires_owner_stop());
        assert_eq!(node.record(ids[8]).unwrap().work, increment(original));
        put_work(&writer, ids[8], original);
        assert!(
            node.confirmation(transaction, ids[1], 1000)
                .unwrap()
                .confirmed
        );
        let settings = node.settings().clone();
        drop(writer);
        drop(node);
        let reopened = open(directory.path(), settings, authenticated);
        assert!(
            reopened
                .confirmation(transaction, ids[1], 1000)
                .unwrap()
                .confirmed
        );
    }
}

#[test]
fn final_callback_same_connection_write_cannot_return_a_stale_confirmation() {
    callback_write_refuses(false);
}

#[test]
fn final_callback_foreign_commit_cannot_return_a_stale_confirmation() {
    callback_write_refuses(true);
}
