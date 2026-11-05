//! Revocation and reward-maturity continuity through actual signed admission,
//! authenticated storage, interrupted reorganization and cold recovery.
//! This installed-genesis fixture is separate from the 65,536-key capacity test.
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, qualified_task_lifecycle};
use trnm_pon_node::{development_public, Error, ErrorCode, Node, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::lifecycle_v2::DemandRevocationV2,
};

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
}
fn signed(settings: &Settings, owner: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(owner),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&owner.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn admit_pair(
    reference: &mut Node,
    native: &mut Node,
    parent: Hash,
    height: u64,
    txs: Vec<Vec<u8>>,
    miner: Hash,
    timestamp_offset: u64,
) -> Hash {
    let packet = reference
        .make_consensus_maintenance(parent, txs, miner, 1 + height * 10 + timestamp_offset, 4096)
        .unwrap();
    assert_eq!(
        packet.header.work_task,
        continuity_v1::maintenance_task().unwrap()
    );
    let id = reference.admit(&packet, 100_000).unwrap();
    assert_eq!(native.admit(&packet, 100_000).unwrap(), id);
    assert_eq!(
        reference.state_at(id).unwrap(),
        native.state_at(id).unwrap()
    );
    id
}

#[test]
fn revoked_optional_work_keeps_maintenance_maturity_and_interrupted_native_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut reference = Node::open(&dir.path().join("reference"), settings.clone(), 1).unwrap();
    let path = dir.path().join("authenticated");
    let mut native = Node::open_with_authenticated_state(&path, settings.clone(), 2).unwrap();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let revoked_task = bootstrap.signed.manifest.matrix_task;
    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: 0,
        demand_id: bootstrap.lease.demand_id,
        requester: bootstrap.lease.requester,
        expected_revision: bootstrap.lease.revision,
    };
    let tx = signed(&settings, 1, 1, 20, revoke.encode().unwrap());
    let mut parent = settings.genesis();
    let recipient_key = format!("account:{}", hex::encode(public(999)));
    assert!(!native.read_active().unwrap().2.contains_key(&recipient_key));
    for height in 1..=21 {
        let txs = if height == 1 {
            vec![tx.clone()]
        } else {
            vec![]
        };
        let miner = public(if height == 1 { 999 } else { 0 });
        let id = admit_pair(&mut reference, &mut native, parent, height, txs, miner, 0);
        reference.activate(id).unwrap();
        native.activate(id).unwrap();
        assert_eq!(
            native.read_active().unwrap(),
            reference.read_active().unwrap()
        );
        assert_eq!(
            native
                .lifecycle_task_lease(id, revoked_task, height + 1)
                .unwrap_err()
                .to_string(),
            "TASK"
        );
        let state = native.read_active().unwrap().2;
        assert_eq!(
            state[continuity_v1::MAINTENANCE_KEY]["useful_output_credit"],
            0
        );
        let slot = &state[&qualified_task_lifecycle::slot_key(0).unwrap()];
        assert_eq!(slot["status"], "revoked");
        assert_eq!(slot["output_count"], 0);
        if height < 21 {
            assert!(!state.contains_key(&recipient_key));
        }
        parent = id;
        if height == 2 {
            let before = native.read_active().unwrap();
            drop(native);
            native = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
            assert_eq!(native.read_active().unwrap(), before);
        }
    }
    let mature = native.read_active().unwrap();
    let reward = mature.2[&recipient_key]["balance"].as_u64().unwrap();
    assert!(reward > 1_000);
    assert_eq!(mature.2[&recipient_key]["nonce"], 0);
    let mut payload = public(1000).to_vec();
    payload.extend(1u64.to_le_bytes());
    let spend = signed(&settings, 999, 1, 1, payload);
    let main22 = admit_pair(
        &mut reference,
        &mut native,
        parent,
        22,
        vec![spend],
        public(0),
        0,
    );
    reference.activate(main22).unwrap();
    native.activate(main22).unwrap();
    let spent = native.read_active().unwrap();
    assert_eq!(spent.2[&recipient_key]["nonce"], 1);
    assert_eq!(
        spent.2[&format!("account:{}", hex::encode(public(1000)))]["balance"],
        1
    );
    // Read cancellation is not a structural failure and cannot mutate the view.
    let error = native
        .capacity_observation_with_progress(&mut || {
            Err(Error::new(ErrorCode::PublicRequestCancelled))
        })
        .unwrap_err();
    assert!(error.is(ErrorCode::PublicRequestCancelled));
    assert!(!error.requires_owner_stop());
    assert_eq!(native.read_active().unwrap(), spent);
    let fork22 = admit_pair(
        &mut reference,
        &mut native,
        parent,
        22,
        vec![],
        public(0),
        1,
    );
    assert_eq!(native.activate(fork22).unwrap(), main22);
    let fork23 = admit_pair(
        &mut reference,
        &mut native,
        fork22,
        23,
        vec![],
        public(0),
        0,
    );
    let mut cuts = 0;
    let error = native
        .activate_with_fault(
            fork23,
            Some(&mut |point| {
                if point == "detach:0" {
                    cuts += 1;
                    Err(Error::from("CONTINUITY_NATIVE_REORG_CUT"))
                } else {
                    Ok(())
                }
            }),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "CONTINUITY_NATIVE_REORG_CUT");
    assert_eq!(cuts, 1);
    assert_eq!(native.read_active().unwrap(), spent);
    drop(native);
    native = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
    reference.activate(fork23).unwrap();
    assert_eq!(
        native.read_active().unwrap(),
        reference.read_active().unwrap()
    );
    let recovered = native.read_active().unwrap();
    assert_eq!(recovered.0, fork23);
    assert_eq!(recovered.2[&recipient_key]["nonce"], 0);
    assert_eq!(recovered.2[&recipient_key]["balance"], reward);
    assert!(!recovered
        .2
        .contains_key(&format!("account:{}", hex::encode(public(1000)))));
    assert_eq!(native.state_at(main22).unwrap(), spent.2);
    assert_eq!(
        native
            .lifecycle_task_lease(fork23, revoked_task, 24)
            .unwrap_err()
            .to_string(),
        "TASK"
    );
    drop(native);
    let native = Node::open_with_authenticated_state(&path, settings, 1).unwrap();
    assert_eq!(native.read_active().unwrap(), recovered);
    eprintln!("native continuity: admitted_packets=24, signed_transactions=2, all_optional_tasks_revoked=true, maturity_height=21, reorg_cut=detach:0, cold_reopens=3, useful_output_credit=0, full_capacity=false");
}
