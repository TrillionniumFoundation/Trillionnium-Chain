//! Actual V4 overlap windows retain all source, parent and native execution authority.
use trnm_crypto_primitives::{
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::qualified_task_lifecycle::slot_key;
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2},
        lifecycle_v4::{AtomicRenewTaskV4 as AtomicRenewTaskV3, ATOMIC_RENEW_TAG, PROFILE},
        TaskPurpose,
    },
};
const POLICY: &str = "native-public-evaluation-dev-v1";
const CLOCK: u64 = 1_800_010_000;
fn signature(who: u64, message: &[u8]) -> [u8; 64] {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    hex::decode(sign_hex(&key, message))
        .unwrap()
        .try_into()
        .unwrap()
}
fn transaction(s: &Settings, who: u64, sequence: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: s.network(),
        sender: development_public(who).unwrap(),
        nonce: sequence,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(who, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}
fn statement(
    s: &Settings,
    current: &DemandLeaseV2,
    model: &[u8],
    input: &[u8],
    sequence: u64,
) -> SignedLifecycleTaskV2 {
    let mut manifest = s.bootstrap_lifecycle_task().unwrap().signed.manifest;
    let (a, b) = derive_matrices(model, input).unwrap();
    manifest.purpose = current.purpose;
    manifest.source = current.source;
    manifest.demand_id = current.demand_id;
    manifest.source_record = current.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[model]);
    manifest.layer =
        trnm_protocol::qualified_work_task::QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[input]);
    manifest.matrix_task = trnm_crypto_primitives::pon_work::task_id(&a, &b).unwrap();
    manifest.availability_manifest = current.availability_manifest;
    manifest.availability_root = current.availability_root;
    manifest.authorization_scope = current.authorization_scope;
    manifest.withdrawal_head = current.withdrawal_frontier().unwrap();
    manifest.demand_nonce = sequence;
    manifest.not_before = current.not_before;
    manifest.expires = current.expires;
    manifest.available_until = current.available_until;
    manifest.useful_output_limit = current.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: current.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    signed.signature = signature(0, &signed.signing_message().unwrap());
    signed
}
fn make(
    node: &Node,
    parent: Hash,
    transactions: Vec<Vec<u8>>,
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    model: &[u8],
    input: &[u8],
) -> Packet {
    let (a, b) = derive_matrices(model, input).unwrap();
    let height = node.parent_height(parent).unwrap() + 1;
    let admission = verify_lifecycle_admission(
        &signed.encode().unwrap(),
        TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        },
        lease,
        height,
    )
    .unwrap();
    node.make_with_task(
        parent,
        transactions,
        development_public(3).unwrap(),
        1_800_000_000 + height * 10,
        4096,
        &admission,
        TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        },
    )
    .unwrap()
}
fn admit(node: &mut Node, packet: &Packet) -> Hash {
    let id = node.admit(packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    id
}
#[test]
fn delayed_atomic_renew_preserves_used_output_meter_and_revoke_reorg_state() {
    let temp = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (bm, bi, _, _) = s.bootstrap_task_material().unwrap();
    let model: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let mut lease = boot.lease.clone();
    lease.slot = 1;
    lease.generation = 2;
    lease.purpose = TaskPurpose::InferenceContraction;
    lease.requester = development_public(2).unwrap();
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    lease.demand_id = lease.derived_demand_id();
    let signed = statement(&s, &lease, &model, &input, 1);
    let mut node = Node::open(temp.path(), s.clone(), 4).unwrap();
    let genesis = s.genesis();
    let txs = vec![
        transaction(&s, 2, 1, 18, lease.encode().unwrap()),
        transaction(&s, 0, 1, 21, signed.encode().unwrap()),
    ];
    let registration = make(&node, genesis, txs, &boot.signed, &boot.lease, &bm, &bi);
    let base = admit(&mut node, &registration);
    let use_first = make(&node, base, vec![], &signed, &lease, &model, &input);
    let used = admit(&mut node, &use_first);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["output_count"],
        1
    );
    let mut successor = lease.clone();
    successor.revision += 1;
    successor.not_before = 2;
    successor.expires = 1002;
    successor.available_until = 1102;
    let resigned = statement(&s, &successor, &model, &input, 2);
    assert_eq!(resigned.manifest.output_meter, signed.manifest.output_meter);
    let renew = make(
        &node,
        used,
        vec![transaction(
            &s,
            2,
            2,
            ATOMIC_RENEW_TAG,
            AtomicRenewTaskV3 {
                lease: successor.clone(),
                signed: resigned.clone(),
            }
            .encode()
            .unwrap(),
        )],
        &signed,
        &lease,
        &model,
        &input,
    );
    let renewed = admit(&mut node, &renew);
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let old = verify_lifecycle_admission(
        &signed.encode().unwrap(),
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &lease,
        4,
    )
    .unwrap();
    assert!(node
        .make_with_task(
            renewed,
            vec![],
            development_public(3).unwrap(),
            1_800_000_040,
            4096,
            &old,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b
            }
        )
        .is_err());
    drop(node);
    let mut node = Node::open(temp.path(), s.clone(), 1).unwrap();
    let use_again = make(
        &node,
        renewed,
        vec![],
        &resigned,
        &successor,
        &model,
        &input,
    );
    let live = admit(&mut node, &use_again);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["output_count"],
        1
    );
    let revocation = DemandRevocationV2 {
        slot: 1,
        network: s.network(),
        parameters: s.parameters(),
        demand_id: lease.demand_id,
        requester: lease.requester,
        expected_revision: 2,
    };
    let revoked_packet = make(
        &node,
        live,
        vec![transaction(&s, 2, 3, 20, revocation.encode().unwrap())],
        &resigned,
        &successor,
        &model,
        &input,
    );
    let revoked = admit(&mut node, &revoked_packet);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["status"],
        "revoked"
    );
    assert!(node
        .lifecycle_task_lease(revoked, resigned.manifest.matrix_task, 6)
        .is_err());
    let mut fork = live;
    for _ in 5..=7 {
        let packet = make(&node, fork, vec![], &resigned, &successor, &model, &input);
        fork = node.admit(&packet, CLOCK).unwrap();
    }
    node.activate(fork).unwrap();
    let value = node.read_active().unwrap().2[&slot_key(1).unwrap()].clone();
    assert_eq!(value["status"], "active");
    assert_eq!(value["output_count"], 1);
    drop(node);
    assert_eq!(
        Node::open(temp.path(), s, 2)
            .unwrap()
            .read_active()
            .unwrap()
            .2[&slot_key(1).unwrap()],
        value
    );
}

#[test]
fn identical_signed_successor_can_be_contained_at_different_real_native_heights() {
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let mut lease = boot.lease.clone();
    lease.revision = 2;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    let signed = statement(&s, &lease, &m, &i, 2);
    let raw = transaction(
        &s,
        1,
        1,
        22,
        AtomicRenewTaskV3 {
            lease: lease.clone(),
            signed: signed.clone(),
        }
        .encode()
        .unwrap(),
    );
    for containing in [1, 2, 4] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), s.clone(), 2).unwrap();
        let mut parent = s.genesis();
        for _ in 1..containing {
            let packet = make(&node, parent, vec![], &boot.signed, &boot.lease, &m, &i);
            parent = admit(&mut node, &packet);
        }
        let packet = make(
            &node,
            parent,
            vec![raw.clone()],
            &boot.signed,
            &boot.lease,
            &m,
            &i,
        );
        assert_eq!(packet.header.height, containing);
        parent = admit(&mut node, &packet);
        let record = node.read_active().unwrap().2[&slot_key(0).unwrap()].clone();
        assert_eq!(record["renewed_height"], containing);
        assert_eq!(record["source_sequence"], 2);
        let after = make(&node, parent, vec![], &signed, &lease, &m, &i);
        admit(&mut node, &after);
        assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 2);
        assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
        drop(node);
        assert_eq!(
            Node::open(dir.path(), s.clone(), 1)
                .unwrap()
                .read_active()
                .unwrap()
                .2[&slot_key(0).unwrap()],
            record
        );
    }
}

#[test]
fn overlap_profile_is_fresh_and_refuses_v3_source_raw_store_standalone19_and_future_window() {
    let v3 =
        Settings::development_with_profiles(None, POLICY, "signed-task-lifecycle-dev-v3").unwrap();
    let v4 = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    assert_ne!(v3.network(), v4.network());
    assert_ne!(v3.parameters(), v4.parameters());
    assert_ne!(v3.genesis(), v4.genesis());
    let directory = tempfile::tempdir().unwrap();
    drop(Node::open(directory.path(), v3.clone(), 1).unwrap());
    assert!(Node::open(directory.path(), v4.clone(), 1).is_err());
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path(), v4.clone(), 1).unwrap();
    let boot = v4.bootstrap_lifecycle_task().unwrap();
    let (m, i, a, b) = v4.bootstrap_task_material().unwrap();
    let before = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    let mut next = boot.lease.clone();
    next.revision = 2;
    next.not_before = 2;
    next.expires = 1002;
    next.available_until = 1102;
    let good = statement(&v4, &next, &m, &i, 2);
    let old = v3.bootstrap_lifecycle_task().unwrap();
    let mut oldlease = old.lease.clone();
    oldlease.revision = 2;
    oldlease.not_before = 1;
    oldlease.expires = 1001;
    oldlease.available_until = 1101;
    let oldsigned = statement(&v3, &oldlease, &m, &i, 2);
    let oldraw = transaction(
        &v3,
        1,
        1,
        22,
        AtomicRenewTaskV3 {
            lease: oldlease,
            signed: oldsigned,
        }
        .encode()
        .unwrap(),
    );
    let future = AtomicRenewTaskV3 {
        lease: next.clone(),
        signed: good.clone(),
    };
    let mut valid_lease = next.clone();
    valid_lease.not_before = 1;
    valid_lease.expires = 1001;
    valid_lease.available_until = 1101;
    let valid = AtomicRenewTaskV3 {
        lease: valid_lease.clone(),
        signed: statement(&v4, &valid_lease, &m, &i, 2),
    };
    let mut badsig = valid.clone();
    badsig.signed.signature[0] ^= 1;
    let mut badseq = valid;
    badseq.signed = statement(&v4, &valid_lease, &m, &i, 3);
    let admission = verify_lifecycle_admission(
        &boot.signed.encode().unwrap(),
        TaskMaterial {
            model: &m,
            input: &i,
            a: &a,
            b: &b,
        },
        &boot.lease,
        1,
    )
    .unwrap();
    for raw in [
        oldraw,
        transaction(&v4, 1, 1, 19, next.encode().unwrap()),
        transaction(&v4, 1, 1, 22, future.encode().unwrap()),
        transaction(&v4, 1, 1, 22, badsig.encode().unwrap()),
        transaction(&v4, 1, 1, 22, badseq.encode().unwrap()),
    ] {
        assert!(node
            .make_with_task(
                v4.genesis(),
                vec![raw],
                development_public(3).unwrap(),
                1800000010,
                4096,
                &admission,
                TaskMaterial {
                    model: &m,
                    input: &i,
                    a: &a,
                    b: &b
                }
            )
            .is_err());
        assert_eq!(node.read_active().unwrap(), before);
        assert_eq!(node.stats().unwrap(), stats);
    }
}

#[test]
#[ignore = "explicit release-only 1001-height logical continuity receipt campaign"]
fn actual_900_preview_905_delayed_inclusion_999_reorg_preserves_certificate_and_local_prune() {
    use serde_json::json;
    use std::{fs, time::Instant};
    use trnm_pon_node::PoolLimits;
    let started = Instant::now();
    let path =
        std::env::var("TRNM_V4_OVERLAP_RECEIPTS").expect("explicit fresh receipt path required");
    let directory = std::path::PathBuf::from(path);
    assert!(!directory.exists(), "never overwrite evidence");
    fs::create_dir_all(directory.join("packets")).unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let mut lease = boot.lease.clone();
    lease.revision = 2;
    lease.not_before = 900;
    lease.expires = 1900;
    lease.available_until = 2000;
    let signed = statement(&s, &lease, &m, &i, 2);
    let raw = transaction(
        &s,
        1,
        1,
        22,
        AtomicRenewTaskV3 {
            lease: lease.clone(),
            signed: signed.clone(),
        }
        .encode()
        .unwrap(),
    );
    fs::write(directory.join("renewal.pnx1"), &raw).unwrap();
    fs::write(directory.join("successor.qwa2"), signed.encode().unwrap()).unwrap();
    fs::write(directory.join("successor.qdl2"), lease.encode().unwrap()).unwrap();
    let mut node = Node::open(&directory.join("store"), s.clone(), 4).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 8,
        max_bytes: 16384,
        max_group_members: 2,
        critical_reserve: 1,
        max_removals: 8,
        preview_miner: development_public(3).unwrap(),
    })
    .unwrap();
    let mut packets = 0_u64;
    let mut save = |packet: &Packet| {
        packets += 1;
        let bytes = packet.encode().unwrap();
        fs::write(
            directory.join("packets").join(format!(
                "{:04}-{}.pn",
                packets,
                hex::encode(hash(b"v4-overlap-receipt", &[&bytes]))
            )),
            bytes,
        )
        .unwrap();
    };
    let mut parent = s.genesis();
    let mut ancestor = parent;
    for height in 1..=899 {
        let packet = make(&node, parent, vec![], &boot.signed, &boot.lease, &m, &i);
        assert_eq!(packet.header.height, height);
        save(&packet);
        parent = admit(&mut node, &packet);
        if height == 899 {
            ancestor = parent;
        }
    }
    let receipt = node.pool_submit(raw.clone()).unwrap();
    let (head, generation) = node.active().unwrap();
    let batch900 = node.pool_mining_batch(head, generation, 8, 16384).unwrap();
    assert_eq!(batch900.transactions, vec![raw.clone()]);
    assert_eq!(node.pool_validate_batch(&batch900).unwrap(), 1);
    // Same preserved certificate has a real side branch at its earliest signed height.
    let at900 = make(
        &node,
        ancestor,
        vec![raw.clone()],
        &boot.signed,
        &boot.lease,
        &m,
        &i,
    );
    save(&at900);
    let branch900 = node.admit(&at900, CLOCK).unwrap();
    let at901 = make(&node, branch900, vec![], &signed, &lease, &m, &i);
    save(&at901);
    node.admit(&at901, CLOCK).unwrap();
    // Active old-authority branch delays the actual queued raw through five blocks.
    for height in 900..=904 {
        let packet = make(&node, parent, vec![], &boot.signed, &boot.lease, &m, &i);
        assert_eq!(packet.header.height, height);
        save(&packet);
        parent = admit(&mut node, &packet);
    }
    assert!(!node.pool_batch_is_current(&batch900).unwrap());
    let (head, generation) = node.active().unwrap();
    let batch905 = node.pool_mining_batch(head, generation, 8, 16384).unwrap();
    assert_eq!(batch905.transactions, vec![raw.clone()]);
    assert_eq!(node.pool_validate_batch(&batch905).unwrap(), 1);
    let at905 = make(
        &node,
        parent,
        batch905.transactions,
        &boot.signed,
        &boot.lease,
        &m,
        &i,
    );
    save(&at905);
    parent = admit(&mut node, &at905);
    let at906 = make(&node, parent, vec![], &signed, &lease, &m, &i);
    save(&at906);
    admit(&mut node, &at906);
    let renewed = node.read_active().unwrap().2[&slot_key(0).unwrap()].clone();
    assert_eq!(renewed["renewed_height"], 905);
    assert_eq!(renewed["source_sequence"], 2);
    assert_eq!(renewed["output_count"], 0);
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 2);
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    node.pool_prune_terminal(hex::decode(&receipt.group).unwrap().try_into().unwrap())
        .unwrap();
    assert_eq!(node.pool_status_snapshot().unwrap().local_removals, 1);
    drop(node);
    let mut node = Node::open(&directory.join("store"), s.clone(), 2).unwrap();
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(0).unwrap()],
        renewed
    );
    assert!(node.pool_submit(raw.clone()).is_err());
    // A genuinely heavier branch restores old lease/source/main nonce, but not local removal.
    let mut fork = ancestor;
    for height in 900..=998 {
        let packet = make(&node, fork, vec![], &boot.signed, &boot.lease, &m, &i);
        assert_eq!(packet.header.height, height);
        save(&packet);
        fork = node.admit(&packet, CLOCK).unwrap();
        if height == 907 {
            node.activate(fork).unwrap();
            let old = node.read_active().unwrap().2[&slot_key(0).unwrap()].clone();
            assert_eq!(old["source_sequence"], 1);
            assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 1);
            assert_eq!(node.pool_status_snapshot().unwrap().local_removals, 1);
            assert!(node.pool_submit(raw.clone()).is_err());
        }
    }
    // Local operator prune never changes consensus authority of another producer's block.
    let at999 = make(
        &node,
        fork,
        vec![raw.clone()],
        &boot.signed,
        &boot.lease,
        &m,
        &i,
    );
    save(&at999);
    parent = admit(&mut node, &at999);
    for height in 1000..=1001 {
        let packet = make(&node, parent, vec![], &signed, &lease, &m, &i);
        assert_eq!(packet.header.height, height);
        save(&packet);
        parent = admit(&mut node, &packet);
    }
    let final_record = node.read_active().unwrap().2[&slot_key(0).unwrap()].clone();
    assert_eq!(final_record["renewed_height"], 999);
    assert_eq!(final_record["source_sequence"], 2);
    assert_eq!(final_record["output_count"], 0);
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 2);
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    assert_eq!(node.pool_status_snapshot().unwrap().local_removals, 1);
    assert!(node.pool_submit(raw).is_err());
    drop(node);
    let node = Node::open(&directory.join("store"), s.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, parent);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(0).unwrap()],
        final_record
    );
    let status = node.pool_status_snapshot().unwrap();
    assert_eq!(status.local_removals, 1);
    let report = json!({"schema":"task-lifecycle-v4-overlap-native-receipts-v1",
        "profile":PROFILE,"evaluation_policy":POLICY,"network":hex::encode(s.network()),
        "parameters":hex::encode(s.parameters()),"genesis":hex::encode(s.genesis()),
        "packet_count":packets,"final_height":1001,"final_tip":hex::encode(parent),
        "same_raw_valid_containing_heights":[900,905,999],"queued_preview_next_height":900,
        "queued_included_height":905,"requester_next_nonce":2,"source_main_next_nonce":1,
        "source_sequence":2,"output_count":0,"reopens":2,"local_removals":1,
        "pool":status,"elapsed_ns":started.elapsed().as_nanos(),"logical_spacing_seconds":10,
        "clock":CLOCK,"wall_continuity_qualified":false,"independent_requester":false,
        "public_network_qualified":false,"hardness_qualified":false,"useful_value_qualified":false,
        "scope":"actual native proofs and transitions; dev keys; frozen verifier clock and synthetic chain timestamps; local operator tombstone survives reorg and does not revoke consensus validity"});
    fs::write(
        directory.join("summary.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());
}

#[test]
fn independent_go_q4_double_signed_vector_matches_original_native_codecs() {
    // Fixed Go-generated, signed development keys and SHA-256 byte domains.
    // This is NOT parent-State, source consent, Node::admit or final use.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/q4_reference_go/q4-reference-development-vector.json"
    ))
    .unwrap();
    let decode = |key: &str| hex::decode(fixture[key].as_str().unwrap()).unwrap();
    let network: Hash = decode("network").try_into().unwrap();
    let parameters: Hash = decode("parameters").try_into().unwrap();
    let raw = decode("signed_transaction");
    let previous = DemandLeaseV2::decode(&decode("old_lease")).unwrap();
    let old_source = decode("old_source_statement");
    let height = fixture["containing_height"].as_u64().unwrap();
    let envelope = Envelope::decode(&raw).unwrap();
    assert_eq!(envelope.encode().unwrap(), raw);
    assert_eq!(envelope.tag, 22);
    assert_eq!(envelope.network, network);
    assert_eq!(envelope.sender, previous.requester);
    assert_eq!(previous.network, network);
    assert_eq!(previous.parameters, parameters);
    let successor =
        trnm_protocol::qualified_work_task::lifecycle_v4::AtomicRenewTaskV4::decode(
            &envelope.payload,
        )
        .unwrap();
    assert_eq!(successor.lease.network, network);
    assert_eq!(successor.lease.parameters, parameters);
    assert_eq!(successor.lease.requester, previous.requester);
    assert_eq!(successor.lease.source, previous.source);
    assert_eq!(successor.lease.revision, previous.revision + 1);
    assert!(previous.not_before <= successor.lease.not_before);
    assert!(successor.lease.not_before <= height && height <= previous.expires);
    assert!(successor.lease.expires > previous.expires);

    // Neither a digest nor an encoded struct is signature-verified authority.
    // Invoke the EXISTING strict native Ed25519 implementation on both owners.
    let digest = envelope.signing_digest().unwrap();
    trnm_crypto_primitives::verify_hex_strict(
        &hex::encode(previous.requester),
        &digest,
        &hex::encode(envelope.signature),
    )
    .unwrap();
    let former = trnm_crypto_primitives::qualified_work_task::lifecycle_v2::
        verify_lifecycle_statement(&old_source, &previous, height)
        .unwrap();
    let next_source = successor.signed.encode().unwrap();
    let future = trnm_crypto_primitives::qualified_work_task::lifecycle_v2::
        verify_lifecycle_statement(&next_source, &successor.lease, height)
        .unwrap();
    assert_eq!(former.manifest().model, future.manifest().model);
    assert_eq!(former.manifest().input, future.manifest().input);
    assert_eq!(former.manifest().matrix_task, future.manifest().matrix_task);
    assert_eq!(former.manifest().output_meter, future.manifest().output_meter);
    assert_eq!(future.manifest().demand_nonce, former.manifest().demand_nonce + 1);

    assert_eq!(
        hex::encode(envelope.id().unwrap()),
        "133e6e6588018bdb8cc5888cd35e9daa5202fdcaa1e458951b3ecb3dd2ee3233"
    );
    assert_eq!(
        hex::encode(successor.lease.id().unwrap()),
        "bbb982203bb12668be298fcae53ec89f1600098da691133d7a068d931af2f880"
    );
    assert_eq!(
        hex::encode(successor.signed.id().unwrap()),
        "6566c9ed51e887d5f0e3ac0cb32bb95141f71ae873ffc1c2456b2b50607991b0"
    );

    let mut tampered_requester = raw.clone();
    tampered_requester[1123] ^= 1;
    let bad_requester = Envelope::decode(&tampered_requester).unwrap();
    assert!(trnm_crypto_primitives::verify_hex_strict(
        &hex::encode(previous.requester),
        &bad_requester.signing_digest().unwrap(),
        &hex::encode(bad_requester.signature),
    )
    .is_err());
    let mut tampered_source = next_source;
    tampered_source[620] ^= 1;
    assert!(
        trnm_crypto_primitives::qualified_work_task::lifecycle_v2::
            verify_lifecycle_statement(&tampered_source, &successor.lease, height)
            .is_err()
    );
}
