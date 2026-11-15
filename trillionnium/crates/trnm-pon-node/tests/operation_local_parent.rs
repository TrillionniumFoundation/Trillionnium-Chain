//! Exact native packets and error precedence across operation-local parent reuse.
use rusqlite::{params, Connection};
use trnm_crypto_primitives::qualified_work_task::{
    derive_matrices, lifecycle_v2::verify_lifecycle_admission, verify_development_admission,
    TaskMaterial,
};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    qualified_work_task::lifecycle_v4::PROFILE,
};

fn packet_fingerprint(name: &str, packet: &Packet) {
    println!(
        "OPERATION_PARENT_PARITY {name} {} {} {}",
        hex::encode(hash(
            b"operation-parent-parity",
            &[&packet.encode().unwrap()]
        )),
        hex::encode(packet.header.state),
        hex::encode(packet.header.receipts),
    );
}

fn explicit(node: &Node, parent: Hash, model: &[u8], input: &[u8]) -> Packet {
    let settings = node.settings();
    let height = node.parent_height(parent).unwrap() + 1;
    let (a, b) = derive_matrices(model, input).unwrap();
    let material = || TaskMaterial {
        model,
        input,
        a: &a,
        b: &b,
    };
    let admission = if settings.task_profile() == PROFILE {
        let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
        verify_lifecycle_admission(
            &bootstrap.signed.encode().unwrap(),
            material(),
            &bootstrap.lease,
            height,
        )
        .unwrap()
    } else {
        let signed = settings.bootstrap_task_statement().unwrap();
        let context = settings
            .qualified_task_context(signed.manifest.demand_id, height)
            .unwrap();
        verify_development_admission(&signed.encode().unwrap(), material(), &context).unwrap()
    };
    node.make_with_task(
        parent,
        vec![],
        development_public(3).unwrap(),
        settings.genesis_time() + height * 10,
        4096,
        &admission,
        material(),
    )
    .unwrap()
}

#[test]
fn registered_and_explicit_packets_match_active_inactive_parent_and_reopen() {
    for profile in ["signed-task-dev-v1", PROFILE] {
        let temp = tempfile::tempdir().unwrap();
        let s =
            Settings::development_with_profiles(None, "native-public-evaluation-dev-v1", profile)
                .unwrap();
        let (model, input, _, _) = s.bootstrap_task_material().unwrap();
        let mut node = Node::open(temp.path(), s.clone(), 4).unwrap();
        let mut parent = s.genesis();
        for height in 1..=3 {
            let expected = explicit(&node, parent, &model, &input);
            let actual = node
                .make_with_registered_material(
                    parent,
                    vec![],
                    development_public(3).unwrap(),
                    s.genesis_time() + height * 10,
                    4096,
                    &model,
                    &input,
                )
                .unwrap();
            assert_eq!(actual.encode().unwrap(), expected.encode().unwrap());
            packet_fingerprint(&format!("{profile}-{height}"), &actual);
            let id = node.admit(&actual, s.genesis_time() + 10_000).unwrap();
            node.activate(id).unwrap();
            parent = id;
        }
        let fork = node
            .make_with_registered_material(
                s.genesis(),
                vec![],
                development_public(2).unwrap(),
                s.genesis_time() + 11,
                4096,
                &model,
                &input,
            )
            .unwrap();
        node.admit(&fork, s.genesis_time() + 10_000).unwrap();
        let branch = node
            .make_with_registered_material(
                fork.id().unwrap(),
                vec![],
                development_public(3).unwrap(),
                s.genesis_time() + 20,
                4096,
                &model,
                &input,
            )
            .unwrap();
        assert_eq!(
            branch.encode().unwrap(),
            explicit(&node, fork.id().unwrap(), &model, &input)
                .encode()
                .unwrap()
        );
        packet_fingerprint(&format!("{profile}-inactive"), &branch);
        let before = node.read_active().unwrap();
        drop(node);
        let node = Node::open(temp.path(), s.clone(), 1).unwrap();
        assert_eq!(before, node.read_active().unwrap());
        let after = node
            .make_with_registered_material(
                parent,
                vec![],
                development_public(3).unwrap(),
                s.genesis_time() + 40,
                4096,
                &model,
                &input,
            )
            .unwrap();
        assert_eq!(
            after.encode().unwrap(),
            explicit(&node, parent, &model, &input).encode().unwrap()
        );
        packet_fingerprint(&format!("{profile}-reopen"), &after);
    }
}

#[test]
fn every_new_operation_rereads_actual_kv_and_preserves_material_error_order() {
    let temp = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, "native-public-evaluation-dev-v1", PROFILE)
        .unwrap();
    let node = Node::open(temp.path(), s.clone(), 1).unwrap();
    let (model, input, a, b) = s.bootstrap_task_material().unwrap();
    let bootstrap = s.bootstrap_lifecycle_task().unwrap();
    let material = || TaskMaterial {
        model: &model,
        input: &input,
        a: &a,
        b: &b,
    };
    let admission = verify_lifecycle_admission(
        &bootstrap.signed.encode().unwrap(),
        material(),
        &bootstrap.lease,
        1,
    )
    .unwrap();
    let expected = explicit(&node, s.genesis(), &model, &input);
    let db = Connection::open(temp.path().join("native.sqlite")).unwrap();
    let key = format!("account:{}", hex::encode(development_public(0).unwrap()));
    let (slot, raw): (u64, Vec<u8>) = db
        .query_row(
            "SELECT slot,value FROM kv WHERE key=? AND slot=(SELECT state_slot FROM active)",
            [&key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut noncanonical = b" ".to_vec();
    noncanonical.extend(&raw);
    db.execute(
        "UPDATE kv SET value=? WHERE slot=? AND key=?",
        params![noncanonical, slot, &key],
    )
    .unwrap();
    assert_eq!(
        node.make_with_registered_material(
            s.genesis(),
            vec![],
            development_public(3).unwrap(),
            s.genesis_time() + 10,
            4096,
            &model,
            &input,
        )
        .unwrap_err()
        .to_string(),
        "STATE_BYTES"
    );
    assert_eq!(
        node.make_with_task(
            s.genesis(),
            vec![],
            development_public(3).unwrap(),
            s.genesis_time() + 10,
            0,
            &admission,
            TaskMaterial {
                model: &[],
                ..material()
            },
        )
        .unwrap_err()
        .to_string(),
        "STATE_BYTES"
    );
    db.execute(
        "UPDATE kv SET value=? WHERE slot=? AND key=?",
        params![raw, slot, &key],
    )
    .unwrap();
    assert_eq!(
        node.make_with_task(
            s.genesis(),
            vec![],
            development_public(3).unwrap(),
            s.genesis_time() + 10,
            0,
            &admission,
            TaskMaterial {
                model: &[],
                ..material()
            },
        )
        .unwrap_err()
        .to_string(),
        "TASK_MATERIAL"
    );
    assert_eq!(
        node.make_with_task(
            s.genesis(),
            vec![],
            development_public(3).unwrap(),
            s.genesis_time() + 10,
            0,
            &admission,
            material(),
        )
        .unwrap_err()
        .to_string(),
        "WORK_BUDGET"
    );
    assert_eq!(
        node.make_with_registered_material(
            [123; 32],
            vec![],
            development_public(3).unwrap(),
            s.genesis_time() + 10,
            0,
            &[],
            &input,
        )
        .unwrap_err()
        .to_string(),
        "TASK_MATERIAL:MaterialLength"
    );
    let restored = explicit(&node, s.genesis(), &model, &input);
    assert_eq!(restored.encode().unwrap(), expected.encode().unwrap());
    packet_fingerprint("restored-after-independent-actual-KV-read", &restored);
}
