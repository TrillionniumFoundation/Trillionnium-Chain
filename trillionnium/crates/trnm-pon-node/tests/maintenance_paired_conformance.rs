//! Exact public genesis maintenance with an independent complete producer.
//! This checks native admission, not demand, work hardness or a mining scheduler.
use trnm_crypto_primitives::pon_work::{self, paired_product::PairedPreparedTask};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Settings};

#[test]
fn paired_genesis_maintenance_preserves_actual_parent_admission_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let (model, input, a, b) = settings.consensus_maintenance_material().unwrap();
    for i in 0..pon_work::CELLS {
        assert_eq!(a[i], ((13 * i + 17) % 257) as u32);
        assert_eq!(b[i], ((29 * i + 31) % 263) as u32);
    }
    let task = pon_work::task_id(&a, &b).unwrap();
    assert_eq!(task, continuity_v1::maintenance_task().unwrap());
    assert_eq!(
        hex::encode(task),
        "c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496"
    );
    let paired = PairedPreparedTask::new(&a, &b).unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let mut challenges = Vec::new();
    for height in 1..=3 {
        let mut packet = node
            .make_consensus_maintenance(
                node.active().unwrap().0,
                vec![],
                development_public(0).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        assert_eq!(packet.header.work_task, task);
        let challenge = packet.header.challenge();
        assert!(!challenges.contains(&challenge));
        challenges.push(challenge);
        let proof = paired.prove(challenge).unwrap();
        assert_eq!(proof, packet.proof);
        assert_eq!(proof, pon_work::prove(challenge, &a, &b).unwrap());
        let ordinary = pon_work::verify(challenge, task, packet.header.target, &proof).unwrap();
        let reference =
            pon_work::verify_reference(challenge, task, packet.header.target, &proof).unwrap();
        assert_eq!(ordinary.ticket(), reference.ticket());
        packet.proof = proof;
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate(id).unwrap();
        let before = node.read_active().unwrap();
        assert_eq!(
            before.2[continuity_v1::MAINTENANCE_KEY]["useful_output_credit"],
            0
        );
        // Reopen at every different actual parent while the mathematical cache
        // lives outside Node. It grants no admission and stores no prior trace.
        drop(node);
        node = Node::open(dir.path(), settings.clone(), 1).unwrap();
        assert_eq!(node.read_active().unwrap(), before);
    }
    assert_eq!(
        paired.prove(challenges[0]).unwrap(),
        pon_work::prove(challenges[0], &a, &b).unwrap()
    );
    let before = node.read_active().unwrap();
    let mut changed_model = model;
    changed_model[0] ^= 1;
    assert!(node
        .make_with_registered_material(
            before.0,
            vec![],
            development_public(0).unwrap(),
            41,
            4096,
            &changed_model,
            &input,
        )
        .is_err());
    assert_eq!(node.read_active().unwrap(), before);

    let legacy_dir = tempfile::tempdir().unwrap();
    let legacy_settings = Settings::development(Some(1)).unwrap();
    assert_eq!(
        legacy_settings
            .consensus_maintenance_material()
            .unwrap_err()
            .to_string(),
        "CONTINUITY_PROFILE"
    );
    let legacy = Node::open(legacy_dir.path(), legacy_settings, 1).unwrap();
    assert!(legacy
        .make_consensus_maintenance(
            legacy.active().unwrap().0,
            vec![],
            development_public(0).unwrap(),
            11,
            4096,
        )
        .is_err());
}
