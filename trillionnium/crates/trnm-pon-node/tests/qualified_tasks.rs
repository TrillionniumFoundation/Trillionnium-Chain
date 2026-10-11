//! Actual registration, branch eligibility and single-output accounting in a fresh dev context.
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{verify_development_admission, DevelopmentTaskAdmission, TaskMaterial},
};
use trnm_mvcc_fee::pon_executor::{self, Config, SIGNED_TASK_PROFILE};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{SignedQualifiedWorkTask, TaskPurpose},
};

const CLOCK: u64 = 1_800_010_000;
const POLICY: &str = "legacy-first-two-v3";
struct Artifacts {
    model: Vec<u8>,
    input: Vec<u8>,
    a: Vec<u32>,
    b: Vec<u32>,
}
impl Artifacts {
    fn dense() -> Self {
        let a: Vec<_> = (0..pon_work::CELLS)
            .map(|i| ((i * 11 + 3) % 97) as u32)
            .collect();
        let b: Vec<_> = (0..pon_work::CELLS)
            .map(|i| ((i * 17 + 7) % 101) as u32)
            .collect();
        Self {
            model: a.iter().flat_map(|v| v.to_le_bytes()).collect(),
            input: b.iter().flat_map(|v| v.to_le_bytes()).collect(),
            a,
            b,
        }
    }
    fn bootstrap(settings: &Settings) -> Self {
        let (model, input, a, b) = settings.bootstrap_task_material().unwrap();
        Self { model, input, a, b }
    }
    fn material(&self) -> TaskMaterial<'_> {
        TaskMaterial {
            model: &self.model,
            input: &self.input,
            a: &self.a,
            b: &self.b,
        }
    }
}
fn settings() -> Settings {
    Settings::development_with_profiles(None, POLICY, SIGNED_TASK_PROFILE).unwrap()
}
fn admission(
    settings: &Settings,
    signed: &SignedQualifiedWorkTask,
    artifacts: &Artifacts,
    height: u64,
) -> DevelopmentTaskAdmission {
    let ctx = settings
        .qualified_task_context(signed.manifest.demand_id, height)
        .unwrap();
    verify_development_admission(&signed.encode().unwrap(), artifacts.material(), &ctx).unwrap()
}
fn transaction(settings: &Settings, tag: u8, payload: Vec<u8>, nonce: u64, sender: u64) -> Vec<u8> {
    let mut envelope = Envelope {
        network: settings.network(),
        sender: development_public(sender).unwrap(),
        nonce,
        expiry: 1000,
        fee_limit: 10_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let seed = hash(b"DEV-ONLY-KEY", &[&sender.to_le_bytes()]);
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed)).unwrap();
    envelope.signature = hex::decode(trnm_crypto_primitives::sign_hex(
        &key,
        &envelope.signing_digest().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    envelope.encode().unwrap()
}
fn make(
    node: &Node,
    parent: Hash,
    transactions: Vec<Vec<u8>>,
    signed: &SignedQualifiedWorkTask,
    artifacts: &Artifacts,
    miner: u64,
) -> Packet {
    let height = node.parent_height(parent).unwrap() + 1;
    let permit = admission(node.settings(), signed, artifacts, height);
    node.make_with_task(
        parent,
        transactions,
        development_public(miner).unwrap(),
        node.settings().genesis_time() + height * 10,
        4096,
        &permit,
        artifacts.material(),
    )
    .unwrap()
}
fn activate(node: &mut Node, packet: &Packet) -> Hash {
    let id = node.admit(packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    id
}

#[test]
fn validator_rejects_signed_false_recipe_even_with_manually_constructed_valid_work_and_state() {
    for mismatch in ["control", "model", "input"] {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path(), settings(), 2).unwrap();
        let genesis = node.settings().genesis();
        let bootstrap = node.settings().bootstrap_task_statement().unwrap();
        let base = Artifacts::bootstrap(node.settings());
        let artifacts = Artifacts::dense();
        let mut statement = node
            .settings()
            .development_task_manifest(
                1,
                TaskPurpose::InferenceContraction,
                &artifacts.model,
                &artifacts.input,
                1,
                100,
                2,
            )
            .unwrap();
        if mismatch == "model" {
            let mut unrelated = artifacts.model.clone();
            unrelated[0] ^= 1;
            statement.manifest.model = hash(b"artifact", &[&unrelated]);
            statement.manifest.layer =
                trnm_protocol::qualified_work_task::QualifiedWorkTask::layer_id(
                    statement.manifest.model,
                );
        } else if mismatch == "input" {
            let mut unrelated = artifacts.input.clone();
            unrelated[0] ^= 1;
            statement.manifest.input = hash(b"qualified-task-input-v1", &[&unrelated]);
        }
        statement.manifest.output_meter = statement.manifest.derived_output_meter();
        let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(hash(
            b"DEV-ONLY-KEY",
            &[&0_u64.to_le_bytes()],
        )))
        .unwrap();
        statement.signature = hex::decode(trnm_crypto_primitives::sign_hex(
            &key,
            &SignedQualifiedWorkTask::signing_message(&statement.manifest).unwrap(),
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let registration = make(
            &node,
            genesis,
            vec![transaction(
                node.settings(),
                13,
                statement.encode().unwrap(),
                1,
                0,
            )],
            &bootstrap,
            &base,
            0,
        );
        let parent = activate(&mut node, &registration);
        let before = node.stats().unwrap();
        // Bypass material admission and the qualified builder completely. The local
        // maintenance builder only supplies otherwise-valid header context; all work,
        // arithmetic-meter state and roots below are manually constructed by an attacker.
        let mut packet = make(&node, parent, vec![], &bootstrap, &base, 0);
        packet.header.work_task = statement.manifest.matrix_task;
        let prepared = pon_work::PreparedTask::new(&artifacts.a, &artifacts.b).unwrap();
        let mut output = pon_executor::execute(
            &node.state_at(parent).unwrap(),
            &[],
            2,
            packet.header.miner,
            parent,
            2,
            &Config::installed_with_profiles(POLICY, SIGNED_TASK_PROFILE).unwrap(),
        )
        .unwrap();
        output.state.insert(format!("work-output:{}",hex::encode(statement.manifest.output_meter)),
            serde_json::json!({"product":hex::encode(hash(b"qualified-task-product-v1", &[prepared.product_bytes()])),
                "arithmetic_output_count":1,"matrix_task":hex::encode(statement.manifest.matrix_task),
                "scope":"source-attested-fixed-contraction-not-model-value"}));
        packet.header.state = pon_executor::root(&output.state).unwrap();
        let proof = (0..4096)
            .find_map(|nonce| {
                packet.header.nonce = nonce;
                let proof = prepared.prove(packet.header.challenge()).unwrap();
                (hash(
                    b"ticket",
                    &[&packet.header.challenge(), &proof[proof.len() - 32..]],
                ) <= packet.header.target)
                    .then_some(proof)
            })
            .unwrap();
        packet.proof = proof;
        // A complete correct transcript and product for the committed TaskId is
        // insufficient if its raw A/B contradict the source's signed model/input.
        pon_work::verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .unwrap();
        if mismatch == "control" {
            let id = activate(&mut node, &packet);
            assert_eq!(node.state_at(id).unwrap(), output.state);
            let mut bad_magic = packet.clone();
            bad_magic.proof[0] ^= 1;
            // A new identity avoids the exact-duplicate path, while preserving A/B.
            bad_magic.header.nonce += 1;
            assert_eq!(
                node.admit(&bad_magic, CLOCK).unwrap_err().to_string(),
                "TASK_PROOF_MATERIAL"
            );
        } else {
            let expected = if mismatch == "model" {
                "TASK_MODEL_BINDING"
            } else {
                "TASK_INPUT_BINDING"
            };
            assert_eq!(
                node.admit(&packet, CLOCK).unwrap_err().to_string(),
                expected
            );
            let mut invalid_transcript = packet.clone();
            invalid_transcript.proof[40_000] ^= 1;
            assert_eq!(
                node.admit(&invalid_transcript, CLOCK)
                    .unwrap_err()
                    .to_string(),
                expected
            );
            assert_eq!(node.stats().unwrap(), before);
            assert_eq!(node.read_active().unwrap().0, parent);
        }
    }
}

#[test]
fn registered_task_mines_real_work_and_counts_one_output_across_fresh_challenges() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = Node::open(temp.path(), settings(), 2).unwrap();
    let genesis = node.settings().genesis();
    let bootstrap = node.settings().bootstrap_task_statement().unwrap();
    let bootstrap_artifacts = Artifacts::bootstrap(node.settings());
    let artifacts = Artifacts::dense();
    let signed = node
        .settings()
        .development_task_manifest(
            1,
            TaskPurpose::InferenceContraction,
            &artifacts.model,
            &artifacts.input,
            1,
            100,
            2,
        )
        .unwrap();
    let permit = admission(node.settings(), &signed, &artifacts, 1);
    assert_eq!(
        node.make_with_task(
            genesis,
            vec![],
            development_public(0).unwrap(),
            node.settings().genesis_time() + 10,
            4096,
            &permit,
            artifacts.material()
        )
        .unwrap_err()
        .to_string(),
        "TASK"
    );
    assert_eq!(
        node.make(
            genesis,
            vec![],
            development_public(0).unwrap(),
            node.settings().genesis_time() + 10,
            4096
        )
        .unwrap_err()
        .to_string(),
        "EXPLICIT_TASK_REQUIRED"
    );
    let register = transaction(node.settings(), 13, signed.encode().unwrap(), 1, 0);
    let block = make(
        &node,
        genesis,
        vec![register.clone()],
        &bootstrap,
        &bootstrap_artifacts,
        0,
    );
    let parent = activate(&mut node, &block);
    let state = node.state_at(parent).unwrap();
    let record = &state[&format!("work:{}", hex::encode(signed.manifest.matrix_task))];
    assert_eq!(record["manifest"], hex::encode(signed.encode().unwrap()));
    assert!(state.keys().all(|k| !k.starts_with("work-output:")));
    let block = make(&node, parent, vec![], &signed, &artifacts, 0);
    let parent = activate(&mut node, &block);
    let key = format!("work-output:{}", hex::encode(signed.manifest.output_meter));
    let first = node.state_at(parent).unwrap()[&key].clone();
    assert_eq!(first["arithmetic_output_count"], 1);
    let next = make(&node, parent, vec![], &signed, &artifacts, 0);
    assert_ne!(next.header.challenge(), block.header.challenge());
    let parent = activate(&mut node, &next);
    assert_eq!(node.state_at(parent).unwrap()[&key], first);
    assert_eq!(node.admit(&next, CLOCK).unwrap(), parent);
    let before = node.stats().unwrap();
    let replay = transaction(node.settings(), 13, signed.encode().unwrap(), 2, 0);
    let error = node
        .make_with_task(
            parent,
            vec![replay],
            development_public(0).unwrap(),
            node.settings().genesis_time() + 40,
            4096,
            &admission(node.settings(), &bootstrap, &bootstrap_artifacts, 4),
            bootstrap_artifacts.material(),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("TASK_SOURCE_NONCE"), "{error}");
    assert_eq!(node.stats().unwrap(), before);
    drop(node);
    let node = Node::open(temp.path(), settings(), 2).unwrap();
    assert_eq!(node.state_at(parent).unwrap()[&key], first);
    drop(node);
    assert!(Node::open(temp.path(), Settings::development(None).unwrap(), 2).is_err());
}

#[test]
fn source_nonce_demand_withdrawal_and_historical_profile_are_checked_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let node = Node::open(temp.path(), settings(), 2).unwrap();
    let artifacts = Artifacts::dense();
    let signed = node
        .settings()
        .development_task_manifest(
            1,
            TaskPurpose::InferenceContraction,
            &artifacts.model,
            &artifacts.input,
            1,
            100,
            2,
        )
        .unwrap();
    let parent = node.state_at(node.settings().genesis()).unwrap();
    let cfg = Config::installed_with_profiles(POLICY, SIGNED_TASK_PROFILE).unwrap();
    let run = |state: &pon_executor::State, tx: Vec<u8>| {
        pon_executor::execute(
            state,
            &[tx],
            1,
            development_public(0).unwrap(),
            node.settings().genesis(),
            2,
            &cfg,
        )
    };
    let wrong = transaction(node.settings(), 13, signed.encode().unwrap(), 1, 1);
    assert!(run(&parent, wrong).unwrap_err().contains("TASK_SOURCE"));
    let mut unsigned = signed.clone();
    unsigned.signature = [0; 64];
    assert!(run(
        &parent,
        transaction(node.settings(), 13, unsigned.encode().unwrap(), 1, 0)
    )
    .unwrap_err()
    .contains("TASK_STATEMENT"));
    let register = transaction(node.settings(), 13, signed.encode().unwrap(), 1, 0);
    let mut revoked = parent.clone();
    revoked.insert(
        format!("work-withdrawal:{}", hex::encode(signed.manifest.source)),
        serde_json::json!(hex::encode([7; 32])),
    );
    assert!(run(&revoked, register.clone())
        .unwrap_err()
        .contains("TASK_WITHDRAWAL"));
    let mut wrong_nonce = signed.clone();
    wrong_nonce.manifest.demand_nonce = 3;
    let seed = hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]);
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed)).unwrap();
    wrong_nonce.signature = hex::decode(trnm_crypto_primitives::sign_hex(
        &key,
        &SignedQualifiedWorkTask::signing_message(&wrong_nonce.manifest).unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    assert!(run(
        &parent,
        transaction(node.settings(), 13, wrong_nonce.encode().unwrap(), 1, 0)
    )
    .unwrap_err()
    .contains("TASK_SOURCE_NONCE"));
    let mut absent = parent.clone();
    absent.remove(&format!(
        "work-demand-registry:{}",
        hex::encode(signed.manifest.demand_id)
    ));
    assert!(run(&absent, register.clone())
        .unwrap_err()
        .contains("TASK_DEMAND"));
    assert!(run(
        &parent,
        transaction(
            node.settings(),
            12,
            signed.manifest.matrix_task.to_vec(),
            1,
            0
        )
    )
    .unwrap_err()
    .contains("WORK_TASK_PROFILE"));
    let legacy = Settings::development(None).unwrap();
    let register = transaction(&legacy, 13, signed.encode().unwrap(), 1, 0);
    let legacy_node = Node::open(&temp.path().join("legacy"), legacy, 1).unwrap();
    let legacy_parent = legacy_node
        .state_at(legacy_node.settings().genesis())
        .unwrap();
    assert!(pon_executor::execute(
        &legacy_parent,
        &[register],
        1,
        development_public(0).unwrap(),
        legacy_node.settings().genesis(),
        1,
        &Config::installed().unwrap()
    )
    .unwrap_err()
    .contains("WORK_TASK_PROFILE"));
    assert_eq!(node.state_at(node.settings().genesis()).unwrap(), parent);
}

#[test]
fn expiry_precedes_expensive_proof_and_a_heavier_branch_removes_registration_and_meter() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = Node::open(temp.path(), settings(), 2).unwrap();
    let genesis = node.settings().genesis();
    let bootstrap = node.settings().bootstrap_task_statement().unwrap();
    let base = Artifacts::bootstrap(node.settings());
    let artifacts = Artifacts::dense();
    let signed = node
        .settings()
        .development_task_manifest(
            1,
            TaskPurpose::InferenceContraction,
            &artifacts.model,
            &artifacts.input,
            1,
            2,
            2,
        )
        .unwrap();
    let tx = transaction(node.settings(), 13, signed.encode().unwrap(), 1, 0);
    let registration = make(&node, genesis, vec![tx.clone()], &bootstrap, &base, 0);
    let registration_id = activate(&mut node, &registration);
    let work = make(&node, registration_id, vec![], &signed, &artifacts, 0);
    let work_id = activate(&mut node, &work);
    let mut expired = make(&node, work_id, vec![], &bootstrap, &base, 0);
    expired.header.work_task = signed.manifest.matrix_task;
    expired.proof.fill(0);
    let error = node.admit(&expired, CLOCK).unwrap_err().to_string();
    assert!(error.starts_with("TASK_STATEMENT:Height"), "{error}");
    let mut fork = genesis;
    for _ in 0..3 {
        let block = make(&node, fork, vec![], &bootstrap, &base, 1);
        fork = node.admit(&block, CLOCK).unwrap();
    }
    node.activate(fork).unwrap();
    let state = node.read_active().unwrap().2;
    assert!(!state.contains_key(&format!(
        "work:{}",
        hex::encode(signed.manifest.matrix_task)
    )));
    assert!(!state.contains_key(&format!(
        "work-output:{}",
        hex::encode(signed.manifest.output_meter)
    )));
    assert_eq!(
        state[&format!("work-source:{}", hex::encode(signed.manifest.source))],
        1
    );
    let fresh = node
        .settings()
        .development_task_manifest(
            1,
            TaskPurpose::InferenceContraction,
            &artifacts.model,
            &artifacts.input,
            1,
            100,
            2,
        )
        .unwrap();
    let tx = transaction(node.settings(), 13, fresh.encode().unwrap(), 1, 0);
    let block = make(&node, fork, vec![tx], &bootstrap, &base, 1);
    let tip = activate(&mut node, &block);
    assert!(node
        .state_at(tip)
        .unwrap()
        .contains_key(&format!("work:{}", hex::encode(fresh.manifest.matrix_task))));
}
