use super::*;
use crate::{development_public, digest, Packet, Settings};
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::{hash, Envelope};

fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
}
fn open(path: &Path, authenticated: bool) -> Result<Node> {
    if authenticated {
        Node::open_with_authenticated_state(path, settings(), 1)
    } else {
        Node::open(path, settings(), 1)
    }
}
fn signed(node: &Node, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: node.settings.network(),
        sender: public(who),
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn packet(node: &Node, parent: Hash, txs: Vec<Vec<u8>>, miner: u64) -> Packet {
    let height = node.parent_height(parent).unwrap() + 1;
    node.make_consensus_maintenance(parent, txs, public(miner), 1 + height * 10, 4096)
        .unwrap()
}
fn mine(node: &mut Node, txs: Vec<Vec<u8>>) -> Hash {
    let packet = packet(node, node.active().unwrap().0, txs, 3);
    let id = node.admit(&packet, 100_000).unwrap();
    node.activate(id).unwrap();
    id
}
fn fund(node: &mut Node) -> (Hash, Hash) {
    let (network, parameters) = (node.settings.network(), node.settings.parameters());
    let quota = hash(
        b"quota-instance-v3",
        &[
            &network,
            &parameters,
            &public(0),
            &1u64.to_le_bytes(),
            &public(2),
            &public(1),
            &4u64.to_le_bytes(),
            &100u64.to_le_bytes(),
        ],
    );
    let mut quota_payload = [quota.as_slice(), public(2).as_slice(), public(1).as_slice()].concat();
    quota_payload.extend(4u64.to_le_bytes());
    quota_payload.extend(100u64.to_le_bytes());
    let task = hash(
        b"task-instance-v3",
        &[
            &network,
            &parameters,
            &public(0),
            &2u64.to_le_bytes(),
            &public(1),
            &1000u64.to_le_bytes(),
            &100u64.to_le_bytes(),
        ],
    );
    let mut task_payload = [task.as_slice(), public(1).as_slice()].concat();
    task_payload.extend(1000u64.to_le_bytes());
    task_payload.extend(100u64.to_le_bytes());
    let transactions = vec![
        signed(node, 0, 1, 10, quota_payload),
        signed(node, 0, 2, 2, task_payload),
    ];
    mine(node, transactions);
    (quota, task)
}
fn request(lane: NativeBudgetLaneV1, source: Hash, byte: u8) -> NativeBudgetRequestV1 {
    NativeBudgetRequestV1 {
        operation: [byte; 32],
        subject: [byte + 1; 32],
        beneficiary: public(1),
        lane,
        source,
        amount: 100,
        source_cap: 500,
        resource_cap: [100, 100],
        resource_reservation: [40, 50],
        contribution: None,
    }
}
fn error<T>(result: Result<T>, expected: &str) {
    assert_eq!(result.err().unwrap().to_string(), expected);
}

#[test]
fn exact_local_inventory_recovers_pending_and_receipted_intents_without_dispatch_authority() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node");
        let mut node = open(&path, authenticated).unwrap();
        assert!(node
            .native_budget_inventory_v1()
            .unwrap()
            .records
            .is_empty());
        assert_eq!(node.native_budget_operation_v1([99; 32]).unwrap(), None);
        let (quota, task) = fund(&mut node);
        let source_view = node.active().unwrap();
        let serving = request(NativeBudgetLaneV1::Serving, quota, 21);
        let evaluation = request(NativeBudgetLaneV1::Evaluation, task, 31);
        node.reserve_native_budget_v1(serving.clone()).unwrap();
        node.reserve_native_budget_v1(evaluation.clone()).unwrap();
        node.settle_native_budget_resources_v1(serving.operation, [20, 30])
            .unwrap();
        node.prepare_native_budget_effect_v1(serving.operation, [91; 32])
            .unwrap();
        let retained = node.native_budget_records_v1().unwrap();
        let state_before = node.read_active().unwrap();
        drop(node);
        let mut node = open(&path, authenticated).unwrap();
        let inventory = node.native_budget_inventory_v1().unwrap();
        assert_eq!(inventory.schema, "pon-native-budget-local-inventory-v1");
        assert_eq!(inventory.network, node.settings.network());
        assert_eq!(inventory.parameters, node.settings.parameters());
        assert_eq!(inventory.genesis, node.settings.genesis());
        assert!(
            !inventory.chain_funds_locked
                && !inventory.payment_executed
                && !inventory.execution_authority
                && !inventory.production_activation
        );
        assert_eq!(inventory.records.len(), 2);
        let pending = node
            .native_budget_operation_v1(serving.operation)
            .unwrap()
            .unwrap();
        assert_eq!(pending, inventory.records[0]);
        assert_eq!(pending.request, serving);
        assert_eq!(pending.source_tip, source_view.0);
        assert_eq!(pending.source_generation, source_view.1);
        assert_eq!(pending.source_height, 1);
        assert_eq!(
            pending.source_funding_digest,
            hash(
                b"native-budget-source-v1",
                &[&canonical(&state_before.2[&format!("quota:{}", hex::encode(quota))]).unwrap()],
            )
        );
        assert_eq!(pending.resources_consumed, Some([20, 30]));
        assert_eq!(pending.effect, Some([91; 32]));
        assert_eq!(pending.receipt, None);
        assert_eq!(inventory.records[1].request, evaluation);
        assert_eq!(inventory.records[1].resources_consumed, None);
        assert_eq!(inventory.records[1].effect, None);
        assert_eq!(inventory.records[1].receipt, None);
        assert_eq!(node.native_budget_records_v1().unwrap(), retained);
        assert_eq!(node.read_active().unwrap(), state_before);
        // A caller receives detached local data, never mutable store authority.
        let mut altered = inventory.clone();
        altered.records[0].request.beneficiary = [98; 32];
        altered.records[0].effect = Some([97; 32]);
        assert_eq!(node.native_budget_inventory_v1().unwrap(), inventory);
        // Resume with the exact recovered identity/effect; do not re-dispatch.
        node.finish_native_budget_effect_v1(
            pending.request.operation,
            pending.effect.unwrap(),
            [93; 32],
        )
        .unwrap();
        let mut fork = node.settings.genesis();
        for _ in 0..3 {
            let next = packet(&node, fork, vec![], 2);
            fork = node.admit(&next, 100_000).unwrap();
        }
        node.activate(fork).unwrap();
        drop(node);
        let node = open(&path, authenticated).unwrap();
        let completed = node
            .native_budget_operation_v1(serving.operation)
            .unwrap()
            .unwrap();
        let mut expected = pending;
        expected.receipt = Some([93; 32]);
        assert_eq!(completed, expected);
        assert_eq!(node.native_budget_operation_v1([99; 32]).unwrap(), None);
        assert_eq!(node.native_budget_inventory_v1().unwrap().records.len(), 2);
    }
}

#[test]
fn native_signed_funding_and_exact_operations_survive_both_backends_reopen() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node");
        let mut node = open(&path, authenticated).unwrap();
        let (quota, task) = fund(&mut node);
        let serving = request(NativeBudgetLaneV1::Serving, quota, 21);
        let evaluation = request(NativeBudgetLaneV1::Evaluation, task, 31);
        let state_before = node.read_active().unwrap();
        for req in [&serving, &evaluation] {
            let observation = node.reserve_native_budget_v1(req.clone()).unwrap();
            assert!(observation.funding_current);
            assert!(
                !observation.chain_funds_locked
                    && !observation.payment_executed
                    && !observation.execution_authority
                    && !observation.production_activation
            );
        }
        assert_eq!(node.read_active().unwrap(), state_before);
        assert_eq!(
            node.reserve_native_budget_v1(serving.clone())
                .unwrap()
                .durable_records,
            2
        );
        let mut cross_subject = serving.clone();
        cross_subject.subject = [61; 32];
        error(
            node.reserve_native_budget_v1(cross_subject),
            "BUDGET_OPERATION_REPLAY",
        );
        let mut cross_operation_lane = serving.clone();
        cross_operation_lane.lane = NativeBudgetLaneV1::Evaluation;
        cross_operation_lane.source = task;
        error(
            node.reserve_native_budget_v1(cross_operation_lane),
            "BUDGET_OPERATION_REPLAY",
        );
        let mut cross_operation_payee = serving.clone();
        cross_operation_payee.beneficiary = public(2);
        error(
            node.reserve_native_budget_v1(cross_operation_payee),
            "BUDGET_OPERATION_REPLAY",
        );
        let mut cross_lane = evaluation.clone();
        cross_lane.operation = [71; 32];
        cross_lane.subject = [72; 32];
        cross_lane.lane = NativeBudgetLaneV1::Storage;
        error(
            node.reserve_native_budget_v1(cross_lane),
            "BUDGET_SOURCE_REPLAY",
        );
        let mut wrong_payee = serving.clone();
        wrong_payee.operation = [81; 32];
        wrong_payee.beneficiary = public(2);
        error(node.reserve_native_budget_v1(wrong_payee), "BUDGET_PAYEE");
        node.settle_native_budget_resources_v1(serving.operation, [20, 30])
            .unwrap();
        error(
            node.settle_native_budget_resources_v1(serving.operation, [19, 30]),
            "BUDGET_RESOURCE_REPLAY",
        );
        node.prepare_native_budget_effect_v1(serving.operation, [91; 32])
            .unwrap();
        drop(node);
        let mut node = open(&path, authenticated).unwrap();
        let pending = node.reserve_native_budget_v1(serving.clone()).unwrap();
        assert_eq!(pending.resources_consumed, Some([20, 30]));
        assert!(pending.effect_pending);
        error(
            node.prepare_native_budget_effect_v1(serving.operation, [92; 32]),
            "BUDGET_EFFECT_REPLAY",
        );
        node.finish_native_budget_effect_v1(serving.operation, [91; 32], [93; 32])
            .unwrap();
        drop(node);
        let mut node = open(&path, authenticated).unwrap();
        assert!(
            node.reserve_native_budget_v1(serving.clone())
                .unwrap()
                .effect_completed
        );
        error(
            node.finish_native_budget_effect_v1(serving.operation, [91; 32], [94; 32]),
            "BUDGET_RECEIPT_REPLAY",
        );
    }
}

#[test]
fn fork_or_spent_source_denies_new_intent_but_preserves_resource_and_target_receipt() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node");
        let mut node = open(&path, authenticated).unwrap();
        let (quota, _) = fund(&mut node);
        let first = request(NativeBudgetLaneV1::Serving, quota, 21);
        node.reserve_native_budget_v1(first.clone()).unwrap();
        node.settle_native_budget_resources_v1(first.operation, [20, 30])
            .unwrap();
        node.prepare_native_budget_effect_v1(first.operation, [91; 32])
            .unwrap();
        let mut tip = node.settings.genesis();
        for _ in 0..3 {
            let next = packet(&node, tip, vec![], 2);
            tip = node.admit(&next, 100_000).unwrap();
        }
        node.activate(tip).unwrap();
        let orphaned = node.reserve_native_budget_v1(first.clone()).unwrap();
        assert!(!orphaned.funding_current && orphaned.effect_pending);
        assert_eq!(orphaned.resources_consumed, Some([20, 30]));
        error(
            node.reserve_native_budget_v1(request(NativeBudgetLaneV1::Serving, quota, 41)),
            "BUDGET_SOURCE_ABSENT",
        );
        let finished = node
            .finish_native_budget_effect_v1(first.operation, [91; 32], [93; 32])
            .unwrap();
        assert!(!finished.funding_current && finished.effect_completed);
        drop(node);
        let mut node = open(&path, authenticated).unwrap();
        assert!(
            node.reserve_native_budget_v1(first)
                .unwrap()
                .effect_completed
        );
    }
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(&directory.path().join("spent"), false).unwrap();
    let (quota, _) = fund(&mut node);
    let req = request(NativeBudgetLaneV1::Serving, quota, 21);
    node.reserve_native_budget_v1(req.clone()).unwrap();
    node.settle_native_budget_resources_v1(req.operation, [20, 30])
        .unwrap();
    let result = [75; 32];
    let digest = hash(
        b"use",
        &[
            &node.settings.network(),
            &node.settings.parameters(),
            &quota,
            &public(1),
            &1u64.to_le_bytes(),
            &1u64.to_le_bytes(),
            &result,
        ],
    );
    let consumer =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&2u64.to_le_bytes()]))).unwrap();
    let mut payload = quota.to_vec();
    payload.extend(1u64.to_le_bytes());
    payload.extend(result);
    payload.extend(hex::decode(sign_hex(&consumer, &digest)).unwrap());
    let use_quota = signed(&node, 1, 1, 11, payload);
    mine(&mut node, vec![use_quota]);
    assert!(
        !node
            .reserve_native_budget_v1(req.clone())
            .unwrap()
            .funding_current
    );
    error(
        node.prepare_native_budget_effect_v1(req.operation, [91; 32]),
        "BUDGET_FUNDING_NOT_CURRENT",
    );
    error(
        node.reserve_native_budget_v1(request(NativeBudgetLaneV1::Serving, quota, 41)),
        "BUDGET_SOURCE_REPLAY",
    );
}

#[test]
fn transaction_failure_leaves_no_partial_record_head_or_double_resource_charge() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(&directory.path().join("node"), false).unwrap();
    let (quota, _) = fund(&mut node);
    let req = request(NativeBudgetLaneV1::Serving, quota, 21);
    node.db.execute_batch("CREATE TEMP TRIGGER omit_head BEFORE INSERT ON metadata WHEN NEW.key='pon-native-budget-v1:head' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let failure = node.reserve_native_budget_v1(req.clone()).err().unwrap();
    assert_eq!(failure.to_string(), "BUDGET_WRITE");
    assert!(failure.requires_owner_stop());
    assert!(node.native_budget_records_v1().unwrap().is_empty());
    node.db.execute_batch("DROP TRIGGER omit_head;").unwrap();
    node.reserve_native_budget_v1(req.clone()).unwrap();
    node.db.execute_batch("CREATE TEMP TRIGGER omit_head BEFORE UPDATE ON metadata WHEN NEW.key='pon-native-budget-v1:head' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let failure = node
        .settle_native_budget_resources_v1(req.operation, [20, 30])
        .err()
        .unwrap();
    assert_eq!(failure.to_string(), "BUDGET_WRITE");
    assert!(failure.requires_owner_stop());
    assert_eq!(
        node.reserve_native_budget_v1(req.clone())
            .unwrap()
            .resources_consumed,
        None
    );
    node.db.execute_batch("DROP TRIGGER omit_head;").unwrap();
    node.settle_native_budget_resources_v1(req.operation, [20, 30])
        .unwrap();
    node.settle_native_budget_resources_v1(req.operation, [20, 30])
        .unwrap();
    assert_eq!(
        node.reserve_native_budget_v1(req).unwrap().durable_records,
        1
    );
}

#[test]
fn cold_open_refuses_deleted_oversized_and_forged_funding_records() {
    for corruption in [
        "deleted",
        "oversized",
        "funding",
        "too-many",
        "ascii-key",
        "utf8-key",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node");
        let mut node = open(&path, false).unwrap();
        let (quota, _) = fund(&mut node);
        node.reserve_native_budget_v1(request(NativeBudgetLaneV1::Serving, quota, 21))
            .unwrap();
        match corruption {
            "deleted" => {
                node.db
                    .execute(
                        "DELETE FROM metadata WHERE key GLOB 'pon-native-budget-v1:op:*'",
                        [],
                    )
                    .unwrap();
            }
            "oversized" => {
                node.db.execute("UPDATE metadata SET value=zeroblob(?1) WHERE key GLOB 'pon-native-budget-v1:op:*'", [MAX_BYTES * 2]).unwrap();
            }
            "funding" => {
                let mut records = node.native_budget_records_v1().unwrap();
                let (key, record) = records.iter_mut().next().unwrap();
                record.funding.remaining += 1;
                let raw = canonical(&serde_json::to_value(record).unwrap()).unwrap();
                node.db
                    .execute(
                        "UPDATE metadata SET value=?1 WHERE key=?2",
                        params![raw, key.as_str()],
                    )
                    .unwrap();
                node.db
                    .execute(
                        "UPDATE metadata SET value=?1 WHERE key=?2",
                        params![head(&records).unwrap(), HEAD],
                    )
                    .unwrap();
            }
            "too-many" => {
                for index in 0..MAX_RECORDS {
                    node.db
                        .execute(
                            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                            params![format!("{PREFIX}{index:064x}"), [0u8].as_slice()],
                        )
                        .unwrap();
                }
            }
            "ascii-key" | "utf8-key" => {
                let suffix = if corruption == "ascii-key" {
                    "x"
                } else {
                    "界"
                };
                let key = format!("{PREFIX}{}", suffix.repeat(MAX_KEY_BYTES + 1));
                node.db
                    .execute(
                        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                        params![key, [0u8].as_slice()],
                    )
                    .unwrap();
            }
            _ => panic!("unknown corruption fixture"),
        }
        let failure = node.native_budget_inventory_v1().err().unwrap();
        assert!(failure.requires_owner_stop(), "{corruption}: {failure}");
        // Even an absent local lookup may not bypass a damaged set/history.
        let failure = node.native_budget_operation_v1([99; 32]).err().unwrap();
        assert!(failure.requires_owner_stop(), "{corruption}: {failure}");
        drop(node);
        let failure = open(&path, false).err().unwrap();
        assert!(failure.requires_owner_stop(), "{corruption}: {failure}");
    }
}

#[test]
fn native_mining_funds_keep_maturity_and_do_not_create_payment_authority() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(&directory.path().join("node"), false).unwrap();
    fund(&mut node);
    let (_, _, state) = node.read_active().unwrap();
    let key = state.keys().find(|key| key.starts_with("reward:")).unwrap();
    let source = digest(key.strip_prefix("reward:").unwrap()).unwrap();
    let mut req = request(NativeBudgetLaneV1::Mining, source, 21);
    req.beneficiary = public(3);
    let observation = node.reserve_native_budget_v1(req.clone()).unwrap();
    assert!(!observation.funding_current && !observation.payment_executed);
    node.settle_native_budget_resources_v1(req.operation, [20, 30])
        .unwrap();
    error(
        node.prepare_native_budget_effect_v1(req.operation, [91; 32]),
        "BUDGET_FUNDING_NOT_CURRENT",
    );
    let maturity = node
        .native_budget_records_v1()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .funding
        .maturity;
    while node.parent_height(node.active().unwrap().0).unwrap() < maturity {
        mine(&mut node, vec![]);
    }
    // Mandatory maturity already credits the miner and removes this source.
    assert!(!node
        .read_active()
        .unwrap()
        .2
        .contains_key(&format!("reward:{}", hex::encode(source))));
    assert!(
        !node
            .reserve_native_budget_v1(req.clone())
            .unwrap()
            .funding_current
    );
    error(
        node.prepare_native_budget_effect_v1(req.operation, [91; 32]),
        "BUDGET_FUNDING_NOT_CURRENT",
    );
    let mut mature_reuse = request(NativeBudgetLaneV1::Mining, source, 41);
    mature_reuse.beneficiary = public(3);
    error(
        node.reserve_native_budget_v1(mature_reuse),
        "BUDGET_SOURCE_ABSENT",
    );
    let retained = node
        .native_budget_operation_v1(req.operation)
        .unwrap()
        .unwrap();
    assert_eq!(retained.resources_consumed, Some([20, 30]));
    assert_eq!(retained.effect, None);
    assert_eq!(retained.receipt, None);
}

#[test]
#[ignore = "selected only by the abrupt-exit parent with a fresh test directory"]
fn native_budget_abrupt_exit_worker() {
    let root = std::env::var_os("TRNM_NATIVE_BUDGET_EXIT_PATH").expect("explicit test directory");
    let phase = std::env::var("TRNM_NATIVE_BUDGET_EXIT_PHASE").expect("explicit test phase");
    assert!(phase == "reserved" || phase == "intent");
    let mut node = open(Path::new(&root), true).unwrap();
    let (quota, _) = fund(&mut node);
    let req = request(NativeBudgetLaneV1::Serving, quota, 21);
    node.reserve_native_budget_v1(req.clone()).unwrap();
    if phase == "intent" {
        node.settle_native_budget_resources_v1(req.operation, [20, 30])
            .unwrap();
        node.prepare_native_budget_effect_v1(req.operation, [91; 32])
            .unwrap();
    }
    // Intentional process exit without Rust Drop/Connection close. This tests
    // committed WAL recovery, not physical power-loss or target-side actuation.
    std::process::exit(86);
}

#[test]
fn abrupt_exit_preserves_committed_resource_reservations_and_pending_intent() {
    for phase in ["reserved", "intent"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "store::native_budget::tests::native_budget_abrupt_exit_worker",
                "--ignored",
                "--exact",
                "--nocapture",
            ])
            .env("TRNM_NATIVE_BUDGET_EXIT_PATH", &path)
            .env("TRNM_NATIVE_BUDGET_EXIT_PHASE", phase)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut node = open(&path, true).unwrap();
        let state = node.read_active().unwrap().2;
        let source = digest(
            state
                .keys()
                .find(|key| key.starts_with("quota:"))
                .unwrap()
                .strip_prefix("quota:")
                .unwrap(),
        )
        .unwrap();
        let req = request(NativeBudgetLaneV1::Serving, source, 21);
        let retained = node.reserve_native_budget_v1(req.clone()).unwrap();
        assert_eq!(retained.durable_records, 1);
        assert_eq!(
            retained.resources_consumed,
            if phase == "intent" {
                Some([20, 30])
            } else {
                None
            }
        );
        assert_eq!(retained.effect_pending, phase == "intent");
        let mut overbooked = request(NativeBudgetLaneV1::Serving, source, 41);
        overbooked.resource_reservation = if phase == "intent" {
            [81, 71]
        } else {
            [61, 51]
        };
        error(node.reserve_native_budget_v1(overbooked), "BUDGET_CAPACITY");
        node.settle_native_budget_resources_v1(req.operation, [20, 30])
            .unwrap();
        node.prepare_native_budget_effect_v1(req.operation, [91; 32])
            .unwrap();
        let completed = node
            .finish_native_budget_effect_v1(req.operation, [91; 32], [93; 32])
            .unwrap();
        assert!(
            completed.effect_completed
                && !completed.payment_executed
                && !completed.execution_authority
        );
    }
}
