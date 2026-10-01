//! Fresh V3 packets cannot separate renewal from source authentication.
use trnm_crypto_primitives::{
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::qualified_task_lifecycle::slot_key;
use trnm_pon_node::{development_public, Node, Packet, PoolLimits, PoolState, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v3::PROFILE,
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

fn limits(records: usize, bytes: usize) -> PoolLimits {
    PoolLimits {
        max_records: records,
        max_bytes: bytes,
        max_group_members: records.min(16),
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: development_public(3).unwrap(),
    }
}
fn transfer(s: &Settings, who: u64, sequence: u64, to: u64, amount: u64) -> Vec<u8> {
    let mut payload = development_public(to).unwrap().to_vec();
    payload.extend(amount.to_le_bytes());
    transaction(s, who, sequence, 1, payload)
}
fn mine_batch(node: &mut Node, s: &Settings) -> Hash {
    let (parent, generation) = node.active().unwrap();
    let batch = node
        .pool_mining_batch(parent, generation, 256, 524288)
        .unwrap();
    assert_eq!(
        node.pool_validate_batch(&batch).unwrap(),
        batch.transactions.len()
    );
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let packet = make(
        node,
        parent,
        batch.transactions,
        &boot.signed,
        &boot.lease,
        &m,
        &i,
    );
    admit(node, &packet)
}
#[test]
fn queued_facts_reopen_exact_raws_real_typed_gate_and_funding_nonce_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 4).unwrap();
    let policy = limits(16, 32768);
    assert!(node.pool_status().is_err());
    node.enable_local_mempool(policy.clone()).unwrap();
    // Account4 has no initial funds; this transaction depends on queued funding.
    let funding = transfer(&s, 0, 1, 4, 1000);
    let spend = transfer(&s, 4, 1, 2, 100);
    assert!(node.pool_submit(spend.clone()).is_err());
    assert_eq!(node.pool_status().unwrap().retained_records, 0);
    let first = node.pool_submit(funding.clone()).unwrap();
    assert_eq!(first.state, PoolState::Queued);
    assert_eq!(first.typed_gate_admissions, 1);
    assert_eq!(first.typed_gate_ready_metadata, 1);
    let second = node.pool_submit(spend.clone()).unwrap();
    assert_eq!(second.typed_gate_admissions, 2);
    let next = transfer(&s, 0, 2, 1, 20);
    node.pool_submit(next.clone()).unwrap();
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    let current = node.active().unwrap();
    let batch = node
        .pool_mining_batch(current.0, current.1, 256, 524288)
        .unwrap();
    assert_eq!(
        batch.transactions,
        vec![funding.clone(), spend.clone(), next.clone()]
    );
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 3);
    let duplicate = node.pool_submit(funding.clone()).unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(node.pool_status().unwrap().retained_records, 3);
    drop(node);
    let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(policy.clone()).unwrap();
    assert_eq!(
        node.pool_mining_batch(current.0, current.1, 256, 524288)
            .unwrap()
            .transactions,
        batch.transactions
    );
    let mut incompatible = policy;
    incompatible.max_bytes -= 1;
    assert!(node.enable_local_mempool(incompatible).is_err());
    let before = node.read_active().unwrap();
    mine_batch(&mut node, &s);
    assert_ne!(node.read_active().unwrap().0, before.0);
    let stale = node.pool_status_snapshot().unwrap();
    assert!(!stale.classification_current);
    assert_eq!(stale.checked_parent, Some(hex::encode(current.0)));
    assert_eq!(stale.checked_generation, Some(current.1));
    assert!(node.pool_status().unwrap().classification_current);
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 3);
    assert!(node
        .pool_status()
        .unwrap()
        .groups
        .iter()
        .all(|g| g.state == PoolState::SequenceConsumed));
    assert!(!node.pool_batch_is_current(&batch).unwrap());
    assert!(node.pool_validate_batch(&batch).is_err());
}
#[test]
fn conflicts_expiry_profile_signature_fee_and_resource_rejection_never_insert_partial_rows() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 2).unwrap();
    node.enable_local_mempool(limits(2, 400)).unwrap();
    let one = transfer(&s, 0, 1, 1, 20);
    node.pool_submit(one.clone()).unwrap();
    let conflict = transfer(&s, 0, 1, 1, 21);
    assert!(node.pool_submit(conflict).is_err());
    let before = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    let mut bad = Envelope::decode(&transfer(&s, 1, 1, 2, 30)).unwrap();
    bad.fee_limit = 1;
    bad.signature = signature(1, &bad.signing_digest().unwrap());
    assert!(node.pool_submit(bad.encode().unwrap()).is_err());
    let mut wrong = Envelope::decode(&transfer(&s, 1, 1, 2, 30)).unwrap();
    wrong.network = [9; 32];
    wrong.signature = signature(1, &wrong.signing_digest().unwrap());
    assert!(node.pool_submit(wrong.encode().unwrap()).is_err());
    let mut expired = Envelope::decode(&transfer(&s, 1, 1, 2, 30)).unwrap();
    expired.expiry = 0;
    expired.signature = signature(1, &expired.signing_digest().unwrap());
    assert!(node.pool_submit(expired.encode().unwrap()).is_err());
    let mut bad = transfer(&s, 1, 1, 2, 30);
    let end = bad.len() - 1;
    bad[end] ^= 1;
    assert!(node.pool_submit(bad).is_err());
    assert!(node.pool_submit(vec![0; 2049]).is_err());
    // 199+199 <=400 bytes, exactly two retained records.
    let two = transfer(&s, 0, 2, 1, 20);
    node.pool_submit(two).unwrap();
    assert_eq!(node.pool_status().unwrap().retained_records, 2);
    assert!(node.pool_submit(transfer(&s, 1, 1, 2, 30)).is_err());
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(node.stats().unwrap(), stats);
    // Accepted local queue writes do not consume chain ledger nonces or funds.
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
}
#[test]
fn atomic_local_control_group_is_full_m06_and_cannot_be_split_by_batch_budget() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 4).unwrap();
    node.enable_local_mempool(limits(16, 32768)).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let mut lease = boot.lease;
    lease.slot = 1;
    lease.generation = 2;
    lease.requester = development_public(2).unwrap();
    lease.purpose = TaskPurpose::InferenceContraction;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    lease.demand_id = lease.derived_demand_id();
    let m: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let i: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let signed = statement(&s, &lease, &m, &i, 1);
    let open = transaction(&s, 2, 1, 18, lease.encode().unwrap());
    let register = transaction(&s, 0, 1, 21, signed.encode().unwrap());
    let mut bad = register.clone();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    assert!(node.pool_submit_bundle(vec![open.clone(), bad]).is_err());
    assert_eq!(node.pool_status().unwrap().retained_records, 0);
    assert!(!node
        .read_active()
        .unwrap()
        .2
        .contains_key(&slot_key(1).unwrap()));
    let receipt = node
        .pool_submit_bundle(vec![open.clone(), register.clone()])
        .unwrap();
    assert_eq!(receipt.typed_gate_admissions, 2);
    assert_eq!(receipt.typed_gate_ready_metadata, 2);
    let (parent, generation) = node.active().unwrap();
    assert!(node
        .pool_mining_batch(parent, generation, 1, 32768)
        .unwrap()
        .transactions
        .is_empty());
    let batch = node
        .pool_mining_batch(parent, generation, 2, 32768)
        .unwrap();
    assert_eq!(batch.transactions, vec![open, register]);
    let mut changed = batch.clone();
    changed.transactions.pop();
    assert!(node.pool_validate_batch(&changed).is_err());
    let mut changed = batch.clone();
    changed.groups.reverse();
    changed.groups[0][0] ^= 1;
    assert!(node.pool_validate_batch(&changed).is_err());
    mine_batch(&mut node, &s);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["source_sequence"],
        1
    );
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["output_count"],
        0
    );
    assert_eq!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::SequenceConsumed
    );
    node.pool_prune_terminal(hex::decode(receipt.group).unwrap().try_into().unwrap())
        .unwrap();
    assert_eq!(node.pool_status().unwrap().local_removals, 2);
    // Group reshuffling cannot revive any exact locally removed signed member.
    assert_eq!(
        node.pool_submit(batch.transactions[0].clone())
            .unwrap_err()
            .to_string(),
        "POOL_REMOVED"
    );
    assert_eq!(
        node.pool_submit(batch.transactions[1].clone())
            .unwrap_err()
            .to_string(),
        "POOL_REMOVED"
    );
}
#[test]
fn retained_groups_restore_after_real_heavier_fork_and_terminal_prune_is_monotonic() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 4).unwrap();
    let policy = limits(8, 16384);
    node.enable_local_mempool(policy.clone()).unwrap();
    let raw = transfer(&s, 0, 1, 1, 20);
    let receipt = node.pool_submit(raw.clone()).unwrap();
    mine_batch(&mut node, &s);
    assert_eq!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::SequenceConsumed
    );
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let mut fork = s.genesis();
    for _ in 1..=2 {
        let packet = make(&node, fork, vec![], &boot.signed, &boot.lease, &m, &i);
        fork = node.admit(&packet, CLOCK).unwrap();
    }
    node.activate(fork).unwrap();
    assert_eq!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::Queued
    );
    let cursor = node.active().unwrap();
    let restored = node
        .pool_mining_batch(cursor.0, cursor.1, 256, 524288)
        .unwrap();
    assert_eq!(restored.transactions, vec![raw.clone()]);
    drop(node);
    let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(policy).unwrap();
    assert_eq!(node.pool_validate_batch(&restored).unwrap(), 1);
    mine_batch(&mut node, &s);
    node.pool_prune_terminal(hex::decode(receipt.group).unwrap().try_into().unwrap())
        .unwrap();
    assert_eq!(node.pool_status().unwrap().retained_records, 0);
    assert_eq!(node.pool_status().unwrap().local_removals, 1);
    // Roll back the spent ledger sequence again through an actual heavier branch.
    let mut alternative = fork;
    for _ in 3..=4 {
        let packet = make(
            &node,
            alternative,
            vec![],
            &boot.signed,
            &boot.lease,
            &m,
            &i,
        );
        alternative = node.admit(&packet, CLOCK).unwrap();
    }
    node.activate(alternative).unwrap();
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    assert_eq!(node.pool_status().unwrap().local_removals, 1);
    assert_eq!(
        node.pool_submit(raw).unwrap_err().to_string(),
        "POOL_REMOVED"
    );
}
#[test]
fn expiry_cache_is_retained_until_new_admission_and_operator_prune_history_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 2).unwrap();
    let mut policy = limits(2, 400);
    policy.max_removals = 1;
    node.enable_local_mempool(policy).unwrap();
    let mut raw = Envelope::decode(&transfer(&s, 0, 1, 1, 20)).unwrap();
    raw.expiry = 1;
    raw.signature = signature(0, &raw.signing_digest().unwrap());
    let first = node.pool_submit(raw.encode().unwrap()).unwrap();
    let mut raw = Envelope::decode(&transfer(&s, 1, 1, 2, 20)).unwrap();
    raw.expiry = 1;
    raw.signature = signature(1, &raw.signing_digest().unwrap());
    let second = node.pool_submit(raw.encode().unwrap()).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let parent = node.active().unwrap().0;
    let packet = make(&node, parent, vec![], &boot.signed, &boot.lease, &m, &i);
    admit(&mut node, &packet);
    assert!(node
        .pool_status()
        .unwrap()
        .groups
        .iter()
        .all(|g| g.state == PoolState::Expired));
    assert_eq!(node.pool_status().unwrap().retained_records, 2);
    assert_eq!(node.pool_status().unwrap().gc.evicted_records, 0);
    node.pool_prune_terminal(hex::decode(first.group).unwrap().try_into().unwrap())
        .unwrap();
    assert_eq!(node.pool_status().unwrap().retained_records, 1);
    assert_eq!(
        node.pool_prune_terminal(hex::decode(second.group).unwrap().try_into().unwrap())
            .unwrap_err()
            .to_string(),
        "POOL_REMOVAL_LIMIT"
    );
}

#[test]
fn second_sqlite_row_failure_rolls_back_whole_bundle_and_reopen_recovers_no_partial() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
    let policy = limits(8, 16384);
    node.enable_local_mempool(policy.clone()).unwrap();
    let fault = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    fault.execute_batch("CREATE TRIGGER pool_second_row_cut BEFORE INSERT ON local_pool_rows WHEN NEW.position=1 BEGIN SELECT RAISE(ABORT,'owned-fixture-second-row-cut'); END;").unwrap();
    let before = node.read_active().unwrap();
    assert!(node
        .pool_submit_bundle(vec![transfer(&s, 0, 1, 1, 20), transfer(&s, 1, 1, 2, 30)])
        .is_err());
    assert_eq!(node.pool_status().unwrap().retained_records, 0);
    assert_eq!(node.pool_status().unwrap().groups.len(), 0);
    assert_eq!(node.read_active().unwrap(), before);
    fault
        .execute_batch("DROP TRIGGER pool_second_row_cut;")
        .unwrap();
    drop(fault);
    drop(node);
    let mut reopened = Node::open(dir.path(), s, 1).unwrap();
    reopened.enable_local_mempool(policy).unwrap();
    assert_eq!(reopened.pool_status().unwrap().retained_records, 0);
}
#[test]
fn owner_rejects_previous_schema_shape_instead_of_adding_or_migrating_pool_tables() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    drop(Node::open(dir.path(), s.clone(), 1).unwrap());
    // Owned fixture creates the prior table set. No live namespace is changed.
    let fixture = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    fixture.execute_batch("DROP TABLE local_pool_rows; DROP TABLE local_pool_groups; DROP TABLE local_pool_removals; DROP TABLE local_pool_metadata;").unwrap();
    drop(fixture);
    assert_eq!(
        Node::open(dir.path(), s, 1).err().unwrap().to_string(),
        "SCHEMA"
    );
}

#[test]
fn admission_triggered_cache_eviction_is_not_revocation_and_real_heavier_fork_can_resubmit() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 2).unwrap();
    let policy = limits(1, 2048);
    node.enable_local_mempool(policy.clone()).unwrap();
    let first = transfer(&s, 0, 1, 1, 20);
    node.pool_submit(first.clone()).unwrap();
    mine_batch(&mut node, &s);
    let before = node.pool_status().unwrap();
    assert_eq!(before.retained_records, 1);
    assert_eq!(before.gc.evicted_records, 0);
    let second = transfer(&s, 0, 2, 1, 30);
    node.pool_submit(second).unwrap();
    let after = node.pool_status().unwrap();
    assert_eq!(after.retained_records, 1);
    assert_eq!(after.local_removals, 0);
    assert_eq!(after.gc.evicted_records, 1);
    assert_eq!(after.gc.evicted_groups, 1);
    assert_eq!(after.gc.evicted_raw_bytes, first.len() as u64);
    assert_ne!(after.gc.history_head, hex::encode([0u8; 32]));
    // A real stronger branch restores nonce1; GC did not promise automatic requeue.
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let mut fork = s.genesis();
    for _ in 1..=2 {
        let packet = make(&node, fork, vec![], &boot.signed, &boot.lease, &m, &i);
        fork = node.admit(&packet, CLOCK).unwrap();
    }
    node.activate(fork).unwrap();
    let snap = node.pool_status().unwrap();
    assert_eq!(snap.gc, after.gc);
    assert_eq!(snap.groups[0].state, PoolState::Blocked);
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    // Free the retained blocked successor only through explicit operator pruning.
    // Its tombstone must survive yet another branch change.
    node.pool_prune_terminal(
        hex::decode(&snap.groups[0].group)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        node.pool_submit(first.clone()).unwrap().state,
        PoolState::Queued
    );
    let current = node.active().unwrap();
    assert_eq!(
        node.pool_mining_batch(current.0, current.1, 256, 524288)
            .unwrap()
            .transactions,
        vec![first]
    );
    drop(node);
    let mut reopened = Node::open(dir.path(), s, 1).unwrap();
    reopened.enable_local_mempool(policy).unwrap();
    assert_eq!(reopened.pool_status().unwrap().gc, after.gc);
    assert_eq!(reopened.pool_status().unwrap().local_removals, 1);
}

#[test]
fn mixed_terminal_group_and_pending_full_are_protected_from_cache_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 2).unwrap();
    node.enable_local_mempool(limits(2, 4096)).unwrap();
    let first = transfer(&s, 0, 1, 1, 20);
    let second = transfer(&s, 1, 1, 2, 30);
    node.pool_submit_bundle(vec![first.clone(), second])
        .unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let packet = make(
        &node,
        s.genesis(),
        vec![first],
        &boot.signed,
        &boot.lease,
        &m,
        &i,
    );
    admit(&mut node, &packet);
    assert_eq!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::SequenceConsumed
    );
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 1);
    assert_eq!(
        node.pool_submit(transfer(&s, 2, 1, 1, 2))
            .unwrap_err()
            .to_string(),
        "POOL_RECORD_LIMIT"
    );
    assert_eq!(node.pool_status().unwrap().retained_records, 2);
    assert_eq!(node.pool_status().unwrap().gc.evicted_records, 0);
    let pending_dir = tempfile::tempdir().unwrap();
    let mut pending = Node::open(pending_dir.path(), s.clone(), 1).unwrap();
    pending.enable_local_mempool(limits(1, 2048)).unwrap();
    pending.pool_submit(transfer(&s, 0, 1, 1, 1)).unwrap();
    assert_eq!(
        pending
            .pool_submit(transfer(&s, 1, 1, 2, 1))
            .unwrap_err()
            .to_string(),
        "POOL_RECORD_LIMIT"
    );
    assert_eq!(pending.pool_status().unwrap().gc.evicted_records, 0);
}

#[test]
fn needed_gc_and_failed_signed_admission_or_sqlite_insert_roll_back_original_cache_and_counters() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
    let policy = limits(2, 4096);
    node.enable_local_mempool(policy.clone()).unwrap();
    node.pool_submit_bundle(vec![transfer(&s, 0, 1, 1, 1), transfer(&s, 1, 1, 2, 1)])
        .unwrap();
    mine_batch(&mut node, &s);
    let before = serde_json::to_value(node.pool_status().unwrap()).unwrap();
    let active = node.active().unwrap();
    let fresh = vec![transfer(&s, 0, 2, 1, 2), transfer(&s, 1, 2, 2, 2)];
    let mut bad = fresh.clone();
    let end = bad[1].len() - 1;
    bad[1][end] ^= 1;
    assert!(node.pool_submit_bundle(bad).is_err());
    assert_eq!(
        serde_json::to_value(node.pool_status().unwrap()).unwrap(),
        before
    );
    let fault = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    fault.execute_batch("CREATE TRIGGER pool_gc_insert_cut BEFORE INSERT ON local_pool_rows WHEN NEW.position=1 BEGIN SELECT RAISE(ABORT,'owned-v2-gc-second-row-cut'); END;").unwrap();
    assert!(node.pool_submit_bundle(fresh.clone()).is_err());
    assert_eq!(
        serde_json::to_value(node.pool_status().unwrap()).unwrap(),
        before
    );
    assert_eq!(node.active().unwrap(), active);
    fault
        .execute_batch("DROP TRIGGER pool_gc_insert_cut;")
        .unwrap();
    drop(fault);
    drop(node);
    let mut reopened = Node::open(dir.path(), s, 1).unwrap();
    reopened.enable_local_mempool(policy).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.pool_status().unwrap()).unwrap(),
        before
    );
    reopened.pool_submit_bundle(fresh).unwrap();
    let after = reopened.pool_status().unwrap();
    assert_eq!(after.retained_records, 2);
    assert_eq!(after.gc.evicted_groups, 1);
    assert_eq!(after.gc.evicted_records, 2);
    assert_eq!(after.local_removals, 0);
}

#[test]
#[ignore = "actual4500 signed raws and563 native blocks; run explicitly with its own evidence directory"]
fn cache_gc_supports_4500_actual_signed_raws_beyond_v1_lifetime_with_bounded_retained_pool() {
    use std::{io::Write, time::Instant};
    let temporary = tempfile::tempdir().unwrap();
    let evidence = std::env::var_os("LOCAL_POOL_V2_EVIDENCE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().join("evidence"));
    std::fs::create_dir(&evidence).unwrap();
    let store = evidence.join("store");
    let packets = evidence.join("packets");
    std::fs::create_dir(&packets).unwrap();
    let mut raw_log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("signed-raws.jsonl"))
        .unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let policy = limits(8, 8 * 199);
    let mut node = Node::open(&store, s.clone(), 2).unwrap();
    node.enable_local_mempool(policy.clone()).unwrap();
    let before_state = node.read_active().unwrap().2;
    let sender_key = format!("account:{}", hex::encode(development_public(0).unwrap()));
    let receiver_key = format!("account:{}", hex::encode(development_public(1).unwrap()));
    let before_sender = before_state[&sender_key]["balance"].as_u64().unwrap();
    let before_receiver = before_state[&receiver_key]["balance"].as_u64().unwrap();
    let started = Instant::now();
    let mut activated = 0u64;
    let mut proof_bytes = 0u64;
    let mut packet_bytes = 0u64;
    let mut receipt_head = [0u8; 32];
    let mut receipt_log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("block-receipts.jsonl"))
        .unwrap();
    let mut peak_records = 0;
    let mut peak_bytes = 0;
    for sequence in 1..=4500u64 {
        let raw = transfer(&s, 0, sequence, 1, 1);
        let receipt = node.pool_submit(raw.clone()).unwrap();
        assert!(!receipt.duplicate);
        writeln!(raw_log,"{}",serde_json::json!({"sequence":sequence,"raw":hex::encode(&raw),"digest":hex::encode(hash(b"tx-id",&[&raw])),"receipt":receipt})).unwrap();
        let status = node.pool_status_snapshot().unwrap();
        peak_records = peak_records.max(status.retained_records);
        peak_bytes = peak_bytes.max(status.retained_bytes);
        assert!(status.retained_records <= 8 && status.retained_bytes <= 8 * 199);
        assert_eq!(status.local_removals, 0);
        if sequence.is_multiple_of(8) || sequence == 4500 {
            let stage = Instant::now();
            let id = mine_batch(&mut node, &s);
            let packet = node.packet(id).unwrap();
            let wire = packet.encode().unwrap();
            assert_eq!(
                packet.transactions.len(),
                if sequence == 4500 { 4 } else { 8 }
            );
            for (offset, raw) in packet.transactions.iter().enumerate() {
                let nonce = Envelope::decode(raw).unwrap().nonce;
                assert_eq!(
                    nonce,
                    sequence - packet.transactions.len() as u64 + offset as u64 + 1
                );
            }
            activated += 1;
            assert_eq!(node.active().unwrap().0, id);
            assert_eq!(
                node.next_nonce(development_public(0).unwrap()).unwrap(),
                sequence + 1
            );
            proof_bytes += packet.proof.len() as u64;
            packet_bytes += wire.len() as u64;
            let packet_digest = hash(b"local-pool-v2-observed-packet", &[&wire]);
            receipt_head = hash(
                b"local-pool-v2-observed-block-chain",
                &[&receipt_head, &id, &packet_digest, &sequence.to_le_bytes()],
            );
            std::fs::write(packets.join(format!("{:04}.pnw1", activated)), &wire).unwrap();
            writeln!(receipt_log,"{}",serde_json::json!({"height":activated,"last_sequence":sequence,"block":hex::encode(id),"packet_digest":hex::encode(packet_digest),"receipt_head":hex::encode(receipt_head),"transactions":packet.transactions.len(),"proof_bytes":packet.proof.len(),"packet_bytes":wire.len(),"actual_make_admit_activate_ns":stage.elapsed().as_nanos()})).unwrap();
            if activated == 281 {
                let before = node.active().unwrap();
                drop(node);
                node = Node::open(&store, s.clone(), 1).unwrap();
                node.enable_local_mempool(policy.clone()).unwrap();
                assert_eq!(node.active().unwrap(), before);
            }
        }
    }
    raw_log.sync_all().unwrap();
    receipt_log.sync_all().unwrap();
    let status = node.pool_status().unwrap();
    assert_eq!(activated, 563);
    assert_eq!(status.gc.evicted_records, 4492);
    assert_eq!(status.retained_records, 8);
    assert_eq!(status.gc.evicted_groups, 4492);
    assert_eq!(status.gc.evicted_raw_bytes, 4492 * 199);
    assert_eq!(status.local_removals, 0);
    let actual = node.read_active().unwrap();
    let account = &actual.2[&format!("account:{}", hex::encode(development_public(0).unwrap()))];
    assert_eq!(account["nonce"], 4500);
    // Exact selected dev registry:100 base fee+199 bytes+1 transferred unit.
    assert_eq!(
        account["balance"].as_u64().unwrap(),
        before_sender - 4500 * 300
    );
    assert_eq!(
        actual.2[&receiver_key]["balance"].as_u64().unwrap(),
        before_receiver + 4500
    );
    assert_eq!(
        node.next_nonce(development_public(0).unwrap()).unwrap(),
        4501
    );
    let result = serde_json::json!({"schema":"native-local-pool-v2-actual-lifecycle-v1","integration_lineage_base":"56a7dfea51669cd829df95c64cbecbe2c4080e56","source_scope":"compiled native test observation; exact executed source and binary must be bound by the external runner","profile":trnm_pon_node::LOCAL_POOL_PROFILE,"valid_raw_admissions":4500,"actual_activated_blocks":activated,"reopens":1,"actual_elapsed_ns":started.elapsed().as_nanos(),"logical_timestamp_seconds":5630,"clock_scope":"logical finite native execution, no wall-clock sustained service qualification","peak_retained_records":peak_records,"peak_retained_raw_bytes":peak_bytes,"final_status":status,"final_account":account,"proof_bytes":proof_bytes,"packet_bytes":packet_bytes,"receipt_head":hex::encode(receipt_head),"maintenance_utility":0,"hardness_qualified":false,"physical_disk_bounded":false,"public_network_ready":false});
    std::fs::write(
        evidence.join("summary.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{}", result);
}

#[test]
fn expired_cache_is_evicted_on_byte_need_without_tombstone_and_reading_does_not_gc() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
    node.enable_local_mempool(limits(2, 199)).unwrap();
    let mut expired = Envelope::decode(&transfer(&s, 0, 1, 1, 1)).unwrap();
    expired.expiry = 1;
    expired.signature = signature(0, &expired.signing_digest().unwrap());
    let old = expired.encode().unwrap();
    node.pool_submit(old.clone()).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (m, i, _, _) = s.bootstrap_task_material().unwrap();
    let packet = make(
        &node,
        s.genesis(),
        vec![],
        &boot.signed,
        &boot.lease,
        &m,
        &i,
    );
    admit(&mut node, &packet);
    assert_eq!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::Expired
    );
    assert_eq!(node.pool_status().unwrap().gc.evicted_records, 0);
    // Row budget still has one spare; raw bytes alone cause this entire terminal GC.
    node.pool_submit(transfer(&s, 1, 1, 2, 1)).unwrap();
    let after = node.pool_status().unwrap();
    assert_eq!(after.retained_records, 1);
    assert_eq!(after.gc.evicted_records, 1);
    assert_eq!(after.gc.evicted_raw_bytes, 199);
    assert_eq!(after.local_removals, 0);
    let current = serde_json::to_value(&after).unwrap();
    assert!(node.pool_submit(old).is_err()); // Native expiry rules still apply.
    assert_eq!(
        serde_json::to_value(node.pool_status().unwrap()).unwrap(),
        current
    );
}

#[test]
fn exact_v1_metadata_schema_fixture_is_refused_before_database_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    drop(Node::open(dir.path(), s.clone(), 1).unwrap());
    let fixture = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    // Exact predecessor table definition from the preserved V1 source; this is
    // an owned schema fixture, not a claim of rerunning an older published binary.
    fixture.execute_batch("DROP TABLE local_pool_metadata; CREATE TABLE local_pool_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),context BLOB NOT NULL CHECK(length(context)=32),limits BLOB NOT NULL,checked_parent BLOB,checked_generation INTEGER,CHECK((checked_parent IS NULL AND checked_generation IS NULL) OR (length(checked_parent)=32 AND checked_generation>=0)));").unwrap();
    let raw = serde_json::to_vec(&limits(1, 2048)).unwrap();
    let context = hash(
        b"native-local-queued-pnx1-v1",
        &[&s.network(), &s.parameters(), &s.genesis(), &raw],
    );
    fixture
        .execute(
            "INSERT INTO local_pool_metadata(singleton,context,limits) VALUES(1,?,?)",
            rusqlite::params![context.as_slice(), raw],
        )
        .unwrap();
    fixture
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(fixture);
    let path = dir.path().join("native.sqlite");
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        Node::open(dir.path(), s, 1).err().unwrap().to_string(),
        "SCHEMA"
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}
