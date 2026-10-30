//! Actual legacy checkpoint -> locked NPQ5 import -> dual-PQ CLAIM -> task work.
//! Public fixture keys only. Prior registry timing and source retirement/finality
//! remain explicit external premises for this new, separately selected network.
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Instant};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{pq_accounts_v2 as pq, State},
};
use trnm_pon_node::{
    development_public,
    pq_accounts_v2::{GenesisAccount, PqNodeV2, PrecommittedAccount, TrustedPqPrecommitments},
    pq_tasks_v5::{PqNodeV5, PqPacketV5},
    Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    pq_native_accounts_v2 as wire,
    qualified_work_task::pq_lifecycle_v5::DemandLeaseV5,
};
#[allow(dead_code)]
#[path = "../../trnm-protocol/tests/support/native_pq_task_fixture_v5.rs"]
mod fixture;
#[path = "../../trnm-protocol/tests/support/native_pq_accounts_fixture.rs"]
mod old_fixture;
use fixture::{Key, Witness};

const PROFILE: &str = "pon-native-pq-tasks-v5-anchored-migration-v1";
const SCOPE: &str = "actual ordinary W1/reference/admit/SQL on shared host; external prior PQ registry and source finality remain premises";

#[derive(Clone, Copy)]
struct Sample {
    case: &'static str,
    phase: &'static str,
}
fn sample(case: &'static str, phase: &'static str) -> Sample {
    Sample { case, phase }
}
fn account(state: &State, id: Hash) -> &Value {
    &state[&format!("account:{}", hex::encode(id))]
}
fn nonce(state: &State, id: Hash) -> u64 {
    account(state, id)["nonce"].as_u64().unwrap()
}
fn auth(state: &State, id: Hash) -> &Value {
    &state[&format!("pq-auth-v2:{}", hex::encode(id))]
}
fn locked(state: &State, id: Hash) -> bool {
    state[&format!("pq-import-v2:{}", hex::encode(id))]["claimed"] == false
        && !state.contains_key(&format!("pq-auth-v2:{}", hex::encode(id)))
}
fn limits(miner: Hash) -> PoolLimits {
    PoolLimits {
        max_records: 256,
        max_bytes: 524288,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 256,
        preview_miner: miner,
    }
}
fn ordinal(path: &Path) -> u64 {
    Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='local_pool_groups'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}
fn legacy(settings: &Settings, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut row = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 100_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let secret =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    row.signature = hex::decode(sign_hex(&secret, &row.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    row.encode().unwrap()
}
fn source_admit(source: &mut Node, packet: &Packet, observation: Sample, started: Instant) {
    pon_work::verify_reference(
        packet.header.challenge(),
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .unwrap();
    let id = source.admit(packet, 10_000).unwrap();
    assert_eq!(id, packet.id().unwrap());
    source.activate(id).unwrap();
    assert_eq!(
        source
            .settings()
            .state_root(&source.state_at(id).unwrap())
            .unwrap(),
        packet.header.state
    );
    println!(
        "{}",
        json!({"schema":"native-pq5-migration-actual-phase-v1", "case":observation.case,
        "phase":observation.phase,"profile":"source-legacy", "block":hex::encode(id),
        "parent":hex::encode(packet.header.parent),"state_root":hex::encode(packet.header.state),
        "transactions":packet.transactions.len(),"raw_bytes":packet.transactions.iter().map(Vec::len).sum::<usize>(),
        "proof_bytes":packet.proof.len(),"packet_bytes":packet.encode().unwrap().len(),
        "activated":true,"wall_nanoseconds":started.elapsed().as_nanos(),"scope":SCOPE})
    );
}
struct Source {
    node: Node,
    settings: Settings,
    registry: TrustedPqPrecommitments,
    prior: Vec<Key>,
    ids: Vec<Hash>,
    checkpoint: Hash,
    state: State,
    reserve: Vec<u8>,
    task: Hash,
    _directory: tempfile::TempDir,
}
fn source(case: &'static str, extra_accounts: usize) -> Source {
    assert!(extra_accounts <= 56);
    let settings = Settings::development_with_profiles(
        Some(1000),
        "legacy-first-two-v3",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let ids: Vec<_> = (0..4)
        .chain(100..100 + extra_accounts as u64)
        .map(|index| development_public(index).unwrap())
        .collect();
    let prior: Vec<_> = (0..ids.len())
        .map(|index| Key::public_test_seed(30 + index as u8))
        .collect();
    let entries: Vec<_> = ids
        .iter()
        .zip(&prior)
        .map(|(account, key)| PrecommittedAccount {
            source_account: *account,
            spki: key.spki.clone(),
            generation: 9,
        })
        .collect();
    // This is the separately trusted prior registry, pinned before the actual
    // checkpoint is produced; it is not asserted to be historical old-chain data.
    let registry =
        TrustedPqPrecommitments::pin(settings.network(), settings.genesis(), &entries).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 1).unwrap();
    let budget = 10_000_u64;
    let deadline = 10_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &ids[0],
            &1_u64.to_le_bytes(),
            &ids[1],
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let reserve = legacy(
        &settings,
        1,
        2,
        [
            task.as_slice(),
            &ids[1],
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ]
        .concat(),
    );
    let mut rows = vec![reserve.clone()];
    for (index, destination) in ids.iter().skip(4).enumerate() {
        rows.push(legacy(
            &settings,
            index as u64 + 2,
            1,
            [destination.as_slice(), &100_000_u64.to_le_bytes()].concat(),
        ));
    }
    let started = Instant::now();
    let packet = node
        .make_consensus_maintenance(settings.genesis(), rows, ids[1], 1010, 4096)
        .unwrap();
    source_admit(
        &mut node,
        &packet,
        sample(case, "source-checkpoint"),
        started,
    );
    let checkpoint = packet.id().unwrap();
    let state = node.state_at(checkpoint).unwrap();
    assert_eq!(
        state
            .keys()
            .filter(|key| key.starts_with("account:"))
            .count(),
        ids.len()
    );
    assert!(node
        .pin_native_pq_migration_checkpoint(registry.clone(), [7; 32])
        .is_err());
    Source {
        node,
        settings,
        registry,
        prior,
        ids,
        checkpoint,
        state,
        reserve,
        task,
        _directory: directory,
    }
}
fn imported(source: &Source) -> Settings {
    let anchor = source
        .node
        .pin_native_pq_migration_checkpoint(source.registry.clone(), source.checkpoint)
        .unwrap();
    assert_eq!(anchor.checkpoint(), source.checkpoint);
    assert_eq!(
        anchor.source_root(),
        source.settings.state_root(&source.state).unwrap()
    );
    Settings::native_pq_tasks_v5_with_anchored_migration_v1(&[], 1500, anchor).unwrap()
}
fn claim(
    settings: &Settings,
    account: Hash,
    nonce: u64,
    payload: &[u8],
    prior: &Key,
    next: &Key,
) -> Vec<u8> {
    let raw = fixture::signed(
        &fixture::common(
            settings.native_pq_accounts_context().unwrap(),
            account,
            nonce,
            0,
        ),
        wire::CLAIM,
        payload,
        &[
            Witness {
                key: prior,
                role: 5,
                generation: 9,
                carried: false,
            },
            Witness {
                key: next,
                role: 6,
                generation: 1,
                carried: true,
            },
        ],
        None,
    );
    assert_eq!(raw.len(), 9432);
    raw
}
fn target_admit(
    node: &mut PqNodeV5,
    packet: &PqPacketV5,
    observation: Sample,
    started: Instant,
    activate: bool,
) -> Hash {
    pon_work::verify_reference(
        packet.header().challenge(),
        packet.header().work_task,
        packet.header().target,
        packet.proof(),
    )
    .unwrap();
    let id = node.admit(packet, 10_000).unwrap();
    assert_eq!(id, packet.id().unwrap());
    assert_eq!(
        node.settings()
            .state_root(&node.state_at(id).unwrap())
            .unwrap(),
        packet.header().state
    );
    if activate {
        node.activate(id).unwrap();
    }
    println!(
        "{}",
        json!({"schema":"native-pq5-migration-actual-phase-v1","case":observation.case,
        "phase":observation.phase,"profile":PROFILE,"block":hex::encode(id),"parent":hex::encode(packet.header().parent),
        "state_root":hex::encode(packet.header().state),"transactions":packet.transactions().len(),
        "raw_bytes":packet.transactions().iter().map(Vec::len).sum::<usize>(),"proof_bytes":packet.proof().len(),
        "packet_bytes":packet.encode().unwrap().len(),"activated":activate,"wall_nanoseconds":started.elapsed().as_nanos(),"scope":SCOPE})
    );
    id
}
fn block(
    node: &mut PqNodeV5,
    parent: Hash,
    rows: Vec<Vec<u8>>,
    miner: Hash,
    time: u64,
    observation: Sample,
    activate: bool,
) -> Hash {
    let started = Instant::now();
    let packet = node.make(parent, rows, miner, time, 4096).unwrap();
    target_admit(node, &packet, observation, started, activate)
}
fn pooled(
    node: &mut PqNodeV5,
    rows: Vec<Vec<u8>>,
    miner: Hash,
    time: u64,
    observation: Sample,
) -> Hash {
    for (index, row) in rows.iter().enumerate() {
        let receipt = node.pool_submit(row.clone()).unwrap();
        assert!(!receipt.duplicate);
        // These receipts count the entire reconstructed pending prefix.
        assert_eq!(receipt.typed_gate_admissions, index + 1);
        assert_eq!(receipt.typed_gate_ready_metadata, index + 1);
    }
    let (parent, generation) = node.active().unwrap();
    let batch = node
        .pool_mining_batch(parent, generation, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, rows);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), rows.len());
    block(
        node,
        parent,
        batch.transactions,
        miner,
        time,
        observation,
        true,
    )
}
fn lease(settings: &Settings, requester: Hash, provider: Hash, height: u64) -> DemandLeaseV5 {
    let mut value = fixture::lease(
        settings.native_pq_accounts_context().unwrap(),
        requester,
        provider,
    );
    value.not_before = height;
    value.demand_id = value.derived_demand_id();
    value
}
fn open(settings: &Settings, lease: &DemandLeaseV5, key: &Key, nonce: u64) -> Vec<u8> {
    fixture::signed(
        &fixture::common(
            settings.native_pq_accounts_context().unwrap(),
            lease.requester,
            nonce,
            1,
        ),
        18,
        &lease.encode().unwrap(),
        &[fixture::primary(key, 1)],
        None,
    )
}
fn register(
    settings: &Settings,
    lease: &DemandLeaseV5,
    requester: &Key,
    provider: &Key,
    nonce: u64,
) -> Vec<u8> {
    let (_, _, a, b) = fixture::material();
    let task = pon_work::task_id(&a, &b).unwrap();
    fixture::signed(
        &fixture::common(
            settings.native_pq_accounts_context().unwrap(),
            lease.requester,
            nonce,
            1,
        ),
        21,
        &fixture::registration(lease, task, 1, [0; 32])
            .encode()
            .unwrap(),
        &[fixture::primary(requester, 1), fixture::source(provider, 1)],
        None,
    )
}
fn material(
    node: &mut PqNodeV5,
    parent: Hash,
    miner: Hash,
    time: u64,
    observation: Sample,
) -> Hash {
    let (model, input, _, _) = fixture::material();
    let started = Instant::now();
    let packet = node
        .make_with_registered_material(parent, vec![], miner, time, 4096, &model, &input)
        .unwrap();
    let id = target_admit(node, &packet, observation, started, true);
    let state = node.state_at(id).unwrap();
    let row = &state[&pq::tasks_v5::slot_key(0).unwrap()];
    assert_eq!(row["output_count"], 1);
    assert_ne!(row["output_product"], hex::encode([0; 32]));
    id
}
fn fresh_observation() {
    let accounts: Vec<_> = (221..224)
        .map(Key::public_test_seed)
        .map(|key| GenesisAccount {
            spki: key.spki,
            balance: 100_000_000,
        })
        .collect();
    let settings = Settings::native_pq_tasks_v5(&accounts, 1000).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    let state = node.state_at(settings.genesis()).unwrap();
    assert!(node.migration_claim_payload([1; 32]).is_err());
    println!(
        "{}",
        json!({"schema":"native-pq5-fresh-namespace-observation-v1",
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),"state_root":hex::encode(settings.state_root(&state).unwrap()),
        "state_json_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&state).unwrap())),
        "anchored_constructor_used":false})
    );
}

#[test]
fn actual_anchored_claim_pq5_task_native_work_reorg_and_cold_readback() {
    const CASE: &str = "unified";
    fresh_observation();
    let source = source(CASE, 0);
    let settings = imported(&source);
    let (owner, provider) = (source.ids[0], source.ids[1]);
    let keys = [Key::public_test_seed(120), Key::public_test_seed(121)];
    let directory = tempfile::tempdir().unwrap();
    let mut node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    node.enable_local_mempool(limits(provider)).unwrap();
    let genesis = node.state_at(settings.genesis()).unwrap();
    assert_eq!(genesis["meta:issued"], source.state["meta:issued"]);
    for id in &source.ids {
        assert_eq!(account(&genesis, *id), account(&source.state, *id));
        assert!(locked(&genesis, *id));
    }
    let old_task = format!("task:{}", hex::encode(source.task));
    assert_eq!(genesis[&old_task]["deadline"], 9);
    assert!(!genesis.contains_key(&pq::tasks_v5::slot_key(0).unwrap()));
    let claims: Vec<_> = [owner, provider]
        .iter()
        .enumerate()
        .map(|(index, id)| {
            claim(
                &settings,
                *id,
                nonce(&genesis, *id) + 1,
                &node.migration_claim_payload(*id).unwrap(),
                &source.prior[index],
                &keys[index],
            )
        })
        .collect();
    assert!(node.pool_submit(source.reserve.clone()).is_err());
    let claimed = pooled(
        &mut node,
        claims.clone(),
        provider,
        1510,
        sample(CASE, "claims"),
    );
    let claimed_state = node.state_at(claimed).unwrap();
    assert_eq!(nonce(&claimed_state, owner), 2);
    assert_eq!(nonce(&claimed_state, provider), 1);
    assert_eq!(
        auth(&claimed_state, owner)["key_id"],
        hex::encode(keys[0].id)
    );
    assert_eq!(
        auth(&claimed_state, provider)["key_id"],
        hex::encode(keys[1].id)
    );
    let initial_lease = lease(&settings, owner, provider, 2);
    let opened = pooled(
        &mut node,
        vec![open(&settings, &initial_lease, &keys[0], 3)],
        provider,
        1520,
        sample(CASE, "lease"),
    );
    let before = node.state_at(opened).unwrap();
    assert!(node
        .pool_submit(register(
            &settings,
            &initial_lease,
            &keys[0],
            &source.prior[1],
            4
        ))
        .is_err());
    assert_eq!(node.state_at(opened).unwrap(), before);
    let registered = pooled(
        &mut node,
        vec![register(&settings, &initial_lease, &keys[0], &keys[1], 4)],
        provider,
        1530,
        sample(CASE, "registration"),
    );
    let worked = material(
        &mut node,
        registered,
        provider,
        1540,
        sample(CASE, "material"),
    );
    let worked_state = node.state_at(worked).unwrap();
    assert_eq!(
        worked_state
            .keys()
            .filter(|key| key.starts_with(pq::tasks_v5::WITNESS_PREFIX))
            .count(),
        5
    );
    let before_ordinal = ordinal(directory.path());
    drop(node);
    let mut node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, worked);
    assert_eq!(node.state_at(worked).unwrap(), worked_state);
    let mut fork = settings.genesis();
    for (height, phase) in ["fork-1", "fork-2", "fork-3", "fork-4", "fork-5"]
        .into_iter()
        .enumerate()
    {
        fork = block(
            &mut node,
            fork,
            vec![],
            provider,
            1511 + 10 * height as u64,
            sample(CASE, phase),
            false,
        );
    }
    node.activate(fork).unwrap();
    let restored = node.state_at(fork).unwrap();
    assert!(locked(&restored, owner) && locked(&restored, provider));
    assert_eq!(nonce(&restored, owner), 1);
    assert_eq!(nonce(&restored, provider), 0);
    assert_eq!(restored[&old_task]["remaining"], 10_000);
    assert!(!restored.contains_key(&pq::tasks_v5::slot_key(0).unwrap()));
    assert_eq!(ordinal(directory.path()), before_ordinal);
    let batch = node
        .pool_mining_batch(fork, node.active().unwrap().1, 256, 524288)
        .unwrap();
    assert_eq!(batch.transactions, claims);
    assert_eq!(node.pool_validate_batch(&batch).unwrap(), 2);
    let reclaimed = block(
        &mut node,
        fork,
        batch.transactions,
        provider,
        1561,
        sample(CASE, "replayed-claims"),
        true,
    );
    assert_eq!(nonce(&node.state_at(reclaimed).unwrap(), owner), 2);
    assert_eq!(ordinal(directory.path()), before_ordinal);
    let current = lease(&settings, owner, provider, 7);
    let reopened = pooled(
        &mut node,
        vec![open(&settings, &current, &keys[0], 3)],
        provider,
        1571,
        sample(CASE, "fresh-lease"),
    );
    let reregistered = pooled(
        &mut node,
        vec![register(&settings, &current, &keys[0], &keys[1], 4)],
        provider,
        1581,
        sample(CASE, "fresh-registration"),
    );
    assert_ne!(reopened, reregistered);
    let final_tip = material(
        &mut node,
        reregistered,
        provider,
        1591,
        sample(CASE, "fresh-material"),
    );
    assert_eq!(ordinal(directory.path()), before_ordinal + 2);
    let final_state = node.state_at(final_tip).unwrap();
    let bytes = node.packet(final_tip).unwrap().encode().unwrap();
    assert!(bytes.starts_with(b"PQP5\x05\0\0\0"));
    assert!(Packet::decode(&bytes).is_err());
    drop(node);
    let node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, final_tip);
    assert_eq!(node.state_at(final_tip).unwrap(), final_state);
    assert_eq!(node.packet(final_tip).unwrap().encode().unwrap(), bytes);
    assert_eq!(
        settings.state_root(&final_state).unwrap(),
        node.packet(final_tip).unwrap().header().state
    );
    assert_eq!(
        source.node.state_at(source.checkpoint).unwrap(),
        source.state
    );
    println!(
        "{}",
        json!({"schema":"native-pq5-migration-completion-v1","case":CASE,
        "source_checkpoint":hex::encode(source.checkpoint),"genesis":hex::encode(settings.genesis()),
        "cold_tip":hex::encode(final_tip),"cold_state_root":hex::encode(settings.state_root(&final_state).unwrap()),
        "reorg_claims_and_nonce_restored":true,"task_authority_restored":true,
        "local_pool_ordinal_preserved":true,"new_branch_signed_records":2,
        "prior_pq_registry_external":true,"source_retirement_finality_proved":false})
    );
}

#[test]
fn full_9432_byte_claims_preserve_the_original_55_accept_56_reject_capacity() {
    const CASE: &str = "capacity";
    let source = source(CASE, 56);
    let settings = imported(&source);
    let directory = tempfile::tempdir().unwrap();
    let mut node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    let miner = source.ids[1];
    node.enable_local_mempool(limits(miner)).unwrap();
    let initial = node.state_at(settings.genesis()).unwrap();
    assert_eq!(
        initial
            .keys()
            .filter(|key| key.starts_with("account:"))
            .count(),
        60
    );
    let next: Vec<_> = (120..176).map(Key::public_test_seed).collect();
    let rows: Vec<_> = source
        .ids
        .iter()
        .skip(4)
        .enumerate()
        .map(|(index, id)| {
            claim(
                &settings,
                *id,
                1,
                &node.migration_claim_payload(*id).unwrap(),
                &source.prior[index + 4],
                &next[index],
            )
        })
        .collect();
    assert_eq!(rows.len(), 56);
    assert_eq!(rows.iter().map(Vec::len).sum::<usize>(), 528192);
    assert!(node
        .make(settings.genesis(), rows.clone(), miner, 1510, 4096)
        .is_err());
    assert_eq!(node.active().unwrap().0, settings.genesis());
    assert_eq!(node.state_at(settings.genesis()).unwrap(), initial);
    assert!(node.pool_status().unwrap().groups.is_empty());
    let accepted = pooled(
        &mut node,
        rows[..55].to_vec(),
        miner,
        1510,
        sample(CASE, "claims-capacity"),
    );
    let state = node.state_at(accepted).unwrap();
    for (index, id) in source.ids.iter().skip(4).take(55).enumerate() {
        assert_eq!(nonce(&state, *id), 1);
        assert_eq!(auth(&state, *id)["key_id"], hex::encode(next[index].id));
    }
    assert!(locked(&state, source.ids[59]));
    let packet = node.packet(accepted).unwrap();
    assert_eq!(
        packet.transactions().iter().map(Vec::len).sum::<usize>(),
        518760
    );
    assert!(packet.encode().unwrap().len() <= 1048576);
    drop(node);
    let node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, accepted);
    assert_eq!(node.state_at(accepted).unwrap(), state);
    assert_eq!(
        node.packet(accepted).unwrap().encode().unwrap(),
        packet.encode().unwrap()
    );
    println!(
        "{}",
        json!({"schema":"native-pq5-migration-completion-v1","case":CASE,
        "claim_bytes":9432,"accepted_claims":55,"accepted_raw_bytes":518760,
        "refused_claims":56,"refused_raw_bytes":528192,"transaction_bytes_limit":524288,
        "packet_bytes_limit":1048576,"source_accounts":60,"source_checkpoint":hex::encode(source.checkpoint),
        "cold_tip":hex::encode(accepted),"cold_state_root":hex::encode(settings.state_root(&state).unwrap()),
        "prior_pq_registry_external":true,"source_retirement_finality_proved":false})
    );
}

#[test]
fn wrong_anchor_current_context_prior_key_and_legacy_profiles_never_grant_claim_authority() {
    const CASE: &str = "refusal";
    let mut source = source(CASE, 0);
    let settings = imported(&source);
    let owner = source.ids[0];
    let provider = source.ids[1];
    let current = Key::public_test_seed(120);
    let started = Instant::now();
    let other_packet = source
        .node
        .make_consensus_maintenance(source.checkpoint, vec![], provider, 1020, 4096)
        .unwrap();
    source_admit(
        &mut source.node,
        &other_packet,
        sample(CASE, "other-source-checkpoint"),
        started,
    );
    assert!(source
        .node
        .pin_native_pq_migration_checkpoint(source.registry.clone(), source.checkpoint)
        .is_err());
    let other_anchor = source
        .node
        .pin_native_pq_migration_checkpoint(source.registry.clone(), other_packet.id().unwrap())
        .unwrap();
    let other_settings =
        Settings::native_pq_tasks_v5_with_anchored_migration_v1(&[], 1500, other_anchor.clone())
            .unwrap();
    assert_ne!(settings.network(), other_settings.network());
    assert_ne!(settings.parameters(), other_settings.parameters());
    assert_ne!(settings.genesis(), other_settings.genesis());
    let other_directory = tempfile::tempdir().unwrap();
    let other_node = PqNodeV5::open(other_directory.path(), other_settings.clone(), 1).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    node.enable_local_mempool(limits(provider)).unwrap();
    let before = node.state_at(settings.genesis()).unwrap();
    let payload = node.migration_claim_payload(owner).unwrap();
    let original = claim(&settings, owner, 2, &payload, &source.prior[0], &current);
    let bad_context = claim(
        &other_settings,
        owner,
        2,
        &payload,
        &source.prior[0],
        &current,
    );
    let bad_anchor = claim(
        &settings,
        owner,
        2,
        &other_node.migration_claim_payload(owner).unwrap(),
        &source.prior[0],
        &current,
    );
    let bad_prior = claim(&settings, owner, 2, &payload, &source.prior[1], &current);
    let old_settings =
        Settings::native_pq_accounts_v2_with_migration(&[], 1500, other_anchor).unwrap();
    let old_prior = old_fixture::Key::public_test_seed(30);
    let old_current = old_fixture::Key::public_test_seed(120);
    let old_common = fixture::common(
        old_settings.native_pq_accounts_context().unwrap(),
        owner,
        2,
        0,
    );
    let old_raw = old_fixture::signed(
        &old_common,
        wire::CLAIM,
        &other_node.migration_claim_payload(owner).unwrap(),
        &[
            old_fixture::Witness {
                key: &old_prior,
                role: 5,
                generation: 9,
                carried: false,
            },
            old_fixture::Witness {
                key: &old_current,
                role: 6,
                generation: 1,
                carried: true,
            },
        ],
        None,
    );
    for raw in [
        bad_context,
        bad_anchor,
        bad_prior,
        old_raw,
        source.reserve.clone(),
    ] {
        assert!(node.pool_submit(raw).is_err());
        assert_eq!(node.active().unwrap().0, settings.genesis());
        assert_eq!(node.state_at(settings.genesis()).unwrap(), before);
        assert!(node.pool_status().unwrap().groups.is_empty());
    }
    let accepted = pooled(
        &mut node,
        vec![original],
        provider,
        1510,
        sample(CASE, "valid-claim-after-refusals"),
    );
    let state = node.state_at(accepted).unwrap();
    assert_eq!(nonce(&state, owner), 2);
    assert_eq!(auth(&state, owner)["key_id"], hex::encode(current.id));
    let wire = node.packet(accepted).unwrap().encode().unwrap();
    assert!(trnm_pon_node::pq_accounts_v2::PqPacketV2::decode(&wire).is_err());
    assert!(trnm_pon_node::pq_tasks_v4::PqPacketV4::decode(&wire).is_err());
    assert!(Packet::decode(&wire).is_err());
    drop(node);
    assert!(PqNodeV5::open(directory.path(), other_settings, 1).is_err());
    assert!(PqNodeV2::open(directory.path(), old_settings, 1).is_err());
    let node = PqNodeV5::open(directory.path(), settings.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, accepted);
    assert_eq!(node.state_at(accepted).unwrap(), state);
    println!(
        "{}",
        json!({"schema":"native-pq5-migration-completion-v1","case":CASE,
        "wrong_checkpoint_refused":true,"wrong_context_refused":true,"wrong_anchor_refused":true,
        "wrong_prior_key_refused":true,"old_pq2_refused":true,"old_ed25519_refused":true,
        "wrong_cold_context_refused":true,"source_checkpoint":hex::encode(source.checkpoint),
        "cold_tip":hex::encode(accepted),"cold_state_root":hex::encode(settings.state_root(&state).unwrap()),
        "prior_pq_registry_external":true,"source_retirement_finality_proved":false})
    );
}
