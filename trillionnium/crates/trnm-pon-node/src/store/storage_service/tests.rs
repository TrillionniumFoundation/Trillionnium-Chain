use super::*;

#[path = "cache_quota_tests.rs"]
mod cache_quota;
use crate::development_public;
use crate::store::StateBackend;
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::Path,
    time::Duration,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_data_availability::cell::{CellContextV1, CellManifestV1, CellRetentionConfigV1};
use trnm_mvcc_fee::continuity_v1;
use trnm_protocol::pon_wire::Envelope;
use trnm_service_settlement::native_budget::NativeBudgetConfigV1;

fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn open_node(path: &Path, backend: StateBackend) -> Node {
    let settings = crate::Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    match backend {
        StateBackend::HistoryEffectV6 => panic!("use the protected V6 fixture"),
        StateBackend::Legacy => Node::open(path, settings, 1).unwrap(),
        StateBackend::AuthenticatedV1 => {
            Node::open_with_authenticated_state(path, settings, 1).unwrap()
        }
        StateBackend::PermanentAccountGrowthV2 => Node::open_with_permanent_account_growth_v2(
            path,
            settings
                .with_permanent_account_growth_v2("native-cell-storage-v2")
                .unwrap(),
        )
        .unwrap(),
    }
}
fn mine(node: &mut Node, parent: Hash, transactions: Vec<Vec<u8>>) -> Hash {
    let height = node.record(parent).unwrap().height + 1;
    let tip = if node.state_backend == StateBackend::PermanentAccountGrowthV2 {
        let packet = node
            .make_growth_consensus_maintenance(
                parent,
                transactions,
                public(3),
                1 + 10 * height,
                4096,
            )
            .unwrap();
        node.admit_growth(&packet, 100_000).unwrap()
    } else {
        let packet = node
            .make_consensus_maintenance(parent, transactions, public(3), 1 + 10 * height, 4096)
            .unwrap();
        node.admit(&packet, 100_000).unwrap()
    };
    node.activate(tip).unwrap();
    tip
}
fn fund(node: &mut Node, amount: u64) -> NativeFundingSourceV1 {
    // This is the current account transaction sequence, not a cryptographic
    // nonce. Read the real backend so repeated funding follows committed state.
    let nonce = node.next_nonce(public(0)).unwrap();
    let network = node.settings.network();
    let until = 50u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &network,
            &node.settings.parameters(),
            &public(0),
            &nonce.to_le_bytes(),
            &public(1),
            &amount.to_le_bytes(),
            &until.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(public(1));
    payload.extend(amount.to_le_bytes());
    payload.extend(until.to_le_bytes());
    let mut transaction = Envelope {
        network,
        sender: public(0),
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 2,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let parent = node.active().unwrap().0;
    mine(node, parent, vec![transaction.encode().unwrap()]);
    NativeFundingSourceV1::Task(task)
}
fn config(node: &Node) -> NativeBudgetConfigV1 {
    NativeBudgetConfigV1 {
        network: node.settings.network(),
        parameters: node.settings.parameters(),
        genesis: node.settings.genesis(),
        max_records: 128,
    }
}
fn retention_config() -> CellRetentionConfigV1 {
    CellRetentionConfigV1 {
        store_id: [71; 32],
        capacity_bytes: 40_960,
        maximum_obligations: 16,
    }
}
fn material(directory: &Path) -> (CellStoreV1, CellManifestV1, Vec<u8>) {
    let bytes = (0..37_000)
        .map(|i| ((i * 41 + 3) % 251) as u8)
        .collect::<Vec<_>>();
    let source = directory.join("source.cell");
    fs::write(&source, &bytes).unwrap();
    let cache = CellStoreV1::open(&directory.join("cache.sqlite"), cache_config()).unwrap();
    let manifest = cache
        .pack_file(
            &source,
            CellContextV1 {
                family: "native-funded-retention-v1".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    (cache, manifest, bytes)
}
fn request(
    source: NativeFundingSourceV1,
    manifest: &CellManifestV1,
) -> NativeCellRetentionRequestV1 {
    let contract = CellRetentionContractV1 {
        operation: [72; 32],
        funding_operation: [73; 32],
        manifest: manifest.clone(),
        retain_from_height: 1,
        retain_until_height: 20,
        maximum_repair_bytes: manifest.size() * 2,
        successor: None,
    };
    let resources = NativeBudgetResourcesV1::Storage {
        retained_bytes: manifest.size(),
        retained_byte_blocks: manifest.size() * 19,
    };
    NativeCellRetentionRequestV1 {
        policy: NativeBudgetPolicyV1 {
            budget: [74; 32],
            source,
            monetary_cap: 1000,
            deadline: 40,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim: contract.funding_operation,
            budget: [74; 32],
            subject: contract.commitment(retention_config().store_id),
            beneficiary: public(1),
            monetary_reservation: 1000,
            resource_reservation: resources,
        },
        contract,
    }
}
fn damage(path: &Path) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path.join("payload.arena"))
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn native_cell_storage_escrow_replay_and_reorg_keep_physical_obligation() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let node_path = dir.path().join("node");
        let mut node = open_node(&node_path, backend);
        let genesis = node.settings.genesis();
        let source = fund(&mut node, 1000);
        let (cache, manifest, _) = material(dir.path());
        let request = request(source, &manifest);
        let conf = config(&node);
        let journal = dir.path().join("budgets.sqlite");
        let mut budgets = NativeBudgetStoreV1::open(&journal, conf.clone()).unwrap();
        let path = dir.path().join("retention");
        let mut retained = CellRetentionStoreV1::create(&path, retention_config()).unwrap();
        let first = node
            .retain_native_cell(
                &mut budgets,
                &mut retained,
                &cache,
                request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(first.replay, NativeBudgetReplayV1::New);
        assert!(first.target.acknowledged);
        assert_eq!(first.target.initial_copy_bytes_committed, manifest.size());
        let charged = budgets.report().unwrap();
        assert_eq!(
            charged["budgets"][0]["resource_charge"],
            serde_json::json!([37_000, 703_000, 0, 0])
        );
        assert!(node
            .retire_native_cell(&mut retained, request.contract.operation, None, deadline())
            .is_err());
        let fork = mine(&mut node, genesis, vec![]);
        mine(&mut node, fork, vec![]);
        assert!(node
            .native_funding_observation(source)
            .unwrap()
            .row
            .is_none());
        drop(node);
        drop(budgets);
        drop(retained);
        drop(cache);
        fs::remove_file(dir.path().join("source.cell")).unwrap();
        let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
        let mut node = open_node(&node_path, backend);
        let mut budgets = NativeBudgetStoreV1::open(&journal, conf).unwrap();
        let mut retained = CellRetentionStoreV1::open(&path, retention_config()).unwrap();
        let replay = node
            .retain_native_cell(
                &mut budgets,
                &mut retained,
                &empty,
                request.clone(),
                deadline(),
            )
            .unwrap();
        assert_eq!(replay.replay, NativeBudgetReplayV1::Done);
        assert_eq!(replay.target_receipt, first.target_receipt);
        assert_eq!(replay.target, first.target);
        assert_eq!(budgets.report().unwrap(), charged);
        damage(&path);
        assert!(node
            .retain_native_cell(&mut budgets, &mut retained, &empty, request, deadline())
            .is_err());
        assert_eq!(budgets.report().unwrap(), charged);
    }
}

#[test]
fn native_cell_storage_subject_and_real_byte_block_capacity_are_required_before_effect() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open_node(&dir.path().join("node"), StateBackend::AuthenticatedV1);
    let source = fund(&mut node, 1000);
    let (cache, manifest, _) = material(dir.path());
    let request = request(source, &manifest);
    let mut budgets =
        NativeBudgetStoreV1::open(&dir.path().join("budgets.sqlite"), config(&node)).unwrap();
    let mut retained =
        CellRetentionStoreV1::create(&dir.path().join("retention"), retention_config()).unwrap();
    let before = budgets.report().unwrap();
    let mut wrong = request.clone();
    wrong.claim.subject = [99; 32];
    assert!(node
        .retain_native_cell(&mut budgets, &mut retained, &cache, wrong, deadline())
        .is_err());
    let mut short = request.clone();
    short.claim.resource_reservation = NativeBudgetResourcesV1::Storage {
        retained_bytes: manifest.size(),
        retained_byte_blocks: manifest.size() * 19 - 1,
    };
    assert!(node
        .retain_native_cell(&mut budgets, &mut retained, &cache, short, deadline())
        .is_err());
    assert_eq!(budgets.report().unwrap(), before);
    assert!(retained.contract(request.contract.operation).is_err());
}

#[test]
fn native_cell_failed_initial_copy_needs_a_separate_funded_repair_and_preserves_unknown_cost() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &dir.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let storage_source = fund(&mut node, 1000);
    let repair_source = fund(&mut node, 200);
    let (cache, manifest, bytes) = material(dir.path());
    let storage = request(storage_source, &manifest);
    let partial = CellStoreV1::open(&dir.path().join("partial.sqlite"), cache_config()).unwrap();
    partial
        .put_chunk(
            &manifest.chunks()[0],
            &bytes[..manifest.chunks()[0].size as usize],
        )
        .unwrap();
    let mut budgets =
        NativeBudgetStoreV1::open(&dir.path().join("budgets.sqlite"), config(&node)).unwrap();
    let path = dir.path().join("retention");
    let mut retained = CellRetentionStoreV1::create(&path, retention_config()).unwrap();
    assert!(node
        .retain_native_cell(
            &mut budgets,
            &mut retained,
            &partial,
            storage.clone(),
            deadline()
        )
        .is_err());
    let unknown = budgets.report().unwrap();
    assert!(node
        .retain_native_cell(
            &mut budgets,
            &mut retained,
            &cache,
            storage.clone(),
            deadline()
        )
        .is_err());
    assert_eq!(budgets.report().unwrap(), unknown);
    let resources = NativeBudgetResourcesV1::Repair {
        cpu_ns: 1_000_000_000,
        download_bytes: manifest.size(),
        upload_bytes: 0,
        attempts: 1,
    };
    let repair = NativeCellRepairRequestV1 {
        policy: NativeBudgetPolicyV1 {
            budget: [81; 32],
            source: repair_source,
            monetary_cap: 200,
            deadline: 40,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim: [82; 32],
            budget: [81; 32],
            subject: native_cell_repair_subject_v1(
                &retained,
                &storage.contract,
                [83; 32],
                [82; 32],
            ),
            beneficiary: public(1),
            monetary_reservation: 200,
            resource_reservation: resources,
        },
        obligation: storage.contract.operation,
        repair_operation: [83; 32],
    };
    let before_repair = budgets.report().unwrap();
    for cpu_ns in [0, 1] {
        let mut insufficient = repair.clone();
        insufficient.claim.resource_reservation = NativeBudgetResourcesV1::Repair {
            cpu_ns,
            download_bytes: manifest.size(),
            upload_bytes: 0,
            attempts: 1,
        };
        insufficient.policy.resource_cap = insufficient.claim.resource_reservation.clone();
        assert!(node
            .repair_native_cell(
                &mut budgets,
                &mut retained,
                &cache,
                insufficient,
                deadline()
            )
            .is_err());
        assert_eq!(budgets.report().unwrap(), before_repair);
    }
    let repaired = node
        .repair_native_cell(
            &mut budgets,
            &mut retained,
            &cache,
            repair.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(repaired.target.repair_bytes_committed, manifest.size());
    let observation = repaired.repair_cpu_observation.unwrap();
    assert!(observation.original_attempt && observation.observed_ns > 0);
    assert!(observation.observed_ns <= observation.ceiling_ns);
    let reconciled = node
        .retain_native_cell(&mut budgets, &mut retained, &partial, storage, deadline())
        .unwrap();
    assert_eq!(reconciled.replay, NativeBudgetReplayV1::Pending);
    assert!(reconciled.target.acknowledged);
    let charged = budgets.report().unwrap();
    let repeated = node
        .repair_native_cell(
            &mut budgets,
            &mut retained,
            &partial,
            repair.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(repeated.replay, NativeBudgetReplayV1::Done);
    assert_eq!(repeated.target_receipt, repaired.target_receipt);
    assert!(!repeated.repair_cpu_observation.unwrap().original_attempt);
    damage(&path);
    assert!(node
        .repair_native_cell(&mut budgets, &mut retained, &cache, repair, deadline())
        .is_err());
    assert_eq!(budgets.report().unwrap(), charged);
}

#[test]
#[cfg(target_os = "linux")]
fn native_cell_repair_cpu_owner_cannot_move_threads_or_resume_after_exhaustion() {
    let owner = RepairCpuOwner::start(1_000_000_000, deadline()).unwrap();
    std::thread::spawn(move || {
        let mut owner = owner;
        assert!(owner.check().is_err());
        assert!(owner.check().is_err());
        assert!(owner.finish(true).is_err());
    })
    .join()
    .unwrap();
    let mut tiny = RepairCpuOwner::start(1, deadline()).unwrap();
    assert!(tiny.check().is_err());
    tiny.ceiling_ns = u64::MAX;
    assert!(tiny.check().is_err());
    assert!(RepairCpuOwner::start(1_000_000_000, Instant::now() - Duration::from_secs(1)).is_err());
}

// Explicit finite fixture quota; covers the existing <=32MiB commit fixtures.
fn cache_config() -> trnm_data_availability::cell::CellCacheConfigV4 {
    trnm_data_availability::cell::CellCacheConfigV4 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
