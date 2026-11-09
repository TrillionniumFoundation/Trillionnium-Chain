//! Child of version_retention::tests: actual full catalog, targets and bytes.

use super::*;
use crate::cell::{
    CellReleaseLimitsV1, CellRetainedShardPlanFileV1, CellRetainedShardPlanRequestV1,
    CellRetainedShardPlanV1, CellRs46RepairBudgetV1, CellRs46ShardInputV1,
    CellRs46ShardPlacementV1, CellRs46ShardProviderConfigV1, CellRs46ShardProviderV1,
    CellVersionLoaderContextV1,
};

fn providers() -> [CellRs46ShardProviderConfigV1; 6] {
    std::array::from_fn(|slot| CellRs46ShardProviderConfigV1 {
        placement: CellRs46ShardPlacementV1 {
            provider_id: [101 + slot as u8; 32],
            responsible_owner: [111 + slot as u8; 32],
            administrator: [121 + slot as u8; 32],
            failure_domain: [131 + slot as u8; 32],
            domain_evidence: [141 + slot as u8; 32],
            repair_owner: [151 + slot as u8; 32],
        },
        owner_generation: 7,
        capacity_bytes: 64 * 4096,
        maximum_obligations: 64,
    })
}

fn request(store: &CellVersionRetentionStoreV3, chunks: usize) -> CellRetainedShardPlanRequestV1 {
    CellRetainedShardPlanRequestV1 {
        operation: [181; 32],
        expected_catalog: store.anchor(deadline()).unwrap(),
        current_height: 10,
        required_until_height: 90,
        providers: providers(),
        maximum_repairs_per_slot: 2,
        funding_operations: (0..chunks)
            .map(|chunk| {
                std::array::from_fn(|slot| {
                    let mut hash = Sha256::new();
                    hash.update(b"test-only-unfunded-plan-slot-identity");
                    hash.update((chunk as u32).to_be_bytes());
                    hash.update([slot as u8]);
                    hash.finalize().into()
                })
            })
            .collect(),
    }
}

fn acknowledge(
    store: &mut CellVersionRetentionStoreV3,
    contract: &CellVersionRetentionContractV3,
    source: &CellStoreV1,
) {
    store
        .reserve_version(
            contract.clone(),
            store.anchor(deadline()).unwrap(),
            deadline(),
        )
        .unwrap();
    store
        .acknowledge_version(contract.operation, source, deadline())
        .unwrap();
}

fn plan_digest(bytes: &[u8]) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-retained-shard-plan.v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

#[test]
fn retained_shard_plan_reopens_all_versions_six_actual_slots_and_four_slot_full_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contracts = [make_contract(&source, 1), make_contract(&source, 2)];
    let path = dir.path().join("catalog");
    let config = config(32);
    let mut catalog = CellVersionRetentionStoreV3::create(&path, config.clone()).unwrap();
    for contract in &contracts {
        acknowledge(&mut catalog, contract, &source);
    }
    let plan_path = dir.path().join("full-plan.crp1");
    let prepared = request(&catalog, 4);
    let file = CellRetainedShardPlanFileV1::create(
        &plan_path,
        &mut catalog,
        &source,
        prepared,
        deadline(),
    )
    .unwrap();
    let pin = file.commitment();
    assert_eq!(file.plan().roots().len(), 2);
    assert_eq!(file.plan().manifests().len(), 4);
    assert_eq!(file.plan().chunks().len(), 4);
    let original_wire = file.plan().encode();
    assert_eq!(
        CellRetainedShardPlanV1::decode_pinned(&original_wire, pin, deadline()).unwrap(),
        *file.plan()
    );
    let anchor = catalog.anchor(deadline()).unwrap();
    drop(file);
    drop(source);
    drop(catalog);
    fs::remove_file(dir.path().join("source.sqlite")).unwrap();
    let file = CellRetainedShardPlanFileV1::open(&plan_path, pin, deadline()).unwrap();
    let mut catalog = CellVersionRetentionStoreV3::open(&path, config, anchor).unwrap();
    let staging = cache(&dir.path().join("staging.sqlite"));
    let plan = file.read_current(&catalog, 11, deadline()).unwrap();
    plan.stage_from_catalog(&mut catalog, &staging, 11, deadline())
        .unwrap();
    let mut stores: [CellRs46ShardProviderV1; 6] = providers()
        .into_iter()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::create(&dir.path().join(format!("provider-{slot}")), config)
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    for chunk in plan.chunks() {
        for (slot, contract) in chunk.slots().iter().enumerate() {
            let (_, actual) = stores[slot]
                .publish(contract, contract.operation(), &staging, deadline())
                .unwrap();
            assert_eq!(actual.shard().id(), contract.codeword().shard_ids()[slot]);
        }
    }
    drop(staging);
    fs::remove_file(dir.path().join("staging.sqlite")).unwrap();
    let recovered = cache(&dir.path().join("recovered.sqlite"));
    for manifest in plan.manifests() {
        recovered
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
    }
    let input_limit: u64 = plan
        .chunks()
        .iter()
        .flat_map(|chunk| &chunk.slots()[..4])
        .map(|slot| slot.manifest().size())
        .sum();
    let reconstruction_limit: u64 = plan
        .chunks()
        .iter()
        .map(|chunk| {
            u64::from(chunk.binding().source_bytes())
                + chunk
                    .slots()
                    .iter()
                    .map(|slot| slot.manifest().size())
                    .sum::<u64>()
        })
        .sum();
    let end = deadline();
    let mut budget = CellRs46RepairBudgetV1::new(end, 4, input_limit, reconstruction_limit);
    for chunk in plan.chunks() {
        let wires: Vec<_> = (0..4)
            .map(|slot| {
                stores[slot]
                    .read(
                        chunk.binding(),
                        chunk.slots()[slot].operation(),
                        end,
                        &mut || Ok(()),
                    )
                    .unwrap()
                    .shard()
                    .encode()
            })
            .collect();
        let inputs: Vec<_> = wires
            .iter()
            .enumerate()
            .map(|(slot, wire)| CellRs46ShardInputV1 {
                index: slot as u8,
                wire,
            })
            .collect();
        let codeword = chunk.slots()[0].codeword();
        let actual = codeword
            .repair_chunk(chunk.binding(), codeword.id(), &inputs, &mut budget)
            .unwrap();
        let manifest = plan
            .manifests()
            .iter()
            .find(|manifest| manifest.id() == chunk.manifest())
            .unwrap();
        recovered
            .put_chunk(
                &manifest.chunks()[chunk.chunk_index() as usize],
                actual.source(),
            )
            .unwrap();
    }
    assert_eq!(budget.usage().attempts_committed, 4);
    for contract in &contracts {
        let model = contract.model.loader_context();
        let environment = contract.environment.loader_context();
        let expected = CellVersionLoaderContextV1 {
            commitment: contract.version.commitment(),
            model: &model,
            environment: &environment,
        };
        let actual = contract
            .version
            .verify_cached(
                &recovered,
                &expected,
                CellReleaseLimitsV1 {
                    max_payload_bytes: 4096,
                    max_chunks: 8,
                    deadline: end,
                },
            )
            .unwrap();
        assert_eq!(actual.payload_bytes, 34);
    }
    assert_eq!(fs::read(plan_path).unwrap(), original_wire);
}

#[test]
fn retained_shard_plan_pending_expired_or_added_catalog_roots_cannot_be_omitted() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(32)).unwrap();
    catalog
        .reserve_version(
            contract.clone(),
            catalog.anchor(deadline()).unwrap(),
            deadline(),
        )
        .unwrap();
    let output = dir.path().join("pending.crp1");
    let pending = request(&catalog, 2);
    assert!(CellRetainedShardPlanFileV1::create(
        &output,
        &mut catalog,
        &source,
        pending,
        deadline()
    )
    .is_err());
    assert!(!output.exists());
    catalog
        .acknowledge_version(contract.operation, &source, deadline())
        .unwrap();
    let prepared = request(&catalog, 2);
    let file =
        CellRetainedShardPlanFileV1::create(&output, &mut catalog, &source, prepared, deadline())
            .unwrap();
    assert!(file.read_current(&catalog, 90, deadline()).is_err());
    let next = make_contract(&source, 2);
    catalog
        .reserve_version(next, catalog.anchor(deadline()).unwrap(), deadline())
        .unwrap();
    assert!(file.read_current(&catalog, 11, deadline()).is_err());
    let mut expired = request(&catalog, 4);
    expired.current_height = 100;
    expired.required_until_height = 101;
    let expired_path = dir.path().join("expired.crp1");
    assert!(CellRetainedShardPlanFileV1::create(
        &expired_path,
        &mut catalog,
        &source,
        expired,
        deadline()
    )
    .is_err());
    assert!(!expired_path.exists());
}

#[test]
fn retained_shard_plan_requires_full_distinct_funding_roster_before_file_creation() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let mut cases = Vec::new();
    let mut omitted = request(&catalog, 2);
    omitted.funding_operations.pop();
    cases.push(omitted);
    let mut aliased = request(&catalog, 2);
    aliased.funding_operations[1][5] = aliased.funding_operations[0][0];
    cases.push(aliased);
    let mut reused = request(&catalog, 2);
    reused.funding_operations[0][0] = contract.objects[0].funding_operation;
    cases.push(reused);
    let mut provider = request(&catalog, 2);
    provider.providers[1] = provider.providers[0].clone();
    cases.push(provider);
    let mut history = request(&catalog, 2);
    history.providers[0].maximum_obligations = 1;
    cases.push(history);
    let mut capacity = request(&catalog, 2);
    capacity.providers[0].capacity_bytes = 4096;
    cases.push(capacity);
    for (index, prepared) in cases.into_iter().enumerate() {
        let path = dir.path().join(format!("refused-{index}.crp1"));
        assert!(CellRetainedShardPlanFileV1::create(
            &path,
            &mut catalog,
            &source,
            prepared,
            deadline()
        )
        .is_err());
        assert!(!path.exists());
    }
}

fn one_manifest_subset(plan: &CellRetainedShardPlanV1) -> Vec<u8> {
    let mut wire = b"CRP1".to_vec();
    wire.extend(plan.operation());
    wire.extend(plan.catalog_store());
    wire.extend(plan.catalog_anchor().encode());
    wire.extend(plan.retained_commitment());
    wire.extend(plan.retain_from_height().to_be_bytes());
    wire.extend(plan.retain_until_height().to_be_bytes());
    wire.extend((plan.roots().len() as u16).to_be_bytes());
    for root in plan.roots() {
        wire.extend(root.operation());
        wire.extend(root.contract_commitment());
        wire.extend(root.version());
    }
    wire.extend(1_u16.to_be_bytes());
    let manifest = plan.manifests()[0].encode();
    wire.extend((manifest.len() as u32).to_be_bytes());
    wire.extend(manifest);
    let chunks: Vec<_> = plan
        .chunks()
        .iter()
        .filter(|chunk| chunk.manifest() == plan.manifests()[0].id())
        .collect();
    wire.extend((chunks.len() as u16).to_be_bytes());
    for chunk in chunks {
        wire.extend(chunk.manifest());
        wire.extend(chunk.chunk_index().to_be_bytes());
        for slot in chunk.slots() {
            let bytes = slot.encode();
            wire.extend(slot.operation());
            wire.extend((bytes.len() as u32).to_be_bytes());
            wire.extend(bytes);
        }
    }
    wire
}

#[test]
fn retained_shard_plan_self_consistent_subset_still_fails_actual_owner_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let prepared = request(&catalog, 2);
    let original = CellRetainedShardPlanFileV1::create(
        &dir.path().join("full.crp1"),
        &mut catalog,
        &source,
        prepared,
        deadline(),
    )
    .unwrap();
    let bytes = one_manifest_subset(original.plan());
    let pin = plan_digest(&bytes);
    let subset = CellRetainedShardPlanV1::decode_pinned(&bytes, pin, deadline()).unwrap();
    assert_eq!(subset.manifests().len(), 1);
    assert!(subset
        .verify_current_catalog(&catalog, 11, deadline())
        .is_err());
    let path = dir.path().join("subset.crp1");
    fs::write(&path, bytes).unwrap();
    let supplied = CellRetainedShardPlanFileV1::open(&path, pin, deadline()).unwrap();
    assert!(supplied.read_current(&catalog, 11, deadline()).is_err());
}

#[test]
fn retained_shard_plan_namespace_pins_and_actual_immutable_file_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let source = cache(&dir.path().join("source.sqlite"));
    let contract = make_contract(&source, 1);
    let mut catalog =
        CellVersionRetentionStoreV3::create(&dir.path().join("catalog"), config(16)).unwrap();
    acknowledge(&mut catalog, &contract, &source);
    let prepared = request(&catalog, 2);
    let path = dir.path().join("full.crp1");
    let owner =
        CellRetainedShardPlanFileV1::create(&path, &mut catalog, &source, prepared, deadline())
            .unwrap();
    let wire = owner.plan().encode();
    assert!(CellRetainedShardPlanV1::decode_pinned(&wire, [8; 32], deadline()).is_err());
    let mut foreign = wire.clone();
    foreign[..4].copy_from_slice(b"CSP1");
    assert!(
        CellRetainedShardPlanV1::decode_pinned(&foreign, plan_digest(&foreign), deadline())
            .is_err()
    );
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(
        CellRetainedShardPlanV1::decode_pinned(&trailing, plan_digest(&trailing), deadline())
            .is_err()
    );
    let duplicate = request(&catalog, 2);
    assert!(CellRetainedShardPlanFileV1::create(
        &path,
        &mut catalog,
        &source,
        duplicate,
        deadline()
    )
    .is_err());
    assert_eq!(fs::read(&path).unwrap(), wire);
    let replacement = dir.path().join("replacement.crp1");
    fs::write(&replacement, &wire).unwrap();
    fs::rename(&replacement, &path).unwrap();
    assert!(owner.read(deadline()).is_err());
    #[cfg(unix)]
    {
        let reopened =
            CellRetainedShardPlanFileV1::open(&path, owner.commitment(), deadline()).unwrap();
        fs::hard_link(&path, dir.path().join("aliased.crp1")).unwrap();
        assert!(reopened.read(deadline()).is_err());
    }
}

#[path = "shard_plan_capacity.rs"]
mod capacity;
