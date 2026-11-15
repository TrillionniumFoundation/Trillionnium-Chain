//! Actual native funding, immutable CSP1 targets and original M12 replay state.

use super::*;
use trnm_data_availability::cell::{
    CellRs46ChunkBindingV1, CellRs46CodewordV1, CellRs46PlacementPolicyV1, CellRs46ShardContractV1,
    CellRs46ShardOwnerV1, CellRs46ShardPlacementV1, CellRs46ShardProviderConfigV1,
    CellRs46ShardProviderV1, CellRs46ShardRepairRequestV1,
};

fn shard_material(
    directory: &Path,
) -> (
    CellStoreV1,
    CellRs46ShardContractV1,
    CellRs46ShardProviderConfigV1,
    Vec<u8>,
) {
    let (cache, manifest, bytes) = material(directory);
    let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
        &manifest,
        manifest.id(),
        manifest.context(),
        0,
    )
    .unwrap();
    let bytes = &bytes[..manifest.chunks()[0].size as usize];
    let codeword = CellRs46CodewordV1::from_verified_chunk(&binding, bytes).unwrap();
    let placement = CellRs46PlacementPolicyV1 {
        codeword: codeword.id(),
        placements: std::array::from_fn(|slot| CellRs46ShardPlacementV1 {
            provider_id: [10 + slot as u8; 32],
            responsible_owner: public(slot as u64 + 1),
            administrator: [30 + slot as u8; 32],
            failure_domain: [40 + slot as u8; 32],
            domain_evidence: [50 + slot as u8; 32],
            repair_owner: public(slot as u64 + 1),
        }),
    };
    let config = CellRs46ShardProviderConfigV1 {
        placement: placement.placements[0].clone(),
        owner_generation: 7,
        capacity_bytes: 65_536,
        maximum_obligations: 16,
    };
    let wire = binding.encode_chunk(bytes).unwrap()[0].encode();
    let contract = CellRs46ShardContractV1::from_verified_shard(
        CellRs46ShardOwnerV1 {
            original_operation: [101; 32],
            provider_store: config.store_id().unwrap(),
            owner_generation: config.owner_generation,
            funding_operation: [102; 32],
            codeword: codeword.id(),
            placement: placement.id().unwrap(),
            slot: 0,
            context: manifest.context().clone(),
            retain_from_height: 1,
            retain_until_height: 20,
            maximum_repair_bytes: 3 * wire.len() as u64,
        },
        &binding,
        &codeword,
        &placement,
        &wire,
    )
    .unwrap();
    CellRs46ShardProviderV1::cache_shard(
        &contract,
        contract.operation(),
        &wire,
        &cache,
        deadline(),
    )
    .unwrap();
    (cache, contract, config, wire)
}

fn funded_shard(
    node: &mut Node,
    contract: &CellRs46ShardContractV1,
) -> NativeCellShardRetentionRequestV1 {
    let bytes = contract.manifest().size();
    let resources = NativeBudgetResourcesV1::Storage {
        retained_bytes: bytes,
        retained_byte_blocks: bytes
            * (contract.owner().retain_until_height - contract.owner().retain_from_height),
    };
    NativeCellShardRetentionRequestV1 {
        policy: NativeBudgetPolicyV1 {
            budget: [103; 32],
            source: fund(node, 1000),
            monetary_cap: 1000,
            deadline: 40,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim: contract.owner().funding_operation,
            budget: [103; 32],
            subject: contract
                .retention_contract()
                .commitment(contract.owner().provider_store),
            beneficiary: public(1),
            monetary_reservation: 1000,
            resource_reservation: resources,
        },
        contract: contract.clone(),
    }
}

fn funded_shard_repair(
    node: &mut Node,
    provider: &CellRs46ShardProviderV1,
    contract: &CellRs46ShardContractV1,
) -> NativeCellShardRepairRequestV1 {
    let resources = NativeBudgetResourcesV1::Repair {
        cpu_ns: 5_000_000_000,
        download_bytes: contract.manifest().size(),
        // Original complete CRS1 wire allowance, not observed WAN traffic.
        upload_bytes: contract.manifest().size(),
        attempts: 1,
    };
    NativeCellShardRepairRequestV1 {
        policy: NativeBudgetPolicyV1 {
            budget: [144; 32],
            source: fund(node, 400),
            monetary_cap: 400,
            deadline: 40,
            resource_cap: resources.clone(),
            max_inflight: 1,
        },
        claim: NativeBudgetClaimV1 {
            claim: [145; 32],
            budget: [144; 32],
            subject: native_cell_shard_repair_subject_v1(provider, contract, [146; 32], [145; 32]),
            beneficiary: public(1),
            monetary_reservation: 400,
            resource_reservation: resources,
        },
        binding: contract.binding().clone(),
        operation: contract.operation(),
        repair_operation: [146; 32],
    }
}

fn shard_ledger(path: &Path, operation: Hash) -> (u8, u64, u64) {
    rusqlite::Connection::open(path.join("retention.sqlite"))
        .unwrap()
        .query_row(
            "SELECT status,initial_bytes,repair_bytes FROM obligations WHERE operation=?1",
            [operation.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

#[test]
fn native_shard_real_funding_target_readback_and_repair_keep_original_debits() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &dir.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract, config, wire) = shard_material(dir.path());
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, config.clone()).unwrap();
    let request = funded_shard(&mut node, &contract);
    let journal = dir.path().join("budget.sqlite");
    let mut budgets = NativeBudgetStoreV1::open(&journal, super::config(&node)).unwrap();
    let first = node
        .retain_native_cell_shard(
            &mut budgets,
            &mut provider,
            &cache,
            request.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(first.native.replay, NativeBudgetReplayV1::New);
    assert_eq!(first.stored.shard().encode(), wire);
    assert_eq!(
        shard_ledger(&path, contract.operation()),
        (1, wire.len() as u64, 0)
    );
    let charged = budgets.report().unwrap();
    drop(cache);
    fs::remove_file(dir.path().join("source.cell")).unwrap();
    fs::remove_file(dir.path().join("cache.sqlite")).unwrap();
    drop(provider);
    drop(budgets);
    let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
    let mut provider = CellRs46ShardProviderV1::open(&path, config).unwrap();
    let mut budgets = NativeBudgetStoreV1::open(&journal, super::config(&node)).unwrap();
    let repeated = node
        .retain_native_cell_shard(
            &mut budgets,
            &mut provider,
            &empty,
            request.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(repeated.native.replay, NativeBudgetReplayV1::Done);
    assert_eq!(repeated.stored, first.stored);
    assert_eq!(budgets.report().unwrap(), charged);
    damage(&path);
    assert!(node
        .retain_native_cell_shard(&mut budgets, &mut provider, &empty, request, deadline())
        .is_err());
    assert_eq!(budgets.report().unwrap(), charged);
    let repair_cache =
        CellStoreV1::open(&dir.path().join("repair.sqlite"), cache_config()).unwrap();
    CellRs46ShardProviderV1::cache_shard(
        &contract,
        contract.operation(),
        &wire,
        &repair_cache,
        deadline(),
    )
    .unwrap();
    let repair = funded_shard_repair(&mut node, &provider, &contract);
    let fixed = node
        .repair_native_cell_shard(
            &mut budgets,
            &mut provider,
            &repair_cache,
            repair.clone(),
            deadline(),
        )
        .unwrap();
    assert_eq!(fixed.native.replay, NativeBudgetReplayV1::New);
    assert_eq!(fixed.stored.shard().encode(), wire);
    let cpu = fixed.native.repair_cpu_observation.unwrap();
    assert!(cpu.original_attempt && cpu.observed_ns <= cpu.ceiling_ns);
    assert_eq!(
        shard_ledger(&path, contract.operation()),
        (1, wire.len() as u64, wire.len() as u64)
    );
    let charged = budgets.report().unwrap();
    drop(repair_cache);
    fs::remove_file(dir.path().join("repair.sqlite")).unwrap();
    let replay = node
        .repair_native_cell_shard(&mut budgets, &mut provider, &empty, repair, deadline())
        .unwrap();
    assert_eq!(replay.native.replay, NativeBudgetReplayV1::Done);
    assert!(
        !replay
            .native
            .repair_cpu_observation
            .unwrap()
            .original_attempt
    );
    assert_eq!(budgets.report().unwrap(), charged);
}

#[test]
fn native_shard_pending_initial_effect_cannot_dispatch_even_with_source_present() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open_node(&dir.path().join("node"), StateBackend::AuthenticatedV1);
    let (cache, contract, config, wire) = shard_material(dir.path());
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, config).unwrap();
    let request = funded_shard(&mut node, &contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&dir.path().join("budget.sqlite"), super::config(&node)).unwrap();
    budgets
        .open_budget(&mut node, request.policy.clone())
        .unwrap();
    budgets.reserve(&mut node, request.claim.clone()).unwrap();
    provider
        .reserve(&contract, contract.operation(), deadline())
        .unwrap();
    assert_eq!(
        budgets
            .begin_effect_in_window(
                &mut node,
                request.claim.claim,
                contract.operation(),
                request.claim.subject,
                1,
                20
            )
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    let charged = budgets.report().unwrap();
    assert!(node
        .retain_native_cell_shard(
            &mut budgets,
            &mut provider,
            &cache,
            request.clone(),
            deadline()
        )
        .is_err());
    assert_eq!(shard_ledger(&path, contract.operation()), (0, 0, 0));
    assert_eq!(budgets.report().unwrap(), charged);
    // Completion of the already-recorded original dispatch arrives late. The
    // next native call sees Pending and only reconciles these actual bytes.
    provider
        .publish(&contract, contract.operation(), &cache, deadline())
        .unwrap();
    let empty = CellStoreV1::open(&dir.path().join("empty.sqlite"), cache_config()).unwrap();
    let replay = node
        .retain_native_cell_shard(&mut budgets, &mut provider, &empty, request, deadline())
        .unwrap();
    assert_eq!(replay.native.replay, NativeBudgetReplayV1::Pending);
    assert_eq!(replay.stored.shard().encode(), wire);
    assert_eq!(
        shard_ledger(&path, contract.operation()),
        (1, wire.len() as u64, 0)
    );
}

#[test]
fn native_shard_unknown_repair_never_reissues_and_foreign_owner_cannot_retire() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open_node(
        &dir.path().join("node"),
        StateBackend::PermanentAccountGrowthV2,
    );
    let (cache, contract, config, wire) = shard_material(dir.path());
    let path = dir.path().join("provider");
    let mut provider = CellRs46ShardProviderV1::create(&path, config).unwrap();
    let request = funded_shard(&mut node, &contract);
    let mut budgets =
        NativeBudgetStoreV1::open(&dir.path().join("budget.sqlite"), super::config(&node)).unwrap();
    node.retain_native_cell_shard(&mut budgets, &mut provider, &cache, request, deadline())
        .unwrap();
    let settings = crate::Settings::development_with_profiles(
        Some(2),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut foreign = Node::open(&dir.path().join("foreign"), settings, 1).unwrap();
    let error = foreign
        .retire_native_cell_shard(
            &budgets,
            &mut provider,
            contract.binding(),
            contract.operation(),
            deadline(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("BUDGET_NATIVE_CONTEXT"));
    assert!(node
        .retire_native_cell_shard(
            &budgets,
            &mut provider,
            contract.binding(),
            contract.operation(),
            deadline()
        )
        .is_err());
    damage(&path);
    let repair = funded_shard_repair(&mut node, &provider, &contract);
    budgets
        .open_budget(&mut node, repair.policy.clone())
        .unwrap();
    budgets.reserve(&mut node, repair.claim.clone()).unwrap();
    assert_eq!(
        budgets
            .begin_effect_in_window(
                &mut node,
                repair.claim.claim,
                repair.repair_operation,
                repair.claim.subject,
                1,
                20
            )
            .unwrap(),
        NativeBudgetReplayV1::New
    );
    let mut stopped = false;
    let outcome = provider.repair(
        CellRs46ShardRepairRequestV1 {
            binding: contract.binding(),
            operation: contract.operation(),
            repair_operation: repair.repair_operation,
            cache: &cache,
            deadline: deadline(),
        },
        &mut || {
            let count: u64 = rusqlite::Connection::open(path.join("retention.sqlite"))?.query_row(
                "SELECT count(*) FROM repairs WHERE operation=?1",
                [repair.repair_operation.as_slice()],
                |row| row.get(0),
            )?;
            if count != 0 {
                stopped = true;
                return Err(CellErrorV1::Invalid("stop after original repair debit"));
            }
            Ok(())
        },
    );
    assert!(outcome.is_err() && stopped);
    let original = shard_ledger(&path, contract.operation());
    assert_eq!(original, (1, wire.len() as u64, wire.len() as u64));
    let charged = budgets.report().unwrap();
    assert!(node
        .repair_native_cell_shard(&mut budgets, &mut provider, &cache, repair, deadline())
        .is_err());
    assert_eq!(shard_ledger(&path, contract.operation()), original);
    assert_eq!(budgets.report().unwrap(), charged);
}
