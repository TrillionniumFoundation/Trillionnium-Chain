//! Single-operator research composition of existing native funding/M12 owners.
//! Known development keys and synthetic ledger coins are explicit. This entry
//! grants no actual customer demand, provider payment, FinalUse or activation.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
    time::Instant,
};
use trnm_data_availability::cell::*;
use trnm_pon_node::{
    development_public, NativeCellPagedRetainedShardPlanTargetsV2,
    NativeCellRetainedShardVerificationBudgetV1, NativeCellRetentionRequestV1,
    NativeCellShardGroupJournalConfigV3, NativeCellShardGroupJournalV3,
    NativeCellVersionRetentionRequestV3, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_service_settlement::native_budget::{
    NativeBudgetClaimV1, NativeBudgetConfigV1, NativeBudgetPolicyV1, NativeBudgetReplayV1,
    NativeBudgetResourcesV1, NativeBudgetStoreV1, NativeFundingSourceV1,
};

use super::original::CellResearchRetentionInputsV2;

mod funding;
mod groups_v3;
mod recovery;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const CAPTURE_BOUND: u64 = 512 * 1024 * 1024;
const MAX_CHUNKS: usize = 128;

fn check(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn before(deadline: Instant) -> Result<()> {
    check(
        Instant::now() < deadline,
        "original native research deadline",
    )
}
fn identity(operation: Hash, label: &[u8], index: usize) -> Hash {
    hash(
        b"trnm.cell-native-shard-research.v2\0",
        &[&operation, label, &(index as u64).to_be_bytes()],
    )
}
fn save(path: &Path, value: &Value) -> Result<()> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(&serde_json::to_vec_pretty(value)?)?;
    output.sync_all()?;
    Ok(())
}
fn empty_cache(path: &Path) -> Result<CellStoreV1> {
    Ok(CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 1024 * 1024 * 1024,
            max_logical_bytes: CAPTURE_BOUND,
            max_chunk_rows: 2_048,
            max_manifest_rows: 128,
        },
    )?)
}
/// New V3 temporary wire metadata admission. Input and consumer caches retain
/// their original 128-manifest limit; wire rows have a separate explicit grant.
fn wire_cache<'a>(
    path: &Path,
    manifests: impl Iterator<Item = &'a CellManifestV1>,
    deadline: Instant,
) -> Result<(CellStoreV1, Value)> {
    before(deadline)?;
    let mut manifest_union = BTreeMap::new();
    for manifest in manifests {
        before(deadline)?;
        if let Some(previous) = manifest_union.insert(manifest.id(), manifest) {
            check(previous == manifest, "canonical wire manifest identity")?;
        }
    }
    let mut chunk_union = BTreeMap::new();
    for manifest in manifest_union.values() {
        for chunk in manifest.chunks() {
            if let Some(size) = chunk_union.insert(chunk.sha256, chunk.size) {
                check(size == chunk.size, "canonical wire chunk size")?;
            }
        }
    }
    let logical = chunk_union.values().try_fold(0_u64, |sum, size| {
        sum.checked_add(u64::from(*size))
            .ok_or("wire-cache logical-byte overflow")
    })?;
    let max_manifests = 6 * MAX_CHUNKS as u64;
    check(
        !manifest_union.is_empty()
            && manifest_union.len() as u64 <= max_manifests
            && chunk_union.len() <= 2_048
            && logical <= CAPTURE_BOUND,
        "complete wire-cache union exceeds explicit V3 rows or original byte budget",
    )?;
    check(!path.exists(), "fresh research-owned wire cache")?;
    let cache = CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 1024 * 1024 * 1024,
            max_logical_bytes: CAPTURE_BOUND,
            max_chunk_rows: 2_048,
            max_manifest_rows: max_manifests,
        },
    )?;
    let usage = cache.cache_usage()?;
    check(
        usage.manifest_rows == 0 && usage.chunk_rows == 0 && usage.logical_bytes == 0,
        "actually empty admitted wire cache",
    )?;
    before(deadline)?;
    Ok((
        cache,
        json!({
            "profile":"native-grouped-temporary-wire-cache-v3",
            "expected_manifest_rows":manifest_union.len(), "expected_chunk_rows":chunk_union.len(),
            "expected_logical_bytes":logical, "max_manifest_rows":max_manifests,
            "max_chunk_rows":2048, "max_logical_bytes":CAPTURE_BOUND,
            "max_database_bytes":1024_u64*1024*1024,
            "input_and_consumer_max_manifest_rows":128,
            "new_temporary_wire_metadata_grant":true,
            "original_128_temporary_wire_gate_passed":false,
            "full_payload_profile_not_unconditionally_supported":true,
            "original_absolute_deadline":true,
        }),
    ))
}
fn wire_usage(cache: &CellStoreV1, admission: &Value) -> Result<Value> {
    let usage = cache.cache_usage()?;
    check(
        usage.manifest_rows
            == admission["expected_manifest_rows"]
                .as_u64()
                .ok_or("wire rows")?
            && usage.chunk_rows
                == admission["expected_chunk_rows"]
                    .as_u64()
                    .ok_or("wire chunks")?
            && usage.logical_bytes
                == admission["expected_logical_bytes"]
                    .as_u64()
                    .ok_or("wire bytes")?,
        "actual complete wire-cache union readback",
    )?;
    Ok(
        json!({"manifest_rows":usage.manifest_rows,"chunk_rows":usage.chunk_rows,
        "logical_bytes":usage.logical_bytes}),
    )
}
fn remove_cache(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    for extension in ["sqlite-wal", "sqlite-shm"] {
        let sidecar = path.with_extension(extension);
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    Ok(())
}
fn codec_json(usage: CellRs46RepairUsageV1) -> Value {
    json!({
        "attempts_committed": usage.attempts_committed,
        "input_bytes_committed": usage.input_bytes_committed,
        "reconstruction_bytes_committed": usage.reconstruction_bytes_committed,
        "cache_bytes_committed": usage.cache_bytes_committed,
    })
}

/// The retained-plan union deduplicates manifests, never distinct indices
/// sharing the same chunk bytes. Keep exactly that canonical binding order.
fn canonical_manifest_union(version: &CellVersionManifestV1) -> BTreeMap<Hash, &CellManifestV1> {
    version.manifests().iter().map(|m| (m.id(), m)).collect()
}

fn provider_configs(
    operation: Hash,
    version: &CellVersionManifestV1,
) -> Result<[CellRs46ShardProviderConfigV1; 6]> {
    let union = canonical_manifest_union(version);
    let chunks: Vec<_> = union.values().flat_map(|m| m.chunks()).collect();
    check(
        !chunks.is_empty() && chunks.len() <= MAX_CHUNKS,
        "explicit fresh provider obligation admission",
    )?;
    let header = (MAX_CELL_RS46_SHARD_WIRE_BYTES_V1 - MAX_CELL_RS46_SHARD_BYTES_V1) as u64;
    let capacity: u64 = chunks
        .iter()
        .map(|chunk| (header + u64::from(chunk.size).div_ceil(4)).div_ceil(4096) * 4096)
        .sum();
    let mut configurations = Vec::new();
    for slot in 0..6 {
        configurations.push(CellRs46ShardProviderConfigV1 {
            placement: CellRs46ShardPlacementV1 {
                provider_id: identity(operation, b"provider", slot),
                responsible_owner: development_public(slot as u64 + 1)?,
                administrator: identity(operation, b"declared-local-administrator", slot),
                failure_domain: identity(operation, b"declared-local-domain", slot),
                domain_evidence: identity(operation, b"local-domain-description", slot),
                repair_owner: development_public(slot as u64 + 1)?,
            },
            owner_generation: 1,
            capacity_bytes: capacity,
            maximum_obligations: chunks.len() as u32,
        });
    }
    configurations
        .try_into()
        .map_err(|_| "six provider configurations".into())
}

fn storage_resources(bytes: u64, from: u64, until: u64) -> Result<NativeBudgetResourcesV1> {
    let span = until.checked_sub(from).ok_or("native retention window")?;
    Ok(NativeBudgetResourcesV1::Storage {
        retained_bytes: bytes,
        retained_byte_blocks: bytes.checked_mul(span).ok_or("byte-block overflow")?,
    })
}

/// Only new research-owned arena payloads are destroyed. Immutable descriptors,
/// obligation history and M12 intents remain, so original recovery must repair
/// the original targets and cannot treat structural loss as fresh authority.
fn destroy_payload(path: &Path, deadline: Instant) -> Result<u64> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let bytes = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let zeros = [0_u8; 64 * 1024];
    let mut remaining = bytes;
    while remaining != 0 {
        before(deadline)?;
        let size = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..size])?;
        remaining -= size as u64;
    }
    file.sync_all()?;
    before(deadline)?;
    Ok(bytes)
}

pub(super) fn retain(
    inputs: CellResearchRetentionInputsV2<'_>,
    report: &mut Value,
) -> Result<CellStoreV1> {
    let CellResearchRetentionInputsV2 {
        operation,
        output,
        deadline,
        version,
        snapshot,
        content,
        model_owner,
        environment_owner,
        source,
        source_path,
        received,
        received_path,
    } = inputs;
    before(deadline)?;
    report["stage"] = json!("native development funding and complete retained owner");
    report["native_shard_cycle"] = json!({
        "profile": "native-funded-grouped-paged-rs46-research-v3", "complete": false,
        "known_development_keys": true, "native_ledger_coins_are_development_only": true,
        "independent_real_money_funding": false, "service_fee_paid": false,
        "independent_failure_domains": false, "customer_demand_qualified": false,
        "hepta_final_use": false, "production_activation": false,
        "original_absolute_deadline": true, "cts1": hex::encode(snapshot.commitment()),
    });
    let union = canonical_manifest_union(version);
    let chunks = union.values().map(|m| m.chunks().len()).sum::<usize>();
    let payload = version
        .manifests()
        .iter()
        .map(CellManifestV1::size)
        .sum::<u64>();
    check(
        payload <= CAPTURE_BOUND && (1..=MAX_CHUNKS).contains(&chunks),
        "bounded native research payload and original chunks",
    )?;
    let configurations = provider_configs(operation, version)?;
    let directory = output.join("native-shards");
    fs::create_dir(&directory)?;
    let node_path = directory.join("node");
    let mut node = funding::open_node(&node_path)?;
    let member_count = version.manifests().len();
    let owner = development_public(1)?;
    let grants = groups_v3::funding_grants(member_count, chunks)?;
    let sources = funding::fund_all(
        &mut node,
        &grants,
        &directory.join("funding.jsonl"),
        deadline,
    )?;
    let current_height = node.active()?.1;
    check(
        current_height < funding::REPAIR_DEADLINE,
        "native funding precedes original repair expiry",
    )?;
    let config = CellVersionRetentionConfigV3 {
        retention: CellRetentionConfigV1 {
            store_id: identity(operation, b"catalog", 0),
            capacity_bytes: CAPTURE_BOUND,
            maximum_obligations: 128,
        },
        maximum_versions: 16,
        maximum_metadata_bytes: 64 << 20,
    };
    let catalog_path = directory.join("catalog");
    let mut catalog = CellVersionRetentionStoreV3::create(&catalog_path, config.clone())?;
    let contract = CellVersionRetentionContractV3 {
        operation,
        funding_operation: identity(operation, b"root-claim", 0),
        responsible_owner: owner,
        failure_domain: identity(operation, b"one-actual-local-host", 0),
        replica_index: 0,
        required_replicas: 1,
        retain_from_height: current_height,
        retain_until_height: funding::RETAIN_UNTIL,
        repair_deadline_height: funding::REPAIR_DEADLINE,
        version: version.clone(),
        model: CellVersionLoaderPinV3::from_context(model_owner),
        environment: CellVersionLoaderPinV3::from_context(environment_owner),
        tensor_model: Some(snapshot.tensors().clone()),
        snapshot: None,
        objects: version
            .manifests()
            .iter()
            .enumerate()
            .map(|(index, m)| CellRetentionContractV1 {
                operation: identity(operation, b"member", index),
                funding_operation: identity(operation, b"member-claim", index),
                manifest: m.clone(),
                retain_from_height: current_height,
                retain_until_height: funding::RETAIN_UNTIL,
                maximum_repair_bytes: m.size(),
                successor: None,
            })
            .collect(),
    };
    let mut members = Vec::new();
    for (index, object) in contract.objects.iter().enumerate() {
        let (policy, claim) = funding::policy_claim(
            operation,
            b"member-budget",
            index,
            sources[index],
            (
                object.funding_operation,
                object.commitment(catalog.store_id()),
                owner,
            ),
            storage_resources(
                object.manifest.size(),
                current_height,
                object.retain_until_height,
            )?,
        );
        members.push(NativeCellRetentionRequestV1 {
            policy,
            claim,
            contract: object.clone(),
        });
    }
    let (policy, claim) = funding::policy_claim(
        operation,
        b"root-budget",
        0,
        sources[member_count],
        (
            contract.funding_operation,
            catalog.contract_commitment(&contract)?,
            owner,
        ),
        storage_resources(payload, current_height, contract.retain_until_height)?,
    );
    let root = NativeCellVersionRetentionRequestV3 {
        policy,
        claim,
        expected_catalog: catalog.anchor(deadline)?,
        contract,
        members,
    };
    let journal_path = directory.join("budgets.sqlite");
    let budget_config = funding::budget_config(&node);
    let mut budgets = NativeBudgetStoreV1::open(&journal_path, budget_config.clone())?;
    let root_readback = node.retain_native_cell_version(
        &mut budgets,
        &mut catalog,
        &received,
        root.clone(),
        deadline,
    )?;
    check(
        root_readback.replay == NativeBudgetReplayV1::New
            && root_readback.members.len() == member_count,
        "native root and every member effect",
    )?;
    let plan_path = directory.join("paged-plan");
    let expected_catalog = catalog.anchor(deadline)?;
    let mut plan_file = CellPagedRetainedShardPlanFileV2::create(
        &plan_path,
        &mut catalog,
        CellPagedRetainedShardPlanRequestV2 {
            operation: identity(operation, b"plan", 0),
            expected_catalog,
            current_height,
            required_until_height: funding::REPAIR_DEADLINE,
            providers: configurations.clone(),
            funding_operations: (0..chunks)
                .map(|chunk| {
                    std::array::from_fn(|slot| {
                        identity(operation, b"shard-claim", chunk * 6 + slot)
                    })
                })
                .collect(),
            maximum_repairs_per_slot: 1,
            chunks_per_page: 32,
        },
        deadline,
    )?;
    let mut providers = create_providers(&directory, &configurations)?;
    let storage = groups_v3::storage(operation, &plan_file, &sources, member_count, deadline)?;
    let repairs = groups_v3::repair(
        operation,
        &plan_file,
        storage.clone(),
        &sources,
        member_count,
        &providers,
        deadline,
    )?;
    let wire_bytes = storage
        .groups
        .iter()
        .flat_map(|group| &group.children)
        .try_fold(0_u64, |total, child| {
            total
                .checked_add(child.contract.manifest().size())
                .ok_or("native grouped wire-byte overflow")
        })?;
    let storage_parents = storage.groups.len();
    let repair_parents = repairs.groups.len();
    let child_journal_path = directory.join("children-v3.sqlite");
    let child_config = NativeCellShardGroupJournalConfigV3 {
        network: node.settings().network(),
        parameters: node.settings().parameters(),
        genesis: node.settings().genesis(),
        plan: plan_file.commitment(),
        owner_generation: configurations[0].owner_generation,
    };
    let mut child_journal =
        NativeCellShardGroupJournalV3::create(&child_journal_path, child_config.clone())?;
    let delivery_path = directory.join("delivery.sqlite");
    let (delivery, storage_wire_admission) = wire_cache(
        &delivery_path,
        storage
            .groups
            .iter()
            .flat_map(|group| &group.children)
            .map(|child| child.contract.manifest()),
        deadline,
    )?;
    save(
        &directory.join("storage-wire-cache-config.json"),
        &storage_wire_admission,
    )?;
    let mut verification = NativeCellRetainedShardVerificationBudgetV1::new(
        deadline,
        (2 * chunks) as u32,
        2 * wire_bytes,
        2 * (wire_bytes + payload),
    );
    let retained = node.retain_native_cell_grouped_shard_plan_v3(
        &mut budgets,
        NativeCellPagedRetainedShardPlanTargetsV2 {
            catalog: &mut catalog,
            plan_file: &plan_file,
            providers: &mut providers,
            cache: &delivery,
        },
        storage,
        &mut child_journal,
        &mut verification,
    )?;
    check(
        retained.children == 6 * chunks
            && retained.parents.len() == storage_parents
            && retained
                .parents
                .iter()
                .all(|parent| parent.replay == NativeBudgetReplayV1::Done),
        "complete native initial slot readback",
    )?;
    let anchor = catalog.anchor(deadline)?;
    let plan_pin = plan_file.commitment();
    save(
        &directory.join("native-initial.json"),
        &json!({
            "root_effect": hex::encode(root_readback.effect),
            "root_receipt": hex::encode(root_readback.target_receipt),
            "members": member_count, "children": retained.children, "m12_storage_parents": retained.parents.len(), "pages": plan_file.plan().page_count(),
            "catalog_anchor": hex::encode(anchor.encode()), "plan": hex::encode(plan_pin),
            "verification": codec_json(verification.usage()),
            "codec": codec_json(verification.codec_usage()),
            "m12": budgets.report()?, "child_journal": child_journal.report(deadline)?,
            "wire_cache_admission":storage_wire_admission,
            "wire_cache_actual":wire_usage(&delivery,&storage_wire_admission)?,
        }),
    )?;
    report["m12_funding_admitted"] = json!(true);
    report["native_shard_cycle"]["initial_native_slots"] = json!(retained.children);
    report["native_shard_cycle"]["m12_parent_claims_expected"] = json!(sources.len());
    report["native_shard_cycle"]["v3_children"] = json!(8 * chunks);
    report["native_shard_cycle"]["logical_work_items"] = json!(member_count + 1 + 8 * chunks);
    report["native_shard_cycle"]["storage_parent_groups"] = json!(storage_parents);
    report["native_shard_cycle"]["repair_parent_groups"] = json!(repair_parents);
    drop(plan_file);
    drop(catalog);
    drop(providers);
    drop(child_journal);
    drop(budgets);
    drop(node);
    drop(source);
    drop(received);
    drop(delivery);
    remove_cache(source_path)?;
    remove_cache(received_path)?;
    remove_cache(&delivery_path)?;
    report["stage"] = json!("destroy two original provider payloads and cold reopen owners");
    let catalog_destroyed = destroy_payload(&catalog_path.join("objects/payload.arena"), deadline)?;
    let mut destroyed = Vec::new();
    for slot in [4, 5] {
        destroyed.push(destroy_payload(
            &directory.join(format!("provider-{slot}/payload.arena")),
            deadline,
        )?);
    }
    node = funding::open_node(&node_path)?;
    budgets = NativeBudgetStoreV1::open(&journal_path, budget_config)?;
    catalog = CellVersionRetentionStoreV3::open(&catalog_path, config, anchor)?;
    plan_file = CellPagedRetainedShardPlanFileV2::open(&plan_path, plan_pin, deadline)?;
    providers = open_providers(&directory, &configurations)?;
    child_journal = NativeCellShardGroupJournalV3::open(&child_journal_path, child_config)?;
    let (empty_delivery, repair_wire_admission) = wire_cache(
        &directory.join("repair-delivery.sqlite"),
        repairs
            .groups
            .iter()
            .flat_map(|group| &group.children)
            .map(|child| child.contract.manifest()),
        deadline,
    )?;
    save(
        &directory.join("repair-wire-cache-config.json"),
        &repair_wire_admission,
    )?;
    let native_recovery = recovery::repair_native(recovery::NativeRecovery {
        node: &mut node,
        budgets: &mut budgets,
        catalog: &mut catalog,
        file: &plan_file,
        providers: &mut providers,
        cache: &empty_delivery,
        request: repairs,
        journal: &mut child_journal,
        payload,
        wire_bytes,
        deadline,
        output: &directory,
    })?;
    let consumer = empty_cache(&output.join("consumer.sqlite"))?;
    let restored = recovery::restore_consumer(recovery::ConsumerRestore {
        file: &plan_file,
        providers: &mut providers,
        consumer: &consumer,
        version,
        content,
        model: model_owner,
        environment: environment_owner,
        payload,
        wire_bytes,
        deadline,
    })?;
    save(
        &directory.join("native-final.json"),
        &json!({
            "recovery": native_recovery, "restore": restored,
            "m12": budgets.report()?, "child_journal": child_journal.report(deadline)?,
            "wire_cache_admission":repair_wire_admission,
            "wire_cache_actual":wire_usage(&empty_delivery,&repair_wire_admission)?,
        }),
    )?;
    let expected_funding_owner = hex::encode(development_public(0)?);
    let mut live_rows = Vec::with_capacity(sources.len());
    let mut live_matches = true;
    let mut live_anchor = None;
    for (index, (source, (beneficiary, amount))) in sources.iter().zip(&grants).enumerate() {
        before(deadline)?;
        let observed = node.native_funding_observation(*source)?;
        let anchor = observed.anchor;
        let same_anchor = live_anchor
            .as_ref()
            .is_none_or(|expected| expected == &anchor);
        live_anchor = Some(anchor);
        let matches = same_anchor
            && observed.source == *source
            && observed.row.as_ref().is_some_and(|row| {
                row["status"].as_str() == Some("reserved")
                    && row.get("output") == Some(&Value::Null)
                    && row["owner"].as_str() == Some(expected_funding_owner.as_str())
                    && row["remaining"].as_u64() == Some(*amount)
                    && row["provider"].as_str() == Some(hex::encode(beneficiary).as_str())
                    && row["deadline"]
                        .as_u64()
                        .is_some_and(|until| until > anchor.height)
            });
        live_matches &= matches;
        live_rows.push(json!({"index":index,"source":source.key(),"expected_amount":amount,
            "expected_provider":hex::encode(beneficiary),"matches_expected":matches,"row":observed.row,
            "anchor":{"network":hex::encode(anchor.network),"parameters":hex::encode(anchor.parameters),
                "genesis":hex::encode(anchor.genesis),"block":hex::encode(anchor.block),
                "state_root":hex::encode(anchor.state_root),"height":anchor.height,"generation":anchor.generation}}));
    }
    save(
        &directory.join("native-current-funding.json"),
        &json!({"all_match":live_matches,
        "sources":live_rows,"cancellations_submitted":false,"payments_submitted":false}),
    )?;
    check(
        live_matches,
        "all original native parent sources remain actually funded",
    )?;
    report["native_shard_cycle"]["all_parent_tasks_currently_funded"] = json!(true);
    let actual_claims = budgets.report()?["claim_count"]
        .as_u64()
        .ok_or("actual M12 claim count")?;
    check(
        actual_claims == sources.len() as u64,
        "actual complete original M12 parent claim count",
    )?;
    report["native_shard_cycle"]["m12_parent_claims"] = json!(actual_claims);
    report["cold_restore"] = json!({
        "source_cache_absent": !source_path.exists(),
        "bep52_cache_absent": !received_path.exists(),
        "retained_from_bep52_received_cache": true, "anchored_reopen": true,
        "actual_target_readback": true, "consumer_chunks": consumer.cache_usage()?.chunk_rows,
        "m12_funding_admitted": true, "native_development_ledger": true,
        "retention_heights_are_research_terms": true, "native_ledger_height_enforced": true,
        "native_erasure_shard_recovery": true, "source_catalog_arena_overwritten_bytes": catalog_destroyed,
        "destroyed_provider_arena_bytes": destroyed,
        "four_original_shard_slots": [0, 1, 2, 3],
        "source_catalog_not_used_for_reconstruction": true,
        "source_catalog_payload_repaired":false,
        "root_member_payload_current_readback_after_catalog_overwrite":false,
        "grouped_child_journal_cold_reopened": true,
        "parent_settlement_on_hold": true, "future_retention_positive": false,
        "native_task_payment": false, "cancellation_used": false,
    });
    before(deadline)?;
    report["native_shard_cycle"]["wire_cache_metadata_grant"] = json!({
        "storage":storage_wire_admission,"repair":repair_wire_admission,
        "original_128_temporary_wire_gate_passed":false,
    });
    report["native_shard_cycle"]["complete"] = json!(true);
    report["native_shard_cycle"]["chunks"] = json!(chunks);
    report["native_shard_cycle"]["pages"] = json!(plan_file.plan().page_count());
    report["native_shard_cycle"]["recovery"] = native_recovery;
    report["native_shard_cycle"]["restore"] = restored;
    Ok(consumer)
}

fn create_providers(
    directory: &Path,
    configurations: &[CellRs46ShardProviderConfigV1; 6],
) -> Result<[CellRs46ShardProviderV1; 6]> {
    let providers: Vec<_> = configurations
        .iter()
        .cloned()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::create(&directory.join(format!("provider-{slot}")), config)
        })
        .collect::<std::result::Result<_, _>>()?;
    providers
        .try_into()
        .map_err(|_| "six created providers".into())
}
fn open_providers(
    directory: &Path,
    configurations: &[CellRs46ShardProviderConfigV1; 6],
) -> Result<[CellRs46ShardProviderV1; 6]> {
    let providers: Vec<_> = configurations
        .iter()
        .cloned()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::open(&directory.join(format!("provider-{slot}")), config)
        })
        .collect::<std::result::Result<_, _>>()?;
    providers
        .try_into()
        .map_err(|_| "six reopened providers".into())
}

#[cfg(test)]
mod tests;
