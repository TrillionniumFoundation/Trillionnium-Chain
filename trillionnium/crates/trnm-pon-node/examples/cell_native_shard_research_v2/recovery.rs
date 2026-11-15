use super::*;
use std::collections::BTreeSet;
use trnm_pon_node::{
    NativeCellGroupedShardRecoveryBudgetV3, NativeCellGroupedShardRepairRequestV3,
    NativeCellShardGroupJournalV3, NativeCellShardRecoveryLimitsV1,
};

fn usage_json(usage: trnm_pon_node::NativeCellShardRecoveryUsageV1) -> Value {
    json!({
        "plan_attempts_committed": usage.plan_attempts_committed,
        "provider_reads_committed": usage.provider_reads_committed,
        "input_bytes_committed": usage.input_bytes_committed,
        "reconstruction_bytes_committed": usage.reconstruction_bytes_committed,
        "repairs_committed": usage.repairs_committed,
        "repair_bytes_committed": usage.repair_bytes_committed,
        "cpu_ns_committed": usage.cpu_ns_committed,
    })
}

fn cpu_allowance(deadline: Instant) -> Result<u64> {
    before(deadline)?;
    let remaining = u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_nanos(),
    )?;
    check(remaining > 0, "remaining original CPU/wall allowance")?;
    Ok(remaining)
}

fn anchor_json(anchor: trnm_service_settlement::native_budget::NativeBudgetAnchorV1) -> Value {
    json!({
        "network": hex::encode(anchor.network),
        "parameters": hex::encode(anchor.parameters),
        "genesis": hex::encode(anchor.genesis),
        "block": hex::encode(anchor.block),
        "state_root": hex::encode(anchor.state_root),
        "height": anchor.height,
        "generation": anchor.generation,
    })
}

pub(super) struct NativeRecovery<'a> {
    pub node: &'a mut Node,
    pub budgets: &'a mut NativeBudgetStoreV1,
    pub catalog: &'a mut CellVersionRetentionStoreV3,
    pub file: &'a CellPagedRetainedShardPlanFileV2,
    pub providers: &'a mut [CellRs46ShardProviderV1; 6],
    pub cache: &'a CellStoreV1,
    pub request: NativeCellGroupedShardRepairRequestV3,
    pub journal: &'a mut NativeCellShardGroupJournalV3,
    pub payload: u64,
    pub wire_bytes: u64,
    pub deadline: Instant,
    pub output: &'a Path,
}

/// The grouped owner returns original M12 parent receipts separately from its
/// V3 child history and per-child CPU readbacks. Neither is future-retention
/// performance, a Positive verdict, group settlement or a Task payment.
pub(super) fn repair_native(inputs: NativeRecovery<'_>) -> Result<Value> {
    let NativeRecovery {
        node,
        budgets,
        catalog,
        file,
        providers,
        cache,
        request,
        journal,
        payload,
        wire_bytes,
        deadline,
        output,
    } = inputs;
    before(deadline)?;
    let chunks = file.plan().chunk_count();
    let per_provider = chunks.div_ceil(16);
    check(
        (1..=128).contains(&chunks)
            && request.repair_slots == [4, 5]
            && request.storage.groups.len() == 6 * per_provider
            && request.groups.len() == 2 * per_provider,
        "complete two-provider grouped research recovery roster",
    )?;
    let expected_storage_children =
        request
            .storage
            .groups
            .iter()
            .try_fold(0_usize, |count, group| {
                count
                    .checked_add(group.children.len())
                    .ok_or("grouped research child-count overflow")
            })?;
    let expected_repair_children = request.groups.iter().try_fold(0_usize, |count, group| {
        count
            .checked_add(group.children.len())
            .ok_or("grouped research child-count overflow")
    })?;
    check(
        expected_storage_children == 6 * chunks && expected_repair_children == 2 * chunks,
        "complete grouped research original child coverage",
    )?;
    let storage_parents: Vec<_> = request
        .storage
        .groups
        .iter()
        .map(|group| (group.operation, group.claim.claim))
        .collect();
    let repair_parents: Vec<_> = request
        .groups
        .iter()
        .map(|group| (group.operation, group.claim.claim))
        .collect();
    let repair_operations: BTreeSet<_> = request
        .groups
        .iter()
        .flat_map(|group| &group.children)
        .map(|child| {
            child
                .repair_operation
                .ok_or("original grouped repair operation")
        })
        .collect::<std::result::Result<_, _>>()?;
    check(
        repair_operations.len() == expected_repair_children,
        "unique grouped research repair operations",
    )?;
    let repair_bytes = request
        .groups
        .iter()
        .flat_map(|group| &group.children)
        .try_fold(0_u64, |bytes, child| {
            bytes
                .checked_add(child.contract.manifest().size())
                .ok_or("grouped research repair-byte overflow")
        })?;
    let provider_reads = u64::try_from(expected_storage_children)?
        .checked_mul(3)
        .and_then(|reads| reads.checked_add(expected_repair_children as u64))
        .ok_or("grouped research provider-read overflow")?;
    let input_bytes = wire_bytes
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(repair_bytes))
        .ok_or("grouped research input-byte overflow")?;
    let reconstruction_bytes = wire_bytes
        .checked_add(payload)
        .and_then(|bytes| bytes.checked_mul(3))
        .ok_or("grouped research reconstruction-byte overflow")?;
    let cpu_ns = cpu_allowance(deadline)?;
    let mut budget =
        NativeCellGroupedShardRecoveryBudgetV3::new(NativeCellShardRecoveryLimitsV1 {
            deadline,
            maximum_plan_attempts: 1,
            maximum_provider_reads: provider_reads,
            maximum_input_bytes: input_bytes,
            maximum_reconstruction_bytes: reconstruction_bytes,
            maximum_repairs: expected_repair_children as u64,
            maximum_repair_bytes: repair_bytes,
            maximum_cpu_ns: cpu_ns,
            cpu_ns_per_attempt: cpu_ns,
        })?;
    let result = node.recover_native_cell_grouped_shard_plan_v3(
        budgets,
        NativeCellPagedRetainedShardPlanTargetsV2 {
            catalog,
            plan_file: file,
            providers,
            cache,
        },
        request,
        journal,
        &mut budget,
    );
    let result = match result {
        Ok(result) => result,
        Err(failure) => {
            save(
                &output.join("native-recovery-failure.json"),
                &json!({
                    "profile": "native-parent-group-paged-rs46-v3",
                    "passed": false,
                    "error": failure.to_string(),
                    "usage": usage_json(failure.usage),
                    "codec": codec_json(failure.codec_usage),
                    "detected_damage": failure.detected_damage.len(),
                    "completed_children": failure.completed_children,
                    "cpu": failure.cpu.as_ref().map(|cpu| json!({
                        "observed_ns": cpu.observed_ns,
                        "ceiling_ns": cpu.ceiling_ns,
                        "metadata_funding_preflight_included": false,
                    })),
                    "future_retention_qualified": false,
                    "group_settlement_qualified": false,
                    "positive_verdict_issued": false,
                    "native_task_payment_submitted": false,
                }),
            )?;
            return Err(failure);
        }
    };
    let parent_matches = |actual: &trnm_pon_node::NativeCellShardParentGroupReadbackV3,
                          expected: &(Hash, Hash)| {
        actual.operation == expected.0
            && actual.claim == expected.1
            && actual.receipt != [0; 32]
            && actual.replay == NativeBudgetReplayV1::Done
    };
    check(
        result.plan == file.commitment()
            && result.storage_parents.len() == storage_parents.len()
            && result.repair_parents.len() == repair_parents.len()
            && result
                .storage_parents
                .iter()
                .zip(&storage_parents)
                .all(|(actual, expected)| parent_matches(actual, expected))
            && result
                .repair_parents
                .iter()
                .zip(&repair_parents)
                .all(|(actual, expected)| parent_matches(actual, expected))
            && result.storage_children == expected_storage_children
            && result.repair_children == expected_repair_children
            && result.detected_damage.len() == expected_repair_children,
        "complete grouped native parents and all original child readbacks Done",
    )?;
    let observed_repair_operations: BTreeSet<_> = result
        .child_cpu
        .iter()
        .map(|child| child.operation)
        .collect();
    check(
        result.child_cpu.len() == expected_repair_children
            && observed_repair_operations == repair_operations
            && result.child_cpu.iter().all(|child| {
                child.original_attempt
                    && child.observed_ns > 0
                    && child.observed_ns <= child.ceiling_ns
            }),
        "all original grouped repair children have actual fresh CPU readbacks",
    )?;
    let child_history = journal.report(deadline)?;
    let expected_children = expected_storage_children + expected_repair_children;
    check(
        child_history["groups"].as_u64()
            == Some((storage_parents.len() + repair_parents.len()) as u64)
            && child_history["children"].as_u64() == Some(expected_children as u64)
            && child_history["done"].as_u64() == Some(expected_children as u64)
            && child_history["unstarted"].as_u64() == Some(0)
            && child_history["pending"].as_u64() == Some(0),
        "complete durable grouped child history Done after current readback",
    )?;
    before(deadline)?;
    Ok(json!({
        "profile": "native-parent-group-paged-rs46-v3",
        "plan": hex::encode(result.plan),
        "catalog_anchor": hex::encode(file.plan().catalog_anchor().encode()),
        "observed_at": anchor_json(result.observed_at),
        "pages": file.plan().page_count(),
        "slots": result.storage_children,
        "storage_parents": result.storage_parents.len(),
        "repair_parents": result.repair_parents.len(),
        "storage_children": result.storage_children,
        "repair_children": result.repair_children,
        "detected_damage": result.detected_damage.len(),
        "repaired_slots": result.repair_children,
        "original_storage_parent_intents_done": true,
        "all_parent_effects_done": true,
        "all_child_history_done_current": true,
        "usage": usage_json(result.usage),
        "codec": codec_json(result.codec_usage),
        "cpu": {
            "observed_ns": result.cpu.observed_ns,
            "ceiling_ns": result.cpu.ceiling_ns,
            "metadata_funding_preflight_included": false,
        },
        "storage_parent_receipts": result.storage_parents.iter().map(|parent| json!({
            "operation": hex::encode(parent.operation),
            "claim": hex::encode(parent.claim),
            "receipt": hex::encode(parent.receipt),
            "replay": format!("{:?}", parent.replay),
        })).collect::<Vec<_>>(),
        "repair_parent_receipts": result.repair_parents.iter().map(|parent| json!({
            "operation": hex::encode(parent.operation),
            "claim": hex::encode(parent.claim),
            "receipt": hex::encode(parent.receipt),
            "replay": format!("{:?}", parent.replay),
        })).collect::<Vec<_>>(),
        "child_cpu": result.child_cpu.iter().map(|child| json!({
            "operation": hex::encode(child.operation),
            "observed_ns": child.observed_ns,
            "ceiling_ns": child.ceiling_ns,
            "original_attempt": child.original_attempt,
        })).collect::<Vec<_>>(),
        "child_cpu_scope": "existing CSP1 repair/reconcile interval; cache publication precedes this scope",
        "child_journal": child_history,
        "future_retention_qualified": false,
        "group_settlement_qualified": false,
        "positive_verdict_issued": false,
        "native_task_payment_submitted": false,
    }))
}

pub(super) struct ConsumerRestore<'a> {
    pub file: &'a CellPagedRetainedShardPlanFileV2,
    pub providers: &'a mut [CellRs46ShardProviderV1; 6],
    pub consumer: &'a CellStoreV1,
    pub version: &'a CellVersionManifestV1,
    pub content: &'a CellVersionContentV2,
    pub model: &'a CellLoaderContextV1,
    pub environment: &'a CellLoaderContextV1,
    pub payload: u64,
    pub wire_bytes: u64,
    pub deadline: Instant,
}

/// Every original chunk comes from exactly four current original provider
/// readbacks, then strong content verification and actual CAS readback.
pub(super) fn restore_consumer(inputs: ConsumerRestore<'_>) -> Result<Value> {
    let ConsumerRestore {
        file,
        providers,
        consumer,
        version,
        content,
        model,
        environment,
        payload,
        wire_bytes,
        deadline,
    } = inputs;
    check(
        consumer.cache_usage()?.chunk_rows == 0,
        "actually empty cold consumer",
    )?;
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model,
        environment,
    };
    let strong = content.pin_for_owner(&expected, content.commitment())?;
    for manifest in version.manifests() {
        before(deadline)?;
        consumer.put_manifest(manifest.id(), &manifest.encode())?;
    }
    let chunks = file.plan().chunk_count();
    let mut budget = CellRs46RepairBudgetV1::new_with_cache(
        deadline,
        chunks as u32,
        wire_bytes,
        wire_bytes + payload,
        2 * payload,
    );
    let mut restored = 0;
    let mut provider_bytes = 0_u64;
    for page_index in 0..file.plan().page_count() {
        let page = file.read_page(page_index, deadline)?;
        for chunk in page.chunks() {
            let mut wires = Vec::with_capacity(4);
            for (slot, provider) in providers.iter_mut().enumerate().take(4) {
                before(deadline)?;
                let stored = provider.read(
                    chunk.binding(),
                    chunk.slots()[slot].operation(),
                    deadline,
                    &mut || {
                        if Instant::now() < deadline {
                            Ok(())
                        } else {
                            Err(CellErrorV1::Invalid("original consumer restore deadline"))
                        }
                    },
                )?;
                wires.push(stored.shard().encode());
            }
            provider_bytes += wires.iter().map(|w| w.len() as u64).sum::<u64>();
            let inputs: Vec<_> = wires
                .iter()
                .enumerate()
                .map(|(slot, wire)| CellRs46ShardInputV1 {
                    index: slot as u8,
                    wire,
                })
                .collect();
            let original = &chunk.slots()[0];
            let repaired = original.codeword().repair_chunk_to_cache(
                chunk.binding(),
                original.codeword().id(),
                &inputs,
                CellRs46CacheTargetV1 {
                    store: consumer,
                    content: &strong,
                },
                &mut budget,
            )?;
            check(
                repaired.cache_readback_observed() && repaired.verified_slots() == [0, 1, 2, 3],
                "actual four-provider original chunk and strong cache readback",
            )?;
            restored += 1;
        }
    }
    check(
        restored == chunks,
        "complete cold chunk coverage across every page",
    )?;
    let mut readback = CellContentReadSessionV2::new(
        CellReleaseLimitsV1 {
            max_payload_bytes: CAPTURE_BOUND,
            max_chunks: 2_048,
            deadline,
        },
        1,
    )?;
    content.verify_cached(consumer, &expected, content.commitment(), &mut readback)?;
    before(deadline)?;
    Ok(json!({
        "restored_original_chunks": restored, "original_provider_slots": [0, 1, 2, 3],
        "actual_provider_payload_wire_bytes": provider_bytes,
        "codec": codec_json(budget.usage()), "complete_content_readback": true,
        "complete_content_reserved_bytes": readback.usage().reserved_payload_bytes,
        "complete_content_reserved_chunks": readback.usage().reserved_chunks,
        "source_catalog_payload_used": false,
        "same_tcv1": hex::encode(version.commitment()), "same_tcv2": hex::encode(content.commitment()),
    }))
}
