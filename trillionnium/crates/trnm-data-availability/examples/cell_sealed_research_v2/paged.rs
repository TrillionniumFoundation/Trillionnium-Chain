//! Explicit local paged-shard research route. No funding or execution grant.

use super::*;
use std::{fs::File, os::unix::fs::MetadataExt, sync::atomic::Ordering};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub(super) schema: String,
    pub(super) chunks_per_page: u16,
    pub(super) available_slots: [u8; 4],
}

impl Profile {
    pub(super) fn validate(&self) -> Result<()> {
        check(
            self.schema == "trnm.cell-sealed-paged-custody.v1"
                && self.chunks_per_page == 64
                && self.available_slots.iter().all(|slot| *slot < 6)
                && self
                    .available_slots
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
            "fresh paged research profile and four canonical slots",
        )
    }

    pub(super) fn commitment(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"TRNM/Cell/SealedPagedResearchProfile/v1\0");
        hash.update((self.schema.len() as u32).to_be_bytes());
        hash.update(self.schema.as_bytes());
        hash.update(self.chunks_per_page.to_be_bytes());
        hash.update(self.available_slots);
        Ok(hash.finalize().into())
    }
}

pub(super) struct Restore<'a, 'owner> {
    pub(super) source: CellStoreV1,
    pub(super) received: CellStoreV1,
    pub(super) archive: CellVersionRetentionStoreV3,
    pub(super) config: CellVersionRetentionConfigV3,
    pub(super) anchor: CellVersionCatalogAnchorV3,
    pub(super) version: &'a CellVersionManifestV1,
    pub(super) content: &'a CellVersionContentV2,
    pub(super) owner: &'a CellVersionLoaderContextV1<'owner>,
    pub(super) source_path: &'a Path,
    pub(super) received_path: &'a Path,
    pub(super) archive_path: &'a Path,
    pub(super) output: &'a Path,
    pub(super) operation: [u8; 32],
    pub(super) deadline: Instant,
    pub(super) started: Instant,
    pub(super) cancelled: &'a AtomicBool,
}

fn controlled(deadline: Instant, cancelled: &AtomicBool) -> CellResultV1<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(CellErrorV1::Invalid("paged research original cancellation"));
    }
    if Instant::now() >= deadline {
        return Err(CellErrorV1::Invalid("paged research original deadline"));
    }
    Ok(())
}

fn identity(operation: &[u8; 32], label: &[u8], ordinal: u64, slot: u8) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"TRNM/Cell/SealedPagedResearchOperation/v1\0");
    hash.update(operation);
    hash.update((label.len() as u32).to_be_bytes());
    hash.update(label);
    hash.update(ordinal.to_be_bytes());
    hash.update([slot]);
    hash.finalize().into()
}

fn record_budget(report: &mut Value, budget: &CellPagedShardRestoreBudgetV2) {
    let usage = budget.usage();
    report["restore_budget"] = json!({
        "attempts_committed": usage.attempts_committed,
        "chunks_committed": usage.chunks_committed,
        "provider_reads_committed": usage.provider_reads_committed,
        "input_bytes_committed": usage.input_bytes_committed,
        "reconstruction_bytes_committed": usage.reconstruction_bytes_committed,
        "cache_bytes_committed": usage.cache_bytes_committed,
        "readback_payload_bytes_committed": usage.readback_payload_bytes_committed,
        "readback_chunks_committed": usage.readback_chunks_committed,
    });
    let usage = budget.codec_usage();
    report["codec_budget"] = json!({
        "attempts_committed": usage.attempts_committed,
        "input_bytes_committed": usage.input_bytes_committed,
        "reconstruction_bytes_committed": usage.reconstruction_bytes_committed,
        "cache_bytes_committed": usage.cache_bytes_committed,
    });
    let usage = budget.readback_usage();
    report["readback_budget"] = json!({
        "attempted_scans": usage.attempted_scans,
        "reserved_payload_bytes": usage.reserved_payload_bytes,
        "reserved_chunks": usage.reserved_chunks,
    });
}

pub(super) fn restore(
    context: Restore<'_, '_>,
    profile: &Profile,
    report: &mut Value,
) -> Result<CellStoreV1> {
    let started = context.started;
    let custody_started = Instant::now();
    let mut observation = json!({
        "schema": "trnm.cell-sealed-paged-custody-observation.v1",
        "stage": "initial", "passed": false,
        "m12_funding_admitted": false, "provider_repair_dispatched": false,
        "custody_completion_granted": false, "execution_granted": false,
        "independent_failure_domains": false,
        "retention_heights_are_research_terms": true,
        "provider_reads": 0, "provider_reads_are_logical_callback_attempts": true,
        "callback_attempts": 0, "unavailable_callbacks": 0,
        "actual_provider_read_attempts": 0, "obtained_wire_bytes": 0,
        "published_slots": 0, "staged_chunks": 0,
        "catalog_zero_bytes": 0, "catalog_payload_unavailable": false,
        "restore_budget": {"attempts_committed": 0, "chunks_committed": 0,
            "provider_reads_committed": 0, "input_bytes_committed": 0,
            "reconstruction_bytes_committed": 0, "cache_bytes_committed": 0,
            "readback_payload_bytes_committed": 0, "readback_chunks_committed": 0},
        "codec_budget": {"attempts_committed": 0, "input_bytes_committed": 0,
            "reconstruction_bytes_committed": 0, "cache_bytes_committed": 0},
        "readback_budget": {"attempted_scans": 0, "reserved_payload_bytes": 0,
            "reserved_chunks": 0},
    });
    let result = restore_inner(context, profile, &mut observation);
    observation["passed"] = json!(result.is_ok());
    let operation_elapsed = started.elapsed().as_millis();
    observation["elapsed_ms"] = json!(operation_elapsed);
    observation["elapsed_ms_scope"] = json!("whole operation including earlier stages");
    observation["operation_elapsed_ms"] = json!(operation_elapsed);
    observation["custody_elapsed_ms"] = json!(custody_started.elapsed().as_millis());
    if let Err(error) = &result {
        observation["error"] = json!(error.to_string());
    }
    report["paged_custody"] = observation;
    result
}

fn restore_inner(
    context: Restore<'_, '_>,
    profile: &Profile,
    report: &mut Value,
) -> Result<CellStoreV1> {
    let Restore {
        source,
        received,
        mut archive,
        config,
        anchor,
        version,
        content,
        owner,
        source_path,
        received_path,
        archive_path,
        output,
        operation,
        deadline,
        started: _,
        cancelled,
    } = context;
    controlled(deadline, cancelled)?;
    profile.validate()?;
    check(
        output.is_absolute()
            && source_path.parent() == Some(output)
            && received_path.parent() == Some(output)
            && archive_path.parent() == Some(output)
            && operation != [0; 32],
        "paged research faults confined to fresh operation children",
    )?;
    let contract = archive.contract(operation, deadline)?;
    check(
        contract.version == *version
            && archive.anchor(deadline)? == anchor
            && archive
                .inventory(contract.retain_from_height, deadline)?
                .protected
                .len()
                == 1,
        "paged research exact original complete catalog root",
    )?;
    content.pin_for_owner(owner, content.commitment())?;
    let mut chunks = 0_u64;
    let mut payload = 0_u64;
    let mut provider_payload = 0_u64;
    let mut provider_capacity = 0_u64;
    let header = (MAX_CELL_RS46_SHARD_WIRE_BYTES_V1 as u64)
        .checked_sub(u64::from(MAX_CHUNK_BYTES) / 4)
        .ok_or("RS46 public wire limits")?;
    for manifest in version.manifests() {
        for chunk in manifest.chunks() {
            chunks = chunks.checked_add(1).ok_or("paged chunk count overflow")?;
            payload = payload
                .checked_add(u64::from(chunk.size))
                .ok_or("paged payload overflow")?;
            let wire_bytes = header + u64::from(chunk.size).div_ceil(4);
            provider_payload = provider_payload
                .checked_add(wire_bytes)
                .ok_or("paged shard payload overflow")?;
            // Retention reserves a separately aligned extent for every obligation.
            let extent_bytes = wire_bytes
                .checked_add(4095)
                .map(|bytes| bytes / 4096 * 4096)
                .ok_or("paged provider extent overflow")?;
            provider_capacity = provider_capacity
                .checked_add(extent_bytes)
                .ok_or("paged provider capacity overflow")?;
        }
    }
    check(
        (1..=MAX_CELL_PAGED_RETAINED_CHUNKS_V2 as u64).contains(&chunks)
            && (1..=SNAPSHOT_BOUND).contains(&payload),
        "paged research complete version bounds",
    )?;
    let slots = chunks.checked_mul(6).ok_or("paged slot count overflow")?;
    let input = provider_payload
        .checked_mul(6)
        .ok_or("paged input overflow")?;
    check(
        input <= SNAPSHOT_BOUND,
        "paged staging original logical allowance",
    )?;
    let reconstruction = payload
        .checked_add(input)
        .ok_or("paged reconstruction overflow")?;
    let cache_bytes = payload
        .checked_mul(2)
        .ok_or("paged cache allowance overflow")?;
    report["profile"] = json!(hex::encode(profile.commitment()?));
    report["provider_slots"] = json!(profile.available_slots);
    report["chunk_count"] = json!(chunks);
    report["payload_bytes"] = json!(payload);
    report["potential"] = json!({"provider_reads": slots, "input_bytes": input,
        "reconstruction_bytes": reconstruction, "cache_bytes": cache_bytes,
        "readback_payload_bytes": payload, "readback_chunks": chunks});

    check(
        provider_capacity <= SNAPSHOT_BOUND,
        "paged provider original storage bound",
    )?;
    report["provider_wire_bytes"] = json!(provider_payload);
    report["provider_capacity_bytes"] = json!(provider_capacity);
    let maximum_obligations = u32::try_from(chunks)?;
    let configs: [CellRs46ShardProviderConfigV1; 6] = std::array::from_fn(|slot| {
        let slot = slot as u8;
        CellRs46ShardProviderConfigV1 {
            placement: CellRs46ShardPlacementV1 {
                provider_id: identity(&operation, b"provider", 0, slot),
                responsible_owner: identity(&operation, b"declared-local-owner", 0, slot),
                administrator: identity(&operation, b"declared-local-administrator", 0, slot),
                failure_domain: identity(&operation, b"declared-local-domain", 0, slot),
                domain_evidence: identity(&operation, b"local-fixture-domain-evidence", 0, slot),
                repair_owner: identity(&operation, b"local-fixture-repair-owner", 0, slot),
            },
            owner_generation: 1,
            capacity_bytes: provider_capacity,
            maximum_obligations,
        }
    });
    let plan_path = output.join("paged-shard-plan");
    let provider_root = output.join("paged-shard-providers");
    let staging_path = output.join("paged-shard-staging.sqlite");
    report["provider_root"] = json!(provider_root);
    report["staging_path"] = json!(staging_path);
    report["stage"] = json!("commit complete paged intent from original acknowledged catalog");
    let plan = CellPagedRetainedShardPlanFileV2::create(
        &plan_path,
        &mut archive,
        CellPagedRetainedShardPlanRequestV2 {
            operation: identity(&operation, b"paged-plan", 0, 0),
            expected_catalog: anchor,
            current_height: contract.retain_from_height,
            required_until_height: contract.retain_until_height,
            providers: configs.clone(),
            funding_operations: (0..chunks)
                .map(|ordinal| {
                    std::array::from_fn(|slot| {
                        identity(&operation, b"declared-slot-funding", ordinal, slot as u8)
                    })
                })
                .collect(),
            maximum_repairs_per_slot: 1,
            chunks_per_page: profile.chunks_per_page,
        },
        deadline,
    )?;
    controlled(deadline, cancelled)?;
    let plan_pin = plan.commitment();
    report["plan"] = json!(hex::encode(plan_pin));
    report["catalog_anchor"] = json!(hex::encode(anchor.encode()));
    report["page_count"] = json!(plan.plan().page_count());
    write_new(
        &output.join("owner-paged-custody.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema": "trnm.cell-sealed-paged-custody-owner.v1",
            "operation": hex::encode(operation), "profile": hex::encode(profile.commitment()?),
            "plan": hex::encode(plan_pin), "catalog_anchor": hex::encode(anchor.encode()),
            "version": hex::encode(version.commitment()), "content": hex::encode(content.commitment()),
            "available_slots": profile.available_slots,
            "provider_capacity_bytes": provider_capacity, "provider_wire_bytes": provider_payload,
            "provider_obligations": chunks,
            "six_declared_local_slots_are_independent_operators": false,
        }))?,
    )?;
    let mut staging_metadata = 0_u64;
    for page_index in 0..plan.plan().page_count() {
        controlled(deadline, cancelled)?;
        let page = plan.read_page(page_index, deadline)?;
        for chunk in page.chunks() {
            for duty in chunk.slots() {
                staging_metadata = staging_metadata
                    .checked_add(duty.manifest().encode().len() as u64)
                    .ok_or("paged staging metadata overflow")?;
            }
        }
    }
    // Cache V4 charges each 32-byte CAS key in addition to its row payload.
    let staging_keys = slots.checked_mul(64).ok_or("paged staging key overflow")?;
    let staging_logical = input
        .checked_add(staging_metadata)
        .and_then(|bytes| bytes.checked_add(staging_keys))
        .ok_or("paged staging logical overflow")?;
    check(
        staging_logical <= SNAPSHOT_BOUND,
        "paged staging original storage bound",
    )?;
    report["staging_manifest_bytes"] = json!(staging_metadata);
    report["staging_key_bytes"] = json!(staging_keys);
    report["staging_logical_bytes"] = json!(staging_logical);
    let staging = CellStoreV1::open(
        &staging_path,
        CellCacheConfigV4 {
            max_database_bytes: 1024 * 1024 * 1024,
            max_logical_bytes: staging_logical,
            max_chunk_rows: slots,
            max_manifest_rows: slots,
        },
    )?;
    fs::create_dir(&provider_root)?;
    fs::set_permissions(&provider_root, fs::Permissions::from_mode(0o700))?;
    let mut providers = configs
        .iter()
        .enumerate()
        .map(|(slot, config)| {
            CellRs46ShardProviderV1::create(
                &provider_root.join(format!("provider-{slot}")),
                config.clone(),
            )
        })
        .collect::<CellResultV1<Vec<_>>>()?;
    report["stage"] = json!("stage and acknowledge six original provider targets");
    let mut staged = 0_u64;
    let mut published = 0_u64;
    for page_index in 0..plan.plan().page_count() {
        let page = plan.read_page(page_index, deadline)?;
        for (local, chunk) in page.chunks().iter().enumerate() {
            controlled(deadline, cancelled)?;
            plan.stage_chunk_from_catalog(
                page_index,
                local,
                &mut archive,
                &staging,
                contract.retain_from_height,
                deadline,
            )?;
            staged += 1;
            report["staged_chunks"] = json!(staged);
            for (slot, duty) in chunk.slots().iter().enumerate() {
                report["current_slot"] = json!({"page": page_index,
                    "chunk_in_page": local, "slot": slot,
                    "operation": hex::encode(duty.operation()),
                    "outcome": "pending_original_target_observation"});
                providers[slot].publish_controlled(
                    duty,
                    duty.operation(),
                    &staging,
                    deadline,
                    &mut || controlled(deadline, cancelled),
                )?;
                published += 1;
                report["published_slots"] = json!(published);
                report["current_slot"]["outcome"] = json!("original_target_readback_observed");
            }
        }
    }
    controlled(deadline, cancelled)?;
    plan.read_complete_current(&archive, contract.retain_from_height, deadline)?;
    drop(plan);
    drop(archive);
    drop(providers);
    drop(staging);
    drop(source);
    drop(received);
    report["stage"] = json!("close owners and remove only operation caches");
    remove_cache(source_path)?;
    report["source_cache_absent"] = json!(!source_path.exists());
    remove_cache(received_path)?;
    report["received_cache_absent"] = json!(!received_path.exists());
    remove_cache(&staging_path)?;
    report["staging_cache_absent"] = json!(!staging_path.exists());
    let missing: Vec<u8> = (0..6)
        .filter(|slot| !profile.available_slots.contains(slot))
        .collect();
    report["quarantine_requested_slots"] = json!(missing);
    let mut quarantined = Vec::new();
    report["quarantined_slots"] = json!(quarantined);
    for slot in &missing {
        controlled(deadline, cancelled)?;
        fs::rename(
            provider_root.join(format!("provider-{slot}")),
            provider_root.join(format!("quarantined-{slot}")),
        )?;
        quarantined.push(*slot);
        report["quarantined_slots"] = json!(quarantined);
    }
    File::open(&provider_root)?.sync_all()?;
    report["stage"] = json!("make only this catalog payload unavailable at unchanged length");
    let arena = archive_path.join("objects/payload.arena");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&arena)?;
    let before = file.metadata()?;
    let entry = fs::symlink_metadata(&arena)?;
    check(
        before.is_file()
            && entry.is_file()
            && before.nlink() == 1
            && before.ino() == entry.ino()
            && before.dev() == entry.dev()
            && before.len() > 0
            && before.len() <= SNAPSHOT_BOUND,
        "owned bounded catalog arena for explicit fault injection",
    )?;
    report["catalog_zero_bytes_reserved"] = json!(before.len());
    let zeros = [0_u8; 65536];
    let mut zeroed = 0_u64;
    while zeroed < before.len() {
        controlled(deadline, cancelled)?;
        let count = (before.len() - zeroed).min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..count])?;
        zeroed += count as u64;
        report["catalog_zero_bytes"] = json!(zeroed);
    }
    file.sync_all()?;
    let current = fs::symlink_metadata(&arena)?;
    check(
        file.metadata()?.len() == before.len()
            && current.is_file()
            && current.dev() == before.dev()
            && current.ino() == before.ino()
            && current.nlink() == 1
            && current.len() == before.len(),
        "catalog fault retains original arena length and identity",
    )?;
    drop(file);
    controlled(deadline, cancelled)?;
    report["catalog_payload_unavailable"] = json!(true);

    report["stage"] = json!("reopen independently pinned root and four original providers");
    let plan = CellPagedRetainedShardPlanFileV2::open(&plan_path, plan_pin, deadline)?;
    let archive = CellVersionRetentionStoreV3::open(archive_path, config, anchor)?;
    let mut providers = configs
        .iter()
        .enumerate()
        .map(|(slot, config)| {
            if profile.available_slots.contains(&(slot as u8)) {
                CellRs46ShardProviderV1::open(
                    &provider_root.join(format!("provider-{slot}")),
                    config.clone(),
                )
                .map(Some)
            } else {
                Ok(None)
            }
        })
        .collect::<CellResultV1<Vec<_>>>()?;
    controlled(deadline, cancelled)?;
    let consumer = cache(&output.join("consumer.sqlite"))?;
    check(
        consumer.cache_usage()?.chunk_rows == 0 && consumer.cache_usage()?.manifest_rows == 0,
        "paged research consumer actually empty",
    )?;
    let mut budget = CellPagedShardRestoreBudgetV2::new(CellPagedShardRestoreLimitsV2 {
        deadline,
        maximum_attempts: 1,
        maximum_chunks: chunks,
        maximum_provider_reads: slots,
        maximum_input_bytes: input,
        maximum_reconstruction_bytes: reconstruction,
        maximum_cache_bytes: cache_bytes,
        maximum_readback_payload_bytes: payload,
        maximum_readback_chunks: chunks,
    })?;
    report["stage"] = json!("reconstruct every original chunk from four reopened providers");
    let mut reads = 0_u64;
    let mut unavailable = 0_u64;
    let mut actual_reads = 0_u64;
    let mut obtained_wire_bytes = 0_u64;
    let result = restore_cell_paged_version_to_cache_v2(
        CellPagedShardRestoreRequestV2 {
            plan_file: &plan,
            catalog: &archive,
            current_height: contract.retain_from_height,
            original_root_operation: operation,
            content,
            expected: owner,
            content_pin: content.commitment(),
            target: &consumer,
        },
        &mut budget,
        |duty, original_deadline| {
            reads += 1;
            controlled(original_deadline, cancelled)?;
            let slot = usize::from(duty.owner().slot);
            let Some(provider) = providers[slot].as_mut() else {
                unavailable += 1;
                return Ok(None);
            };
            actual_reads += 1;
            let wire = provider
                .read(
                    duty.binding(),
                    duty.operation(),
                    original_deadline,
                    &mut || controlled(original_deadline, cancelled),
                )?
                .shard()
                .encode();
            obtained_wire_bytes += wire.len() as u64;
            Ok(Some(wire))
        },
    );
    report["provider_reads"] = json!(reads);
    report["callback_attempts"] = json!(reads);
    report["unavailable_callbacks"] = json!(unavailable);
    report["actual_provider_read_attempts"] = json!(actual_reads);
    report["obtained_wire_bytes"] = json!(obtained_wire_bytes);
    record_budget(report, &budget);
    let observed = result?;
    report["verified_shards"] = json!(observed.verified_shards);
    report["missing_shards"] = json!(observed.missing_shards);
    report["rejected_shards"] = json!(observed.rejected_shards);
    report["consumer_chunks"] = json!(consumer.cache_usage()?.chunk_rows);
    controlled(deadline, cancelled)?;
    report["stage"] = json!("complete actual selected-version readback from four providers");
    Ok(consumer)
}

#[cfg(test)]
mod tests;
