// Private cfg(test) child of the byte-exact original store.rs.
// Observe actual default Settings/Node/SQLite operations only.
// This is a proposed oracle adapter; no native behavior or expected result is implemented here.
use super::*;
use serde_json::json;
use std::collections::BTreeSet;
use std::io::BufRead;

const TABLES: &[&str] = &[
    "metadata",
    "blocks",
    "deltas",
    "active",
    "kv",
    "reorg",
    "reorg_lifecycle_v1",
    "steps",
    "events",
    "snapshots",
    "local_pool_metadata",
    "local_pool_groups",
    "local_pool_rows",
    "local_pool_removals",
    "peer_replay",
    "peer_request_audit",
    "peer_outbox",
    "ancestry_jump",
];

fn mark(phase: &mut String, calls: &mut Vec<String>, name: impl Into<String>) {
    *phase = name.into();
    calls.push(phase.clone());
}

fn failure(error: &crate::Error) -> Value {
    let mut sources = Vec::new();
    let mut source = std::error::Error::source(error);
    while let Some(actual) = source {
        sources.push(actual.to_string());
        source = actual.source();
    }
    json!({
        "display": error.to_string(),
        "code": error.code().map(|value| value.as_str()),
        "kind": format!("{:?}", error.kind()),
        "requires_owner_stop": error.requires_owner_stop(),
        "source_displays": sources,
    })
}

fn settings_observation(settings: &Settings) -> crate::Result<Value> {
    let state = serde_json::to_value(&settings.initial)?;
    let params = settings.app.params.clone();
    let registry = settings.app.model_registry.clone();
    Ok(json!({
        "params": params,
        "params_canonical_hex": hex::encode(canonical(&settings.app.params)?),
        "network_hex": hex::encode(settings.network()),
        "parameters_hex": hex::encode(settings.parameters()),
        "genesis_hex": hex::encode(settings.genesis()),
        "initial_state": state,
        "initial_state_canonical_hex": hex::encode(canonical(&serde_json::to_value(&settings.initial)?)?),
        "initial_root_hex": hex::encode(settings.state_root(&settings.initial)?),
        "family_hex": hex::encode(settings.app.family),
        "plan_hex": hex::encode(settings.app.plan),
        "evaluators": settings.app.evaluators.iter().cloned().collect::<Vec<_>>(),
        "fees": settings.app.fees.to_vec(),
        "model_registry": registry,
        "model_registry_canonical_hex": hex::encode(canonical(&settings.app.model_registry)?),
        "has_task_windows": settings.app.task_windows.is_some(),
        "has_operator_bootstrap": settings.operator_bootstrap.is_some(),
        "has_operator_material": settings.operator_material.is_some(),
        "has_checkpoint_tile_paths": settings.checkpoint_tile_paths.is_some(),
        "is_permanent_account_growth_v2": settings.is_permanent_account_growth_v2(),
        "pq_enabled": trnm_mvcc_fee::pon_executor::pq_accounts_v2::enabled(&settings.app),
    }))
}

fn observe(
    node: &Node,
    phase: &mut String,
    calls: &mut Vec<String>,
    pass: &str,
) -> crate::Result<Value> {
    mark(phase, calls, format!("{pass}.Node::read_active"));
    let (tip, generation, state) = node.read_active()?;
    mark(phase, calls, format!("{pass}.Node::record"));
    let record = node.record(tip)?;
    mark(phase, calls, format!("{pass}.Node::slot"));
    let slot = node.slot()?;
    mark(phase, calls, format!("{pass}.Settings::state_root"));
    let root = node.settings.state_root(&state)?;
    let state_value = serde_json::to_value(&state)?;
    let state_canonical = canonical(&state_value)?;
    let logical_rows: Vec<Value> = state
        .iter()
        .map(|(key, value)| -> crate::Result<Value> {
            Ok(json!({
                "key": key,
                "key_hex": hex::encode(key.as_bytes()),
                "value": value,
                "value_canonical_hex": hex::encode(canonical(value)?),
            }))
        })
        .collect::<crate::Result<_>>()?;

    mark(phase, calls, format!("{pass}.SQL.kv"));
    let raw_kv: Vec<(u64, String, Vec<u8>, String, String)> = node
        .db
        .prepare("SELECT slot,key,value,typeof(key),typeof(value) FROM kv ORDER BY slot,key")?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut kv = Vec::new();
    for (stored_slot, key, raw, key_type, value_type) in raw_kv {
        let decoded: Value = serde_json::from_slice(&raw)?;
        let recanonical = canonical(&decoded)?;
        kv.push(json!({
            "slot": stored_slot, "key": key, "key_hex": hex::encode(key.as_bytes()),
            "value_hex": hex::encode(&raw), "value": decoded,
            "key_sql_type": key_type, "value_sql_type": value_type,
            "canonical_exact": raw == recanonical,
        }));
    }

    mark(phase, calls, format!("{pass}.SQL.blocks"));
    type BlockRow = (
        Vec<u8>,
        Option<Vec<u8>>,
        u64,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
    );
    let raw_blocks: Vec<BlockRow> = node
        .db
        .prepare("SELECT id,parent,height,chainwork,packet,state_root FROM blocks ORDER BY id")?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let blocks: Vec<Value> = raw_blocks
        .into_iter()
        .map(|(id, parent, height, work, packet, root)| {
            json!({
                "id_hex": hex::encode(id), "parent_hex": parent.map(hex::encode),
                "height": height, "chainwork_hex": hex::encode(work),
                "packet_hex": packet.map(hex::encode), "state_root_hex": hex::encode(root),
            })
        })
        .collect();

    mark(phase, calls, format!("{pass}.SQL.active"));
    let raw_active: Vec<(u64, Vec<u8>, u64, u64)> = node
        .db
        .prepare("SELECT singleton,tip,generation,state_slot FROM active ORDER BY singleton")?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let active: Vec<Value> = raw_active
        .into_iter()
        .map(|(singleton, tip, generation, slot)| {
            json!({"singleton": singleton, "tip_hex": hex::encode(tip),
                   "generation": generation, "state_slot": slot})
        })
        .collect();

    mark(phase, calls, format!("{pass}.SQL.snapshots"));
    let raw_snapshots: Vec<(Vec<u8>, Vec<u8>)> = node
        .db
        .prepare("SELECT block,state FROM snapshots ORDER BY block")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut snapshots = Vec::new();
    for (block, raw) in raw_snapshots {
        let decoded: Value = serde_json::from_slice(&raw)?;
        let recanonical = canonical(&decoded)?;
        snapshots.push(json!({
            "block_hex": hex::encode(&block), "state_hex": hex::encode(&raw),
            "state": decoded, "canonical_exact": raw == recanonical,
            "equals_complete_read_active_state": decoded == state_value,
            "equals_complete_read_active_canonical": raw == state_canonical,
            "names_active_tip": block.as_slice() == tip.as_slice(),
        }));
    }

    mark(phase, calls, format!("{pass}.SQL.metadata"));
    let raw_metadata: Vec<(String, Vec<u8>, String, String)> = node
        .db
        .prepare("SELECT key,value,typeof(key),typeof(value) FROM metadata ORDER BY key")?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let metadata: Vec<Value> = raw_metadata
        .into_iter()
        .map(|(key, value, key_type, value_type)| {
            json!({"key": key, "value_hex": hex::encode(value),
                   "key_sql_type": key_type, "value_sql_type": value_type})
        })
        .collect();

    mark(phase, calls, format!("{pass}.SQL.all_catalog_counts"));
    let mut counts = BTreeMap::new();
    for table in TABLES {
        let count: u64 =
            node.db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
        counts.insert(*table, count);
    }
    mark(phase, calls, format!("{pass}.SQL.schema"));
    let actual_schema = schema(&node.db)?;
    Ok(json!({
        "is_legacy_backend": node.state_backend == StateBackend::Legacy,
        "workers": node.workers,
        "tip_hex": hex::encode(tip), "generation": generation, "slot": slot,
        "complete_state": state_value, "complete_state_canonical_hex": hex::encode(&state_canonical),
        "logical_rows": logical_rows, "state_root_hex": hex::encode(root),
        "read_state_equals_settings_initial": state == node.settings.initial,
        "record": {"parent_hex": record.parent.map(hex::encode), "height": record.height,
                   "chainwork_hex": hex::encode(record.work.bytes()),
                   "state_root_hex": hex::encode(record.root)},
        "actual_kv_rows": kv, "actual_block_rows": blocks, "actual_active_rows": active,
        "actual_snapshot_rows": snapshots, "actual_metadata_rows": metadata,
        "actual_table_counts": counts,
        "original_sql_schema": actual_schema,
        "original_selected_schema_id_hex": hex::encode(node.state_backend.selected_schema_id(&node.settings)),
        "schema_cross_format_equivalence_claimed": false,
    }))
}

fn invoke(index: usize, item: &Value, artifact_root: &Path) {
    let name = item["name"].as_str().expect("fixture name");
    let timestamp = if item["timestamp"].is_null() {
        None
    } else {
        Some(
            item["timestamp"]
                .as_u64()
                .expect("fixture timestamp null or u64"),
        )
    };
    let workers_u64 = item["workers"].as_u64().expect("fixture workers u64");
    let workers = usize::try_from(workers_u64)
        .expect("original target must admit the complete u64 worker input");
    // Fixture directories are indexed internally, never selected by an input name.
    let directory = artifact_root.join(format!("case-{index:06}"));
    std::fs::create_dir(&directory).expect("fresh private original fixture");
    let mut phase = String::new();
    let mut calls = Vec::new();
    let mut constructed = None;
    let mut first = None;
    let mut reopened = None;
    let mut held_lock_probe = None;
    let outcome: crate::Result<()> = (|| {
        mark(&mut phase, &mut calls, "Settings::development");
        let settings = Settings::development(timestamp)?;
        mark(&mut phase, &mut calls, "observe_actual_Settings");
        constructed = Some(settings_observation(&settings)?);
        mark(&mut phase, &mut calls, "first.Node::open");
        let node = Node::open(&directory, settings.clone(), workers)?;
        first = Some(observe(&node, &mut phase, &mut calls, "first")?);

        mark(&mut phase, &mut calls, "held_lock.Node::open");
        held_lock_probe = Some(match Node::open(&directory, settings.clone(), workers) {
            Ok(other) => {
                drop(other);
                json!({"opened": true, "error": null})
            }
            Err(error) => json!({"opened": false, "error": failure(&error)}),
        });
        mark(&mut phase, &mut calls, "first.drop_Node");
        drop(node);

        mark(&mut phase, &mut calls, "reopen.Node::open");
        let node = Node::open(&directory, settings, workers)?;
        reopened = Some(observe(&node, &mut phase, &mut calls, "reopen")?);
        mark(&mut phase, &mut calls, "reopen.drop_Node");
        drop(node);
        Ok(())
    })();
    let (status, error, error_phase) = match outcome {
        Ok(()) => ("OK", None, None),
        Err(error) => ("ERR", Some(failure(&error)), Some(phase.clone())),
    };
    let full_reopen_observation_equal = if status == "OK" {
        Some(first == reopened)
    } else {
        None
    };
    println!(
        "HIA_GENESIS_OWNER_ORACLE:{}",
        json!({
            "name": name, "timestamp": timestamp, "workers": workers_u64,
            "status": status, "error": error, "error_phase": error_phase,
            "constructed": constructed, "first": first, "reopened": reopened,
            "full_reopen_observation_equal": full_reopen_observation_equal,
            "held_lock_probe": held_lock_probe,
            "public_and_observation_invocations_attempted": calls,
            "fixture_index": index, "fixture_directory": directory,
            "arbitrary_successor_or_delta_supplied": false,
            "cross_format_sqlite_compatibility_claimed": false,
        })
    );
}

#[test]
fn evaluate() {
    let path = std::env::var("TRNM_HIA_GENESIS_OWNER_CORPUS").expect("exact bound corpus");
    let artifact_root = std::path::PathBuf::from(
        std::env::var("TRNM_HIA_GENESIS_OWNER_ARTIFACT_DIR")
            .expect("fresh private original artifact root"),
    );
    assert!(artifact_root.is_dir());
    assert!(std::fs::read_dir(&artifact_root).unwrap().next().is_none());
    let file = std::fs::File::open(path).unwrap();
    let mut names = BTreeSet::new();
    let mut count = 0usize;
    for (index, line) in std::io::BufReader::new(file).lines().enumerate() {
        let item: Value = serde_json::from_str(&line.unwrap()).unwrap();
        assert!(names.insert(item["name"].as_str().unwrap().to_owned()));
        invoke(index, &item, &artifact_root);
        count += 1;
    }
    assert!(count > 0, "empty original corpus is not qualification");
}
