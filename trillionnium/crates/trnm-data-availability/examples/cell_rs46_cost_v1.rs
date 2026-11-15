//! Offline erasure encode/recovery of real synthetic Cell bytes through the
//! existing native cache. Omitting two shards is a local controlled experiment,
//! not evidence of remote independent custody, network availability or rewards.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, time::Instant};
use trnm_data_availability::cell::{
    digest_hex, CellCacheConfigV4, CellContextV1, CellErrorV1, CellRs46ChunkBindingV1,
    CellRs46ShardV1, CellStoreV1, CELL_RS46_PROFILE_V1,
};

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 32 * 1024 * 1024,
        max_logical_bytes: 16 * 1024 * 1024,
        max_chunk_rows: 1024,
        max_manifest_rows: 32,
    }
}

fn observe(size: usize, chunk_bytes: u32, repeat: u32) -> Value {
    let mut row = json!({
        "payload_bytes": size,
        "chunk_bytes": chunk_bytes,
        "repeat": repeat,
        "status": "RUNNING",
        "retained_shard_indices": [2, 3, 4, 5],
        "omitted_shard_indices": [0, 1],
        "chunk_observations": [],
    });
    let result =
        (|| -> Result<(), Box<dyn Error>> {
            let directory = tempfile::tempdir()?;
            let source_path = directory.path().join("synthetic.bin");
            let bytes: Vec<u8> = (0..size)
                .map(|i| ((i.wrapping_mul(19) + i / 16_384) % 251) as u8)
                .collect();
            fs::write(&source_path, &bytes)?;
            let source =
                CellStoreV1::open(&directory.path().join("source.sqlite"), cache_config())?;
            let recovered =
                CellStoreV1::open(&directory.path().join("recovered.sqlite"), cache_config())?;
            let context = CellContextV1 {
                family: "rs46-synthetic-cost-v1".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            };
            let start = Instant::now();
            let manifest = source.pack_file(&source_path, context.clone(), chunk_bytes)?;
            row["native_pack_file_wall_ns"] = json!(start.elapsed().as_nanos());
            row["manifest_id"] = json!(digest_hex(manifest.id()));
            row["payload_sha256"] = json!(digest_hex(manifest.payload_sha256()));
            recovered.put_manifest(manifest.id(), &manifest.encode())?;
            for (index, chunk) in bytes.chunks(chunk_bytes as usize).enumerate() {
                let start = Instant::now();
                let binding = CellRs46ChunkBindingV1::from_pinned_manifest(
                    &manifest,
                    manifest.id(),
                    &context,
                    index as u32,
                )?;
                let binding_wall_ns = start.elapsed().as_nanos();
                let start = Instant::now();
                let shards = binding.encode_chunk(chunk)?;
                let encode_wall_ns = start.elapsed().as_nanos();
                let start = Instant::now();
                let survivors: Vec<_> = shards[2..]
                    .iter()
                    .map(|s| CellRs46ShardV1::decode(&s.encode()))
                    .collect::<Result<_, _>>()?;
                let wire_roundtrip_wall_ns = start.elapsed().as_nanos();
                let start = Instant::now();
                let restored = binding.recover_chunk(&survivors)?;
                let recover_wall_ns = start.elapsed().as_nanos();
                let mut corrupt_wire = survivors[0].encode();
                let last = corrupt_wire.len() - 1;
                corrupt_wire[last] ^= 1;
                let mut hostile = survivors;
                hostile[0] = CellRs46ShardV1::decode(&corrupt_wire)?;
                let start = Instant::now();
                let invalid = binding.recover_chunk(&hostile);
                let corrupt_reject_wall_ns = start.elapsed().as_nanos();
                row["chunk_observations"].as_array_mut().unwrap().push(json!({
                "index": index,
                "source_bytes": chunk.len(),
                "shard_payload_bytes": binding.shard_bytes(),
                "all_six_payload_bytes": 6 * binding.shard_bytes(),
                "retained_four_payload_bytes": 4 * binding.shard_bytes(),
                "all_six_wire_bytes": shards.iter().map(|s| s.encode().len()).sum::<usize>(),
                "binding_wall_ns": binding_wall_ns,
                "encode_wall_ns": encode_wall_ns,
                "selected_wire_roundtrip_wall_ns": wire_roundtrip_wall_ns,
                "recover_wall_ns": recover_wall_ns,
                "matches_source": restored.as_slice() == chunk,
                "corrupt_reject_wall_ns": corrupt_reject_wall_ns,
                "corrupt_rejected": invalid.is_err(),
                "corrupt_error": invalid.as_ref().err().map(ToString::to_string),
            }));
                if restored.as_slice() != chunk || invalid.is_ok() {
                    return Err(CellErrorV1::Invalid("erasure observation mismatch").into());
                }
                recovered.put_chunk(&manifest.chunks()[index], &restored)?;
            }
            let start = Instant::now();
            recovered.verify_complete(&manifest)?;
            row["complete_tcm1_verify_wall_ns"] = json!(start.elapsed().as_nanos());
            let output = directory.path().join("restored.bin");
            recovered.materialize(&manifest, &output)?;
            let restored_bytes = fs::read(output)?;
            if restored_bytes != bytes {
                return Err(CellErrorV1::Invalid("whole cell recovery mismatch").into());
            }
            row["complete_tcm1_payload_verified"] = json!(true);
            row["materialized_sha256"] = json!(hex::encode(Sha256::digest(restored_bytes)));
            Ok(())
        })();
    match result {
        Ok(()) => row["status"] = json!("PASS_LOCAL_OBSERVATION"),
        Err(error) => {
            row["status"] = json!("FAILED_OBSERVATION");
            row["error"] = json!(error.to_string());
        }
    }
    row
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rows = Vec::new();
    for repeat in 0..3 {
        for (size, chunk_bytes) in [
            (16_384, 16_384),
            (16_385, 16_384),
            (1_048_577, 16_384),
            (1_048_577, 4 * 1024 * 1024),
        ] {
            rows.push(observe(size, chunk_bytes, repeat));
        }
    }
    let failures = rows
        .iter()
        .filter(|r| r["status"] != "PASS_LOCAL_OBSERVATION")
        .count();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "trnm.cell-rs46-cost.v1",
            "profile": CELL_RS46_PROFILE_V1,
            "qualification": "HOLD_NO_GO",
            "production_consensus_activation": false,
            "workload": "deterministic synthetic Cell bytes; not a model",
            "timing": "monotonic wall-clock nanoseconds; CPU time and RSS not measured",
            "pack_timing_includes_native_file_reads_hashes_and_cache_writes": true,
            "recovery_timing_excludes_cache_writes_and_network": true,
            "network_requests": 0,
            "independent_provider_custody_qualified": false,
            "reward_sustainability_qualified": false,
            "example_source_sha256": hex::encode(Sha256::digest(include_bytes!("cell_rs46_cost_v1.rs"))),
            "implementation_source_sha256": hex::encode(Sha256::digest(include_bytes!("../src/cell/erasure.rs"))),
            "failed_observations": failures,
            "observations": rows,
        }))?
    );
    if failures != 0 {
        return Err("one or more erasure observations failed; records retained".into());
    }
    Ok(())
}
