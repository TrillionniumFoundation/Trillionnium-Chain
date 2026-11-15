//! Native, offline cost observations for the restricted Cell/BEP52 binding.
//! All payloads are deterministic synthetic bytes, not models. This observes
//! no discovery, network, model loading, GPU, operator independence or payment.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, time::Instant};
use trnm_data_availability::cell::{
    digest_hex, CellBep52BindingV1, CellBep52ChunkProofV1, CellCacheConfigV4, CellContextV1,
    CellErrorV1, CellStoreV1, CELL_BEP52_PIECE_BYTES_V1, CELL_BEP52_PROFILE_V1,
};

fn observe(size: usize, repeat: u32) -> Value {
    let mut row = json!({
        "payload_bytes": size,
        "repeat": repeat,
        "fresh_temporary_cache": true,
        "status": "RUNNING",
        "chunk_observations": [],
    });
    let result = (|| -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("synthetic.bin");
        let bytes: Vec<u8> = (0..size)
            .map(|i| ((i.wrapping_mul(17) + i / 16_384) % 251) as u8)
            .collect();
        fs::write(&source, &bytes)?;
        let store = CellStoreV1::open(
            &directory.path().join("cache.sqlite"),
            CellCacheConfigV4 {
                max_database_bytes: 32 * 1024 * 1024,
                max_logical_bytes: 16 * 1024 * 1024,
                max_chunk_rows: 1024,
                max_manifest_rows: 32,
            },
        )?;
        let context = CellContextV1 {
            family: "bep52-synthetic-cost-v1".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime: [5; 32],
        };
        let start = Instant::now();
        let manifest = store.pack_file(&source, context.clone(), CELL_BEP52_PIECE_BYTES_V1)?;
        row["pack_file_wall_ns"] = json!(start.elapsed().as_nanos());
        row["manifest_id"] = json!(digest_hex(manifest.id()));
        row["payload_sha256"] = json!(digest_hex(manifest.payload_sha256()));
        row["chunk_count"] = json!(manifest.chunks().len());

        let start = Instant::now();
        let binding = CellBep52BindingV1::from_pinned_manifest(&manifest, manifest.id(), &context)?;
        row["binding_wall_ns"] = json!(start.elapsed().as_nanos());
        row["infohash"] = json!(digest_hex(binding.info_hash()));
        row["pieces_root"] = json!(digest_hex(binding.pieces_root()));
        row["info_bytes"] = json!(binding.info_bytes().len());
        row["metainfo_bytes"] = json!(binding.metainfo_bytes().len());

        let start = Instant::now();
        binding.verify_metainfo_bytes(&binding.metainfo_bytes())?;
        binding.verify_magnet(&binding.magnet().encode())?;
        row["descriptor_roundtrip_wall_ns"] = json!(start.elapsed().as_nanos());

        for (index, chunk) in bytes.chunks(CELL_BEP52_PIECE_BYTES_V1 as usize).enumerate() {
            let start = Instant::now();
            let proof = binding.chunk_proof(index as u32)?;
            let proof_wall_ns = start.elapsed().as_nanos();
            let encoded = proof.encode();
            let start = Instant::now();
            let decoded = CellBep52ChunkProofV1::decode(&encoded)?;
            let decode_wall_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            let valid = binding.verify_chunk(&decoded, chunk);
            let valid_wall_ns = start.elapsed().as_nanos();
            let mut corrupted = chunk.to_vec();
            corrupted[0] ^= 1;
            let start = Instant::now();
            let invalid = binding.verify_chunk(&decoded, &corrupted);
            let invalid_wall_ns = start.elapsed().as_nanos();
            row["chunk_observations"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "index": index,
                    "chunk_bytes": chunk.len(),
                    "proof_bytes": encoded.len(),
                    "proof_construction_wall_ns": proof_wall_ns,
                    "proof_decode_wall_ns": decode_wall_ns,
                    "valid_verify_wall_ns": valid_wall_ns,
                    "valid_accepted": valid.is_ok(),
                    "corrupt_verify_wall_ns": invalid_wall_ns,
                    "corrupt_rejected": invalid.is_err(),
                    "corrupt_error": invalid.as_ref().err().map(ToString::to_string),
                }));
            valid?;
            if invalid.is_ok() {
                return Err(CellErrorV1::Invalid("corrupt synthetic bytes accepted").into());
            }
        }
        let start = Instant::now();
        store.verify_complete(&manifest)?;
        row["complete_cached_payload_verify_wall_ns"] = json!(start.elapsed().as_nanos());
        row["complete_payload_verified"] = json!(true);
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
        for size in [3, 16_384, 16_385, 1_048_576, 1_048_577] {
            rows.push(observe(size, repeat));
        }
    }
    let failures = rows
        .iter()
        .filter(|row| row["status"] != "PASS_LOCAL_OBSERVATION")
        .count();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "trnm.cell-bep52-cost.v1",
            "profile": CELL_BEP52_PROFILE_V1,
            "qualification": "HOLD_NO_GO",
            "production_consensus_activation": false,
            "workload": "deterministic synthetic bytes; not tensors or models",
            "timing": "monotonic wall-clock nanoseconds; CPU time and RSS not measured",
            "pack_file_timing_scope": "existing native pack_file, including file reads, hashes and SQLite cache writes; excludes input generation and cache open",
            "verification_timing_scope": "in-memory chunk bytes and prebuilt binding; no transport or model loading",
            "network_requests": 0,
            "gpu_operations": 0,
            "rewards_observed": false,
            "example_source_sha256": hex::encode(Sha256::digest(include_bytes!("cell_bep52_cost_v1.rs"))),
            "binding_source_sha256": hex::encode(Sha256::digest(include_bytes!("../src/cell/bep52.rs"))),
            "failed_observations": failures,
            "observations": rows,
        }))?
    );
    if failures != 0 {
        return Err("one or more local observations failed; all records retained above".into());
    }
    Ok(())
}
