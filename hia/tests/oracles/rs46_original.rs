//! Test-only observation of the unchanged original RS(6,4) implementation.
//!
//! Appended beneath cell::erasure only in an isolated complete workspace.
//! HRS1 supplies an already selected chunk pin. Constructing that private pin
//! here compares the byte kernel; it does not authenticate a TCM1/context or
//! create a production release, provider, retention or execution authority.
use super::*;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::Path;

fn bounded_read(path: &Path, bound: u64) -> Vec<u8> {
    let metadata = std::fs::symlink_metadata(path).expect("regular oracle input");
    assert!(metadata.is_file() && metadata.len() <= bound);
    let mut file = std::fs::File::open(path).expect("open oracle input");
    assert_eq!(file.metadata().unwrap().len(), metadata.len());
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(bound + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() as u64 <= bound);
    assert_eq!(bytes.len() as u64, metadata.len());
    bytes
}

fn original(request: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() < 80
        || &request[..4] != b"HRS1"
        || request[4] != 1
        || request[7] != 0
        || request[5] > 1
    {
        return Err("HRS1 wrapper".into());
    }
    let operation = request[5];
    let count = usize::from(request[6]);
    let index = u32::from_le_bytes(request[40..44].try_into().unwrap());
    let source_size = u32::from_le_bytes(request[44..48].try_into().unwrap());
    if !(1..=MAX_CHUNK_BYTES).contains(&source_size) || index > MAX_CHUNK_INDEX {
        return Err("HRS1 selected pin extent".into());
    }
    let binding = CellRs46ChunkBindingV1 {
        manifest: request[8..40].try_into().unwrap(),
        index,
        chunk: CellChunkV1 {
            size: source_size,
            sha256: request[48..80].try_into().unwrap(),
        },
    };
    let body = &request[80..];
    if operation == 0 {
        if count != 0 || body.len() != source_size as usize {
            return Err("HRS1 encode extent".into());
        }
        // These methods and their GF arithmetic, padding, SHA, CRS1 framing
        // and validation remain the complete original implementation.
        let shards = binding.encode_chunk(body).map_err(|e| e.to_string())?;
        Ok(shards.iter().flat_map(CellRs46ShardV1::encode).collect())
    } else {
        if !(4..=6).contains(&count) {
            return Err("HRS1 recovery count".into());
        }
        let wire_bytes = SHARD_HEADER_BYTES + source_size.div_ceil(4) as usize;
        if body.len() != count * wire_bytes {
            return Err("HRS1 recovery extent".into());
        }
        let shards = body
            .chunks_exact(wire_bytes)
            .map(CellRs46ShardV1::decode)
            .collect::<CellResultV1<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        binding.recover_chunk(&shards).map_err(|e| e.to_string())
    }
}

#[test]
fn evaluate() {
    let corpus_path = std::env::var("TRNM_HIA_RS46_ORACLE_CORPUS")
        .expect("explicit independent original corpus");
    let corpus_path = Path::new(&corpus_path);
    let directory = corpus_path.parent().expect("corpus directory");
    let corpus = bounded_read(corpus_path, 1024 * 1024);
    let corpus = std::str::from_utf8(&corpus).expect("UTF-8 corpus");
    let mut cases = 0;
    for line in corpus.lines() {
        let row: Value = serde_json::from_str(line).expect("typed corpus row");
        let name = row["name"].as_str().expect("case name");
        let stem = row["stem"].as_str().expect("case file stem");
        assert!(!stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit()));
        let input = directory.join(format!("{stem}.input"));
        let output = directory.join(format!("{stem}.original"));
        assert!(!output.exists());
        let request = bounded_read(&input, 80 + 6 * MAX_CELL_RS46_SHARD_WIRE_BYTES_V1 as u64);
        let input_sha256 = hex::encode(Sha256::digest(&request));
        let result = match original(&request) {
            Ok(bytes) => {
                let mut file = std::fs::OpenOptions::new()
                    .write(true).create_new(true).open(output).expect("new oracle output");
                file.write_all(&bytes).expect("complete original bytes");
                json!({"name": name, "accepted": true, "error": null,
                    "input_sha256": input_sha256, "output_bytes": bytes.len(),
                    "output_sha256": hex::encode(Sha256::digest(&bytes))})
            }
            Err(error) => json!({"name": name, "accepted": false, "error": error,
                "input_sha256": input_sha256, "output_bytes": 0, "output_sha256": null}),
        };
        println!("HIA_RS46_ORIGINAL:{result}");
        cases += 1;
    }
    assert!(cases > 0, "an empty corpus cannot qualify the original adapter");
}
