// Test-only: actual disposable original Node. The only pipe input is a barrier.
use serde_json::json;
use std::{
    env, fs,
    io::{self, Write},
    path::Path,
};
use trnm_pon_node::{development_public, Node, PoolLimits, Settings};
use trnm_protocol::pon_wire::hash;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().collect();
    assert_eq!(args.len(), 3);
    let mode = args[1].to_str().unwrap();
    assert!(matches!(mode, "fresh" | "refuse"));
    let path = Path::new(&args[2]);
    let root = path.parent().unwrap();
    assert!(path.is_absolute() && path.canonicalize()? == path && path.is_dir());
    assert!(root
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("m05-owner-shadow-"));
    let marker = root.join(".disposable-m05-owner-shadow");
    assert!(fs::symlink_metadata(&marker)?.file_type().is_file());
    assert_eq!(fs::read(marker)?, b"synthetic-local-node-only\n");
    let sqlite = path.join("native.sqlite");
    if mode == "fresh" {
        assert!(fs::read_dir(path)?.next().is_none());
    } else {
        assert!(fs::symlink_metadata(sqlite)?.file_type().is_file());
    }

    let mut node = Node::open(path, Settings::development(Some(1))?, 1)?;
    let limits = PoolLimits {
        max_records: if mode == "fresh" { 8 } else { 9 },
        max_bytes: 16384,
        max_group_members: 8,
        critical_reserve: 0,
        max_removals: 8,
        preview_miner: development_public(3)?,
    };
    let source = node.settings();
    let network = source.network();
    let parameters = source.parameters();
    let genesis = source.genesis();
    let mut request = b"LPV1".to_vec();
    for id in [&network, &parameters, &genesis, &limits.preview_miner] {
        request.extend_from_slice(id);
    }
    for limit in [
        limits.max_records as u64,
        limits.max_bytes as u64,
        limits.max_group_members as u64,
        limits.critical_reserve as u64,
        limits.max_removals as u64,
    ] {
        request.extend_from_slice(&limit.to_le_bytes());
    }
    let raw = serde_json::to_vec(&limits)?;
    let context = hash(
        b"native-local-queued-pnx1-v2",
        &[&network, &parameters, &genesis, &raw],
    );
    let original = node.read_active()?;
    let (parent, generation, _) = &original;
    println!(
        "{}",
        json!({
            "request": hex(&request), "reference_context": hex(&context), "reference_raw": hex(&raw),
            "active": [json!(hex(parent)), json!(generation)]
        })
    );
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    assert_eq!(line, "continue\n");

    // Deliberately re-enter the unchanged original public API with the typed
    // Rust policy captured above. The subprocess cannot receive a native value.
    let result = node.enable_local_mempool(limits);
    let (outcome, returned) = match result {
        Ok(value) => ("accepted".to_string(), Some(hex(&value))),
        Err(error) => (error.to_string(), None),
    };
    assert_eq!(node.read_active()?, original);
    let committed = node.pool_status_snapshot()?;
    assert!(committed.groups.is_empty() && committed.retained_records == 0);
    println!(
        "{}",
        json!({"outcome":outcome, "returned":returned, "readback_context":committed.context})
    );
    drop(node);
    Ok(())
}
