// Test-only adapter: invokes unmodified public trnm-pon-node on a fixture-only directory.
use std::{env, fs, path::Path};
use trnm_pon_node::{development_public, Node, PoolLimits, Settings};

const MARKER: &[u8] = b"dot-m05-disposable-policy-fixture\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().collect();
    assert_eq!(args.len(), 3);
    let mode = args[1].to_str().unwrap();
    let path = Path::new(&args[2]);
    assert!(path.is_absolute() && fs::symlink_metadata(path)?.file_type().is_dir());
    assert!(path.parent().unwrap().file_name().unwrap().to_str().unwrap().starts_with("trnm-m05-held-policy-"));
    assert!(fs::symlink_metadata(path.parent().unwrap().join(".m05-test-owned"))?.file_type().is_file());
    assert_eq!(fs::read(path.parent().unwrap().join(".m05-test-owned"))?, MARKER);
    let db = path.join("native.sqlite");
    if mode == "fresh" {
        assert!(!db.exists());
    } else {
        assert!(fs::symlink_metadata(&db)?.file_type().is_file());
    }
    let settings = Settings::development(Some(1))?;
    let miner = development_public(3)?;
    println!("network\t{}", hex(&settings.network()));
    println!("parameters\t{}", hex(&settings.parameters()));
    println!("genesis\t{}", hex(&settings.genesis()));
    println!("preview_miner\t{}", hex(&miner));
    let good = PoolLimits {
        max_records: 8,
        max_bytes: 16384,
        max_group_members: 8,
        critical_reserve: 0,
        max_removals: 8,
        preview_miner: miner,
    };
    let mut node = Node::open(path, settings, 1)?;
    let before = node.read_active()?;
    match mode {
        "fresh" => {
            let context = node.enable_local_mempool(good.clone())?;
            assert_eq!(node.enable_local_mempool(good)?, context);
            let status = node.pool_status_snapshot()?;
            assert_eq!(status.context, hex(&context));
            assert_eq!(status.retained_records, 0);
            assert!(status.groups.is_empty());
            println!("context\t{}", status.context);
        }
        "cold" => {
            let status = node.pool_status_snapshot()?;
            assert_eq!(status.retained_records, 0);
            assert!(status.groups.is_empty());
            println!("context\t{}", status.context);
        }
        "refuse" => {
            let baseline = node.pool_status_snapshot()?;
            let mut invalid = good.clone();
            invalid.max_records = 0;
            let refusal = node.enable_local_mempool(invalid).unwrap_err();
            assert_eq!(refusal.to_string(), "POOL_LIMITS");
            let mut changed = good.clone();
            changed.max_records = 9;
            let refusal = node.enable_local_mempool(changed).unwrap_err();
            assert_eq!(refusal.to_string(), "POOL_CONTEXT");
            let after = node.pool_status_snapshot()?;
            assert_eq!(baseline.context, after.context);
            assert_eq!(baseline.retained_records, after.retained_records);
            assert_eq!(baseline.retained_bytes, after.retained_bytes);
            assert_eq!(baseline.local_removals, after.local_removals);
            assert_eq!(baseline.generation, after.generation);
            assert_eq!(baseline.parent, after.parent);
            println!("context\t{}", after.context);
            println!("refusals\tPOOL_LIMITS,POOL_CONTEXT");
            assert_eq!(hex(&node.enable_local_mempool(good)?), after.context);
        }
        "refuse_same_context_stale_policy" => {
            let e = node.pool_status_snapshot().unwrap_err();
            assert_eq!(e.to_string(), "POOL_CONTEXT");
            let e = node.enable_local_mempool(good).unwrap_err();
            assert_eq!(e.to_string(), "POOL_CONTEXT");
            println!("refusals\tPOOL_CONTEXT,POOL_CONTEXT");
        }
        _ => panic!("test mode only"),
    }
    assert_eq!(node.read_active()?, before);
    println!("active_parent\t{}", hex(&before.0));
    println!("active_generation\t{}", before.1);
    drop(node);
    Ok(())
}
