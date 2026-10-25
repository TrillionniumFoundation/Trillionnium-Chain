//! Real independent CLI writers, pinned readers, dedup and cold recovery.
//! This bounds supported cache sidecars; it is not an operating-system quota.
use rusqlite::Connection;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trnm_data_availability::cell::{
    parse_digest, CellCacheConfigV4, CellCacheUsageV2, CellStoreV1,
};

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 1_048_576,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 1024,
        max_manifest_rows: 64,
    }
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(suffix);
    p.into()
}
fn command(path: &Path, input: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-cell"));
    command
        .args(["pack", "--store"])
        .arg(path)
        .arg("--input")
        .arg(input)
        .args([
            "--family",
            "wal-cli",
            "--base",
            &"01".repeat(32),
            "--parent",
            &"02".repeat(32),
            "--tokenizer",
            &"03".repeat(32),
            "--layout",
            &"04".repeat(32),
            "--runtime",
            &"05".repeat(32),
            "--chunk-bytes",
            "16384",
            "--cache-max-db-bytes",
            "1048576",
            "--cache-max-bytes",
            "1048576",
            "--cache-max-chunks",
            "1024",
            "--cache-max-manifests",
            "64",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
struct Owned(Option<Child>);
impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn finish(mut owner: Owned) -> std::process::Output {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if owner.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            return owner.0.take().unwrap().wait_with_output().unwrap();
        }
        assert!(Instant::now() < end, "owned cache CLI deadline");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn two_actual_process_writers_share_the_cache_gate_and_replay_exactly_after_reader_release() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.sqlite");
    drop(CellStoreV1::open(&path, config()).unwrap());
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(sidecar(&path, "-writer-lock-v4"))
        .unwrap();
    lock.lock().unwrap();
    let inputs: Vec<_> = (0..2)
        .map(|worker| {
            let input = directory.path().join(format!("input-{worker}"));
            let bytes: Vec<u8> = (1..=8)
                .flat_map(|n| std::iter::repeat_n(worker * 8 + n, 16384))
                .collect();
            fs::write(&input, &bytes).unwrap();
            (input, bytes)
        })
        .collect();
    let mut children: Vec<_> = inputs
        .iter()
        .map(|(input, _)| Owned(Some(command(&path, input).spawn().unwrap())))
        .collect();
    assert_ne!(
        children[0].0.as_ref().unwrap().id(),
        children[1].0.as_ref().unwrap().id()
    );
    thread::sleep(Duration::from_millis(20));
    for child in &mut children {
        assert!(child.0.as_mut().unwrap().try_wait().unwrap().is_none());
    }
    lock.unlock().unwrap();
    let outputs: Vec<_> = children.into_iter().map(finish).collect();
    let mut manifests = Vec::new();
    let cache = CellStoreV1::open_read_only(&path).unwrap();
    let mut wire_bytes = 0;
    for output in &outputs {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["chunks"], 8);
        let id = parse_digest(report["manifest"].as_str().unwrap()).unwrap();
        let manifest = cache.manifest(id).unwrap().unwrap();
        wire_bytes += manifest.encode().len() as u64;
        cache.verify_complete(&manifest).unwrap();
        manifests.push(manifest);
    }
    let expected = CellCacheUsageV2 {
        logical_bytes: 2 * 8 * 16384 + 16 * 32 + 2 * 32 + wire_bytes,
        chunk_rows: 16,
        manifest_rows: 2,
    };
    assert_eq!(cache.cache_usage().unwrap(), expected);
    drop(cache);
    let reader = Connection::open(&path).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM cell_cache_quota_v4")
        .unwrap();
    let wal_before = fs::metadata(sidecar(&path, "-wal")).unwrap().len();
    let rejected = finish(Owned(Some(command(&path, &inputs[0].0).spawn().unwrap())));
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("CELL_CACHE_WRITER_BUSY"));
    assert_eq!(
        fs::metadata(sidecar(&path, "-wal")).unwrap().len(),
        wal_before
    );
    assert_eq!(
        CellStoreV1::open_read_only(&path)
            .unwrap()
            .cache_usage()
            .unwrap(),
        expected
    );
    reader.execute_batch("ROLLBACK").unwrap();
    let retry = finish(Owned(Some(command(&path, &inputs[0].0).spawn().unwrap())));
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    for cache in [
        CellStoreV1::open_read_only(&path).unwrap(),
        CellStoreV1::open(&path, config()).unwrap(),
    ] {
        assert_eq!(cache.cache_usage().unwrap(), expected);
        for (n, manifest) in manifests.iter().enumerate() {
            cache.verify_complete(manifest).unwrap();
            assert_eq!(manifest.size(), inputs[n].1.len() as u64);
        }
    }
    assert!(fs::metadata(&path).unwrap().len() <= config().max_database_bytes);
    assert!(fs::metadata(sidecar(&path, "-wal"))
        .map_or(true, |m| m.len() <= config().max_wal_bytes().unwrap()));
    assert!(fs::metadata(sidecar(&path, "-shm"))
        .map_or(true, |m| m.len() <= config().max_shm_bytes().unwrap()));
    assert_eq!(
        File::open(sidecar(&path, "-writer-lock-v4"))
            .unwrap()
            .metadata()
            .unwrap()
            .len(),
        0
    );
}
