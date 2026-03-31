use super::helpers::args_with_wal_dir;
use super::*;

#[test]
fn resolve_wal_dir_fail_if_exists_rejects_stale_state() {
    let wal_dir = temp_wal_dir("fail-if-exists");
    fs::create_dir_all(&wal_dir).unwrap();
    fs::write(wal_meta_file(&wal_dir), "existing").unwrap();

    let args = args_with_wal_dir(wal_dir.display().to_string(), WalDirMode::FailIfExists);

    let err = resolve_wal_dir(&args).unwrap_err().to_string();
    assert!(
        err.contains("refusing to reuse existing BFT WAL state")
            && err.contains(&wal_dir.display().to_string())
            && err.contains("--bft-wal-mode reuse")
            && err.contains("--bft-wal-dir"),
        "unexpected fail-if-exists error: {err}"
    );

    let _ = fs::remove_dir_all(&wal_dir);
}
