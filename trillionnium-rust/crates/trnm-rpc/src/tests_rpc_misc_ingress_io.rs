use super::*;

#[test]
fn atomic_write_text_file_replaces_without_leaving_temp_files() {
    let path = unique_tmp_path("rpc-atomic-write", "json");
    let parent = path.parent().expect("temp parent").to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap()
        .to_string();
    let _ = fs::remove_file(&path);

    atomic_write_text_file(&path, "{\"ok\":true}\n").expect("atomic write succeeds");
    let raw = fs::read_to_string(&path).expect("read atomic target");
    assert_eq!(raw, "{\"ok\":true}\n");

    let leftovers: Vec<_> = fs::read_dir(&parent)
        .expect("read temp dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with(&format!(".{}.tmp-", file_name)))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary atomic-write files should be cleaned"
    );

    let _ = fs::remove_file(&path);
}
