use super::*;

pub(super) fn assert_lock_file_cleaned(ingress: &PathBuf) {
    let lock = ingress.with_file_name(format!(
        "{}.lock",
        ingress
            .file_name()
            .and_then(|v| v.to_str())
            .expect("ingress file name")
    ));
    assert!(
        !lock.exists(),
        "lock file should be cleaned after concurrent writers exit"
    );
}
