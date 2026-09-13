use std::{
    env, fs,
    path::{Path, PathBuf},
};

const WAL_BYTES_V1: usize = 28_263;
const GENERATED_NAME_V1: &str = "finalization_intent_wal_process_v1.rs";

fn replace_exact_once_v1(source: String, old: &str, new: &str, label: &str) -> String {
    let matches = source.match_indices(old).count();
    assert_eq!(
        matches, 1,
        "G1-R4A build preimage mismatch for {label}: expected one match, found {matches}"
    );
    source.replacen(old, new, 1)
}

fn read_fragment_v1(manifest_dir: &Path, name: &str) -> String {
    fs::read_to_string(manifest_dir.join("src").join(name))
        .unwrap_or_else(|error| panic!("read G1-R4A source fragment {name}: {error}"))
}

fn main() {
    for path in [
        "src/finalization_intent_wal.rs",
        "src/finalization_intent_process_prefix_v1.inc",
        "src/finalization_intent_process_support_v1_1.inc",
        "src/finalization_intent_process_support_v1_2.inc",
        "src/finalization_intent_process_support_v1_3.inc",
        "src/finalization_intent_process_support_v1_4.inc",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    if env::var_os("CARGO_FEATURE_LAB_VALIDATOR_RUNTIME_TEST_SUPPORT").is_none() {
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let wal_path = manifest_dir.join("src/finalization_intent_wal.rs");
    let mut generated = fs::read_to_string(&wal_path)
        .unwrap_or_else(|error| panic!("read exact production finalization WAL: {error}"));
    assert_eq!(
        generated.len(),
        WAL_BYTES_V1,
        "production finalization WAL byte length changed; review the exact-derived process copy"
    );

    generated = replace_exact_once_v1(
        generated,
        "#![cfg(feature = \"lab-validator-runtime\")]\n\n",
        "",
        "module cfg",
    );
    let mut normalized = String::with_capacity(generated.len());
    for line in generated.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("//!") {
            normalized.push_str("//");
            normalized.push_str(rest);
        } else {
            normalized.push_str(line);
        }
    }
    generated = normalized;

    generated = replace_exact_once_v1(
        generated,
        "use sha2::{Digest, Sha256};\n",
        "#[cfg(feature = \"lab-validator-runtime-test-support\")]\nuse std::sync::OnceLock;\n\nuse sha2::{Digest, Sha256};\n",
        "process OnceLock import",
    );

    let prefix = read_fragment_v1(&manifest_dir, "finalization_intent_process_prefix_v1.inc");
    generated = replace_exact_once_v1(
        generated,
        "const FIXED_BYTES_V0: usize = 8 + (6 * 8) + (11 * 32) + 32;\n",
        &format!("const FIXED_BYTES_V0: usize = 8 + (6 * 8) + (11 * 32) + 32;\n{prefix}"),
        "process checkpoint prefix",
    );

    generated = replace_exact_once_v1(
        generated,
        "    file.write_all(&marker.encode())\n        .and_then(|()| file.sync_all())\n        .map_err(|_| \"finalization intent temporary marker fsync failed\")?;\n    drop(file);\n",
        "    file.write_all(&marker.encode())\n        .and_then(|()| file.sync_all())\n        .map_err(|_| \"finalization intent temporary marker fsync failed\")?;\n    #[cfg(feature = \"lab-validator-runtime-test-support\")]\n    maybe_hold_process_checkpoint_v1(\n        FinalizationIntentProcessCheckpointV1::WriteTempFsyncedBeforePublish,\n        store_path,\n        marker,\n    )?;\n    drop(file);\n",
        "temp fsync cut",
    );

    generated = replace_exact_once_v1(
        generated,
        "    sync_parent_v0(&path, parent_identity)?;\n    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;\n    validate_path_identity_v0(\n        &temp,\n",
        "    sync_parent_v0(&path, parent_identity)?;\n    #[cfg(feature = \"lab-validator-runtime-test-support\")]\n    maybe_hold_process_checkpoint_v1(\n        FinalizationIntentProcessCheckpointV1::WritePublishedBeforeTempCleanup,\n        store_path,\n        marker,\n    )?;\n    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;\n    validate_path_identity_v0(\n        &temp,\n",
        "published-before-cleanup cut",
    );

    generated = replace_exact_once_v1(
        generated,
        "    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;\n    ensure_parent_identity_v0(&path, parent_identity)?;\n    sync_parent_v0(&path, parent_identity)\n}\n\npub(crate) fn clear_marker_v0(\n",
        "    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;\n    ensure_parent_identity_v0(&path, parent_identity)?;\n    sync_parent_v0(&path, parent_identity)?;\n    #[cfg(feature = \"lab-validator-runtime-test-support\")]\n    maybe_hold_process_checkpoint_v1(\n        FinalizationIntentProcessCheckpointV1::WriteCompleteBeforeReturn,\n        store_path,\n        marker,\n    )?;\n    Ok(())\n}\n\npub(crate) fn clear_marker_v0(\n",
        "write-complete cut",
    );

    generated = replace_exact_once_v1(
        generated,
        "    fs::remove_file(&path).map_err(|_| \"finalization intent marker remove failed\")?;\n    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;\n",
        "    fs::remove_file(&path).map_err(|_| \"finalization intent marker remove failed\")?;\n    #[cfg(feature = \"lab-validator-runtime-test-support\")]\n    maybe_hold_process_checkpoint_v1(\n        FinalizationIntentProcessCheckpointV1::ClearUnlinkedBeforeParentFsync,\n        store_path,\n        expected,\n    )?;\n    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;\n",
        "clear-unlinked cut",
    );

    let mut support = String::new();
    for name in [
        "finalization_intent_process_support_v1_1.inc",
        "finalization_intent_process_support_v1_2.inc",
        "finalization_intent_process_support_v1_3.inc",
        "finalization_intent_process_support_v1_4.inc",
    ] {
        support.push_str(&read_fragment_v1(&manifest_dir, name));
    }
    generated = replace_exact_once_v1(
        generated,
        "    if fs::symlink_metadata(&path).is_ok() {\n        return Err(\"finalization intent marker reappeared during clear\");\n    }\n    sync_parent_v0(&path, parent_identity)\n}\n\n#[cfg(test)]\n",
        &format!(
            "    if fs::symlink_metadata(&path).is_ok() {{\n        return Err(\"finalization intent marker reappeared during clear\");\n    }}\n    sync_parent_v0(&path, parent_identity)?;\n    #[cfg(feature = \"lab-validator-runtime-test-support\")]\n    maybe_hold_process_checkpoint_v1(\n        FinalizationIntentProcessCheckpointV1::ClearCompleteBeforeReturn,\n        store_path,\n        expected,\n    )?;\n    Ok(())\n}}\n{support}\n#[cfg(test)]\n"
        ),
        "clear-complete cut and process support",
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out_dir.join(GENERATED_NAME_V1), generated)
        .unwrap_or_else(|error| panic!("write exact-derived G1-R4A process module: {error}"));
}
