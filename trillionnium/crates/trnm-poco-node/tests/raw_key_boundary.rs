//! Compile/source contract for the node's raw-consensus-key boundary.
//!
//! The node still contains deterministic key fixtures for tests and process
//! helpers.  This test makes the distinction executable: the default library
//! must compile without the fixture feature, and every source file which names
//! `SigningKey` must be either test-only or explicitly selected by a fixture
//! feature.  It is deliberately a source contract rather than a claim that a
//! test key is a production signer.

use std::{
    fs,
    path::{Path, PathBuf},
};

const RAW_KEY_TOKENS: [&str; 2] = ["SigningKey", "ed25519_dalek"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::metadata(&path).unwrap_or_else(|error| {
            panic!("stat {}: {error}", path.display());
        });
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).unwrap_or_else(|error| {
                panic!("read {}: {error}", path.display());
            }) {
                pending.push(
                    entry
                        .unwrap_or_else(|error| panic!("read directory entry: {error}"))
                        .path(),
                );
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

fn has_raw_key(source: &str) -> bool {
    RAW_KEY_TOKENS.iter().any(|token| source.contains(token))
}

fn assert_raw_lines_are_after_test_cfg(path: &Path, source: &str) {
    let first_test_cfg = source
        .match_indices("#[cfg")
        .find_map(|(offset, _)| {
            let tail = &source[offset..];
            let end = tail.find(']').map(|index| index + 1)?;
            tail[..end].contains("test").then_some(offset)
        })
        .unwrap_or_else(|| panic!("raw-key source is not test-gated: {}", path.display()));
    for (line_number, line) in source.lines().enumerate() {
        if RAW_KEY_TOKENS.iter().any(|token| line.contains(token)) {
            let offset = source
                .lines()
                .take(line_number)
                .map(|line| line.len() + 1)
                .sum::<usize>();
            assert!(
                offset >= first_test_cfg,
                "raw-key reference before #[cfg(test)] in {}:{}",
                path.display(),
                line_number + 1
            );
        }
    }
}

#[test]
fn host_raw_key_feature_has_no_production_dependency_claim() {
    assert_eq!(
        trnm_poco_node::FIXTURE_RAW_KEY_FEATURE_ONLY_V0,
        cfg!(feature = "fixture-raw-key")
    );
    assert!(!trnm_poco_node::PRODUCTION_RAW_KEY_DEPENDENCY_V0);

    let manifest = fs::read_to_string(manifest_dir().join("Cargo.toml"))
        .expect("read trnm-poco-node manifest");
    assert!(
        manifest.contains("fixture-raw-key = [\"dep:ed25519-dalek\"]"),
        "raw key must have one explicit fixture-only feature"
    );
    assert!(manifest.contains("fixture_raw_key_feature_only = true"));
    assert!(manifest.contains("production_raw_key_dependency = false"));
    assert!(manifest.contains("lab_raw_key_split_complete = false"));

    for feature in [
        "lab-validator-runtime-test-support",
        "recovery-process-test-support",
        "g2-process-test-support",
    ] {
        let feature_start = manifest
            .find(&format!("{feature} = ["))
            .unwrap_or_else(|| panic!("missing feature {feature}"));
        let feature_tail = &manifest[feature_start..]
            .split_once(']')
            .expect("feature list terminator")
            .0;
        assert!(
            feature_tail.contains("fixture-raw-key"),
            "{feature} must opt into fixture-raw-key explicitly"
        );
    }
}

#[test]
fn raw_key_references_are_test_or_fixture_gated() {
    let root = manifest_dir();
    let source_root = root.join("src");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read node manifest");
    let lib = fs::read_to_string(source_root.join("lib.rs")).expect("read node lib");

    for path in source_paths(&source_root) {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        if !has_raw_key(&source) {
            continue;
        }
        let relative = path
            .strip_prefix(&root)
            .unwrap_or_else(|error| panic!("strip {}: {error}", path.display()));
        let relative = relative.to_string_lossy();

        if relative == "src/native_h1_ordinary_test_support.rs" {
            assert!(
                lib.contains(
                    "#[cfg(feature = \"lab-validator-runtime-test-support\")]\nmod native_h1_ordinary_test_support;"
                ),
                "ordinary test-support raw key module lost its feature gate"
            );
            continue;
        }

        if relative == "src/g2_order_commit_v1_real_e2e.rs" {
            let parent = fs::read_to_string(source_root.join("g2_order_commit_v1.rs"))
                .expect("read G2 parent module");
            assert!(
                parent.contains("#[cfg(any(test, feature = \"g2-process-test-support\"))]"),
                "G2 raw-key module lost its test/fixture gate"
            );
            continue;
        }

        if relative == "src/recovery_tests.rs" {
            assert!(
                lib.contains(
                    "#[cfg(all(test, feature = \"recovery-test-support\", target_os = \"linux\"))]\nmod recovery_tests;"
                ),
                "recovery raw-key module lost its test/fixture gate"
            );
            continue;
        }

        if relative.starts_with("src/bin/") {
            let binary_name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .expect("binary file stem");
            let declaration = format!("name = \"{binary_name}\"");
            let Some(declaration_start) = manifest.find(&declaration) else {
                // This historical helper is deliberately not a Cargo target
                // (`autobins = false`); it cannot be pulled into a default or
                // production build.  If it is revived, it must be added back
                // with `required-features = ["recovery-process-test-support"]`.
                assert_eq!(
                    binary_name, "trnm-poco-recovery-kill-helper",
                    "unregistered raw-key binary must remain an archived helper"
                );
                assert!(manifest.contains("autobins = false"));
                continue;
            };
            let declaration_tail = &manifest[declaration_start..]
                .split_once("[[")
                .map(|(head, _)| head)
                .unwrap_or(&manifest[declaration_start..]);
            assert!(
                declaration_tail
                    .contains("required-features = [\"recovery-process-test-support\"]"),
                "raw-key helper {binary_name} must require the fixture feature"
            );
            continue;
        }

        // All remaining references are in an inline `#[cfg(test)]` module.
        // This catches an accidental production import while allowing the
        // deterministic test fixtures to keep their existing coverage.
        assert_raw_lines_are_after_test_cfg(&path, &source);
    }
}
