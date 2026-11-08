//! Checkpoint and claim-boundary rejection tests, not cryptographic proof tests.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ArtifactDir(PathBuf);

impl ArtifactDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "trnm-w1-recursion-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for ArtifactDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn boundary_checks_reject_reordering_discontinuity_early_halt_and_output() {
    let left = schedule::Range { start: 0, end: 2 };
    let right = schedule::Range { start: 2, end: 3 };
    let digest = Digest::from([7u32; 8]);
    validate_join_boundary(left, right, digest, digest, ExitCode::SystemSplit, true).unwrap();
    assert!(validate_join_boundary(
        left,
        right,
        digest,
        Digest::from([8u32; 8]),
        ExitCode::SystemSplit,
        true
    )
    .is_err());
    assert!(
        validate_join_boundary(right, left, digest, digest, ExitCode::SystemSplit, true).is_err()
    );
    assert!(validate_join_boundary(
        left,
        schedule::Range { start: 3, end: 4 },
        digest,
        digest,
        ExitCode::SystemSplit,
        true
    )
    .is_err());
    assert!(
        validate_join_boundary(left, right, digest, digest, ExitCode::Halted(0), true).is_err()
    );
    assert!(
        validate_join_boundary(left, right, digest, digest, ExitCode::SystemSplit, false).is_err()
    );
}

#[test]
fn balanced_checkpoint_does_not_consume_legacy_or_other_resource_cache() {
    let dir = ArtifactDir::new();
    let old = dir.0.join("lift-0000.bin");
    fs::write(&old, [0u8]).unwrap();
    let other = dir.0.join(format!(
        "{}-lift-0000.bin",
        schedule::Resources::new(1, 8)
            .unwrap()
            .checkpoint_namespace()
    ));
    fs::write(&other, [1u8]).unwrap();
    let name = format!(
        "{}-lift-0000",
        schedule::Resources::new(2, 4)
            .unwrap()
            .checkpoint_namespace()
    );
    let called = AtomicUsize::new(0);
    let error = match recursive_checkpoint(&dir.0, &name, "lift", Digest::from([7u32; 8]), || {
        called.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("fresh proof remains required; no synthetic receipt is supplied")
    }) {
        Ok(_) => panic!("a deliberately failed proof call must remain an error"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("fresh proof remains required"));
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(old).unwrap(), [0u8]);
    assert_eq!(fs::read(other).unwrap(), [1u8]);
    assert!(!dir.0.join(format!("{name}.bin")).exists());
}

#[test]
fn truncated_checkpoint_is_retained_and_never_repaired_by_new_proving() {
    let dir = ArtifactDir::new();
    let name = format!(
        "{}-lift-0000",
        schedule::Resources::new(2, 4)
            .unwrap()
            .checkpoint_namespace()
    );
    let path = dir.0.join(format!("{name}.bin"));
    fs::write(&path, [0u8]).unwrap();
    let called = AtomicUsize::new(0);
    assert!(
        recursive_checkpoint(&dir.0, &name, "lift", Digest::from([7u32; 8]), || {
            called.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("must not replace an unreadable observation")
        })
        .is_err()
    );
    assert_eq!(called.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(path).unwrap(), [0u8]);
}

#[test]
fn worker_event_rows_remain_complete_json_and_keep_every_item() {
    let dir = ArtifactDir::new();
    schedule::scoped_items(
        16,
        2,
        |_| Ok(()),
        |_, worker, index| {
            event(
                &dir.0,
                json!({
                    "stage":"SCHEDULER_TEST_DATA_ONLY", "worker":worker,
                    "index":index,"payload":"x".repeat(8192)
                }),
            )?;
            Ok(index)
        },
    )
    .unwrap();
    let bytes = fs::read_to_string(dir.0.join("stages.jsonl")).unwrap();
    let mut indices: Vec<_> = bytes
        .lines()
        .map(|line| {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(row["event"]["stage"], "SCHEDULER_TEST_DATA_ONLY");
            assert_eq!(row["event"]["payload"].as_str().unwrap().len(), 8192);
            row["event"]["index"].as_u64().unwrap()
        })
        .collect();
    indices.sort_unstable();
    assert_eq!(indices, (0..16).collect::<Vec<_>>());
}
