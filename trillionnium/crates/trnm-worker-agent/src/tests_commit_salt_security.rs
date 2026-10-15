//! Adversarial commitment hiding: fixed public task IDs must not reveal the salt.
#[test]
fn equal_public_task_identity_does_not_predict_unrevealed_commit_salts() {
    let (_, first) = crate::execute_payload("low-entropy-response", 1001).unwrap();
    let (_, second) = crate::execute_payload("low-entropy-response", 1001).unwrap();
    assert_eq!(first.len(), 64);
    assert_eq!(second.len(), 64);
    assert_ne!(
        first, second,
        "public task identity must not determine commitment salt"
    );
    assert_ne!(first, format!("{:064x}", 1001u64));
}

#[cfg(unix)]
mod durable {
    use crate::commit_salt::journal_automatic_submission;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::{Arc, Barrier};

    fn digest(payload: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(payload))
    }

    #[test]
    fn first_private_commit_survives_restart_and_keeps_exact_bytes_without_new_row() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("submissions.jsonl");
        let hash = digest(b"small known answer");
        let (_, proposal_a) = crate::execute_payload("small known answer", 17).unwrap();
        let (_, proposal_b) = crate::execute_payload("small known answer", 17).unwrap();
        assert_ne!(proposal_a, proposal_b);
        assert_eq!(
            journal_automatic_submission(&path, 17, "worker-a", &hash, &proposal_a).unwrap(),
            proposal_a
        );
        let original = fs::read(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.nlink(), 1);
        let retained =
            journal_automatic_submission(&path, 17, "worker-a", &hash, &proposal_b).unwrap();
        assert_eq!(
            retained, proposal_a,
            "a restarted owner must reuse the exact committed salt"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        let row: crate::SubmissionRecord =
            serde_json::from_slice(&original[..original.len() - 1]).unwrap();
        assert_eq!(
            row.commit_hash,
            crate::commitment(17, &hash, &proposal_a, "worker-a")
        );
        assert_eq!(row.nonce, Some(17));
        assert!(row.reveal_cmd.ends_with(&proposal_a));
    }

    #[test]
    fn manual_submit_keeps_explicit_salt_and_creates_an_owner_only_synced_log() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manual.jsonl");
        let worker = "worker-a";
        let result = digest(b"manual-result");
        let salt = "manually-chosen-salt";
        let commit_hash = crate::commitment(73, &result, salt, worker);
        crate::append_submission(&path, 73, worker, &commit_hash, &result, salt).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.nlink(), 1);
        let before = fs::read(&path).unwrap();
        assert!(before.ends_with(b"\n"));
        let rec: crate::SubmissionRecord =
            serde_json::from_slice(&before[..before.len() - 1]).unwrap();
        assert_eq!(rec.salt_hex, salt, "manual salt must not be silently regenerated");
        assert_eq!(rec.worker, worker);
        assert_eq!(rec.commit_hash, commit_hash);
        assert_eq!(
            rec.commit_cmd,
            crate::workflow_ops::commit_template(73, worker, &commit_hash, 73)
        );
        // Manual submission retains its explicit append semantics.
        crate::append_submission(&path, 73, worker, &commit_hash, &result, salt).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn manual_submit_rejects_public_symlink_hardlink_and_incomplete_logs() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manual.jsonl");
        let target = root.path().join("target.jsonl");
        let alias = root.path().join("hardlink.jsonl");
        let result = digest(b"manual");
        let salt = "manual-salt";
        let commit_hash = crate::commitment(74, &result, salt, "operator");
        let submit = |path: &std::path::Path| {
            crate::append_submission(path, 74, "operator", &commit_hash, &result, salt)
        };

        fs::write(&target, b"must-not-touch").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(submit(&path).is_err(), "manual salt must reject symlink targets");
        assert_eq!(fs::read(&target).unwrap(), b"must-not-touch");
        fs::remove_file(&path).unwrap();

        fs::write(&path, b"prior\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let old = fs::read(&path).unwrap();
        assert!(submit(&path).is_err(), "legacy public salt log must fail closed");
        assert_eq!(fs::read(&path).unwrap(), old);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::hard_link(&path, &alias).unwrap();
        assert!(submit(&path).is_err(), "hard linked salt log must fail closed");
        assert_eq!(fs::read(&path).unwrap(), old);
        fs::remove_file(&alias).unwrap();

        fs::write(&path, b"partial-json{").unwrap();
        let truncated = fs::read(&path).unwrap();
        assert!(submit(&path).is_err(), "partial JSON line must not be extended");
        assert_eq!(fs::read(path).unwrap(), truncated);
    }

    #[test]
    fn private_replay_quotes_untrusted_worker_without_changing_commit_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("submissions.jsonl");
        let worker = "w';$(echo injected)";
        let output = digest(b"known-output");
        let (_, first_salt) = crate::execute_payload("known-output", 71).unwrap();
        let (_, unused_second_salt) = crate::execute_payload("known-output", 71).unwrap();
        assert_eq!(
            journal_automatic_submission(&path, 71, worker, &output, &first_salt).unwrap(),
            first_salt
        );
        let original = fs::read(&path).unwrap();
        let row: crate::SubmissionRecord =
            serde_json::from_slice(&original[..original.len() - 1]).unwrap();
        assert_eq!(row.worker, worker);
        assert_eq!(
            row.commit_hash,
            crate::commitment(71, &output, &first_salt, worker),
            "command rendering must not change the original worker or commitment"
        );
        assert_eq!(
            row.commit_cmd,
            format!(
                "trnm-node tx commit-result 71 'w'\\'';$(echo injected)' {} 71",
                row.commit_hash
            ),
            "all worker metacharacters must remain inside one POSIX shell argument"
        );
        assert_eq!(
            journal_automatic_submission(&path, 71, worker, &output, &unused_second_salt).unwrap(),
            first_salt
        );
        assert_eq!(
            fs::read(path).unwrap(),
            original,
            "replay may not rewrite the first command"
        );
    }

    #[test]
    fn conflicting_result_or_worker_cannot_invent_second_commitment() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("submissions.jsonl");
        let one = digest(b"low entropy");
        let two = digest(b"changed output");
        let (_, s1) = crate::execute_payload("low entropy", 23).unwrap();
        let (_, s2) = crate::execute_payload("changed output", 23).unwrap();
        journal_automatic_submission(&path, 23, "first", &one, &s1).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(journal_automatic_submission(&path, 23, "first", &two, &s2).is_err());
        assert!(journal_automatic_submission(&path, 23, "second", &one, &s2).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn corrupted_incomplete_and_publicly_readable_logs_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("submissions.jsonl");
        let hash = digest(b"known");
        let (_, salt) = crate::execute_payload("known", 91).unwrap();
        fs::write(&path, b"{\"task_id\":91").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(journal_automatic_submission(&path, 91, "worker", &hash, &salt).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_file(&path).unwrap();
        journal_automatic_submission(&path, 91, "worker", &hash, &salt).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(journal_automatic_submission(&path, 91, "worker", &hash, &salt).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn symlink_input_never_opens_or_mutates_a_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target.jsonl");
        let link = root.path().join("submissions.jsonl");
        fs::write(&target, b"keep-original").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        let (_, salt) = crate::execute_payload("hello", 11).unwrap();
        assert!(
            journal_automatic_submission(&link, 11, "worker", &digest(b"hello"), &salt).is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"keep-original");
    }

    #[test]
    fn retained_identity_mutation_or_link_alias_never_overwrites_original_bytes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("submissions.jsonl");
        let alias = root.path().join("second-hardlink.jsonl");
        let hash = digest(b"value");
        let (_, salt) = crate::execute_payload("value", 55).unwrap();
        journal_automatic_submission(&path, 55, "worker", &hash, &salt).unwrap();
        let pristine = fs::read(&path).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(journal_automatic_submission(&path, 55, "worker", &hash, &salt).is_err());
        assert_eq!(fs::read(&path).unwrap(), pristine);
        fs::remove_file(&alias).unwrap();
        let mut altered: serde_json::Value =
            serde_json::from_slice(&pristine[..pristine.len() - 1]).unwrap();
        altered["commit_hash"] = serde_json::json!("00".repeat(32));
        let damaged = format!("{}\n", serde_json::to_string(&altered).unwrap());
        fs::write(&path, damaged.as_bytes()).unwrap();
        let old = fs::read(&path).unwrap();
        assert!(journal_automatic_submission(&path, 55, "worker", &hash, &salt).is_err());
        assert_eq!(fs::read(&path).unwrap(), old);
    }

    #[test]
    fn excessive_existing_log_is_not_read_into_unbounded_memory() {
        use std::fs::OpenOptions;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("submissions.jsonl");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(64 * 1024 * 1024 + 1).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (_, salt) = crate::execute_payload("tiny", 55).unwrap();
        assert!(
            journal_automatic_submission(&path, 55, "worker", &digest(b"tiny"), &salt).is_err()
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 64 * 1024 * 1024 + 1);
    }

    #[test]
    fn competing_local_threads_reuse_one_kernel_locked_journal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("submissions.jsonl");
        let barrier = Arc::new(Barrier::new(9));
        let output = std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for _ in 0..8 {
                let p = path.clone();
                let b = barrier.clone();
                joins.push(scope.spawn(move || {
                    let (_, salt) = crate::execute_payload("same", 43).unwrap();
                    b.wait();
                    journal_automatic_submission(&p, 43, "worker", &digest(b"same"), &salt).unwrap()
                }));
            }
            barrier.wait();
            joins
                .into_iter()
                .map(|join| join.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(output.len(), 8);
        assert!(output.iter().all(|v| v == &output[0]));
        assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 1);
    }
}
