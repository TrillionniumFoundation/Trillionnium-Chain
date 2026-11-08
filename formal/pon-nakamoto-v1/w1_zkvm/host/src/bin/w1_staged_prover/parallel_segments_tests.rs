//! Batch fences and rejected real-decoder inputs. No successful proof is faked.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture {
    out: PathBuf,
    manifest_sha256: String,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let out = std::env::temp_dir().join(format!(
            "trnm-w1-parallel-segment-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst),
        ));
        fs::create_dir(&out).unwrap();
        let input = trnm_w1_zk_relation::fixture(0);
        let journal = check_complete_relation(&input).unwrap();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            source_commit: "test-source".into(),
            runner_sha256: "test-runner".into(),
            guest_sha256: sha(TRNM_W1_FULL_GUEST_ELF),
            image_id: TRNM_W1_FULL_GUEST_ID,
            r0vm_sha256: R0VM_SHA256.into(),
            input_sha256: sha(&input),
            journal_sha256: sha(&journal),
            full_claim_digest: original_claim(&journal).digest().to_string(),
            segment_limit_po2: 18,
            // These are deliberately invalid segment assets, never successful
            // SDK receipts. The fence must reject before constructing a client.
            segments: (0..2)
                .map(|index| Segment {
                    index,
                    po2: 18,
                    cycles: 1,
                    bytes: 1,
                    sha256: sha(&[index as u8]),
                })
                .collect(),
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        write_new(&out.join("manifest.json"), &manifest_bytes).unwrap();
        write_new(&out.join("input.bin"), &input).unwrap();
        write_new(&out.join("expected-journal.bin"), &journal).unwrap();
        for index in 0..2 {
            write_new(&out.join(format!("segment-{index:04}.bin")), &[index as u8]).unwrap();
        }
        Self {
            out,
            manifest_sha256: sha(&manifest_bytes),
        }
    }

    fn plan(&self) -> BatchPlan {
        BatchPlan {
            schema: BATCH_SCHEMA.into(),
            source_commit: "test-source".into(),
            runner_sha256: "test-runner".into(),
            manifest_sha256: self.manifest_sha256.clone(),
            start: 0,
            end: 2,
            workers: 2,
            rayon_threads: 4,
        }
    }

    fn call(&self) -> Result<()> {
        let unavailable_backend = self.out.join("backend-must-never-be-created-or-called");
        assert!(!unavailable_backend.exists());
        prove_parallel(
            &unavailable_backend,
            &self.out,
            2,
            schedule::Resources::new(2, 4).unwrap(),
            "test-source",
            "test-runner",
        )
    }

    fn no_canonical_receipts(&self) {
        assert!(!self.out.join("receipt-0000.bin").exists());
        assert!(!self.out.join("receipt-0001.bin").exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.out);
    }
}

fn metadata_only_completion(plan: &BatchPlan, plan_bytes: &[u8]) -> JoinedBatch {
    JoinedBatch {
        schema: JOINED_SCHEMA.into(),
        plan_sha256: sha(plan_bytes),
        candidates: (plan.start..plan.end)
            .map(|index| Candidate {
                index,
                bytes: 1,
                sha256: sha(&[0]),
                claim_digest: "0".repeat(64),
            })
            .collect(),
        all_started_rust_workers_joined: true,
        native_child_reaping_verified: false,
    }
}

#[test]
fn pending_batch_retains_candidates_and_cannot_redispatch_or_promote() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let bytes = serde_json::to_vec_pretty(&plan).unwrap();
    write_new(&plan_path(&fixture.out, 0), &bytes).unwrap();
    let candidate = plan.candidate_path(&fixture.out, 0).unwrap();
    write_new(&candidate, &[0]).unwrap();
    let error = fixture.call().unwrap_err();
    assert!(format!("{error:#}").contains("failed or pending"));
    assert_eq!(fs::read(&candidate).unwrap(), [0]);
    assert_eq!(fs::read(plan_path(&fixture.out, 0)).unwrap(), bytes);
    assert!(!joined_path(&fixture.out, 0).exists());
    fixture.no_canonical_receipts();
}

#[test]
fn completion_json_cannot_make_invalid_seals_into_a_verified_prefix() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let bytes = serde_json::to_vec_pretty(&plan).unwrap();
    write_new(&plan_path(&fixture.out, 0), &bytes).unwrap();
    for index in 0..2 {
        write_new(&plan.candidate_path(&fixture.out, index).unwrap(), &[0]).unwrap();
    }
    let joined = metadata_only_completion(&plan, &bytes);
    let joined_bytes = serde_json::to_vec_pretty(&joined).unwrap();
    write_new(&joined_path(&fixture.out, 0), &joined_bytes).unwrap();
    let error = fixture.call().unwrap_err();
    // The real bounded bincode/SDK receipt path must reject. No successful
    // receipt or verification function is substituted in this test.
    assert!(format!("{error:#}")
        .contains("parallel candidate is not a complete bounded segment receipt"));
    assert_eq!(
        fs::read(joined_path(&fixture.out, 0)).unwrap(),
        joined_bytes
    );
    assert_eq!(
        fs::read(plan.candidate_path(&fixture.out, 0).unwrap()).unwrap(),
        [0]
    );
    fixture.no_canonical_receipts();
}

#[test]
fn changed_candidate_is_retained_and_cannot_be_published() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let bytes = serde_json::to_vec_pretty(&plan).unwrap();
    write_new(&plan_path(&fixture.out, 0), &bytes).unwrap();
    let joined = metadata_only_completion(&plan, &bytes);
    write_new(
        &joined_path(&fixture.out, 0),
        &serde_json::to_vec_pretty(&joined).unwrap(),
    )
    .unwrap();
    let candidate = plan.candidate_path(&fixture.out, 0).unwrap();
    write_new(&candidate, &[1]).unwrap();
    let error = fixture.call().unwrap_err();
    assert!(format!("{error:#}").contains("candidate bytes changed"));
    assert_eq!(fs::read(candidate).unwrap(), [1]);
    fixture.no_canonical_receipts();
}

#[test]
fn orphan_completion_cannot_authorize_a_new_batch() {
    let fixture = Fixture::new();
    write_new(&joined_path(&fixture.out, 0), b"untrusted completion").unwrap();
    let error = fixture.call().unwrap_err();
    assert!(format!("{error:#}").contains("orphan parallel batch completion"));
    assert!(!plan_path(&fixture.out, 0).exists());
    fixture.no_canonical_receipts();
}

#[test]
fn batch_plan_binds_source_manifest_range_and_resource_budget() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let valid = |plan: &BatchPlan| {
        plan.validate(0, 2, &fixture.manifest_sha256, "test-source", "test-runner")
    };
    valid(&plan).unwrap();
    let mut changed = plan.clone();
    changed.manifest_sha256 = "f".repeat(64);
    assert!(valid(&changed).is_err());
    changed = plan.clone();
    changed.source_commit.push('x');
    assert!(valid(&changed).is_err());
    changed = plan.clone();
    changed.runner_sha256.push('x');
    assert!(valid(&changed).is_err());
    changed = plan.clone();
    changed.start = 1;
    assert!(valid(&changed).is_err());
    changed = plan.clone();
    changed.end = 3;
    assert!(valid(&changed).is_err());
    changed = plan.clone();
    changed.end = 0;
    assert!(valid(&changed).is_err());
    changed = plan.clone();
    changed.rayon_threads = 8;
    assert!(valid(&changed).is_err());
    let mut other = plan.clone();
    other.workers = 1;
    other.rayon_threads = 8;
    assert_ne!(
        plan.candidate_path(&fixture.out, 0).unwrap(),
        other.candidate_path(&fixture.out, 0).unwrap()
    );
    assert_ne!(
        plan.candidate_path(&fixture.out, 0).unwrap(),
        fixture.out.join("receipt-0000.bin")
    );
    assert!(plan.candidate_path(&fixture.out, 2).is_err());
}

#[test]
fn completion_metadata_requires_all_ordered_candidates_and_exact_plan_bytes() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let bytes = serde_json::to_vec_pretty(&plan).unwrap();
    let joined = metadata_only_completion(&plan, &bytes);
    // This is only a structural check; the invalid bytes above still cannot
    // survive actual receipt decoding or seal and prefix verification.
    joined.validate(&plan, &bytes).unwrap();
    let mut changed = joined.clone();
    changed.candidates.pop();
    assert!(changed.validate(&plan, &bytes).is_err());
    changed = joined.clone();
    changed.candidates.swap(0, 1);
    assert!(changed.validate(&plan, &bytes).is_err());
    changed = joined.clone();
    changed.candidates[1].index = 0;
    assert!(changed.validate(&plan, &bytes).is_err());
    changed = joined.clone();
    changed.all_started_rust_workers_joined = false;
    assert!(changed.validate(&plan, &bytes).is_err());
    changed = joined.clone();
    changed.native_child_reaping_verified = true;
    assert!(changed.validate(&plan, &bytes).is_err());
    changed = joined.clone();
    changed.candidates[0].claim_digest.pop();
    assert!(changed.validate(&plan, &bytes).is_err());
    let mut changed_bytes = bytes.clone();
    changed_bytes.push(b'\n');
    assert!(joined.validate(&plan, &changed_bytes).is_err());
    let mut invalid_range = plan.clone();
    invalid_range.start = plan.end + 1;
    assert!(joined.validate(&invalid_range, &bytes).is_err());
    let mut json = serde_json::to_value(&joined).unwrap();
    json["assume_verified"] = true.into();
    assert!(serde_json::from_value::<JoinedBatch>(json).is_err());
}
