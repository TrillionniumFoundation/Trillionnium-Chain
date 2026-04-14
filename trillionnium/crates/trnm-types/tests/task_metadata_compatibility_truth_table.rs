use trnm_types::{
    TaskMetadata, TaskMetadataCompatibility, TaskMetadataCompatibilityFinding, TaskObject,
    TaskSettlementSnapshot, TaskSettlementSnapshotSource, TaskStatus,
};

fn task_with_metadata(metadata: Option<TaskMetadata>) -> TaskObject {
    TaskObject {
        task_id: 42,
        creator: "did:trnm:creator:test".into(),
        bounty: 777,
        status: TaskStatus::Assigned,
        proof_type: Default::default(),
        metadata,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    }
}

#[test]
fn task_metadata_compatibility_truth_table_preserves_typed_governance_upgrade_decisions() {
    let cases = [
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: true,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: true,
            },
            false,
            None,
            Vec::new(),
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: true,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: true,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: false,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: true,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields),
            vec![TaskMetadataCompatibilityFinding::NonCanonicalCoreFields],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: true,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: true,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot),
            vec![TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: true,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot),
            vec![TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: false,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: true,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: true,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: true,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: true,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: false,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: true,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields),
            vec![
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: false,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields),
            vec![
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: false,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields),
            vec![
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: true,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot),
            vec![
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: false,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: false,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: true,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: true,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: false,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        ),
    ];

    assert_eq!(
        cases.len(),
        16,
        "truth table should enumerate all 16 compatibility combinations"
    );

    for (compatibility, requires_upgrade, primary_finding, findings) in cases {
        assert_eq!(
            compatibility.is_runtime_compatible(),
            compatibility.canonical_core_fields
                && compatibility.complete_metering_snapshot
                && compatibility.complete_settlement_snapshot,
            "compatibility={compatibility:?}"
        );
        assert_eq!(
            compatibility.requires_governance_upgrade(),
            requires_upgrade,
            "compatibility={compatibility:?}"
        );
        assert_eq!(
            compatibility.primary_finding(),
            primary_finding,
            "compatibility={compatibility:?}"
        );
        assert_eq!(
            compatibility.findings(),
            findings,
            "compatibility={compatibility:?}"
        );
    }
}

#[test]
fn task_metadata_compatibility_truth_table_settlement_threading_promotes_legacy_fallback_without_breaking_note_only_compatibility(
) {
    let fallback_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "a".repeat(64)),
        output_token_count: 512,
        output_root: Some(format!("0x{}", "b".repeat(64))),
        output_span_commitment: None,
    };
    let legacy_metadata = TaskMetadata {
        note: Some("legacy".into()),
        ..TaskMetadata::default()
    };

    let legacy_report =
        legacy_metadata.compatibility_report_with_settlement_snapshot(Some(&fallback_settlement));
    assert_eq!(
        legacy_report.settlement_snapshot_source,
        TaskSettlementSnapshotSource::LegacyFallback
    );
    assert!(legacy_report.compatibility.legacy_note_only);
    assert!(legacy_report.compatibility.complete_settlement_snapshot);
    assert_eq!(
        legacy_report.findings,
        vec![TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload]
    );

    let mut threaded_metadata = legacy_metadata.clone();
    assert!(threaded_metadata.thread_settlement_snapshot(Some(&fallback_settlement)));
    assert_eq!(
        threaded_metadata.settlement.as_ref(),
        Some(&fallback_settlement)
    );
    assert_eq!(
        threaded_metadata.settlement_snapshot_source(None),
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert!(!threaded_metadata.thread_settlement_snapshot(Some(&fallback_settlement)));

    let threaded_report = threaded_metadata.compatibility_report();
    assert_eq!(
        threaded_report.settlement_snapshot_source,
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert!(!threaded_report.compatibility.legacy_note_only);
    assert!(threaded_report.compatibility.complete_settlement_snapshot);
    assert!(threaded_report.compatibility.is_runtime_compatible());
    assert!(!threaded_report.requires_governance_upgrade);
    assert!(threaded_report.findings.is_empty());
}

#[test]
fn task_metadata_compatibility_truth_table_settlement_threading_keeps_legacy_note_only_fallback_distinct_from_threaded_incomplete_snapshot(
) {
    let incomplete_fallback_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "c".repeat(64)),
        output_token_count: 512,
        output_root: None,
        output_span_commitment: None,
    };
    let legacy_metadata = TaskMetadata {
        note: Some("legacy".into()),
        ..TaskMetadata::default()
    };

    let legacy_report = legacy_metadata
        .compatibility_report_with_settlement_snapshot(Some(&incomplete_fallback_settlement));
    assert_eq!(
        legacy_report.settlement_snapshot_source,
        TaskSettlementSnapshotSource::LegacyFallback
    );
    assert!(legacy_report.compatibility.legacy_note_only);
    assert!(!legacy_report.compatibility.complete_settlement_snapshot);
    assert!(legacy_report.requires_governance_upgrade);
    assert_eq!(
        legacy_report.findings,
        vec![
            TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
            TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
        ]
    );
    assert_eq!(
        legacy_report.primary_finding(),
        Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload)
    );

    let mut threaded_metadata = legacy_metadata.clone();
    assert!(threaded_metadata.thread_settlement_snapshot(Some(&incomplete_fallback_settlement)));

    let threaded_report = threaded_metadata.compatibility_report();
    assert_eq!(
        threaded_report.settlement_snapshot_source,
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert!(!threaded_report.compatibility.legacy_note_only);
    assert!(!threaded_report.compatibility.complete_settlement_snapshot);
    assert!(threaded_report.requires_governance_upgrade);
    assert_eq!(
        threaded_report.findings,
        vec![TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot]
    );
    assert_eq!(
        threaded_report.primary_finding(),
        Some(TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot)
    );
}

#[test]
fn task_metadata_compatibility_truth_table_settlement_threading_serialization_keeps_legacy_note_only_shape_compact(
) {
    let fallback_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "d".repeat(64)),
        output_token_count: 512,
        output_root: Some(format!("0x{}", "e".repeat(64))),
        output_span_commitment: None,
    };
    let legacy_metadata = TaskMetadata {
        note: Some("legacy".into()),
        ..TaskMetadata::default()
    };

    assert_eq!(
        serde_json::to_value(&legacy_metadata).expect("serialize legacy note-only metadata"),
        serde_json::json!({
            "note": "legacy",
        })
    );

    let mut threaded_metadata = legacy_metadata.clone();
    assert!(threaded_metadata.thread_settlement_snapshot(Some(&fallback_settlement)));

    assert_eq!(
        serde_json::to_value(&threaded_metadata)
            .expect("serialize note-only metadata with threaded settlement"),
        serde_json::json!({
            "note": "legacy",
            "settlement": {
                "settlement_schema": "poco_v1",
                "tokenizer_id": "llama3-tokenizer",
                "tokenizer_version": "1.0.0",
                "output_hash": format!("0x{}", "d".repeat(64)),
                "output_token_count": 512,
                "output_root": format!("0x{}", "e".repeat(64)),
                "output_span_commitment": null,
            }
        })
    );
}

#[test]
fn task_metadata_compatibility_truth_table_settlement_threading_report_serialization_preserves_fallback_vs_threaded_source(
) {
    let fallback_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "f".repeat(64)),
        output_token_count: 512,
        output_root: Some(format!("0x{}", "1".repeat(64))),
        output_span_commitment: None,
    };
    let legacy_metadata = TaskMetadata {
        note: Some("legacy".into()),
        ..TaskMetadata::default()
    };

    let legacy_report =
        legacy_metadata.compatibility_report_with_settlement_snapshot(Some(&fallback_settlement));
    assert_eq!(
        serde_json::to_value(&legacy_report)
            .expect("serialize legacy fallback compatibility report"),
        serde_json::json!({
            "compatibility": {
                "legacy_note_only": true,
                "canonical_core_fields": true,
                "complete_metering_snapshot": true,
                "complete_settlement_snapshot": true,
            },
            "requires_governance_upgrade": true,
            "settlement_snapshot_source": "legacy_fallback",
            "findings": ["legacy_note_only_payload"],
        })
    );

    let mut threaded_metadata = legacy_metadata.clone();
    assert!(threaded_metadata.thread_settlement_snapshot(Some(&fallback_settlement)));

    let threaded_report = threaded_metadata.compatibility_report();
    assert_eq!(
        serde_json::to_value(&threaded_report).expect("serialize threaded compatibility report"),
        serde_json::json!({
            "compatibility": {
                "legacy_note_only": false,
                "canonical_core_fields": true,
                "complete_metering_snapshot": true,
                "complete_settlement_snapshot": true,
            },
            "requires_governance_upgrade": false,
            "settlement_snapshot_source": "threaded_metadata",
            "findings": [],
        })
    );
}

#[test]
fn task_metadata_compatibility_truth_table_settlement_threading_prefers_incomplete_inline_settlement_over_complete_legacy_fallback(
) {
    let inline_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "2".repeat(64)),
        output_token_count: 512,
        output_root: None,
        output_span_commitment: None,
    };
    let fallback_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "3".repeat(64)),
        output_token_count: 512,
        output_root: Some(format!("0x{}", "4".repeat(64))),
        output_span_commitment: None,
    };
    let metadata = TaskMetadata {
        note: Some("threaded".into()),
        settlement: Some(inline_settlement.clone()),
        ..TaskMetadata::default()
    };

    assert_eq!(
        metadata
            .effective_settlement_snapshot(Some(&fallback_settlement))
            .expect("inline settlement should remain authoritative once threaded")
            .output_hash,
        inline_settlement.output_hash
    );

    let report = metadata.compatibility_report_with_settlement_snapshot(Some(&fallback_settlement));
    assert_eq!(
        report.settlement_snapshot_source,
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert!(!report.compatibility.legacy_note_only);
    assert!(!report.compatibility.complete_settlement_snapshot);
    assert!(report.requires_governance_upgrade);
    assert_eq!(
        report.findings,
        vec![TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot]
    );
    assert_eq!(
        report.primary_finding(),
        Some(TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot)
    );
}

#[test]
fn task_metadata_compatibility_truth_table_task_object_threading_creates_metadata_when_absent() {
    let fallback_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "5".repeat(64)),
        output_token_count: 512,
        output_root: Some(format!("0x{}", "6".repeat(64))),
        output_span_commitment: None,
    };
    let mut task = task_with_metadata(None);

    assert!(task.thread_settlement_snapshot(Some(&fallback_settlement)));
    assert_eq!(
        task.metadata
            .as_ref()
            .and_then(|metadata| metadata.settlement.as_ref()),
        Some(&fallback_settlement)
    );
    assert_eq!(
        task.metadata
            .as_ref()
            .expect("threading should materialize task metadata")
            .settlement_snapshot_source(None),
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert!(!task.thread_settlement_snapshot(Some(&fallback_settlement)));
}

#[test]
fn task_metadata_compatibility_truth_table_task_object_settlement_helpers_preserve_absent_fallback_and_threaded_precedence(
) {
    let fallback_settlement = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "7".repeat(64)),
        output_token_count: 512,
        output_root: Some(format!("0x{}", "8".repeat(64))),
        output_span_commitment: None,
    };
    let competing_fallback = TaskSettlementSnapshot {
        settlement_schema: "poco_v1".into(),
        tokenizer_id: "llama3-tokenizer".into(),
        tokenizer_version: "1.0.0".into(),
        output_hash: format!("0x{}", "9".repeat(64)),
        output_token_count: 512,
        output_root: Some(format!("0x{}", "a".repeat(64))),
        output_span_commitment: None,
    };
    let mut task = task_with_metadata(None);

    assert_eq!(
        task.settlement_snapshot_source(None),
        TaskSettlementSnapshotSource::Absent
    );
    assert_eq!(
        task.settlement_snapshot_source(Some(&fallback_settlement)),
        TaskSettlementSnapshotSource::LegacyFallback
    );
    assert_eq!(
        task.effective_settlement_snapshot(Some(&fallback_settlement)),
        Some(&fallback_settlement)
    );

    assert!(task.thread_settlement_snapshot(Some(&fallback_settlement)));
    assert_eq!(
        task.settlement_snapshot_source(Some(&competing_fallback)),
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert_eq!(
        task.effective_settlement_snapshot(Some(&competing_fallback))
            .expect("threaded task settlement should remain authoritative")
            .output_hash,
        fallback_settlement.output_hash
    );
}

#[test]
fn task_metadata_compatibility_truth_table_task_object_threading_ignores_absent_fallback_without_materializing_metadata(
) {
    let mut task = task_with_metadata(None);

    assert!(!task.thread_settlement_snapshot(None));
    assert!(task.metadata.is_none());
}
