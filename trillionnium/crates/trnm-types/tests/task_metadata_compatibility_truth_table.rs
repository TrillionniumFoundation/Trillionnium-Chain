use trnm_types::{
    TaskMetadata, TaskMetadataCompatibility, TaskMetadataCompatibilityFinding,
    TaskSettlementSnapshot, TaskSettlementSnapshotSource,
};

#[test]
fn metadata_compatibility_truth_table_preserves_typed_governance_upgrade_decisions() {
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
fn settlement_threading_promotes_legacy_fallback_without_breaking_note_only_compatibility() {
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
    assert_eq!(threaded_metadata.settlement.as_ref(), Some(&fallback_settlement));
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
