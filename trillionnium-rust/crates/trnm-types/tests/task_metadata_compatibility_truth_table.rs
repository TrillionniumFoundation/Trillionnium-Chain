use trnm_types::{
    TaskMetadataCompatibility, TaskMetadataCompatibilityFinding,
};

#[test]
fn metadata_compatibility_truth_table_preserves_typed_governance_upgrade_decisions() {
    let cases = [
        (
            TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: true,
                complete_metering_snapshot: true,
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
            },
            true,
            Some(TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot),
            vec![TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot],
        ),
        (
            TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: false,
                complete_metering_snapshot: true,
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
                legacy_note_only: false,
                canonical_core_fields: false,
                complete_metering_snapshot: false,
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
                legacy_note_only: true,
                canonical_core_fields: false,
                complete_metering_snapshot: false,
            },
            true,
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
            ],
        ),
    ];

    for (compatibility, requires_upgrade, primary_finding, findings) in cases {
        assert_eq!(
            compatibility.is_runtime_compatible(),
            compatibility.canonical_core_fields && compatibility.complete_metering_snapshot,
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
