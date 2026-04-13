use trnm_types::{TaskMetadata, TaskSettlementSnapshot, TaskSettlementSnapshotSource};

fn complete_settlement(output_hash: &str, output_root: &str) -> TaskSettlementSnapshot {
    TaskSettlementSnapshot {
        settlement_schema: "poco_v1".to_string(),
        tokenizer_id: "llama3-tokenizer".to_string(),
        tokenizer_version: "1.0.0".to_string(),
        output_hash: output_hash.to_string(),
        output_token_count: 256,
        output_root: Some(output_root.to_string()),
        output_span_commitment: None,
    }
}

#[test]
fn thread_settlement_snapshot_lifts_legacy_fallback_into_metadata() {
    let settlement = complete_settlement(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let mut metadata = TaskMetadata {
        note: Some("legacy note".to_string()),
        ..TaskMetadata::default()
    };

    let legacy_report = metadata.compatibility_report_with_settlement_snapshot(Some(&settlement));
    assert!(legacy_report.compatibility.legacy_note_only);
    assert!(legacy_report.compatibility.complete_settlement_snapshot);
    assert_eq!(
        legacy_report.settlement_snapshot_source,
        TaskSettlementSnapshotSource::LegacyFallback
    );

    assert!(metadata.thread_settlement_snapshot(Some(&settlement)));

    let threaded_report = metadata.compatibility_report();
    assert!(!threaded_report.compatibility.legacy_note_only);
    assert!(threaded_report.compatibility.complete_settlement_snapshot);
    assert_eq!(
        threaded_report.settlement_snapshot_source,
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert_eq!(
        metadata
            .settlement
            .as_ref()
            .expect("settlement should be threaded into metadata")
            .output_hash,
        settlement.output_hash
    );
}

#[test]
fn thread_settlement_snapshot_does_not_clobber_existing_inline_settlement() {
    let inline_settlement = complete_settlement(
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let fallback_settlement = complete_settlement(
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    let mut metadata = TaskMetadata {
        note: Some("threaded".to_string()),
        settlement: Some(inline_settlement.clone()),
        ..TaskMetadata::default()
    };

    assert!(!metadata.thread_settlement_snapshot(Some(&fallback_settlement)));
    assert_eq!(metadata.settlement.as_ref(), Some(&inline_settlement));
}

#[test]
fn thread_settlement_snapshot_ignores_absent_fallback() {
    let mut metadata = TaskMetadata {
        note: Some("legacy note".to_string()),
        ..TaskMetadata::default()
    };

    assert!(!metadata.thread_settlement_snapshot(None));
    assert!(metadata.settlement.is_none());
    assert_eq!(
        metadata.settlement_snapshot_source(None),
        TaskSettlementSnapshotSource::Absent
    );
    assert!(metadata.compatibility_profile().legacy_note_only);
}
