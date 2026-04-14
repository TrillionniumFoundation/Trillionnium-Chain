use trnm_types::{TaskMetadata, TaskSettlementSnapshotSource};

#[test]
fn settlement_snapshot_alias_deserializes_into_threaded_task_metadata() {
    let metadata: TaskMetadata = serde_json::from_str(
        r#"{
            "note": "interop",
            "settlement_snapshot": {
                "settlement_schema": "poco_v1",
                "tokenizer_id": "llama3-tokenizer",
                "tokenizer_version": "1.0.0",
                "output_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "output_token_count": 512,
                "output_root": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        }"#,
    )
    .expect("transitional settlement_snapshot alias should deserialize");

    assert!(metadata.settlement.is_some());
    assert_eq!(
        metadata.settlement_snapshot_source(None),
        TaskSettlementSnapshotSource::ThreadedMetadata
    );

    let compatibility = metadata.compatibility_profile();
    assert!(!compatibility.legacy_note_only);
    assert!(compatibility.complete_settlement_snapshot);
}

#[test]
fn settlement_snapshot_alias_serializes_back_under_canonical_settlement_key() {
    let metadata: TaskMetadata = serde_json::from_str(
        r#"{
            "note": "interop",
            "settlement_snapshot": {
                "settlement_schema": "poco_v1",
                "tokenizer_id": "llama3-tokenizer",
                "tokenizer_version": "1.0.0",
                "output_hash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "output_token_count": 256,
                "output_span_commitment": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            }
        }"#,
    )
    .expect("transitional settlement_snapshot alias should deserialize");

    let value = serde_json::to_value(&metadata).expect("serialize canonical task metadata");

    assert!(value.get("settlement").is_some());
    assert!(value.get("settlement_snapshot").is_none());
}

#[test]
fn canonical_settlement_wins_when_transitional_payload_sends_both_keys() {
    let metadata: TaskMetadata = serde_json::from_str(
        r#"{
            "note": "interop",
            "settlement": {
                "settlement_schema": "poco_v1",
                "tokenizer_id": "llama3-tokenizer",
                "tokenizer_version": "1.0.0",
                "output_hash": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "output_token_count": 256,
                "output_root": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            },
            "settlement_snapshot": {
                "settlement_schema": "poco_v1",
                "tokenizer_id": "llama3-tokenizer",
                "tokenizer_version": "1.0.0",
                "output_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "output_token_count": 256
            }
        }"#,
    )
    .expect("mixed transitional payload should deserialize without duplicate-field failure");

    let settlement = metadata
        .settlement
        .as_ref()
        .expect("canonical settlement should be retained");
    assert_eq!(
        settlement.output_hash,
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    );
    assert_eq!(
        metadata.settlement_snapshot_source(None),
        TaskSettlementSnapshotSource::ThreadedMetadata
    );
    assert!(
        metadata
            .compatibility_profile()
            .complete_settlement_snapshot
    );
}
