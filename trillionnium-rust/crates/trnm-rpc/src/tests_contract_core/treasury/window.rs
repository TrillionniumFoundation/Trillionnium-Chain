use super::*;

#[test]
fn summarize_challenge_treasury_window_daily_summary_counts() {
    let events = vec![
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 11,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c11".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "a".into(),
            ts_unix_ms: 1_000,
            signer: None,
            challenger: Some("c11".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-5),
            bond_disposition: Some("posted".into()),
            metering: None,
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 11,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "v".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "b".into(),
            ts_unix_ms: 2_000,
            signer: None,
            challenger: Some("c11".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("refunded".into()),
            metering: None,
        },
        NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 12,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c12".into(),
            tx_id: 3,
            block_height: 3,
            state_root: "c".into(),
            ts_unix_ms: 3_000,
            signer: None,
            challenger: Some("c12".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(-8),
            bond_disposition: Some("posted".into()),
            metering: None,
        },
        NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 99,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "v".into(),
            tx_id: 4,
            block_height: 4,
            state_root: "d".into(),
            ts_unix_ms: 4_000,
            signer: None,
            challenger: Some("c99".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
            metering: None,
        },
    ];

    let out = summarize_challenge_treasury(
        &events,
        10,
        Some((500, 3_500, "custom".to_string())),
        NodeEventScanMode::Authoritative,
        false,
    );

    let summary = out.daily_summary.expect("summary expected");
    assert_eq!(summary.posted, 2);
    assert_eq!(summary.refunded, 1);
    assert_eq!(summary.forfeited, 0);
    assert_eq!(summary.unresolved, 1);
    assert_eq!(out.window.expect("window expected").mode, "custom");
}
