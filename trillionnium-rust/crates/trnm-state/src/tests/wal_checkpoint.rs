use super::*;

#[test]
fn wal_checkpoint_verification_picks_latest_valid() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let h2 = e2.content_hash_hex();

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: h2,
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 2);
}

#[test]
fn wal_checkpoint_verification_falls_back_on_chain_break() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some("wrong-prev".into()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
}

#[test]
fn wal_checkpoint_verification_falls_back_on_non_monotonic_height() {
    let e1 = WalMeta {
        height: 10,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        // Repeated height must terminate verification.
        height: 10,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 10,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 10,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_falls_back_on_height_gap() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e3 = WalMeta {
        // Height gaps must terminate verification; a checkpoint proof prefix must be contiguous.
        height: 3,
        round: 0,
        proposal_hash: "p3".into(),
        committed: true,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1.clone(),
        },
        CheckpointMeta {
            height: 3,
            state_root_hex: "r3".into(),
            wal_entry_hash_hex: e3.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e3])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
    assert_eq!(got.wal_entry_hash_hex, h1);
}

#[test]
fn wal_checkpoint_verification_is_height_ordered_even_if_checkpoint_list_is_not() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1),
    };
    let h2 = e2.content_hash_hex();

    // Intentionally unsorted input: height 2 checkpoint appears first.
    let checkpoints = vec![
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: h2,
        },
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 2);
    assert_eq!(got.state_root_hex, "r2");
}

#[test]
fn wal_checkpoint_verification_stops_before_uncommitted_tail() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: false,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_rejects_metadata_only_chain_without_genesis_anchor() {
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some("genesis-missing".into()),
    };

    let checkpoints = vec![CheckpointMeta {
        height: 2,
        state_root_hex: "r2".into(),
        wal_entry_hash_hex: e2.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e2]).unwrap();
    assert!(
        got.is_none(),
        "metadata-only WAL chains that start above height 1 must fail closed"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_metadata_only_chain_without_genesis_entry() {
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: None,
    };

    let checkpoints = vec![CheckpointMeta {
        height: 2,
        state_root_hex: "r2".into(),
        wal_entry_hash_hex: e2.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e2]).unwrap();
    assert!(
        got.is_none(),
        "metadata-only WAL chains that skip the genesis entry must fail closed"
    );
}
