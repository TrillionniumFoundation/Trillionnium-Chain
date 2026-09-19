use super::*;

pub(crate) fn initial() -> EpochNodeCheckpointV1 {
    EpochNodeCheckpointV1::new(EpochNodeCheckpointFieldsV1 {
        phase: EpochCheckpointPhaseV1::ActivationCommitted,
        role: EpochCheckpointRoleV1::Continuing,
        predecessor_kind: EpochCheckpointPredecessorV1::TerminalV0,
        lineage_id: [1; 32],
        origin_checksum: [2; 32],
        generation: 2,
        predecessor_checksum: [3; 32],
        genesis_hash: [4; 32],
        chain_id: ChainId::from_static("epoch-test"),
        protocol_version: 0,
        epoch: 1,
        author: ValidatorId::new([5; 32]),
        validator_set_id: [6; 32],
        parameters_hash: [7; 32],
        owner_generation: 1,
        phase_authority_binding: [8; 32],
        source_safety: Some(EpochSafetyCutV1 {
            journal_id: [9; 32],
            context_ref: [10; 32],
            revision: 40,
            record_checksum: [11; 32],
            chain_checksum: [12; 32],
        }),
        target_safety: EpochSafetyCutV1 {
            journal_id: [13; 32],
            context_ref: [14; 32],
            revision: 41,
            record_checksum: [15; 32],
            chain_checksum: [16; 32],
        },
        edge: EpochApplicationEdgeCutV1 {
            checkpoint_block_id: [17; 32],
            checkpoint_height: 8,
            checkpoint_state_root: [18; 32],
            terminal_old_block_id: [19; 32],
            terminal_old_height: 10,
            terminal_old_view: 12,
            terminal_old_qc_id: [20; 32],
            native_authorization_id: [21; 32],
        },
        application: EpochApplicationCutV1 {
            block_id: [17; 32],
            height: 8,
            epoch: 0,
            view: 10,
            timestamp_ms: 1000,
            state_root: [18; 32],
            native_store_id: [22; 32],
            native_commit_id: [23; 32],
            p_sequence: 8,
            p_digest: [24; 32],
            artifact_digest: [25; 32],
            overlay_digest: [26; 32],
            commit_sequence: 8,
        },
        retired: Some(EpochRetiredCustodyCutV1 {
            epoch: 0,
            author: ValidatorId::new([5; 32]),
            validator_set_id: [27; 32],
            parameters_hash: [28; 32],
            scope: [29; 32],
            journal_id: [30; 32],
            profile_checksum: [31; 32],
            source_sequence: 10,
            source_chain_checksum: [32; 32],
            terminal_sequence: 11,
            terminal_chain_checksum: [33; 32],
            retirement_record_checksum: [34; 32],
        }),
        ordinary: Some(EpochOrdinaryCustodyCutV1 {
            scope: [35; 32],
            journal_id: [36; 32],
            profile_checksum: [37; 32],
            sequence: 0,
            chain_checksum: [38; 32],
        }),
    })
    .unwrap()
}
fn ordinary(old: &EpochNodeCheckpointV1) -> EpochNodeCheckpointFieldsV1 {
    let mut f = *old.fields();
    f.phase = EpochCheckpointPhaseV1::Ordinary;
    f.predecessor_kind = EpochCheckpointPredecessorV1::V1;
    f.generation += 1;
    f.predecessor_checksum = old.checksum();
    f
}
#[test]
fn canonical_roundtrip_rejects_every_truncation_and_corruption() {
    let v = initial();
    let bytes = v.encode_canonical();
    assert_eq!(EpochNodeCheckpointV1::decode_canonical_exact(&bytes), Ok(v));
    for cut in 0..bytes.len() {
        assert!(
            EpochNodeCheckpointV1::decode_canonical_exact(&bytes[..cut]).is_err(),
            "cut {cut}"
        );
    }
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(
            EpochNodeCheckpointV1::decode_canonical_exact(&changed).is_err(),
            "at {at}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(EpochNodeCheckpointV1::decode_canonical_exact(&trailing).is_err());
    assert!(EpochNodeCheckpointV1::decode_canonical_exact(&vec![0; 8193]).is_err());
}

#[test]
fn independent_domain_hash_vectors_pin_layout_and_endianness() {
    // Independently serialized from the M15 ordered field table using Python
    // struct.pack with big-endian u16/u32/u64 and hashlib.sha256, not the
    // Rust encoder or hash helper. The initial fixture prefix is 1492 bytes.
    let record = initial();
    assert_eq!(record.encode_canonical().len(), 1524);
    assert_eq!(
        hex::encode(record.checksum()),
        "267baf60ed070f37e6e50cf5f9b63fc8ffe80654e06fb65906cfb462782ccc61"
    );
    // Origin hashing consumes all supplied bytes, including an original
    // record's integrity field. Zeroes are hash input here, not a valid V0 cut.
    assert_eq!(
        hex::encode(epoch_origin_checksum_v1(&[0u8; 672])),
        "a156244b36c2936957ddde2135765a8f3b2114753b95aea0e0141a07c3a9fdbc"
    );
}
#[test]
fn closed_tags_and_bounded_identities_reject() {
    let bytes = initial().encode_canonical();
    for at in [10, 11, 12] {
        let mut bad = bytes.clone();
        bad[at] = 3;
        assert_eq!(
            EpochNodeCheckpointV1::decode_canonical_exact(&bad),
            Err(EpochNodeCheckpointErrorV1::Tag)
        );
    }
    // Envelope is 117 bytes; genesis is 32, then the chain's u16 byte length.
    for length in [0u16, 129, u16::MAX] {
        let mut bad = bytes.clone();
        bad[149..151].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            EpochNodeCheckpointV1::decode_canonical_exact(&bad),
            Err(EpochNodeCheckpointErrorV1::Length)
        );
    }
}
#[test]
fn phase_role_matrix_and_retirement_cannot_retain_old_authority() {
    let base = *initial().fields();
    for role in [
        EpochCheckpointRoleV1::VirginNew,
        EpochCheckpointRoleV1::Removed,
    ] {
        let mut f = base;
        f.role = role;
        assert!(EpochNodeCheckpointV1::new(f).is_err());
    }
    let mut f = base;
    f.ordinary.as_mut().unwrap().sequence = 1;
    assert!(EpochNodeCheckpointV1::new(f).is_err());
    let mut f = base;
    f.retired.as_mut().unwrap().epoch = 1;
    assert!(EpochNodeCheckpointV1::new(f).is_err());
    let mut f = base;
    f.ordinary.as_mut().unwrap().scope = f.retired.unwrap().scope;
    assert!(EpochNodeCheckpointV1::new(f).is_err());
    let mut f = base;
    f.phase = EpochCheckpointPhaseV1::EpochRetired;
    assert!(EpochNodeCheckpointV1::new(f).is_err());
    f.ordinary = None;
    assert!(
        EpochNodeCheckpointV1::new(f).is_err(),
        "incoming e-1 retirement must not retire e"
    );
}
#[test]
fn ordinary_rejects_checksummed_rebinding_and_virtual_seal_commit() {
    let base = initial();
    let f = ordinary(&base);
    let good = EpochNodeCheckpointV1::new(f).unwrap();
    assert_eq!(good.validate_successor_of(&base), Ok(()));
    let changes: [fn(&mut EpochNodeCheckpointFieldsV1); 13] = [
        |f| f.origin_checksum = [99; 32],
        |f| f.phase_authority_binding = [99; 32],
        |f| f.validator_set_id = [99; 32],
        |f| f.target_safety.journal_id = [99; 32],
        |f| f.source_safety.as_mut().unwrap().record_checksum = [99; 32],
        |f| f.ordinary.as_mut().unwrap().chain_checksum = [99; 32],
        |f| f.ordinary.as_mut().unwrap().scope = [99; 32],
        |f| f.application.native_store_id = [99; 32],
        |f| f.application.p_digest = [99; 32],
        |f| f.retired.as_mut().unwrap().retirement_record_checksum = [99; 32],
        |f| f.edge.terminal_old_qc_id = [99; 32],
        |f| f.target_safety.record_checksum = [99; 32],
        |f| f.owner_generation += 1,
    ];
    for change in changes {
        let mut bad = f;
        change(&mut bad);
        assert!(EpochNodeCheckpointV1::new(bad)
            .unwrap()
            .validate_successor_of(&base)
            .is_err());
    }
    for height in [9, 10] {
        let mut bad = f;
        bad.application.height = height;
        bad.application.epoch = 1;
        assert!(EpochNodeCheckpointV1::new(bad).is_err());
    }
    let mut next = f;
    next.application.height = 11;
    next.application.epoch = 1;
    next.application.view = 1;
    next.application.block_id = [99; 32];
    next.application.commit_sequence += 1;
    next.application.p_sequence += 1;
    assert!(
        EpochNodeCheckpointV1::new(next)
            .unwrap()
            .validate_successor_of(&base)
            .is_ok(),
        "view resets only across epoch"
    );
    for change in [
        |f: &mut EpochNodeCheckpointFieldsV1| f.application.commit_sequence = 8,
        |f: &mut EpochNodeCheckpointFieldsV1| f.application.p_sequence = 8,
    ] {
        let mut bad = next;
        change(&mut bad);
        assert!(
            EpochNodeCheckpointV1::new(bad)
                .unwrap()
                .validate_successor_of(&base)
                .is_err(),
            "a real new head requires both a new P and a new commit sequence"
        );
    }
}

#[test]
fn ordinary_at_checkpoint_requires_exact_incoming_application_scope() {
    let base = initial();
    let f = ordinary(&base);
    let changes: [fn(&mut EpochNodeCheckpointFieldsV1); 3] = [
        |f| f.application.block_id = [99; 32],
        |f| f.application.state_root = [99; 32],
        |f| f.application.epoch = f.epoch,
    ];
    for change in changes {
        let mut bad = f;
        change(&mut bad);
        assert!(EpochNodeCheckpointV1::new(bad).is_err());
    }
    // A shape-valid e=2 record still at C cannot call that checkpoint e=0.
    let mut older = f;
    older.epoch = 2;
    older.retired.as_mut().unwrap().epoch = 1;
    assert!(EpochNodeCheckpointV1::new(older).is_err());
}

#[test]
fn predecessor_kind_cannot_commission_an_ordinary_or_wrong_role_record() {
    let initial = initial();
    for kind in [
        EpochCheckpointPredecessorV1::TerminalV0,
        EpochCheckpointPredecessorV1::VirginCommission,
    ] {
        let mut bad = ordinary(&initial);
        bad.predecessor_kind = kind;
        assert!(EpochNodeCheckpointV1::new(bad).is_err());
    }
    let mut wrong = *initial.fields();
    wrong.predecessor_kind = EpochCheckpointPredecessorV1::VirginCommission;
    assert!(EpochNodeCheckpointV1::new(wrong).is_err());
    let mut virgin = wrong;
    virgin.role = EpochCheckpointRoleV1::VirginNew;
    virgin.source_safety = None;
    virgin.retired = None;
    assert!(EpochNodeCheckpointV1::new(virgin).is_ok());
    virgin.predecessor_kind = EpochCheckpointPredecessorV1::TerminalV0;
    assert!(EpochNodeCheckpointV1::new(virgin).is_err());
}
#[test]
fn retired_to_next_activation_copies_current_retirement_and_removed_fences() {
    let initial = initial();
    let mut f = ordinary(&initial);
    f.application.height = 11;
    f.application.epoch = 1;
    f.application.view = 1;
    f.application.block_id = [50; 32];
    f.application.commit_sequence += 1;
    f.application.p_sequence += 1;
    f.ordinary.as_mut().unwrap().sequence = 2;
    f.ordinary.as_mut().unwrap().chain_checksum = [51; 32];
    let live = EpochNodeCheckpointV1::new(f).unwrap();
    live.validate_successor_of(&initial).unwrap();
    let mut r = ordinary(&live);
    r.phase = EpochCheckpointPhaseV1::EpochRetired;
    r.source_safety = Some(live.fields.target_safety);
    r.target_safety.revision += 1;
    r.target_safety.record_checksum = [52; 32];
    r.target_safety.chain_checksum = [53; 32];
    r.phase_authority_binding = [54; 32];
    r.edge.checkpoint_height = 11;
    r.edge.checkpoint_block_id = [50; 32];
    r.edge.terminal_old_height = 13;
    r.edge.terminal_old_block_id = [55; 32];
    r.edge.terminal_old_view = 3;
    r.edge.terminal_old_qc_id = [56; 32];
    r.edge.native_authorization_id = [57; 32];
    let o = r.ordinary.take().unwrap();
    let retired = r.retired.as_mut().unwrap();
    retired.epoch = 1;
    retired.validator_set_id = r.validator_set_id;
    retired.parameters_hash = r.parameters_hash;
    retired.scope = o.scope;
    retired.journal_id = o.journal_id;
    retired.profile_checksum = o.profile_checksum;
    retired.source_sequence = o.sequence;
    retired.source_chain_checksum = o.chain_checksum;
    retired.terminal_sequence = o.sequence + 1;
    retired.terminal_chain_checksum = [58; 32];
    retired.retirement_record_checksum = [59; 32];
    let retired = EpochNodeCheckpointV1::new(r).unwrap();
    retired.validate_successor_of(&live).unwrap();
    let mut wrong_generation = r;
    wrong_generation.owner_generation += 1;
    assert!(EpochNodeCheckpointV1::new(wrong_generation)
        .unwrap()
        .validate_successor_of(&live)
        .is_err());
    let mut n = *retired.fields();
    n.phase = EpochCheckpointPhaseV1::ActivationCommitted;
    n.epoch = 2;
    n.owner_generation += 1;
    n.generation += 1;
    n.predecessor_checksum = retired.checksum();
    n.source_safety = Some(r.target_safety);
    n.target_safety.journal_id = [60; 32];
    n.target_safety.context_ref = [61; 32];
    n.target_safety.revision += 1;
    n.target_safety.record_checksum = [62; 32];
    n.target_safety.chain_checksum = [63; 32];
    n.validator_set_id = [64; 32];
    n.phase_authority_binding = [65; 32];
    n.edge.native_authorization_id = [66; 32];
    n.ordinary = Some(EpochOrdinaryCustodyCutV1 {
        scope: [67; 32],
        journal_id: [68; 32],
        profile_checksum: [69; 32],
        sequence: 0,
        chain_checksum: [70; 32],
    });
    let next = EpochNodeCheckpointV1::new(n).unwrap();
    next.validate_successor_of(&retired).unwrap();
    for generation in [r.owner_generation, r.owner_generation + 2] {
        let mut bad = n;
        bad.owner_generation = generation;
        assert!(EpochNodeCheckpointV1::new(bad)
            .unwrap()
            .validate_successor_of(&retired)
            .is_err());
    }
    let mut removed = r;
    removed.role = EpochCheckpointRoleV1::Removed;
    let removed = EpochNodeCheckpointV1::new(removed).unwrap();
    n.predecessor_checksum = removed.checksum();
    assert!(EpochNodeCheckpointV1::new(n)
        .unwrap()
        .validate_successor_of(&removed)
        .is_err());
}
