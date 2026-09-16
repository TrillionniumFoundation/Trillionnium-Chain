fn native_body_fixture_open(
    path: &Path,
    profile: NativeAdmissionProfileV1,
    now: u64,
    recovery: bool,
) -> Result<NodeOwnedTxAdmissionBoundaryV0, NativeAdmissionErrorV1> {
    NodeOwnedTxAdmissionBoundaryV0::open_native_candidate_v1(
        path,
        [0x88; 32],
        profile,
        BuilderFixtureSignerResolver {
            signer: CanonicalSignerId::from_bytes([0xa5; 32]).unwrap(),
        },
        BuilderFixtureAdmissionContext {
            chain_id: "trnm-devnet",
            now_unix_ms: now,
        },
        recovery,
    )
}
fn native_body_fixture_tx(nonce: u64) -> BuiltCanonicalTxV0 {
    let key = SigningKey::from_bytes(&[0x47; 32]);
    let signer = BuilderFixtureSigner {
        public_key: hex::encode(key.verifying_key().to_bytes()),
        key,
        id: "did:trnm:alice".to_owned(),
    };
    build_signed_canonical_tx_v0(
        CanonicalTxBuildContextV0 {
            chain_id: "trnm-devnet".to_owned(),
            sender: signer.id.clone(),
            command_id: None,
            transaction_sequence: nonce,
            issued_at_unix_ms: 1000,
            expires_at_unix_ms: 2000,
            max_gas: 10000,
            fee_limit: 17,
            limits: TxBuilderLimitsV0::candidate_v0(),
        },
        CanonicalCommandV1::CreditAccount {
            account: signer.id.clone(),
            amount: 1,
        },
        &signer,
    )
    .unwrap()
}

#[test]
fn native_body_ack_survives_owner_drop_restart_and_exact_retry() {
    let path = temp_path();
    let profile = NativeAdmissionProfileV1::candidate_defaults([7; 32]);
    let bytes = builder_fixture_transaction().exact_outer_bytes().to_vec();
    let first = {
        let mut owner = native_body_fixture_open(&path, profile, 1500, false).unwrap();
        let receipt = owner.submit_native_bytes_v1(&bytes).unwrap();
        assert_eq!(receipt.receive_sequence(), 1);
        assert_eq!(owner.submit_native_bytes_v1(&bytes).unwrap(), receipt);
        assert_eq!(owner.queued_counts().0, 1);
        receipt
    };
    // Dropping the in-memory reservation must not release an acknowledged body.
    let mut owner = native_body_fixture_open(&path, profile, 1500, false).unwrap();
    assert_eq!(
        owner
            .native_record_v1(first.native_tx_hash())
            .unwrap()
            .unwrap(),
        first
    );
    assert_eq!(owner.queued_counts().0, 1);
    let pending = owner.pop_native_ready_v1().unwrap().unwrap();
    assert_eq!(pending.transaction().exact_outer_bytes(), bytes);
    drop(pending);
    drop(owner);
    let mut owner = native_body_fixture_open(&path, profile, 2500, false).unwrap();
    let expired = owner.submit_native_bytes_v1(&bytes).unwrap();
    assert_eq!(expired.status(), NativeAdmissionStatusV1::Expired);
    assert_eq!(expired.receive_sequence(), first.receive_sequence());
    assert!(owner.pop_native_ready_v1().unwrap().is_none());
    drop(owner);
    cleanup(&path);
}

#[test]
fn native_live_handoff_allows_other_admission_but_lost_owner_fences_it() {
    let path = temp_path();
    let profile = NativeAdmissionProfileV1::candidate_defaults([7; 32]);
    let mut owner = native_body_fixture_open(&path, profile, 1500, false).unwrap();
    owner
        .submit_native_bytes_v1(native_body_fixture_tx(1).exact_outer_bytes())
        .unwrap();
    let mut in_flight = owner.pop_native_ready_v1().unwrap().unwrap();
    in_flight.handoff().unwrap();
    assert!(matches!(
        in_flight.admission.commit(),
        Err(AdmissionReject::ReservationStateConflict)
    ));
    assert_eq!(
        owner
            .submit_native_bytes_v1(native_body_fixture_tx(2).exact_outer_bytes())
            .unwrap()
            .receive_sequence(),
        2
    );
    drop(in_flight);
    assert!(matches!(
        owner.submit_native_bytes_v1(native_body_fixture_tx(3).exact_outer_bytes()),
        Err(NativeAdmissionErrorV1::Wal(
            TxAdmissionWalErrorV0::AmbiguousHandoff
        ))
    ));
    drop(owner);
    assert!(matches!(
        native_body_fixture_open(&path, profile, 1500, false),
        Err(NativeAdmissionErrorV1::Wal(
            TxAdmissionWalErrorV0::AmbiguousHandoff
        ))
    ));
    let mut recovery = native_body_fixture_open(&path, profile, 1500, true).unwrap();
    assert_eq!(recovery.native_pending_inventory_v1().unwrap().len(), 2);
    assert!(recovery.restore_native_pending_v1().is_err());
    drop(recovery);
    cleanup(&path);
}

#[test]
fn native_body_atomic_insert_rollback_bad_signature_capacity_and_nonce_conflict() {
    let path = temp_path();
    let mut profile = NativeAdmissionProfileV1::candidate_defaults([7; 32]);
    profile.maximum_pending = 1;
    let mut owner = native_body_fixture_open(&path, profile, 1500, false).unwrap();
    let good = native_body_fixture_tx(1);
    let mut envelope = good.envelope().clone();
    envelope.signature_hex = "00".repeat(64);
    assert!(owner
        .submit_native_bytes_v1(&serde_json::to_vec(&envelope).unwrap())
        .is_err());
    assert_eq!(owner.retained_rows().unwrap(), 0);
    // Body insertion fails after the nonce INSERT inside the same transaction.
    owner.authority.connection.borrow().execute_batch("CREATE TEMP TRIGGER fail_native_body BEFORE INSERT ON native_admission_body_v1 BEGIN SELECT RAISE(ABORT,'test cut'); END;").unwrap();
    assert!(owner
        .submit_native_bytes_v1(good.exact_outer_bytes())
        .is_err());
    assert_eq!(owner.retained_rows().unwrap(), 0);
    assert!(owner.native_pending_inventory_v1().unwrap().is_empty());
    owner
        .authority
        .connection
        .borrow()
        .execute_batch("DROP TRIGGER fail_native_body;")
        .unwrap();
    let receipt = owner
        .submit_native_bytes_v1(good.exact_outer_bytes())
        .unwrap();
    assert_eq!(receipt.receive_sequence(), 1);
    assert!(matches!(
        owner.submit_native_bytes_v1(native_body_fixture_tx(2).exact_outer_bytes()),
        Err(NativeAdmissionErrorV1::Backpressure)
    ));
    assert_eq!(
        owner
            .submit_native_bytes_v1(good.exact_outer_bytes())
            .unwrap(),
        receipt
    );
    assert_eq!(owner.retained_rows().unwrap(), 1);
    drop(owner);
    cleanup(&path);
}

#[test]
fn native_body_reopen_rejects_missing_or_mutated_canonical_preimages() {
    for missing in [true, false] {
        let path = temp_path();
        let profile = NativeAdmissionProfileV1::candidate_defaults([7; 32]);
        {
            let mut owner = native_body_fixture_open(&path, profile, 1500, false).unwrap();
            owner
                .submit_native_bytes_v1(native_body_fixture_tx(1).exact_outer_bytes())
                .unwrap();
        }
        let connection = Connection::open(&path).unwrap();
        if missing {
            connection
                .execute("DELETE FROM native_admission_body_v1", [])
                .unwrap();
        } else {
            connection
                .execute(
                    "UPDATE native_admission_body_v1 SET exact_outer=?1",
                    params![b"{}".as_slice()],
                )
                .unwrap();
        }
        drop(connection);
        assert!(native_body_fixture_open(&path, profile, 1500, false).is_err());
        cleanup(&path);
    }
}

#[test]
fn native_profile_rejects_legacy_wal_without_implicit_migration() {
    let path = temp_path();
    drop(SqlitePendingNonceAuthorityV0::open(&path, [0x88; 32]).unwrap());
    assert!(matches!(
        native_body_fixture_open(
            &path,
            NativeAdmissionProfileV1::candidate_defaults([7; 32]),
            1500,
            false
        ),
        Err(NativeAdmissionErrorV1::Wal(
            TxAdmissionWalErrorV0::NativeMigrationRequired
        ))
    ));
    let legacy = SqlitePendingNonceAuthorityV0::open(&path, [0x88; 32]).unwrap();
    assert_eq!(legacy.retained_rows().unwrap(), 0);
    drop(legacy);
    cleanup(&path);
}

fn legacy_native_reserved_fixture(path: &Path, nonces: &[u64]) {
    let mut legacy = SqlitePendingNonceAuthorityV0::open(path, [0x88; 32]).unwrap();
    for nonce in nonces {
        let built = native_body_fixture_tx(*nonce);
        let view = built.admission_view_v0(CanonicalSignerId::from_bytes([0xa5; 32]).unwrap());
        let gate = TypedAdmissionGate::new(256, 0, 262144);
        let metadata = gate.canonical_metadata_v0(&view).unwrap();
        // This raw authority token has no in-memory queue Drop callback. The
        // persisted Reserved row models a process cut after the old ACK.
        drop(legacy.reserve_record(&view, &metadata).unwrap());
    }
}

#[test]
fn native_explicit_migration_is_complete_deterministic_and_preserves_expired_bodies() {
    let path = temp_path();
    let profile = NativeAdmissionProfileV1::candidate_defaults([7; 32]);
    legacy_native_reserved_fixture(&path, &[9, 2]);
    let signer = BuilderFixtureSignerResolver {
        signer: CanonicalSignerId::from_bytes([0xa5; 32]).unwrap(),
    };
    let context = BuilderFixtureAdmissionContext {
        chain_id: "trnm-devnet",
        now_unix_ms: 2500,
    };
    let two = native_body_fixture_tx(2).exact_outer_bytes().to_vec();
    let nine = native_body_fixture_tx(9).exact_outer_bytes().to_vec();
    // Missing or substituted preimages cannot partially install the schema.
    assert!(
        NodeOwnedTxAdmissionBoundaryV0::migrate_legacy_native_candidate_v1(
            &path,
            [0x88; 32],
            profile,
            std::slice::from_ref(&two),
            &signer,
            &context
        )
        .is_err()
    );
    let legacy = SqlitePendingNonceAuthorityV0::open(&path, [0x88; 32]).unwrap();
    assert_eq!(legacy.retained_rows().unwrap(), 2);
    drop(legacy);
    let digest = NodeOwnedTxAdmissionBoundaryV0::migrate_legacy_native_candidate_v1(
        &path,
        [0x88; 32],
        profile,
        &[nine.clone(), two.clone()],
        &signer,
        &context,
    )
    .unwrap();
    assert_ne!(digest, [0; 32]);
    let mut owner = native_body_fixture_open(&path, profile, 2500, false).unwrap();
    let first = owner.submit_native_bytes_v1(&two).unwrap();
    let second = owner.submit_native_bytes_v1(&nine).unwrap();
    assert_eq!(
        (first.receive_sequence(), second.receive_sequence()),
        (1, 2)
    );
    assert_eq!(first.status(), NativeAdmissionStatusV1::Expired);
    assert!(owner.pop_native_ready_v1().unwrap().is_none());
    drop(owner);
    cleanup(&path);
}

#[test]
fn native_migration_rejects_handoff_and_live_owner_without_mutation() {
    let path = temp_path();
    let profile = NativeAdmissionProfileV1::candidate_defaults([7; 32]);
    let signer = BuilderFixtureSignerResolver {
        signer: CanonicalSignerId::from_bytes([0xa5; 32]).unwrap(),
    };
    let context = BuilderFixtureAdmissionContext {
        chain_id: "trnm-devnet",
        now_unix_ms: 1500,
    };
    legacy_native_reserved_fixture(&path, &[1]);
    let built = native_body_fixture_tx(1);
    let mut legacy = SqlitePendingNonceAuthorityV0::open(&path, [0x88; 32]).unwrap();
    assert!(
        NodeOwnedTxAdmissionBoundaryV0::migrate_legacy_native_candidate_v1(
            &path,
            [0x88; 32],
            profile,
            &[built.exact_outer_bytes().to_vec()],
            &signer,
            &context
        )
        .is_err()
    );
    let view = built.admission_view_v0(signer.signer);
    let gate = TypedAdmissionGate::new(256, 0, 262144);
    let mut held = legacy
        .reserve_record(&view, &gate.canonical_metadata_v0(&view).unwrap())
        .unwrap();
    held.handoff().unwrap();
    drop(held);
    drop(legacy);
    assert!(matches!(
        NodeOwnedTxAdmissionBoundaryV0::migrate_legacy_native_candidate_v1(
            &path,
            [0x88; 32],
            profile,
            &[built.exact_outer_bytes().to_vec()],
            &signer,
            &context
        ),
        Err(NativeAdmissionErrorV1::Wal(
            TxAdmissionWalErrorV0::AmbiguousHandoff
        ))
    ));
    cleanup(&path);
}
