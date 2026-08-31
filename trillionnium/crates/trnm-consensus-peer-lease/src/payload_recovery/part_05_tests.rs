#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::PayloadReplayStoreV1;
    use tempfile::TempDir;

    fn private_tempdir(prefix: &str) -> TempDir {
        let directory = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn namespace() -> PayloadReplayNamespaceV1 {
        PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32]).unwrap()
    }

    fn frame(
        namespace: PayloadReplayNamespaceV1,
        sequence: u64,
        fingerprint: [u8; 32],
    ) -> PayloadReplayFrameV1 {
        PayloadReplayFrameV1::new(
            namespace
                .scope_for([9; 32], PeerLeaseDirectionV1::Inbound)
                .unwrap(),
            namespace.run_id_hash(),
            namespace.network_context_hash(),
            [5; 32],
            1,
            sequence,
            2,
            11,
            fingerprint,
        )
        .unwrap()
    }

    fn acknowledgement_root(root: &Path) -> PathBuf {
        let path = root.join("core-acks");
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn seeded_payload(path: &Path) -> (PayloadReplayNamespaceV1, PayloadReplayRecoveryTargetV1) {
        let namespace = namespace();
        let frame = frame(namespace, 0, [10; 32]);
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(path, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        (
            namespace,
            PayloadReplayRecoveryTargetV1::from_admission(frame, receipt),
        )
    }

    fn rewind_head_to_genesis(payload: &Path, namespace: PayloadReplayNamespaceV1) {
        let wal = fs::read(payload).unwrap();
        let genesis = decode_record(&wal[..RECORD_BYTES_V1]).unwrap();
        let head = sidecar_path(payload, "head-v1").unwrap();
        fs::write(
            head,
            encode_head(1, genesis.record_hash, namespace_digest(namespace)),
        )
        .unwrap();
    }

    #[test]
    fn reports_admitted_then_acknowledged_and_reopens_idempotently() {
        let root = private_tempdir("trnm-payload-recovery-");
        let payload = root.path().join("frames.wal");
        let acknowledgements = acknowledgement_root(root.path());
        let namespace = namespace();
        let frame = frame(namespace, 0, [10; 32]);
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(&payload, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
        let mut owner =
            PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target)
                .unwrap();
        assert!(matches!(
            owner.status().unwrap(),
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { .. }
        ));
        let acknowledgement = PayloadReplayCoreAcknowledgementV1::new(target, 9, [11; 32]).unwrap();
        let written = owner.acknowledge_core(acknowledgement).unwrap();
        assert!(!written.idempotent_replay());
        drop(owner);

        let mut reopened =
            PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target)
                .unwrap();
        assert!(reopened.status().unwrap().core_acknowledged());
        let replayed = reopened.acknowledge_core(acknowledgement).unwrap();
        assert!(replayed.idempotent_replay());
        assert_eq!(
            replayed.acknowledgement_hash(),
            written.acknowledgement_hash()
        );
    }

    #[test]
    fn conflicting_acknowledgement_fails_closed() {
        let root = private_tempdir("trnm-payload-ack-conflict-");
        let payload = root.path().join("frames.wal");
        let acknowledgements = acknowledgement_root(root.path());
        let namespace = namespace();
        let frame = frame(namespace, 0, [10; 32]);
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(&payload, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
        let mut owner =
            PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target)
                .unwrap();
        owner
            .acknowledge_core(PayloadReplayCoreAcknowledgementV1::new(target, 9, [11; 32]).unwrap())
            .unwrap();
        assert!(matches!(
            owner.acknowledge_core(
                PayloadReplayCoreAcknowledgementV1::new(target, 10, [12; 32]).unwrap(),
            ),
            Err(PayloadReplayRecoveryErrorV1::AckConflict)
        ));
    }

    #[test]
    fn exact_one_record_head_lag_and_retained_temp_are_recovered() {
        let root = private_tempdir("trnm-payload-head-recovery-");
        let payload = root.path().join("frames.wal");
        let acknowledgements = acknowledgement_root(root.path());
        let namespace = namespace();
        let frame = frame(namespace, 0, [10; 32]);
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(&payload, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
        rewind_head_to_genesis(&payload, namespace);
        let head = sidecar_path(&payload, "head-v1").unwrap();
        let head_name = utf8_filename(&head, "head").unwrap();
        let retained = head.with_file_name(format!(".{head_name}.tmp-test"));
        fs::write(&retained, b"retained evidence").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o600)).unwrap();

        let mut owner =
            PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target)
                .unwrap();
        assert!(matches!(
            owner.status().unwrap(),
            PayloadReplayRecoveryStatusV1::RecoverableHeadLag { .. }
        ));
        assert!(matches!(
            owner.recover_payload_publication().unwrap(),
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { .. }
        ));
        drop(owner);
        PayloadReplayStoreV1::open(&payload, namespace).unwrap();
    }

    #[test]
    fn acknowledgement_requires_publication_recovery_first() {
        let root = private_tempdir("trnm-payload-ack-before-recovery-");
        let payload = root.path().join("frames.wal");
        let acknowledgements = acknowledgement_root(root.path());
        let namespace = namespace();
        let frame = frame(namespace, 0, [10; 32]);
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(&payload, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
        rewind_head_to_genesis(&payload, namespace);
        let mut owner =
            PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target)
                .unwrap();
        let acknowledgement = PayloadReplayCoreAcknowledgementV1::new(target, 9, [11; 32]).unwrap();
        assert!(matches!(
            owner.acknowledge_core(acknowledgement),
            Err(PayloadReplayRecoveryErrorV1::RecoveryRequired)
        ));
    }

    #[test]
    fn live_payload_owner_blocks_external_recovery_owner() {
        let root = private_tempdir("trnm-payload-live-owner-");
        let payload = root.path().join("frames.wal");
        let acknowledgements = acknowledgement_root(root.path());
        let namespace = namespace();
        let frame = frame(namespace, 0, [10; 32]);
        let mut store = PayloadReplayStoreV1::open(&payload, namespace).unwrap();
        let receipt = store.admit(&frame).unwrap();
        let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
        assert!(matches!(
            PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target,),
            Err(PayloadReplayRecoveryErrorV1::PayloadJournalBusy)
        ));
    }

    #[test]
    fn mismatched_target_fails_before_acknowledgement() {
        let root = private_tempdir("trnm-payload-target-mismatch-");
        let payload = root.path().join("frames.wal");
        let acknowledgements = acknowledgement_root(root.path());
        let namespace = namespace();
        let frame = frame(namespace, 0, [10; 32]);
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(&payload, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        let mut target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);
        target.frame_fingerprint = [99; 32];
        assert!(matches!(
            PayloadReplayRecoveryOwnerV1::open(&payload, &acknowledgements, namespace, target,),
            Err(PayloadReplayRecoveryErrorV1::PayloadRecordMismatch)
        ));
    }

    #[test]
    fn retained_ack_temporary_is_an_ambiguous_stop_condition() {
        let root = private_tempdir("trnm-payload-ack-temp-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        let retained = ack_root.join(".ack-retained.v1.tmp-1-1");
        fs::write(&retained, b"retained ambiguity").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o600)).unwrap();

        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");
        assert!(matches!(
            owner.status(),
            Err(PayloadReplayRecoveryErrorV1::AckCommitAmbiguous(_))
        ));
    }

    #[test]
    fn two_link_ack_publication_residue_is_ambiguous() {
        let root = private_tempdir("trnm-payload-ack-hardlink-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");
        let acknowledgement = PayloadReplayCoreAcknowledgementV1::new(target, 9, [11; 32]).unwrap();
        let bytes = encode_ack(namespace_digest(namespace), acknowledgement);
        let final_path = ack_path(&ack_root, target);
        let temp_path = ack_temp_path(&final_path);
        drop(write_ack_temp(&temp_path, &bytes).unwrap());
        fs::hard_link(&temp_path, &final_path).unwrap();

        assert!(matches!(
            owner.status(),
            Err(PayloadReplayRecoveryErrorV1::AckCommitAmbiguous(_))
        ));
    }

    #[test]
    fn tampered_acknowledgement_is_rejected() {
        let root = private_tempdir("trnm-payload-ack-tamper-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        {
            let mut owner =
                PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target).unwrap();
            owner
                .acknowledge_core(
                    PayloadReplayCoreAcknowledgementV1::new(target, 9, [11; 32]).unwrap(),
                )
                .unwrap();
        }
        let final_path = ack_path(&ack_root, target);
        let mut bytes = fs::read(&final_path).unwrap();
        bytes[124] ^= 0x01;
        fs::write(&final_path, bytes).unwrap();

        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");
        assert!(matches!(
            owner.status(),
            Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt)
        ));
    }

    #[test]
    fn head_lag_longer_than_one_target_record_is_rejected() {
        let root = private_tempdir("trnm-payload-long-head-lag-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let namespace = namespace();
        let first = frame(namespace, 0, [10; 32]);
        let second = frame(namespace, 1, [11; 32]);
        let second_receipt = {
            let mut store = PayloadReplayStoreV1::open(&wal, namespace).unwrap();
            store.admit(&first).unwrap();
            store.admit(&second).unwrap()
        };
        let target = PayloadReplayRecoveryTargetV1::from_admission(second, second_receipt);
        rewind_head_to_genesis(&wal, namespace);
        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");
        assert!(matches!(
            owner.status(),
            Err(PayloadReplayRecoveryErrorV1::PayloadHeadDiverged)
        ));
    }

    #[test]
    fn wrong_namespace_fails_full_wal_replay() {
        let root = private_tempdir("trnm-payload-wrong-namespace-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (_, target) = seeded_payload(&wal);
        let wrong_namespace =
            PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [44; 32]).unwrap();
        assert!(matches!(
            PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, wrong_namespace, target,),
            Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_head_temporary_is_rejected() {
        let root = private_tempdir("trnm-payload-head-symlink-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        let head = sidecar_path(&wal, "head-v1").unwrap();
        let head_name = utf8_filename(&head, "head").unwrap();
        let retained = head.with_file_name(format!(".{head_name}.tmp-symlink"));
        std::os::unix::fs::symlink(&wal, retained).unwrap();

        assert!(matches!(
            PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target),
            Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn broad_acknowledgement_root_is_rejected() {
        let root = private_tempdir("trnm-payload-broad-ack-root-");
        let wal = root.path().join("frames.wal");
        let ack_root = root.path().join("acks");
        fs::create_dir(&ack_root).unwrap();
        fs::set_permissions(&ack_root, fs::Permissions::from_mode(0o755)).unwrap();
        let (namespace, target) = seeded_payload(&wal);

        assert!(matches!(
            PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target),
            Err(PayloadReplayRecoveryErrorV1::InvalidRequest(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_identity_rejects_payload_replacement_after_open() {
        let root = private_tempdir("trnm-payload-endpoint-payload-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");

        let original = root.path().join("frames.wal.original");
        fs::rename(&wal, &original).unwrap();
        fs::copy(&original, &wal).unwrap();
        fs::set_permissions(&wal, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            owner.verify_bound_endpoint_identity(),
            Err(PayloadReplayRecoveryErrorV1::InvalidRequest(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_identity_rejects_head_replacement_after_open() {
        let root = private_tempdir("trnm-payload-endpoint-head-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");
        let head = sidecar_path(&wal, "head-v1").unwrap();

        let original = root.path().join("frames.head.original");
        fs::rename(&head, &original).unwrap();
        fs::copy(&original, &head).unwrap();
        fs::set_permissions(&head, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            owner.verify_bound_endpoint_identity(),
            Err(PayloadReplayRecoveryErrorV1::InvalidRequest(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_identity_rejects_acknowledgement_root_replacement_after_open() {
        let root = private_tempdir("trnm-payload-endpoint-ack-root-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");

        let original = root.path().join("core-acks.original");
        fs::rename(&ack_root, &original).unwrap();
        fs::create_dir(&ack_root).unwrap();
        fs::set_permissions(&ack_root, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            owner.verify_bound_endpoint_identity(),
            Err(PayloadReplayRecoveryErrorV1::InvalidRequest(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_identity_rejects_lock_replacement_after_open() {
        let root = private_tempdir("trnm-payload-endpoint-lock-");
        let wal = root.path().join("frames.wal");
        let ack_root = acknowledgement_root(root.path());
        let (namespace, target) = seeded_payload(&wal);
        let owner = PayloadReplayRecoveryOwnerV1::open(&wal, &ack_root, namespace, target)
            .expect("open recovery owner");
        let lock = sidecar_path(&wal, "lock-v1").unwrap();

        let original = root.path().join("frames.lock.original");
        fs::rename(&lock, &original).unwrap();
        fs::copy(&original, &lock).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            owner.verify_bound_endpoint_identity(),
            Err(PayloadReplayRecoveryErrorV1::InvalidRequest(_))
        ));
    }
}
