#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PeerKeyV1 {
    remote_id: [u8; 32],
    direction: PeerLeaseDirectionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayStateV1 {
    session_id: [u8; 32],
    generation: u64,
    last_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodedRecordV1 {
    operation: u8,
    index: u64,
    namespace_digest: [u8; 32],
    local_id: [u8; 32],
    remote_id: [u8; 32],
    direction: Option<PeerLeaseDirectionV1>,
    epoch: u64,
    validator_set_id: [u8; 32],
    run_id_hash: [u8; 32],
    network_context_hash: [u8; 32],
    session_id: [u8; 32],
    generation: u64,
    sequence: u64,
    frame_kind: u8,
    payload_len: u32,
    frame_fingerprint: [u8; 32],
    predecessor: [u8; 32],
    record_hash: [u8; 32],
}

impl DecodedRecordV1 {
    fn matches_target(self, target: PayloadReplayRecoveryTargetV1) -> bool {
        self.operation == LOG_FRAME_KIND_V1
            && self.index == target.record_index
            && self.record_hash == target.record_hash
            && self.remote_id == target.remote_id
            && self.direction == Some(target.direction)
            && self.session_id == target.session_id
            && self.generation == target.generation
            && self.sequence == target.sequence
            && self.frame_kind == target.frame_kind
            && self.payload_len == target.payload_len
            && self.frame_fingerprint == target.frame_fingerprint
    }
}

#[derive(Debug)]
struct PayloadSnapshotV1 {
    bytes: Vec<u8>,
    last_hash: [u8; 32],
    record_count: u64,
}

impl PayloadSnapshotV1 {
    fn record(&self, index: u64) -> Result<DecodedRecordV1, PayloadReplayRecoveryErrorV1> {
        let index = usize::try_from(index)
            .map_err(|_| PayloadReplayRecoveryErrorV1::PayloadRecordMismatch)?;
        let start = index
            .checked_mul(RECORD_BYTES_V1)
            .ok_or(PayloadReplayRecoveryErrorV1::PayloadRecordMismatch)?;
        let end = start
            .checked_add(RECORD_BYTES_V1)
            .ok_or(PayloadReplayRecoveryErrorV1::PayloadRecordMismatch)?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or(PayloadReplayRecoveryErrorV1::PayloadRecordMismatch)?;
        decode_record(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PayloadHeadV1 {
    record_count: u64,
    record_hash: [u8; 32],
    namespace_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationStateV1 {
    Durable,
    HeadLag,
    ResidualTemporaries,
}

#[derive(Debug)]
struct PayloadJournalRecoveryV1 {
    path: PathBuf,
    head_path: PathBuf,
    directory: File,
    _file: File,
    _lock: File,
    namespace_digest: [u8; 32],
    snapshot: PayloadSnapshotV1,
    head: PayloadHeadV1,
    stale_temporaries: Vec<PathBuf>,
}

impl PayloadJournalRecoveryV1 {
    fn open(
        path: &Path,
        namespace: PayloadReplayNamespaceV1,
    ) -> Result<Self, PayloadReplayRecoveryErrorV1> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(PayloadReplayRecoveryErrorV1::PayloadJournalMissing)
            }
            Err(error) => return Err(PayloadReplayRecoveryErrorV1::Io(error)),
        };
        if !metadata.is_file() || !private_file_mode(&metadata) {
            return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
        }
        let (directory, _) = private_parent(path)?;
        let lock_path = sidecar_path(path, "lock-v1")?;
        let head_path = sidecar_path(path, "head-v1")?;
        if !fs::symlink_metadata(&lock_path).is_ok_and(|value| value.is_file()) {
            return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
        }
        let lock = open_private_file(&lock_path, true)?;
        try_lock(&lock, PayloadReplayRecoveryErrorV1::PayloadJournalBusy)?;
        let mut file = open_private_file(path, true)?;
        try_lock(&file, PayloadReplayRecoveryErrorV1::PayloadJournalBusy)?;
        let namespace_digest = namespace_digest(namespace);
        let snapshot = read_snapshot(&mut file, namespace, namespace_digest)?;
        let head = read_head(&head_path)?;
        let stale_temporaries = scan_head_temporaries(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            head_path,
            directory,
            _file: file,
            _lock: lock,
            namespace_digest,
            snapshot,
            head,
            stale_temporaries,
        })
    }

    fn target_record(
        &self,
        target: PayloadReplayRecoveryTargetV1,
    ) -> Result<DecodedRecordV1, PayloadReplayRecoveryErrorV1> {
        target.validate()?;
        let record = self.snapshot.record(target.record_index)?;
        if !record.matches_target(target) {
            return Err(PayloadReplayRecoveryErrorV1::PayloadRecordMismatch);
        }
        Ok(record)
    }

    fn classify(
        &self,
        target: PayloadReplayRecoveryTargetV1,
    ) -> Result<PublicationStateV1, PayloadReplayRecoveryErrorV1> {
        let target_record = self.target_record(target)?;
        if self.head.namespace_digest != self.namespace_digest {
            return Err(PayloadReplayRecoveryErrorV1::PayloadHeadDiverged);
        }
        if self.head.record_count == self.snapshot.record_count
            && self.head.record_hash == self.snapshot.last_hash
        {
            return Ok(if self.stale_temporaries.is_empty() {
                PublicationStateV1::Durable
            } else {
                PublicationStateV1::ResidualTemporaries
            });
        }
        let target_is_tip = target_record
            .index
            .checked_add(1)
            .is_some_and(|count| count == self.snapshot.record_count)
            && target_record.record_hash == self.snapshot.last_hash;
        let exact_one_record_lag = self.head.record_count == target_record.index
            && self.head.record_hash == target_record.predecessor
            && target_is_tip;
        if exact_one_record_lag {
            return Ok(PublicationStateV1::HeadLag);
        }
        Err(PayloadReplayRecoveryErrorV1::PayloadHeadDiverged)
    }

    fn recover(
        &mut self,
        target: PayloadReplayRecoveryTargetV1,
    ) -> Result<(), PayloadReplayRecoveryErrorV1> {
        match self.classify(target)? {
            PublicationStateV1::Durable => return Ok(()),
            PublicationStateV1::HeadLag => {
                persist_head(
                    &self.head_path,
                    &self.directory,
                    self.snapshot.record_count,
                    self.snapshot.last_hash,
                    self.namespace_digest,
                )?;
                self.head = PayloadHeadV1 {
                    record_count: self.snapshot.record_count,
                    record_hash: self.snapshot.last_hash,
                    namespace_digest: self.namespace_digest,
                };
            }
            PublicationStateV1::ResidualTemporaries => {}
        }
        quarantine_temporaries(&self.directory, &self.stale_temporaries)?;
        self.stale_temporaries.clear();
        let reread = read_head(&self.head_path)?;
        if reread != self.head || !scan_head_temporaries(&self.path)?.is_empty() {
            return Err(PayloadReplayRecoveryErrorV1::PayloadHeadDiverged);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AckFactsV1 {
    namespace_digest: [u8; 32],
    record_index: u64,
    record_hash: [u8; 32],
    frame_fingerprint: [u8; 32],
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
    acknowledgement_hash: [u8; 32],
}

impl AckFactsV1 {
    fn matches(
        self,
        namespace_digest: [u8; 32],
        acknowledgement: PayloadReplayCoreAcknowledgementV1,
    ) -> bool {
        let target = acknowledgement.target;
        self.namespace_digest == namespace_digest
            && self.record_index == target.record_index
            && self.record_hash == target.record_hash
            && self.frame_fingerprint == target.frame_fingerprint
            && self.core_safety_revision == acknowledgement.core_safety_revision
            && self.core_ack_digest == acknowledgement.core_ack_digest
    }
}

#[derive(Debug)]
pub struct PayloadReplayRecoveryOwnerV1 {
    payload: PayloadJournalRecoveryV1,
    acknowledgement_root: PathBuf,
    acknowledgement_directory: File,
    _ack_lock: File,
    target: PayloadReplayRecoveryTargetV1,
}

impl PayloadReplayRecoveryOwnerV1 {
    pub fn open(
        payload_path: impl AsRef<Path>,
        acknowledgement_root: impl AsRef<Path>,
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
    ) -> Result<Self, PayloadReplayRecoveryErrorV1> {
        target.validate()?;
        let payload_path = payload_path.as_ref();
        let acknowledgement_root = acknowledgement_root.as_ref().to_path_buf();
        if acknowledgement_root == payload_path
            || acknowledgement_root == sidecar_path(payload_path, "head-v1")?
            || acknowledgement_root == sidecar_path(payload_path, "lock-v1")?
        {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "payload and acknowledgement paths collide",
            ));
        }
        let acknowledgement_directory = private_directory(&acknowledgement_root)?;
        let ack_lock_path = acknowledgement_root.join(ACK_LOCK_NAME_V1);
        let ack_lock = open_private_lock(&ack_lock_path)?;
        try_lock(&ack_lock, PayloadReplayRecoveryErrorV1::AckLedgerBusy)?;
        let payload = PayloadJournalRecoveryV1::open(payload_path, namespace)?;
        payload.target_record(target)?;
        Ok(Self {
            payload,
            acknowledgement_root,
            acknowledgement_directory,
            _ack_lock: ack_lock,
            target,
        })
    }

    pub const fn target(&self) -> PayloadReplayRecoveryTargetV1 {
        self.target
    }

    pub fn status(&self) -> Result<PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryErrorV1> {
        match self.payload.classify(self.target)? {
            PublicationStateV1::HeadLag => Ok(PayloadReplayRecoveryStatusV1::RecoverableHeadLag {
                payload_record_count: self.payload.snapshot.record_count,
                payload_head_count: self.payload.head.record_count,
                retained_temporary_count: bounded_count(self.payload.stale_temporaries.len()),
            }),
            PublicationStateV1::ResidualTemporaries => Ok(
                PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries {
                    payload_record_count: self.payload.snapshot.record_count,
                    retained_temporary_count: bounded_count(self.payload.stale_temporaries.len()),
                },
            ),
            PublicationStateV1::Durable => {
                match read_ack_if_present(
                    &self.acknowledgement_root,
                    self.payload.namespace_digest,
                    self.target,
                )? {
                    None => Ok(PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged {
                        payload_record_count: self.payload.snapshot.record_count,
                        payload_head_hash: self.payload.snapshot.last_hash,
                    }),
                    Some(ack) => Ok(PayloadReplayRecoveryStatusV1::CoreAcknowledged {
                        payload_record_count: self.payload.snapshot.record_count,
                        payload_head_hash: self.payload.snapshot.last_hash,
                        core_safety_revision: ack.core_safety_revision,
                        core_ack_digest: ack.core_ack_digest,
                        acknowledgement_hash: ack.acknowledgement_hash,
                    }),
                }
            }
        }
    }

    pub fn recover_payload_publication(
        &mut self,
    ) -> Result<PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryErrorV1> {
        self.payload.recover(self.target)?;
        self.status()
    }

    pub fn acknowledge_core(
        &mut self,
        acknowledgement: PayloadReplayCoreAcknowledgementV1,
    ) -> Result<PayloadReplayCoreAckReceiptV1, PayloadReplayRecoveryErrorV1> {
        if acknowledgement.target != self.target {
            return Err(PayloadReplayRecoveryErrorV1::PayloadRecordMismatch);
        }
        if !matches!(
            self.payload.classify(self.target)?,
            PublicationStateV1::Durable
        ) {
            return Err(PayloadReplayRecoveryErrorV1::RecoveryRequired);
        }
        if let Some(existing) = read_ack_if_present(
            &self.acknowledgement_root,
            self.payload.namespace_digest,
            self.target,
        )? {
            if !existing.matches(self.payload.namespace_digest, acknowledgement) {
                return Err(PayloadReplayRecoveryErrorV1::AckConflict);
            }
            return Ok(PayloadReplayCoreAckReceiptV1 {
                acknowledgement_hash: existing.acknowledgement_hash,
                idempotent_replay: true,
            });
        }
        let bytes = encode_ack(self.payload.namespace_digest, acknowledgement);
        let acknowledgement_hash: [u8; 32] = bytes[ACK_PREFIX_BYTES_V1..]
            .try_into()
            .expect("fixed Core acknowledgement checksum");
        let final_path = ack_path(&self.acknowledgement_root, self.target);
        let temp_path = ack_temp_path(&final_path);
        let write_result = write_ack_temp(&temp_path, &bytes).and_then(|file| {
            drop(file);
            match fs::hard_link(&temp_path, &final_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(PayloadReplayRecoveryErrorV1::AckConflict);
                }
                Err(error) => return Err(PayloadReplayRecoveryErrorV1::Io(error)),
            }
            self.acknowledgement_directory.sync_all()?;
            fs::remove_file(&temp_path)?;
            self.acknowledgement_directory.sync_all()?;
            let final_file = open_private_file(&final_path, false)?;
            validate_private_file(&final_file)?;
            Ok(())
        });
        if let Err(error) = write_result {
            return Err(PayloadReplayRecoveryErrorV1::AckCommitAmbiguous(Box::new(
                error,
            )));
        }
        let reread = read_ack(&final_path, self.payload.namespace_digest, self.target)?;
        if !reread.matches(self.payload.namespace_digest, acknowledgement)
            || reread.acknowledgement_hash != acknowledgement_hash
        {
            return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
        }
        Ok(PayloadReplayCoreAckReceiptV1 {
            acknowledgement_hash,
            idempotent_replay: false,
        })
    }
}
