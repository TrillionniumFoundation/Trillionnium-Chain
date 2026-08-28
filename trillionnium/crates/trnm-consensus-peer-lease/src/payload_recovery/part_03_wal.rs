fn bounded_count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn namespace_digest(namespace: PayloadReplayNamespaceV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE_DOMAIN_V1);
    hasher.update(namespace.local_id());
    hasher.update(namespace.epoch().to_be_bytes());
    hasher.update(namespace.validator_set_id());
    hasher.update(namespace.run_id_hash());
    hasher.update(namespace.network_context_hash());
    hasher.finalize().into()
}

fn record_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN_V1);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn head_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN_V1);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn read_snapshot(
    file: &mut File,
    namespace: PayloadReplayNamespaceV1,
    expected_namespace_digest: [u8; 32],
) -> Result<PayloadSnapshotV1, PayloadReplayRecoveryErrorV1> {
    let maximum = PAYLOAD_REPLAY_MAX_RECORDS_V1
        .checked_mul(RECORD_BYTES_V1 as u64)
        .ok_or(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt)?;
    let length = file.metadata()?.len();
    if length == 0 || length > maximum || length % RECORD_BYTES_V1 as u64 != 0 {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    file.seek(SeekFrom::Start(0))?;
    let capacity =
        usize::try_from(length).map_err(|_| PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    file.seek(SeekFrom::End(0))?;
    if bytes.len() as u64 != length {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    verify_log(&bytes, namespace, expected_namespace_digest)?;
    let last = decode_record(
        bytes
            .get(bytes.len().saturating_sub(RECORD_BYTES_V1)..)
            .ok_or(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt)?,
    )?;
    Ok(PayloadSnapshotV1 {
        record_count: (bytes.len() / RECORD_BYTES_V1) as u64,
        last_hash: last.record_hash,
        bytes,
    })
}

fn verify_log(
    bytes: &[u8],
    namespace: PayloadReplayNamespaceV1,
    expected_namespace_digest: [u8; 32],
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(RECORD_BYTES_V1) {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    let count = bytes.len() / RECORD_BYTES_V1;
    if count == 0 || count as u64 > PAYLOAD_REPLAY_MAX_RECORDS_V1 {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    let mut states = BTreeMap::<PeerKeyV1, ReplayStateV1>::new();
    let mut seen_sessions = BTreeSet::<(PeerKeyV1, [u8; 32])>::new();
    let mut previous_hash = [0; 32];
    for (index, record_bytes) in bytes.chunks_exact(RECORD_BYTES_V1).enumerate() {
        let record = decode_record(record_bytes)?;
        if record.index != index as u64
            || record.namespace_digest != expected_namespace_digest
            || record.local_id != namespace.local_id()
            || record.epoch != namespace.epoch()
            || record.validator_set_id != namespace.validator_set_id()
            || record.run_id_hash != namespace.run_id_hash()
            || record.network_context_hash != namespace.network_context_hash()
            || record.predecessor != previous_hash
        {
            return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
        }
        if index == 0 {
            if record.operation != LOG_GENESIS_KIND_V1
                || record.remote_id != [0; 32]
                || record.direction.is_some()
                || record.session_id != [0; 32]
                || record.generation != 0
                || record.sequence != 0
                || record.frame_kind != 0
                || record.payload_len != 0
                || record.frame_fingerprint != [0; 32]
                || record.predecessor != [0; 32]
            {
                return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
            }
        } else {
            verify_frame_record(record, &mut states, &mut seen_sessions)?;
        }
        previous_hash = record.record_hash;
    }
    Ok(())
}

fn verify_frame_record(
    record: DecodedRecordV1,
    states: &mut BTreeMap<PeerKeyV1, ReplayStateV1>,
    seen_sessions: &mut BTreeSet<(PeerKeyV1, [u8; 32])>,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    if record.operation != LOG_FRAME_KIND_V1
        || record.remote_id == [0; 32]
        || record.remote_id == record.local_id
        || record.session_id == [0; 32]
        || record.generation == 0
        || record.frame_kind == 0
        || record.payload_len as usize > PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1
        || record.frame_fingerprint == [0; 32]
    {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    let direction = record
        .direction
        .ok_or(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt)?;
    let key = PeerKeyV1 {
        remote_id: record.remote_id,
        direction,
    };
    let new_session = states
        .get(&key)
        .map(|state| state.session_id != record.session_id)
        .unwrap_or(true);
    if new_session && !seen_sessions.insert((key, record.session_id)) {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    match states.get(&key).copied() {
        None => {
            if record.generation != 1 || record.sequence != 0 {
                return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
            }
        }
        Some(previous) if record.generation == previous.generation => {
            let expected = previous
                .last_sequence
                .checked_add(1)
                .ok_or(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt)?;
            if record.session_id != previous.session_id || record.sequence != expected {
                return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
            }
        }
        Some(previous) if record.generation == previous.generation.saturating_add(1) => {
            if record.session_id == previous.session_id || record.sequence != 0 {
                return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
            }
        }
        Some(_) => return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt),
    }
    states.insert(
        key,
        ReplayStateV1 {
            session_id: record.session_id,
            generation: record.generation,
            last_sequence: record.sequence,
        },
    );
    Ok(())
}

fn decode_record(bytes: &[u8]) -> Result<DecodedRecordV1, PayloadReplayRecoveryErrorV1> {
    if bytes.len() != RECORD_BYTES_V1
        || bytes[..8] != LOG_MAGIC_V1
        || bytes[8] != LOG_VERSION_V1
        || bytes[10..12] != [0, 0]
        || bytes[117..124].iter().any(|byte| *byte != 0)
        || bytes[277..280].iter().any(|byte| *byte != 0)
    {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    let stored: [u8; 32] = bytes[RECORD_PREFIX_BYTES_V1..]
        .try_into()
        .expect("fixed payload replay digest");
    if stored != record_digest(&bytes[..RECORD_PREFIX_BYTES_V1]) {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    let direction = match bytes[116] {
        0 => None,
        1 => Some(PeerLeaseDirectionV1::Outbound),
        2 => Some(PeerLeaseDirectionV1::Inbound),
        _ => return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt),
    };
    Ok(DecodedRecordV1 {
        operation: bytes[9],
        index: u64::from_be_bytes(bytes[12..20].try_into().expect("record index")),
        namespace_digest: bytes[20..52].try_into().expect("namespace digest"),
        local_id: bytes[52..84].try_into().expect("local id"),
        remote_id: bytes[84..116].try_into().expect("remote id"),
        direction,
        epoch: u64::from_be_bytes(bytes[124..132].try_into().expect("epoch")),
        validator_set_id: bytes[132..164].try_into().expect("validator set"),
        run_id_hash: bytes[164..196].try_into().expect("run id hash"),
        network_context_hash: bytes[196..228].try_into().expect("network context"),
        session_id: bytes[228..260].try_into().expect("session id"),
        generation: u64::from_be_bytes(bytes[260..268].try_into().expect("generation")),
        sequence: u64::from_be_bytes(bytes[268..276].try_into().expect("sequence")),
        frame_kind: bytes[276],
        payload_len: u32::from_be_bytes(bytes[280..284].try_into().expect("payload length")),
        frame_fingerprint: bytes[284..316].try_into().expect("frame fingerprint"),
        predecessor: bytes[316..348].try_into().expect("predecessor"),
        record_hash: stored,
    })
}

fn read_head(path: &Path) -> Result<PayloadHeadV1, PayloadReplayRecoveryErrorV1> {
    let mut file = open_private_file(path, false)?;
    if file.metadata()?.len() != HEAD_BYTES_V1 as u64 {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    let mut bytes = [0u8; HEAD_BYTES_V1];
    file.read_exact(&mut bytes)?;
    let mut trailing = [0u8; 1];
    let stored: [u8; 32] = bytes[HEAD_PREFIX_BYTES_V1..]
        .try_into()
        .expect("fixed payload replay head checksum");
    if file.read(&mut trailing)? != 0
        || bytes[..8] != HEAD_MAGIC_V1
        || bytes[8] != HEAD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
        || stored != head_digest(&bytes[..HEAD_PREFIX_BYTES_V1])
    {
        return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
    }
    Ok(PayloadHeadV1 {
        record_count: u64::from_be_bytes(bytes[12..20].try_into().expect("head count")),
        record_hash: bytes[20..52].try_into().expect("head hash"),
        namespace_digest: bytes[52..84].try_into().expect("head namespace"),
    })
}

fn encode_head(
    record_count: u64,
    record_hash: [u8; 32],
    namespace_digest: [u8; 32],
) -> [u8; HEAD_BYTES_V1] {
    let mut bytes = Vec::with_capacity(HEAD_BYTES_V1);
    bytes.extend_from_slice(&HEAD_MAGIC_V1);
    bytes.push(HEAD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&record_count.to_be_bytes());
    bytes.extend_from_slice(&record_hash);
    bytes.extend_from_slice(&namespace_digest);
    bytes.extend_from_slice(&head_digest(&bytes));
    bytes.try_into().expect("fixed payload replay head")
}

fn persist_head(
    path: &Path,
    directory: &File,
    record_count: u64,
    record_hash: [u8; 32],
    namespace_digest: [u8; 32],
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let name = utf8_filename(path, "payload replay head filename")?;
    let temporary = path.with_file_name(format!(
        ".{name}.tmp-recovery-{}-{}",
        std::process::id(),
        TEMP_NONCE_V1.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_options(&mut options);
    let mut file = options.open(&temporary)?;
    file.write_all(&encode_head(record_count, record_hash, namespace_digest))?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    directory.sync_all()?;
    Ok(())
}

fn scan_head_temporaries(
    payload_path: &Path,
) -> Result<Vec<PathBuf>, PayloadReplayRecoveryErrorV1> {
    let parent = payload_path
        .parent()
        .ok_or(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "payload replay path has no parent",
        ))?;
    let head_path = sidecar_path(payload_path, "head-v1")?;
    let head_name = utf8_filename(&head_path, "payload replay head filename")?;
    let prefix = format!(".{head_name}.tmp-");
    let mut paths = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|value| value.starts_with(&prefix))
        {
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || !private_file_mode(&metadata)
            {
                return Err(PayloadReplayRecoveryErrorV1::PayloadJournalCorrupt);
            }
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn quarantine_temporaries(
    directory: &File,
    paths: &[PathBuf],
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    for (index, path) in paths.iter().enumerate() {
        let file = open_private_file(path, false)?;
        validate_private_file(&file)?;
        let parent = path
            .parent()
            .ok_or(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "payload replay temporary has no parent",
            ))?;
        let quarantine = parent.join(format!(
            "payload-head-recovery-evidence-{}-{}-{index}.v1",
            std::process::id(),
            TEMP_NONCE_V1.fetch_add(1, Ordering::Relaxed)
        ));
        fs::rename(path, quarantine)?;
    }
    directory.sync_all()?;
    Ok(())
}
