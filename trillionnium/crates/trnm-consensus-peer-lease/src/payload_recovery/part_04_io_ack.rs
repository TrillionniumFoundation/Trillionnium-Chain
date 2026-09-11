fn encode_ack(
    namespace_digest: [u8; 32],
    acknowledgement: PayloadReplayCoreAcknowledgementV1,
) -> [u8; ACK_BYTES_V1] {
    let target = acknowledgement.target;
    let mut bytes = Vec::with_capacity(ACK_BYTES_V1);
    bytes.extend_from_slice(&ACK_MAGIC_V1);
    bytes.push(ACK_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&namespace_digest);
    bytes.extend_from_slice(&target.record_index.to_be_bytes());
    bytes.extend_from_slice(&target.record_hash);
    bytes.extend_from_slice(&target.frame_fingerprint);
    bytes.extend_from_slice(&acknowledgement.core_safety_revision.to_be_bytes());
    bytes.extend_from_slice(&acknowledgement.core_ack_digest);
    debug_assert_eq!(bytes.len(), ACK_PREFIX_BYTES_V1);
    let mut hasher = Sha256::new();
    hasher.update(ACK_DOMAIN_V1);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    bytes.extend_from_slice(&hasher.finalize());
    bytes
        .try_into()
        .expect("fixed payload Core acknowledgement")
}

fn decode_ack(bytes: &[u8]) -> Result<AckFactsV1, PayloadReplayRecoveryErrorV1> {
    if bytes.len() != ACK_BYTES_V1
        || bytes[..8] != ACK_MAGIC_V1
        || bytes[8] != ACK_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
    {
        return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
    }
    let stored: [u8; 32] = bytes[ACK_PREFIX_BYTES_V1..]
        .try_into()
        .expect("fixed Core acknowledgement checksum");
    let mut hasher = Sha256::new();
    hasher.update(ACK_DOMAIN_V1);
    hasher.update((ACK_PREFIX_BYTES_V1 as u64).to_be_bytes());
    hasher.update(&bytes[..ACK_PREFIX_BYTES_V1]);
    let expected: [u8; 32] = hasher.finalize().into();
    if stored != expected {
        return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
    }
    let core_safety_revision =
        u64::from_be_bytes(bytes[116..124].try_into().expect("Core safety revision"));
    let core_ack_digest = bytes[124..156].try_into().expect("Core ack digest");
    if core_safety_revision == 0 || core_ack_digest == [0; 32] {
        return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
    }
    Ok(AckFactsV1 {
        namespace_digest: bytes[12..44].try_into().expect("namespace digest"),
        record_index: u64::from_be_bytes(bytes[44..52].try_into().expect("record index")),
        record_hash: bytes[52..84].try_into().expect("record hash"),
        frame_fingerprint: bytes[84..116].try_into().expect("frame fingerprint"),
        core_safety_revision,
        core_ack_digest,
        acknowledgement_hash: stored,
    })
}

fn ack_path(root: &Path, target: PayloadReplayRecoveryTargetV1) -> PathBuf {
    root.join(format!(
        "ack-{:020}-{}.v1",
        target.record_index,
        hex32(target.record_hash)
    ))
}

fn ack_temp_path(final_path: &Path) -> PathBuf {
    let name = final_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("payload-core-ack.v1");
    final_path.with_file_name(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        TEMP_NONCE_V1.fetch_add(1, Ordering::Relaxed)
    ))
}

fn write_ack_temp(
    path: &Path,
    bytes: &[u8; ACK_BYTES_V1],
) -> Result<File, PayloadReplayRecoveryErrorV1> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_options(&mut options);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(file)
}

fn read_ack_if_present(
    root: &Path,
    namespace_digest: [u8; 32],
    target: PayloadReplayRecoveryTargetV1,
) -> Result<Option<AckFactsV1>, PayloadReplayRecoveryErrorV1> {
    let retained_temporaries = scan_ack_temporaries(root)?;
    if !retained_temporaries.is_empty() {
        return Err(PayloadReplayRecoveryErrorV1::AckCommitAmbiguous(Box::new(
            PayloadReplayRecoveryErrorV1::AckLedgerCorrupt,
        )));
    }
    let path = ack_path(root, target);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_ack(&path, namespace_digest, target).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(PayloadReplayRecoveryErrorV1::Io(error)),
    }
}

fn scan_ack_temporaries(root: &Path) -> Result<Vec<PathBuf>, PayloadReplayRecoveryErrorV1> {
    let mut paths = Vec::new();
    let mut scanned = 0_usize;
    for entry in fs::read_dir(root)? {
        scanned = scanned
            .checked_add(1)
            .ok_or(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt)?;
        if scanned > PAYLOAD_REPLAY_MAX_TEMPORARY_SCAN_ENTRIES_V1 {
            return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
        };
        if name.starts_with(".ack-") && name.contains(".tmp-") {
            if paths.len() >= PAYLOAD_REPLAY_MAX_TEMPORARY_FILES_V1 {
                return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !private_ack_temporary_mode(&metadata) {
                return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
            }
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn private_ack_temporary_mode(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.is_file()
            && matches!(metadata.nlink(), 1 | 2)
            && metadata.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE_V1
            && metadata.uid() == rustix::process::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn read_ack(
    path: &Path,
    namespace_digest: [u8; 32],
    target: PayloadReplayRecoveryTargetV1,
) -> Result<AckFactsV1, PayloadReplayRecoveryErrorV1> {
    let mut file = open_private_file(path, false)?;
    if file.metadata()?.len() != ACK_BYTES_V1 as u64 {
        return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
    }
    let mut bytes = [0u8; ACK_BYTES_V1];
    file.read_exact(&mut bytes)?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(PayloadReplayRecoveryErrorV1::AckLedgerCorrupt);
    }
    let decoded = decode_ack(&bytes)?;
    if decoded.namespace_digest != namespace_digest
        || decoded.record_index != target.record_index
        || decoded.record_hash != target.record_hash
        || decoded.frame_fingerprint != target.frame_fingerprint
    {
        return Err(PayloadReplayRecoveryErrorV1::AckConflict);
    }
    Ok(decoded)
}

fn sidecar_path(path: &Path, suffix: &str) -> Result<PathBuf, PayloadReplayRecoveryErrorV1> {
    let name = utf8_filename(path, "payload replay filename")?;
    Ok(path.with_file_name(format!(".{name}.{suffix}")))
}

fn utf8_filename<'a>(
    path: &'a Path,
    reason: &'static str,
) -> Result<&'a str, PayloadReplayRecoveryErrorV1> {
    path.file_name()
        .and_then(|value| value.to_str())
        .ok_or(PayloadReplayRecoveryErrorV1::InvalidRequest(reason))
}

fn private_parent(path: &Path) -> Result<(File, PathBuf), PayloadReplayRecoveryErrorV1> {
    let parent = path
        .parent()
        .ok_or(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "authority path has no parent",
        ))?
        .to_path_buf();
    let metadata = fs::symlink_metadata(&parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !private_parent_mode(&metadata)
        || fs::canonicalize(&parent)? != parent
    {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "authority parent directory is not a canonical private directory",
        ));
    }
    ensure_private_directory(&parent).map_err(map_peer_lease_error)?;
    Ok((File::open(&parent)?, parent))
}

fn private_directory(path: &Path) -> Result<File, PayloadReplayRecoveryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !private_parent_mode(&metadata)
        || fs::canonicalize(path)? != path
    {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "Core acknowledgement root is not a canonical private directory",
        ));
    }
    ensure_private_directory(path).map_err(map_peer_lease_error)?;
    File::open(path).map_err(PayloadReplayRecoveryErrorV1::Io)
}

fn map_peer_lease_error(error: crate::PeerLeaseErrorV1) -> PayloadReplayRecoveryErrorV1 {
    match error {
        crate::PeerLeaseErrorV1::InvalidRequest(reason)
        | crate::PeerLeaseErrorV1::Protocol(reason) => {
            PayloadReplayRecoveryErrorV1::InvalidRequest(reason)
        }
        crate::PeerLeaseErrorV1::Io(error) => PayloadReplayRecoveryErrorV1::Io(error),
        crate::PeerLeaseErrorV1::Rejected(_) => {
            PayloadReplayRecoveryErrorV1::InvalidRequest("authority parent ancestry is not private")
        }
    }
}

fn open_private_lock(
    path: &Path,
) -> Result<(File, AuthorityPathIdentityV1), PayloadReplayRecoveryErrorV1> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_private_options(&mut options);
    let file = options.open(path)?;
    validate_private_file(&file)?;
    let identity = descriptor_identity(&file)?;
    verify_bound_path_identity(path, identity)?;
    Ok((file, identity))
}

fn open_private_file(path: &Path, writable: bool) -> Result<File, PayloadReplayRecoveryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || !private_file_mode(&metadata) {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "authority file is not a private single-link regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path)?;
    validate_private_file(&file)?;
    #[cfg(unix)]
    {
        let descriptor = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        if descriptor.dev() != named.dev()
            || descriptor.ino() != named.ino()
            || descriptor.uid() != named.uid()
        {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "authority descriptor/path identity changed",
            ));
        }
    }
    Ok(file)
}

fn validate_private_file(file: &File) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || !private_file_mode(&metadata) {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "authority file is not a private single-link regular file",
        ));
    }
    Ok(())
}

fn try_lock(
    file: &File,
    busy: PayloadReplayRecoveryErrorV1,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(busy),
        Err(error) => Err(PayloadReplayRecoveryErrorV1::Io(error)),
    }
}

fn set_private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(PRIVATE_FILE_MODE_V1);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
}

fn private_parent_mode(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o077 == 0
            && metadata.uid() == rustix::process::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn private_file_mode(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.nlink() == 1
            && metadata.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE_V1
            && metadata.uid() == rustix::process::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
