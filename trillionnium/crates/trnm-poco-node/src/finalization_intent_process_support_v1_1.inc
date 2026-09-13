
#[cfg(feature = "lab-validator-runtime-test-support")]
fn process_fixture_marker_v1() -> FinalizationIntentMarkerV0 {
    let seed = PROCESS_FIXTURE_SEED_V1;
    FinalizationIntentMarkerV0 {
        scope: [seed; 32],
        owner_id: [seed.wrapping_add(1); 32],
        proof_id: [seed.wrapping_add(2); 32],
        target_block_id: [seed.wrapping_add(3); 32],
        parent_block_id: [seed.wrapping_add(4); 32],
        target_state_root: [seed.wrapping_add(5); 32],
        target_receipts_root: [seed.wrapping_add(6); 32],
        parent_state_root: [seed.wrapping_add(7); 32],
        parent_commit_id: [seed.wrapping_add(8); 32],
        target_overlay_checksum: [seed.wrapping_add(9); 32],
        source_artifact_checksum: [seed.wrapping_add(10); 32],
        target_height: 7,
        target_view: 8,
        target_timestamp_ms: 9,
        parent_height: 6,
        parent_view: 7,
        parent_timestamp_ms: 8,
    }
}

#[cfg(feature = "lab-validator-runtime-test-support")]
fn process_marker_fingerprint_v1(marker: FinalizationIntentMarkerV0) -> [u8; 32] {
    checksum_v0(&marker.encode())
}

#[cfg(feature = "lab-validator-runtime-test-support")]
fn lower_hex_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let byte = *byte;
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(feature = "lab-validator-runtime-test-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessResidueFactsV1 {
    exists: bool,
    links: u64,
    identity: Option<PathIdentityV0>,
}

#[cfg(feature = "lab-validator-runtime-test-support")]
fn residue_facts_v1(path: &Path) -> Result<ProcessResidueFactsV1, &'static str> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(ProcessResidueFactsV1 {
            exists: true,
            #[cfg(unix)]
            links: metadata.nlink(),
            #[cfg(not(unix))]
            links: 1,
            identity: Some(PathIdentityV0::from_metadata(&metadata)),
        }),
        Ok(_) => Err("finalization intent process residue is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ProcessResidueFactsV1 {
            exists: false,
            links: 0,
            identity: None,
        }),
        Err(_) => Err("finalization intent process residue lookup failed"),
    }
}

#[cfg(feature = "lab-validator-runtime-test-support")]
fn residue_exists_v1(path: &Path) -> Result<bool, &'static str> {
    residue_facts_v1(path).map(|facts| facts.exists)
}

#[cfg(feature = "lab-validator-runtime-test-support")]
fn maybe_hold_process_checkpoint_v1(
    phase: FinalizationIntentProcessCheckpointV1,
    store_path: &Path,
    marker: FinalizationIntentMarkerV0,
) -> Result<(), &'static str> {
    if SELECTED_PROCESS_CHECKPOINT_V1.get().copied() != Some(phase) {
        return Ok(());
    }
    let marker_facts = residue_facts_v1(&marker_path_v0(store_path))?;
    let temp_facts = residue_facts_v1(&marker_temp_path_v0(store_path))?;
    let same_inode = marker_facts
        .identity
        .zip(temp_facts.identity)
        .is_some_and(|(marker_identity, temp_identity)| marker_identity == temp_identity);
    let fingerprint = lower_hex_v1(&process_marker_fingerprint_v1(marker));
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        concat!(
            "checkpoint_v1={};fingerprint={};marker={};temp={};",
            "marker_links={};temp_links={};same_inode={}"
        ),
        phase.as_str(),
        fingerprint,
        u8::from(marker_facts.exists),
        u8::from(temp_facts.exists),
        marker_facts.links,
        temp_facts.links,
        u8::from(same_inode),
    )
    .and_then(|()| output.flush())
    .map_err(|_| "finalization intent process checkpoint write failed")?;

    // The parent process keeps this pipe open and sends SIGKILL after reading
    // the checkpoint.  A manual `continue` is accepted for local diagnosis,
    // but EOF or any other input fails closed rather than allowing an
    // unobserved durability cut to proceed.
    let mut acknowledgement = String::new();
    let bytes = std::io::stdin()
        .read_line(&mut acknowledgement)
        .map_err(|_| "finalization intent process checkpoint read failed")?;
    if bytes == 0 || acknowledgement.trim() != "continue" {
        return Err("finalization intent process checkpoint was not explicitly continued");
    }
    Ok(())
}
