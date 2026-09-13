#[cfg(feature = "lab-validator-runtime-test-support")]
fn validate_recovery_file_v1(
    file: &File,
    path: &Path,
    allowed_links: &[u64],
) -> Result<PathIdentityV0, &'static str> {
    let metadata = file
        .metadata()
        .map_err(|_| "finalization intent recovery marker metadata failed")?;
    if !metadata.is_file() || metadata.len() != FIXED_BYTES_V0 as u64 || !path.is_absolute() {
        return Err("finalization intent recovery marker file shape invalid");
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 || !allowed_links.contains(&metadata.nlink()) {
        return Err("finalization intent recovery marker permissions/links invalid");
    }
    let identity = PathIdentityV0::from_metadata(&metadata);
    validate_path_identity_v0(
        path,
        identity,
        "finalization intent recovery marker was replaced during open",
    )?;
    Ok(identity)
}

#[cfg(feature = "lab-validator-runtime-test-support")]
fn read_recovery_marker_v1(
    path: &Path,
    allowed_links: &[u64],
) -> Result<(FinalizationIntentMarkerV0, PathIdentityV0), &'static str> {
    let mut file = open_read_v0(path)?;
    let identity = validate_recovery_file_v1(&file, path, allowed_links)?;
    let mut bytes = Vec::with_capacity(FIXED_BYTES_V0);
    file.read_to_end(&mut bytes)
        .map_err(|_| "finalization intent recovery marker read failed")?;
    validate_path_identity_v0(
        path,
        identity,
        "finalization intent recovery marker was replaced after read",
    )?;
    Ok((FinalizationIntentMarkerV0::decode(&bytes)?, identity))
}

/// Explicit test-support repair for an interrupted marker publication.
///
/// The repair accepts only the exact expected tuple.  It handles the two
/// crash-surviving publication residues produced by `write_marker_v0`:
/// a single fsynced temporary file before publication, or the marker and
/// temporary name as two hard links to the same inode after publication.
/// It never deletes conflicting bytes, never invents an expected tuple from
/// caller-controlled fields, and never runs in the default or production
/// feature set.
#[cfg(feature = "lab-validator-runtime-test-support")]
fn recover_marker_publication_v1(
    store_path: &Path,
    expected: FinalizationIntentMarkerV0,
) -> Result<(), &'static str> {
    let (store_identity, parent_identity) = validate_store_v0(store_path)?;
    let path = marker_path_v0(store_path);
    let temp = marker_temp_path_v0(store_path);
    let marker_exists = residue_exists_v1(&path)?;
    let temp_exists = residue_exists_v1(&temp)?;

    match (marker_exists, temp_exists) {
        (false, false) => {
            return Err("finalization intent publication has no recoverable exact residue");
        }
        (true, false) => {
            if load_marker_v0(store_path)? != Some(expected) {
                return Err("published finalization intent differs from the exact fixture");
            }
        }
        (false, true) => {
            let (temporary, temp_identity) = read_recovery_marker_v1(&temp, &[1])?;
            if temporary != expected {
                return Err("temporary finalization intent differs from the exact fixture");
            }
            ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
            ensure_parent_identity_v0(&path, parent_identity)?;
            validate_path_identity_v0(
                &temp,
                temp_identity,
                "temporary finalization intent was replaced before recovery publish",
            )?;
            fs::hard_link(&temp, &path)
                .map_err(|_| "finalization intent recovery publish raced or failed")?;
            ensure_parent_identity_v0(&path, parent_identity)?;
            validate_path_identity_v0(
                &path,
                temp_identity,
                "finalization intent recovery publish identity mismatch",
            )?;
            sync_parent_v0(&path, parent_identity)?;
            validate_path_identity_v0(
                &temp,
                temp_identity,
                "temporary finalization intent was replaced before recovery cleanup",
            )?;
            fs::remove_file(&temp)
                .map_err(|_| "temporary finalization intent recovery cleanup failed")?;
            sync_parent_v0(&path, parent_identity)?;
        }
        (true, true) => {
            let (published, marker_identity) = read_recovery_marker_v1(&path, &[2])?;
            let (temporary, temp_identity) = read_recovery_marker_v1(&temp, &[2])?;
            if published != expected || temporary != expected || marker_identity != temp_identity {
                return Err("published and temporary finalization intent residues conflict");
            }
            ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
            ensure_parent_identity_v0(&path, parent_identity)?;
            fs::remove_file(&temp)
                .map_err(|_| "published finalization intent temporary cleanup failed")?;
            sync_parent_v0(&path, parent_identity)?;
        }
    }

    ensure_store_identity_v0(store_path, store_identity, parent_identity)?;
    if residue_exists_v1(&temp)? || load_marker_v0(store_path)? != Some(expected) {
        return Err(
            "finalization intent publication recovery did not reach the exact stable marker",
        );
    }
    Ok(())
}
