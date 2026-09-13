#[cfg(feature = "lab-validator-runtime-test-support")]
fn process_store_v1(root: &Path, create: bool) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err("finalization-intent process root is not absolute".to_owned());
    }
    let canonical = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize process root: {error:?}"))?;
    if canonical != root {
        return Err("finalization-intent process root is not canonical".to_owned());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect process root: {error:?}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("finalization-intent process root is not a directory".to_owned());
    }
    let store_path = root.join(PROCESS_STORE_NAME_V1);
    if create {
        if fs::read_dir(root)
            .map_err(|error| format!("read fresh process root: {error:?}"))?
            .next()
            .is_some()
        {
            return Err("fresh finalization-intent process root is not empty".to_owned());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut store = options
            .open(&store_path)
            .map_err(|error| format!("create process store: {error:?}"))?;
        store
            .write_all(b"TRNM finalization-intent process fixture v1\n")
            .and_then(|()| store.sync_all())
            .map_err(|error| format!("persist process store identity: {error:?}"))?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("persist process store directory: {error:?}"))?;
    }
    validate_store_v0(&store_path)
        .map_err(|error| format!("authenticate process store: {error}"))?;
    Ok(store_path)
}

#[cfg(feature = "lab-validator-runtime-test-support")]
fn print_process_state_v1(
    prefix: &str,
    phase: FinalizationIntentProcessCheckpointV1,
    store_path: &Path,
    marker: FinalizationIntentMarkerV0,
) -> Result<(), String> {
    let marker_facts = residue_facts_v1(&marker_path_v0(store_path))
        .map_err(|error| error.to_owned())?;
    let temp_facts = residue_facts_v1(&marker_temp_path_v0(store_path))
        .map_err(|error| error.to_owned())?;
    let same_inode = marker_facts
        .identity
        .zip(temp_facts.identity)
        .is_some_and(|(marker_identity, temp_identity)| marker_identity == temp_identity);
    println!(
        concat!(
            "{}_v1={};fingerprint={};marker={};temp={};",
            "marker_links={};temp_links={};same_inode={}"
        ),
        prefix,
        phase.as_str(),
        lower_hex_v1(&process_marker_fingerprint_v1(marker)),
        u8::from(marker_facts.exists),
        u8::from(temp_facts.exists),
        marker_facts.links,
        temp_facts.links,
        u8::from(same_inode),
    );
    Ok(())
}
