use super::*;

pub(crate) fn load_wal_meta_entries(wal_dir: &Path) -> Result<Vec<WalMeta>> {
    let f = wal_meta_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw =
        fs::read_to_string(&f).with_context(|| format!("read wal meta failed: {}", f.display()))?;
    let list: WalMetaList =
        toml::from_str(&raw).with_context(|| format!("parse wal meta failed: {}", f.display()))?;
    Ok(list.entries)
}

pub(crate) fn persist_wal_meta_entries(wal_dir: &Path, entries: &[WalMeta]) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_meta_file(wal_dir);
    let raw = toml::to_string(&WalMetaList {
        entries: entries.to_vec(),
    })?;
    fs::write(&f, raw).with_context(|| format!("write wal meta failed: {}", f.display()))?;
    Ok(())
}

pub(crate) fn load_checkpoint_meta(wal_dir: &Path) -> Result<Vec<CheckpointMeta>> {
    let f = checkpoint_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&f)
        .with_context(|| format!("read checkpoint failed: {}", f.display()))?;
    let mut list: CheckpointMetaList = toml::from_str(&raw)
        .with_context(|| format!("parse checkpoint failed: {}", f.display()))?;
    list.checkpoints.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
            .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
    });
    Ok(list.checkpoints)
}

pub(crate) fn persist_checkpoint_meta(
    wal_dir: &Path,
    checkpoints: &[CheckpointMeta],
) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = checkpoint_file(wal_dir);
    let mut checkpoints = checkpoints.to_vec();
    checkpoints.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
            .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
    });
    let raw = toml::to_string(&CheckpointMetaList { checkpoints })?;
    fs::write(&f, raw).with_context(|| format!("write checkpoint failed: {}", f.display()))?;
    Ok(())
}

pub(crate) fn persist_consensus_wal(wal_dir: &Path, wal: &ConsensusWal) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_file(wal_dir);
    let raw = toml::to_string(wal)?;
    fs::write(&f, raw).with_context(|| format!("write wal failed: {}", f.display()))?;
    Ok(())
}
