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

fn canonicalize_checkpoint_meta(checkpoints: &mut [CheckpointMeta]) {
    checkpoints.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
            .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
    });
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
    canonicalize_checkpoint_meta(&mut list.checkpoints);
    Ok(list.checkpoints)
}

pub(crate) fn persist_checkpoint_meta(
    wal_dir: &Path,
    checkpoints: &[CheckpointMeta],
) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = checkpoint_file(wal_dir);
    let mut checkpoints = checkpoints.to_vec();
    canonicalize_checkpoint_meta(&mut checkpoints);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_wal_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trnm-node-runtime-recovery-wal-{}-{}",
            name,
            now_unix_ms()
        ))
    }

    #[test]
    fn load_checkpoint_meta_canonicalizes_equal_height_entries_for_recovery_audit_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-canonical-equal-height-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&CheckpointMetaList {
            checkpoints: vec![
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
            ],
        })
        .unwrap();
        fs::write(checkpoint_file(&wal_dir), raw).unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(
            checkpoints,
            vec![
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
            ]
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_rejects_unknown_top_level_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-unknown-top-level-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                checkpoints = []
                forged = true
            "#,
        )
        .unwrap();

        let err = load_checkpoint_meta(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_rejects_unknown_entry_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-unknown-entry-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                [[checkpoints]]
                height = 7
                state_root_hex = "aa"
                wal_entry_hash_hex = "bb"
                forged = true
            "#,
        )
        .unwrap();

        let err = load_checkpoint_meta(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_rejects_duplicate_top_level_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-duplicate-top-level-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                checkpoints = []
                checkpoints = []
            "#,
        )
        .unwrap();

        let err = load_checkpoint_meta(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("duplicate") && err.contains("checkpoints"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_rejects_duplicate_entry_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-duplicate-entry-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                [[checkpoints]]
                height = 7
                state_root_hex = "aa"
                state_root_hex = "bb"
                wal_entry_hash_hex = "cc"
            "#,
        )
        .unwrap();

        let err = load_checkpoint_meta(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("duplicate") && err.contains("state_root_hex"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_rejects_unknown_top_level_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-unknown-top-level-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            r#"
                entries = []
                forged = true
            "#,
        )
        .unwrap();

        let err = load_wal_meta_entries(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_rejects_unknown_entry_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-unknown-entry-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            r#"
                [[entries]]
                height = 7
                round = 1
                proposal_hash = "proposal-7"
                committed = true
                state_root_hex = "aa"
                prev_hash_hex = "bb"
                forged = true
            "#,
        )
        .unwrap();

        let err = load_wal_meta_entries(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_rejects_duplicate_top_level_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-duplicate-top-level-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            r#"
                entries = []
                entries = []
            "#,
        )
        .unwrap();

        let err = load_wal_meta_entries(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("duplicate") && err.contains("entries"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_rejects_duplicate_entry_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-duplicate-entry-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            r#"
                [[entries]]
                height = 7
                round = 1
                proposal_hash = "proposal-7"
                committed = true
                state_root_hex = "aa"
                state_root_hex = "bb"
                prev_hash_hex = "cc"
            "#,
        )
        .unwrap();

        let err = load_wal_meta_entries(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("duplicate") && err.contains("state_root_hex"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }
}
