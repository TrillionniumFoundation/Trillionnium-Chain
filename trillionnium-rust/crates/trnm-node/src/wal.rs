use crate::args::{Args, WalDirMode, DEFAULT_BFT_WAL_DIR};
use crate::types::ConsensusWal;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_state::{CheckpointMeta, WalMeta};

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct WalMetaList {
    entries: Vec<WalMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CheckpointMetaList {
    checkpoints: Vec<CheckpointMeta>,
}

pub(crate) fn wal_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal.toml")
}

pub(crate) fn wal_dir_has_existing_state(wal_dir: &Path) -> bool {
    wal_file(wal_dir).exists()
        || wal_meta_file(wal_dir).exists()
        || checkpoint_file(wal_dir).exists()
}

pub(crate) fn isolated_default_wal_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(format!("session-{}-{}", now_unix_ms(), std::process::id()))
}

pub(crate) fn resolve_wal_dir(args: &Args) -> Result<(PathBuf, Option<String>)> {
    let requested = PathBuf::from(&args.bft_wal_dir);
    let uses_builtin_default = requested == PathBuf::from(DEFAULT_BFT_WAL_DIR);
    let has_existing_state = wal_dir_has_existing_state(&requested);

    match args.bft_wal_mode {
        WalDirMode::Reuse => Ok((requested, None)),
        WalDirMode::FailIfExists => {
            if has_existing_state {
                anyhow::bail!(
                    "refusing to reuse existing BFT WAL state at {} (pass --bft-wal-mode reuse to recover, or choose a fresh --bft-wal-dir)",
                    requested.display()
                );
            }
            Ok((requested, None))
        }
        WalDirMode::Auto => {
            if uses_builtin_default && has_existing_state {
                let isolated = isolated_default_wal_dir(&requested);
                Ok((
                    isolated.clone(),
                    Some(format!(
                        "[bft-wal] existing default WAL state detected at {}; isolating this run in {} (pass --bft-wal-mode reuse to recover prior state explicitly)",
                        requested.display(),
                        isolated.display()
                    )),
                ))
            } else {
                Ok((requested, None))
            }
        }
    }
}

pub(crate) fn wal_meta_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal-meta.toml")
}

pub(crate) fn checkpoint_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-checkpoints.toml")
}

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
        std::env::temp_dir().join(format!("trnm-node-wal-{}-{}", name, now_unix_ms()))
    }

    #[test]
    fn persist_checkpoint_meta_canonicalizes_disk_order_for_audit_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-canonical-persist-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "bb".repeat(32),
                    wal_entry_hash_hex: "22".repeat(32),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "aa".repeat(32),
                    wal_entry_hash_hex: "11".repeat(32),
                },
            ],
        )
        .unwrap();

        let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
        let parsed: CheckpointMetaList = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.checkpoints.len(), 2);
        assert_eq!(parsed.checkpoints[0].height, 1);
        assert_eq!(parsed.checkpoints[0].state_root_hex, "aa".repeat(32));
        assert_eq!(parsed.checkpoints[1].height, 2);
        assert_eq!(parsed.checkpoints[1].state_root_hex, "bb".repeat(32));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_canonicalizes_out_of_order_disk_entries_for_audit_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-canonical-load-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&CheckpointMetaList {
            checkpoints: vec![
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "cc".repeat(32),
                    wal_entry_hash_hex: "33".repeat(32),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "aa".repeat(32),
                    wal_entry_hash_hex: "11".repeat(32),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "bb".repeat(32),
                    wal_entry_hash_hex: "22".repeat(32),
                },
            ],
        })
        .unwrap();
        fs::write(checkpoint_file(&wal_dir), raw).unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 3);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "aa".repeat(32));
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "bb".repeat(32));
        assert_eq!(checkpoints[2].height, 3);
        assert_eq!(checkpoints[2].state_root_hex, "cc".repeat(32));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn equal_height_checkpoint_entries_canonicalize_for_auditable_proof_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-canonical-equal-height-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
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
        )
        .unwrap();

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

        let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
        let first = raw.find("root-a").unwrap();
        let second = raw.rfind("root-b").unwrap();
        assert!(first < second);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_rejects_unknown_top_level_fields_for_auditable_surfaces() {
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
    fn load_checkpoint_meta_rejects_unknown_entry_fields_for_auditable_surfaces() {
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
    fn load_wal_meta_rejects_unknown_top_level_fields_for_auditable_surfaces() {
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
    fn load_wal_meta_rejects_unknown_entry_fields_for_auditable_surfaces() {
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
}

