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

fn file_contains_meaningful_recovery_surface(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    match fs::read_to_string(path) {
        Ok(raw) => !metadata_scaffold_is_effectively_empty(&raw),
        Err(_) => true,
    }
}

pub(crate) fn wal_dir_has_existing_state(wal_dir: &Path) -> bool {
    file_contains_meaningful_recovery_surface(&wal_file(wal_dir))
        || file_contains_meaningful_recovery_surface(&wal_meta_file(wal_dir))
        || file_contains_meaningful_recovery_surface(&checkpoint_file(wal_dir))
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

fn canonicalize_wal_meta(entries: &mut Vec<WalMeta>) {
    entries.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.round.cmp(&b.round))
            .then_with(|| a.proposal_hash.cmp(&b.proposal_hash))
            .then_with(|| a.committed.cmp(&b.committed))
            .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
            .then_with(|| a.prev_hash_hex.cmp(&b.prev_hash_hex))
    });
    entries.dedup_by(|a, b| a == b);
}

fn metadata_scaffold_is_effectively_empty(raw: &str) -> bool {
    raw.lines().all(|line| {
        let line = line.trim_start_matches('\u{feff}');
        let without_comment = line.split_once('#').map_or(line, |(before, _)| before);
        without_comment.trim().is_empty()
    })
}

pub(crate) fn load_wal_meta_entries(wal_dir: &Path) -> Result<Vec<WalMeta>> {
    let f = wal_meta_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw =
        fs::read_to_string(&f).with_context(|| format!("read wal meta failed: {}", f.display()))?;
    if metadata_scaffold_is_effectively_empty(&raw) {
        return Ok(vec![]);
    }
    let mut list: WalMetaList =
        toml::from_str(&raw).with_context(|| format!("parse wal meta failed: {}", f.display()))?;
    canonicalize_wal_meta(&mut list.entries);
    Ok(list.entries)
}

pub(crate) fn persist_wal_meta_entries(wal_dir: &Path, entries: &[WalMeta]) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_meta_file(wal_dir);
    let mut entries = entries.to_vec();
    canonicalize_wal_meta(&mut entries);
    let raw = toml::to_string(&WalMetaList { entries })?;
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
    if metadata_scaffold_is_effectively_empty(&raw) {
        return Ok(vec![]);
    }
    let mut list: CheckpointMetaList = toml::from_str(&raw)
        .with_context(|| format!("parse checkpoint failed: {}", f.display()))?;
    canonicalize_checkpoint_meta(&mut list.checkpoints);
    list.checkpoints.dedup_by(|a, b| {
        a.height == b.height
            && a.state_root_hex == b.state_root_hex
            && a.wal_entry_hash_hex == b.wal_entry_hash_hex
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
    canonicalize_checkpoint_meta(&mut checkpoints);
    checkpoints.dedup_by(|a, b| {
        a.height == b.height
            && a.state_root_hex == b.state_root_hex
            && a.wal_entry_hash_hex == b.wal_entry_hash_hex
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn temp_wal_dir(name: &str) -> PathBuf {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "trnm-node-wal-{}-{}-{}",
            name,
            std::process::id(),
            now_nanos
        ))
    }

    fn default_args() -> Args {
        Args::parse_from(["trnm-node"])
    }

    #[test]
    fn resolve_wal_dir_auto_isolates_existing_builtin_default_state_for_safe_rejoin() {
        let sandbox = temp_wal_dir("resolve-auto-isolates-default");
        let prior_cwd = std::env::current_dir().unwrap();
        fs::create_dir_all(sandbox.join(DEFAULT_BFT_WAL_DIR)).unwrap();
        fs::write(
            checkpoint_file(&sandbox.join(DEFAULT_BFT_WAL_DIR)),
            "[[checkpoints]]\nheight = 1\nstate_root_hex = \"aa\"\nwal_entry_hash_hex = \"bb\"\n",
        )
        .unwrap();
        std::env::set_current_dir(&sandbox).unwrap();

        let args = default_args();
        let requested = PathBuf::from(DEFAULT_BFT_WAL_DIR);
        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_ne!(resolved, requested);
        assert!(resolved.starts_with(&requested));
        assert!(
            note.unwrap().contains("isolating this run"),
            "expected auto isolation note for existing default-path state"
        );

        std::env::set_current_dir(prior_cwd).unwrap();
        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn resolve_wal_dir_auto_preserves_explicit_custom_recovery_path() {
        let wal_dir = temp_wal_dir("resolve-auto-preserves-custom");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_meta_file(&wal_dir), "entries = []\n").unwrap();

        let mut args = default_args();
        args.bft_wal_dir = wal_dir.display().to_string();
        args.bft_wal_mode = WalDirMode::Auto;

        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(note.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_comment_only_checkpoint_scaffold_exists() {
        let sandbox = temp_wal_dir("resolve-auto-comment-only-checkpoint-scaffold");
        let prior_cwd = std::env::current_dir().unwrap();
        fs::create_dir_all(sandbox.join(DEFAULT_BFT_WAL_DIR)).unwrap();
        fs::write(
            checkpoint_file(&sandbox.join(DEFAULT_BFT_WAL_DIR)),
            "# operator left a recovery note\n   # keep until next successful catch-up\n",
        )
        .unwrap();
        std::env::set_current_dir(&sandbox).unwrap();

        let args = default_args();
        let requested = PathBuf::from(DEFAULT_BFT_WAL_DIR);
        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, requested);
        assert!(note.is_none());

        std::env::set_current_dir(prior_cwd).unwrap();
        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_comment_only_consensus_wal_scaffold_exists(
    ) {
        let sandbox = temp_wal_dir("resolve-auto-comment-only-consensus-wal-scaffold");
        let prior_cwd = std::env::current_dir().unwrap();
        fs::create_dir_all(sandbox.join(DEFAULT_BFT_WAL_DIR)).unwrap();
        fs::write(
            wal_file(&sandbox.join(DEFAULT_BFT_WAL_DIR)),
            "# operator left a rejoin note\n   # safe to reuse builtin default once catch-up succeeds\n",
        )
        .unwrap();
        std::env::set_current_dir(&sandbox).unwrap();

        let args = default_args();
        let requested = PathBuf::from(DEFAULT_BFT_WAL_DIR);
        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, requested);
        assert!(note.is_none());

        std::env::set_current_dir(prior_cwd).unwrap();
        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_blank_consensus_wal_scaffold_exists() {
        let sandbox = temp_wal_dir("resolve-auto-blank-consensus-wal-scaffold");
        let prior_cwd = std::env::current_dir().unwrap();
        fs::create_dir_all(sandbox.join(DEFAULT_BFT_WAL_DIR)).unwrap();
        fs::write(wal_file(&sandbox.join(DEFAULT_BFT_WAL_DIR)), "  \n\t").unwrap();
        std::env::set_current_dir(&sandbox).unwrap();

        let args = default_args();
        let requested = PathBuf::from(DEFAULT_BFT_WAL_DIR);
        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, requested);
        assert!(note.is_none());

        std::env::set_current_dir(prior_cwd).unwrap();
        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_bom_prefixed_comment_consensus_wal_scaffold_exists(
    ) {
        let sandbox = temp_wal_dir("resolve-auto-bom-comment-consensus-wal-scaffold");
        let prior_cwd = std::env::current_dir().unwrap();
        fs::create_dir_all(sandbox.join(DEFAULT_BFT_WAL_DIR)).unwrap();
        fs::write(
            wal_file(&sandbox.join(DEFAULT_BFT_WAL_DIR)),
            "\u{feff}# operator left a rejoin note\n   # safe to reuse builtin default once catch-up succeeds\n",
        )
        .unwrap();
        std::env::set_current_dir(&sandbox).unwrap();

        let args = default_args();
        let requested = PathBuf::from(DEFAULT_BFT_WAL_DIR);
        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, requested);
        assert!(note.is_none());

        std::env::set_current_dir(prior_cwd).unwrap();
        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_comment_only_wal_meta_scaffold_exists() {
        let sandbox = temp_wal_dir("resolve-auto-comment-only-wal-meta-scaffold");
        let prior_cwd = std::env::current_dir().unwrap();
        fs::create_dir_all(sandbox.join(DEFAULT_BFT_WAL_DIR)).unwrap();
        fs::write(
            wal_meta_file(&sandbox.join(DEFAULT_BFT_WAL_DIR)),
            "# operator left a catch-up note\n\t# safe to treat as empty metadata scaffold\n",
        )
        .unwrap();
        std::env::set_current_dir(&sandbox).unwrap();

        let args = default_args();
        let requested = PathBuf::from(DEFAULT_BFT_WAL_DIR);
        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, requested);
        assert!(note.is_none());

        std::env::set_current_dir(prior_cwd).unwrap();
        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_allows_comment_only_checkpoint_scaffold() {
        let wal_dir = temp_wal_dir("resolve-fail-if-exists-comment-only-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "# operator left a recovery note\n   # safe to reuse after catch-up succeeds\n",
        )
        .unwrap();

        let mut args = default_args();
        args.bft_wal_dir = wal_dir.display().to_string();
        args.bft_wal_mode = WalDirMode::FailIfExists;

        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(note.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_allows_bom_prefixed_comment_only_checkpoint_scaffold() {
        let wal_dir = temp_wal_dir("resolve-fail-if-exists-bom-comment-only-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "\u{feff}# operator left a recovery note\n   # safe to reuse after catch-up succeeds\n",
        )
        .unwrap();

        let mut args = default_args();
        args.bft_wal_dir = wal_dir.display().to_string();
        args.bft_wal_mode = WalDirMode::FailIfExists;

        let (resolved, note) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(note.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_rejects_checkpoint_only_recovery_surface() {
        let wal_dir = temp_wal_dir("resolve-fail-if-exists-checkpoint-only");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(checkpoint_file(&wal_dir), "[[checkpoints]]\nheight = 7\nstate_root_hex = \"root-a\"\nwal_entry_hash_hex = \"hash-a\"\n").unwrap();

        let mut args = default_args();
        args.bft_wal_dir = wal_dir.display().to_string();
        args.bft_wal_mode = WalDirMode::FailIfExists;

        let err = resolve_wal_dir(&args).unwrap_err().to_string();
        assert!(
            err.contains("refusing to reuse existing BFT WAL state"),
            "unexpected fail-if-exists error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_wal_meta_canonicalizes_disk_order_for_audit_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-persist-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(
            &wal_dir,
            &[
                WalMeta {
                    height: 2,
                    round: 0,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "bb".repeat(32),
                    prev_hash_hex: Some("22".repeat(32)),
                },
                WalMeta {
                    height: 1,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "aa".repeat(32),
                    prev_hash_hex: None,
                },
            ],
        )
        .unwrap();

        let raw = fs::read_to_string(wal_meta_file(&wal_dir)).unwrap();
        let parsed: WalMetaList = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].height, 1);
        assert_eq!(parsed.entries[0].state_root_hex, "aa".repeat(32));
        assert_eq!(parsed.entries[1].height, 2);
        assert_eq!(parsed.entries[1].state_root_hex, "bb".repeat(32));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_canonicalizes_out_of_order_disk_entries_for_audit_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-load-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&WalMetaList {
            entries: vec![
                WalMeta {
                    height: 3,
                    round: 0,
                    proposal_hash: "proposal-c".into(),
                    committed: true,
                    state_root_hex: "cc".repeat(32),
                    prev_hash_hex: Some("33".repeat(32)),
                },
                WalMeta {
                    height: 1,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "aa".repeat(32),
                    prev_hash_hex: None,
                },
                WalMeta {
                    height: 2,
                    round: 0,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "bb".repeat(32),
                    prev_hash_hex: Some("22".repeat(32)),
                },
            ],
        })
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), raw).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].height, 1);
        assert_eq!(entries[0].state_root_hex, "aa".repeat(32));
        assert_eq!(entries[1].height, 2);
        assert_eq!(entries[1].state_root_hex, "bb".repeat(32));
        assert_eq!(entries[2].height, 3);
        assert_eq!(entries[2].state_root_hex, "cc".repeat(32));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn equal_height_wal_entries_canonicalize_for_auditable_proof_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-equal-height-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(
            &wal_dir,
            &[
                WalMeta {
                    height: 7,
                    round: 2,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "root-b".into(),
                    prev_hash_hex: Some("prev-b".into()),
                },
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-c".into()),
                },
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: false,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
            ],
        )
        .unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(
            entries,
            vec![
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: false,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-c".into()),
                },
                WalMeta {
                    height: 7,
                    round: 2,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "root-b".into(),
                    prev_hash_hex: Some("prev-b".into()),
                },
            ]
        );

        let raw = fs::read_to_string(wal_meta_file(&wal_dir)).unwrap();
        let first = raw.find("proposal-a").unwrap();
        let second = raw.rfind("proposal-b").unwrap();
        assert!(first < second);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_wal_meta_canonicalizes_missing_prev_hash_before_linked_successors_for_audit_surfaces() {
        let wal_dir = temp_wal_dir("wal-persist-canonical-missing-prev-hash-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(
            &wal_dir,
            &[
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-z".into()),
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: None,
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
            ],
        )
        .unwrap();

        let raw = fs::read_to_string(wal_meta_file(&wal_dir)).unwrap();
        let parsed: WalMetaList = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].prev_hash_hex, None);
        assert_eq!(parsed.entries[1].prev_hash_hex.as_deref(), Some("prev-a"));
        assert_eq!(parsed.entries[2].prev_hash_hex.as_deref(), Some("prev-z"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_canonicalizes_missing_prev_hash_before_linked_successors_for_audit_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-missing-prev-hash-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&WalMetaList {
            entries: vec![
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-z".into()),
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: None,
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
            ],
        })
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), raw).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].prev_hash_hex, None);
        assert_eq!(entries[1].prev_hash_hex.as_deref(), Some("prev-a"));
        assert_eq!(entries[2].prev_hash_hex.as_deref(), Some("prev-z"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_wal_meta_deduplicates_identical_entries_for_auditable_surfaces() {
        let wal_dir = temp_wal_dir("wal-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        let entry = WalMeta {
            height: 7,
            round: 1,
            proposal_hash: "proposal-7".into(),
            committed: true,
            state_root_hex: "aa".repeat(32),
            prev_hash_hex: Some("bb".repeat(32)),
        };
        persist_wal_meta_entries(&wal_dir, &[entry.clone(), entry.clone()]).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries, vec![entry.clone()]);

        let raw = fs::read_to_string(wal_meta_file(&wal_dir)).unwrap();
        assert_eq!(raw.matches("height = 7").count(), 1, "unexpected raw WAL file: {raw}");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_deduplicates_identical_disk_entries_for_auditable_surfaces() {
        let wal_dir = temp_wal_dir("wal-load-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        let entry = WalMeta {
            height: 9,
            round: 0,
            proposal_hash: "proposal-9".into(),
            committed: true,
            state_root_hex: "cc".repeat(32),
            prev_hash_hex: Some("dd".repeat(32)),
        };
        let raw = toml::to_string(&WalMetaList {
            entries: vec![entry.clone(), entry.clone()],
        })
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), raw).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries, vec![entry]);

        let _ = fs::remove_dir_all(&wal_dir);
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
    fn persist_checkpoint_meta_deduplicates_identical_entries_for_auditable_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 8,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
            ],
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 7);
        assert_eq!(checkpoints[0].state_root_hex, "root-a");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, "hash-a");
        assert_eq!(checkpoints[1].height, 8);
        assert_eq!(checkpoints[1].state_root_hex, "root-b");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, "hash-b");

        let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
        assert_eq!(raw.matches("height = 7").count(), 1, "unexpected raw checkpoint file: {raw}");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_deduplicates_identical_disk_entries_for_auditable_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-load-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                [[checkpoints]]
                height = 7
                state_root_hex = "root-a"
                wal_entry_hash_hex = "hash-a"

                [[checkpoints]]
                height = 8
                state_root_hex = "root-b"
                wal_entry_hash_hex = "hash-b"

                [[checkpoints]]
                height = 7
                state_root_hex = "root-a"
                wal_entry_hash_hex = "hash-a"
            "#,
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 7);
        assert_eq!(checkpoints[0].state_root_hex, "root-a");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, "hash-a");
        assert_eq!(checkpoints[1].height, 8);
        assert_eq!(checkpoints[1].state_root_hex, "root-b");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, "hash-b");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_treats_blank_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-blank-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(checkpoint_file(&wal_dir), "  \n\t").unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_treats_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "# operator left a recovery note\n   # keep until next successful catch-up\n",
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_treats_bom_prefixed_blank_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-bom-blank-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(checkpoint_file(&wal_dir), "\u{feff} \n\t").unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_treats_bom_prefixed_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-bom-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "\u{feff}# operator left a recovery note\n   # keep until next successful catch-up\n",
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_treats_crlf_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-crlf-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "# operator left a recovery note\r\n   # keep until next successful catch-up\r\n",
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

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
    fn load_wal_meta_treats_blank_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-blank-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_meta_file(&wal_dir), "\n  \t").unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_treats_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            "# operator left a catch-up note\n\t# safe to treat as empty metadata scaffold\n",
        )
        .unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_treats_bom_prefixed_blank_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-bom-blank-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_meta_file(&wal_dir), "\u{feff}\n  \t").unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_treats_bom_prefixed_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-bom-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            "\u{feff}# operator left a catch-up note\n\t# safe to treat as empty metadata scaffold\n",
        )
        .unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_treats_crlf_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-crlf-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            "# operator left a catch-up note\r\n\t# safe to treat as empty metadata scaffold\r\n",
        )
        .unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

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
