use super::*;

pub(crate) fn wal_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal.toml")
}

pub(crate) fn wal_meta_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal-meta.toml")
}

pub(crate) fn checkpoint_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-checkpoints.toml")
}

fn file_contains_meaningful_recovery_surface(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    match fs::read_to_string(path) {
        Ok(raw) => !is_effectively_empty_toml_scaffold(&raw),
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
