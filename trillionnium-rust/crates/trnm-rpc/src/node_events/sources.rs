use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use crate::envpaths::{normalized_path_from_env, normalize_wrapped_env_value};
use crate::{NODE_EVENT_LOG_MANIFEST_ENV, NODE_EVENT_LOG_SOURCES_ENV};

#[cfg(test)]
use std::sync::{Mutex, MutexGuard, OnceLock};

pub(super) fn parse_node_event_log_sources_list(raw: &str) -> Vec<PathBuf> {
    raw.split(|c: char| c == ',' || c == ';' || c == '\n')
        .filter_map(|part| normalize_node_event_log_source_entry(part).map(PathBuf::from))
        .collect()
}

fn normalize_node_event_log_source_entry(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = normalize_wrapped_env_value(trimmed);
    if normalized.is_empty() || normalized.starts_with('#') {
        return None;
    }

    let inline_comment_idx = normalized.char_indices().find_map(|(idx, ch)| {
        (ch == '#'
            && idx > 0
            && normalized[..idx]
                .chars()
                .last()
                .is_some_and(char::is_whitespace))
        .then_some(idx)
    });
    let normalized = inline_comment_idx
        .map(|idx| normalize_wrapped_env_value(normalized[..idx].trim_end()))
        .unwrap_or(normalized);
    if normalized.is_empty() || normalized.starts_with('#') {
        return None;
    }

    Some(normalized.to_string())
}

fn normalize_lexical_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn discover_default_node_event_log_sources_impl(root: &Path) -> Vec<PathBuf> {
    let run_dir = root.join("run");
    let mut out = BTreeSet::<PathBuf>::new();
    for seed in ["event-field-check.log", "parallel-sanity.log"] {
        let candidate = run_dir.join(seed);
        if candidate.is_file() {
            out.insert(candidate);
        }
    }
    if let Ok(entries) = fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if name.ends_with(".log") {
                out.insert(path);
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
pub(crate) fn discover_default_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    discover_default_node_event_log_sources_impl(root)
}

#[cfg(not(test))]
pub(super) fn discover_default_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    discover_default_node_event_log_sources_impl(root)
}

fn load_node_event_log_sources_impl(root: &Path) -> Vec<PathBuf> {
    let mut sources = BTreeSet::<PathBuf>::new();

    if let Some(manifest_path) = normalized_path_from_env(NODE_EVENT_LOG_MANIFEST_ENV) {
        if let Ok(raw) = fs::read_to_string(&manifest_path) {
            let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
            for line in raw.lines() {
                let Some(normalized) = normalize_node_event_log_source_entry(line) else {
                    continue;
                };
                let path = PathBuf::from(normalized);
                let resolved = if path.is_absolute() {
                    normalize_lexical_path(path)
                } else {
                    normalize_lexical_path(manifest_dir.join(path))
                };
                sources.insert(resolved);
            }
        }
    }

    if let Ok(raw) = std::env::var(NODE_EVENT_LOG_SOURCES_ENV) {
        for path in parse_node_event_log_sources_list(&raw) {
            let normalized = normalize_wrapped_env_value(&path.to_string_lossy());
            if normalized.is_empty() || normalized.starts_with('#') {
                continue;
            }
            let path = PathBuf::from(normalized);
            let resolved = if path.is_absolute() {
                normalize_lexical_path(path)
            } else {
                normalize_lexical_path(root.join(path))
            };
            sources.insert(resolved);
        }
    }

    if sources.is_empty() {
        return discover_default_node_event_log_sources(root);
    }

    sources.into_iter().collect()
}

#[cfg(test)]
pub(crate) fn load_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    load_node_event_log_sources_impl(root)
}

#[cfg(not(test))]
pub(super) fn load_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    load_node_event_log_sources_impl(root)
}

pub(super) fn node_event_log_candidates(root: &Path) -> Vec<PathBuf> {
    load_node_event_log_sources(root)
}

#[cfg(test)]
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
fn lock_env<'a>() -> MutexGuard<'a, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
fn unique_tmp_path(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_node_event_log_sources_unwraps_quoted_env_entries_for_historical_replay() {
        let _guard = lock_env();
        let root = unique_tmp_path("trnm-rpc-node-event-sources-quoted-env");
        fs::create_dir_all(&root).expect("create root dir");

        let shared_log = root.join("shared.log");
        fs::write(&shared_log, "").expect("write shared log");

        let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
        let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
        unsafe {
            std::env::set_var(
                NODE_EVENT_LOG_SOURCES_ENV,
                "  \"shared.log\" ; `./shared.log`  ",
            );
            std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV);
        }

        let got = load_node_event_log_sources(&root);

        match prev_sources {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
        }
        match prev_manifest {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
        }

        assert_eq!(
            got,
            vec![shared_log],
            "quoted historical replay env entries should resolve to canonical log sources"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_node_event_log_sources_deduplicates_manifest_and_env_entries_after_lexical_normalization(
    ) {
        let _guard = lock_env();
        let root = unique_tmp_path("trnm-rpc-node-event-sources-manifest-env-dedupe");
        let history_dir = root.join("history");
        fs::create_dir_all(&history_dir).expect("create history dir");

        let shared_log = root.join("shared.log");
        let manifest = history_dir.join("sources.txt");
        fs::write(&shared_log, "").expect("write shared log");
        fs::write(&manifest, "../shared.log\n").expect("write manifest");

        let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
        let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
        unsafe {
            std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, "./shared.log");
            std::env::set_var(
                NODE_EVENT_LOG_MANIFEST_ENV,
                manifest.to_string_lossy().to_string(),
            );
        }

        let got = load_node_event_log_sources(&root);

        match prev_sources {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
        }
        match prev_manifest {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
        }

        assert_eq!(
            got,
            vec![shared_log],
            "historical replay sources should dedupe across manifest/env lexical path variants"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_node_event_log_sources_ignores_wrapped_comment_manifest_entries() {
        let _guard = lock_env();
        let root = unique_tmp_path("trnm-rpc-node-event-sources-comment-manifest");
        let archive_dir = root.join("archive");
        let manifest_dir = root.join("cfg/history");
        fs::create_dir_all(&archive_dir).expect("create archive dir");
        fs::create_dir_all(&manifest_dir).expect("create manifest dir");

        let archived_log = archive_dir.join("node4.log");
        let manifest = manifest_dir.join("sources.txt");
        fs::write(&archived_log, "").expect("write archived log");
        fs::write(
            &manifest,
            "\"# ignored wrapped comment\"\n../../archive/node4.log\n",
        )
        .expect("write manifest");

        let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
        let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
        unsafe {
            std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV);
            std::env::set_var(
                NODE_EVENT_LOG_MANIFEST_ENV,
                manifest.to_string_lossy().to_string(),
            );
        }

        let got = load_node_event_log_sources(&root);

        match prev_sources {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
        }
        match prev_manifest {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
        }

        assert_eq!(
            got,
            vec![archive_dir.join("node4.log")],
            "wrapped comment manifest entries should not create bogus historical replay paths"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_node_event_log_sources_ignores_inline_manifest_comments_after_wrapped_paths() {
        let _guard = lock_env();
        let root = unique_tmp_path("trnm-rpc-node-event-sources-inline-comment-manifest");
        let archive_dir = root.join("archive");
        let manifest_dir = root.join("cfg/history");
        fs::create_dir_all(&archive_dir).expect("create archive dir");
        fs::create_dir_all(&manifest_dir).expect("create manifest dir");

        let archived_log = archive_dir.join("node4.log");
        let manifest = manifest_dir.join("sources.txt");
        fs::write(&archived_log, "").expect("write archived log");
        fs::write(
            &manifest,
            "\"../../archive/node4.log\" # operator note\n",
        )
        .expect("write manifest");

        let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
        let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
        unsafe {
            std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV);
            std::env::set_var(
                NODE_EVENT_LOG_MANIFEST_ENV,
                manifest.to_string_lossy().to_string(),
            );
        }

        let got = load_node_event_log_sources(&root);

        match prev_sources {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
        }
        match prev_manifest {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
        }

        assert_eq!(
            got,
            vec![archive_dir.join("node4.log")],
            "inline manifest comments should not corrupt wrapped historical replay paths"
        );

        let _ = fs::remove_dir_all(root);
    }
}
