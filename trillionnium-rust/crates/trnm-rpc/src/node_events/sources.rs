use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use crate::envpaths::normalized_path_from_env;
use crate::{NODE_EVENT_LOG_MANIFEST_ENV, NODE_EVENT_LOG_SOURCES_ENV};

pub(super) fn parse_node_event_log_sources_list(raw: &str) -> Vec<PathBuf> {
    raw.split(|c: char| c == ',' || c == ';' || c == '\n')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        })
        .collect()
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
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let path = PathBuf::from(trimmed);
                let resolved = if path.is_absolute() {
                    path
                } else {
                    manifest_dir.join(path)
                };
                sources.insert(resolved);
            }
        }
    }

    if let Ok(raw) = std::env::var(NODE_EVENT_LOG_SOURCES_ENV) {
        for path in parse_node_event_log_sources_list(&raw) {
            let resolved = if path.is_absolute() { path } else { root.join(path) };
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
