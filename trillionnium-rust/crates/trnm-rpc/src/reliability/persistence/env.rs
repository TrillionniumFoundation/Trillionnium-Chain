#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliabilityStoreMode {
    Sqlite,
    Memory,
}

impl ReliabilityStoreMode {
    pub fn from_env() -> Self {
        let mode = std::env::var("RELIABILITY_STORE")
            .ok()
            .and_then(|raw| normalized_env_path(&raw).map(|v| v.to_ascii_lowercase()))
            .unwrap_or_else(|| "sqlite".to_string());

        match mode.as_str() {
            "memory" => Self::Memory,
            _ => Self::Sqlite,
        }
    }
}

fn normalized_env_path(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let starts_with_quote = trimmed.starts_with('"') || trimmed.starts_with('\'');
    let ends_with_quote = trimmed.ends_with('"') || trimmed.ends_with('\'');

    if trimmed.len() == 1 && (starts_with_quote || ends_with_quote) {
        return None;
    }

    // Treat mismatched leading/trailing quote wrappers as noisy malformed input.
    if starts_with_quote ^ ends_with_quote {
        return None;
    }
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0];
        let last = trimmed.as_bytes()[trimmed.len() - 1];
        let mixed_quote_pair = (first == b'\'' && last == b'"') || (first == b'"' && last == b'\'');
        if mixed_quote_pair {
            return None;
        }
    }

    let quoted = trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')));

    let stripped = if quoted {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
    .trim();

    if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    }
}

pub fn default_reliability_db_path() -> PathBuf {
    if let Ok(path) = std::env::var("RELIABILITY_DB_PATH") {
        if let Some(normalized) = normalized_env_path(&path) {
            return PathBuf::from(normalized);
        }
    }

    if let Ok(state_directory) = std::env::var("STATE_DIRECTORY") {
        if let Some(normalized) = normalized_env_path(&state_directory) {
            return PathBuf::from(normalized).join("reliability.sqlite");
        }
    }

    if let Ok(xdg_state_home) = std::env::var("XDG_STATE_HOME") {
        if let Some(normalized) = normalized_env_path(&xdg_state_home) {
            return PathBuf::from(normalized)
                .join("trillionnium")
                .join("reliability.sqlite");
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        if let Some(normalized) = normalized_env_path(&home) {
            return PathBuf::from(normalized)
                .join(".trillionnium")
                .join("reliability.sqlite");
        }
    }

    PathBuf::from("run/reliability/reliability.sqlite")
}
