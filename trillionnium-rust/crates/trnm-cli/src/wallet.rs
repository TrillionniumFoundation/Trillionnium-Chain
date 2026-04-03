use super::*;

fn is_hidden_env_wrapper(c: char) -> bool {
    c.is_whitespace()
        || c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2060}'
                | '\u{FEFF}'
                | '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
        )
}

fn is_single_sided_env_quote(c: char) -> bool {
    matches!(
        c,
        '"'
            | '\''
            | '`'
            | '“'
            | '”'
            | '‘'
            | '’'
            | '«'
            | '»'
            | '‹'
            | '›'
            | '「'
            | '」'
            | '『'
            | '』'
            | '《'
            | '》'
            | '〈'
            | '〉'
            | '｢'
            | '｣'
            | '（'
            | '）'
            | '('
            | ')'
            | '［'
            | '］'
            | '['
            | ']'
            | '｛'
            | '｝'
            | '{'
            | '}'
            | '<'
            | '>'
            | '＜'
            | '＞'
            | '【'
            | '】'
            | '〔'
            | '〕'
            | '〖'
            | '〗'
            | '〘'
            | '〙'
            | '〚'
            | '〛'
            | '〝'
            | '〞'
            | '〟'
    )
}

fn is_suspicious_path_wrapper(c: char) -> bool {
    is_single_sided_env_quote(c)
}

pub(crate) fn normalize_wallet_store_env(raw: &str) -> Option<&str> {
    let mut normalized = raw.trim_matches(is_hidden_env_wrapper);
    loop {
        let Some(first) = normalized.chars().next() else {
            return None;
        };
        let Some(last) = normalized.chars().last() else {
            return None;
        };
        let wrapped_by_quotes = matches!(
            (Some(first), Some(last)),
            (Some('"'), Some('"'))
                | (Some('\''), Some('\''))
                | (Some('`'), Some('`'))
                | (Some('“'), Some('”'))
                | (Some('‘'), Some('’'))
                | (Some('«'), Some('»'))
                | (Some('‹'), Some('›'))
                | (Some('「'), Some('」'))
                | (Some('『'), Some('』'))
                | (Some('《'), Some('》'))
                | (Some('〈'), Some('〉'))
                | (Some('｢'), Some('｣'))
                | (Some('（'), Some('）'))
                | (Some('［'), Some('］'))
                | (Some('｛'), Some('｝'))
                | (Some('<'), Some('>'))
                | (Some('＜'), Some('＞'))
                | (Some('【'), Some('】'))
                | (Some('〔'), Some('〕'))
                | (Some('〖'), Some('〗'))
                | (Some('〘'), Some('〙'))
                | (Some('〚'), Some('〛'))
                | (Some('〝'), Some('〞'))
                | (Some('〟'), Some('〟'))
        );
        if wrapped_by_quotes {
            normalized = normalized[first.len_utf8()..normalized.len() - last.len_utf8()]
                .trim_matches(is_hidden_env_wrapper);
            continue;
        }

        let trimmed_single_sided = normalized
            .trim_start_matches(is_single_sided_env_quote)
            .trim_end_matches(is_single_sided_env_quote)
            .trim_matches(is_hidden_env_wrapper);
        if trimmed_single_sided.len() == normalized.len() {
            break;
        }
        normalized = trimmed_single_sided;
    }
    if normalized.is_empty() || normalized.chars().any(is_hidden_env_wrapper) {
        return None;
    }
    Some(normalized)
}

fn wallet_store_path_is_safe(path: &Path) -> bool {
    use std::path::Component;

    let rendered = path.to_string_lossy();
    path.is_absolute()
        && path.parent().is_some()
        && !rendered.contains("//")
        && rendered.chars().all(|c| {
            !c.is_whitespace()
                && !c.is_control()
                && !is_suspicious_path_wrapper(c)
                && !matches!(
                    c,
                    '\u{061C}'
                        | '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{2060}'
                        | '\u{FEFF}'
                        | '\u{202A}'
                        | '\u{202B}'
                        | '\u{202C}'
                        | '\u{202D}'
                        | '\u{202E}'
                        | '\u{2066}'
                        | '\u{2067}'
                        | '\u{2068}'
                        | '\u{2069}'
                )
        })
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn ensure_wallet_store_path_is_safe(store: &Path) -> Result<()> {
    if !wallet_store_path_is_safe(store) {
        bail!(
            "wallet store '{}' must be an absolute normalized path without '.' or '..' segments",
            store.display()
        );
    }
    Ok(())
}

fn ensure_wallet_store_ancestors_not_symlink(store: &Path) -> Result<()> {
    for ancestor in store.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "wallet store '{}' traverses symlinked ancestor '{}'; refusing non-canonical keystore path",
                    store.display(),
                    ancestor.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                bail!(
                    "failed to inspect wallet store ancestor '{}' for symlink safety: {err}",
                    ancestor.display()
                );
            }
        }
    }
    Ok(())
}

fn wallet_store_ancestors_are_symlink_free(store: &Path) -> bool {
    store
        .ancestors()
        .skip(1)
        .all(|ancestor| match fs::symlink_metadata(ancestor) {
            Ok(meta) => !meta.file_type().is_symlink(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        })
}

pub(crate) fn default_wallet_store() -> PathBuf {
    if let Ok(p) = std::env::var("TRNM_WALLET_STORE") {
        if let Some(normalized) = normalize_wallet_store_env(&p) {
            let candidate = PathBuf::from(normalized);
            if wallet_store_path_is_safe(&candidate)
                && wallet_store_ancestors_are_symlink_free(&candidate)
            {
                return candidate;
            }
        }
    }

    let home_root = std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .filter(|path| wallet_store_path_is_safe(path) && wallet_store_ancestors_are_symlink_free(path))
        .or_else(|| {
            std::env::current_dir().ok().filter(|path| {
                wallet_store_path_is_safe(path) && wallet_store_ancestors_are_symlink_free(path)
            })
        })
        .unwrap_or_else(|| PathBuf::from("/"));

    home_root.join(".trnm").join("wallets")
}

pub(crate) fn wallet_file(store: &Path, name: &str) -> PathBuf {
    store.join(format!("{}.key", name))
}

pub(crate) fn ensure_wallet_name(name: &str) -> Result<()> {
    let has_hidden_or_whitespace = name.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '\u{061C}'
                    | '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{2060}'
                    | '\u{FEFF}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202C}'
                    | '\u{202D}'
                    | '\u{202E}'
                    | '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
            )
    });
    let uppercase = name.to_ascii_uppercase();
    let is_windows_reserved_device = matches!(
        uppercase.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );

    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.ends_with('.')
        || name.starts_with('-')
        || name.starts_with(['‐', '‑', '‒', '–', '—', '―', '−', '﹣', '－'])
        || name.contains(['/', '\\', ':', '=', '|', '&', '$', '*', '?', '!'])
        || name.contains(['‐', '‑', '‒', '–', '—', '―', '−', '﹣', '－'])
        || name.contains(['：', '＝', '｜', '＆', '？', '，', '；', '！'])
        || name.contains(['∕', '⁄', '／', '＼', '⧵', '⟋', '⟍'])
        || name.contains(['.', '．', '。', '｡', '﹒', '․'])
        || name.contains(['"', '\'', '`', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';'])
        || name.contains([
            '“', '”', '‘', '’', '«', '»', '‹', '›', '「', '」', '『', '』', '《', '》',
            '〈', '〉', '｢', '｣', '（', '）', '［', '］', '｛', '｝', '＜', '＞', '【', '】',
            '〔', '〕', '〖', '〗', '〘', '〙', '〚', '〛', '〝', '〞', '〟',
        ])
        || has_hidden_or_whitespace
        || is_windows_reserved_device
    {
        bail!(
            "invalid wallet name '{}': use a simple local name without path separators or reserved device names",
            name
        );
    }
    Ok(())
}

pub(crate) fn ensure_hex_32_bytes(s: &str) -> Result<String> {
    let cleaned = s
        .trim_matches(|c: char| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '"'
                        | '\''
                        | '`'
                        | '“'
                        | '”'
                        | '‘'
                        | '’'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | ','
                        | ';'
                        | '.'
                        | '!'
                        | '?'
                        | '（'
                        | '）'
                        | '［'
                        | '］'
                        | '｛'
                        | '｝'
                        | '＜'
                        | '＞'
                        | '「'
                        | '」'
                        | '『'
                        | '』'
                        | '《'
                        | '》'
                        | '〈'
                        | '〉'
                        | '｢'
                        | '｣'
                        | '«'
                        | '»'
                        | '‹'
                        | '›'
                        | '【'
                        | '】'
                        | '〔'
                        | '〕'
                        | '〖'
                        | '〗'
                        | '〘'
                        | '〙'
                        | '〚'
                        | '〛'
                        | '〝'
                        | '〞'
                        | '〟'
                        | '｢'
                        | '｣'
                        | '，'
                        | '；'
                        | '：'
                        | '！'
                        | '？'
                        | '。'
                        | '｡'
                        | '．'
                        | '﹒'
                        | '․'
                )
                || matches!(
                    c,
                    '\u{061C}'
                        | '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{2060}'
                        | '\u{FEFF}'
                        | '\u{202A}'
                        | '\u{202B}'
                        | '\u{202C}'
                        | '\u{202D}'
                        | '\u{202E}'
                        | '\u{2066}'
                        | '\u{2067}'
                        | '\u{2068}'
                        | '\u{2069}'
                )
        })
        .trim();
    let x = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned)
        .to_lowercase();
    if x.len() != 64 {
        bail!("private key hex must be 32 bytes (64 hex chars)");
    }
    let _ = hex::decode(&x).map_err(|e| anyhow!("invalid private_key_hex: {e}"))?;
    Ok(x)
}

#[cfg(unix)]
fn ensure_owner_only_permissions(meta: &fs::Metadata, path: &Path, kind: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} '{}' has insecure permissions {:o}; expected owner-only access",
            kind,
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only_permissions(_meta: &fs::Metadata, _path: &Path, _kind: &str) -> Result<()> {
    Ok(())
}

pub(crate) fn write_key(store: &Path, name: &str, priv_hex: &str) -> Result<PathBuf> {
    ensure_wallet_name(name)?;
    let normalized_priv_hex = ensure_hex_32_bytes(priv_hex)?;
    ensure_wallet_store_path_is_safe(store)?;
    ensure_wallet_store_ancestors_not_symlink(store)?;
    if let Ok(meta) = fs::symlink_metadata(store) {
        if meta.file_type().is_symlink() {
            bail!(
                "wallet store '{}' is a symlink; refusing to write keys through non-regular wallet store path",
                store.display()
            );
        }
        if !meta.file_type().is_dir() {
            bail!(
                "wallet store '{}' is not a directory; refusing to write keys through non-regular wallet store path",
                store.display()
            );
        }
        ensure_owner_only_permissions(&meta, store, "wallet store")?;
    }
    fs::create_dir_all(store)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(store, fs::Permissions::from_mode(0o700))?;
    }
    let f = wallet_file(store, name);
    if fs::symlink_metadata(&f).is_ok() {
        bail!(
            "wallet '{}' already exists at {}; refusing to overwrite existing key",
            name,
            f.display()
        );
    }
    fs::write(&f, format!("{}\n", normalized_priv_hex))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

pub(crate) fn read_key(store: &Path, name: &str) -> Result<String> {
    ensure_wallet_name(name)?;
    ensure_wallet_store_path_is_safe(store)?;
    ensure_wallet_store_ancestors_not_symlink(store)?;
    let store_meta = fs::symlink_metadata(store)
        .map_err(|e| anyhow!("failed to inspect wallet store '{}': {e}", store.display()))?;
    if store_meta.file_type().is_symlink() {
        bail!(
            "wallet store '{}' is a symlink; refusing to read keys through non-regular wallet store path",
            store.display()
        );
    }
    if !store_meta.file_type().is_dir() {
        bail!(
            "wallet store '{}' is not a directory; refusing to read keys through non-regular wallet store path",
            store.display()
        );
    }
    ensure_owner_only_permissions(&store_meta, store, "wallet store")?;
    let f = wallet_file(store, name);
    let meta = fs::symlink_metadata(&f)
        .map_err(|e| anyhow!("failed to inspect wallet '{}' at {}: {e}", name, f.display()))?;
    if !meta.file_type().is_file() {
        bail!(
            "wallet '{}' at {} is not a regular file; refusing to follow non-regular wallet path",
            name,
            f.display()
        );
    }
    ensure_owner_only_permissions(&meta, &f, "wallet")?;
    let raw = fs::read_to_string(&f)
        .map_err(|e| anyhow!("failed to read wallet '{}' at {}: {e}", name, f.display()))?;
    ensure_hex_32_bytes(raw.trim())
}

pub(crate) fn derive_address_from_priv_hex(priv_hex: &str) -> Result<String> {
    let key = hex::decode(priv_hex)?;
    let key_bytes: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("private key hex must be 32 bytes (64 hex chars)"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let digest = Sha256::digest(signing_key.verifying_key().as_bytes());
    let addr_hex = hex::encode(&digest[..20]);
    Ok(format!("trnm1{}", addr_hex))
}

fn is_unsafe_sign_message_char(c: char) -> bool {
    (c.is_whitespace() && c != ' ')
        || c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2060}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

pub(crate) fn ensure_safe_sign_message(message: &str) -> Result<()> {
    if message.is_empty() {
        bail!("wallet sign message must not be empty");
    }
    if message.trim() != message {
        bail!(
            "wallet sign message contains leading or trailing whitespace; refusing ambiguous offline-signing output"
        );
    }
    if message.chars().any(is_unsafe_sign_message_char) {
        bail!(
            "wallet sign message contains control or bidi override characters; refusing unsafe offline-signing output"
        );
    }
    Ok(())
}

pub(crate) fn random_priv_hex() -> Result<String> {
    let mut b = [0u8; 32];
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(&mut b)?;
    Ok(hex::encode(b))
}

pub(crate) fn wallet_create(name: String, out: Option<PathBuf>) -> Result<()> {
    let store = out.unwrap_or_else(default_wallet_store);
    let priv_hex = random_priv_hex()?;
    let path = write_key(&store, &name, &priv_hex)?;
    let addr = derive_address_from_priv_hex(&priv_hex)?;
    println!("wallet_name={}", name);
    println!("wallet_path={}", path.display());
    println!("address={}", addr);
    println!("public_key_hint={}", sha256_hex(priv_hex.as_bytes()));
    Ok(())
}

pub(crate) fn resolve_address_for_query(
    address: Option<String>,
    name: Option<String>,
    store: Option<PathBuf>,
) -> Result<String> {
    if let Some(a) = address {
        return Ok(a);
    }
    let wallet_name = name.unwrap_or_else(|| "default".to_string());
    let s = store.unwrap_or_else(default_wallet_store);
    let priv_hex = read_key(&s, &wallet_name)?;
    derive_address_from_priv_hex(&priv_hex)
}
