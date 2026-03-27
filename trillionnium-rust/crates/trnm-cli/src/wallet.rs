use super::*;

pub(crate) fn default_wallet_store() -> PathBuf {
    if let Ok(p) = std::env::var("TRNM_WALLET_STORE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".trnm").join("wallets")
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
                '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
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

    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\'])
        || has_hidden_or_whitespace
    {
        bail!(
            "invalid wallet name '{}': use a simple local name without path separators",
            name
        );
    }
    Ok(())
}

pub(crate) fn ensure_hex_32_bytes(s: &str) -> Result<String> {
    let x = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
        .to_lowercase();
    if x.len() != 64 {
        bail!("private key hex must be 32 bytes (64 hex chars)");
    }
    let _ = hex::decode(&x).map_err(|e| anyhow!("invalid private_key_hex: {e}"))?;
    Ok(x)
}

pub(crate) fn write_key(store: &Path, name: &str, priv_hex: &str) -> Result<PathBuf> {
    ensure_wallet_name(name)?;
    fs::create_dir_all(store)?;
    let f = wallet_file(store, name);
    if f.exists() {
        bail!(
            "wallet '{}' already exists at {}; refusing to overwrite existing key",
            name,
            f.display()
        );
    }
    fs::write(&f, format!("{}\n", priv_hex))?;
    Ok(f)
}

pub(crate) fn read_key(store: &Path, name: &str) -> Result<String> {
    ensure_wallet_name(name)?;
    let f = wallet_file(store, name);
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
