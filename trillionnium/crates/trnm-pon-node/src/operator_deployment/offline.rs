//! Explicit offline I/O. The UID check uses the process effective identity, never
//! an environment variable. No secret text is returned or logged by this API.
use super::{ActorApproval, BootstrapTemplate, OperatorDeploymentSpec};
use crate::{ensure, Result};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
#[cfg(unix)]
fn read_file(path: &Path, limit: u64, secret: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "ACTOR_FILE")?;
    let meta = file.metadata().map_err(|_| "ACTOR_FILE")?;
    ensure(
        meta.file_type().is_file() && meta.nlink() == 1 && meta.len() <= limit,
        "ACTOR_FILE",
    )?;
    let mode = meta.permissions().mode();
    if secret {
        ensure(
            secret_owner_mode(mode, meta.uid(), rustix::process::geteuid().as_raw()),
            "ACTOR_SECRET_OWNER_MODE",
        )?;
    } else {
        ensure(mode & 0o022 == 0, "ACTOR_FILE_MODE")?;
    }
    let mut raw = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "ACTOR_FILE")?;
    ensure(raw.len() as u64 <= limit, "ACTOR_FILE_LENGTH")?;
    Ok(raw)
}
#[cfg(not(unix))]
fn read_file(_path: &Path, _limit: u64, _secret: bool) -> Result<Vec<u8>> {
    Err("ACTOR_OFFLINE_PLATFORM_UNSUPPORTED".into())
}
pub fn read_public(path: &Path, limit: u64) -> Result<Vec<u8>> {
    read_file(path, limit, false)
}
pub fn sign_approval_from_file(
    spec: &OperatorDeploymentSpec,
    template: &BootstrapTemplate,
    model: &[u8],
    input: &[u8],
    role: &str,
    path: &Path,
) -> Result<ActorApproval> {
    let expected = super::prepare(spec, model, input)?;
    ensure(*template == expected, "ACTOR_TEMPLATE")?;
    let raw = read_file(path, 65, true)?;
    let text = std::str::from_utf8(&raw).map_err(|_| "ACTOR_SECRET_ENCODING")?;
    let secret = text.strip_suffix('\n').unwrap_or(text);
    ensure(secret.len() == 64, "ACTOR_SECRET_LENGTH")?;
    let key = trnm_crypto_primitives::signing_key_from_hex(secret)
        .map_err(|_| "ACTOR_SECRET_ENCODING")?;
    let (public, message) = match role {
        "source" => (&expected.source_public, &expected.source_message),
        "requester" => (&expected.requester_public, &expected.requester_message),
        _ => return Err("ACTOR_ROLE".into()),
    };
    ensure(
        trnm_crypto_primitives::public_key_hex(&key) == *public,
        "ACTOR_SIGNER_PIN",
    )?;
    let message = super::bytes(message, 32)?;
    super::approval(
        &expected,
        role,
        trnm_crypto_primitives::sign_hex(&key, &message),
    )
}
#[cfg(unix)]
pub fn write_new_public(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
pub fn write_new_public(_path: &Path, _raw: &[u8]) -> Result<()> {
    Err("ACTOR_OFFLINE_PLATFORM_UNSUPPORTED".into())
}

#[cfg(unix)]
fn secret_owner_mode(mode: u32, owner: u32, effective: u32) -> bool {
    mode & 0o7777 == 0o600 && owner == effective
}
#[cfg(all(test, unix))]
mod tests {
    use super::secret_owner_mode;
    #[test]
    fn actual_effective_uid_is_required_independently_of_mode() {
        let uid = rustix::process::geteuid().as_raw();
        assert!(secret_owner_mode(0o100600, uid, uid));
        assert!(!secret_owner_mode(0o100600, uid.wrapping_add(1), uid));
        assert!(!secret_owner_mode(0o100640, uid, uid));
        assert!(!secret_owner_mode(0o104600, uid, uid));
    }
}
/// Explicit offline digest signing for finite operator fixtures. The caller owns
/// the native message construction; this proves possession, not ledger permission.
/// The actual strict public key must match the supplied pin; no key is returned.
pub fn sign_pinned_digest_from_file(
    public: &str,
    digest: [u8; 32],
    path: &Path,
) -> Result<[u8; 64]> {
    trnm_mvcc_fee::deployment_actors::operator_key(public)?;
    let raw = read_file(path, 65, true)?;
    let text = std::str::from_utf8(&raw).map_err(|_| "ACTOR_SECRET_ENCODING")?;
    let secret = text.strip_suffix('\n').unwrap_or(text);
    ensure(secret.len() == 64, "ACTOR_SECRET_LENGTH")?;
    let key = trnm_crypto_primitives::signing_key_from_hex(secret)
        .map_err(|_| "ACTOR_SECRET_ENCODING")?;
    ensure(
        trnm_crypto_primitives::public_key_hex(&key) == public,
        "ACTOR_SIGNER_PIN",
    )?;
    hex::decode(trnm_crypto_primitives::sign_hex(&key, &digest))
        .map_err(|_| "ACTOR_SIGNATURE")?
        .try_into()
        .map_err(|_| "ACTOR_SIGNATURE".into())
}
/// Public identity of an explicitly opened offline signer. The bounded owner check
/// precedes decoding; this does not return a secret or grant an actor role.
pub fn owned_signer_public(path: &Path) -> Result<String> {
    let raw = read_file(path, 65, true)?;
    let text = std::str::from_utf8(&raw).map_err(|_| "ACTOR_SECRET_ENCODING")?;
    let secret = text.strip_suffix('\n').unwrap_or(text);
    ensure(secret.len() == 64, "ACTOR_SECRET_LENGTH")?;
    let key = trnm_crypto_primitives::signing_key_from_hex(secret)
        .map_err(|_| "ACTOR_SECRET_ENCODING")?;
    let public = trnm_crypto_primitives::public_key_hex(&key);
    trnm_mvcc_fee::deployment_actors::operator_key(&public)?;
    Ok(public)
}
