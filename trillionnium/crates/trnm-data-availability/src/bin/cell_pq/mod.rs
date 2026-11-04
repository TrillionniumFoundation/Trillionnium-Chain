//! Bounded descriptor-based PQ key/public-file IO shared by the actual CLIs.
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_data_availability::cell::{CellErrorV1, CellResultV1};
use zeroize::Zeroizing;

pub fn read_regular<const N: usize>(path: &Path, private: bool) -> CellResultV1<[u8; N]> {
    let mut out = [0; N];
    read_into(path, private, &mut out)?;
    Ok(out)
}
fn read_into(path: &Path, private: bool, output: &mut [u8]) -> CellResultV1<()> {
    #[cfg(not(unix))]
    {
        let _ = (path, private, output);
        Err(CellErrorV1::Invalid("PQ file identity unsupported"))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.len() != output.len() as u64
            || meta.nlink() != 1
            || (private && meta.mode() & 0o077 != 0)
        {
            return Err(CellErrorV1::Invalid("PQ file length/type/mode/links"));
        }
        file.read_exact(output)?;
        let mut extra = [0];
        if file.read(&mut extra)? != 0 {
            return Err(CellErrorV1::Invalid("PQ file grew"));
        }
        Ok(())
    }
}
pub fn signing_key(path: &Path, expected_id: [u8; 32]) -> CellResultV1<PqNativeSigningKey> {
    let mut seed = Zeroizing::new([0; 32]);
    read_into(path, true, seed.as_mut())?;
    PqNativeSigningKey::from_owned_seed(seed, expected_id)
        .map_err(|_| CellErrorV1::Invalid("PQ seed does not match pinned key"))
}
pub fn public_spki(path: &Path) -> CellResultV1<[u8; 1974]> {
    let mut seed = Zeroizing::new([0; 32]);
    read_into(path, true, seed.as_mut())?;
    Ok(PqNativeSigningKey::public_spki_from_seed(&seed))
}
pub fn write_new(path: &Path, bytes: &[u8]) -> CellResultV1<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
