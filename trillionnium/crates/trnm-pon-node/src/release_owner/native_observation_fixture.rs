//! Native-suite observations and a deterministic post-sealing catalog fault.
//! These are fixture operations, never production authority or a root override.
use super::frontier::{invalid, Digest32, Result};
use super::native_build_fixture::bounded;
use super::native_isolation_fixture::{self as isolation, RUNTIME_UID};
use super::native_provision_fixture::OWNER;
use super::records::{Index, Record};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub(super) fn index() -> Result<Index> {
    let value: Index = super::codec::decode(
        &bounded(
            &PathBuf::from(OWNER).join("index.json"),
            super::frontier::MAX_INDEX_BYTES as u64,
        )?,
        super::frontier::MAX_INDEX_BYTES,
    )?;
    if value.records.len() > super::records::MAX_RECORDS {
        return Err(invalid("native observed index record bound"));
    }
    Ok(value)
}
pub(super) fn record(digest: Digest32) -> Result<Record> {
    let value: Record = super::codec::decode(
        &bounded(
            &PathBuf::from(OWNER).join(format!("proof-{}.json", hex::encode(digest))),
            super::records::MAX_RECORD_BYTES as u64,
        )?,
        super::records::MAX_RECORD_BYTES,
    )?;
    if value.digest()? != digest {
        return Err(invalid("native observed proof digest"));
    }
    Ok(value)
}
pub(super) fn records() -> Result<Vec<(Digest32, Record)>> {
    index()?
        .records
        .into_iter()
        .map(|digest| Ok((digest, record(digest)?)))
        .collect()
}
pub(super) fn image(pid: u32, expected: Digest32, size: u64) -> Result<()> {
    // An observation of the actual child after startup. The consumer itself
    // independently checked its sealed image before claiming/opening Node.
    let file = File::open(format!("/proc/{pid}/exe"))?;
    let before = super::sealed::identity(&file)?;
    let seals = rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::EXEC;
    if !file.metadata()?.is_file()
        || before.size != size
        || before.uid != RUNTIME_UID
        || !rustix::fs::fcntl_get_seals(&file)?.contains(seals)
        || super::sealed::digest(&file, size)? != expected
        || before != super::sealed::identity(&file)?
    {
        return Err(invalid("native actual same-process sealed image"));
    }
    super::elf::verify(&file, size, super::elf::platform()?)
}

#[derive(Default)]
struct Cut {
    armed: Option<(Digest32, u64)>,
    witness: Option<serde_json::Value>,
}
#[derive(Clone, Default)]
pub(super) struct ArtifactCut(Arc<Mutex<Cut>>);
impl ArtifactCut {
    pub fn arm(&self, expected: Digest32, size: u64) -> Result<()> {
        let mut cut = self.0.lock().map_err(|_| invalid("native cut lock"))?;
        if cut.armed.is_some() || cut.witness.is_some() || expected == [0; 32] || size == 0 {
            return Err(invalid("native catalog fault is one-shot"));
        }
        cut.armed = Some((expected, size));
        Ok(())
    }
    pub fn after_owner_clock_request(&self) -> Result<()> {
        let mut cut = self.0.lock().map_err(|_| invalid("native cut lock"))?;
        let Some((expected, size)) = cut.armed else {
            return Ok(());
        };
        let current = index()?;
        let Some(digest) = current.records.last().copied() else {
            return Ok(());
        };
        let Record::LaunchAttempt(attempt) = record(digest)? else {
            return Ok(());
        };
        if attempt.contract.program_sha256 != expected || attempt.contract.program_size != size {
            return Err(invalid(
                "native fault actual committed attempt/image binding",
            ));
        }
        // Production launch copied, hashed, sealed and authenticated this image
        // before appending this real attempt. This next Clock request is before
        // exec. Change both the source inode and its named slot, without changing
        // any time sample, signature, owner index, policy or production hook.
        let path = PathBuf::from(OWNER).join(format!("artifact-{}.elf", hex::encode(expected)));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)?;
        let original = super::sealed::identity(&file)?;
        let mut first = [0u8; 1];
        file.read_exact_at(&mut first, 0)?;
        if !file.metadata()?.is_file()
            || file.metadata()?.nlink() != 1
            || original.uid != RUNTIME_UID
            || original.size != size
            || first != [0x7f]
        {
            return Err(invalid("native fault original installed static ELF"));
        }
        file.write_all_at(&[0], 0)?;
        file.sync_all()?;
        let modified = super::sealed::identity(&file)?;
        let retained = PathBuf::from(OWNER).join("retained-mutated-artifact.elf");
        fs::rename(&path, &retained)?;
        isolation::write(
            &path,
            b"intentionally invalid replacement; must never become executable\n",
            RUNTIME_UID,
            0o600,
        )?;
        File::open(OWNER)?.sync_all()?;
        let replacement = super::sealed::identity(&File::open(&path)?)?;
        let named_retained = super::sealed::identity(&File::open(&retained)?)?;
        if original.device != modified.device
            || original.inode != modified.inode
            || modified.device != named_retained.device
            || modified.inode != named_retained.inode
            || (replacement.device, replacement.inode) == (original.device, original.inode)
        {
            return Err(invalid("native physical rewrite/replacement observations"));
        }
        cut.witness = Some(
            serde_json::json!({"schema":"trnm-m15-post-sealing-catalog-fault-v1",
            "attempt":hex::encode(digest),"program_sha256":hex::encode(expected),
            "before":original,"in_place":modified,"renamed_original":named_retained,
            "replacement":replacement,"retained_path":retained,"replacement_path":path,
            "first_byte_before":first[0],"first_byte_after":0,"production_qualified":false}),
        );
        cut.armed = None;
        Ok(())
    }
    pub fn require_fired(&self) -> Result<serde_json::Value> {
        let cut = self.0.lock().map_err(|_| invalid("native cut lock"))?;
        let witness = cut
            .witness
            .clone()
            .ok_or_else(|| invalid("native post-sealing fault did not run"))?;
        if cut.armed.is_some() {
            return Err(invalid("native fault remains armed"));
        }
        Ok(witness)
    }
    pub fn retain_witness(&self) -> Result<()> {
        isolation::write(
            Path::new("/m15/evidence/catalog-fault.json"),
            &serde_json::to_vec(&self.require_fired()?).map_err(std::io::Error::other)?,
            0,
            0o600,
        )
    }
}
