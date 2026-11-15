//! Root-owned fixed-path service provisioning; no environment/CLI trust override.
use super::frontier::{invalid, Result};
use rustix::fs::{openat, Mode, OFlags};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

fn protected_directory(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7022 != 0 {
        return Err(invalid(
            "M15 service provisioning ancestor is not root protected",
        ));
    }
    Ok(())
}
pub(super) fn read(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(invalid("M15 service provisioning path"));
    }
    let mut directory = File::open("/")?;
    protected_directory(&directory)?;
    let mut parts = path.components().peekable();
    if parts.next() != Some(Component::RootDir) {
        return Err(invalid("M15 service provisioning root"));
    }
    let name = loop {
        let Some(Component::Normal(name)) = parts.next() else {
            return Err(invalid("M15 service provisioning component"));
        };
        if parts.peek().is_none() {
            break name;
        }
        directory = File::from(openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        protected_directory(&directory)?;
    };
    let mut file = File::from(openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = super::sealed::identity(&file)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o7022 != 0
        || meta.len() == 0
        || meta.len() > 65536
    {
        return Err(invalid("M15 service provisioning file"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)?;
    let named = File::from(openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if bytes.len() as u64 != before.size
        || before != super::sealed::identity(&file)?
        || before != super::sealed::identity(&named)?
        || named.metadata()?.nlink() != 1
    {
        return Err(invalid("M15 service provisioning changed"));
    }
    Ok(bytes)
}
