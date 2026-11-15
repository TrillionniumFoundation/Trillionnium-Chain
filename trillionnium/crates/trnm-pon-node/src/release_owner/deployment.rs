//! Independent OS-provisioned root. No CLI, environment, or handoff root selection.
use super::frontier::{invalid, Digest32, Result};
use rustix::fs::{openat, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const PROVISIONED: &str = "/etc/trillionnium/m15-operator-deployment-v1.json";

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Deployment {
    pub schema_version: u32,
    pub profile: String,
    pub runtime_uid: u32,
    pub namespace: Digest32,
    pub owner_directory: PathBuf,
    pub trust_configuration: PathBuf,
    pub trust_configuration_sha256: Digest32,
}

fn directory(file: &File, owner: u32) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != owner || m.mode() & 0o7022 != 0 {
        return Err(invalid("M15 deployment ancestor is not root-protected"));
    }
    Ok(())
}

fn read_from(path: &Path, provisioner_uid: u32, runtime_uid: u32) -> Result<Deployment> {
    if !path.is_absolute() || runtime_uid == 0 {
        return Err(invalid(
            "M15 requires an independently provisioned non-root runtime",
        ));
    }
    let mut parent = File::open("/")?;
    directory(&parent, provisioner_uid)?;
    let mut parts = path.components().peekable();
    if parts.next() != Some(Component::RootDir) {
        return Err(invalid("M15 deployment root"));
    }
    let name = loop {
        let Some(Component::Normal(name)) = parts.next() else {
            return Err(invalid("M15 deployment path"));
        };
        if parts.peek().is_none() {
            break name;
        }
        parent = File::from(openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        directory(&parent, provisioner_uid)?;
    };
    let mut file = File::from(openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = file.metadata()?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if !before.is_file()
        || before.uid() != provisioner_uid
        || before.nlink() != 1
        || before.mode() & 0o7022 != 0
        || before.len() == 0
        || before.len() > 65536
    {
        return Err(invalid("M15 deployment file ownership/mode/bound"));
    }
    let mut raw = Vec::new();
    Read::by_ref(&mut file).take(65537).read_to_end(&mut raw)?;
    let named = File::from(openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if raw.len() != before.len() as usize
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&named.metadata()?)
    {
        return Err(invalid("M15 deployment changed during read"));
    }
    let value: Deployment = super::codec::decode(&raw, 65536)?;
    if value.schema_version != 1
        || value.profile != "trnm-m15-operator-deployment-v1"
        || value.runtime_uid != runtime_uid
        || value.namespace == [0; 32]
        || value.trust_configuration_sha256 == [0; 32]
        || !value.owner_directory.is_absolute()
        || !value.trust_configuration.is_absolute()
    {
        return Err(invalid("M15 complete deployment binding"));
    }
    Ok(value)
}

impl Deployment {
    pub fn load() -> Result<Self> {
        read_from(
            Path::new(PROVISIONED),
            0,
            rustix::process::geteuid().as_raw(),
        )
    }

    pub fn connect(&self) -> Result<super::trust_client::SignedAuthorityClient> {
        let client = super::trust_client::SignedAuthorityClient::from_protected(
            &self.trust_configuration,
            self.trust_configuration_sha256,
        )?;
        if client.config.namespace != self.namespace {
            return Err(invalid("M15 deployment/client namespace mismatch"));
        }
        Ok(client)
    }
    pub fn revalidate(&self) -> Result<()> {
        if Self::load()? != *self {
            return Err(invalid("M15 deployment changed; fresh owner required"));
        }
        Ok(())
    }
}
