use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use super::*;

/// One bounded immutable file, with no second mutable progress or payment log.
/// Its independent commitment and catalog anchor must remain with the owner.
/// The same-privilege rollback of every owner and ledger is not prevented here.
pub struct CellRetainedShardPlanFileV1 {
    path: PathBuf,
    parent_path: PathBuf,
    file: File,
    parent: File,
    expected: CellDigestV1,
    plan: CellRetainedShardPlanV1,
}

impl CellRetainedShardPlanFileV1 {
    /// Prepare the complete actual source union, then create/fsync/read back
    /// CRP1 before any provider execution. A partial existing file is never
    /// overwritten. To recover an existing plan use open with its original pin.
    pub fn create(
        path: &Path,
        catalog: &mut CellVersionRetentionStoreV3,
        cache: &CellStoreV1,
        request: CellRetainedShardPlanRequestV1,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        let plan = CellRetainedShardPlanV1::build(catalog, cache, request, deadline)?;
        let expected = plan.commitment();
        let parent_path = parent_path(path)?;
        let parent = open_parent(&parent_path)?;
        check_parent(&parent_path, &parent)?;
        let mut file = open_file(path, true)?;
        check_file(path, &file)?;
        file.write_all(&plan.encode())?;
        check(deadline)?;
        file.sync_all()?;
        parent.sync_all()?;
        check(deadline)?;
        let owner = Self {
            path: path.to_path_buf(),
            parent_path,
            file,
            parent,
            expected,
            plan,
        };
        owner.read_current(catalog, owner.plan.from, deadline)?;
        Ok(owner)
    }

    pub fn open(path: &Path, expected: CellDigestV1, deadline: Instant) -> CellResultV1<Self> {
        check(deadline)?;
        let parent_path = parent_path(path)?;
        let parent = open_parent(&parent_path)?;
        check_parent(&parent_path, &parent)?;
        let file = open_file(path, false)?;
        let plan = read_file(path, &file, expected, deadline)?;
        check_parent(&parent_path, &parent)?;
        let owner = Self {
            path: path.to_path_buf(),
            parent_path,
            file,
            parent,
            expected,
            plan,
        };
        owner.read(deadline)?;
        Ok(owner)
    }

    pub fn commitment(&self) -> CellDigestV1 {
        self.expected
    }

    /// This immutable cached descriptor is useful for preparing original native
    /// task claims. It is not a fresh on-disk or complete-catalog observation.
    pub fn plan(&self) -> &CellRetainedShardPlanV1 {
        &self.plan
    }

    pub fn read(&self, deadline: Instant) -> CellResultV1<CellRetainedShardPlanV1> {
        check_parent(&self.parent_path, &self.parent)?;
        let actual = read_file(&self.path, &self.file, self.expected, deadline)?;
        require(actual == self.plan, "retained shard plan file changed")?;
        check_parent(&self.parent_path, &self.parent)?;
        check(deadline)?;
        Ok(actual)
    }

    pub fn read_current(
        &self,
        catalog: &CellVersionRetentionStoreV3,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<CellRetainedShardPlanV1> {
        let actual = self.read(deadline)?;
        actual.verify_current_catalog(catalog, current_height, deadline)?;
        self.read(deadline)?;
        Ok(actual)
    }
}

fn parent_path(path: &Path) -> CellResultV1<PathBuf> {
    require(
        path.is_absolute() && path.file_name().is_some(),
        "retained shard plan absolute path",
    )?;
    Ok(path
        .parent()
        .ok_or(CellErrorV1::Invalid("retained shard plan parent"))?
        .to_path_buf())
}

fn read_file(
    path: &Path,
    file: &File,
    expected: CellDigestV1,
    deadline: Instant,
) -> CellResultV1<CellRetainedShardPlanV1> {
    check(deadline)?;
    check_file(path, file)?;
    let length = file.metadata()?.len();
    require(
        length <= MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1 as u64,
        "retained shard plan file size",
    )?;
    let mut bytes = Vec::with_capacity(length as usize);
    let mut input = file;
    input.seek(SeekFrom::Start(0))?;
    input
        .take(MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)?;
    check(deadline)?;
    require(
        bytes.len() as u64 == length && file.metadata()?.len() == length,
        "retained shard plan file length changed",
    )?;
    check_file(path, file)?;
    let result = CellRetainedShardPlanV1::decode_pinned(&bytes, expected, deadline)?;
    check_file(path, file)?;
    check(deadline)?;
    Ok(result)
}

fn open_file(path: &Path, create: bool) -> CellResultV1<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    if create {
        options.write(true).create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    Ok(options.open(path)?)
}

fn open_parent(path: &Path) -> CellResultV1<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    Ok(options.open(path)?)
}

fn check_parent(path: &Path, file: &File) -> CellResultV1<()> {
    let entry = fs::symlink_metadata(path)?;
    let fd = file.metadata()?;
    require(
        entry.is_dir() && fd.is_dir(),
        "retained shard plan parent directory",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            entry.dev() == fd.dev() && entry.ino() == fd.ino(),
            "retained shard plan parent identity",
        )?;
    }
    Ok(())
}

fn check_file(path: &Path, file: &File) -> CellResultV1<()> {
    let entry = fs::symlink_metadata(path)?;
    let fd = file.metadata()?;
    require(
        entry.is_file() && fd.is_file(),
        "retained shard plan regular file",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            entry.dev() == fd.dev() && entry.ino() == fd.ino() && fd.nlink() == 1,
            "retained shard plan file identity",
        )?;
    }
    Ok(())
}
