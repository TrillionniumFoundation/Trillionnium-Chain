use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use super::*;

const ROOT_FILE: &str = "root.crr2";

/// A pinned complete root and bounded immutable pages. This owner has no second
/// effect ledger. Reopening and reading pages never dispatch source copies;
/// native recovery must use the original M12/CSP1 targets and identities.
pub struct CellPagedRetainedShardPlanFileV2 {
    directory_path: PathBuf,
    directory: File,
    parent_path: PathBuf,
    parent: File,
    root: BoundFile,
    pages: Vec<BoundFile>,
    plan: CellPagedRetainedShardPlanV2,
}

impl CellPagedRetainedShardPlanFileV2 {
    /// Prepare the exact whole-catalog intent, then write/fsync each bounded
    /// page before publishing the root. Only metadata and original acknowledged
    /// source chunks are read here; no CAS fill, funding debit or provider write
    /// occurs. An interrupted directory is never overwritten by a fresh plan.
    pub fn create(
        directory: &Path,
        catalog: &mut CellVersionRetentionStoreV3,
        request: CellPagedRetainedShardPlanRequestV2,
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        let mut plan = CellPagedRetainedShardPlanV2::prepare(catalog, request, deadline)?;
        let parent_path = parent_path(directory)?;
        let parent = open_directory(&parent_path)?;
        check_directory(&parent_path, &parent)?;
        fs::create_dir(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let directory_fd = open_directory(directory)?;
        check_directory(directory, &directory_fd)?;
        let mut identities = plan.reserved_identities()?;
        for index in 0..plan.page_count() {
            check(deadline)?;
            let page = plan.build_page(index, catalog, deadline)?;
            for slot in page.chunks().iter().flat_map(|chunk| chunk.slots()) {
                require(
                    identities.insert(slot.operation()),
                    "paged shard cross-page identity alias",
                )?;
            }
            let bytes = page.encode();
            let expected = page.commitment();
            let file = BoundFile::create(
                &directory.join(page_name(index)),
                expected,
                MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1,
                &bytes,
                deadline,
            )?;
            require(
                file.read(deadline)? == bytes,
                "paged shard page write readback",
            )?;
            plan.pages[index].commitment = expected;
        }
        plan.verify_current_catalog(catalog, plan.from, deadline)?;
        let bytes = plan.encode();
        let expected = plan.commitment();
        let root = BoundFile::create(
            &directory.join(ROOT_FILE),
            expected,
            MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2,
            &bytes,
            deadline,
        )?;
        require(
            root.read(deadline)? == bytes,
            "paged shard root write readback",
        )?;
        directory_fd.sync_all()?;
        parent.sync_all()?;
        check_directory(directory, &directory_fd)?;
        check_directory(&parent_path, &parent)?;
        check(deadline)?;
        let owner = Self::open(directory, expected, deadline)?;
        owner.read_current(catalog, owner.plan.from, deadline)?;
        Ok(owner)
    }

    /// Open only an independently pinned, complete root. Audit every page and
    /// all cross-page operation identities before returning an execution owner.
    /// Missing pages leave the original physical obligations untouched.
    pub fn open(directory: &Path, expected: CellDigestV1, deadline: Instant) -> CellResultV1<Self> {
        check(deadline)?;
        let parent_path = parent_path(directory)?;
        let parent = open_directory(&parent_path)?;
        check_directory(&parent_path, &parent)?;
        let directory_fd = open_directory(directory)?;
        check_directory(directory, &directory_fd)?;
        let root = BoundFile::open(
            &directory.join(ROOT_FILE),
            expected,
            MAX_CELL_RETAINED_SHARD_ROOT_BYTES_V2,
        )?;
        let plan =
            CellPagedRetainedShardPlanV2::decode_pinned(&root.read(deadline)?, expected, deadline)?;
        let mut pages = Vec::with_capacity(plan.page_count());
        let mut identities = plan.reserved_identities()?;
        for index in 0..plan.page_count() {
            check(deadline)?;
            let file = BoundFile::open(
                &directory.join(page_name(index)),
                plan.pages[index].commitment,
                MAX_CELL_RETAINED_SHARD_PLAN_BYTES_V1,
            )?;
            let page = CellRetainedShardPageV2::decode_pinned(
                &file.read(deadline)?,
                &plan,
                index,
                deadline,
            )?;
            for slot in page.chunks().iter().flat_map(|chunk| chunk.slots()) {
                require(
                    identities.insert(slot.operation()),
                    "paged shard cross-page identity alias",
                )?;
            }
            pages.push(file);
        }
        let owner = Self {
            directory_path: directory.to_path_buf(),
            directory: directory_fd,
            parent_path,
            parent,
            root,
            pages,
            plan,
        };
        owner.check_paths()?;
        owner.read(deadline)?;
        Ok(owner)
    }

    pub fn commitment(&self) -> CellDigestV1 {
        self.root.expected
    }
    /// Cached immutable metadata, not a current-catalog or custody observation.
    pub fn plan(&self) -> &CellPagedRetainedShardPlanV2 {
        &self.plan
    }

    pub fn read(&self, deadline: Instant) -> CellResultV1<CellPagedRetainedShardPlanV2> {
        self.check_paths()?;
        let actual = CellPagedRetainedShardPlanV2::decode_pinned(
            &self.root.read(deadline)?,
            self.root.expected,
            deadline,
        )?;
        require(actual == self.plan, "paged shard root file changed")?;
        self.check_paths()?;
        check(deadline)?;
        Ok(actual)
    }

    /// Check the root and current complete catalog. This deliberately does not
    /// read every page payload; per-chunk staging uses this bounded metadata
    /// check. Use read_complete_current for a complete page-integrity readback.
    pub fn read_current(
        &self,
        catalog: &CellVersionRetentionStoreV3,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<CellPagedRetainedShardPlanV2> {
        let actual = self.read(deadline)?;
        actual.verify_current_catalog(catalog, current_height, deadline)?;
        self.read(deadline)?;
        Ok(actual)
    }

    /// Reobserve every bounded page under the same root and original catalog
    /// anchor. A same-inode change to an earlier page cannot hide behind the
    /// root's unchanged directory names. The observation is sequential, not an
    /// atomic filesystem snapshot, and grants no provider effect authority.
    pub fn read_complete_current(
        &self,
        catalog: &CellVersionRetentionStoreV3,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<CellPagedRetainedShardPlanV2> {
        let actual = self.read_current(catalog, current_height, deadline)?;
        let mut identities = actual.reserved_identities()?;
        let mut covered = 0_usize;
        for (index, file) in self.pages.iter().enumerate() {
            check(deadline)?;
            let page = CellRetainedShardPageV2::decode_pinned(
                &file.read(deadline)?,
                &actual,
                index,
                deadline,
            )?;
            require(
                page.start_chunk() == covered,
                "paged shard complete page coverage",
            )?;
            covered = covered
                .checked_add(page.chunks().len())
                .ok_or(CellErrorV1::Invalid("paged shard complete page coverage"))?;
            for slot in page.chunks().iter().flat_map(|chunk| chunk.slots()) {
                require(
                    identities.insert(slot.operation()),
                    "paged shard cross-page identity alias",
                )?;
            }
        }
        require(
            covered == actual.chunk_count(),
            "paged shard complete page coverage",
        )?;
        require(
            self.read_current(catalog, current_height, deadline)? == actual,
            "paged shard root file changed",
        )?;
        check(deadline)?;
        Ok(actual)
    }

    pub fn read_page(
        &self,
        index: usize,
        deadline: Instant,
    ) -> CellResultV1<CellRetainedShardPageV2> {
        let root = self.read(deadline)?;
        let file = self
            .pages
            .get(index)
            .ok_or(CellErrorV1::Invalid("paged shard page index"))?;
        let actual =
            CellRetainedShardPageV2::decode_pinned(&file.read(deadline)?, &root, index, deadline)?;
        self.read(deadline)?;
        Ok(actual)
    }

    /// Stage only one original chunk's six codeword payloads. The caller must
    /// select this source path only for new authorized effects; Unknown/Done
    /// reconciliation has no need to call it. Cache quotas remain unchanged.
    pub fn stage_chunk_from_catalog(
        &self,
        page_index: usize,
        chunk_index_in_page: usize,
        catalog: &mut CellVersionRetentionStoreV3,
        cache: &CellStoreV1,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        let root = self.read_current(catalog, current_height, deadline)?;
        let page = self.read_page(page_index, deadline)?;
        let chunk = page
            .chunks()
            .get(chunk_index_in_page)
            .ok_or(CellErrorV1::Invalid("paged shard chunk index"))?;
        let (manifest, index) = root.chunk_at(page.start_chunk() + chunk_index_in_page)?;
        let bytes = root.read_source_chunk(catalog, manifest, index, deadline)?;
        let shards = chunk.binding().encode_chunk(&bytes)?;
        for (contract, shard) in chunk.slots().iter().zip(shards) {
            check(deadline)?;
            CellRs46ShardProviderV1::cache_shard(
                contract,
                contract.operation(),
                &shard.encode(),
                cache,
                deadline,
            )?;
        }
        self.read_current(catalog, current_height, deadline)?;
        check(deadline)
    }

    /// Convenience staging is still subject to the caller's bounded cache. It
    /// does not promise that earlier chunks remain cached after later chunks;
    /// native execution stages/consumes one chunk at a time instead.
    pub fn stage_page_from_catalog(
        &self,
        index: usize,
        catalog: &mut CellVersionRetentionStoreV3,
        cache: &CellStoreV1,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        let page = self.read_page(index, deadline)?;
        for chunk in 0..page.chunks().len() {
            self.stage_chunk_from_catalog(index, chunk, catalog, cache, current_height, deadline)?;
        }
        check(deadline)
    }

    fn check_paths(&self) -> CellResultV1<()> {
        check_directory(&self.parent_path, &self.parent)?;
        check_directory(&self.directory_path, &self.directory)?;
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(&self.directory_path)? {
            let name = entry?.file_name();
            require(
                names.len() < self.plan.page_count() + 1,
                "paged shard directory entry count",
            )?;
            names.insert(name);
        }
        let expected: BTreeSet<_> = std::iter::once(std::ffi::OsString::from(ROOT_FILE))
            .chain(
                (0..self.plan.page_count()).map(|index| std::ffi::OsString::from(page_name(index))),
            )
            .collect();
        require(names == expected, "paged shard complete directory coverage")?;
        Ok(())
    }
}

struct BoundFile {
    path: PathBuf,
    file: File,
    expected: CellDigestV1,
    maximum: usize,
}

impl BoundFile {
    fn create(
        path: &Path,
        expected: CellDigestV1,
        maximum: usize,
        bytes: &[u8],
        deadline: Instant,
    ) -> CellResultV1<Self> {
        check(deadline)?;
        require(bytes.len() <= maximum, "paged shard file size")?;
        let mut file = open_file(path, true)?;
        check_file(path, &file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        check(deadline)?;
        check_file(path, &file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            expected,
            maximum,
        })
    }
    fn open(path: &Path, expected: CellDigestV1, maximum: usize) -> CellResultV1<Self> {
        let file = open_file(path, false)?;
        check_file(path, &file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            expected,
            maximum,
        })
    }
    fn read(&self, deadline: Instant) -> CellResultV1<Vec<u8>> {
        check(deadline)?;
        check_file(&self.path, &self.file)?;
        let length = self.file.metadata()?.len();
        require(length <= self.maximum as u64, "paged shard file size")?;
        let mut bytes = Vec::with_capacity(length as usize);
        let mut input = &self.file;
        input.seek(SeekFrom::Start(0))?;
        input
            .take(self.maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() as u64 == length && self.file.metadata()?.len() == length,
            "paged shard file length changed",
        )?;
        check_file(&self.path, &self.file)?;
        check(deadline)?;
        Ok(bytes)
    }
}

fn page_name(index: usize) -> String {
    format!("page-{index:05}.crg2")
}

fn parent_path(path: &Path) -> CellResultV1<PathBuf> {
    require(
        path.is_absolute() && path.file_name().is_some(),
        "paged shard absolute directory",
    )?;
    Ok(path
        .parent()
        .ok_or(CellErrorV1::Invalid("paged shard parent"))?
        .to_path_buf())
}

fn open_directory(path: &Path) -> CellResultV1<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    Ok(options.open(path)?)
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

fn check_directory(path: &Path, file: &File) -> CellResultV1<()> {
    let entry = fs::symlink_metadata(path)?;
    let fd = file.metadata()?;
    require(entry.is_dir() && fd.is_dir(), "paged shard directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            entry.dev() == fd.dev() && entry.ino() == fd.ino(),
            "paged shard directory identity",
        )?;
    }
    Ok(())
}

fn check_file(path: &Path, file: &File) -> CellResultV1<()> {
    let entry = fs::symlink_metadata(path)?;
    let fd = file.metadata()?;
    require(entry.is_file() && fd.is_file(), "paged shard regular file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            entry.dev() == fd.dev() && entry.ino() == fd.ino() && fd.nlink() == 1,
            "paged shard file identity",
        )?;
    }
    Ok(())
}
