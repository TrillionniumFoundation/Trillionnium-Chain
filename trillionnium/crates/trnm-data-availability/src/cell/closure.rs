//! Owner-pinned dependency/file plan over existing TCM1 and TCR1 identities.
//!
//! This validates a declared graph, portable names and exact loader context. It
//! cannot infer dependencies omitted by the release owner, parse tensors, select
//! CURRENT, authorize export or mint FinalUse. The safe loader still owns those
//! decisions and supplies its expected closure/profile/generation independently.

use std::{
    collections::BTreeSet,
    io::{Cursor, Read},
};

use sha2::{Digest, Sha256};

use super::{
    require, CellContextV1, CellDigestV1, CellErrorV1, CellManifestV1, CellReleaseManifestV1,
    CellResultV1, MAX_CELL_BYTES,
};

pub const MAX_CELL_CLOSURE_BYTES_V1: usize = 1024 * 1024;
pub const MAX_CELL_CLOSURE_FILES_V1: usize = 256;
const MAX_GRAPH_DEPTH: usize = 16;
const MAX_PATH_BYTES: usize = 255;

/// Data roles only. No role requests code execution or supplies a dynamic loader.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CellFileRoleV1 {
    Base = 1,
    Tokenizer = 2,
    Preprocessor = 3,
    Adapter = 4,
    Router = 5,
    Configuration = 6,
}

impl CellFileRoleV1 {
    fn decode(value: u8) -> CellResultV1<Self> {
        match value {
            1 => Ok(Self::Base),
            2 => Ok(Self::Tokenizer),
            3 => Ok(Self::Preprocessor),
            4 => Ok(Self::Adapter),
            5 => Ok(Self::Router),
            6 => Ok(Self::Configuration),
            _ => Err(CellErrorV1::Invalid("closure role")),
        }
    }
}

/// An immutable data-file mapping. Dependencies are indices in canonical path order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellClosureFileV1 {
    pub path: String,
    pub role: CellFileRoleV1,
    pub manifest: CellDigestV1,
    pub payload_sha256: CellDigestV1,
    pub payload_bytes: u64,
    pub dependencies: Vec<u16>,
}

/// Expected values from the existing release/loader owner, never peer discovery.
/// A matching profile identifies the loader's format/shape/ABI policy; it does
/// not prove that a tensor parser has executed or that use is authorized.
#[derive(Clone, Debug)]
pub struct CellLoaderContextV1 {
    pub closure_id: CellDigestV1,
    pub context: CellContextV1,
    pub selected_generation: u64,
    pub loader_profile: CellDigestV1,
    pub required_roles: Vec<CellFileRoleV1>,
    pub max_payload_bytes: u64,
    pub max_chunks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellReleaseClosureV1 {
    release: CellReleaseManifestV1,
    selected_generation: u64,
    loader_profile: CellDigestV1,
    roots: Vec<u16>,
    files: Vec<CellClosureFileV1>,
}

impl CellReleaseClosureV1 {
    /// Order is part of the wire contract. Do not silently sort paths/indices.
    pub fn new(
        context: CellContextV1,
        selected_generation: u64,
        loader_profile: CellDigestV1,
        roots: Vec<u16>,
        files: Vec<CellClosureFileV1>,
    ) -> CellResultV1<Self> {
        require(
            !files.is_empty() && files.len() <= MAX_CELL_CLOSURE_FILES_V1,
            "closure file count",
        )?;
        let release =
            CellReleaseManifestV1::new(context, files.iter().map(|file| file.manifest).collect())?;
        let value = Self {
            release,
            selected_generation,
            loader_profile,
            roots,
            files,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn release(&self) -> &CellReleaseManifestV1 {
        &self.release
    }
    pub fn files(&self) -> &[CellClosureFileV1] {
        &self.files
    }
    pub fn roots(&self) -> &[u16] {
        &self.roots
    }
    pub fn selected_generation(&self) -> u64 {
        self.selected_generation
    }
    pub fn loader_profile(&self) -> CellDigestV1 {
        self.loader_profile
    }

    pub fn validate(&self) -> CellResultV1<()> {
        self.release.validate()?;
        require(self.selected_generation > 0, "closure generation")?;
        require(self.loader_profile != [0; 32], "closure loader profile")?;
        require(
            !self.files.is_empty() && self.files.len() <= MAX_CELL_CLOSURE_FILES_V1,
            "closure file count",
        )?;
        validate_indices(&self.roots, self.files.len(), "closure roots")?;
        require(!self.roots.is_empty(), "closure roots")?;
        require(
            self.files
                .windows(2)
                .all(|pair| pair[0].path < pair[1].path),
            "closure canonical paths",
        )?;
        // Preserve the owner's exact names (including README.md), while
        // rejecting aliases on case-insensitive filesystems.
        let paths: BTreeSet<String> = self
            .files
            .iter()
            .map(|file| file.path.to_ascii_lowercase())
            .collect();
        require(
            paths.len() == self.files.len(),
            "closure case-fold path alias",
        )?;
        let mut manifests = BTreeSet::new();
        for (index, file) in self.files.iter().enumerate() {
            validate_path(&file.path)?;
            let folded = file.path.to_ascii_lowercase();
            for (offset, _) in folded.match_indices('/') {
                require(
                    !paths.contains(&folded[..offset]),
                    "closure file/directory alias",
                )?;
            }
            require(
                file.manifest != [0; 32]
                    && file.payload_sha256 != [0; 32]
                    && (1..=MAX_CELL_BYTES).contains(&file.payload_bytes),
                "closure payload identity",
            )?;
            require(manifests.insert(file.manifest), "closure manifest alias")?;
            validate_indices(&file.dependencies, self.files.len(), "closure dependency")?;
            require(
                !file.dependencies.contains(&(index as u16)),
                "closure self dependency",
            )?;
        }
        require(
            manifests
                .into_iter()
                .eq(self.release.cells().iter().copied()),
            "closure release membership",
        )?;
        let mut states = vec![0; self.files.len()];
        let mut heights = vec![0; self.files.len()];
        for root in &self.roots {
            visit(
                usize::from(*root),
                &self.files,
                &mut states,
                &mut heights,
                1,
            )?;
        }
        require(
            states.iter().all(|state| *state == 2),
            "closure unreachable file",
        )?;
        require(
            self.encode().len() <= MAX_CELL_CLOSURE_BYTES_V1,
            "closure wire length",
        )
    }

    /// This is byte-plan admission only. It intentionally returns no use token.
    pub fn verify_for_loader(&self, expected: &CellLoaderContextV1) -> CellResultV1<()> {
        self.validate()?;
        require(
            self.id() == expected.closure_id
                && self.release.context() == &expected.context
                && self.selected_generation == expected.selected_generation
                && self.loader_profile == expected.loader_profile,
            "closure loader context",
        )?;
        require(
            expected.max_payload_bytes > 0 && expected.max_chunks > 0,
            "closure loader budget",
        )?;
        let required: BTreeSet<_> = expected.required_roles.iter().copied().collect();
        require(
            !required.is_empty() && required.len() == expected.required_roles.len(),
            "closure required roles",
        )?;
        require(
            required
                .iter()
                .all(|role| self.files.iter().any(|file| file.role == *role)),
            "closure missing required role",
        )?;
        let total = self.files.iter().try_fold(0u64, |total, file| {
            total
                .checked_add(file.payload_bytes)
                .ok_or(CellErrorV1::Invalid("closure payload budget"))
        })?;
        require(
            total <= expected.max_payload_bytes,
            "closure payload budget",
        )
    }

    /// Check exact TCM1 metadata before any member payload acquisition.
    pub(crate) fn verify_manifest(&self, manifest: &CellManifestV1) -> CellResultV1<()> {
        manifest.validate()?;
        let id = manifest.id();
        let file = self
            .files
            .iter()
            .find(|file| file.manifest == id)
            .ok_or(CellErrorV1::Invalid("closure unexpected manifest"))?;
        require(
            manifest.context() == self.release.context()
                && manifest.payload_sha256() == file.payload_sha256
                && manifest.size() == file.payload_bytes,
            "closure manifest payload",
        )
    }

    pub fn id(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-dependency-closure.v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn encode(&self) -> Vec<u8> {
        let release = self.release.encode();
        let mut out = Vec::new();
        out.extend_from_slice(b"TCD1");
        out.extend_from_slice(&self.selected_generation.to_be_bytes());
        out.extend_from_slice(&self.loader_profile);
        out.extend_from_slice(&(release.len() as u32).to_be_bytes());
        out.extend_from_slice(&release);
        out.extend_from_slice(&(self.roots.len() as u16).to_be_bytes());
        for root in &self.roots {
            out.extend_from_slice(&root.to_be_bytes());
        }
        out.extend_from_slice(&(self.files.len() as u16).to_be_bytes());
        for file in &self.files {
            out.extend_from_slice(&(file.path.len() as u16).to_be_bytes());
            out.extend_from_slice(file.path.as_bytes());
            out.push(file.role as u8);
            out.extend_from_slice(&file.manifest);
            out.extend_from_slice(&file.payload_sha256);
            out.extend_from_slice(&file.payload_bytes.to_be_bytes());
            out.extend_from_slice(&(file.dependencies.len() as u16).to_be_bytes());
            for dependency in &file.dependencies {
                out.extend_from_slice(&dependency.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            bytes.len() <= MAX_CELL_CLOSURE_BYTES_V1,
            "closure wire length",
        )?;
        let mut input = Cursor::new(bytes);
        require(read_array::<4>(&mut input)? == *b"TCD1", "closure version")?;
        let selected_generation = u64::from_be_bytes(read_array(&mut input)?);
        let loader_profile = read_array(&mut input)?;
        let release_size = u32::from_be_bytes(read_array(&mut input)?) as usize;
        require(
            release_size <= MAX_CELL_CLOSURE_BYTES_V1,
            "closure release length",
        )?;
        let start = input.position() as usize;
        let end = start
            .checked_add(release_size)
            .ok_or(CellErrorV1::Invalid("closure release length"))?;
        require(end <= bytes.len(), "closure release length")?;
        let release = CellReleaseManifestV1::decode(&bytes[start..end])?;
        input.set_position(end as u64);
        let roots = read_indices(&mut input)?;
        let count = usize::from(u16::from_be_bytes(read_array(&mut input)?));
        require(
            (1..=MAX_CELL_CLOSURE_FILES_V1).contains(&count),
            "closure file count",
        )?;
        let mut files = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(u16::from_be_bytes(read_array(&mut input)?));
            require(
                (1..=MAX_PATH_BYTES).contains(&length),
                "closure path length",
            )?;
            let mut path = vec![0; length];
            input.read_exact(&mut path)?;
            let path = String::from_utf8(path)
                .map_err(|_| CellErrorV1::Invalid("closure path encoding"))?;
            let role = CellFileRoleV1::decode(read_array::<1>(&mut input)?[0])?;
            files.push(CellClosureFileV1 {
                path,
                role,
                manifest: read_array(&mut input)?,
                payload_sha256: read_array(&mut input)?,
                payload_bytes: u64::from_be_bytes(read_array(&mut input)?),
                dependencies: read_indices(&mut input)?,
            });
        }
        require(
            input.position() == bytes.len() as u64,
            "closure trailing bytes",
        )?;
        let value = Self {
            release,
            selected_generation,
            loader_profile,
            roots,
            files,
        };
        value.validate()?;
        Ok(value)
    }
}

fn validate_indices(indices: &[u16], count: usize, reason: &'static str) -> CellResultV1<()> {
    require(
        indices.len() <= MAX_CELL_CLOSURE_FILES_V1
            && indices.iter().all(|index| usize::from(*index) < count)
            && indices.windows(2).all(|pair| pair[0] < pair[1]),
        reason,
    )
}

fn visit(
    index: usize,
    files: &[CellClosureFileV1],
    states: &mut [u8],
    heights: &mut [usize],
    depth: usize,
) -> CellResultV1<usize> {
    require(depth <= MAX_GRAPH_DEPTH, "closure graph depth")?;
    require(states[index] != 1, "closure dependency cycle")?;
    if states[index] == 2 {
        return Ok(heights[index]);
    }
    states[index] = 1;
    let mut height = 1;
    for dependency in &files[index].dependencies {
        height =
            height.max(1 + visit(usize::from(*dependency), files, states, heights, depth + 1)?);
        require(height <= MAX_GRAPH_DEPTH, "closure graph depth")?;
    }
    states[index] = 2;
    heights[index] = height;
    Ok(height)
}

fn validate_path(path: &str) -> CellResultV1<()> {
    require(
        !path.is_empty()
            && path.len() <= MAX_PATH_BYTES
            && path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte)),
        "closure portable path",
    )?;
    let parts: Vec<_> = path.split('/').collect();
    require(parts.len() <= 8, "closure path depth")?;
    for part in parts {
        require(
            !part.is_empty() && part.len() <= 64 && !part.starts_with('.') && !part.ends_with('.'),
            "closure path component",
        )?;
        let stem = part.split('.').next().unwrap_or("").to_ascii_lowercase();
        let reserved = matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
            || ((stem.starts_with("com") || stem.starts_with("lpt"))
                && stem.len() == 4
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        require(!reserved, "closure reserved path")?;
    }
    Ok(())
}

fn read_array<const N: usize>(input: &mut Cursor<&[u8]>) -> CellResultV1<[u8; N]> {
    let mut value = [0; N];
    input.read_exact(&mut value)?;
    Ok(value)
}

fn read_indices(input: &mut Cursor<&[u8]>) -> CellResultV1<Vec<u16>> {
    let count = usize::from(u16::from_be_bytes(read_array(input)?));
    require(count <= MAX_CELL_CLOSURE_FILES_V1, "closure index count")?;
    (0..count)
        .map(|_| Ok(u16::from_be_bytes(read_array(input)?)))
        .collect()
}
