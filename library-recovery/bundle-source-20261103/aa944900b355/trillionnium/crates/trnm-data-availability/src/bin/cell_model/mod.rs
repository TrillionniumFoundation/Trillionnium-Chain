//! Explicit model-root composition/readback; never release authentication.

use super::{Args, Result};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use trnm_data_availability::cell::{
    digest_hex, parse_digest, CellErrorV1, CellModelReleaseRootV1, MAX_MODEL_RELEASE_ROOT_BYTES_V1,
};

pub(super) fn prepare(args: &mut Args) -> Result<()> {
    let path = PathBuf::from(args.take("--closure-file")?);
    let pin = parse_digest(&args.take("--closure")?)?;
    let parents_text = args.take("--parent-root-files")?;
    let output = PathBuf::from(args.take("--output")?);
    args.finish()?;
    let paths: Vec<_> = parents_text
        .split(',')
        .filter(|value| !value.is_empty())
        .collect();
    if paths.len() > 16 {
        return Err(CellErrorV1::Invalid("model root lineage count").into());
    }
    let closure = super::cell_closure::read_closure(&path)?;
    if closure.id() != pin {
        return Err(CellErrorV1::Invalid("closure pin").into());
    }
    let mut parents = paths
        .iter()
        .map(|path| read(Path::new(path)))
        .collect::<Result<Vec<_>>>()?;
    parents.sort_by_key(CellModelReleaseRootV1::id);
    let root = CellModelReleaseRootV1::new(
        closure,
        parents.iter().map(CellModelReleaseRootV1::id).collect(),
    )?;
    root.verify_parent_roots(&parents)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    file.write_all(&root.encode())?;
    file.sync_all()?;
    println!("{{\"schema\":\"trnm.cell.model-root.prepare.v1\",\"model_root\":\"{}\",\"closure\":\"{}\",\"parents_verified\":{},\"selection_authority\":false,\"use_authority\":false}}",
        digest_hex(root.id()), digest_hex(root.closure().id()), parents.len());
    Ok(())
}

pub(super) fn read(path: &Path) -> Result<CellModelReleaseRootV1> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(CellErrorV1::Invalid("model root descriptor IO unsupported").into())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_MODEL_RELEASE_ROOT_BYTES_V1 as u64
        {
            return Err(CellErrorV1::Invalid("model root input size/type").into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_MODEL_RELEASE_ROOT_BYTES_V1 as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(CellErrorV1::Invalid("model root input changed length").into());
        }
        Ok(CellModelReleaseRootV1::decode(&bytes)?)
    }
}
