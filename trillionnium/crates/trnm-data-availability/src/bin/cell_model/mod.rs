//! Explicit model-root composition/readback; never release authentication.

use super::{Args, Result};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use trnm_data_availability::cell::{
    digest_hex, parse_digest, CellErrorV1, CellModelReleaseRootV1, CellTensorContractV1,
    CellTensorModelManifestV1, MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1,
    MAX_MODEL_RELEASE_ROOT_BYTES_V1,
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
    Ok(CellModelReleaseRootV1::decode(&read_wire(
        path,
        MAX_MODEL_RELEASE_ROOT_BYTES_V1,
    )?)?)
}

pub(super) fn prepare_tensor(args: &mut Args) -> Result<()> {
    let root_path = PathBuf::from(args.take("--model-root-file")?);
    let root_pin = parse_digest(&args.take("--model-root")?)?;
    let contract_path = PathBuf::from(args.take("--tensor-contract-file")?);
    let contract_pin = parse_digest(&args.take("--tensor-contract")?)?;
    let output = PathBuf::from(args.take("--output")?);
    args.finish()?;
    let root = read(&root_path)?;
    if root.id() != root_pin {
        return Err(CellErrorV1::Invalid("model root pin").into());
    }
    // TMT1 has a 1 MiB parser bound of its own; the descriptor is bounded
    // before reading and no tensor weights are decoded by this preparation.
    let contract = CellTensorContractV1::decode(&read_wire(&contract_path, 1024 * 1024)?)?;
    contract.verify_for_model(&root, contract_pin)?;
    let model = CellTensorModelManifestV1::new(root, contract)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    file.write_all(&model.encode())?;
    file.sync_all()?;
    println!("{{\"schema\":\"trnm.cell.tensor-model.prepare.v1\",\"tensor_model\":\"{}\",\"model_root\":\"{}\",\"tensor_contract\":\"{}\",\"selection_authority\":false,\"use_authority\":false}}",
        digest_hex(model.id()), digest_hex(model.root().id()), digest_hex(model.contract().id()));
    Ok(())
}

pub(super) fn read_tensor_manifest(path: &Path) -> Result<CellTensorModelManifestV1> {
    Ok(CellTensorModelManifestV1::decode(&read_wire(
        path,
        MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1,
    )?)?)
}

fn read_wire(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    #[cfg(not(unix))]
    {
        let _ = (path, maximum);
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
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
            return Err(CellErrorV1::Invalid("model root input size/type").into());
        }
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(CellErrorV1::Invalid("model root input changed length").into());
        }
        Ok(bytes)
    }
}
