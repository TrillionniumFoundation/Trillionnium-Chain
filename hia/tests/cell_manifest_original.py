"""Offline original TCM1, requiring a trusted locked SHA-256 Cargo artifact."""
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

from hia.tests.integer_model_material_original import LOCK, pin, sha
from hia.tests.test_verification_profile_registry import ROOT, pick

CELL = ROOT / "trillionnium/crates/trnm-data-availability/src/cell"
CODEC = CELL / "manifest.rs"
ERASURE = CELL / "erasure.rs"
CLOSURE = CELL / "closure.rs"
MODEL_ROOT = CELL / "model_root.rs"
TENSOR_CONTRACT = CELL / "tensor.rs"
ADAPTER = Path(__file__).with_name("rust_cell_manifest_reference.rs")
BINDING_ADAPTER = Path(__file__).with_name("rust_cell_binding_reference.rs")
ENV = "HIA_M09_SHA2_RLIB"


def binding_source():
    original = ERASURE.read_bytes()
    start = original.index(b"/// Exact original chunk identity")
    end = original.index(b"impl CellRs46ChunkBindingV1 {",start)
    return original[start:end]


def tensor_contract_source(with_model_manifest=False):
    original = TENSOR_CONTRACT.read_bytes()
    names = (b"MAX_CELL_TENSOR_CONTRACT_BYTES_V1", b"HASH_PROFILE_SHA256_V1",
             b"CODEC_SAFETENSORS_DENSE_V1", b"MAX_TENSORS", b"MAX_TENSOR_NAME_BYTES", b"MAX_RANK")
    sizes = b"".join(pick(original, rb"^(?:pub )?const " + name + rb":[^\n]+;\n")
                     for name in names)
    start = original.index(b"#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n#[repr(u8)]\npub enum CellTensorDTypeV1")
    terminal = original.index(b"#[derive(Clone, Debug, Eq, PartialEq)]\npub struct CellTensorReadbackV1", start)
    declaration = original[start:terminal]
    a = original.index(b"impl CellTensorContractV1 {")
    b = original.index(b"    /// Verify the independent owner pin", a)
    c = original.index(b"    pub fn encode(", b)
    d = original.index(b"    /// Re-read one complete real container", c)
    helpers = original[original.index(b"fn valid_name("):original.index(b"fn read_section<")]
    contract = sizes + declaration + original[a:b]
    if with_model_manifest:
        contract += original[b:c]
    contract += original[c:d] + b"}\n"
    if with_model_manifest:
        contract += (pick(original, rb"^pub const MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1:[^;]+;\n") +
                     original[original.index(b"/// TMA1 is a self-contained"):original.index(b"fn valid_name(")])
        helpers += original[original.index(b"fn read_section<"):original.index(b"fn check_deadline(")]
    return contract + helpers


def source(with_closure=False, with_model_root=False, with_tensor_contract=False,
           with_tensor_model_manifest=False):
    boundary = CELL.with_suffix(".rs").read_bytes()
    digest = pick(boundary, rb"^pub type CellDigestV1 = [^\n]+;\n")
    result = pick(boundary, rb"^pub type CellResultV1<T> = [^\n]+;\n")
    check = pick(boundary, rb"^pub\(crate\) fn require\([^\n]+\n.*?^}\n")
    wire = CODEC.read_bytes()
    # The independent I/O shell uses only the two enum variants the unchanged
    # byte decoder can reach; no cache or SQLite dependency is mocked into it.
    variants = pick(boundary, rb"^    Invalid\(&'static str\),\n    Io\(io::Error\),\n")
    conversion = pick(boundary, rb"^impl From<io::Error> for CellErrorV1 \{\n.*?^}\n")
    shell = (b"use std::io::{self, Read, Write};\n#[derive(Debug)]\npub enum CellErrorV1 {\n" +
             variants + b"}\n" + conversion)
    if with_tensor_contract:
        constants = (pick(wire, rb"^pub const MAX_CELL_BYTES:[^\n]+;\n") +
                     pick(CLOSURE.read_bytes(), rb"^pub const MAX_CELL_CLOSURE_FILES_V1:[^\n]+;\n"))
        return (shell + digest + result + check + constants +
                b"#[allow(dead_code)]\nmod tensor_contract {\n"
                b"use super::{require,CellDigestV1,CellErrorV1,CellResultV1,MAX_CELL_BYTES,MAX_CELL_CLOSURE_FILES_V1};\n"
                b"use std::io::{Cursor,Read}; use sha2::{Digest,Sha256};\n" +
                tensor_contract_source() + b"}\n" + b'include!("tensor_contract_observation.rs");\n')
    isolated = b"""#[allow(dead_code)]
mod binding {
    use super::{require, CellDigestV1, CellErrorV1, CellResultV1};
    use super::manifest::{CellChunkV1, CellContextV1, CellManifestV1};
"""
    base = shell + digest + result + check + b"#[allow(dead_code)]\nmod manifest {\n" + wire + b"\n}\n"
    if with_closure or with_model_root or with_tensor_model_manifest:
        base = (base +
                b"use manifest::{CellContextV1, CellManifestV1, CellReleaseManifestV1, MAX_CELL_BYTES};\n"
                b"#[allow(dead_code)]\nmod closure {\n" + CLOSURE.read_bytes() + b"\n}\n")
        if with_tensor_model_manifest:
            return (base +
                    b"use closure::{CellFileRoleV1, CellLoaderContextV1, CellReleaseClosureV1, "
                    b"MAX_CELL_CLOSURE_BYTES_V1, MAX_CELL_CLOSURE_FILES_V1};\n"
                    b"#[allow(dead_code)]\nmod model_root {\n" + MODEL_ROOT.read_bytes() + b"\n}\n"
                    b"#[allow(dead_code)]\nmod tensor_contract {\nuse super::{require,CellDigestV1,CellErrorV1,"
                    b"CellResultV1,MAX_CELL_BYTES,MAX_CELL_CLOSURE_FILES_V1,CellModelReleaseRootV1,"
                    b"CellFileRoleV1,MAX_MODEL_RELEASE_ROOT_BYTES_V1};\n"
                    b"use std::io::{Cursor,Read}; use sha2::{Digest,Sha256};\n" +
                    tensor_contract_source(with_model_manifest=True) + b"}\n"
                    b"use model_root::{CellModelReleaseRootV1,MAX_MODEL_RELEASE_ROOT_BYTES_V1};\n"
                    b"#[allow(dead_code)]\nmod closure_observer {\nuse super::*;\n"
                    b'include!("closure_observation.rs");\n}\n'
                    b"#[allow(dead_code)]\nmod root_observer {\nuse super::*;\n"
                    b'include!("model_root_observation.rs");\n'
                    b"pub(crate) fn diag(e: CellErrorV1) -> u8 { model_root_status(e) }\n}\n"
                    b"#[allow(dead_code)]\nmod contract_observer {\nuse super::*;\n"
                    b'include!("tensor_contract_observation.rs");\n'
                    b"pub(crate) fn diag(e: CellErrorV1) -> u8 { contract_error(e) }\n}\n"
                    b'include!("tensor_model_observation.rs");\n')
        if with_model_root:
            return (base +
                    b"use closure::{CellFileRoleV1, CellLoaderContextV1, CellReleaseClosureV1, MAX_CELL_CLOSURE_BYTES_V1};\n"
                    b"#[allow(dead_code)]\nmod model_root {\n" + MODEL_ROOT.read_bytes() + b"\n}\n"
                    b"#[allow(dead_code)]\nmod closure_observer {\nuse super::*;\n"
                    b'include!("closure_observation.rs");\n}\n'
                    b'include!("model_root_observation.rs");\n')
        return base + b'include!("closure_observation.rs");\n'
    return (base + isolated + binding_source() +
            b'include!("binding_observation.rs");\n}\n' + ADAPTER.read_bytes())

def regular(path):
    if path.resolve(strict=True) != path or not path.is_file():
        raise ValueError("oracle provenance is not a direct regular file")
    return path.read_bytes()


def lock_row(records, name, dep_info):
    matched = [row for row in records if row["name"] == name and
               f"/{name}-{row['version']}/src/lib.rs" in dep_info]
    [row] = matched
    if (row.get("source") != "registry+https://github.com/rust-lang/crates.io-index" or
            re.fullmatch(r"[a-f0-9]{64}", row.get("checksum", "")) is None):
        raise ValueError("oracle library does not bind the public workspace lock")
    return row


def dependency_graph(artifact):
    deps = artifact.parent
    target = deps.parent.parent
    fingerprints = deps.parent / ".fingerprint"
    rust = pin()
    if not any(r.get("stdout") == rust and r.get("success") is True for r in
               json.loads(regular(target / ".rustc_info.json"))["outputs"].values()):
        raise ValueError("prebuilt target does not bind the pinned rustc")
    records = tomllib.loads(LOCK.read_text())["package"]
    [member] = [r for r in records if r["name"] == "trnm-data-availability"]
    if "sha2 0.10.9" not in member["dependencies"]:
        raise ValueError("original crate has changed SHA-256 dependency")
    seen = {}
    bound = {}

    def visit(package, path):
        library = package.replace("-", "_")
        if path in seen:
            return seen[path]
        if re.fullmatch(rf"lib{library}-[0-9a-f]{{16}}\.rlib", path.name) is None:
            raise ValueError("unexpected Cargo artifact address")
        suffix = path.stem.split("-")[-1]
        dep = deps / f"{library}-{suffix}.d"
        fp_dir = fingerprints / f"{package}-{suffix}"
        fp = fp_dir / f"lib-{library}.json"
        info = regular(dep).decode().splitlines()[0]
        row = lock_row(records, package, info)
        config = json.loads(regular(fp))
        if config["rustflags"] or config["compile_kind"] != 0:
            raise ValueError("oracle native library flags or target differ")
        features = json.loads(config["features"])
        if package == "sha2" and (features != ["default", "std"] or row["version"] != "0.10.9"):
            raise ValueError("expected the pinned ordinary SHA-256 library")
        declared = set(row.get("dependencies", []))
        seen[path] = row["version"]
        bound[path] = sha(regular(path))
        edges = []
        for _, name, host, dependency_hash in config["deps"]:
            if host:
                raise ValueError("unexpected host-only library edge")
            marker = dependency_hash.to_bytes(8, "little").hex()
            if name == "build_script_build":
                # Cargo stores an executed build-script marker separately.
                matches = [p for p in fingerprints.glob(f"{package}-*/run-build-script-build-script-build")
                           if regular(p).decode().strip() == marker]
                [run] = matches
                edges.append({"cargo_executed_build_script": marker,
                              "marker_sha256": sha(regular(run)),
                              "receipt_sha256": sha(regular(run.with_suffix(".json")))})
                continue
            dep_package = name.replace("_", "-")
            markers = [p for p in fingerprints.glob(f"{dep_package}-*/lib-{name}")
                       if regular(p).decode().strip() == marker]
            [matched] = markers
            dep_suffix = matched.parent.name.split("-")[-1]
            dep_version = visit(dep_package, deps / f"lib{name}-{dep_suffix}.rlib")
            if dep_package not in declared and f"{dep_package} {dep_version}" not in declared:
                raise ValueError("oracle artifact dependency differs from original lock")
            edges.append({"package": dep_package, "version": dep_version, "cargo_fingerprint": marker})
        details[path.stem] = {"package": package, "version": row["version"],
                              "registry_checksum": row["checksum"], "features": features,
                              "artifact_sha256": bound[path], "dep_info_sha256": sha(regular(dep)),
                              "fingerprint_sha256": sha(regular(fp)), "edges": edges}
        return row["version"]

    details = {}
    visit("sha2", artifact)
    return rust, details, bound


def build(work, *, with_closure=False, with_model_root=False, with_tensor_contract=False,
          with_tensor_model_manifest=False):
    path = Path(os.environ[ENV]).absolute()
    rust, graph, bound = dependency_graph(path)
    source_path, binary = work / "original.rs", work / "original"
    raw = source(with_closure=with_closure, with_model_root=with_model_root,
                 with_tensor_contract=with_tensor_contract,
                 with_tensor_model_manifest=with_tensor_model_manifest)
    source_path.write_bytes(raw)
    observe = BINDING_ADAPTER.read_bytes()
    (work / "binding_observation.rs").write_bytes(observe)
    extra_proof = {}
    if with_tensor_model_manifest:
        for name, target in (("closure", "closure"), ("model_root", "model_root"),
                             ("tensor_contract", "tensor_contract"), ("tensor_model", "tensor_model")):
            observer = Path(__file__).with_name(f"rust_cell_{name}_reference.rs").read_bytes()
            (work / f"{target}_observation.rs").write_bytes(observer)
            extra_proof[f"oracle_{name}_observer_sha256"] = sha(observer)
        extra_proof.update(original_closure_source_sha256=sha(CLOSURE.read_bytes()),
                           original_model_root_source_sha256=sha(MODEL_ROOT.read_bytes()),
                           original_tensor_model_source_sha256=sha(TENSOR_CONTRACT.read_bytes()),
                           original_tensor_model_pure_extract_sha256=sha(tensor_contract_source(with_model_manifest=True)))
    elif with_tensor_contract:
        observer = Path(__file__).with_name("rust_cell_tensor_contract_reference.rs").read_bytes()
        (work / "tensor_contract_observation.rs").write_bytes(observer)
        extra_proof = {"original_tensor_contract_source_sha256": sha(TENSOR_CONTRACT.read_bytes()),
                       "original_tensor_contract_pure_extract_sha256": sha(tensor_contract_source()),
                       "oracle_tensor_contract_observer_sha256": sha(observer)}
    elif with_closure or with_model_root:
        closure_observer = Path(__file__).with_name("rust_cell_closure_reference.rs").read_bytes()
        (work / "closure_observation.rs").write_bytes(closure_observer)
        extra_proof = {"original_closure_source_sha256": sha(CLOSURE.read_bytes()),
                       "oracle_closure_observer_sha256": sha(closure_observer)}
        if with_model_root:
            root_observer = Path(__file__).with_name("rust_cell_model_root_reference.rs").read_bytes()
            (work / "model_root_observation.rs").write_bytes(root_observer)
            extra_proof.update(original_model_root_source_sha256=sha(MODEL_ROOT.read_bytes()),
                               oracle_model_root_observer_sha256=sha(root_observer))
    else:
        extra_proof = {"original_binding_source_sha256": sha(binding_source()),
                       "oracle_binding_observer_sha256": sha(observe)}
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "-L", f"dependency={path.parent}",
                    "--extern", f"sha2={path}", source_path, "-o", binary],
                   check=True, timeout=45, capture_output=True)
    if any(sha(regular(p)) != expected for p, expected in bound.items()):
        raise ValueError("locked oracle library changed during linking")
    return binary, {"mode": "verified-prebuilt-original-sha2", "cargo_lock_sha256": sha(LOCK.read_bytes()),
                    "original_manifest_source_sha256": sha(CODEC.read_bytes()),
                    "oracle_source_sha256": sha(raw), "oracle_sha256": sha(binary.read_bytes()),
                    "rustc": rust, "locked_graph": graph, **extra_proof}
