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
ADAPTER = Path(__file__).with_name("rust_cell_manifest_reference.rs")
ENV = "HIA_M09_SHA2_RLIB"


def source():
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
    return (shell + digest + result + check + b"#[allow(dead_code)]\nmod manifest {\n" +
            wire + b"\n}\n" + ADAPTER.read_bytes())


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


def build(work):
    path = Path(os.environ[ENV]).absolute()
    rust, graph, bound = dependency_graph(path)
    source_path, binary = work / "original.rs", work / "original"
    raw = source()
    source_path.write_bytes(raw)
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "-L", f"dependency={path.parent}",
                    "--extern", f"sha2={path}", source_path, "-o", binary],
                   check=True, timeout=45, capture_output=True)
    if any(sha(regular(p)) != expected for p, expected in bound.items()):
        raise ValueError("locked oracle library changed during linking")
    return binary, {"mode": "verified-prebuilt-original-sha2", "cargo_lock_sha256": sha(LOCK.read_bytes()),
                    "original_manifest_source_sha256": sha(CODEC.read_bytes()),
                    "oracle_source_sha256": sha(raw), "oracle_sha256": sha(binary.read_bytes()),
                    "rustc": rust, "locked_graph": graph}
