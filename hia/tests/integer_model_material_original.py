"""Real offline Rust/Serde reference for a source-bound model material fixture."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

from hia.tests.test_integer_model_codec import LEGACY, PROTO, SHA_ADAPTER
from hia.tests.test_verification_profile_registry import ROOT, pick
from hia.tests.test_worker_audit_jsonl_row import locked_dependencies

LOCK = ROOT / "trillionnium/Cargo.lock"
ADAPTER = Path(__file__).with_name("rust_integer_model_material_reference.rs")
PACKAGE = "trnm-model-material-reference"
BINARIES = ("serde_json", "hex", "serde_core", "itoa", "memchr", "zmij")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def source():
    old = LEGACY.read_bytes()
    start = old.index(b"pub struct IntegerModelV2")
    end = old.index(b"struct ReadState", start)
    model = old[old.rfind(b"#[derive", 0, start):end]
    constants = [pick(old, rb"^pub const " + tag + rb":[^\n]+;\n") for tag in
                 (b"MODEL_BYTES", b"EVOLUTION_MODEL_BYTES", b"MAX_MODEL_BYTES", b"CHUNK_BYTES")]
    binary = (PROTO / "integer_factor_v2.rs").read_bytes()
    geometry = [pick(binary, rb"^pub const " + tag + rb":[^\n]+;\n") for tag in (b"ROWS", b"COLUMNS")]
    protocol = (PROTO / "pon_wire.rs").read_bytes()
    framing = pick(protocol, rb"^pub fn hash\([^\n]+\n.*?^}\n")
    hash_type = pick(protocol, rb"^pub type Hash = \[u8; 32\];\n")
    functions = [pick(old, rb"^fn " + tag + rb"\([^\n]+\n.*?^}\n")
                 for tag in (b"ensure", b"prefix")]
    a = old.index(b"pub(crate) fn load_model(")
    b = old.index(b"pub(crate) fn parent(", a)
    seam = SHA_ADAPTER.read_bytes()
    seam = seam[seam.index(b"use std::io"):seam.index(b"fn array")]
    return (seam.replace(b", Read, Write", b", Write", 1) + b"use serde_json::{json, Value};\nuse std::collections::BTreeMap;\n"
            b"type State = BTreeMap<String, Value>;\n"
            b"type Result<T> = std::result::Result<T, &'static str>;\n"
            + b"".join(constants + geometry) + hash_type + framing + b"".join(functions)
            + model + old[a:b] + ADAPTER.read_bytes())


def pin():
    rust = subprocess.run(["rustc", "-vV"], check=True, capture_output=True, timeout=10).stdout.decode()
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if rust.split()[:2] != ["rustc", toolchain]:
        raise ValueError("source-bound oracle requires the repository's pinned rustc")
    return rust


def verified_prebuilt(work, target, raw):
    target = Path(target).absolute()
    if target.resolve(strict=True) != target:
        raise ValueError("prebuilt target must be a direct directory")
    deps = target / "debug/deps"
    records = tomllib.loads(LOCK.read_text())["package"]
    if not any(x.get("stdout") == pin() and x.get("success") is True for x in
               json.loads((target / ".rustc_info.json").read_bytes())["outputs"].values()):
        raise ValueError("prebuilt dependency compiler differs")
    entries = {}
    files = {}
    for name in BINARIES:
        rows = [r for r in records if r["name"] == name]
        [row] = rows
        if (row["source"] != "registry+https://github.com/rust-lang/crates.io-index"
                or re.fullmatch("[a-f0-9]{64}", row["checksum"]) is None):
            raise ValueError("prebuilt dependency not in original lock")
        [artifact] = deps.glob(f"lib{name}-*.rlib")
        stem = artifact.stem[3:]
        info = deps / f"{stem}.d"
        fingerprint = target / f"debug/.fingerprint/{stem}/lib-{name}.json"
        for path in (artifact, info, fingerprint):
            if path.resolve(strict=True) != path or not path.is_file():
                raise ValueError("nonregular prebuilt evidence")
        if f"/{name}-{row['version']}/src/lib.rs" not in info.read_text().splitlines()[0]:
            raise ValueError("prebuilt dependency source version differs")
        info_doc = json.loads(fingerprint.read_bytes())
        if info_doc["rustflags"] or info_doc["compile_kind"] != 0:
            raise ValueError("prebuilt compiler flags or target differ")
        entries[name] = {"version": row["version"], "registry_checksum": row["checksum"],
                         "artifact_sha256": sha(artifact.read_bytes()),
                         "dep_info_sha256": sha(info.read_bytes()),
                         "fingerprint_sha256": sha(fingerprint.read_bytes())}
        files[name] = artifact
    src, binary = work / "oracle-source.rs", work / "oracle"
    src.write_bytes(raw)
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "-L", f"dependency={deps}",
                    "--extern", f"serde_json={files['serde_json']}", "--extern", f"hex={files['hex']}",
                    src, "-o", binary], check=True, timeout=45)
    if any(sha(path.read_bytes()) != entries[name]["artifact_sha256"] for name, path in files.items()):
        raise ValueError("a bound original artifact changed while linking")
    return binary, {"mode": "verified-prebuilt-original-lock", "locked_artifacts": entries}


def cargo_offline(work, raw):
    # Same original lock projection as the tracked Worker JSONL oracle, plus hex.
    deps = locked_dependencies()
    [hexc] = [row for row in tomllib.loads(LOCK.read_text())["package"] if row["name"] == "hex"]
    if hexc.get("dependencies") or re.fullmatch("[a-f0-9]{64}", hexc["checksum"]) is None:
        raise ValueError("the original Hex lock changed")
    deps = {**deps, "hex": hexc}
    locks = {**deps, PACKAGE: {"name": PACKAGE, "version": "0.0.0",
                             "dependencies": ["serde", "serde_json", "hex"]}}
    manifest = f"""[package]
name = "{PACKAGE}"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
serde = {{ version = "={deps['serde']['version']}", features = ["derive"] }}
serde_json = "={deps['serde_json']['version']}"
hex = "={hexc['version']}"
"""
    (work / "Cargo.toml").write_text(manifest)
    rows = ["version = 4", ""]
    for _, row in sorted(locks.items()):
        rows.append("[[package]]")
        rows.extend(f"{k} = {json.dumps(row[k])}" for k in ("name", "version", "source", "checksum") if k in row)
        if row.get("dependencies"):
            links = [edge.split()[0] for edge in row["dependencies"]]
            if not set(links) <= set(deps):
                raise ValueError("lock projection missing a dependency")
            rows.append("dependencies = " + json.dumps(links))
        rows.append("")
    projected = "\n".join(rows).encode("ascii")
    (work / "Cargo.lock").write_bytes(projected)
    (work / "src").mkdir()
    (work / "src/main.rs").write_bytes(raw)
    cargo = subprocess.run(["cargo", "--version"], check=True, capture_output=True, timeout=10).stdout
    if cargo.split()[:2] != [b"cargo", pin().split()[1].encode()]:
        raise ValueError("genuine original oracle requires pinned Cargo")
    env = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
               CARGO_BUILD_JOBS="1", CARGO_TARGET_DIR=str(work / "target"))
    run = subprocess.run(["cargo", "build", "--offline", "--locked", "--message-format=json"],
                         cwd=work, env=env, check=True, capture_output=True, timeout=180)
    bins, found = [], {}
    for row in map(json.loads, run.stdout.splitlines()):
        if row.get("reason") != "compiler-artifact":
            continue
        if row.get("executable") and row["target"]["name"] == PACKAGE:
            bins.append(Path(row["executable"]))
        for name, dep in deps.items():
            if row.get("package_id", "").endswith(f"#{name}@{dep['version']}"):
                found[name] = dep["version"]
    [binary] = bins
    if (work / "Cargo.lock").read_bytes() != projected or found != {k:v["version"] for k,v in deps.items()}:
        raise ValueError("tiny original build did not use the exact locked projection")
    return binary, {"mode": "tiny-locked-offline-cargo", "projected_lock_sha256": sha(projected),
                    "actual_locked_packages": found}


def build(work):
    raw = source()
    prebuilt = os.environ.get("HIA_M06_ORACLE_PREBUILT")
    if prebuilt and os.environ.get("HIA_M06_LOCKED_CARGO_ORACLE") == "1":
        raise ValueError("select one genuine original oracle mode")
    if prebuilt:
        binary, proof = verified_prebuilt(work, prebuilt, raw)
    else:
        binary, proof = cargo_offline(work, raw)
    proof.update(source_sha256=sha(raw), oracle_sha256=sha(binary.read_bytes()), rustc=pin(),
                 cargo_lock_sha256=sha(LOCK.read_bytes()))
    return binary, proof
