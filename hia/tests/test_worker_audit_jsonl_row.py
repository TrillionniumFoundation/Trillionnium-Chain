"""Worker-only native row bytes versus the active original Rust/Serde path.

The Rust adapter does not implement formatting. We extract the complete
active declaration including derive and attributes, compile its exact locked
Serde dependency closure, and call the same to_string used by export-audit.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule


ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / "trillionnium/crates/trnm-worker-agent"
HIA = ROOT / "hia/src/worker_agent/audit_jsonl_row.hepta"
LOCK = ROOT / "trillionnium/Cargo.lock"
PACKAGE = "trnm-worker-audit-jsonl-reference"
FIELDS = (
    "request_id", "task_id", "status", "provider_request_id",
    "provenance_schema_version", "provenance_fingerprint", "provider",
    "model", "adapter", "agent_protocol", "compliance_profile",
    "reputation_label", "reputation_delta", "reputation_tier",
    "reputation_weight_bps", "reputation_score_bps", "reputation_rank_ordinal",
    "reputation_gap_bps_from_best",
)
TEXT = (0, *range(2, 12))
NUMERIC = (1, *range(12, 18))
WIRE = struct.Struct("<4sI7Q11I")
INVALID, INSUFFICIENT = 0xFFFFFFFF, 0xFFFFFFFE
FILL = b"\xa5"
SCRATCH = b"\x19\x7e\xa3"
SOURCE = r'''
use std::io::{self, BufRead, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sink = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let row: EnterpriseAuditExportRecord = serde_json::from_str(&line?)?;
        let line = serde_json::to_string(&row)?;
        sink.write_all(line.as_bytes())?;
        sink.write_all(b"\n")?;
    }
    Ok(())
}
'''


def identity(data):
    return hashlib.sha256(data).hexdigest()


def rust_declaration():
    active, main, dispatch = (
        (WORKER / f"src/{name}.rs").read_bytes()
        for name in ("audit", "main", "dispatch")
    )
    if (b"\nmod audit;\n" not in main
            or b"use audit::{handle_export_audit, handle_query_audit};" not in main
            or b"} => handle_export_audit(ingress_file, output_file)?," not in dispatch
            or b"let line = serde_json::to_string(export)?;\n"
               b"                file.write_all(line.as_bytes())?;\n"
               b'                file.write_all(b"\\n")?;' not in active):
        raise AssertionError("Active Worker audit export production seam changed")
    declarations = re.findall(
        rb"(?ms)^#\[derive\(Debug, Clone, Serialize, Deserialize, PartialEq, Eq\)\]\n"
        rb"pub\(crate\) struct EnterpriseAuditExportRecord \{\n.*?^\}\n",
        active,
    )
    if len(declarations) != 1:
        raise AssertionError("Expected exactly one active Worker audit record")
    fields = re.findall(rb"(?m)^    pub\(crate\) (\w+): ", declarations[0])
    if tuple(x.decode("ascii") for x in fields) != FIELDS:
        raise AssertionError("Active Worker audit declaration order changed")
    return declarations[0]


def locked_dependencies():
    workspace = tomllib.loads(LOCK.read_text())
    if workspace["version"] != 4:
        raise AssertionError("Review Worker adapter projection for a new Cargo.lock format")
    names = collections.defaultdict(list)
    for pkg in workspace["package"]:
        names[pkg["name"]].append(pkg)
    selected = {}

    def visit(edge):
        name, *version = edge.split()
        matches = [row for row in names[name] if not version or row["version"] == version[0]]
        if len(matches) != 1 or len(version) > 1:
            raise AssertionError(f"Ambiguous locked audit dependency: {edge!r}")
        candidate, = matches
        if name in selected:
            if selected[name] != candidate:
                raise AssertionError(f"Multiple revisions required for {name!r}")
            return
        if (candidate.get("source") != "registry+https://github.com/rust-lang/crates.io-index"
                or re.fullmatch("[0-9a-f]{64}", candidate.get("checksum", "")) is None):
            raise AssertionError(f"Audit helper dependency is not registry-locked: {name!r}")
        selected[name] = candidate
        for dep in candidate.get("dependencies", []):
            visit(dep)

    visit("serde")
    visit("serde_json")
    return selected


def build_rust_oracle(directory):
    deps = locked_dependencies()
    (directory / "Cargo.toml").write_text(f'''
[package]
name = "{PACKAGE}"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
serde = {{ version = "={deps["serde"]["version"]}", features = ["derive"] }}
serde_json = "={deps["serde_json"]["version"]}"
'''.lstrip())
    rows = {
        **deps,
        PACKAGE: {"name": PACKAGE, "version": "0.0.0", "dependencies": ["serde", "serde_json"]},
    }
    projected = ["version = 4", ""]
    for name, row in sorted(rows.items()):
        projected.append("[[package]]")
        projected.extend(f"{key} = {json.dumps(row[key])}"
                         for key in ("name", "version", "source", "checksum") if key in row)
        if row.get("dependencies"):
            projected.append("dependencies = [")
            for edge in row["dependencies"]:
                # The original lock can qualify a name with its version when
                # other workspace consumers select additional versions.
                # This closed subgraph has exactly one version per name.
                target = edge.split()[0]
                if target not in deps:
                    raise AssertionError(f"Missing dependency from locked projection: {edge}")
                projected.append(f" {json.dumps(target)},")
            projected.append("]")
        projected.append("")
    projected_lock = "\n".join(projected).encode("ascii")
    (directory / "Cargo.lock").write_bytes(projected_lock)
    declaration = rust_declaration()
    (directory / "src").mkdir()
    (directory / "src/main.rs").write_bytes(
        b"use serde::{Deserialize, Serialize};\n" + declaration + SOURCE.encode("ascii"))
    cargo, rustc = os.environ.get("CARGO", "cargo"), os.environ.get("RUSTC", "rustc")
    tools = {}
    for cmd, name in ((cargo, "cargo"), (rustc, "rustc")):
        observed = subprocess.run([cmd, "--version"], check=True, capture_output=True,
                                  timeout=15, text=True).stdout.strip()
        if observed.split()[:2] != [name, "1.95.0"]:
            raise AssertionError(f"Pinned {name} 1.95.0 required, observed {observed!r}")
        tools[name] = observed
    env = dict(os.environ, RUSTC=rustc, CARGO_TARGET_DIR=str(directory / "target"),
               CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_BUILD_JOBS="1")
    result = subprocess.run([cargo, "build", "--offline", "--locked", "--message-format=json",
                             "--manifest-path", str(directory / "Cargo.toml")],
                            cwd=directory, env=env, capture_output=True, timeout=180)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    built = []
    observed = {}
    for line in result.stdout.splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact":
            continue
        if row.get("executable") and row["target"]["name"] == PACKAGE:
            built.append(Path(row["executable"]))
        package_id = row.get("package_id", "")
        for name, dependency in deps.items():
            if package_id.endswith(f"#{name}@{dependency['version']}"):
                observed[name] = dependency["version"]
    if len(built) != 1 or observed != {n: row["version"] for n, row in deps.items()}:
        raise AssertionError("Build did not observe every expected pinned crate and the oracle")
    if (directory / "Cargo.lock").read_bytes() != projected_lock:
        raise AssertionError("Locked build changed the projected dependency graph")
    return built[0], {
        "cargo_lock_sha256": identity(LOCK.read_bytes()),
        "projected_lock_sha256": identity(projected_lock),
        "rust_declaration_sha256": identity(declaration),
        "oracle_sha256": identity(built[0].read_bytes()),
        "tools": tools,
        "actual_locked_packages": sorted(observed.items()),
    }


def frame(record):
    present = sum(1 << (i - 3) for i in range(3, 18) if record[i] is not None)
    numbers = [(record[i] or 0) & (0xFFFFFFFF if i in (12, 15, 17) else 0xFFFFFFFFFFFFFFFF)
               for i in NUMERIC]
    texts = [record[i].encode("utf-8") if record[i] is not None else b"" for i in TEXT]
    return WIRE.pack(b"WJL1", present, *numbers, *(len(x) for x in texts)) + b"".join(texts)


def records():
    base = ("", 0, "", *([None] * 15))
    maximum = ("請求✦", (1 << 64) - 1, "ready\n\t",
               "", "字𐀀", "a" + "".join(chr(i) for i in range(0x20)) + '"\\/',
               "with pipe|", "emoji 😀😀", "x\x7f", "a\u2028b\u2029c", "e\u0301", "last ",
               -(1 << 31), 255, 65535, (1 << 31) - 1, 0, -1)
    result = [base, maximum, ("A" * 16_383 + "\0𐀀\n", *maximum[1:])]
    for i in range(3, len(FIELDS)):
        row = list(base)
        row[i] = "" if i in TEXT else 0
        result.append(tuple(row))
        row[i] = maximum[i]
        result.append(tuple(row))
    rng = random.Random(0x574A4C31)
    for n in range(24):
        cells = ["r" + str(n), rng.getrandbits(64), "status"]
        for i in range(3, 18):
            if rng.randrange(4) == 0:
                cells.append(None)
            elif i in TEXT:
                cells.append("".join(rng.choice("ab😀\"\\\r\n\t\x1f") for _ in range(rng.randrange(18))))
            elif i in (12, 15, 17):
                cells.append(rng.randrange(-(1 << 31), 1 << 31))
            else:
                cells.append(rng.randrange(1 << (16 if i == 14 else 8)))
        result.append(tuple(cells))
    return result


def invalid_frames(valid):
    def put(offset, replacement):
        return valid[:offset] + replacement + valid[offset + len(replacement):]

    split_utf8 = (b"\xc3", b"\xa9")
    fragmented = WIRE.pack(b"WJL1", 0, *([0] * 7), 1, 1, *([0] * 9)) + b"".join(split_utf8)
    late = frame(("", 8, "ready", *([None] * 8), "A", *([None] * 6)))
    return [b"", valid[:3], valid[:107], valid[:-1], valid + b"x", b"other",
            put(0, b"WJL2"), put(4, (1 << 15).to_bytes(4, "little")),
            put(64, b"\xff" * 4),
            WIRE.pack(b"WJL1", 0, *([0] * 7), 0, 0, 1, *([0] * 8)) + b"x",
            put(16, (1 << 32).to_bytes(8, "little")),
            put(24, (1 << 8).to_bytes(8, "little")),
            put(32, (1 << 16).to_bytes(8, "little")),
            put(40, (1 << 32).to_bytes(8, "little")),
            put(48, (1 << 8).to_bytes(8, "little")),
            put(56, (1 << 32).to_bytes(8, "little")), fragmented, late[:-1] + b"\xff"]


class WorkerAuditJsonlRow(unittest.TestCase):
    def test_native_rows_match_actual_locked_rust_and_refuse_atomically(self):
        rows = records()
        with tempfile.TemporaryDirectory(prefix="trnm-worker-jsonl-") as tmp:
            oracle, proof = build_rust_oracle(Path(tmp))
            # This is only a typed fixture input to the Rust process. Sorting
            # keeps the input object order independent from the output oracle.
            input_data = b"".join((json.dumps(dict(zip(FIELDS, row, strict=True)),
                                              sort_keys=True) + "\n").encode() for row in rows)
            replay = subprocess.run([str(oracle)], check=True, capture_output=True,
                                    input=input_data, timeout=30)
            self.assertEqual(replay.stderr, b"")
        original = replay.stdout.splitlines(keepends=True)
        self.assertEqual(len(original), len(rows))
        self.assertTrue(original[0].startswith(b'{"request_id":"","task_id":0,"status":"'))
        self.assertIn(b'"provider_request_id":null', original[0])
        self.assertIn(b'"provider_request_id":""', original[1])
        self.assertIn(b'"reputation_rank_ordinal":0', original[1])
        self.assertEqual(json.loads(original[1]), dict(zip(FIELDS, rows[1], strict=True)))
        runs = {}
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(HIA, backend=backend,
                                                            byte_exports=("f0",)) as native:
                payloads = [frame(row) for row in rows]
                cases = []
                for j, (request, expected) in enumerate(zip(payloads, original, strict=True)):
                    cases.append((request, len(expected) + (12 if j % 2 == 0 else 0),
                                  len(expected), expected))
                for j in (0, 1, 2):
                    cases.append((payloads[j], len(original[j]) - 1, INSUFFICIENT, b""))
                cases.append((payloads[1], 0, INSUFFICIENT, b""))
                invalid = invalid_frames(payloads[1])
                for j, request in enumerate(invalid):
                    cases.append((request, 1024 if j % 2 else 0, INVALID, b""))
                for start in range(0, len(cases), 16):
                    batch = cases[start:start + 16]
                    results = native.call_many([("f0", [request, FILL * cap, SCRATCH])
                                                for request, cap, _, _ in batch])
                    for case, result in zip(batch, results, strict=True):
                        request, cap, answer, expected = case
                        result.require_returned()
                        self.assertEqual(result.value, answer)
                        self.assertEqual(result.arguments,
                                         [request, expected + FILL * (cap - len(expected)), SCRATCH])
                runs[backend] = {"artifact_sha256": native.artifact_sha256,
                                 "parity_rows": len(rows), "atomic_refusals": len(cases) - len(rows)}
        print(json.dumps({**proof, "native": runs, "oracle_output_sha256": identity(replay.stdout),
                          "scope": "typed Worker row, not production CLI"}, sort_keys=True))
