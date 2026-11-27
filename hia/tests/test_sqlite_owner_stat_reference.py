"""Original-side descriptor observation prerequisite, not a native HIA claim."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest

from hia.tests.test_settlement_schema_read import execute

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "hia/platform/service_settlement/qualification/original_sources.json"
WITNESS = ROOT / "hia/tests/rust_sqlite_owner_stat_reference.rs"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
LIB = Path("trillionnium/crates/trnm-sqlite-io-boundary/src/lib.rs")
TEST = LIB.with_name("owner_stat_witness.rs")
INJECTION = b'\n#[cfg(all(test, target_os = "linux"))]\nmod owner_stat_witness;\n'
FILTER = "owner_stat_witness::original_fd_and_held_name_observation"
MARKER = b"owner-stat-v1|"


def pinned(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"Immutable input differs: {path.name}")
    return data


def checked_original():
    manifest = json.loads(pinned(MAP, "5a9956bb08fdc4f14d5090a3e020a3a3e4a328796faab6512d4163a222d7b3bc"))
    tree = execute(["git", "-C", ROOT, "ls-tree", "-rz", "--full-tree", "HEAD", "trillionnium"]).stdout
    records = {}
    for line in tree.rstrip(b"\0").split(b"\0"):
        meta, raw = line.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        rel = raw.decode("utf-8")
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError(f"Nonordinary original source: {rel}")
        records[rel] = (blob, mode)
    if len(manifest) != 1700 or records.keys() != manifest.keys():
        raise ValueError("Original immutable source roster differs")
    captured = {}
    for rel, entry in manifest.items():
        blob, mode = records[rel]
        path = ROOT / rel
        if not path.is_file() or path.resolve(strict=True) != path:
            raise ValueError(f"Nonordinary original workspace input: {rel}")
        data = pinned(path, entry["sha256"])
        git_blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        if len(data) != entry["bytes"] or git_blob != blob or blob != entry["git_blob"]:
            raise ValueError(f"Original immutable bytes differ: {rel}")
        captured[Path(rel)] = (data, int(mode, 8) & 0o777)
    return captured


def tool_environment():
    pin = tomllib.loads(pinned(TOOLCHAIN, "24ef3b9d3edbd850aa386cb0a98e10450b0030991a4537cb359f54d49dbbb33a").decode())["toolchain"]["channel"]
    requested = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    first = execute([requested, "--version"]).stdout
    sysroot = Path(execute([requested, "--print", "sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc, cargo, lib = sysroot / "bin/rustc", sysroot / "bin/cargo", sysroot / "lib"
    if (first.decode().split()[1] != pin or execute([rustc, "--version"]).stdout != first
            or any(path.resolve(strict=True) != path for path in (rustc, cargo, lib))
            or not lib.is_dir() or os.environ.get("LD_LIBRARY_PATH") not in (None, "", str(lib))):
        raise ValueError("Original build tool or approved canonical loader differs")
    return cargo, {**os.environ, "RUSTC": str(rustc), "LD_LIBRARY_PATH": str(lib), "CARGO_BUILD_JOBS": "2"}


class SqliteOwnerStatReferenceTests(unittest.TestCase):
    def test_original_held_stat_and_bind(self):
        originals = checked_original()
        witness = pinned(WITNESS, "67df8e9a3588daf2166e019a955d483d5398bb6451edb1146ae09049787e5eac")
        cargo, env = tool_environment()
        with tempfile.TemporaryDirectory(prefix="m15-stat-") as directory:
            root = Path(directory)
            self.assertNotIn(TEST, originals)
            for rel, (data, mode) in originals.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(mode)
            (root / LIB).write_bytes(originals[LIB][0] + INJECTION)
            (root / TEST).write_bytes(witness)
            files = {p.relative_to(root) for p in (root / "trillionnium").rglob("*") if p.is_file()}
            self.assertEqual(files, originals.keys() | {TEST})
            for rel, (data, _) in originals.items():
                self.assertEqual((root / rel).read_bytes(), data + (INJECTION if rel == LIB else b""), rel)
            self.assertEqual((root / TEST).read_bytes(), witness)
            args = ["--locked", "--offline", "--manifest-path", root / "trillionnium/Cargo.toml",
                    "--target-dir", root / "target", "-p", "trnm-sqlite-io-boundary", "--lib"]
            run = execute([cargo, "test", *args, FILTER, "--", "--exact", "--nocapture"],
                          env=env, cwd=root, timeout=160).stdout
            rows = []
            for line in run.splitlines():
                if line.startswith(MARKER):
                    _, length, fd, named = line.split(b"|")
                    fd, named = json.loads(fd), json.loads(named)
                    self.assertEqual(fd, named)
                    self.assertEqual(len(fd), 7)
                    self.assertEqual(fd[4:6], [1, int(length)])
                    rows.append(fd)
            self.assertEqual([row[5] for row in rows], [0, 3, 8193])
            self.assertTrue(all(row[:5] == rows[0][:5] for row in rows))
            self.assertIn(b"1 passed; 0 failed", run)
            full = execute([cargo, "test", *args], env=env, cwd=root, timeout=160).stdout
            self.assertIn(b"24 passed; 0 failed; 0 ignored", full)
            execute([cargo, "build", *args], env=env, cwd=root, timeout=160)
            self.assertNotIn(MARKER, (root / "target/debug/libtrnm_sqlite_io_boundary.rlib").read_bytes())
        self.assertEqual(checked_original(), originals)
