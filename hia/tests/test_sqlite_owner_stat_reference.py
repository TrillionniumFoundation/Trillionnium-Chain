"""Original-side descriptor observation prerequisite, not a native HIA claim."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import tomllib
import unittest

from hia.tests.test_settlement_schema_read import execute
from hia.platform.build import Build, inspect_executable

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "hia/platform/service_settlement/qualification/original_sources.json"
WITNESS = ROOT / "hia/tests/rust_sqlite_owner_stat_reference.rs"
EMITTER = ROOT / "hia/platform/sqlite_owner_stat/emit.hepta"
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
        self.check_held_stat(native=False)

    def test_pinned_native_and_original_same_inode_stat(self):
        self.check_held_stat(native=True)

    def check_held_stat(self, *, native):
        originals = checked_original()
        witness = pinned(WITNESS, "cbfa1d2703ce4d355119a39c836e975959b774e6423cbf13d08e433c1a3a0870")
        cargo, env = tool_environment()
        env.pop("TRNM_TEST_OWNED_STAT_IMAGE", None)
        with tempfile.TemporaryDirectory(prefix="m15-stat-") as directory:
            root = Path(directory)
            if native:
                image = self.native_image(root)
                env["TRNM_TEST_OWNED_STAT_IMAGE"] = str(image)
                self.check_native_refusals(root, image)
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
            pairs = [s for s in run.splitlines() if s.startswith(b"owner-stat-native-v1|")]
            self.assertEqual(pairs, [f"owner-stat-native-v1|{n}|paired-112".encode()
                                     for n in (0, 3, 8193)] if native else [])
            self.assertIn(b"1 passed; 0 failed", run)
            full = execute([cargo, "test", *args], env=env, cwd=root, timeout=160).stdout
            self.assertIn(b"24 passed; 0 failed; 0 ignored", full)
            execute([cargo, "build", *args], env=env, cwd=root, timeout=160)
            self.assertNotIn(MARKER, (root / "target/debug/libtrnm_sqlite_io_boundary.rlib").read_bytes())
        self.assertEqual(checked_original(), originals)

    def native_image(self, root):
        native = Build(root / "native-build")
        source = pinned(EMITTER, "5114c59dab5ba5191e3038a70f26faa67ca01188cf14fe057033d6eb52fc99d6")
        emitter = native.stage(native.compiler, source, "compile-stat-emitter")
        inspect_executable(emitter)
        image = native.stage(emitter, b"", "emit-owned-stat-v1")
        inspect_executable(image)
        self.assertEqual(len(image), 684)
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         "092f350e2169ab37df0d15871e37922c4c691acd197eeb243a8868766039332f")
        self.assertTrue(image.endswith(b".\0native.sqlite\0"))
        native.check_pin()
        path = root / "owned-stat-linux-x86-64"
        path.write_bytes(image)
        path.chmod(0o500)
        return path

    def check_native_refusals(self, root, image):
        directory = root / "native-refusals"
        directory.mkdir(mode=0o700)
        leaf = directory / "native.sqlite"

        def refuse(*extra):
            result = subprocess.run([image, *extra], cwd=directory, env={},
                                    input=b"", capture_output=True, timeout=3)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (70, b"", b""))

        refuse()  # no file
        leaf.write_bytes(b"")
        leaf.chmod(0o640)
        refuse()  # not the fixture's private mode
        leaf.chmod(0o600)
        refuse("unexpected")
        leaf.write_bytes(bytes(8194))
        refuse()  # exceeds the closed fixture profile
        self.assertEqual(leaf.read_bytes(), bytes(8194))
