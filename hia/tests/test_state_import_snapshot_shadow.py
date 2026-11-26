"""Real unchanged Rust SQLite cold export then independent native HIA commitment replay."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule, unlinked_path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/durable_snapshot_shadow.hepta"
MANIFEST = ROOT / "trillionnium/Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
CRATE = ROOT / "trillionnium/crates/trnm-state-import"
ADAPTER = ROOT / "hia/tests/rust_state_import_snapshot_shadow_reference.rs"


def _run(command, *, timeout=30, **kwargs):
    out = subprocess.run(command, capture_output=True, timeout=timeout, **kwargs)
    if out.returncode:
        raise ValueError(f"Original StateImport command failed: {out.stderr.decode(errors='replace')}")
    return out


def _build_original(directory, adapter=ADAPTER):
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    version = _run([rustc, "--version"]).stdout.decode().split()[1]
    expected = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version != expected:
        raise ValueError("The full original StateImport build needs the pinned Rust toolchain")
    build = _run(
        [cargo, "build", "--locked", "--offline", "--manifest-path", str(MANIFEST),
         "--target-dir", str(directory / "target"), "-p", "trnm-state-import", "--message-format=json"],
        timeout=160, env={**os.environ, "RUSTC": rustc},
    )
    events = [json.loads(line) for line in build.stdout.splitlines()]
    [library] = [e for e in events if e.get("reason") == "compiler-artifact"
                 and e["target"]["name"] == "trnm_state_import"]
    if (Path(library["target"]["src_path"]) != CRATE / "src/lib.rs"
            or Path(library["manifest_path"]) != CRATE / "Cargo.toml" or library["features"]):
        raise ValueError("Wrong original StateImport source or profile")
    [sqlite] = [e for e in events if e.get("reason") == "build-script-executed"
                and e["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [source] = [e for e in events if e.get("reason") == "compiler-artifact"
                and e["package_id"] == sqlite["package_id"] and e["target"]["name"] == "libsqlite3_sys"]
    sqlite_dependency = unlinked_path(source["manifest_path"]).parent
    [sqlite_native] = sqlite["linked_paths"]
    if sqlite["linked_libs"] != ["static=sqlite3"] or not sqlite_native.startswith("native="):
        raise ValueError("Original StateImport must link its locked bundled SQLite")
    native_path = unlinked_path(sqlite_native[7:], directory=True)
    [rust_artifact] = [unlinked_path(n) for n in library["filenames"] if n.endswith(".rlib")]
    deps = rust_artifact.parent / "deps"
    binary = directory / "snapshot-owner"
    _run([rustc, "--edition=2024", "-O", "--extern", f"trnm_state_import={rust_artifact}",
          "-L", f"dependency={deps}", "-L", f"native={native_path}", str(adapter), "-o", str(binary)],
         timeout=60)
    return binary, sqlite_dependency


def _digest(path):
    return hashlib.sha256(path.read_bytes()).digest()


def original_snapshots():
    bound = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
    before = tuple(_digest(p) for p in bound)
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-snapshot-") as tmp:
        directory = Path(tmp)
        binary, _ = _build_original(directory)
        snapshots = []
        def cold_export(db, count, generation):
            database = _digest(db)
            first = _run([binary, "export", db])
            again = _run([binary, "export", db])
            if (first.stderr or again.stderr or first.stdout != again.stdout
                    or len(first.stdout) < 272 or _digest(db) != database
                    or int.from_bytes(first.stdout[192:200], "big") != count
                    or int.from_bytes(first.stdout[200:208], "big") != generation):
                raise ValueError("Original repeated cold SQLite snapshots differ")
            snapshots.append((count, first.stdout))

        for count in (0, 1, 17, 257):
            db = directory / f"owned-{count}.db"
            seed = _run([binary, "seed", db, str(count)])
            if seed.stdout or seed.stderr or not db.is_file():
                raise ValueError("Original durable initialize did not publish the owned fixture")
            cold_export(db, count, 0)
        predecessor_db = _digest(db)
        advance = _run([binary, "advance", db])
        if advance.stdout or advance.stderr or _digest(db) == predecessor_db:
            raise ValueError("Original durable apply did not commit its successor")
        cold_export(db, 256, 1)
        zero, successor = snapshots[-2][1], snapshots[-1][1]
        if (zero[64:96] != successor[64:96]
                or any(zero[i:i + 32] == successor[i:i + 32] for i in (96, 128, 160))
                or successor[208:240] == bytes(32)):
            raise ValueError("Original successor did not change its context, commitment or root")
    if tuple(_digest(p) for p in bound) != before:
        raise ValueError("Original source or reference changed during SQLite qualification")
    return snapshots


class StateImportSnapshotShadow(unittest.TestCase):
    def test_original_sqlite_cold_exports_replay_in_both_native_backends(self):
        snapshots = original_snapshots()
        valid = [(row, count, 0) for count, row in snapshots]
        count, row = snapshots[-1]

        def updated(raw, at):
            return raw[:at] + bytes((raw[at] ^ 1,)) + raw[at + 1:]

        refused = [(updated(row, col), count, 111) for col in (0, 32, 64, 96, 160, 207, 208, 240)]
        refused += [(updated(row, 128), count, 110), (updated(row, 284), count, 101),
                    (row[:-1], count, 100), (row + b"\x00", count, 100)]
        _, previous = snapshots[-2]
        # Take exactly the first successor-count predecessor rows. The frame
        # remains well-formed and every row's own digest remains authentic.
        cut = 272
        for _ in range(count):
            cut += 44 + sum(int.from_bytes(previous[cut + i:cut + i + 4], "little") for i in (0, 4, 8))
        refused.append((row[:272] + previous[272:cut], count, 110))
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as module:
                cases = valid + refused
                args = [[wire, b"\xa5" * 37, b"\xcc" * (1400 + 32 * n)]
                        for wire, n, _ in cases]
                results = module.call_many([("f0", spans) for spans in args])
                for i, (got, (wire, _, status)) in enumerate(zip(results, cases)):
                    self.assertEqual(got.require_returned().value, status, i)
                    expected = wire[240:272] + b"\xa5" * 5 if status == 0 else args[i][1]
                    self.assertEqual(got.arguments[:2], [wire, expected], i)
