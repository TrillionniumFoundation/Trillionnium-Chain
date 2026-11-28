"""Probe the locked original DA constructor/Borsh and both emitted HIA objects."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule, unlinked_path

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "trillionnium"
MANIFEST = WORKSPACE / "Cargo.toml"
CRATE = WORKSPACE / "crates/trnm-data-availability"
CALLER = Path(__file__).with_name("rust_da_protocol_context_reference.rs")
SOURCE = ROOT / "hia/src/data_availability/protocol_context.hepta"
HEADER = bytes(range(64))
MARK = b"\xa5"
SCRATCH = b"\xc3" * 19


def _run(argv, data=None, timeout=180, env=None):
    return subprocess.run(argv, cwd=ROOT, input=data, check=True, capture_output=True,
                          timeout=timeout, env=env)


def locked_reference(directory, stream, caller=CALLER, *, extra_externs=()):
    bound = (MANIFEST, WORKSPACE / "Cargo.lock", CRATE / "Cargo.toml",
             CRATE / "src/types.rs", CRATE / "src/lib.rs", CRATE / "src/error.rs",
             ROOT / "rust-toolchain.toml", caller)

    def identities():
        return [hashlib.sha256(path.read_bytes()).digest() for path in bound]

    before = identities()
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    pinned = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if _run([rustc, "--version"]).stdout.decode().split()[1] != pinned:
        raise ValueError("Original DA qualification requires repository pinned Rust")
    target = directory / "cargo-target"
    build = _run([cargo, "build", "--manifest-path", str(MANIFEST), "--locked", "--offline",
                  "--package", "trnm-data-availability", "--lib", "--target-dir", str(target),
                  "--message-format=json"], env={**os.environ, "RUSTC": rustc,
                                                       "CARGO_INCREMENTAL": "0"})
    events = [json.loads(line) for line in build.stdout.splitlines()]
    if not events or events[-1] != {"reason": "build-finished", "success": True}:
        raise ValueError("No successful original Cargo build observation")

    def expected_artifact(name, locked_package=None):
        [event] = [row for row in events if row.get("reason") == "compiler-artifact"
                   and row["target"]["name"] == name and not row["profile"]["test"]
                   and (locked_package is None or row["package_id"].endswith("#" + locked_package))]
        [file] = [unlinked_path(path) for path in event["filenames"] if path.endswith(".rlib")]
        if not file.is_relative_to(target) or file.parent.name != "deps":
            # Cargo reports a top-level duplicate for the primary lib; take the
            # original path while using the exact same target's pinned deps.
            if file != target / "debug/libtrnm_data_availability.rlib":
                raise ValueError("Artifact is not in the private Cargo target")
        return event, file

    original, da = expected_artifact("trnm_data_availability")
    _, borsh = expected_artifact("borsh")
    if (Path(original["target"]["src_path"]) != CRATE / "src/lib.rs"
            or Path(original["manifest_path"]) != CRATE / "Cargo.toml" or original["features"] != ["default"]):
        raise ValueError("Unexpected original DA library identity")
    [sqlite] = [row for row in events if row.get("reason") == "build-script-executed"
                and row["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [library_path] = sqlite["linked_paths"]
    if not library_path.startswith("native=") or sqlite["linked_libs"] != ["static=sqlite3"]:
        raise ValueError("Original DA must use the locked bundled SQLite build")
    native = unlinked_path(library_path[7:], directory=True)
    if not native.is_relative_to(target):
        raise ValueError("Original SQLite library is outside the private target")
    extra = []
    if len(set(extra_externs)) != len(extra_externs) or set(extra_externs) - {"ed25519_dalek", "sha2"}:
        raise ValueError("Unexpected locked DA oracle dependency")
    locked_fixture_packages = {"ed25519_dalek": "ed25519-dalek@3.0.0", "sha2": "sha2@0.10.9"}
    for name in extra_externs:
        _, artifact = expected_artifact(name, locked_fixture_packages[name])
        extra.extend(("--extern", f"{name}={artifact}"))
    exe = directory / "original-da-context"
    _run([rustc, "--edition=2021", "--extern", f"trnm_data_availability={da}",
          "--extern", f"borsh={borsh}", *extra, "-L", f"dependency={target / 'debug/deps'}",
          "-L", f"native={native}", str(caller), "-o", str(exe)], timeout=60)
    result = _run([str(exe)], stream, timeout=30)
    if result.stderr or before != identities():
        raise ValueError("Original comparison did not retain unchanged source and stderr")
    return result.stdout


def packets(raw, count):
    at = 0
    for _ in range(count):
        code, size = struct.unpack_from("<BI", raw, at)
        at += 5
        data = raw[at:at + size]
        if len(data) != size or (code not in (0, 2)) or (code == 2 and size):
            raise ValueError("Malformed original observation")
        at += size
        yield code, data
    if at != len(raw):
        raise ValueError("Trailing original observation")


class DaProtocolContext(unittest.TestCase):
    def test_original_ascii_validation_and_canonical_borsh(self):
        strings = [bytes([i]) for i in range(128)]
        strings += [b"", bytes(range(128)), b"x" * 129, b"\0tab\t\n\r",
                    "é".encode(), "链".encode(), "😀".encode(),
                    b"x" * 126 + "é".encode()]
        req = [HEADER + value for value in strings]
        req += [bytes(64) + b"z", bytes(range(63, -1, -1)) + b"z"]
        stream = b"".join(struct.pack("<I", len(item)) + item for item in req)
        with tempfile.TemporaryDirectory(prefix="trnm-da-original-") as directory:
            exact = list(packets(locked_reference(Path(directory), stream), len(req)))
        expected = [(0, b"\1\0" + item[:32] + struct.pack("<I", len(item) - 64)
                      + item[64:] + b"\1\0\0\0" + item[32:64])
                    if 64 < len(item) <= 192 and item[64:].isascii() else (2, b"")
                    for item in req]
        self.assertEqual(exact, expected)

        panel = [(item, code, data, len(data) + 13) for item, (code, data) in zip(req, exact, strict=True)]
        panel += [(HEADER[:63], 100, b"", 195), (b"", 100, b"", 0),
                  (HEADER + b"\xff", 2, b"", 202), (HEADER + b"z", 102, b"", 74),
                  (HEADER + b"z", 0, exact[ord("z")][1], 75),
                  (HEADER + bytes(range(128)), 102, b"", 201),
                  (HEADER + bytes(range(128)), 0, exact[129][1], 202),
                  (HEADER + b"\xff", 2, b"", 0)]
        hashes = []
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, backend=backend, byte_exports=("f0",)) as module:
                hashes.append(module.artifact_sha256)
                requests = [("f0", [item, MARK * room, SCRATCH]) for item, _, _, room in panel]
                for result, (item, code, data, room) in zip(module.call_many(requests, timeout=55), panel, strict=True):
                    self.assertEqual(result.require_returned().value, code, item.hex())
                    self.assertEqual(result.arguments, [item, data + MARK * (room - len(data)), SCRATCH])
        self.assertEqual(len(set(hashes)), 2)
