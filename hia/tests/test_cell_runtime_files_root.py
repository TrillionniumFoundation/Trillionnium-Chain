"""Frozen public immutable runtime-files metadata root; no filesystem access."""
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_runtime_files_root.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_runtime_files_root_reference.rs")
LEGACY = ROOT / "trillionnium"
ORIGINAL = "563bb7e471b3db278d50feceb3cbac7de4ab281a"
CARGO_LOCK = "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e"


def original(directory, reference=REFERENCE):
    git = ['git','-C',ROOT]
    if execute([*git,'rev-parse','HEAD:trillionnium']).stdout.decode().strip() != ORIGINAL:
        raise ValueError("Wrong frozen Rust workspace")
    execute([*git,'diff','--quiet','HEAD','--','trillionnium'])
    if hashlib.sha256((LEGACY/'Cargo.lock').read_bytes()).hexdigest() != CARGO_LOCK:
        raise ValueError("Wrong frozen Cargo graph")
    src = LEGACY / "crates/trnm-data-availability/src/cell/runtime_root.rs"
    if hashlib.sha256(src.read_bytes()).hexdigest() != "71664dad11c66acac87cecdb265dd9c99cd730cb8b63279b295a8788b89a7a5c":
        raise ValueError("Wrong frozen runtime metadata owner")
    requested = os.environ.get("TRNM_HIA_RUSTC","rustc")
    channel = tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = execute([requested,"--version"]).stdout
    sysroot = Path(execute([requested,"--print","sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc,cargo = sysroot/"bin/rustc",sysroot/"bin/cargo"
    if version.decode().split()[1] != channel or execute([rustc,"--version"]).stdout != version:
        raise ValueError("Wrong original toolchain")
    target = directory/"target"
    manifest = LEGACY/"crates/trnm-data-availability/Cargo.toml"
    env = {**os.environ,"RUSTC":str(rustc),"CARGO_BUILD_JOBS":"1",
           "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    log = execute([cargo,"build","--locked","--offline","--no-default-features","--lib",
                   "-p","trnm-data-availability","--manifest-path",LEGACY/"Cargo.toml",
                   "--target-dir",target,"--message-format=json"],env=env,timeout=360).stdout
    events = [json.loads(line) for line in log.splitlines()]
    if events[-1] != {"reason":"build-finished","success":True}:
        raise ValueError("Native oracle did not build")
    [m] = [e for e in events if e.get("reason") == "compiler-artifact"
           and e["target"]["name"] == "trnm_data_availability" and "lib" in e["target"]["kind"]]
    if (m["fresh"] or m["features"] or Path(m["manifest_path"]) != manifest
            or Path(m["target"]["src_path"]) != manifest.parent/"src/lib.rs"):
        raise ValueError("Original linked package differs")
    [lib] = [Path(p) for p in m["filenames"] if p.endswith(".rlib")]
    if not lib.is_relative_to(target):
        raise ValueError("Original library escaped private target")
    exe=directory/"cell-runtime-files-root-original"
    execute([rustc,"--edition=2021",reference,"-L",f"dependency={target/'debug/deps'}",
             "--extern",f"trnm_data_availability={lib}","-o",exe],env=env,timeout=90)
    return execute([exe]).stdout


class CellRuntimeFilesRootTests(unittest.TestCase):
    def test_original_runtime_files_metadata_root_two_native(self):
        with tempfile.TemporaryDirectory(prefix="cell-runtime-files-root-") as temp:
            raw = original(Path(temp))
        cases = []
        while raw:
            code, size = struct.unpack_from("<II", raw)
            digest, packet = raw[8:40], raw[40:40 + size]
            self.assertEqual(len(packet), size)
            cases.append((code, packet, digest if not code else b""))
            raw = raw[40 + size:]
        self.assertEqual([c for c, _, _ in cases],
                         [1] + [0] * 6 + [2] * 14 + [3, 3, 3, 2, 3, 0, 0, 2, 0])
        self.assertEqual(len({d for c, _, d in cases if not c}), 9)
        self.assertEqual(len(cases[-1][1]), 274704)
        f = cases[1][1]
        too_many = f[:8] + struct.pack("<Q", 257) + f[16:]
        bad_role = f[:25] + bytes([11]) + f[26:]
        bad_length = f[:16] + b"\xff" * 8 + f[24:]
        controls = [(100, x, b"") for x in
                    (f[:15], f[:-1], f + b"x", b"RFR2" + f[4:], bad_role, bad_length,
                     cases[-1][1] + b"x")]
        controls.append((1, too_many, b""))
        o, w = b"O" * 39, b"W" * 1511
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for (code, packet, digest), call in zip(
                    cases + controls,
                    native.call_many([("f0", [packet, o, w])
                                      for _, packet, _ in cases + controls]),
                    strict=True,
                ):
                    got = call.require_returned()
                    self.assertEqual((got.value, got.arguments[:2]),
                                     (code, [packet, digest + o[len(digest):]]))
                    self.assertEqual(got.arguments[2][1504:], w[1504:])
                for out, scratch in ((o[:31], w), (o, w[:1503])):
                    args = [f, out, scratch]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (102, args))
