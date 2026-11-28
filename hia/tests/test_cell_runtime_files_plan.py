"""Frozen public immutable runtime-files metadata plan; no filesystem access."""
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
SOURCE = ROOT / "hia/src/data_availability/cell_runtime_files_plan.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_runtime_files_plan_reference.rs")
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
    sha2 = [row for row in events if row.get("reason") == "compiler-artifact"
            and row["target"]["name"] == "sha2" and "/sha2-0.10.9/" in row["target"]["src_path"]]
    [h] = sha2
    [sha_lib] = [Path(p) for p in h["filenames"] if p.endswith(".rlib")]
    if not sha_lib.is_relative_to(target) or h["features"] != ["asm", "default", "sha2-asm", "std"]:
        raise ValueError("Wrong original SHA-256 dependency")
    module = src.read_bytes()
    boundary = (src.parent.parent / "cell.rs").read_bytes()
    # Exact frozen private function and exact frozen require/HOST_CAP only.
    # The linked public Rust crate supplies every typed record and method.
    require_at = boundary.index(b"pub(crate) fn require(")
    require_end = boundary.index(b"\npub fn digest_hex(", require_at)
    host_at = module.index(b"const HOST_CAP:")
    host_end = module.index(b"\n", host_at)
    body_at = module.index(b"fn validate_files(")
    body_end = module.index(b"\n/// Enumerate", body_at)
    (directory/"runtime_plan_body.rs").write_bytes(
        boundary[require_at:require_end] + module[host_at:host_end] + b"\n"
        + module[body_at:body_end])
    prepared = directory/"reference.rs"
    prepared.write_bytes(reference.read_bytes())
    exe=directory/"cell-runtime-files-plan-original"
    execute([rustc,"--edition=2021",prepared,"-L",f"dependency={target/'debug/deps'}",
             "--extern",f"trnm_data_availability={lib}","--extern",f"sha2={sha_lib}","-o",exe],env=env,timeout=90)
    return execute([exe]).stdout


class CellRuntimeFilesPlanTests(unittest.TestCase):
    def test_original_frozen_plan_declarations_two_native(self):
        with tempfile.TemporaryDirectory(prefix="cell-runtime-files-plan-") as temp:
            raw = original(Path(temp))
        cases = []
        while raw:
            status, size = struct.unpack_from("<II", raw)
            totals, data = raw[8:24], raw[24:24 + size]
            self.assertEqual(len(data), size)
            cases.append((status, data, totals if not status else b""))
            raw = raw[24 + size:]
        self.assertEqual([s for s, _, _ in cases], [
            1, 11, 0, 0, 11, 0, 0, 0, 11, 0, 0, 0, 11, 2, 3,
            0, 7, 4, 4, 6, 5, 7, 7, 8, 9, 10, 8, 0, 0,
        ])
        self.assertEqual(struct.unpack("<QQ", cases[15][2])[0], 18)
        self.assertEqual(struct.unpack("<QQ", cases[-1][2])[0], 1 << 30)
        packet = cases[15][1]
        rlen, _, clen = struct.unpack_from("<QQQ", packet, 8)
        ctx_end = 32 + clen
        first_seg_count = ctx_end + rlen
        first_cell_len = first_seg_count + 8
        first_cell = first_cell_len + 8

        def change(at, replacement):
            return packet[:at] + replacement + packet[at + len(replacement):]

        malformed = [packet[:209], packet[:-1], packet + b"x",
                     change(0, b"RFP2"), change(8, b"\xff" * 8), change(32, b"\0"),
                     change(first_cell_len, b"\xff" * 8), change(first_cell, b"TCM2")]
        caps = [change(first_seg_count, struct.pack("<Q", 5))]
        cases += [(100, b, b"") for b in malformed]
        cases += [(101, b, b"") for b in caps]
        out, work = b"O" * 23, b"W" * 1513
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for (status, data, result), response in zip(
                    cases, native.call_many([("f0", [bits, out, work]) for _, bits, _ in cases]),
                    strict=True,
                ):
                    got = response.require_returned()
                    self.assertEqual((got.value, got.arguments[:2]),
                                     (status, [data, result + out[len(result):]]))
                    self.assertEqual(got.arguments[2][1504:], work[1504:])
                for o, w in ((out[:15], work), (out, work[:1503])):
                    args = [packet, o, w]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (102, args))
