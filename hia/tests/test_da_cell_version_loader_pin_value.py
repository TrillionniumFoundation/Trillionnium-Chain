"""Original pure owned loader-context/pin conversions and both stock backends."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_version_loader_pin_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_version_loader_pin_value_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/version_retention.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
TAG = b"NVLP0001"
FIXED = 261
OPAQUE = bytes(range(248))


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, rows):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (ORIGINAL, MANIFEST, LOCK, REFERENCE, CRATE / "src/cell/closure.rs")
    before = tuple(sha(p.read_bytes()) for p in paths)
    rust_version = subprocess.run([rustc, "--version"], env=env, check=True, capture_output=True,
                                  text=True, timeout=10).stdout
    if not rust_version.startswith("rustc 1.95.0 (59807616e "):
        raise ValueError("expected original locked Rust 1.95.0")
    comp = subprocess.run([cargo, "build", "--locked", "--offline", "--manifest-path",
                           str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability",
                           "--lib", "--target-dir", str(target), "--message-format=json"],
                          env=env, check=True, capture_output=True, text=True, timeout=180)
    records = [v for v in map(json.loads, comp.stdout.splitlines())
               if v.get("reason") == "compiler-artifact"
               and v["target"]["name"] == "trnm_data_availability" and v["target"]["kind"] == ["lib"]]
    if len(records) != 1 or records[0]["features"] != ["default"]:
        raise ValueError("expected one actual unchanged original default-feature DA library")
    library, = (Path(x) for x in records[0]["filenames"] if x.endswith(".rlib"))
    library_sha = sha(library.read_bytes())
    exe = directory / "original-loader-pin-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != len(wire) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original loader-pin conversion evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "closure_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    expected = []
    cursor = 0
    for row in rows:
        size = struct.unpack_from("<I", observed.stdout, cursor)[0]
        cursor += 4
        if size != len(row):
            raise ValueError("original reformatted unexpected length")
        expected.append(observed.stdout[cursor:cursor+size])
        cursor += size
    if cursor != len(observed.stdout):
        raise ValueError("unexpected original result suffix")
    return expected


def frame(mode, family, roles, opaque=OPAQUE):
    assert len(opaque)==248
    return TAG + struct.pack(">BHH",mode,len(family),len(roles)) + opaque + family + bytes(roles)


def corpus():
    result = []
    rng = random.Random(0x4e564c50)
    for roles in itertools.permutations(range(1,7)):
        result.append(frame(0, b"family_A.1", roles))
        result.append(frame(1, b"family_A.1", roles))
    for mode in (0,1):
        for family in (b"", b"family/name", b"model\0raw", "模型 α β é🙂".encode(), "🙂".encode()*1024):
            for roles in ((), (6,3,3,3,1,6,2,4,5), (6,1)*512):
                result.append(frame(mode, family, roles, bytes(248)))
        for i in range(24):
            roles=tuple(rng.randrange(1,7) for _ in range(i*11))
            result.append(frame(mode, f"family-{i}".encode(), roles,rng.randbytes(248)))
    return result


class CellVersionLoaderPinValue(unittest.TestCase):
    def test_actual_locked_original_typed_pin_projections_both_stock(self):
        rows = corpus()
        with tempfile.TemporaryDirectory(prefix="trnm-loader-pin-value-locked-") as tmp:
            expected = original_rows(Path(tmp), rows)
        for raw,want in zip(rows,expected,strict=True):
            nfamily=int.from_bytes(raw[9:11],"big")
            at=FIXED+nfamily
            self.assertEqual(want[:at],raw[:at])
            self.assertEqual(want[at:],bytes(sorted(raw[at:])) if raw[8]==0 else raw[at:])
        work = b"W"*17
        ordinary=frame(0,"ƒ".encode(),(6,1,1))
        invalid = (
            (b"",100), (ordinary[:260],100), (b"X"+ordinary[1:],100),
            (ordinary[:8]+b"\x02"+ordinary[9:],100),
            (ordinary[:-1],100),(ordinary+b"x",100),
            (frame(0,b"a"*4097,[1]),100),(frame(1,b"",[1]*1025),100),
            (frame(0,b"\xc0\x80",[1]),101),(frame(1,b"\xed\xa0\x80",[1]),101),
            (frame(0,b"\xf0\x9f",[1]),101),
            (frame(0,b"family",[0]),101),(frame(1,b"family",[7]),101),
        )
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),48):
                    sub = rows[at:at+48]
                    results=module.call_many([("f0",[raw,b"X"*(len(raw)+11),work]) for raw in sub])
                    for raw,got,want in zip(sub,results,expected[at:at+48],strict=True):
                        self.assertEqual((got.status,got.value),("returned",0))
                        self.assertEqual(got.arguments,[raw,want+b"X"*11,work])
                for raw,status in invalid:
                    output = b"O"*max(1,len(raw))
                    got=module.call("f0",[raw,output,work])
                    self.assertEqual((got.status,got.value),("returned",status))
                    self.assertEqual(got.arguments,[raw,output,work])
                thin=bytes(len(ordinary)-1)
                got=module.call("f0",[ordinary,thin,b""])
                self.assertEqual((got.status,got.value,got.arguments),("returned",102,[ordinary,thin,b""]))
                fit=module.call("f0",[ordinary,bytes(len(ordinary)),b""])
                self.assertEqual((fit.status,fit.value,fit.arguments[1]),
                                 ("returned",0,ordinary[:-3]+bytes((1,1,6))))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(invalid)+2},
                                 sort_keys=True),flush=True)
