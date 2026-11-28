"""Locked Rust immutable empty-placement policy admission and commitment."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_recovery_placement_policy_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_recovery_placement_policy_value_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/recoverability.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
DOMAIN = b"TRNM/Cell/RecoveryPlacement/v1\0"
TAG = b"NRPP0001"
WORK = 131264


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, rows):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (ORIGINAL, MANIFEST, LOCK, REFERENCE, CRATE / "src/cell/placement.rs")
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
    exe = directory / "original-recovery-placement-policy-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 65 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original recovery placement policy value evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "placement_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    output = []
    for i in range(0, len(observed.stdout), 65):
        status, *body = observed.stdout[i:i+65]
        record = bytes(body)
        if status and any(record):
            raise ValueError("nonzero original recovery policy rejection padding")
        output.append((status, record if not status else b""))
    return output


def frame(pins, loss=1, axes=(1, 2, 3)):
    return TAG + struct.pack(">H", len(pins)) + b"".join(pins) + bytes((loss, len(axes), *axes))


def pin(i, *, same_labels=False):
    # Long common provider-ID prefix: each last byte is significant.
    provider = b"I"*31 + bytes([i])
    if same_labels:
        return provider + b"S"*128
    return provider + b"".join(bytes((i + 1, label)) * 16 for label in range(1, 5))


def corpus():
    left, right = pin(1),pin(2)
    # Exercise every attainable, canonical typed-axis subset, loss count, and
    # provider cardinality, including identical labels on distinct IDs.
    out = []
    subsets = [x for n in range(4) for x in itertools.combinations((1,2,3),n)]
    for cardinality in (1, 2, 8, 16):
        for axes in subsets:
            for loss in (0, 1, 2):
                pins = tuple(pin(i, same_labels=bool(cardinality<16)) for i in range(cardinality))
                out.append((frame(pins, loss, axes), 21 if loss and not axes else 0))
    out += [(frame([],0,()),20), (frame([pin(i) for i in range(17)],0,()),20),
            (frame((right,left),3,(3,2)),20), (frame((left,right),255,(1,)),20),
            (frame((left,right),0,(1,2,3,3)),20), (frame((right,left),0,(3,2)),21),
            (frame((left,right),2,(2,2)),21), (frame((left,left),1,(1,)),22),
            (frame((right,left),1,(1,)),22)]
    for field in range(5):
        start = 32*field
        zero = left[:start] + bytes(32) + left[start+32:]
        out += [(frame((zero,),0,()),23)]
        # Each field binds both its first and last byte.
        for i in (start,start+31):
            variant = left[:i]+bytes([left[i]^0x80])+left[i+1:]
            out.append((frame((variant,right),1,(1,2,3)),22 if field==0 else 0))
    # Domain-evidence bytes and typed event labels never mean authentication.
    out += [(frame((bytes(32)+left[32:],)*2,0,()),22),
            (frame((left, right[:32]+left[32:]),1,(1,2,3)),0)]
    return out


class CellRecoveryPlacementPolicyValue(unittest.TestCase):
    def test_actual_locked_original_empty_placement_policy_commitment_both_stock(self):
        panel = corpus()
        rows = [raw for raw, _ in panel]
        with tempfile.TemporaryDirectory(prefix="trnm-policy-value-locked-") as tmp:
            expected = original_rows(Path(tmp), rows)
        self.assertEqual([s for s, _ in expected], [s for _, s in panel])
        for raw, (status, digest) in zip(rows, expected, strict=True):
            if not status:
                self.assertEqual(digest,hashlib.sha512(DOMAIN+raw[8:]).digest())
        good = frame((pin(1),),1,(1,2,3))
        golden = hashlib.sha512(DOMAIN+good[8:]).digest()
        out, work = b"O"*77,b"W"*(WORK+7)
        controls = ((b"",out,work,100),(b"X"+good[1:],out,work,100),
                    (good[:-1],out,work,100),(good+b"X",out,work,100),
                    (good[:-1]+b"\x04",out,work,21),
                    (good,out[:63],work,102),(good,out,work[:WORK-1],102),
                    (frame([],0,()),b"",b"",20))
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),4):
                    sub = rows[at:at+4]
                    calls = module.call_many([("f0",[raw,out,work]) for raw in sub])
                    for raw, got, (status,digest) in zip(sub,calls,expected[at:at+4],strict=True):
                        self.assertEqual((got.status,got.value),("returned",status))
                        self.assertEqual(got.arguments[0],raw)
                        self.assertEqual(got.arguments[1],digest+out[64:] if not status else out)
                        if status:
                            self.assertEqual(got.arguments[2],work)
                        else:
                            self.assertEqual(got.arguments[2][131232:131263],DOMAIN)
                            self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                for raw,dst,scratch,status in controls:
                    got = module.call("f0",[raw,dst,scratch])
                    self.assertEqual((got.status,got.value),("returned",status))
                    self.assertEqual(got.arguments,[raw,dst,scratch])
                bound = module.call("f0",[good,out[:64],work[:WORK]])
                self.assertEqual((bound.status,bound.value,bound.arguments[1]),("returned",0,golden))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(controls)+1},
                                 sort_keys=True),flush=True)
