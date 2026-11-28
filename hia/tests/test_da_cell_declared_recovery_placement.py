"""Real public Rust versus both stock HIA declared-placement evaluators."""
from collections import Counter
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
SOURCE = ROOT / "hia/src/data_availability/cell_declared_recovery_placement.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_declared_recovery_placement_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/placement.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
TAG = b"NRPE0001"
WORK = 1328
LENGTH = 90
U64 = (1 << 64) - 1


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
    exe = directory / "original-declared-recovery-placement"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 91 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original declared placement evaluation evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "placement_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    output = []
    for i in range(0, len(observed.stdout), 91):
        status, *body = observed.stdout[i:i+91]
        record = bytes(body)
        if status and any(record):
            raise ValueError("nonzero original placement evaluation rejection padding")
        output.append((status, record if not status else b""))
    return output


def row(i, groups=None):
    key = b"I" * 31 + bytes((i,))
    labels = groups if groups is not None else (i,i,i)
    return key+b"".join(bytes((axis,label))*16 for axis,label in enumerate(labels,1))+b"E"*32


def place(provider, part):
    return provider[:32]+struct.pack(">H",part)


def frame(pins, places, loss=0, axes=(), steps=U64):
    return (TAG+struct.pack(">HHBBQ",len(pins),len(places),loss,len(axes),steps)
            +bytes(axes)+b"".join(pins)+b"".join(places))


def corpus():
    providers = tuple(row(i) for i in range(1,17))
    a,b,c = providers[:3]
    known = tuple(place(p,i) for p,i in zip(providers, (0,1,2,3,4,5,6)*3))
    full = tuple(place(p,i) for p in providers for i in range(7))
    caps = (1177,20777)
    maximum = frame(providers,full,2,(1,2,3),caps[1])
    assert len(maximum) == 22 + 3 + 16*160 + 112*34
    out = [(maximum,0), (frame(providers,full,2,(1,2,3),caps[1]-1),27),
           (frame(providers,[],2,(1,2,3),caps[1]),0),
           (frame(providers,known,2,(1,2,3),caps[1]),0),
           (frame((a,), (place(a,0),),2,(1,2,3),17),0),
           (frame((a,), (place(a,0),),2,(1,2,3),16),27),
           (frame((a,b),(),0,(),3),0),(frame((a,b),(),0,(),2),27),
           (frame((a,b),(place(a,0),),1,(1,2,3)),0),
           (frame((a,b),(place(a,0),place(b,1),place(b,2)),2,(1,2,3)),0),
           (frame((a,b,c),(place(a,0),place(b,0),place(c,1)),2,(1,2,3)),0)]
    out.extend([(frame((),()),20),(frame(providers+(row(17),),()),20),
                (frame(providers,full+(full[-1],)),20),
                (frame((b,a), (place(b,256),),3,(3,2)),20),
                (frame((b,a), (place(b,256),),2,()),21),
                (frame((b,a),(),0,(3,2)),21),
                (frame((a,b),(),0,(1,1)),21),
                (frame((a,b),(),0,(1,2,3,3)),20),
                (frame((b,a), (place(b,256),)),22),
                (frame((a,a), (place(a,256),)),22),
                (frame((bytes(32)+a[32:],a), (place(a,256),)),23),
                (frame((a,b),(place(a,256),place(a,256))),24),
                (frame((a,b),(place(b,256),place(a,256))),24),
                (frame((a,b),(place(a,0),place(a,256))),25),
                (frame((a,b),(place(a,7),)),25),
                (frame((a,b),(place(c,256),)),25),
                (frame((a,b),(place(c,0),)),26),
                (frame((a,b),(place(c,0),),steps=0),26)])
    for field in range(1,5):
        bad = a[:field*32]+bytes(32)+a[(field+1)*32:]
        out.append((frame((bad,b),(place(a,256),)),23))
    rng = random.Random(274314)
    for i in range(72):
        n = 1 + (i%16)
        pins = tuple(row(j,tuple(rng.randrange(1,1+n//2+1) for _ in range(3)))
                     for j in range(1,n+1))
        selected = tuple(a for a in (1,2,3) if rng.randrange(2))
        loss = i%3 if selected else 0
        places = tuple(place(p,j) for p in pins for j in range(7) if rng.randrange(5)==0)
        out.append((frame(pins,places,loss,selected),0))
    return out


class CellDeclaredRecoveryPlacement(unittest.TestCase):
    def test_actual_locked_original_declared_placement_and_both_stock(self):
        panel = corpus()
        rows = [raw for raw,_ in panel]
        with tempfile.TemporaryDirectory(prefix="trnm-declared-placement-locked-") as tmp:
            expected = original_rows(Path(tmp), rows)
        statuses = [s for s,_ in expected]
        self.assertEqual(statuses,[s for _,s in panel])
        first = expected[0][1]
        self.assertEqual(first[:8],bytes((1,1,6,6,1,0,0,0)))
        self.assertEqual(struct.unpack("<QQ",first[8:24]),(1177,20777))
        self.assertEqual(expected[8][1][:8],bytes((1,0,0,0,0,1,0,0)))
        self.assertEqual(expected[8][1][24:57],b"\x01"+row(1)[32:64])
        self.assertEqual(expected[10][1][24:90],b"\x01"+row(1)[32:64]+b"\x01"+row(2)[32:64])
        out,work = b"O"*(LENGTH+7),b"W"*(WORK+13)
        nominal = rows[0]
        controls = ((b"",out,work,100),(b"X"+nominal[1:],out,work,100),
                    (nominal[:-1],out,work,100),(nominal+b"X",out,work,100),
                    (frame((row(1),),(),0,(4,)),out,work,21),
                    (nominal,out[:LENGTH-1],work,102),(nominal,out,work[:WORK-1],102))
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),8):
                    sub = rows[at:at+8]
                    calls = module.call_many([("f0",[raw,out,work]) for raw in sub])
                    for raw,got,(status,body) in zip(sub,calls,expected[at:at+8],strict=True):
                        self.assertEqual((got.status,got.value),("returned",status),at)
                        self.assertEqual(got.arguments[0],raw)
                        self.assertEqual(got.arguments[1],body+out[LENGTH:] if not status else out)
                        self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                        if status not in (0,27):
                            self.assertEqual(got.arguments[2],work)
                for raw,dst,scratch,status in controls:
                    got = module.call("f0",[raw,dst,scratch])
                    self.assertEqual((got.status,got.value),("returned",status))
                    self.assertEqual(got.arguments,[raw,dst,scratch])
                bound = module.call("f0",[nominal,out[:LENGTH],work[:WORK]])
                self.assertEqual((bound.status,bound.value,bound.arguments[1]),("returned",0,first))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(controls)+1,
                                  "status_counts":dict(Counter(statuses))},sort_keys=True),flush=True)
