"""Independent real locked original value and both stock predicates."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cell_version_retention_outer_terms.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_cell_version_retention_outer_terms_reference.rs"
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
ORIGINAL = CRATE / "src/cell/version_retention.rs"
MANIFEST = CRATE / "Cargo.toml"
LOCK = ROOT / "trillionnium/Cargo.lock"
TAG = b"NVT30001"
MAX_HEIGHT = (1<<63)-1
MAX_CAP = 64<<30
MAX_META = 64<<20
ZERO = bytes(32)


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, rows):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (ORIGINAL, MANIFEST, LOCK, REFERENCE, CRATE / "src/cell/retention.rs")
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
    exe = directory / "original-version-retention-terms"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(exe)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I", len(row))+row for row in rows)
    observed = subprocess.run([str(exe)], input=wire, env=env,
                              check=True, capture_output=True, timeout=15)
    if (len(observed.stdout) != 2 * len(rows) or observed.stderr
            or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original retention outer terms evidence")
    print(json.dumps({"original_source_sha256": before[0], "cargo_manifest_sha256": before[1],
                      "cargo_lock_sha256": before[2], "adapter_sha256": before[3],
                      "retention_original_sha256": before[4],
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(exe.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout),
                      "oracle_rows": len(rows)}, sort_keys=True), flush=True)
    return list(zip(observed.stdout[::2],observed.stdout[1::2],strict=True))


def change(data, offset, value, width=8):
    if isinstance(value,int):
        value=value.to_bytes(width,"big")
    return data[:offset]+value+data[offset+len(value):]


def baseline(snapshot=False):
    ids = b"".join(bytes([i])*32 for i in range(0x71,0x75))
    common = TAG+b"S"*32+struct.pack(">QIIQ",8192,16,2,16384) + ids
    common += struct.pack(">HHQQQB",0,2,10,120,90,int(snapshot))
    return common + (b"Q"*32+struct.pack(">QQ",1,100)+b"P"*32+b"C"*32 if snapshot else b"")


def corpus():
    short,long = baseline(),baseline(True)
    # (value, native selected predicate status, whole original status)
    panel=[(short,0,0),(long,0,0)]
    for offset,v,w,status in (
        (8,ZERO,32,20),(40,0,8,20),(40,4095,8,20),(40,4097,8,20),(40,MAX_CAP+4096,8,20),
        (48,0,4,20),(48,4097,4,20),(48,2**32-1,4,20),
        (52,0,4,21),(52,129,4,21),(56,0,8,21),(56,MAX_META+1,8,21),
        (64,ZERO,32,22),(96,ZERO,32,22),(128,ZERO,32,22),(160,ZERO,32,22),
        (194,0,2,23),(194,17,2,23),(192,2,2,23),(192,65535,2,23),
        (196,120,8,24),(204,MAX_HEIGHT+1,8,24),(212,9,8,24),(212,120,8,24),
        (221,ZERO,32,25),(253,0,8,25),(253,MAX_HEIGHT+1,8,25),(261,9,8,25),
        (261,120,8,25),(269,ZERO,32,25),(269,b"q"*32,32,25),(301,ZERO,32,25),
    ):
        r=short if offset < 221 else long
        panel.append((change(r,offset,v,w),status,status))
    for i in (64,96,128,160,221,269,301):
        src=short if i<221 else long
        for n in range(32):
            d=bytearray(32);d[n]=1
            panel.append((change(src,i,bytes(d)),0,0))
    for pos,values,w in (
        (40,(8192,12288,MAX_CAP),8),(48,(1,4096),4),(52,(1,128),4),
        (56,(1,MAX_META),8),(192,(0,1),2),(194,(1,16),2),
        (196,(0,90),8),(204,(91,MAX_HEIGHT),8),(212,(10,119),8),
    ):
        panel.extend((change(short,pos,n,w),0,0) for n in values)
    for pos,values in ((253,(1,MAX_HEIGHT)),(261,(10,119))):
        panel.extend((change(long,pos,n),0,0) for n in values)
    largest=change(change(short,192,15,2),194,16,2)
    panel.append((largest,0,0))
    # Defensible exact boundaries between the selected phase and later failures.
    panel += [(change(short,40,4096),0,30),
              (change(short,64,bytes([0xe1])*32),0,31),
              (change(short,96,b"q"*32),0,32)]
    # Earlier errors continue to win in compound invalid typed values.
    invalid_offsets = [(40,0,8,20),(52,0,4,21),(64,ZERO,32,22),
                       (194,0,2,23),(212,120,8,24),(253,0,8,25)]
    for i,(off,a,w,status) in enumerate(invalid_offsets):
        for off2,b,w2,_ in invalid_offsets[i+1:]:
            panel.append((change(change(long,off2,b,w2),off,a,w),status,status))
    return panel


class CellVersionRetentionOuterTerms(unittest.TestCase):
    def test_actual_locked_original_outer_terms_and_both_stock(self):
        panel=corpus()
        rows=[raw for raw,_,_ in panel]
        with tempfile.TemporaryDirectory(prefix="trnm-retention-outer-locked-") as tmp:
            expected=original_rows(Path(tmp),rows)
        self.assertEqual(expected,[(status,whole) for _,status,whole in panel])
        self.assertEqual(Counter(whole for _,whole in expected if whole>=30),{30:1,31:1,32:1})
        good=rows[1]
        nonsnapshot=rows[0]
        bad=(b"", good[:220], good[:-1], good+b"x", b"X"+good[1:],
             change(good,220,0,1), change(good,220,2,1), change(nonsnapshot,220,1,1))
        out,work=b"O"*19,b"W"*23
        for backend in ("selfhost","direct"):
            with self.subTest(backend=backend), NativeModule(SOURCE,byte_exports=("f0",),
                                                             backend=backend) as module:
                for at in range(0,len(rows),24):
                    sub=rows[at:at+24]
                    got=module.call_many([("f0",[raw,out,work]) for raw in sub])
                    for raw,result,(status,_) in zip(sub,got,expected[at:at+24],strict=True):
                        self.assertEqual((result.status,result.value),("returned",status))
                        self.assertEqual(result.arguments,[raw,out,work])
                for raw in bad:
                    result=module.call("f0",[raw,out,work])
                    self.assertEqual((result.status,result.value,result.arguments),("returned",100,[raw,out,work]))
                zero=module.call("f0",[good,b"",b""])
                self.assertEqual((zero.status,zero.value,zero.arguments),("returned",0,[good,b"",b""]))
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_compared":len(rows),"abi_controls":len(bad)+1,
                                  "outer_status":dict(Counter(s for s,_ in expected)),
                                  "distinct_later_original_refusals":3},sort_keys=True),flush=True)
