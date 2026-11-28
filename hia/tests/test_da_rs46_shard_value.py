"""Real original CRS1 standalone decode and byte identity and pinned native dual."""
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
from hia.tests.rs46_native import RS46Native
from hia.tests.test_da_cell_closure_declared_context_relation import CRATE, LIMIT, LOCK, MANIFEST, ROOT

SOURCE = ROOT / "hia/src/data_availability/rs46_shard_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_rs46_shard_value_reference.rs"
WORK = 1232
DOMAIN = b"trnm.cell-rs46-shard.v1\0"


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, wires):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (MANIFEST, LOCK, REFERENCE, *(CRATE / f"src/cell/{name}.rs"
                for name in ("erasure", "manifest")))
    before = tuple(sha(p.read_bytes()) for p in paths)
    version = subprocess.run([rustc, "--version"], env=env, check=True, capture_output=True,
                             text=True, timeout=10).stdout
    if not version.startswith("rustc 1.95.0 (59807616e "):
        raise ValueError("expected original locked Rust 1.95.0")
    built = subprocess.run([cargo, "build", "--locked", "--offline", "--manifest-path",
                            str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability",
                            "--lib", "--target-dir", str(target), "--message-format=json"],
                           env=env, check=True, capture_output=True, text=True, timeout=180)
    records = [v for v in map(json.loads, built.stdout.splitlines())
               if v.get("reason") == "compiler-artifact"
               and v["target"]["name"] == "trnm_data_availability" and v["target"]["kind"] == ["lib"]]
    if len(records) != 1 or records[0]["features"] != ["default"]:
        raise ValueError("expected one actual unchanged original default-feature DA library")
    library, = (Path(x) for x in records[0]["filenames"] if x.endswith(".rlib"))
    library_sha = sha(library.read_bytes())
    executable = directory / "original-rs46-shard-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(executable)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I",len(raw))+raw for raw,_ in wires)
    observed = subprocess.run([str(executable)], env=env, input=wire, check=False,
                              capture_output=True, timeout=45)
    if observed.returncode:
        raise ValueError(f"original standalone shape fixture failed: {observed.stderr.decode(errors='replace')}")
    if (not observed.stdout or observed.stderr or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original shard evidence")
    rows = []
    cursor = 0
    for raw, wanted_status in wires:
        status=observed.stdout[cursor]
        cursor += 1
        if status != wanted_status:
            raise ValueError(f"unexpected original shape status {status} != {wanted_status}")
        result=observed.stdout[cursor:cursor+113] if status==0 else b""
        cursor += len(result)
        rows.append((raw,status,result))
    if cursor!=len(observed.stdout):
        raise ValueError("unconsumed original shard observations")
    print(json.dumps({"original_inputs": dict(zip([p.name for p in paths], before, strict=True)),
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(executable.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout), "oracle_rows": len(rows)},
                     sort_keys=True), flush=True)
    return rows



MAX_SOURCE = 4 * 1024**2
MAX_WIRE = 81 + MAX_SOURCE // 4


def replace(raw, at, value):
    return raw[:at] + value + raw[at+len(value):]


def shard(size, *, index=0, chunk=0, zero_fields=False):
    n=(size+3)//4
    payload=(bytes(range(251))*((n+250)//251))[:n]
    m=bytes(32) if zero_fields else b"M"*32
    digest=bytes(32) if zero_fields else b"S"*32
    return b"CRS1"+m+struct.pack(">II",chunk,size)+digest+bytes([index])+struct.pack(">I",n)+payload


def corpus():
    rows=[(shard(n,index=n%6,chunk=(713*n)%16384),0) for n in range(1,35)]
    rows += [(shard(n,index=n%6,chunk=16383),0) for n in
             (64,111,127,128,129,223,224,225,255,256,257,511,512,513,65535,65536,65537)]
    rows += [(shard(18,index=i,zero_fields=True),0) for i in range(6)]
    edge=4*(LIMIT-81)
    rows += [(shard(n,index=i%6,chunk=16383),0) for i,n in enumerate(
             (edge-4,edge-3,edge,edge+1,edge+4,MAX_SOURCE-4,MAX_SOURCE-3,MAX_SOURCE-2,MAX_SOURCE-1,MAX_SOURCE))]
    sample=shard(13,index=5,chunk=16383)
    rows += [(sample[:n],1) for n in (0,1,4,80,81)]
    rows += [(replace(sample,0,b"BAD!"),2),
             (replace(sample,40,struct.pack(">I",0)),3),
             (replace(sample,40,struct.pack(">I",MAX_SOURCE+1)),3),
             (replace(sample,36,struct.pack(">I",16384)),4),
             (replace(sample,76,b"\x06"),4),(replace(sample,76,b"\xff"),4),
             (replace(sample,77,struct.pack(">I",0)),5),
             (replace(sample,77,struct.pack(">I",5)),5),
             (sample[:-1],5),(sample+b"\x00",5),
             (replace(replace(sample,0,b"BAD!"),40,bytes(4)),2),
             (replace(replace(sample,40,bytes(4)),76,b"\xff"),3),
             (replace(replace(sample,76,b"\xff"),77,bytes(4)),4),
             (shard(MAX_SOURCE)+b"\x00",1)]
    return rows


class Rs46StandaloneShardValue(unittest.TestCase):
    def test_original_full_crs1_and_two_unchanged_stock_profiles(self):
        with tempfile.TemporaryDirectory(prefix="trnm-rs46-codec-locked-") as tmp:
            rows=original_rows(Path(tmp),corpus())
        self.assertEqual(set(s for _,s,_ in rows),set(range(6)))
        self.assertTrue(any(len(r)==LIMIT and not s for r,s,_ in rows))
        self.assertEqual(max(len(r) for r,s,_ in rows if s==0),MAX_WIRE)
        self.assertEqual(max(len(r) for r,_,_ in rows),MAX_WIRE+1)
        out=b"\xa5"*121
        work=b"\x5a"*(WORK+3)
        counts=Counter()
        atoms=Counter()
        for raw,code,report in rows:
            if code==0:
                self.assertEqual(report,hashlib.sha256(DOMAIN+raw).digest()+raw[:81])
        with RS46Native(SOURCE) as selfhost, NativeModule(SOURCE,byte_exports=("f0","f1"),backend="direct") as direct:
            for raw,code,report in rows:
                expected=report+out[len(report):]
                obs=selfhost.call(raw,len(out),scratch_length=len(work),timeout=45).require_returned()
                self.assertEqual((obs.value,obs.arguments[:2]),(code,[raw,expected]))
                counts["selfhost-f0"]+=1
                if code==0:
                    self.assertEqual(obs.arguments[1][32:113]+obs.arguments[0][81:],raw)
                if len(raw)<=LIMIT:
                    d=direct.call("f0",[raw,out,work]).require_returned()
                    self.assertEqual((d.value,d.arguments[:2]),(code,[raw,expected]))
                    self.assertEqual(d.arguments[2][WORK:],work[WORK:])
                    counts["direct-f0"]+=1
                if 81<=len(raw)<=MAX_WIRE:
                    d=direct.call("f1",[raw[:81],raw[81:],out,work],timeout=45).require_returned()
                    self.assertEqual((d.value,d.arguments[:3]),(code,[raw[:81],raw[81:],expected]))
                    self.assertEqual(d.arguments[3][WORK:],work[WORK:])
                    if code==0:
                        self.assertEqual(d.arguments[2][32:113]+d.arguments[1],raw)
                    counts["direct-f1"]+=1
            raw=rows[0][0]
            for width,scratch,status in [(112,WORK,102),(113,WORK-1,102),(113,WORK,0)]:
                report=rows[0][2] if status==0 else out[:width]
                d=direct.call("f0",[raw,out[:width],work[:scratch]]).require_returned()
                self.assertEqual((d.value,d.arguments[1]),(status,report))
                atoms["direct-f0"]+=1
                s=selfhost.call(raw,width,scratch_length=scratch).require_returned()
                self.assertEqual((s.value,s.arguments[1]),(status,report))
                atoms["selfhost-f0"]+=1
                d=direct.call("f1",[raw[:81],raw[81:],out[:width],work[:scratch]]).require_returned()
                self.assertEqual((d.value,d.arguments[2]),(status,report))
                atoms["direct-f1"]+=1
            for h,p in [(raw[:80],raw[80:]),(raw,raw[81:]),(b"",raw)]:
                d=direct.call("f1",[h,p,out,work]).require_returned()
                self.assertEqual((d.value,d.arguments),(100,[h,p,out,work]))
                atoms["direct-f1"]+=1
            print(json.dumps({"observations":dict(counts),"abi_controls":dict(atoms),
                              "original_status_counts":dict(Counter(s for _,s,_ in rows)),
                              "original_max_wire":MAX_WIRE,
                              "selfhost_elf_sha256":selfhost.artifact_sha256,
                              "direct_elf_sha256":direct.artifact_sha256},
                             sort_keys=True),flush=True)
