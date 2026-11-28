"""Frozen public BEP52 chunk comparison with locally owned inert synthetic pieces."""
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
from hia.tests.test_da_bep52_binding_value import BASE, CHUNK, declared, overwrite, request, sha
from hia.tests.test_da_cell_closure_declared_context_relation import CRATE, LOCK, MANIFEST, ROOT

SOURCE = ROOT / "hia/src/data_availability/bep52_piece_compare.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_bep52_piece_compare_reference.rs"
MARK_OUT = b"\xa5" * 537

def locked_original(target):
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    tracked = (LOCK, MANIFEST, REFERENCE, CRATE / "src/cell/bep52.rs", CRATE / "src/cell/manifest.rs", CRATE / "src/cell/store.rs")
    before = tuple(sha(x.read_bytes()) for x in tracked)
    version = subprocess.run([rustc, "--version"], env=env, check=True, capture_output=True, text=True,
                             timeout=10).stdout
    if not version.startswith("rustc 1.95.0 (59807616e "):
        raise ValueError("BEP52 qualification requires the exact frozen Rust")
    runner = subprocess.run([cargo, "build", "--locked", "--offline", "--manifest-path",
                             str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability",
                             "--lib", "--target-dir", str(target), "--message-format=json"],
                            env=env, check=True, capture_output=True, text=True, timeout=180)
    builds = list(map(json.loads, runner.stdout.splitlines()))
    if not builds or builds[-1] != {"reason": "build-finished", "success": True}:
        raise ValueError("Missing actual original Cargo terminal success")
    [build] = [x for x in builds if x.get("reason") == "compiler-artifact"
               and x["target"]["name"] == "trnm_data_availability" and x["target"]["kind"] == ["lib"]]
    if build["features"] != ["default"] or Path(build["manifest_path"]) != MANIFEST:
        raise ValueError("Wrong original library target/profile")
    [library] = [Path(x) for x in build["filenames"] if x.endswith(".rlib")]
    library_sha = sha(library.read_bytes())
    binary = target / "bep52-piece-compare-original"
    subprocess.run([rustc, "--edition=2024", "-O", "-Dwarnings", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(binary)],
                   env=env, check=True, capture_output=True, timeout=35)
    before_inputs = {"original_inputs": dict(zip((x.name for x in tracked), before, strict=True)),
                     "original_rlib_sha256": library_sha, "original_elf_sha256": sha(binary.read_bytes())}

    def check(rows):
        observed = native_original_rows(binary, env, rows)
        if (sha(library.read_bytes()) != library_sha
                or before != tuple(sha(x.read_bytes()) for x in tracked)):
            raise ValueError("Frozen original side changed")
        return observed
    return check, before_inputs


def native_original_rows(binary, env, rows):
    data = b"".join(struct.pack("<I", len(sample)) + sample for sample, *_ in rows)
    result = subprocess.run([str(binary)], env=env, input=data, check=True, capture_output=True, timeout=45)
    if result.stderr or not result.stdout:
        raise ValueError("Incomplete frozen CBP1 output")
    answers = []
    pos = 0
    for _, wanted, _ in rows:
        status = result.stdout[pos]
        pos += 1
        if status != wanted:
            raise ValueError(f"External input disagrees with frozen status {status}, expected {wanted}")
        if status:
            answers.append(b"")
            continue
        n, = struct.unpack_from(">H", result.stdout, pos)
        pos += 2
        if not 77 <= n <= 525:
            raise ValueError("Invalid original canonical CBP1 length")
        end = pos + n
        answers.append(result.stdout[pos:end])
        pos = end
    if pos != len(result.stdout):
        raise ValueError("Incomplete original observation consumption")
    print(json.dumps({"input_sha256": sha(data), "stdout_sha256": sha(result.stdout),
                      "actual_rows": len(rows)}, sort_keys=True), flush=True)
    return answers



def compare_request(bpb, cbp, data):
    return bpb+cbp+data+struct.pack(">IH",len(bpb),len(cbp))


def owned_cases():
    specs = [(1,0,n) for n in (1,3,9,63,64,65,8191,16383,16384)]
    specs += [(count,selected,tail) for count in (2,3,5,8,9,17,33)
              for selected,tail in ((0,37),(count//2,99),(count-1,13))]
    specs += [(4097,4096,147),(16384,16383,16384)]
    for row,(count,i,last) in enumerate(specs):
        n = last if i==count-1 else 16384
        raw=bytes((x*39+row)%251 for x in range(n))
        m=declared((count-1)*CHUNK+last,row)
        at=217+m[4]+i*36
        m=overwrite(m,at,hashlib.sha256(raw).digest())
        bpb=request(m)
        cap=BASE+32*(1<<(count-1).bit_length())
        yield bpb,raw,count,i,cap


class DaBep52PieceCompare(unittest.TestCase):
    def test_actual_frozen_bep52_chunk_comparison_both_stock(self):
        rows = list(owned_cases())
        construction = [(bpb+struct.pack(">IB",i,1),0,cap) for bpb,_,_,i,cap in rows]
        with tempfile.TemporaryDirectory(prefix="trnm-bep52-piece-compare-") as tmp:
            run, proof = locked_original(Path(tmp))
            canonical = run(construction)
            verified = []
            def new(bpb, p, data, status, guard):
                verified.append((compare_request(bpb,p,data),status,guard))
            for (bpb,data,count,index,cap),p in zip(rows,canonical,strict=True):
                self.assertEqual(struct.unpack_from(">II",p,68),(index,count))
                new(bpb,p,data,0,cap)
                if count>33:
                    continue
                new(bpb,p,data[:-1],42,cap)
                new(bpb,p,overwrite(data,0,bytes([data[0]^1])),43,cap)
                new(bpb,overwrite(p,36,bytes([p[36]^1])),data,40,cap)
                new(bpb,overwrite(p,4,bytes([p[4]^1])),data,40,1344)
            (bp,data,_,_,cap),p = next((row,p) for row,p in zip(rows,canonical,strict=True)
                                      if row[2:4]==(5,0))
            new(bp,overwrite(p,72,struct.pack(">I",6)),data,41,cap)
            new(bp,overwrite(p,77,bytes([p[77]^1])),data,44,cap)
            new(bp,overwrite(p,77,bytes([p[77]^1])),data[:-1],42,cap)
            new(bp,overwrite(p,0,b"X"),data,32,1232)
            new(bp,p[:76],data,31,1232)
            new(bp,overwrite(p,72,bytes(4)),data,33,1232)
            new(bp,overwrite(p,68,struct.pack(">I",5)),data,34,1232)
            new(bp,overwrite(p,76,b"\x01"),data,35,1232)
            new(overwrite(bp,4,bytes([bp[4]^1])),overwrite(p,0,b"X"),data,15,1232)
            new(overwrite(bp,37,b"X"),overwrite(p,0,b"X"),data,14,0)
            (bp,data,_,_,cap),p = next((row,p) for row,p in zip(rows,canonical,strict=True)
                                      if row[2:4]==(5,4))
            self.assertEqual(p[77:109],bytes(32))
            self.assertEqual(p[109:141],hashlib.sha256(bytes(64)).digest())
            for loc in (77,109):
                new(bp,overwrite(p,loc,bytes([p[loc]^1])),data,36,1344)
            seen = run([(wire+b"\x02",state,guard) for wire,state,guard in verified])
        self.assertEqual(len(canonical),32)
        observed=Counter(status for _,status,_ in verified)
        self.assertEqual(len(seen),len(verified))
        self.assertEqual(observed[0], 32)
        self.assertEqual(set(observed),{0,14,15,31,32,33,34,35,36,40,41,42,43,44})
        self.assertEqual(len(rows[-1][1]),16384)
        self.assertEqual(rows[-1][2],16384)
        print(json.dumps({**proof,"original_generated_proofs":len(canonical),"comparisons":len(verified),
                          "status_counts":dict(observed)},sort_keys=True),flush=True)
        cases = [(wire,MARK_OUT,b"\x79"*(max(1344,guard)+13),state,guard)
                 for wire,state,guard in verified]
        sample,_,cap=verified[0]
        controls = [(sample,b"",b"\x79"*cap,0,cap),
                    (sample,MARK_OUT,b"\x79"*(cap-1),102,1344),
                    (sample,MARK_OUT,b"\x79"*1343,102,1232),
                    (sample,MARK_OUT,b"\x79"*1231,102,0),
                    (b"",MARK_OUT,b"",100,0),
                    (sample[:-6]+struct.pack(">IH",(1<<32)-1,77),MARK_OUT,b"\x79"*cap,100,0)]
        cases+=controls
        small=[c for c in cases if len(c[0])<40000]
        large=[c for c in cases if len(c[0])>=40000]
        batches=[small[i:i+12] for i in range(0,len(small),12)]+[[x] for x in large]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as n:
                for batch in batches:
                    got=n.call_many([("f0",list(c[:3])) for c in batch],timeout=60)
                    for (sample,out,work,status,guard), result in zip(batch,got,strict=True):
                        self.assertEqual(result.require_returned().value,status,len(sample))
                        self.assertEqual(result.arguments[:2], [sample,out])
                        self.assertEqual(result.arguments[2][guard:],work[guard:])
                print(json.dumps({"backend":backend,"native_elf":n.artifact_sha256,
                                  "verified_original":len(verified),"additional_abi":len(controls)},
                                 sort_keys=True),flush=True)
