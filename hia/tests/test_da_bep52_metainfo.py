"""Actual public BEP52 canonical immutable metadata bytes and equality, with no I/O."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_bep52_binding_value import BASE, CHUNK, declared, overwrite, request, sha
from hia.tests.test_da_cell_closure_declared_context_relation import CRATE, LOCK, MANIFEST, ROOT

SOURCE = ROOT / "hia/src/data_availability/bep52_metainfo.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_bep52_metainfo_reference.rs"
MAX_META = 525312
MAX_LOAN = MAX_EXTENT + MAX_META + 5

def locked_original(target):
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    tracked = (LOCK, MANIFEST, REFERENCE, CRATE / "src/cell/bep52.rs", CRATE / "src/cell/manifest.rs")
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
    binary = target / "bep52-metainfo-original"
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
        raise ValueError("Incomplete frozen metainfo output")
    answers = []
    pos = 0
    for sample, wanted, _ in rows:
        status = result.stdout[pos]
        pos += 1
        if status != wanted:
            raise ValueError(f"External input disagrees with frozen status {status}, expected {wanted}")
        if status:
            answers.append(b"")
            continue
        if sample[-1] != 0:
            answers.append(b"")
            continue
        info_len,n = struct.unpack_from(">HI", result.stdout, pos)
        if not 1 <= info_len <= 256 or not 1 <= n <= MAX_META:
            raise ValueError("Invalid original canonical metainfo length")
        end = pos + 6 + n
        answers.append((info_len,result.stdout[pos+2:end]))
        pos = end
    if pos != len(result.stdout):
        raise ValueError("Incomplete original observation consumption")
    print(json.dumps({"input_sha256": sha(data), "stdout_sha256": sha(result.stdout),
                      "actual_rows": len(rows)}, sort_keys=True), flush=True)
    return answers



def pack(bpb, supplied, mode):
    return bpb+supplied+struct.pack(">IB",len(bpb),mode)


def extent(count, info=False):
    tree=32*(1<<(count-1).bit_length())
    return BASE + (tree if info else max(tree,1024+count*32))


def generation():
    sizes=[(n, n % 79) for n in (1,3,9,10,99,100,1000,16384,16385,32768,32769,81921,
                                131071,131073,163841,1000000,16777217)]
    near=(MAX_EXTENT-637-2*len(b"Declared.Bep52_v1"))//68
    sizes.extend([((count-1)*CHUNK+17,count) for count in (4097,near,16383,16384)])
    rows = []
    for size, seed in sizes:
        m=declared(size,seed)
        n=(size+CHUNK-1)//CHUNK
        rows.append((request(m),n))
    return rows, near


class DaBep52Metainfo(unittest.TestCase):
    def test_actual_public_metainfo_generation_and_equality_both_stock(self):
        seeds,near=generation()
        generated=[(pack(bpb,b"",0),0,extent(count)) for bpb,count in seeds]
        with tempfile.TemporaryDirectory(prefix="trnm-bep52-metainfo-") as tmp:
            run,proof=locked_original(Path(tmp))
            output=run(generated)
            verifies = []
            largest=near_n=near_reference=max_reference=None
            def add(bpb,value,mode,status,guard):
                v=pack(bpb,value,mode)
                verifies.append((v,status,guard))
                return len(v)
            for k,((bpb,count),(info_len,result)) in enumerate(zip(seeds,output,strict=True)):
                meta=result[4:]
                self.assertEqual(len(meta),int.from_bytes(result[:4],"big"))
                info=meta[7:7+info_len]
                self.assertTrue(meta.startswith(b"d4:info"))
                self.assertTrue(info.startswith(b"d9:file tree"))
                self.assertEqual(meta[7+info_len:23+info_len],b"12:piece layersd")
                self.assertTrue(meta.endswith(b"ee"))
                if count==1:
                    self.assertEqual(meta[-18:],b"12:piece layersdee")
                else:
                    layer_start=23+info_len+3+32+len(str(count*32))+1
                    self.assertEqual(len(meta)-layer_start-2,count*32)
                    if k<13:
                        reordered=meta[:layer_start]+meta[layer_start+32:layer_start+64]+meta[layer_start:layer_start+32]+meta[layer_start+64:]
                        self.assertNotEqual(reordered,meta)
                        add(bpb,reordered,2,33,extent(count))
                        add(bpb,meta[:layer_start]+meta[layer_start+32:],2,33,extent(count))
                add(bpb,info,1,0,extent(count,True))
                length=add(bpb,meta,2,0,extent(count))
                if count==near:
                    near_n=length
                    near_reference=len(meta)
                if count==16384:
                    largest=length
                    max_reference=len(meta)
                if k>=13:
                    continue
                add(bpb,overwrite(info,0,b"x"),1,31,extent(count,True))
                add(bpb,info+b"e",1,31,extent(count,True))
                add(bpb,overwrite(meta,0,b"x"),2,33,extent(count))
                add(bpb,meta+b"e",2,33,extent(count))
            small,n=seeds[1]
            wrong_manifest=overwrite(small,4,bytes([small[4]^1]))
            wrong_context=overwrite(small,37,b"X")
            other=request(declared(32769,piece=32768))
            add(small,b"x"*256,1,31,extent(n,True))
            add(small,b"x"*257,1,30,1232)
            add(small,b"x"*MAX_META,2,33,extent(n))
            add(small,b"x"*(MAX_META+1),2,32,1232)
            add(wrong_manifest,b"x"*257,1,15,1232)
            add(wrong_context,b"x"*(MAX_META+1),2,14,0)
            add(other,b"x"*(MAX_META+1),2,16,1232)
            answers=run(verifies)
        self.assertEqual(len(generated),21)
        self.assertEqual(len(verifies),111)
        self.assertEqual(answers,[b""]*len(verifies))
        self.assertEqual(max_reference,524510)
        self.assertEqual(largest,1114783)
        self.assertTrue(near_n<=MAX_EXTENT<near_n+68)
        print(json.dumps({**proof,"generated":len(generated),"verification":len(verifies),
                          "max_meta_bytes":max_reference,"wide_combined_bytes":largest,
                          "direct_combined_bytes":near_n,"direct_metainfo_bytes":near_reference,
                          "status_counts":dict(Counter(s for _,s,_ in verifies))},sort_keys=True),flush=True)
        cases=[]
        for (sample,state,guard),(info_n,data) in zip(generated,output,strict=True):
            cases.append((sample,b"\xa5"*(len(data)+13),b"\x79"*(guard+11),state,data,guard))
        cases += [(sample,b"\xa5"*9,b"\x79"*(max(1232,guard)+11),state,b"",guard)
                  for sample,state,guard in verifies]
        sample,_,work,_,data,guard=cases[0]
        controls=[(b"",b"\xa5",b"",100,b"",0),
                  (sample[:-1]+b"\x03",b"\xa5",work,100,b"",0),
                  (sample[:-5]+struct.pack(">IB",(1<<32)-1,1),b"\xa5",work,100,b"",0),
                  (sample,b"\xa5"*(len(data)-1),work,102,b"",guard),
                  (sample,b"\xa5"*len(data),work[:guard-1],102,b"",1232),
                  (sample,b"\xa5"*len(data),work[:guard],0,data,guard),
                  (sample,b"\xa5"*len(data),work[:1231],102,b"",0)]
        cases+=controls
        for backend in ("direct","selfhost"):
            profile=[c for c in cases if backend=="selfhost" or len(c[0])<=MAX_EXTENT]
            small=[c for c in profile if max(map(len,c[:3]))<40000]
            large=[c for c in profile if max(map(len,c[:3]))>=40000]
            batches=[small[i:i+11] for i in range(0,len(small),11)]+[[x] for x in large]
            kw={"max_input_extent":MAX_LOAN} if backend=="selfhost" else {}
            exports = ("f0", "f1") if backend == "direct" else ("f0",)
            with self.subTest(backend=backend),NativeModule(SOURCE,byte_exports=exports,
                        backend=backend,**kw) as n:
                for batch in batches:
                    got=n.call_many([("f0",list(c[:3])) for c in batch],timeout=60)
                    for (sample,out,work,status,expected,guard),result in zip(batch,got,strict=True):
                        self.assertEqual(result.require_returned().value,status,len(sample))
                        self.assertEqual(result.arguments[0],sample)
                        self.assertEqual(result.arguments[1],expected+out[len(expected):])
                        self.assertEqual(result.arguments[2][guard:],work[guard:])
                print(json.dumps({"backend":backend,"native_elf":n.artifact_sha256,
                                  "original_matches":len(profile)-len(controls),
                                  "abi_controls":len(controls)},sort_keys=True),flush=True)
                if backend == "direct":
                    self._split_direct(n, verifies)

    def _split_direct(self, native, verifies):
        # Split the exact two immutable byte strings already passed in one loan
        # to the frozen public Rust oracle. Do not regenerate, parse or hash
        # either descriptor on the host for native verification.
        rows = []
        for raw, status, limit in verifies:
            if raw[-1] != 2:
                continue
            body = raw[:-5]
            prefix_len = int.from_bytes(raw[-5:-1], "big")
            rows.append((body[:prefix_len], body[prefix_len:], status, limit))
        self.assertEqual(len(rows), 61)
        bpb, meta, expected, need = max((r for r in rows if r[2]==0),
                                       key=lambda r: len(r[0])+len(r[1]))
        self.assertEqual((len(bpb),len(meta)),(590268,524510))
        self.assertLessEqual(max(len(bpb),len(meta)), MAX_EXTENT)
        self.assertGreater(len(bpb)+len(meta), MAX_EXTENT)
        self.assertEqual(expected,0)
        out = b"\xa5"*9
        work = b"\x79"*(need+11)
        vectors = [(p,m,out,b"\x79"*(max(1232,guard)+11),status,guard)
                   for p,m,status,guard in rows]
        controls = [(bpb,meta,b"",work[:need],0,need),
                    (bpb,meta,out,work[:need-1],102,1232),
                    (bpb,meta,out,work[:1231],102,0),
                    (b"",meta,out,work,100,0),
                    (bpb,b"",out,work,33,need)]
        vectors += controls
        small = [v for v in vectors if max(map(len,v[:4]))<40000]
        large = [v for v in vectors if max(map(len,v[:4]))>=40000]
        batches = [small[i:i+11] for i in range(0,len(small),11)] + [[r] for r in large]
        for batch in batches:
            observed = native.call_many([("f1", list(v[:4])) for v in batch], timeout=60)
            for (prefix,data,out,work,status,guard), result in zip(batch,observed,strict=True):
                self.assertEqual(result.require_returned().value,status,(len(prefix),len(data)))
                self.assertEqual(result.arguments[:3],[prefix,data,out])
                self.assertEqual(result.arguments[3][guard:],work[guard:])
        print(json.dumps({"backend":"direct","export":"f1","native_elf":native.artifact_sha256,
                          "original_matches":len(rows),"abi_controls":len(controls),
                          "max_valid_physical_loans":[len(bpb),len(meta)]},sort_keys=True),flush=True)
