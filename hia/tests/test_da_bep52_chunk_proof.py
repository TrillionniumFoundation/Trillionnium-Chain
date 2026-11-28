"""Frozen public CBP1 proof generation and structural readback, without payload access."""
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

SOURCE = ROOT / "hia/src/data_availability/bep52_chunk_proof.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_bep52_chunk_proof_reference.rs"
MARK_OUT = b"\xa5" * 537

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
    binary = target / "bep52-chunk-proof-original"
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


def generation():
    cases = []
    for count in (1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 33, 65):
        manifest = declared((count-1)*CHUNK+11, count)
        depth = (count-1).bit_length()
        work = BASE + 32*((1 << depth) + depth)
        cases.extend((request(manifest)+struct.pack(">IB", index, 1), 0, work)
                     for index in sorted({0, count//2, count-1}))
    for count, index in ((257, 256), (4097, 4096), (16383, 16382), (16384, 16383)):
        depth = (count-1).bit_length()
        cases.append((request(declared((count-1)*CHUNK+29,count))+struct.pack(">IB",index,1),
                      0,BASE+32*((1<<depth)+depth)))
    for count in (1, 5, 7, 9):
        sample = request(declared((count-1)*CHUNK+53))
        cases += [(sample+struct.pack(">IB", count, 1),34,1232),
                  (sample+struct.pack(">IB", (1<<32)-1, 1),34,1232)]
    sample = request(declared(32769))
    cases += [(overwrite(sample,4,b"\xff")+struct.pack(">IB",9,1),15,1232),
              (overwrite(sample,37,b"X")+struct.pack(">IB",9,1),14,0),
              (request(declared(35000,piece=32768))+struct.pack(">IB",9,1),16,1232)]
    return cases


def decoding(proofs):
    cases = [(p+b"\0",0,1344) for p in proofs if p]
    # Last real leaves beside entirely padded siblings at three tree heights.
    selected = {}
    for p in proofs:
        if p:
            index, count = struct.unpack_from(">II",p,68)
            selected[index, count] = p
    for key in ((2,3),(4,5),(8,9),(16,17),(4096,4097)):
        p = selected[key]
        index, count = key
        padded = [h for h in range(p[76]) if (((index >> h)^1) << h) >= count]
        for h in padded:
            i = 77 + 32*h
            cases.append((overwrite(p,i,bytes([p[i]^1]))+b"\0",36,1344))
        cases.append((p[:-1]+b"\0",35,0))
    sample=selected[4,5]
    singleton=selected[0,1]
    minimum=singleton[:-1]
    cases += [(b"\0",31,0), (minimum+b"\0",31,0), (b"x"*526+b"\0",31,0),
              (overwrite(sample,0,b"X")+b"\0",32,0),
              (overwrite(sample,72,bytes(4))+b"\0",33,0),
              (overwrite(sample,72,struct.pack(">I",16385))+b"\0",33,0),
              (overwrite(sample,68,struct.pack(">I",5))+b"\0",34,0),
              (overwrite(sample,76,b"\x04")+b"\0",35,0),
              (sample+b"\xa5\0",35,0)]
    return cases, sample, selected


class DaBep52ChunkProof(unittest.TestCase):
    def test_actual_frozen_cbp1_generation_and_structural_readback_both_stock(self):
        create = generation()
        with tempfile.TemporaryDirectory(prefix="trnm-bep52-proof-original-") as tmp:
            run, proof = locked_original(Path(tmp))
            first = run(create)
            read, chosen, selected = decoding(first)
            second = run(read)
        self.assertEqual(len(chosen),173)
        proof0,proof1=chosen[77:109],chosen[109:141]
        self.assertEqual(proof0,bytes(32))
        self.assertEqual(proof1,hashlib.sha256(bytes(64)).digest())
        self.assertEqual(len(selected[16383,16384]),525)
        self.assertEqual(second[0],first[0])
        proof.update(generation=len(create),readback=len(read),status_counts=dict(Counter(s for _,s,_ in create+read)))
        print(json.dumps(proof,sort_keys=True),flush=True)
        def row(sample,status,extent,out):
            return sample, MARK_OUT, b"\x79"*(max(1344,extent)+13), status, out, extent
        cases=[row(*spec,out) for spec,out in zip(create+read,first+second,strict=True)]
        gen = create[0][0]
        answer = first[0]
        cap = create[0][2]
        dec=chosen+b"\0"
        controls=[(b"",MARK_OUT,b"",100,b"",0),
                  (gen[:-1]+b"\x02",MARK_OUT,b"\x79"*cap,100,b"",0),
                  (gen,MARK_OUT[:len(answer)-1],b"\x79"*cap,102,b"",1232),
                  (gen,MARK_OUT,b"\x79"*(cap-1),102,b"",1232),
                  (gen,MARK_OUT[:len(answer)],b"\x79"*cap,0,answer,cap),
                  (dec,MARK_OUT[:len(chosen)-1],b"\x79"*1344,102,b"",1344),
                  (dec,MARK_OUT,b"\x79"*1343,102,b"",0),
                  (dec,MARK_OUT[:len(chosen)],b"\x79"*1344,0,chosen,1344)]
        cases+=controls
        small=[c for c in cases if len(c[0])<10000]
        large=[c for c in cases if len(c[0])>=10000]
        batches=[small[i:i+12] for i in range(0,len(small),12)]+[[x] for x in large]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as n:
                for batch in batches:
                    got=n.call_many([("f0",list(c[:3])) for c in batch],timeout=60)
                    for (sample,out,work,status,expected,guard), result in zip(batch,got,strict=True):
                        self.assertEqual(result.require_returned().value,status,len(sample))
                        self.assertEqual(result.arguments[0],sample)
                        self.assertEqual(result.arguments[1],expected+out[len(expected):])
                        self.assertEqual(result.arguments[2][guard:],work[guard:])
                print(json.dumps({"backend":backend,"native_elf":n.artifact_sha256,
                                  "generation":len(create),"decode":len(read),
                                  "abi_controls":len(controls)},sort_keys=True),flush=True)
