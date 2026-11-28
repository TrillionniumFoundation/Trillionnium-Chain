"""Frozen public BEP52 descriptor value profile using deterministic inert fixtures."""
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

SOURCE = ROOT / "hia/src/data_availability/bep52_magnet_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_bep52_magnet_value_reference.rs"
PREFIX = b"magnet:?xt=urn:btmh:1220"
OUT = b"\xa5" * 137
DECODE = 1312

def locked_original(target):
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    tracked = (LOCK, MANIFEST, REFERENCE, CRATE / "src/cell/bep52.rs", CRATE / "src/cell/manifest.rs", CRATE / "src/cell.rs")
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
    binary = target / "bep52-magnet-value-original"
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
        raise ValueError("Incomplete frozen descriptor output")
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
        if sample[-1] == 1:
            answers.append(b"")
            continue
        end = pos + 120
        payload = result.stdout[pos:end]
        if len(payload) != 120 or not payload[32:].startswith(PREFIX):
            raise ValueError("Invalid original canonical descriptor length")
        answers.append(payload)
        pos = end
    if pos != len(result.stdout):
        raise ValueError("Incomplete original observation consumption")
    print(json.dumps({"input_sha256": sha(data), "stdout_sha256": sha(result.stdout),
                      "actual_rows": len(rows)}, sort_keys=True), flush=True)
    return answers




def pack(bpb, supplied, mode):
    return bpb+supplied+struct.pack(">IB",len(bpb),mode)


def standalone_rows():
    raw=[bytes([k])*32 for k in range(0,256,9)]
    raw.extend(bytes(range(k,k+32)) for k in range(0,225,32))
    rows=[(PREFIX+d.hex().encode()+b"\0",0,DECODE) for d in raw]
    sample=PREFIX+bytes(range(32)).hex().encode()
    for pos in range(len(PREFIX)):
        rows.append((overwrite(sample,pos,b"X")+b"\0",30,0))
    for pos in (24,31,40,64,86,87):
        for changed in (b"F", b"g", b" ", b"\n"):
            rows.append((overwrite(sample,pos,changed)+b"\0",31,0))
    rows.extend((overwrite(sample,pos,"é".encode())+b"\0",31,0) for pos in (24,46,86))
    rows.extend((changed+b"\0",30,0) for changed in (b"",sample[:-1],b" "+sample,
                  sample+b" ",sample+b"#",sample+b"x",sample[1:]))
    return rows


def bindings():
    for count,tail,seed in ((1,1,4),(1,3,8),(2,11,19),(3,1,25),(5,1,28),(17,99,31),(257,29,32),
                           (4097,41,60),(16384,16384,81)):
        yield request(declared((count-1)*CHUNK+tail,seed)), BASE+32*(1<<(count-1).bit_length())
    simple=declared(32769,4)
    # The same synthetic declared payload in another valid typed context.
    changed=overwrite(simple,5,b"Q")
    yield request(simple),BASE+32*4
    yield request(changed),BASE+32*4


class DaBep52MagnetValue(unittest.TestCase):
    def test_actual_frozen_bep52_descriptor_round_trip_and_binding_both_stock(self):
        positive = list(bindings())
        prepare = [(pack(bpb,b"",2),0,guard) for bpb,guard in positive]
        parse = standalone_rows()
        with tempfile.TemporaryDirectory(prefix="trnm-bep52-descriptor-") as tmp:
            run, proof = locked_original(Path(tmp))
            typed = run(prepare)
            verify = []
            for (bpb,guard), projection in zip(positive,typed,strict=True):
                text = projection[32:]
                verify.append((pack(bpb,text,1),0,guard))
                if guard>BASE+32*256:
                    continue
                valid_other = overwrite(text,24,b"0" if text[24]!=48 else b"1")
                verify.append((pack(bpb,valid_other,1),32,guard))
                verify.append((pack(bpb,overwrite(text,24,b"F"),1),31,1232))
                verify.append((pack(bpb,text+b"x",1),30,1232))
            bpb, guard=positive[0]
            text=typed[0][32:]
            wrong=overwrite(bpb,4,bytes([bpb[4]^1]))
            context=overwrite(bpb,37,b"X")
            other=request(declared(32769,piece=32768))
            verify += [(pack(wrong,text,1),15,1232),(pack(wrong,text[:-1],1),15,1232),
                       (pack(context,text[:-1],1),14,0),(pack(other,text[:-1],1),16,1232),
                       (pack(positive[-1][0],typed[-2][32:],1),0,positive[-1][1])]
            result = run(parse+verify)
        self.assertEqual(len(typed),11)
        self.assertEqual(typed[-1],typed[-2])
        self.assertEqual(len(parse),95)
        self.assertEqual(len(verify),40)
        for (sample,status,_),answer in zip(parse+verify,result,strict=True):
            if sample[-1]==0 and status==0:
                self.assertEqual(answer[:32],bytes.fromhex(sample[24:-1].decode()))
                self.assertEqual(answer[32:],sample[:-1])
            else:
                self.assertFalse(answer)
        print(json.dumps({**proof,"original_parse":len(parse),"original_verify":len(verify),
                          "authentic_synthetic_metadata":len(typed),
                          "status_counts":dict(Counter(s for _,s,_ in parse+verify))},sort_keys=True),flush=True)
        cases = [(data,OUT,b"\x79"*(max(DECODE,guard)+13),s,want,guard)
                 for (data,s,guard),want in zip(parse+verify,result,strict=True)]
        raw=cases[0][0]
        expected=result[0]
        empty=verify[0][0]
        controls=[(b"",OUT,b"",100,b"",0),
                  (raw[:-1]+b"\x02",OUT,b"",100,b"",0),
                  (overwrite(raw,24,b"\xff"),OUT,b"\x79"*DECODE,100,b"",0),
                  (raw,OUT[:119],b"\x79"*DECODE,102,b"",DECODE),
                  (raw,OUT,b"\x79"*(DECODE-1),102,b"",0),
                  (raw,OUT[:120],b"\x79"*DECODE,0,expected,DECODE),
                  (empty,b"",b"\x79"*1791,102,b"",DECODE),
                  (empty,b"",b"\x79"*1792,0,b"",1792)]
        cases+=controls
        small=[c for c in cases if max(map(len,c[:3]))<40000]
        large=[c for c in cases if max(map(len,c[:3]))>=40000]
        batches=[small[i:i+12] for i in range(0,len(small),12)]+[[x] for x in large]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as n:
                for batch in batches:
                    got=n.call_many([("f0",list(c[:3])) for c in batch],timeout=60)
                    for (sample,out,work,status,expected,guard),r in zip(batch,got,strict=True):
                        self.assertEqual(r.require_returned().value,status,len(sample))
                        self.assertEqual(r.arguments[0],sample)
                        self.assertEqual(r.arguments[1],expected+out[len(expected):])
                        self.assertEqual(r.arguments[2][guard:],work[guard:])
                print(json.dumps({"backend":backend,"native_elf":n.artifact_sha256,
                                  "original_matches":len(parse)+len(verify),
                                  "abi_controls":len(controls)},sort_keys=True),flush=True)
