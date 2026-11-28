"""Real original CRC1 exact chunk pin, canonical codeword and native dual."""
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
from hia.tests.test_cell_manifest import CHUNK, MAX_CELL, MAX_CHUNK, MAX_ROWS, wire
from hia.tests.test_da_cell_closure_declared_context_relation import CRATE, LIMIT, LOCK, MANIFEST, ROOT

SOURCE = ROOT / "hia/src/data_availability/rs46_codeword_value.hepta"
REFERENCE = ROOT / "hia/tests/rust_da_rs46_codeword_value_reference.rs"
WORK = 1240
DOMAIN = b"trnm.cell-rs46-codeword.v1\0"


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def original_rows(directory, wires):
    target = directory / "locked-target"
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_PROFILE_DEV_DEBUG": "0"}
    paths = (MANIFEST, LOCK, REFERENCE, *(CRATE / f"src/cell/{name}.rs"
                for name in ("erasure", "erasure/custody", "manifest")))
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
    executable = directory / "original-rs46-codeword-value"
    subprocess.run([rustc, "--edition=2024", "-O", str(REFERENCE),
                    "--extern", f"trnm_data_availability={library}", "-L",
                    f"dependency={target / 'debug/deps'}", "-o", str(executable)],
                   env=env, check=True, capture_output=True, timeout=35)
    wire = b"".join(struct.pack("<I",len(raw))+raw for raw,_ in wires)
    observed = subprocess.run([str(executable)], env=env, input=wire, check=False,
                              capture_output=True, timeout=45)
    if observed.returncode:
        raise ValueError(f"original typed CRC1 fixture failed: {observed.stderr.decode(errors='replace')}")
    if (not observed.stdout or observed.stderr or before != tuple(sha(p.read_bytes()) for p in paths)
            or sha(library.read_bytes()) != library_sha):
        raise ValueError("incomplete or changed original CRC1 evidence")
    rows = []
    cursor = 0
    for raw, wanted_status in wires:
        status=observed.stdout[cursor]
        cursor += 1
        if status != wanted_status:
            raise ValueError(f"unexpected original CRC1 status {status} != {wanted_status}")
        result=observed.stdout[cursor:cursor+300] if status==0 else b""
        cursor += len(result)
        rows.append((raw,status,result))
    if cursor!=len(observed.stdout):
        raise ValueError("unconsumed original CRC1 observations")
    print(json.dumps({"original_inputs": dict(zip([p.name for p in paths], before, strict=True)),
                      "original_library_sha256": library_sha, "actual_executable_sha256": sha(executable.read_bytes()),
                      "oracle_input_sha256": sha(wire), "oracle_stdout_sha256": sha(observed.stdout), "oracle_rows": len(rows)},
                     sort_keys=True), flush=True)
    return rows


def replace(raw, at, value):
    return raw[:at]+value+raw[at+len(value):]


def mid(manifest):
    return hashlib.sha256(b"trnm.cell-manifest.v1\0"+manifest).digest()


def cid(word):
    return hashlib.sha256(DOMAIN+word).digest()


def crc(manifest,index,slots=None):
    row=213+manifest[4]+36*index
    if slots is None:
        slots=[bytes([k])*32 for k in range(10,16)]
    return b"CRC1"+mid(manifest)+struct.pack(">I",index)+manifest[row:row+36]+b"".join(slots)


def request(m,index,word,*,context=None,manifest_id=None,code_pin=None):
    if context is None:
        context=m[4:5+m[4]+160]
    if manifest_id is None:
        manifest_id=mid(m)
    if code_pin is None:
        code_pin=cid(word)
    return b"RCB1"+struct.pack(">I",index)+manifest_id+code_pin+context+struct.pack(">I",len(m))+m+word


def corpus():
    m=wire(b"CRC.metadata-1",2*CHUNK+15,opaque=True)
    rows=[]
    for i in (0,1,2):
        rows.append((request(m,i,crc(m,i)),0))
    base=crc(m,1)
    slots=[bytes([x])*32 for x in range(10,16)]
    for i in range(6):
        for byte in (0,1,19,31):
            nxt=slots.copy()
            nxt[i]=replace(nxt[i],byte,bytes([nxt[i][byte]^0x80]))
            rows.append((request(m,1,crc(m,1,nxt)),0))
        nxt=slots.copy();nxt[i]=bytes(32)
        rows.append((request(m,1,crc(m,1,nxt)),24))
        for j in range(i):
            nxt=slots.copy();nxt[i]=nxt[j]
            rows.append((request(m,1,crc(m,1,nxt)),24))
    for bad_index in (3,16383,16384,2**32-1):
        rows.append((request(m,bad_index,base),13))
    for k in range(32):
        wrong=replace(mid(m),k,bytes([mid(m)[k]^1]))
        rows.append((request(m,1,base,manifest_id=wrong),15))
        wrong=replace(cid(base),k,bytes([cid(base)[k]^1]))
        rows.append((request(m,1,base,code_pin=wrong),22))
    context=m[4:5+m[4]+160]
    for j in (1,2,4,1+m[4],m[4]+32,m[4]+64,m[4]+96,m[4]+128,m[4]+160):
        rows.append((request(m,1,base,context=replace(context,j,bytes([context[j]^64]))),14))
    # Recomputed isolated fixture code pins keep these ordinary comparisons
    # about the original chunk row or distinct opaque slot declarations.
    for j in (4,10,35,36,37,38,39,40,41,42,43,44,52,66,75):
        w=replace(base,j,bytes([base[j]^1]))
        rows.append((request(m,1,w),23))
    for n in (0,1,4,75,76,267):
        rows.append((request(m,1,base[:n]),20))
    rows.append((request(m,1,base+b"\0"),20))
    rows.append((request(m,1,replace(base,0,b"BAD!")),21))
    # Mixed predicate cases check first-error order across real original API stages.
    rows.append((request(m,1,base[:4],manifest_id=bytes(32),context=replace(context,1,b"X")),14))
    rows.append((request(m,2**32-1,base[:4],manifest_id=bytes(32)),15))
    rows.append((request(m,3,base[:4],code_pin=bytes(32)),13))
    rows.append((request(m,1,b"BAD!",code_pin=bytes(32)),20))
    rows.append((request(m,1,replace(base,0,b"BAD!"),code_pin=bytes(32)),21))
    rows.append((request(m,1,replace(base,36,bytes([0xff])),code_pin=cid(base)),22))
    dup=crc(m,1,[slots[0],*slots[:5]])
    rows.append((request(m,1,replace(dup,40,b"\xff")),23))
    bad_manifest=replace(m,len(m)-36,bytes(4))
    rows.append((request(bad_manifest,2**32-1,b"BAD!",context=replace(context,1,b"X")),12))
    # Maximum canonical manifest row count, max selected chunk size, then partial last row.
    upper=wire(b"A"*64,MAX_CELL,MAX_CHUNK,opaque=True)
    rows.append((request(upper,MAX_ROWS-1,crc(upper,MAX_ROWS-1)),0))
    partial=wire(b"A"*64,MAX_CELL-1,MAX_CHUNK,opaque=True)
    rows.append((request(partial,MAX_ROWS-1,crc(partial,MAX_ROWS-1)),0))
    rows.append((request(partial,MAX_ROWS,crc(partial,MAX_ROWS-1)),13))
    return rows


class Rs46CodewordValue(unittest.TestCase):
    def test_original_pinned_crc1_canonical_round_trip_both_stock(self):
        data=corpus()
        with tempfile.TemporaryDirectory(prefix="trnm-rs46-codeword-locked-") as tmp:
            rows=original_rows(Path(tmp),data)
        self.assertEqual(set(s for _,s,_ in rows),{0,12,13,14,15,20,21,22,23,24})
        out=b"O"*309
        work=b"W"*(WORK+5)
        example=rows[0]
        self.assertEqual(example[2],cid(example[0][-268:])+example[0][-268:])
        self.assertTrue(any(len(raw)>590000 and status==0 for raw,status,_ in rows))
        for backend in ("direct","selfhost"):
            with NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as module:
                for start in range(0,len(rows),12):
                    selected=rows[start:start+12]
                    results=module.call_many([("f0",[raw,out,work]) for raw,_,_ in selected],timeout=45)
                    for j,((raw,status,want),res) in enumerate(zip(selected,results,strict=True)):
                        self.assertEqual((res.status,res.value),("returned",status),(start+j,res.stderr))
                        self.assertTrue(res.arguments[0]==raw)
                        self.assertEqual(res.arguments[1],want+out[len(want):])
                        self.assertEqual(res.arguments[2][WORK:],work[WORK:])
                raw,_,report=example
                for raw,wid,size,status in [(raw,299,WORK,102),(raw,300,WORK-1,102),
                        (raw,300,WORK,0),(b"",309,WORK,100),(b"BAD!"+raw[4:],309,WORK,100),
                        (replace(raw,72,bytes([255])),309,WORK,100)]:
                    got=module.call("f0",[raw,out[:wid],work[:size]]).require_returned()
                    self.assertEqual((got.value,got.arguments[0]),(status,raw))
                    self.assertEqual(got.arguments[1],report if status==0 else out[:wid])
                print(json.dumps({"backend":backend,"artifact_sha256":module.artifact_sha256,
                                  "original_matches":len(rows),"abi_controls":6,
                                  "original_counts":dict(Counter(s for _,s,_ in rows))},
                                 sort_keys=True),flush=True)
