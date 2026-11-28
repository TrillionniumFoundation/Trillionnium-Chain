"""Offline structural projection of the exact frozen private BEP52 bencode parser."""
from collections import Counter
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_bep52_binding_value import sha
from hia.tests.test_da_cell_closure_declared_context_relation import CRATE, LOCK, MANIFEST, ROOT

SOURCE = ROOT / "hia/src/data_availability/bep52_bencode_prefix.hepta"
WITNESS = ROOT / "hia/tests/rust_da_bep52_bencode_prefix_reference.rs"
CELL = CRATE / "src/cell.rs"
PARSER = CRATE / "src/cell/bep52_peer/bencode.rs"
CAP = 1 << 20
OUT = bytes([0xa5]) * 32
WORK = bytes([0x5c]) * 89


def original_capture(target, rows, witness=WITNESS):
    rustc = os.environ.get("TRNM_HIA_RUSTC") or os.environ.get("RUSTC", "rustc")
    cargo = os.environ.get("CARGO", "cargo")
    paths = (LOCK, MANIFEST, CELL, PARSER, witness)
    before = {p.name: sha(p.read_bytes()) for p in paths}
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2",
           "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0"}
    v = subprocess.run([rustc, "--version"], check=True, capture_output=True,
                       env=env, timeout=10).stdout
    if not v.startswith(b"rustc 1.95.0 (59807616e "):
        raise ValueError("original parser witness needs the locked Rust toolchain")
    prep = subprocess.run([cargo, "build", "--locked", "--offline", "--manifest-path",
                           str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-data-availability",
                           "--lib", "--target-dir", str(target), "--message-format=json"],
                          check=True, capture_output=True, env=env, timeout=180)
    js = list(map(json.loads, prep.stdout.splitlines()))
    if not js or js[-1] != {"reason": "build-finished", "success": True}:
        raise ValueError("original locked Cargo library has no terminal success")
    [a] = [x for x in js if x.get("reason") == "compiler-artifact"
           and x["target"]["name"] == "trnm_data_availability" and x["target"]["kind"] == ["lib"]]
    if Path(a["manifest_path"]) != MANIFEST or a["features"] != ["default"]:
        raise ValueError("original locked library package/profile mismatch")
    [rlib] = [Path(p) for p in a["filenames"] if p.endswith(".rlib")]
    rlib_sha = sha(rlib.read_bytes())
    # Extract exactly this private immutable helper, no reimplementation/shim.
    [require] = re.findall(rb"(?m)^pub\(crate\) fn require\([^\n]+\n(?:.*\n)*?^}\n", CELL.read_bytes())
    include = target / "exact_cell_require.rs"
    include.write_bytes(require)
    env["HIA_BENCODE_ORIGINAL_REQUIRE"] = str(include)
    elf = target / "frozen-bencode-prefix"
    compile_observation = subprocess.run([rustc, "--edition=2024", "-O", "-Dwarnings", str(witness), "--extern",
                    f"trnm_data_availability={rlib}", "-L", f"dependency={target / 'debug/deps'}",
                    "-o", str(elf)], check=False, capture_output=True, env=env, timeout=35)
    if compile_observation.returncode or compile_observation.stderr:
        raise ValueError(compile_observation.stderr.decode(errors="replace"))
    data = b"".join(struct.pack("<I", len(x)) + x for x in rows)
    execution = subprocess.run([str(elf)], input=data, capture_output=True, check=True,
                               env=env, timeout=45)
    if execution.stderr or before != {p.name: sha(p.read_bytes()) for p in paths} or rlib_sha != sha(rlib.read_bytes()):
        raise ValueError("original source changed or witness emitted diagnostics")
    proof = dict(original_inputs=before, original_require_sha256=sha(require),
                 original_elf_sha256=sha(elf.read_bytes()), original_rlib_sha256=rlib_sha,
                 original_rows=len(rows), framed_inputs_sha256=sha(data),
                 original_stdout_sha256=sha(execution.stdout))
    return execution.stdout, proof


def original(target, rows):
    stdout, proof = original_capture(target, rows)
    result = []
    at = 0
    for row in rows:
        code = stdout[at]
        at += 1
        payload = b""
        if code == 0:
            payload = stdout[at:at+24]
            kind, consumed, count = struct.unpack(">QQQ", payload)
            if not (1 <= kind <= 4 and 0 < consumed <= len(row) and 1 <= count <= 128):
                raise ValueError("original witness observation is outside the expected frame")
            at += 24
        result.append((code, payload))
    if at != len(stdout):
        raise ValueError("original output extent mismatch")
    print(json.dumps(dict(proof, status_counts=Counter(x[0] for x in result)),
                     sort_keys=True), flush=True)
    return result


def string(body):
    return str(len(body)).encode() + b":" + body


def array(seq):
    return b"l" + b"".join(seq) + b"e"


def mapping(seq):
    return b"d" + b"".join(string(k) + value for k, value in seq) + b"e"


def rows():
    # Fixed prefix projections independently assert the public native result shape.
    yield b"0:", 0, (1, 2, 1)
    yield b"4:note", 0, (1, 6, 1)
    yield b"i-0e", 31, None
    yield b"i42e suffix", 0, (2, 4, 1)
    yield b"le", 0, (3, 2, 1)
    yield b"de", 0, (4, 2, 1)
    yield b"d1:aldi-0eee", 23, None
    yield b"d0:l0:i1ee1:bl0:ee", 0, (4, 18, 6)
    negatives = {
        20: [b"l"*9+b"0:"+b"e"*9, array([b"0:"]*128)],
        21: [b"", b"x", b"l", b"e", b"l0:"],
        22: [b"123456:note", b"d000000:0:e"],
        23: [b"12", b"1=x", b"d", b"di1e0:e"],
        24: [b"00:", b"03:abc", b"d01:a0:e"],
        25: [b"4:abc", b"99999:tiny", b"d5:a"],
        26: [b"i"+b"9"*21+b"e", b"i-"+b"0"*20],
        27: [b"i", b"i1", b"i"+b"9"*20],
        28: [b"ie"], 29: [b"i-e", b"i+3e", b"i1xe", b"i00xe"],
        30: [b"i00e", b"i-00e", b"i012e"],
        31: [b"i-0e"],
        32: [mapping([(b"a",b"0:"),(b"a",b"i1e")]), mapping([(b"aa",b"0:"),(b"a",b"0:")])],
        33: [b"i9223372036854775808e", b"i-9223372036854775809e", b"i99999999999999999999e"],
    }
    for status, vals in negatives.items():
        yield from ((x,status,None) for x in vals)
    for n in [0,1,2,127,128,255,256,1<<32,-(1<<32),(1<<63)-1,-(1<<63)]:
        data = b"i" + str(n).encode() + b"e"
        yield data, 0, (2,len(data),1)
    for n in range(9):
        data = b"l"*n + b"i0e" + b"e"*n
        yield data, 0, (3 if n else 2,len(data),n+1)
    for n in [0,1,2,16,63,126,127]:
        data = array([b"0:"]*n)
        yield data, 0, (3,len(data),n+1)
        data = mapping([(str(i).zfill(3).encode(),b"0:") for i in range(n)])
        yield data, 0, (4,len(data),n+1)
    for n in [0,1,8,9,10,99,100,999,1000,9999,10000,99999]:
        body = b"a"*n
        data = string(body)
        yield data, 0, (1,len(data),1)
    for i in range(32):
        # Ordinary inert keys and scalar/list data. Exercise both prefix and
        # equal-prefix key ordering independently, including non-UTF8 byte keys.
        head = bytes([i])
        value = array([b"i"+str(i).encode()+b"e", string(head + b"q")])
        data = mapping([(head,value),(head+b"z",b"de"),(bytes([128+i]),b"0:")])
        yield data, 0, (4,len(data),6)
        yield data+b" inert suffix", 0, (4,len(data),6)
    for terminal in (b"le",b"de"):
        data = b"l"*8 + terminal + b"e"*8
        yield data, 0, (3,len(data),9)
    for invalid_key in (b"=",b"02:ab"):
        status = 23 if invalid_key == b"=" else 24
        prefix = b"d"+b"".join(string(str(i).zfill(3).encode())+b"0:" for i in range(127))
        yield prefix+invalid_key, status, None
    yield b"l"*8+b"d03:abc"+b"e"*9,24,None
    boundary = b"i1e"+b"~"*(CAP-3)
    yield boundary, 0, (2,3,1)
    large = mapping([(b"a"*99998,b"0:"),(b"a"*99998+b"b",b"le")])
    yield large, 0, (4,len(large),3)


class DaBep52BencodePrefix(unittest.TestCase):
    def test_actual_private_original_and_both_stock_structure_projections(self):
        matrix = list(rows())
        with tempfile.TemporaryDirectory(prefix="trnm-pure-bencode-") as temp:
            proof = original(Path(temp),[x[0] for x in matrix])
        self.assertEqual({x[0] for x in proof},{0,*range(20,34)})
        for (_,status,record),(orig_status, payload) in zip(matrix,proof,strict=True):
            self.assertEqual(orig_status,status)
            self.assertEqual(payload,b"" if record is None else struct.pack(">QQQ",*record))
        tests = [(data, OUT, WORK, status, payload, 81)
                 for (data,_,_), (status,payload) in zip(matrix,proof,strict=True)]
        controls = [(b"0:",OUT[:23],WORK,102,b"",0),
                    (b"le",OUT,WORK[:80],102,b"",0),
                    (b"",OUT,WORK[:80],102,b"",0),
                    (b"0:",OUT[:0],WORK[:0],102,b"",0),
                    (b"0:",OUT[:24],WORK[:81],0,struct.pack(">QQQ",1,2,1),81)]
        for backend in ("direct","selfhost"):
            fixture_max = CAP + (backend == "selfhost")
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend, max_input_extent=fixture_max) as n:
                group = tests+controls
                if backend == "selfhost":
                    group += [(tests[-2][0]+b"x",OUT,WORK,100,b"",0)]
                small = [x for x in group if len(x[0])<40000]
                large = [x for x in group if len(x[0])>=40000]
                batches = [small[i:i+12] for i in range(0,len(small),12)] + [[x] for x in large]
                for batch in batches:
                    got = n.call_many([("f0",list(x[:3])) for x in batch],timeout=60)
                    for (data,out,work,status,payload,written), result in zip(batch,got,strict=True):
                        self.assertEqual(result.require_returned().value,status,(backend,len(data),data[:40]))
                        self.assertEqual(result.arguments[0],data)
                        self.assertEqual(result.arguments[1],payload+out[len(payload):])
                        self.assertEqual(result.arguments[2][written:],work[written:])
                print(json.dumps(dict(backend=backend,native_elf=n.artifact_sha256,
                                      original_matches=len(matrix),abi_controls=len(group)-len(matrix)),
                                 sort_keys=True),flush=True)
