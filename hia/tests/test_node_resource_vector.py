"""Pass inert u64 pairs to the exact old private methods and both HIA emitters."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/node/resource_vector.hepta"
BASE = ROOT / "trillionnium/crates/trnm-pon-node/src"
PINS = {
    "resource_owner_v1.rs": "8a764d6398e38f36b699b9e036761c755a5ea41472a6488957cc2429243315f1",
    "lib.rs": "baafb16f125fda88b09d2342a0b6badb253497742c9a106921e8416e930f108d",
    "error.rs": "0f7952a02aca0dfc9d6da3f38e6a1883b7943ad5b9ab94cfef9b4036dd1395fc",
}
MAX = 1 << 60
U64 = (1 << 64) - 1
NUMBERS = (0, 1, MAX-1, MAX, MAX+1, U64-MAX, U64-1, U64)
KINDS = {"OK": 0, "NONE": 34, "RESOURCE_OWNER_OVERFLOW": 32, "RESOURCE_OWNER_UNITS": 33}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def original_source():
    files = {name: (BASE/name).read_bytes() for name in PINS}
    assert {name: sha(raw) for name, raw in files.items()} == PINS
    raw, lib, err = (files[n] for n in ("resource_owner_v1.rs", "lib.rs", "error.rs"))
    start = raw.rindex(b"#[derive", 0, raw.index(b"pub struct ResourcesV1"))
    end = raw.rindex(b"#[derive", 0, raw.index(b"pub enum ClassV1"))
    typed = raw[start:end]
    assert typed.count(b", Serialize, Deserialize") == 1
    typed, count = re.subn(rb"(?m)^#\[serde\([^\n]+\)\]\n", b"", typed.replace(b", Serialize, Deserialize", b""))
    assert count == 1
    maximum = re.search(rb"(?m)^const MAX_UNITS: [^\n]+", raw).group(0)
    result = re.search(rb"(?m)^pub type Result<T> = [^\n]+", lib).group(0)
    ensure = lib[lib.index(b"pub(crate) fn ensure("):lib.index(b"pub fn digest(")]
    error = err[:err.index(b"impl Error {")]
    display = err[err.index(b"impl fmt::Display for Error"):err.index(b"impl From<std::io::Error>")]
    return b"\n".join((b"#![allow(dead_code)]", error, display, result, ensure, maximum, typed)) + br"""
fn main() {
    use std::io::BufRead;
    fn pair(m: ResourcesV1) { println!("OK {} {}", m.cpu_ns, m.io_bytes); }
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<u64> = line.split_whitespace().map(|s| s.parse().unwrap()).collect();
        assert_eq!(v.len(), 5);
        let a = ResourcesV1 { cpu_ns: v[1], io_bytes: v[2] };
        let b = ResourcesV1 { cpu_ns: v[3], io_bytes: v[4] };
        match v[0] {
            0 => match a.add(b) { Ok(m) => pair(m), Err(e) => println!("{e}") },
            1 => println!("OK {}", u64::from(a.within(b))),
            2 => match a.subtract(b) { Some(m) => pair(m), None => println!("NONE") },
            3 => match a.validate() { Ok(()) => println!("OK"), Err(e) => println!("{e}") },
            _ => unreachable!(),
        }
    }
}
"""


def frame(op, a, b, c, d):
    return b"NRVT0001" + struct.pack("<5Q", op, a, b, c, d)


class NodeResourceVector(unittest.TestCase):
    def test_original_resource_arithmetic_and_atomic_buffers(self):
        # Fully cross one component pair; independently cross asymmetric shapes,
        # without pretending this finite corpus exhausts all 256 input bits.
        component_pairs = list(itertools.product(NUMBERS, repeat=2))
        operands = {(a, b, c, d) for a,c in component_pairs for b,d in ((0,0),(MAX,U64),(U64,MAX))}
        operands.update((a,b,c,d) for b,d in component_pairs for a,c in ((0,0),(MAX,U64),(U64,MAX)))
        operands.update((a, U64-a, c, U64-c) for a,c in component_pairs)
        inputs = [(op,*row) for op in range(3) for row in sorted(operands)]
        inputs.extend((3,a,b,0,0) for a,b in component_pairs)
        original = original_source()
        self.assertTrue(subprocess.check_output(["rustc","--version"]).startswith(b"rustc 1.95.0 (59807616e "))
        with tempfile.TemporaryDirectory(prefix="trnm-resource-vector-") as tmp:
            exe=Path(tmp)/"old"
            source=exe.with_suffix(".rs")
            source.write_bytes(original)
            build=subprocess.run(["rustc","--edition=2021", "--deny=warnings",str(source),"-o",str(exe)],capture_output=True,timeout=35)
            self.assertEqual((build.returncode,build.stdout,build.stderr),(0,b"",b""))
            before=set(Path(tmp).iterdir())
            wire="".join(" ".join(map(str,row))+"\n" for row in inputs).encode()
            run=subprocess.run([str(exe)],cwd=tmp,env={},input=wire,capture_output=True,timeout=10)
            self.assertEqual((run.returncode,run.stderr),(0,b""))
            self.assertEqual(set(Path(tmp).iterdir()),before)
            binary=sha(exe.read_bytes())
        rust=[line.split() for line in run.stdout.decode().splitlines()]
        self.assertEqual(len(rust),len(inputs))
        controls = [
            (frame(0,1,2,3,4),15,2),(frame(0,U64,0,1,0),0,32),
            (frame(0,0,U64,0,1),0,32),(frame(1,1,2,3,4),7,2),
            (frame(1,4,2,3,4),7,2),(frame(2,4,5,2,3),15,2),
            (frame(2,4,5,9,3),0,34),(frame(2,4,5,2,9),0,34),
            (frame(3,MAX,MAX,0,0),0,0),(frame(3,0,MAX+1,0,0),0,33),
            (frame(3,U64,0,0,1),0,1),(frame(3,0,0,1,0),16,1),
            (frame(4,0,0,0,0),16,1),(frame(U64,0,0,0,0),16,1),
            (b"?" + frame(0,0,0,0,0)[1:],16,1),
            (frame(0,0,0,0,0)[:-1],16,1),(frame(0,0,0,0,0)+b"!",16,1),
        ]
        expected=[(KINDS[row[0]],b"".join(struct.pack("<Q",int(x)) for x in row[1:])) for row in rust]
        self.assertEqual(set(code for code,_ in expected),set(KINDS.values()))
        self.assertIn((0, struct.pack("<2Q",U64,0)),expected)
        calls = [("f0", [frame(*row), b"\xa5"*(len(data) if i%2 else 25), b"\xd3"*17])
                 for i,(row,(_,data)) in enumerate(zip(inputs,expected,strict=True))]
        calls.extend(("f0",[raw,b"\xa5"*size,b""]) for raw,size,_ in controls)
        expected.extend((code,b"") for _,_,code in controls)
        artifacts={}
        for backend in ("direct","selfhost"):
            module=NativeModule(SOURCE,byte_exports=("f0",),backend=backend)
            self.addCleanup(module.close)
            artifacts[backend]=module.artifact_sha256
            for i in range(0,len(calls),48):
                batch=calls[i:i+48]
                for request,record,(code,data) in zip(batch,module.call_many(batch,timeout=30),expected[i:i+48],strict=True):
                    record.require_returned()
                    source,out,arena=request[1]
                    self.assertEqual((record.value,record.arguments),(code,[source,data+out[len(data):],arena]))
        proof=os.environ.get("HIA_NODE_RESOURCE_VECTOR_PROOF")
        if proof:
            Path(proof).write_text(json.dumps(dict(exact_source_sha256=PINS,original_source_sha256=sha(original),
                original_stdout_sha256=sha(run.stdout),original_binary_sha256=binary,original_rows=len(rust),
                native_rows_each=len(expected),native_artifact_sha256=artifacts,owner_invoked=False,
                status_counts={str(v):sum(KINDS[row[0]]==v for row in rust) for v in KINDS.values()}),
                sort_keys=True,indent=2)+"\n")
