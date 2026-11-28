"""Actual frozen private ResourceRequestV1 validation/total, without any owner."""
from dataclasses import dataclass, replace
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
SOURCE = ROOT / "hia/src/node/resource_request.hepta"
BASE = ROOT / "trillionnium/crates/trnm-pon-node/src"
PINS = {
    "resource_owner_v1.rs": "8a764d6398e38f36b699b9e036761c755a5ea41472a6488957cc2429243315f1",
    "lib.rs": "baafb16f125fda88b09d2342a0b6badb253497742c9a106921e8416e930f108d",
    "error.rs": "0f7952a02aca0dfc9d6da3f38e6a1883b7943ad5b9ab94cfef9b4036dd1395fc",
}
PROTOCOL_PIN = "ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b"
ZERO = bytes(32)
MAX = 1 << 60
U64 = (1 << 64)-1
ERRORS = {
    "RESOURCE_OWNER_BINDING": 32,
    "RESOURCE_OWNER_UNITS": 33,
    "RESOURCE_OWNER_RESERVATION": 34,
    "RESOURCE_OWNER_RECOVERY_LINK": 35,
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Request:
    operation: bytes = bytes(range(32))
    request: bytes = bytes(range(32,64))
    parent: bytes = ZERO
    deadline: int = 1
    kind: int = 0
    recovery: bytes | None = None
    amounts: tuple[int,...] = (9, 17, 21, 11)

    def frame(self):
        return (b"NRRQ0001" + self.operation + self.request + self.parent
                + struct.pack("<QBB6x4Q", self.deadline, self.kind, self.recovery is not None, *self.amounts)
                + (ZERO if self.recovery is None else self.recovery))


def exact_rust_oracle():
    files = {name:(BASE/name).read_bytes() for name in PINS}
    if {k:sha(v) for k,v in files.items()} != PINS:
        raise AssertionError("Frozen Node value relation source changed")
    raw = files["resource_owner_v1.rs"]

    def before_decl(tag):
        end = raw.index(tag)
        return raw.rindex(b"#[derive",0,end)

    resources = before_decl(b"pub struct ResourcesV1")
    class_start = before_decl(b"pub enum ClassV1")
    profile = before_decl(b"pub struct ResourceProfileV1")
    operation = before_decl(b"pub struct OperationBindingV1")
    completion = before_decl(b"pub struct CompletionV1")
    value = raw[resources:profile] + raw[operation:completion]
    # Omit only serialization attributes: the oracle uses the typed Rust
    # constructors, no serialization or owner. All method bytes are copied.
    assert value.count(b", Serialize, Deserialize")==4
    value = value.replace(b", Serialize, Deserialize", b"")
    value, attributes = re.subn(rb"(?m)^#\[serde\([^\n]*\)\]\n", b"", value)
    assert attributes==4
    max_units = re.search(rb"(?m)^const MAX_UNITS: [^\n]+",raw).group(0)
    lib = files["lib.rs"]
    result = re.search(rb"(?m)^pub type Result<T> = [^\n]+",lib).group(0)
    ensure = lib[lib.index(b"pub(crate) fn ensure("):lib.index(b"pub fn digest(")]
    err = files["error.rs"]
    error_definition = err[:err.index(b"impl Error {")]
    error_display = err[err.index(b"impl fmt::Display for Error"):err.index(b"impl From<std::io::Error>")]
    protocol=(ROOT/"trillionnium/crates/trnm-protocol/src/pon_wire.rs").read_bytes()
    assert sha(protocol) == PROTOCOL_PIN
    hash_type=re.search(rb"(?m)^pub type Hash = \[u8; 32\];$",protocol).group(0)
    return b"\n".join((b"#![allow(dead_code)]",error_definition,error_display,
                         hash_type,result,ensure,max_units,value))+br"""
fn read<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset+N].try_into().unwrap()
}
fn amount(data: &[u8], at: usize) -> ResourcesV1 {
    ResourcesV1 { cpu_ns: u64::from_le_bytes(read(data,at)),
        io_bytes: u64::from_le_bytes(read(data,at+8)) }
}
fn main() {
    use std::io::BufRead;
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let data: Vec<u8> = (0..line.len()).step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i+2],16).unwrap()).collect();
        assert_eq!(data.len(),184);
        assert_eq!(&data[..8],b"NRRQ0001");
        let item=ResourceRequestV1 {
            binding: OperationBindingV1 {
                operation_id: read(&data,8), request_digest: read(&data,40),
                parent_state: read(&data,72), deadline_unix_ms: u64::from_le_bytes(read(&data,104)),
            },
            class: match data[112] { 0 => ClassV1::Bootstrap, 1 => ClassV1::Committed,
                2 => ClassV1::Recovery, _ => unreachable!() },
            recovery_of: match data[113] { 0 => None, 1 => Some(read(&data,152)), _ => unreachable!() },
            execution: amount(&data,120), cleanup: amount(&data,136),
        };
        match item.validate() {
            Ok(()) => {
                let total=item.total().unwrap();
                println!("OK {} {}",total.cpu_ns,total.io_bytes);
            }
            Err(e) => println!("ERR {e}"),
        }
    }
}
"""


def corpus():
    seed=Request()
    bindings=(seed, replace(seed, operation=ZERO), replace(seed, request=ZERO), replace(seed, deadline=0),
              replace(seed, parent=b"\xff"*32, deadline=U64), replace(seed,operation=b"\x00"*31+b"\x01"))
    amounts=(
        (1,0,1,0),(MAX-1,MAX,1,0),(1,MAX-1,MAX-1,1),
        (MAX,0,1,0),(1,MAX,1,1),(MAX+1,0,1,0),(1,MAX+1,1,0),
        (1,0,MAX+1,0),(1,0,1,MAX+1),(0,1,1,1),(1,1,0,1),
        (0,U64,1,0),(0,1,1,U64),(U64,1,U64,1),(9,17,21,11),
    )
    return [replace(s,kind=k,recovery=r,amounts=v)
            for (s,k,r,v) in itertools.product(bindings,range(3),(None,ZERO,b"\xaa"*32),amounts)]


class NodeResourceRequest(unittest.TestCase):
    def test_original_frozen_typed_relation_and_borrowed_buffers(self):
        inputs=[r.frame() for r in corpus()]
        original=exact_rust_oracle()
        rust_pin=subprocess.check_output(("rustc","--version"),text=True)
        self.assertTrue(rust_pin.startswith("rustc 1.95.0 (59807616e "),rust_pin)
        with tempfile.TemporaryDirectory(prefix="trnm-resource-request-") as td:
            d=Path(td); src=d/"exact.rs";src.write_bytes(original)
            compiled=subprocess.run(("rustc","--edition=2021","--deny=warnings",str(src),"-o",str(d/"original")),
                                    capture_output=True,timeout=35)
            self.assertEqual((compiled.returncode,compiled.stdout,compiled.stderr),(0,b"",b""))
            before=set(d.iterdir())
            outcome=subprocess.run((str(d/"original"),),env={},cwd=d,timeout=10,capture_output=True,
                input=b"".join(x.hex().encode()+b"\n" for x in inputs))
            self.assertEqual((outcome.returncode,outcome.stderr),(0,b""))
            self.assertEqual(set(d.iterdir()),before)
            oracle_binary_sha=sha((d/"original").read_bytes())
        rows=outcome.stdout.decode().splitlines()
        self.assertEqual(len(rows),len(inputs))
        answers=[]
        for line in rows:
            tokens=line.split()
            answers.append((0,struct.pack("<2Q",*map(int,tokens[1:]))) if tokens[0]=="OK" else (ERRORS[tokens[1]],b""))
        self.assertEqual({code for code,_ in answers},{0,*ERRORS.values()})
        # Both typed optional-None and zero-valued Some are real cases; the
        # former is a transport distinction, the latter is not a checked ID.
        seed=Request()
        self.assertTrue(seed.frame() in inputs)
        valid=seed.frame()
        malformed=[valid[:-1],valid+b"x",b"x"+valid[1:],
                   valid[:112]+bytes([3])+valid[113:],valid[:113]+bytes([2])+valid[114:],
                   valid[:114]+bytes([1])+valid[115:],valid[:152]+b"x"+valid[153:]]
        sent=[("f0",[raw,b"\xa5"*29,b"\xd3"*17]) for raw in inputs+malformed]
        expected=answers+[(1,b"")]*len(malformed)
        sent += [("f0",[valid,b"\xa5"*15,b""]),
                 ("f0",[replace(seed,deadline=0).frame(),b"\xa5"*15,b""])]
        expected += [(2,b""),(32,b"")]
        module_hashes={}
        for backend in ("direct","selfhost"):
            module=NativeModule(SOURCE,byte_exports=("f0",),backend=backend)
            self.addCleanup(module.close)
            module_hashes[backend]=module.artifact_sha256
            for i in range(0,len(sent),24):
                cases=sent[i:i+24]
                records=module.call_many(cases,timeout=30)
                for request,record,(code,data) in zip(cases,records,expected[i:i+24],strict=True):
                    record.require_returned()
                    a,b,c=request[1]
                    self.assertEqual((record.value,record.arguments),(code,[a,data+b[len(data):],c]))
        proof=os.environ.get("HIA_NODE_RESOURCE_REQUEST_PROOF")
        if proof:
            Path(proof).write_text(json.dumps({"exact_source_sha256":{**PINS,"pon_wire.rs":PROTOCOL_PIN},
                "original_oracle_source_sha256":sha(original),"original_oracle_artifact_sha256":oracle_binary_sha,
                "original_oracle_stdout_sha256":sha(outcome.stdout),"real_typed_original_rows":len(answers),
                "native_rows_each":len(expected),"status_counts":{str(code):sum(code==c for c,_ in answers) for code in sorted({x[0] for x in answers})},
                "native_artifact_sha256":module_hashes,"owner_invoked":False},sort_keys=True,indent=2)+"\n")
