"""Actual original State::snapshot projected to inert borrowed lane accounting."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/node/resource_snapshot_fold.hepta"
BASE = ROOT / "trillionnium/crates/trnm-pon-node/src"
LOCK = ROOT / "trillionnium/Cargo.lock"
PINS = {
    "resource_owner_v1.rs": "8a764d6398e38f36b699b9e036761c755a5ea41472a6488957cc2429243315f1",
    "lib.rs": "baafb16f125fda88b09d2342a0b6badb253497742c9a106921e8416e930f108d",
    "error.rs": "0f7952a02aca0dfc9d6da3f38e6a1883b7943ad5b9ab94cfef9b4036dd1395fc",
}
PROTOCOL_PIN = "ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b"
LOCK_PIN = "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e"
LIMIT = 1 << 60
U64 = (1 << 64)-1
DEFAULT = (10, 12, 21, 24, 40, 44, 3, 6)
ERRORS = {"RESOURCE_OWNER_OVERFLOW": 32, "RESOURCE_OWNER_JOURNAL": 33}
WIDTH = 328


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact_source():
    files = {name: (BASE/name).read_bytes() for name in PINS}
    assert {n:sha(raw) for n,raw in files.items()} == PINS
    raw, lib, err = (files[n] for n in ("resource_owner_v1.rs", "lib.rs", "error.rs"))
    kinds = raw[raw.rindex(b"#[derive", 0, raw.index(b"pub struct ResourcesV1")):
                raw.rindex(b"#[derive", 0, raw.index(b"pub struct ResourceOwnerV1"))]
    state = raw[raw.index(b"struct State {"):raw.index(b"    fn reserve(&mut self")]
    hash_impl = raw[raw.index(b"fn digest("):raw.index(b"fn root_metadata(")]
    constants = [re.search(rb"(?m)^" + key + rb"[^\n]+", raw).group(0) for key in
                 (b"pub const PROFILE_V1:", b"const MAX_UNITS:", b"const MAX_OPERATIONS:")]
    result = re.search(rb"(?m)^pub type Result<T> = [^\n]+",lib).group(0)
    ensure = lib[lib.index(b"pub(crate) fn ensure("):lib.index(b"pub fn digest(")]
    protocol = (ROOT/"trillionnium/crates/trnm-protocol/src/pon_wire.rs").read_bytes()
    assert sha(protocol) == PROTOCOL_PIN
    hash_alias = re.search(rb"(?m)^pub type Hash = \[u8; 32\];$",protocol).group(0)
    # Omit unrelated transport/storage conversion methods and tests. The
    # exact Display/From<&str>/From<String>/From<serde_json::Error> remain.
    err = err[:err.index(b"    /// A failed reconstruction/recovery of")] + err[err.index(b"    fn caused_by("):]
    err = err[:err.index(b"impl From<rusqlite::Error>")] + err[err.index(b"impl From<serde_json::Error>"):]
    err = err[:err.index(b"#[cfg(test)]")]
    return b"\n".join((b"#![allow(dead_code)]", b"mod error;", b"use error::Error;",
                       b"use std::collections::BTreeMap;", b"use serde::{Deserialize, Serialize};",
                       b"use sha2::{Digest, Sha256};", hash_alias, *constants, result, ensure,
                       kinds, state+b"}", hash_impl))+br"""
fn main() {
    use std::io::{BufRead, Write};
    fn take_pair(xs: &[u64]) -> ResourcesV1 { ResourcesV1 { cpu_ns:xs[0], io_bytes:xs[1] } }
    fn push_pair(out:&mut Vec<u64>, v:ResourcesV1) { out.extend([v.cpu_ns,v.io_bytes]); }
    for line in std::io::stdin().lock().lines() {
        let xs:Vec<u64> = line.unwrap().split_whitespace().map(|v|v.parse().unwrap()).collect();
        let profile=ResourceProfileV1 {
            owner_id:[1;32], grants:std::array::from_fn(|i|take_pair(&xs[2*i..2*i+2])),
            max_operations:[342,341,341], max_inflight:[1,1,1], overshoot:take_pair(&xs[6..8]),
        };
        let mut operations=BTreeMap::new();
        for (n,r) in xs[8..].chunks_exact(9).enumerate() {
            let class=[ClassV1::Bootstrap,ClassV1::Committed,ClassV1::Recovery][r[0] as usize];
            let mut id=[0;32];
            id[..8].copy_from_slice(&(1+n as u64).to_be_bytes());
            operations.insert(id, OperationRecordV1 {
                request:ResourceRequestV1 {
                    binding:OperationBindingV1 { operation_id:id, request_digest:[2;32],
                        parent_state:[0;32], deadline_unix_ms:17 },
                    class, execution:take_pair(&r[3..5]), cleanup:take_pair(&r[5..7]),
                    recovery_of:None,
                },
                state:[OperationStateV1::Reserved,OperationStateV1::Running,OperationStateV1::Settled][r[1] as usize].clone(),
                charge:match r[2] {0=>None, 1=>Some(ChargeV1::Measured(take_pair(&r[7..9]))),
                    2=>Some(ChargeV1::Conservative), _=>unreachable!()},
                completion:None,
            });
        }
        let s=State { profile, device:0, inode:0, sequence:0, hash:[0;32], clock_floor:0, operations };
        let mut stdout=std::io::stdout().lock();
        match s.snapshot() {
            Err(e) => writeln!(stdout,"{e}").unwrap(),
            Ok(output)=>{
                let mut r=Vec::new();
                for lane in output.lanes {
                    for pair in [lane.grant,lane.charged,lane.inflight_execution,lane.inflight_cleanup] {
                        push_pair(&mut r,pair);
                    }
                    r.push(u64::from(lane.available.is_some()));
                    push_pair(&mut r,lane.available.unwrap_or_default());
                    r.extend([u64::from(lane.retained_operations),u64::from(lane.unresolved_operations)]);
                }
                r.extend([u64::from(output.admission_fenced),u64::from(output.within_declared_accounting_bound)]);
                write!(stdout,"OK").unwrap();
                for v in r { write!(stdout," {}",v).unwrap(); }
                writeln!(stdout).unwrap();
            },
        }
    }
}
""", err


def pack(profile, rows):
    return b"NRSF0001" + struct.pack("<9Q",len(rows),*profile) + b"".join(struct.pack("<9Q",*row) for row in rows)


def corpus():
    def row(c=0, s=0, k=0, values=(1,2,3,4,0,0)):
        return (c,s,k,*values)
    cases = [(DEFAULT,())]
    magnitudes = (0, 1, 10, 11, 42, LIMIT, LIMIT+1, U64)
    for c,s,k,n,sign in itertools.product(range(3),range(3),range(3),magnitudes,(0,1)):
        a,b=(n,1) if sign==0 else (1,n)
        v=(a,b,3,4,a,b) if k==1 else (a,b,3,4,0,0)
        cases.append((DEFAULT,(row(c,s,k,v),)))
    for a in (1,8,LIMIT):
        cases.append(((a,)*8,tuple(row(i) for i in range(3))))
    measured = (1,2,3,4,11,0)
    pending_huge = (U64,0,0,0,0,0)
    cases.extend([
        (DEFAULT,(row(0,2,1,measured),row(2,1))),
        (DEFAULT,(row(0,2,0),row(1,0,0,pending_huge),row(1))),
        (DEFAULT,(row(1,0,0,pending_huge),row(1),row(0,2,0))),
        (DEFAULT,(row(0,0,0,(U64-1,0,2,0,0,0)),)),
        (DEFAULT,(row(0,0,0,pending_huge),row(1,1))),
        (DEFAULT,(row(2,0,0,(0,U64,0,0,0,0)),row(0,1))),
        ((LIMIT,)*8,tuple(row(i%3,i%2) for i in range(1024))),
        (DEFAULT,tuple(row(i%3,2,2) for i in range(1024))),
    ])
    rng=random.Random(19354)
    for n in range(90):
        p=tuple(rng.randint(1,700) for _ in range(7))+(rng.randint(0,100),)
        rows=[]
        for _ in range(n%40):
            c,s=rng.randrange(3),rng.randrange(3)
            k=rng.randrange(1,3) if s==2 else rng.randrange(3)
            vals=tuple(rng.randrange(100) for _ in range(4))
            if k==1:
                vals+=tuple(rng.randrange(120) for _ in range(2))
            else:
                vals+=(0,0)
            rows.append(row(c,s,k,vals))
        cases.append((p,tuple(rows)))
    return cases


class NodeResourceSnapshotFold(unittest.TestCase):
    def test_actual_original_projection_and_atomic_borrowed_buffers(self):
        exact, err = exact_source()
        old_lock=LOCK.read_bytes()
        self.assertEqual(sha(old_lock),LOCK_PIN)
        resolved=tomllib.loads(old_lock.decode())
        frozen={(r["name"],r["version"],r.get("checksum")) for r in resolved["package"]}
        self.assertTrue(subprocess.check_output(["rustc","--version"]).startswith(b"rustc 1.95.0 (59807616e "))
        cases=corpus()
        with tempfile.TemporaryDirectory(prefix="trnm-node-snapshot-fold-") as d:
            work=Path(d)
            (work/"src").mkdir()
            (work/"src/main.rs").write_bytes(exact)
            (work/"src/error.rs").write_bytes(err)
            (work/"Cargo.toml").write_text("""[package]
name = "trnm-frozen-snapshot-fold"
version = "0.0.0"
edition = "2021"
[dependencies]
serde = {version = "=1.0.229", features = ["derive"]}
serde_json = "=1.0.149"
sha2 = "=0.10.9"
""")
            env={**os.environ,"RUSTFLAGS":"-Dwarnings","CARGO_PROFILE_DEV_DEBUG":"0",
                 "CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"2"}
            generate=subprocess.run(["cargo","generate-lockfile","--offline"],cwd=d,env=env,capture_output=True,timeout=15)
            self.assertEqual(generate.returncode,0,generate.stderr)
            closure=tomllib.loads((work/"Cargo.lock").read_text())["package"]
            self.assertTrue(all((r["name"],r["version"],r.get("checksum")) in frozen for r in closure
                                if r["name"]!="trnm-frozen-snapshot-fold"),closure)
            build=subprocess.run(["cargo","build","--locked","--offline"],cwd=d,env=env,capture_output=True,timeout=150)
            self.assertEqual(build.returncode,0,build.stderr)
            oracle=work/"target/debug/trnm-frozen-snapshot-fold"
            sandbox=work/"inert"
            sandbox.mkdir()
            flat=[(*p,*itertools.chain.from_iterable(rows)) for p,rows in cases]
            wire="".join(" ".join(map(str,row))+"\n" for row in flat).encode()
            run=subprocess.run([str(oracle)],env={},cwd=sandbox,input=wire,capture_output=True,timeout=15)
            self.assertEqual((run.returncode,run.stderr),(0,b""))
            self.assertEqual(list(sandbox.iterdir()),[])
            binary_sha=sha(oracle.read_bytes())
        answers=[]
        for line in run.stdout.decode().splitlines():
            r=line.split()
            if r[0]=="OK":
                data=struct.pack("<41Q",*map(int,r[1:]))
                answers.append((0,data))
            else:
                answers.append((ERRORS[r[0]],b""))
        self.assertEqual(len(answers),len(cases))
        self.assertEqual({code for code,_ in answers},{0,32,33})
        diag={(v[312],v[320]) for c,v in answers if c==0}
        self.assertEqual(diag,{(0,1),(1,0),(1,1)})
        empty=pack(DEFAULT,())
        selected_error=next(pack(*pair) for pair,(c,_) in zip(cases,answers,strict=True) if c==33)
        malformed=[
            empty[:-1],empty+b"?", b"!"+empty[1:],
            empty[:8]+struct.pack("<Q",1025)+empty[16:],
            pack((0,)+DEFAULT[1:],()),pack(DEFAULT[:-1]+(LIMIT+1,),()),
            pack(DEFAULT,((3,0,0,1,0,1,0,0,0),)),
            pack(DEFAULT,((0,3,0,1,0,1,0,0,0),)),
            pack(DEFAULT,((0,1,3,1,0,1,0,0,0),)),
            pack(DEFAULT,((0,1,2,1,0,1,0,0,1),)),
        ]
        sent=[("f0",[pack(p,rows),b"\xa5"*(WIDTH+n%2*7),b"\xd3"*(WIDTH+11)]) for n,(p,rows) in enumerate(cases)]
        sent.extend(("f0",[raw,b"\xa5"*WIDTH,b"\xd3"*WIDTH]) for raw in malformed)
        sent.extend([("f0",[empty,b"\xa5"*(WIDTH-1),b"\xd3"*WIDTH]),
                     ("f0",[empty,b"\xa5"*WIDTH,b"\xd3"*(WIDTH-1)]),
                     ("f0",[selected_error,b"",b"\xd3"*WIDTH])])
        expected=answers+[(1,b"")]*len(malformed)+[(2,b""),(2,b""),(33,b"")]
        artifacts={}
        for backend in ("direct","selfhost"):
            module=NativeModule(SOURCE,byte_exports=("f0",),backend=backend)
            self.addCleanup(module.close)
            artifacts[backend]=module.artifact_sha256
            for i in range(0,len(sent),24):
                batch=sent[i:i+24]
                for ask,answer,(code,values) in zip(batch,module.call_many(batch,timeout=35),expected[i:i+24],strict=True):
                    answer.require_returned()
                    src,dst,scratch=ask[1]
                    got,payload,arena=answer.arguments
                    self.assertEqual((answer.value,got,payload,arena[WIDTH:]),(code,src,values+dst[len(values):],scratch[WIDTH:]))
                    if code==1 or len(scratch)<WIDTH:
                        self.assertEqual(arena,scratch)
        proof=os.environ.get("HIA_NODE_RESOURCE_SNAPSHOT_PROOF")
        if proof:
            data=dict(source_pins={**PINS,"pon_wire.rs":PROTOCOL_PIN,"original Cargo.lock":LOCK_PIN},
                      original_method_witness_sha256=sha(exact),original_binary_sha256=binary_sha,
                      original_stdout_sha256=sha(run.stdout),original_rows=len(cases),
                      native_rows_each=len(expected),native_artifacts=artifacts,
                      diagnostic_pairs=sorted(diag),owner_invoked=False,
                      counts={str(c):sum(c==k for k,_ in answers) for c in (0,32,33)})
            Path(proof).write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
