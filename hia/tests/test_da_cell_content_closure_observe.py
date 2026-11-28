"""Declared TCC2 observation only, using the actual locked public Rust method."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule, unlinked_path
from hia.tests.test_da_cell_content_closure_value import (
    PINNED, ROOT, alter, close, matrix as closure_matrix, pins, put, sha, tcm2,
)

SOURCE = ROOT / "hia/src/data_availability/cell_content_closure_observe.hepta"
WITNESS = Path(__file__).with_name("rust_da_cell_content_closure_observe_reference.rs")
TARGET = ROOT / "trillionnium"
PROTO = TARGET / "crates/trnm-protocol"
DA = TARGET / "crates/trnm-data-availability"
WORK = b"\xca" * 131243
OUT = b"\xa5" * 238
DOMAIN = b"TRNM/CPQ1/FullContent/SHA512/v1\0"


def original(target, data, witness=WITNESS):
    manifest = TARGET / "Cargo.toml"
    bound = [manifest, TARGET / "Cargo.lock", DA / "Cargo.toml", PROTO / "Cargo.toml", witness,
             ROOT / "rust-toolchain.toml"]
    before = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in bound}
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    env = {**os.environ, "RUSTC": rustc, "CARGO_INCREMENTAL":"0", "CARGO_BUILD_JOBS":"2",
           "CARGO_PROFILE_DEV_DEBUG":"0"}
    version = subprocess.check_output([rustc,"--version"],env=env)
    if not version.startswith(b"rustc 1.95.0 (59807616e "):
        raise ValueError("the original requires the exact Rust pin")
    cp = subprocess.run([cargo,"build","--locked","--offline","--manifest-path",str(manifest),
                         "-p","trnm-data-availability","--lib","--target-dir",str(target),
                         "--message-format=json"],check=True,capture_output=True,env=env,timeout=180)
    events = [json.loads(line) for line in cp.stdout.splitlines()]
    if not events or events[-1] != {"reason":"build-finished","success":True}:
        raise ValueError("original Cargo terminal receipt absent")
    paths = {}
    for crate, ident in [(DA,"trnm_data_availability"),(PROTO,"trnm_protocol")]:
        [e] = [e for e in events if e.get("reason")=="compiler-artifact"
               and e["target"]["name"]==ident and e["target"]["kind"]==["lib"]]
        if Path(e["manifest_path"]) != crate/"Cargo.toml" or Path(e["target"]["src_path"]) != crate/"src/lib.rs":
            raise ValueError("original Cargo library source mismatch")
        [lib] = [unlinked_path(p) for p in e["filenames"] if p.endswith(".rlib")]
        if not lib.is_relative_to(target):
            raise ValueError("original Cargo library is outside its actual target")
        paths[ident] = lib
    [sqlite] = [e for e in events if e.get("reason")=="build-script-executed"
                and e["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [link] = sqlite["linked_paths"]
    if not link.startswith("native=") or sqlite["linked_libs"] != ["static=sqlite3"]:
        raise ValueError("the unchanged original must use locked SQLite")
    native = unlinked_path(link[7:],directory=True)
    if not native.is_relative_to(target):
        raise ValueError("original linked SQLite library outside actual target")
    libraries = {k:sha(v.read_bytes()) for k,v in paths.items()}
    argv = [rustc,"--edition=2024","-O","-Dwarnings",str(witness)]
    for k,v in paths.items():
        argv += ["--extern", f"{k}={v}"]
    exe = target / "exact-tcc2-observe"
    argv += ["-L",f"dependency={target/'debug/deps'}","-L",f"native={native}","-o",str(exe)]
    subprocess.run(argv,check=True,env=env,capture_output=True,timeout=45)
    res = subprocess.run([str(exe)],input=data,check=True,env=env,capture_output=True,timeout=40)
    if (res.stderr or before!={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in bound}
            or libraries!={k:sha(v.read_bytes()) for k,v in paths.items()}):
        raise ValueError("original changed or emitted stderr")
    return res.stdout, dict(original_elf=sha(exe.read_bytes()),source_sha256=before,rlibs=libraries,
                            input_sha256=sha(data),original_stdout_sha256=sha(res.stdout))


def context_from_manifest(manifest):
    c = manifest[-213:-72]
    assert len(c)==141
    return alter(c,68,3)


def frame(closure, context, reads, size):
    return context+struct.pack(">QQ",reads,size)+closure


def matrix():
    m = tcm2()
    c = context_from_manifest(m)
    first = close(m)
    max_u64 = (1<<64)-1
    z = bytes(64)
    yield frame(first,c,1,len(first)+1),0
    yield frame(first,c,max_u64,max_u64),0
    yield frame(first,c,1,len(first)),35
    yield frame(first,c,4,1),35
    yield frame(first,c,0,max_u64),30
    yield frame(first,c,1,0),30
    yield frame(first,put(c,0,b"XXXX"),1,1),31
    yield frame(first,alter(c,68,255),1,1),31
    yield frame(first,put(c,4,z),1,1),32
    yield frame(first,put(c,69,z),1,1),32
    for k in (1,2,4,5):
        yield frame(first,alter(c,68,k),1,1),33
    for position in (4,67,69,132,133,140):
        yield frame(first,alter(c,position,c[position]^128),1,1),34
    yield frame(first,alter(alter(c,68,4),140,1),1,1),33
    yield frame(first,alter(c,68,4),0,1),30
    yield frame(first,alter(c,68,255),0,0),31
    yield frame(first,put(put(c,69,z),0,b"ZZZZ"),1,1),31
    for n in (0,1,140,156):
        yield bytes(n),100
    for raw,s in closure_matrix():
        if s in (2,3,4,5,6,7,8,9,10,20,21,22,23,26,27,28):
            yield frame(raw,put(c,69,z),0,0),s
    # Sweep original TCM2 family widths and both SHA-512 padding sides without
    # reading the content declarations. Compare exact success/one-byte-short.
    for n in range(1,65):
        m = tcm2(b"X"*n, generation=n<<55, instance=bytes([n])*64)
        c = context_from_manifest(m)
        x = close(m)
        yield frame(x,c,1,len(x)+1),0
        if n in (1,2,3,15,16,17,31,32,33,47,48,49,62,63,64):
            yield frame(x,c,3,len(x)),35


def qualify_observation(self, cases, source, witness):
    data = b"".join(struct.pack("<I",len(x))+x for x,_ in cases)
    self.assertEqual(pins(),PINNED)
    with tempfile.TemporaryDirectory(prefix="trnm-declared-tcc2-original-") as t:
        answer, proof = original(Path(t),data,witness)
    self.assertEqual(pins(),PINNED)
    i = 0
    tested = []
    for j,(raw,expected) in enumerate(cases):
        status=answer[i]
        i+=1
        self.assertEqual(status,expected,j)
        record=b""
        if not status:
            record=answer[i:i+229]
            i+=229
            declaration=raw[157:]
            metadata=raw[:141]+struct.pack(">Q",len(declaration))
            digest=hashlib.sha512(DOMAIN+metadata+declaration).digest()
            self.assertEqual(record,metadata+digest+struct.pack(">QQ",1,len(declaration)+1))
        tested.append((raw,OUT,WORK,status,record))
    self.assertEqual(i,len(answer))
    print(json.dumps(dict(proof,original_matches=len(cases),
                          status_counts=Counter(s for _,s in cases),original_pins=PINNED),
                     sort_keys=True),flush=True)
    admitted = tested[0]
    controls = [(admitted[0],OUT[:228],WORK,102,b""),
                (admitted[0],OUT,WORK[:131231],102,b""),
                (admitted[0],OUT[:0],WORK[:0],102,b""),
                (admitted[0],OUT[:229],WORK[:131232],0,admitted[4]),
                (tested[2][0],OUT[:0],WORK[:0],35,b""),
                (tested[10][0],OUT[:0],WORK[:0],tested[10][3],b"")]
    for backend in ("direct","selfhost"):
        with self.subTest(backend=backend),NativeModule(source,byte_exports=("f0",),backend=backend) as n:
            group = tested+controls
            for start in range(0,len(group),7):
                batch=group[start:start+7]
                got=n.call_many([("f0",list(r[:3])) for r in batch],timeout=60)
                for j,((raw,out,w,status,record),v) in enumerate(zip(batch,got,strict=True),start):
                    self.assertEqual(v.require_returned().value,status,(backend,j))
                    self.assertEqual(v.arguments[0],raw)
                    self.assertEqual(v.arguments[1],record+out[len(record):])
                    if status:
                        self.assertEqual(v.arguments[2],w)
                    else:
                        self.assertEqual(v.arguments[2][1544:131168],w[1544:131168])
                        self.assertEqual(v.arguments[2][131232:],w[131232:])
            print(json.dumps(dict(backend=backend,native_elf=n.artifact_sha256,
                                  original_matches=len(cases),abi_controls=len(controls)),
                             sort_keys=True),flush=True)


class DaCellContentClosureObserve(unittest.TestCase):
    def test_actual_declared_tcc2_observation_and_fresh_budget_both_stock(self):
        qualify_observation(self, list(matrix()), SOURCE, WITNESS)
