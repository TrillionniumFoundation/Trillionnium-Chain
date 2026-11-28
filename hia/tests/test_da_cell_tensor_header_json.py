"""Original immutable TensorHeader JSON decode, without a reader or model authority."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule, unlinked_path
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH
from hia.tests.test_da_protocol_context import _run

SOURCE = ROOT / "hia/src/data_availability/cell_tensor_header_json.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-data-availability/src/cell/tensor.rs"
CALLER = Path(__file__).with_name("rust_cell_tensor_header_json_reference.rs")
MANIFEST = ROOT / "trillionnium/Cargo.toml"
SHA = "73499faf43769355947c598040ddedf9139341bb1a1745924425cd5f11f6c5e8"
PARTS = (("const MAX_TENSORS", "const STREAM_BYTES",
          "c949a0bdf23121c959d37b3c708519831860a0841290be0174e0ef1878b5a961"),
         ("fn valid_name(", "fn read<const N",
          "3da4a10f9bb6400ed50956da5ffe78f6c94ea3a414a9e01f344c02b9966e5ca7"),
         ("struct TensorEntry {", None,
          "41f2c32987a2535819bbe4d52d01ef9b007acbdc41c715c80ebfaef400d6d280"))
LOCK = {"serde": "1.0.229", "serde_json": "1.0.149"}
WORK = 291072
CAP = 131072
JSON = 217
PRIVATE_LIMIT = 218
ENTRY = b'{"dtype":"F32","shape":[],"data_offsets":[0,4]}'


def digest(bytes_):
    return hashlib.sha256(bytes_).hexdigest()


def original_reference(directory, stream):
    inputs = [ORIGINAL, CALLER, MANIFEST, MANIFEST.with_name("Cargo.lock"), ROOT/"rust-toolchain.toml"]
    before = [digest(x.read_bytes()) for x in inputs]
    if before[0] != SHA:
        raise ValueError("Original TensorHeader source pin changed")
    source = ORIGINAL.read_bytes()
    parts = []
    for begin, end, pin in PARTS:
        start = source.index(begin.encode())
        part = source[start:None if end is None else source.index(end.encode(), start)]
        if digest(part) != pin:
            raise ValueError("Original private visitor changed")
        parts.append(part)
    (directory/"original_tensor_header.rs").write_bytes(b"".join(parts))
    adapter = directory/"observe.rs"
    adapter.write_bytes(CALLER.read_bytes())
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    rust = tomllib.loads(inputs[-1].read_text())["toolchain"]["channel"]
    if _run([rustc,"--version"]).stdout.decode().split()[1] != rust:
        raise ValueError("Wrong pinned Rust")
    target = directory/"target"
    build = _run([cargo,"build","--manifest-path",str(MANIFEST),"--locked","--offline",
                  "--package","trnm-data-availability","--lib","--target-dir",str(target),
                  "--message-format=json"],
                 env={**os.environ,"RUSTC":rustc,"CARGO_INCREMENTAL":"0"})
    events = [json.loads(line) for line in build.stdout.splitlines()]
    if not events or events[-1] != {"reason":"build-finished","success":True}:
        raise ValueError("No locked original package observation")
    args = []
    for name, version in LOCK.items():
        [row] = [r for r in events if r.get("reason")=="compiler-artifact"
                 and r["target"]["name"]==name and r["package_id"].endswith("#"+name+"@"+version)
                 and not r["profile"]["test"]]
        [lib] = [unlinked_path(path) for path in row["filenames"] if path.endswith(".rlib")]
        if not lib.is_relative_to(target) or lib.parent.name!="deps":
            raise ValueError("Original Serde artifact escaped the exact Cargo build")
        args.extend(("--extern",name+"="+str(lib)))
    bin_ = directory/"probe"
    try:
        _run([rustc,"--edition=2021",*args,"-L",f"dependency={target/'debug/deps'}",
              str(adapter),"-o",str(bin_)],timeout=60)
    except subprocess.CalledProcessError as error:
        raise ValueError("Exact original reference did not compile: "+error.stderr.decode()) from error
    actual = _run([str(bin_)],stream,timeout=30)
    if actual.stderr or before != [digest(x.read_bytes()) for x in inputs]:
        raise ValueError("Original or comparator inputs changed")
    return actual.stdout


def packet(rows):
    return b"".join(struct.pack("<I",len(b))+b for b in rows)


def field(k, v=ENTRY):
    return b'{"'+k+b'":'+v+b'}'


def many(n, metadata=False):
    entry = b'"v"' if metadata else ENTRY
    body = b",".join(b'"'+f"x{i:03d}".encode()+b'":'+entry for i in reversed(range(n)))
    return field(b"__metadata__",b"{"+body+b"}") if metadata else b"{"+body+b"}"


def fixtures():
    empty=b"{}"
    limit=field(b"x",ENTRY)+b" "*(CAP-len(field(b"x")))
    blank=field(b"x",ENTRY.replace(b'"F32"',b'""'))
    dtype=b"a"*(CAP-len(blank))
    wide=field(b"x",b'{"dtype":"'+dtype+b'","shape":[],"data_offsets":[0,4]}')
    # Scratch adversary is the sole maximum raw string; no silent truncation.
    assert len(wide)==CAP
    basics=[empty,b" \t{\r\n}\n",field(b"a"),many(128),many(64,True),limit,wide,
            field(b"x"*255),field(b"__metadata__",b'{"":"","e":"'+b"x"*16384+b'"}'),
            b'{"Z":'+ENTRY+rb',"\u00e9":'+ENTRY+rb',"e\u0301":'+ENTRY+rb',"\ud834\udd1e":'+ENTRY+b'}',
            field(b"x",rb'{"sh\u0061pe":[0,1,2,3,4,5,6,18446744073709551615],"data_offsets":[18446744073709551615,2],"dtype":"\u0000\t\u00e9\ud834\udd1e"}'),
            field(rb"__metad\u0061ta__",rb'{"\u0000":"v","\u007f":"e","\u0085":"x"}'),
            field(b"long",b'{"shape":[],"data_offsets":[800,2],"dtype":""}'),
            field(rb"a\/x",b'{"dtype":"supported later only","shape":[],"data_offsets":[0,0]}'),
            field(b"__metadata__",rb'{"a":"\n\u0000","\u00e9":"\ud834\udd1e"}')]
    basics += [field(b"t"+bytes([x])+b"x") for x in (32,33,35,126)]
    bad=[b"",b"null",b"[]",b'{ "a":{} }',b'{"a":[]}',b'{"a":[["F32"],[],[0,4]]}',
         b'{"a":null}',b'{ "a":'+ENTRY+b',}',b'{"a":'+ENTRY+b'} {}',
         b'{"a":'+ENTRY+rb',"\u0061":'+ENTRY+b'}',
         rb'{"__metadata__":{},"__metad\u0061ta__":{}}',
         field(b"__metadata__",rb'{"a":"x","\u0061":"y"}'),
         field(b"__metadata__",b'{"a":1}'),field(b"__metadata__",b'["a","b"]'),
         field(b"__metadata__",b'{"a":"b",}'),field(b"__metadata__",b'{"'+b"x"*256+b'":"b"}'),
         field(b"__metadata__",b'{"k":"'+b"x"*16385+b'"}'),
         field(b"x"*256),field(rb"\u0000"),field(rb"\u001f"),field(rb"\u007f"),field(rb"\u0085"),
         field(rb"\ud800"),field(rb"\udc00"),field(rb"\ud800\u0041"),field(rb"\u00XZ"),
         field(b"\xff"),field(b"\xc0\x80"),field(b"\x0a"),field(b""),
         field(b"x",ENTRY[:-1]+rb',"dt\u0079pe":"F32"}'),
         field(b"x",ENTRY[:-1]+b',"data_offsets":[0,4]}'),
         field(b"x",ENTRY[:-1]+b',"other":false}'),
         field(b"x",ENTRY.replace(b'"F32"',b"123")),
         field(b"x",ENTRY.replace(b'[]',b'[1,2,3,4,5,6,7,8,9]')),
         field(b"x",ENTRY.replace(b'[0,4]',b'[0]')),field(b"x",ENTRY.replace(b'[0,4]',b'[0,1,2]'))]
    for repl in (b'-0',b'-1',b'01',b'0.0',b'1e0',b'true',b'null',b'18446744073709551616'):
        bad.append(field(b"a",ENTRY.replace(b'[0,4]',b'[0,'+repl+b']')))
    outside=[many(129),many(65,True),limit+b" ",empty+b" "*((1<<20)-len(empty))]
    return [(x,0) for x in basics]+[(x,JSON) for x in bad]+[(x,PRIVATE_LIMIT) for x in outside]


class CellTensorHeaderJson(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules={name:cls.enterClassContext(NativeModule(SOURCE,backend=name,byte_exports=("f0",)))
                     for name in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.modules.values()})!=2:
            raise ValueError("both distinct stock artifacts required")

    def panel(self, rows):
        for name,m in self.modules.items():
            for i,(data,code,result,n,work) in enumerate(rows):
                with self.subTest(backend=name,fixture=i):
                    out,w=MARK*n,SCRATCH*work
                    o=m.call("f0",[data,out,w],timeout=35).require_returned()
                    self.assertEqual(o.value,code)
                    self.assertEqual(o.arguments[0],data)
                    self.assertEqual(o.arguments[1],result+out[len(result):])
                    self.assertEqual(o.arguments[2][WORK:],w[WORK:])
                    if code==PRIVATE_LIMIT and len(data)>CAP or work<WORK:
                        self.assertEqual(o.arguments[2],w)

    def test_exact_original_private_visitor_and_stock_output(self):
        rows=fixtures()
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-header-exact-") as td:
            out=original_reference(Path(td),packet([d for d,_ in rows]))
        at=0
        observed=[]
        for data,code in rows:
            actual,n=struct.unpack_from("<BI",out,at); at+=5
            got=out[at:at+n]; at+=n
            self.assertEqual(actual,0 if code==PRIVATE_LIMIT else code,repr(data[:120]))
            self.assertEqual(len(got),n)
            self.assertEqual(not got,actual!=0)
            want=b"" if code else got
            observed.append((data,code,want,len(want)+7,WORK+9))
        self.assertEqual(at,len(out))
        self.panel(observed)

    def test_capacity_and_output_atomicity(self):
        d=field(b"x")
        rb=struct.pack("<QQ",1,1)+b"x"+struct.pack("<Q",3)+b"F32"+struct.pack("<QQQ",0,0,4)
        self.panel([(d,0,rb,len(rb),WORK),(d,102,b"",len(rb)-1,WORK),
                    (d,102,b"",len(rb),WORK-1),(d+b"x",JSON,b"",1,WORK),
                    (b"{}"+b" "*CAP,PRIVATE_LIMIT,b"",0,0),(b"{}",102,b"",7,WORK)])
