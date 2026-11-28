"""Same live typed CCT fixture with the exact static Selfhost numeric object."""
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.platform.bench.main_build import exact_native_text
from hia.tests import cell_held_rows_original as original
from hia.tests import test_cell_source_train as cct
from hia.tools.toolchain import HIA_ROOT,build_native

FRAGMENT=Path(__file__).with_name("rust_cell_source_train_held_link.rs")
DRIVER_SHA="9af578b9bf2de81c085e8a488e1e863aad755a2524aad708992e38bb3832a22a"
OBJECT_SHA="f5a9491030fde048335afb901922d4f54470aade3ee194af3364b81127a42ce9"
TEXT_SHA="eb02fef96d66803112c0a787d2c4f0c887ffbfb504e0d0262c3bc5d44e37ba6b"
WIRE_SHA="fdebdf06e1591d27397aae5a02e45ac68ab3539dc70f3a3c5326e8b490124c3f"
SCOPE_SHA="a224debcb2cc94b15e5dd87539e4e00a9247596cd9ab21b4e4c6fddb2c54d974"
OBS_SHA="8439672c68e0b839422785362b6dfcd74a7f6c195d72b7db7d3c409e692811fc"
OBJECT="trnm_cell_source_train.o"
# The shared private Cargo launcher names the exact archive, not a system one.
ARCHIVE="libtrnm_held_train_fixture.a"


def digest(data):
    return sha256(data).hexdigest()


def linked_driver(driver,extra):
    if digest(driver)!=DRIVER_SHA:
        raise ValueError("Exact earlier frozen CCT projection changed")
    source_decl=b"        Err(e)=>return out.write_all(&[match e.to_string().as_str() {"
    source_end=b"            other=>panic!(\"Unexpected frozen source refusal: {other}\"),\n        }]),"
    trace=b"    write_source_trace(&prepared,&products,&admission.policy,&admission.inputs,out)?;"
    execute_decl=b"            return out.write_all(&[match e.to_string().as_str() {"
    execute_end=b"                t=>panic!(\"Unexpected frozen prefix status: {t}\"),\n            }]);"
    ok=b"    out.write_all(&[0])?;\n    out.write_all(&(report.len() as u32).to_le_bytes())?;"
    inserts=(
        (source_decl,b"        Err(e)=>{let code=match e.to_string().as_str() {"),
        (source_end,source_end.split(b"\n")[0]+b"""
        };
        cct_compare_while_held(&admission,f,&[],code,&[],&[]);
        return out.write_all(&[code]);
        },"""),
        (trace,b"""    let mut source_trace=Vec::new();
    write_source_trace(&prepared,&products,&admission.policy,&admission.inputs,&mut source_trace)?;"""),
        (execute_decl,b"            let code=match e.to_string().as_str() {"),
        (execute_end,execute_end.split(b"\n")[0]+b"""
            };
            cct_compare_while_held(&admission,f,&source_trace,code,&[],&[]);
            out.write_all(&source_trace)?;
            return out.write_all(&[code]);"""),
        (ok,b"""    cct_compare_while_held(&admission,f,&source_trace,0,&report,&active_records);
    out.write_all(&source_trace)?;
"""+ok),
    )
    for prior,next_text in inserts:
        if driver.count(prior)!=1:
            raise ValueError("Missing unique live CCT projection site")
        driver=driver.replace(prior,next_text)
    return driver+b"\n"+extra


def prepare(root):
    if (platform.system(),platform.machine())!=("Linux","x86_64"):
        raise ValueError("This private static fixture requires Linux x86-64")
    pin=json.loads((HIA_ROOT/"qualification/compiler-binding.json").read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256")!=pin:
        raise ValueError("Pinned Selfhost compiler required")
    out=root/OBJECT
    meta,_=build_native(cct.MODULE,out,kind="object",backend="selfhost",byte_exports=("f0",),
                       compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=pin)
    obj=out.read_bytes()
    text=exact_native_text(obj)
    if (len(obj),digest(obj),meta["artifact_sha256"],digest(text),meta["compiler_wire_sha256"],
            meta["chain_migration"]["composed_source_sha256"],meta["claims"]["fallback_used"])!=(
            147488,OBJECT_SHA,OBJECT_SHA,TEXT_SHA,WIRE_SHA,SCOPE_SHA,False):
        raise ValueError("Exact resolved stock CCT archive disagrees")
    archive=root/ARCHIVE
    original.run(["ar","crsD",archive,out])
    archive_bytes=archive.read_bytes()
    if (original.run(["ar","t",archive])!=OBJECT.encode()+b"\n"
            or original.run(["ar","p",archive,OBJECT])!=obj):
        raise ValueError("Unexpected private archive membership or bytes")

    def verify(binary):
        if out.read_bytes()!=obj or archive.read_bytes()!=archive_bytes:
            raise ValueError("Exact static link inputs modified")
        names=original.run(["nm","--defined-only",binary]).splitlines()
        [sym]=[line for line in names if line.endswith(b" T f0")]
        address=int(sym.split()[0],16)
        raw=binary.read_bytes()
        h=struct.unpack_from("<16sHHIQQQIHHHHHH",raw)
        if h[0][:7]!=b"\x7fELF\x02\x01\x01" or h[2]!=62 or h[9]!=56:
            raise ValueError("Wrong linked x86-64 executable")
        rows=[struct.unpack_from("<IIQQQQQQ",raw,h[5]+56*i) for i in range(h[10])]
        sites=[off+address-base for kind,flags,off,base,_,n,_,_ in rows
               if kind==1 and flags==5 and base<=address and address+len(text)<=base+n]
        if len(sites)!=1 or raw[sites[0]:sites[0]+len(text)]!=text:
            raise ValueError("Exact stock .text missing at linked f0")
        return dict(elf=digest(raw), object=digest(obj), text=digest(text),
                    archive=digest(archive_bytes), text_bytes=len(text), address=address, wire=WIRE_SHA)
    return verify


class CellSourceTrainHeldLink(unittest.TestCase):
    def test_exact_static_native_before_same_typed_snippet_and_model_release(self):
        driver,source,spans=cct.locked_driver()
        body=FRAGMENT.read_bytes()
        linked=linked_driver(driver,body)
        base=original.execute_source
        def full(harness=None):
            files=base(harness)
            files["source.rs"]=source
            return files
        stream=b"".join(struct.pack("<I",len(f))+f for _,f in cct.fixtures())
        ready=[]
        with tempfile.TemporaryDirectory(prefix="trnm-cct-held-static-") as d:
            folder=Path(d)
            normal_out=folder/"unlinked"
            linked_out=folder/"linked"
            normal_out.mkdir()
            linked_out.mkdir()
            check=prepare(folder)
            def verify(e):
                ready.append(check(e))
            with patch.object(original,"execute_source",full):
                expected,pins=original.locked_original(normal_out,stream,harness=driver)
                actual,extended=original.locked_original(linked_out,stream,harness=linked,link=(folder,verify))
        self.assertEqual(actual,expected)
        self.assertEqual((len(actual),digest(actual)),(1503510,OBS_SHA))
        self.assertEqual(len(ready),2)
        self.assertEqual(ready[0],ready[1])
        self.assertEqual(FRAGMENT.read_bytes(),body)
        self.assertEqual(cct.locked_driver(),(driver,source,spans))
        self.assertEqual({k:v for k,v in pins.items() if k!="source"},
                         {k:v for k,v in extended.items() if k!="source"})
        self.assertEqual({k:v for k,v in pins["source"].items() if k!="main.rs"},
                         {k:v for k,v in extended["source"].items() if k!="main.rs"})
        if out:=os.environ.get("HIA_CCT_STATIC_PROOF"):
            Path(out).write_text(json.dumps(dict(static=ready[0],passes=len(cct.fixtures()),source_spans=spans,
                observations=len(actual),observation_sha=digest(actual),fixture_stream=digest(stream),
                original=pins,linked=extended),indent=2,sort_keys=True)+"\n")
