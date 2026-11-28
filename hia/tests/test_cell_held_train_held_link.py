"""Prove the stock CTRX code survives static linkage in the inert Rust referee."""
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
from hia.tests import cell_held_rows_original as source
from hia.tests.test_cell_held_train import HARNESS, fixtures
from hia.tools.toolchain import HIA_ROOT, build_native

FRAGMENT = Path(__file__).with_name("rust_cell_held_train_held_link.rs")
NATIVE = HIA_ROOT/"src/state/cell_held_train.hepta"
RUST_SHA = "3e44133e38f27cc3b64881f54a9f8585fdcd317eb3dcdfeda573d1593c530805"
OBJECT_SHA = "f0b0c2c6bab8b3f938e78c05c6c787b508321a9027a23ae5b95905fe688d3657"
TEXT_SHA = "3efc2637d4b8dd46f952252b47cdf8579e24ca7aebec6007470efff2c64da42d"
WIRE_SHA = "a21b77bbdd571574a85e7f9268792910cdd1caf0166f364b9fe4cf675e07f889"
SCOPE_SHA = "07ba0241740bd6ceca1071aa445d4a4ba0a689cb26d50f2ae4832e20258d8f1f"
OBJECT = "trnm_held_train.o"
ARCHIVE = "libtrnm_held_train_fixture.a"


def digest(raw):
    return sha256(raw).hexdigest()


def linked_driver(driver, fragment):
    if digest(driver)!=RUST_SHA:
        raise ValueError("Frozen prior CTRX reference driver changed")
    old = b"source::PreparedInputs{features,stages:vec![]},products)"
    new = b"source::PreparedInputs{features:features.clone(),stages:vec![]},products.clone())"
    old_err = b"            return out.write_all(&[match e.to_string().as_str() {"
    new_err = b"            let code=match e.to_string().as_str() {"
    old_end = b"            }]);\n        }\n    };"
    new_end = (b"            };\n            compare_while_held(&admission,&features,&products,f,code,&[],&[]);\n"
               b"            return out.write_all(&[code]);\n        }\n    };")
    old_ok = b"    out.write_all(&[0])?;"
    new_ok = (b"    compare_while_held(&admission,&features,&products,f,0,&report,&active_records);\n"
              +old_ok)
    for before, after in ((old,new),(old_err,new_err),(old_end,new_end),(old_ok,new_ok)):
        if driver.count(before)!=1:
            raise ValueError("Missing unique held input/reference comparison point")
        driver=driver.replace(before,after)
    return driver+b"\n"+fragment


def prepare(path):
    if (platform.system(),platform.machine())!=("Linux","x86_64"):
        raise ValueError("This exact private static fixture requires x86-64 Linux")
    pin=json.loads((HIA_ROOT/"qualification/compiler-binding.json").read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256")!=pin:
        raise ValueError("Pinned Selfhost compiler required")
    obj=path/OBJECT
    receipt,_=build_native(NATIVE,obj,kind="object",backend="selfhost",byte_exports=("f0",),
                           compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=pin)
    raw=obj.read_bytes()
    text=exact_native_text(raw)
    if (len(raw),digest(raw),receipt["artifact_sha256"],digest(text),receipt["compiler_wire_sha256"],
            receipt["chain_migration"]["composed_source_sha256"],receipt["claims"]["fallback_used"])!=(
            50008,OBJECT_SHA,OBJECT_SHA,TEXT_SHA,WIRE_SHA,SCOPE_SHA,False):
        raise ValueError("Pinned resolved CTRX object or closure changed")
    archive=path/ARCHIVE
    source.run(["ar","crsD",archive,obj])
    archived=archive.read_bytes()
    if source.run(["ar","t",archive])!=OBJECT.encode()+b"\n":
        raise ValueError("Exact private archive must have one member")
    if source.run(["ar","p",archive,OBJECT])!=raw:
        raise ValueError("Packed archive member differs from stock object")

    def verify(binary):
        if obj.read_bytes()!=raw or archive.read_bytes()!=archived:
            raise ValueError("Qualified static link input changed")
        symbols=source.run(["nm","--defined-only",binary]).splitlines()
        [entry]=[symbol for symbol in symbols if symbol.endswith(b" T f0")]
        address=int(entry.split()[0],16)
        executable=binary.read_bytes()
        header=struct.unpack_from("<16sHHIQQQIHHHHHH",executable)
        if header[0][:7]!=b"\x7fELF\x02\x01\x01" or header[2]!=62 or header[9]!=56:
            raise ValueError("Incorrect linked Linux x86-64 executable")
        segments=[struct.unpack_from("<IIQQQQQQ",executable,header[5]+56*i)
                  for i in range(header[10])]
        locations=[off+address-base for kind,flags,off,base,_,n,_,_ in segments
                   if kind==1 and flags==5 and base<=address and address+len(text)<=base+n]
        if len(locations)!=1 or executable[locations[0]:locations[0]+len(text)]!=text:
            raise ValueError("Exact unmodified stock text missing at static f0")
        return dict(elf=digest(executable),text=digest(text),object=digest(raw),
                    archive=digest(archived),address=address,object_bytes=len(raw),text_bytes=len(text))
    return verify


class CellHeldTrainLinked(unittest.TestCase):
    def test_frozen_execute_with_same_typed_inputs_calls_exact_static_selfhost(self):
        original_driver=HARNESS.read_bytes()
        fragment=FRAGMENT.read_bytes()
        driver=linked_driver(original_driver,fragment)
        frames=fixtures()
        stream=b"".join(struct.pack("<I",len(f))+f for _,f in frames)
        with tempfile.TemporaryDirectory(prefix="trnm-held-train-static-") as d:
            root=Path(d)
            unlinked=root/"unlinked"
            unlinked.mkdir()
            linked=root/"linked"
            linked.mkdir()
            seen=[]
            check=prepare(root)
            def verify(binary):
                seen.append(check(binary))
            with patch.object(source,"HARNESS",HARNESS):
                baseline,base=source.locked_original(unlinked,stream)
                actual,plus=source.locked_original(linked,stream,harness=driver,link=(root,verify))
        self.assertEqual(len(seen),2)
        self.assertEqual(seen[0],seen[1])
        self.assertEqual({name:v for name,v in base["source"].items() if name!="main.rs"},
                         {name:v for name,v in plus["source"].items() if name!="main.rs"})
        self.assertEqual({name:v for name,v in base.items() if name!="source"},
                         {name:v for name,v in plus.items() if name!="source"})
        self.assertEqual(actual,baseline)
        self.assertEqual(HARNESS.read_bytes(),original_driver)
        self.assertEqual(FRAGMENT.read_bytes(),fragment)
        statuses=[]
        remain=actual
        for key,_ in frames:
            code=remain[0]
            remain=remain[1:]
            if code==0:
                n,r=struct.unpack_from("<II",remain)
                if key=="full-64":
                    self.assertEqual((n,r),(160936,134144))
                remain=remain[8+n+r:]
            statuses.append(code)
        self.assertEqual(remain,b"")
        self.assertEqual(statuses,[0,203,201,0,0,0,0,0])
        proof=os.environ.get("HIA_HELD_TRAIN_LINK_PROOF")
        if proof is not None:
            Path(proof).write_text(json.dumps(dict(static=seen[0],statuses=statuses,frame_sha=digest(stream),
                observation_sha=digest(actual),observation_bytes=len(actual),base=base,linked=plus),
                indent=2,sort_keys=True)+"\n")
