"""Exact source composition and static library of the existing stock HIR1."""
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import struct

from hia.platform.bench.main_build import exact_native_text
from hia.tests.history_inline_record_original import REFERENCE, execute
from hia.tools.toolchain import HIA_ROOT, build_native

CALLER = Path(__file__).with_name("rust_history_inline_record_held_link.rs")
SOURCE = HIA_ROOT/"src/node/history_inline_record.hepta"
OBJECT = "trnm_history_inline_record.o"
ARCHIVE = "libtrnm_history_inline_record_fixture.a"
ORIGINAL_DRIVER_SHA = "d1fdd935cc7f9937a8425d55350ef1447d76f9f26767d88751e61d50cfbff69a"
OBJECT_SHA = "3a7ec09a035a77754e430164a21f9cda3219c12fda2bf44a9d7007af89df64c9"
TEXT_SHA = "cd959e837d1cb5d4a153ecb9ad3b437cc1222632a6951acace78d503e95f0785"
WIRE_SHA = "3d25a473b416c8486ac7e98699edb3d6baedc91f553445711384a93e782a11d4"
SOURCE_SHA = "3a8b66febf938719eb5916b12fe83d9371bf76a8a33b9bf18086530b554d54df"


def prepare(directory):
    if (platform.system(),platform.machine())!=("Linux","x86_64"):
        raise ValueError("Only the fixed private held-row fixture may link the stock x86 object")
    original = REFERENCE.read_bytes()
    if sha256(original).hexdigest()!=ORIGINAL_DRIVER_SHA:
        raise ValueError("Exact earlier same-row fixture changed")
    line = b"        assert!(rows.next().unwrap().is_none());\n"
    if original.count(line)!=1:
        raise ValueError("Missing unique original live row scope")
    fragment = CALLER.read_bytes()
    injected = b"        compare_while_held(row, &input, code, &output);\n"
    driver = original.replace(line, injected+line) + b"\n" + fragment
    pin=json.loads((HIA_ROOT/"qualification/compiler-binding.json").read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256")!=pin:
        raise ValueError("Exact qualified Selfhost pin required")
    obj=directory/OBJECT
    receipt,_=build_native(SOURCE,obj,kind="object",backend="selfhost",byte_exports=("f0",),
                           compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=pin)
    data=obj.read_bytes()
    scopes=(sha256(data).hexdigest(),receipt["artifact_sha256"],sha256(exact_native_text(data)).hexdigest(),
            receipt["compiler_wire_sha256"],receipt["chain_migration"]["composed_source_sha256"])
    if scopes!=(OBJECT_SHA,OBJECT_SHA,TEXT_SHA,WIRE_SHA,SOURCE_SHA) or receipt["claims"]["fallback_used"]:
        raise ValueError("Stock HIR1 object/closure changed")
    archive=directory/ARCHIVE
    execute(["ar","crsD",archive,obj])
    names=execute(["ar","t",archive]).stdout
    if (names!=OBJECT.encode()+b"\n" or execute(["ar","p",archive,OBJECT]).stdout!=data
            or original!=REFERENCE.read_bytes() or fragment!=CALLER.read_bytes()):
        raise ValueError("Exact static member/driver changed")
    return driver,archive


def verify_linked(binary,archive,expected):
    if archive.read_bytes()!=expected:
        raise ValueError("Unexpected archive after linkage")
    names=execute(["nm","--defined-only",binary]).stdout.splitlines()
    [entry] = [entry for entry in names if entry.endswith(b" T f0")]
    address=int(entry.split()[0],16)
    text=exact_native_text(execute(["ar","p",archive,OBJECT]).stdout)
    raw=binary.read_bytes()
    header=struct.unpack_from("<16sHHIQQQIHHHHHH",raw)
    if header[0][:7]!=b"\x7fELF\x02\x01\x01" or header[2]!=62 or header[9]!=56:
        raise ValueError("Wrong linked x86-64 fixture")
    segments=[struct.unpack_from("<IIQQQQQQ",raw,header[5]+56*i) for i in range(header[10])]
    sites=[off+address-base for kind,flags,off,base,_,n,_,_ in segments
           if kind==1 and flags==5 and base<=address and address+len(text)<=base+n]
    if len(sites)!=1 or raw[sites[0]:sites[0]+len(text)]!=text:
        raise ValueError("Final executable does not retain the exact stock text at f0")
