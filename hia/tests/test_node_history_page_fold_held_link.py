"""Same live in-memory read transaction and exact stock static HPF batch."""
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
from hia.tests import history_page_fold_original as frozen
from hia.tests.cell_held_rows_original import run
from hia.tests.test_node_history_page_fold import SOURCE
from hia.tools.toolchain import HIA_ROOT, build_native

FRAGMENT=Path(__file__).with_name("rust_history_page_fold_held_link.rs")
DRIVER_SHA="5007e478d56e04e1b816354f0e59560a0aba15ca66969c64c9dc0c835349f657"
OBJECT_SHA="88c4a67eb81d8b6ddda9b52e9a3776afb421203b056dbf1b44da041eba5b6a61"
TEXT_SHA="bd45ca58875ac264a83788ed152ec49757a2908cf9741f16cc5b3fbd63924e7c"
WIRE_SHA="43fa8f4bf084a15fdee6b3896409d71ed045b0c88d1a826c508fc49671468473"
SCOPE_SHA="31a8719e5392cf8da2cebb72d5905eb0ee00c9c628e78ec8aafae039a79bed72"
OBS_SHA="6d40e75feccfc3204d3cb935f564f18b9bb1359a24032d886f6d3536a4422fd1"
OBJECT="trnm_history_page_fold.o"
ARCHIVE="libtrnm_history_page_fold_fixture.a"


def sha(raw):
    return sha256(raw).hexdigest()


def linked_extraction(extract, fragment):
    # Only the fixture emit() is extended. The actual captured original
    # method, SQL, and dependencies remain the bytes checked by extract().
    if sha(frozen.REFERENCE.read_bytes())!=DRIVER_SHA:
        raise ValueError("Exact earlier HPF Rust fixture changed")
    files,pins=extract()
    driver=files["main.rs"]
    before=b"    let before=db.db.total_changes();"
    after=b"    for n in [name.len() as u64,q.len() as u64,code,payload.len() as u64,local.len() as u64] {"
    inserts=(
        (before,b"""    let tx=db.db.unchecked_transaction().unwrap();
    assert_eq!(tx.transaction_state(Some("main")).unwrap(),rusqlite::TransactionState::None);
"""+before),
        (after,b"""    compare_page_while_held(&tx,name,&q,code,&payload,&local);
    tx.rollback().unwrap();
    assert!(db.db.is_autocommit());
    assert_eq!(db.db.transaction_state(Some("main")).unwrap(),rusqlite::TransactionState::None);
    assert_eq!(db.db.total_changes(),before);
"""+after),
    )
    for prior,updated in inserts:
        if driver.count(prior)!=1:
            raise ValueError("Missing unique same-transaction observer slot")
        driver=driver.replace(prior,updated)
    return {**files,"main.rs":driver+b"\n"+fragment},pins


def prepare(where):
    if (platform.system(),platform.machine())!=("Linux","x86_64"):
        raise ValueError("Exact stock native static qualification requires Linux x86-64")
    pin=json.loads((HIA_ROOT/"qualification/compiler-binding.json").read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256")!=pin:
        raise ValueError("Exact Selfhost compiler pin required")
    obj=where/OBJECT
    meta,_=build_native(SOURCE,obj,kind="object",backend="selfhost",byte_exports=("f0",),
                        compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=pin)
    data=obj.read_bytes()
    code=exact_native_text(data)
    if (len(data),sha(data),meta["artifact_sha256"],len(code),sha(code),
            meta["compiler_wire_sha256"],meta["chain_migration"]["composed_source_sha256"],
            meta["claims"]["fallback_used"])!=(
            32768,OBJECT_SHA,OBJECT_SHA,32186,TEXT_SHA,WIRE_SHA,SCOPE_SHA,False):
        raise ValueError("Exact resolved Selfhost HPF archive changed")
    archive=where/ARCHIVE
    run(["ar","crsD",archive,obj])
    locked=archive.read_bytes()
    if run(["ar","t",archive])!=OBJECT.encode()+b"\n" or run(["ar","p",archive,OBJECT])!=data:
        raise ValueError("Exact static member mismatch")

    def verify(binary):
        if obj.read_bytes()!=data or archive.read_bytes()!=locked:
            raise ValueError("Static object/archive changed")
        names=run(["nm","--defined-only",binary]).splitlines()
        [sym]=[line for line in names if line.endswith(b" T f0")]
        addr=int(sym.split()[0],16)
        raw=binary.read_bytes()
        h=struct.unpack_from("<16sHHIQQQIHHHHHH",raw)
        if h[0][:7]!=b"\x7fELF\x02\x01\x01" or h[2]!=62 or h[9]!=56:
            raise ValueError("Wrong linked x86-64 executable")
        rows=[struct.unpack_from("<IIQQQQQQ",raw,h[5]+56*i) for i in range(h[10])]
        sites=[off+addr-base for kind,flags,off,base,_,n,_,_ in rows
               if kind==1 and flags==5 and base<=addr and addr+len(code)<=base+n]
        if len(sites)!=1 or raw[sites[0]:sites[0]+len(code)]!=code:
            raise ValueError("Linked executable does not retain the exact native .text at f0")
        return dict(elf=sha(raw),archive=sha(locked),object=OBJECT_SHA,text=TEXT_SHA,
                    wire=WIRE_SHA,source=SCOPE_SHA,text_bytes=len(code),address=addr)
    return archive,verify


class HistoryHeldPageFoldStatic(unittest.TestCase):
    def test_full_fold_linked_at_same_owned_read_transaction(self):
        extra=FRAGMENT.read_bytes()
        base=frozen.extract
        observations=[]
        with tempfile.TemporaryDirectory(prefix="history-page-static-") as tmp:
            folder=Path(tmp)
            archive,check=prepare(folder)
            normal=folder/"original"
            normal.mkdir()
            expected,pins=frozen.original(normal)
            # The second genuine pinned graph doesn't need the first graph's
            # tool output. Dispose that private temporary target before replay.
            import shutil
            shutil.rmtree(normal/"target")
            linked=folder/"linked"
            linked.mkdir()
            def verify(binary):
                observations.append(check(binary))
            with patch.object(frozen,"extract",lambda:linked_extraction(base,extra)):
                actual,linked_pins=frozen.original(linked,link=(archive,verify))
        self.assertEqual(len(observations),2)
        self.assertEqual(observations[0],observations[1])
        self.assertEqual(actual,expected)
        self.assertEqual((len(actual),sha(actual)),(98432,OBS_SHA))
        self.assertEqual(FRAGMENT.read_bytes(),extra)
        self.assertEqual({k:v for k,v in pins.items() if k!="captured_sources"},
                         {k:v for k,v in linked_pins.items() if k!="captured_sources"})
        self.assertEqual(pins["captured_sources"]["frozen.rs"],linked_pins["captured_sources"]["frozen.rs"])
        self.assertNotEqual(pins["captured_sources"]["main.rs"],linked_pins["captured_sources"]["main.rs"])
        at=0
        cases=[]
        while at<len(actual):
            nn,qn,code,on,localn=struct.unpack_from("<5Q",actual,at)
            at+=40
            name=actual[at:at+nn].decode("ascii")
            cases.append((name,code,qn,on,localn))
            at+=nn+qn+on+localn
        self.assertEqual(at,len(actual))
        self.assertEqual(len(cases),20)
        self.assertIn(("full-batch-continuation",0,35456,584,544),cases)
        self.assertIn(("unknown-first",40,128,0,32),cases)
        self.assertIn(("missing-late",41,1616,0,96),cases)
        if out:=os.environ.get("HIA_HPF_STATIC_PROOF"):
            Path(out).write_text(json.dumps(dict(cases=cases,static=observations[0],original=pins,
                linked=linked_pins,observations=len(actual),observation_sha=sha(actual)),
                sort_keys=True,indent=2)+"\n")
