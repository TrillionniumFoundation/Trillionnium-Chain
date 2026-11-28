"""Statically linked stock HPT while both projected batches' Rust read transaction is live."""
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
from hia.tests.test_node_history_page_two_batch import DRIVER, SOURCE, composed_original
from hia.tools.toolchain import HIA_ROOT, build_native

FRAGMENT=Path(__file__).with_name("rust_history_page_two_batch_held_link.rs")
DRIVER_SHA="e2878519b43b047c5457b904bc9914efcf0eb4163d3efa92c181ea7646bee2cb"
OBJECT_SHA="5916de14d9c496c4f2e9f1f2e98f6db03e9117a022615195dcae774e4c91474e"
TEXT_SHA="749b565726d3a6be996376160c1ad0e39cccb85c90e1fb429f33aa70ba297c16"
WIRE_SHA="9c8374ccf674086ec9d17f5c946f74808d81d3ff989021602745cb02e3b0b971"
SCOPE_SHA="dbf8c686bae9f162c3d758d593b2954f122482fa233eb9ff8f0c2f0e3b9525a1"
OBS_SHA="3188651f311498de4b38103003d690e6913ded7cc2089792ada170e50c83df39"
OBJECT="trnm_history_two_batch.o"
ARCHIVE="libtrnm_history_two_batch_fixture.a"


def sha(raw):
    return sha256(raw).hexdigest()


def static_extraction(base, extra):
    files,pins=base()
    driver=files["main.rs"]
    begin=b"    let tx=node.db.unchecked_transaction().unwrap();"
    rollback=b"    tx.rollback().unwrap();"
    if driver.count(begin)!=1 or driver.count(rollback)!=1:
        raise ValueError("Cannot bind native observation to unique held read transaction")
    driver=driver.replace(begin,begin+b"""
    assert_eq!(tx.transaction_state(Some("main")).unwrap(),rusqlite::TransactionState::None);
    let writes_before_capture=tx.total_changes();""")
    driver=driver.replace(rollback,b"""    compare_two_batch_while_held(&tx,&frame,code,&output);
    assert_eq!(tx.total_changes(),writes_before_capture);
"""+rollback+b"""
    assert!(node.db.is_autocommit());
    assert_eq!(node.db.transaction_state(Some("main")).unwrap(),rusqlite::TransactionState::None);
    assert_eq!(node.db.total_changes(),writes_before_capture);""")
    return {**files,"main.rs":driver+b"\n"+extra},pins


def prepare(folder):
    if (platform.system(),platform.machine())!=("Linux","x86_64"):
        raise ValueError("Exact static stock held fixture requires Linux x86-64")
    pin=json.loads((HIA_ROOT/"qualification/compiler-binding.json").read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256")!=pin:
        raise ValueError("Exact pinned Selfhost compiler required")
    obj=folder/OBJECT
    receipt,_=build_native(SOURCE,obj,kind="object",backend="selfhost",byte_exports=("f0",),
                           compiler=os.environ["HIA_NATIVE_COMPILER"],compiler_sha256=pin)
    binary=obj.read_bytes()
    code=exact_native_text(binary)
    if (len(binary),sha(binary),receipt["artifact_sha256"],len(code),sha(code),
            receipt["compiler_wire_sha256"],receipt["chain_migration"]["composed_source_sha256"],
            receipt["claims"]["fallback_used"])!=(
            38232,OBJECT_SHA,OBJECT_SHA,37655,TEXT_SHA,WIRE_SHA,SCOPE_SHA,False):
        raise ValueError("Exact resolved stock HPT object differs")
    archive=folder/ARCHIVE
    run(["ar","crsD",archive,obj])
    raw_archive=archive.read_bytes()
    if run(["ar","t",archive])!=OBJECT.encode()+b"\n" or run(["ar","p",archive,OBJECT])!=binary:
        raise ValueError("Unexpected exact native archive contents")

    def verify(path):
        if obj.read_bytes()!=binary or archive.read_bytes()!=raw_archive:
            raise ValueError("Native static link objects mutated")
        [symbol]=[x for x in run(["nm","--defined-only",path]).splitlines() if x.endswith(b" T f0")]
        addr=int(symbol.split()[0],16)
        raw=path.read_bytes()
        h=struct.unpack_from("<16sHHIQQQIHHHHHH",raw)
        if h[0][:7]!=b"\x7fELF\x02\x01\x01" or h[2]!=62 or h[9]!=56:
            raise ValueError("Wrong linked fixture architecture")
        loads=[struct.unpack_from("<IIQQQQQQ",raw,h[5]+56*i) for i in range(h[10])]
        at=[off+addr-base for kind,flags,off,base,_,n,_,_ in loads
            if kind==1 and flags==5 and base<=addr and addr+len(code)<=base+n]
        if len(at)!=1 or raw[at[0]:at[0]+len(code)]!=code:
            raise ValueError("Exact stock HPT text missing at linked f0")
        return dict(elf=sha(raw),archive=sha(raw_archive),object=OBJECT_SHA,text=TEXT_SHA,
                    text_bytes=len(code),wire=WIRE_SHA,source=SCOPE_SHA,address=addr)
    return archive,verify


class HistoryTwoBatchHeldLink(unittest.TestCase):
    def test_exact_static_two_batches_and_cutoff_before_read_transaction_releases(self):
        driver=DRIVER.read_bytes()
        body=FRAGMENT.read_bytes()
        self.assertEqual(sha(driver),DRIVER_SHA)
        unmodified=frozen.extract
        def original():
            return composed_original(unmodified)
        readback=[]
        with tempfile.TemporaryDirectory(prefix="history-two-batch-static-") as tmp:
            folder=Path(tmp)
            archive,check=prepare(folder)
            with tempfile.TemporaryDirectory(prefix="original-",dir=folder) as unlinked:
                with patch.object(frozen,"extract",original):
                    expected,pins=frozen.original(Path(unlinked))
            linked=folder/"linked"
            linked.mkdir()
            def verify(path):
                readback.append(check(path))
            with patch.object(frozen,"extract",lambda:static_extraction(original,body)):
                actual,linked_pins=frozen.original(linked,link=(archive,verify))
        self.assertEqual(len(readback),2)
        self.assertEqual(*readback)
        self.assertEqual(actual,expected)
        self.assertEqual((len(actual),sha(actual)),(231568,OBS_SHA))
        self.assertEqual((DRIVER.read_bytes(),FRAGMENT.read_bytes()),(driver,body))
        self.assertEqual({k:v for k,v in pins.items() if k!="captured_sources"},
                         {k:v for k,v in linked_pins.items() if k!="captured_sources"})
        self.assertEqual(pins["captured_sources"]["frozen.rs"],linked_pins["captured_sources"]["frozen.rs"])
        self.assertNotEqual(pins["captured_sources"]["main.rs"],linked_pins["captured_sources"]["main.rs"])
        cases=[]
        at=0
        while at<len(actual):
            n,status,out=struct.unpack_from("<3Q",actual,at)
            at+=24
            raw_in,raw_out=actual[at:at+n],actual[at+n:at+n+out]
            shape=struct.unpack_from("<3Q",raw_out) if status==0 else None
            cases.append((n,status,out,shape,sha(raw_in),sha(raw_out)))
            at+=n+out
        self.assertEqual(at,len(actual))
        self.assertEqual([x[:4] for x in cases],
            [(36632,0,536,(65,16,792128)),(47216,0,88,(84,2,800000)),
             (71408,0,56,(128,1,1048576)),(38912,0,56,(70,1,400001)),(36544,42,0,None)])
        if path:=os.environ.get("HIA_HPT_STATIC_PROOF"):
            Path(path).write_text(json.dumps(dict(static=readback[0],original=pins,linked=linked_pins,
                cases=cases,observations=len(actual),observation_sha256=sha(actual)),
                sort_keys=True,indent=2)+"\n")
