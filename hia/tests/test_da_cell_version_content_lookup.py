"""Offline exact original TCV2 declaration lookup with immutable input."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests import test_da_cell_complete_version_content as t2
from hia.tests import test_da_cell_version_content_lineage as t3
from hia.tests.test_cell_complete_version import generated, packet
from hia.tests.test_cell_manifest import CHUNK, MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_da_protocol_context import locked_reference

SRC=ROOT/"hia/src/data_availability/cell_version_content_lookup.hepta"
ORACLE=Path(__file__).with_name("rust_cell_version_content_lookup_reference.rs")
OLD=t2.OLD
PINS=t2.PINS
CAP=1<<20
WORK=16032
MISSING="content undeclared file"


def at_bound(length):
    # This existing synthetic fixture is built using each original nested
    # value's bytes and legal path padding. Its 14-byte one-member TCV3 header
    # is not submitted to lookup: the comparison is against the input TCV2.
    wire=t3.at_bound(length-32+14)[14:]
    v1_end=8+int.from_bytes(wire[4:8],"big")
    records=[]
    pos=v1_end+2
    while pos<len(wire):
        chunks=int.from_bytes(wire[pos+96:pos+100],"big")
        end=pos+100+64*chunks
        records.append(wire[pos:end])
        pos=end
    assert pos==len(wire) and len(records)==2
    return wire,records


def corpus():
    model=generated(((CHUNK,CHUNK*2+7),(CHUNK+1,CHUNK*5)))
    manifests=t2.declarations(model[-1])
    inner=packet(*model)
    cv=t2.wire(inner,manifests)
    cases=[]
    def accept(body,record):
        cases.append((record[:32]+body,0,None,record))
    def refuse(key,body,status,why):
        cases.append((key+body,status,why,b""))
    for r in manifests:
        accept(cv,r)
    r0,rm=manifests[0],manifests[-1]
    k0=r0[:32]
    between=(int.from_bytes(k0,"big")+1).to_bytes(32,"big")
    assert k0<between<manifests[1][:32]
    for key in (bytes(32),bytes([0xFF])*32,between):
        refuse(key,cv,234,MISSING)
    larger=generated(((CHUNK,)*256,(CHUNK+1,)*256))
    many=t2.declarations(larger[-1])
    body=t2.wire(packet(*larger),many)
    for idx in (0,255,256,511):
        accept(body,many[idx])
    max_wire,max_r=at_bound(CAP)
    for rec in max_r:
        accept(max_wire,rec)
    refuse(bytes(32),max_wire,234,MISSING)
    over_wire,over_r=at_bound(CAP+1)
    accept(over_wire,max(over_r,key=len))
    # A queried row is not allowed to short-circuit validation. Later declared
    # digest errors/short arrays/trailing data win over any match or absence.
    zero_late=rm[:-64]+bytes(64)
    refuse(k0,t2.wire(inner,[*manifests[:-1],zero_late]),214,t2.BIND)
    refuse(bytes(32),t2.wire(inner,[*manifests[:-1],zero_late]),214,t2.BIND)
    refuse(k0,t2.wire(inner,[*manifests[:-1],rm[:-1]]),215,t2.TRUNC_CHUNKS)
    refuse(k0,t2.wire(inner,[*manifests[:-1],zero_late])+b"x",216,t2.TRAIL)
    refuse(k0,t2.wire(inner,manifests,0),213,t2.COVERAGE)
    refuse(k0,cv+b"x",216,t2.TRAIL)
    refuse(k0,t2.wire(b"NONE"+inner[4:],manifests),104,"version magic")
    refuse(k0,b"NONE"+cv[4:],212,t2.NAMESPACE)
    refuse(k0,b"",211,t2.TRUNC)
    return cases


class CellVersionContentLookup(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def panel(self,cases):
        for backend,mod in self.modules.items():
            for idx,(data,code,want,nout,nwork) in enumerate(cases):
                with self.subTest(backend=backend,row=idx,extent=len(data)):
                    o,w=MARK*nout,SCRATCH*nwork
                    got=mod.call("f0",[data,o,w],timeout=40).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],want+o[len(want):])
                    self.assertEqual(got.arguments[2][WORK:],w[WORK:])
                    if code==102 and nwork<WORK:
                        self.assertEqual(got.arguments[2],w)

    def test_original_public_lookup_after_every_declaration_is_valid(self):
        rows=corpus()
        def checked():
            self.assertEqual({k:hashlib.sha256((OLD/k).read_bytes()).hexdigest() for k in PINS},PINS)
        checked()
        with tempfile.TemporaryDirectory(prefix="trnm-tcv2-declaration-lookup-") as work:
            query=b"".join(struct.pack("<I",len(frame))+frame for frame,_,_,_ in rows)
            actual=locked_reference(Path(work),query,caller=ORACLE)
        checked()
        pos=0
        panel=[]
        for idx,(query,code,error,expected) in enumerate(rows):
            tag,n=struct.unpack_from("<BI",actual,pos)
            pos+=5
            value=actual[pos:pos+n]
            pos+=n
            if error is None:
                self.assertEqual(tag,0,idx)
                self.assertEqual(value,expected,idx)
            else:
                self.assertEqual(tag,1,idx)
                self.assertEqual(value.decode(),error,idx)
                value=b""
            if len(query)<=CAP:
                panel.append((query,code,value,len(value)+11,WORK+9))
        self.assertEqual(pos,len(actual))
        self.assertEqual(sum(len(q)==CAP+1 and code==0 for q,code,_,_ in rows),1)
        self.panel(panel)

    def test_atomic_output_capacity_query_and_absence(self):
        frame,_,_,record=corpus()[0]
        absent=bytes(32)+frame[32:]
        wide,rows=at_bound(CAP)
        largest=max(rows,key=len)
        self.panel([(frame,0,record,len(record),WORK),
                    (frame,102,b"",len(record)-1,WORK),
                    (frame,102,b"",len(record),WORK-1),
                    (absent,234,b"",0,WORK),
                    (absent+b"x",216,b"",0,WORK),
                    (largest[:32]+wide,102,b"",len(largest)-1,WORK),
                    (bytes(31),233,b"",0,0),
                    (bytes(32),211,b"",0,0)])
