"""Actual native root selection versus the unchanged public TCV3 getter."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests import test_da_cell_version_content_lineage as lineage
from hia.tests import tcv3_roots_projection_derivation as binding
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_da_protocol_context import locked_reference

SRC=ROOT/"hia/src/data_availability/cell_version_content_root_commitments.hepta"
ORACLE=Path(__file__).with_name("rust_cell_version_content_root_commitments_reference.rs")


def vector(frame):
    # Independent fixture expectation, not passed into the native validator.
    members,roots=struct.unpack_from(">HH",frame,4)
    chosen=struct.unpack_from(f">{roots}H",frame,8)
    p=8+2*roots
    all_digests=[]
    for _ in range(members):
        length=struct.unpack_from(">I",frame,p)[0]
        p+=4
        bytes_=frame[p:p+length]
        assert len(bytes_)==length
        all_digests.append(hashlib.sha512(lineage.t2.DOMAIN+bytes_).digest())
        p+=length
    assert p==len(frame)
    return struct.pack("<I",roots)+b"".join(all_digests[q] for q in chosen)


def make_sequence():
    nodes=[]
    previous=[]
    for generation in range(1,17):
        frame,mid=lineage.version(generation,previous)
        nodes.append(frame)
        previous=[mid]
    return nodes


def corpus():
    frames=[(data,code,error,vector(data) if code==0 else b"")
            for data,code,error,_ in lineage.corpus()]
    def add(data):
        frames.append((data,0,None,vector(data)))
    nodes=make_sequence()
    vals,top=lineage.ordered(nodes,[nodes[-1]])
    for n in range(2,16):
        # Explicitly vary exact count while retaining highest-generation root
        # as an ancestor traversal witness for every unselected node.
        indices=sorted(top+[i for i in range(16) if i not in top][:n-1])
        add(lineage.wire(vals,indices))
    sparse=sorted({*top,0,3,8,15})
    assert len(sparse)<16 and any(b-a>1 for a,b in zip(sparse,sparse[1:]))
    add(lineage.wire(vals,sparse))
    oversized=lineage.at_bound(lineage.CAP+1)
    add(oversized)
    return frames


class BoundPublishedValidation(unittest.TestCase):
    def test_retains_exact_published_validation_and_failures(self):
        raw=binding.SOURCE.read_bytes()
        prefix,tail=binding.derive(raw)
        actual=SRC.read_text().split("\n",1)[1]
        self.assertEqual(actual.split(binding.BEGIN,1)[0],prefix)
        self.assertEqual(actual[actual.index(binding.FAIL):],tail+"end\n")
        with self.assertRaisesRegex(ValueError,"published full TCV3 source changed"):
            binding.derive(raw+b"\n")


class CellVersionContentRootCommitments(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def panel(self,cases):
        for backend,mod in self.modules.items():
            for j,(item,code,want,nout,nwork) in enumerate(cases):
                with self.subTest(backend=backend,row=j,size=len(item)):
                    o,w=MARK*nout,SCRATCH*nwork
                    got=mod.call("f0",[item,o,w],timeout=40).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],item)
                    self.assertEqual(got.arguments[1],want+o[len(want):])
                    self.assertEqual(got.arguments[2][lineage.WORK:],w[lineage.WORK:])
                    if code==102 and nwork<lineage.WORK:
                        self.assertEqual(got.arguments[2],w)

    def test_actual_original_declared_root_digest_vector(self):
        rows=corpus()
        def checked():
            self.assertEqual({k:hashlib.sha256((lineage.OLD/k).read_bytes()).hexdigest()
                              for k in lineage.PINS},lineage.PINS)
        checked()
        with tempfile.TemporaryDirectory(prefix="trnm-tcv3-root-commitment-") as work:
            stream=b"".join(struct.pack("<I",len(w))+w for w,_,_,_ in rows)
            raw=locked_reference(Path(work),stream,caller=ORACLE)
        checked()
        pos=0
        actual=[]
        for index,(item,code,error,want) in enumerate(rows):
            n=raw[pos]
            pos+=1
            if error is None:
                self.assertEqual(n,0,index)
                count=struct.unpack_from("<I",raw,pos)[0]
                size=4+64*count
                result=raw[pos:pos+size]
                pos+=size
                self.assertEqual(result,want,index)
            else:
                self.assertGreater(n,0)
                self.assertEqual(raw[pos:pos+n].decode(),error,index)
                pos+=n
                result=b""
            if len(item)<=lineage.CAP:
                actual.append((item,code,result,len(result)+7,lineage.WORK+5))
        self.assertEqual(pos,len(raw))
        self.assertEqual({(len(w)-4)//64 for _,s,_,w in rows if s==0},set(range(1,17)))
        self.assertEqual(sum(len(w)==lineage.CAP+1 and s==0 for w,s,_,_ in rows),1)
        self.panel(actual)

    def test_all_roots_capacity_and_late_failure_without_any_output(self):
        nodes=make_sequence()
        vals,indices=lineage.ordered(nodes,nodes)
        data=lineage.wire(vals,indices)
        want=vector(data)
        self.assertEqual(len(want),1028)
        ready=lineage.WORK
        self.panel([(data,0,want,len(want),ready),
                    (data,102,b"",len(want)-1,ready),
                    (data,102,b"",len(want),ready-1),
                    (data+b"x",225,b"",0,ready),
                    (lineage.wire(vals[::-1],indices),227,b"",5,ready),
                    (b"TCV0",222,b"",0,0)])
