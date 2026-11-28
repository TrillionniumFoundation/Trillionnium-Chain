"""Actual bounded TCV3 on both stock emitters versus unchanged public Rust."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests import test_da_cell_complete_version_content as t2
from hia.tests import tcv3_member_derivation as derived
from hia.tests.test_cell_complete_version import closure, env_id, packet, root, roster
from hia.tests.test_cell_closure_manifest_relation import id_of, make_manifest
from hia.tests.test_cell_dependency_closure import row
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_cell_model_release_root import ROOT_DOMAIN
from hia.tests.test_cell_release_manifest import OPAQUE, ident, release
from hia.tests.test_da_protocol_context import locked_reference

SRC=ROOT/"hia/src/data_availability/cell_version_content_lineage.hepta"
ORACLE=Path(__file__).with_name("rust_cell_version_content_lineage_reference.rs")
OLD=t2.OLD
PINS={**t2.PINS,"version_content_closure_v3.rs":
      "65bd7171aa9f70d8c2c426f9e024d47e0c98728d804896f3bd41c807e254227a",
      "model_root.rs":"6311b100634a1358e2d1aad2d9b71300e75f599326f9f5c61d4eff8149ac3915"}
DOMAIN=b"TRNM/Cell/ContentLineageClosure/v3\0"
WORK=133280
CAP=1<<20
FAMILY=b"fixture.A"
TRUNC="content lineage truncated field"
ORDER="content lineage canonical versions"
ROOTS="content lineage canonical roots"
TRAIL="content lineage trailing bytes"
MISSING="content lineage missing parent"
RELATION="content lineage parent family/generation"
ORPHAN="content lineage unreachable version"


def version(generation, parents=(), *, family=FAMILY, marker=111, variant=0,
            env_size=3, model_size=4, extra_path=0):
    env_payload=ident(1)
    env_cell=make_manifest(family,OPAQUE,env_payload,env_size)
    env_claim=id_of(env_cell)
    env=closure(row(b"Cfg.dat",int.from_bytes(env_claim,"big"),role=6,payload=env_payload,size=env_size),
                nested=release(family=family,context=OPAQUE,cells=[env_claim]))
    ctx=OPAQUE[:128]+env_id(env)
    payload=ident(marker)
    model_cell=make_manifest(family,ctx,payload,model_size)
    mid=id_of(model_cell)
    path=(b"x"*extra_path if extra_path<=50 else b"x"*50+b"/"+b"x"*(extra_path-51))
    rows=[row(path+b"Model.dat",int.from_bytes(mid,"big"),role=1,payload=payload,size=model_size)]
    tcd=closure(*rows,generation=generation,nested=release(family=family,context=ctx,cells=[mid]))
    tmr=root(tcd,roster(rows),sorted(parents))
    children=sorted((env_cell,model_cell),key=id_of)
    records=t2.declarations(children)
    if variant:
        records[0]=records[0][:32]+t2.digest64(variant)+records[0][96:]
    return t2.wire(packet(tmr,env,children),records),hashlib.sha256(ROOT_DOMAIN+tmr).digest()


def wire(members,roots,*,count=None,root_count=None):
    v=len(members) if count is None else count
    r=len(roots) if root_count is None else root_count
    return (b"TCV3"+struct.pack(">HH",v,r)+b"".join(struct.pack(">H",x) for x in roots)
            +b"".join(struct.pack(">I",len(x))+x for x in members))


def ordered(members,selected):
    vals=sorted(members,key=lambda v:hashlib.sha512(t2.DOMAIN+v).digest())
    assert len(set(vals))==len(vals)
    return vals,sorted(vals.index(x) for x in selected)


def result(raw,v,r):
    return struct.pack("<II",v,r)+hashlib.sha512(DOMAIN+raw).digest()


def at_bound(extent):
    width=t2.CHUNK
    n=5000
    def current(count,pad=0):
        item=version(1,env_size=n*width,model_size=count*width,extra_path=pad)[0]
        return wire([item],[0])
    add,pad=divmod(extent-len(current(n)),100)
    frame=current(n+add,pad)
    assert len(frame)==extent
    return frame


def corpus():
    cases=[]
    def accept(members,roots):
        raw=wire(members,roots)
        cases.append((raw,0,None,result(raw,len(members),len(roots))))
    def refuse(raw,code,reason):
        cases.append((raw,code,reason,b""))
    first,root0=version(1)
    second,root1=version(2,[root0])
    other,root2=version(2,[root0],marker=123)
    joined,_=version(3,[root1,root2])
    t,indices=ordered([first,second,other,joined],[joined])
    accept(t,indices)
    accept([first],[0])
    pair,pair_root=ordered([first,second],[second])
    accept(pair,pair_root)
    accept(*ordered([first,second,other,joined],[second,joined]))
    sequence=[]
    for j in range(1,17):
        row0,parent=version(j,[] if j==1 else [parent])
        sequence.append(row0)
    accept(*ordered(sequence,[sequence[-1]]))
    independent=[version(j)[0] for j in range(1,17)]
    accept(*ordered(independent,independent))
    extreme,_=version((1<<64)-1,[root0])
    accept(*ordered([first,extreme],[extreme]))
    limit=at_bound(CAP)
    cases.append((limit,0,None,result(limit,1,1)))
    base=wire([first],[0])
    refuse(base[:3],221,TRUNC)
    refuse(b"TCV2"+base[4:],222,"content lineage namespace")
    for n in (4,5,6,7,8,9,10,11,12,13):
        refuse(base[:n],221,TRUNC)
    refuse(wire([],[]),223,"content lineage declared counts")
    refuse(wire([],[],count=17,root_count=1),223,"content lineage declared counts")
    refuse(wire([],[],count=16,root_count=17),223,"content lineage declared counts")
    refuse(wire([first],[]),223,"content lineage declared counts")
    refuse(base[:10]+struct.pack(">I",25165825),224,"content lineage member bound")
    refuse(base[:-1],221,TRUNC)
    refuse(wire([b""],[0]),211,t2.TRUNC)
    refuse(wire([first,b"BAD!"],[2]),212,t2.NAMESPACE)
    refuse(wire([first,b"BAD!"],[2])+b"x",212,t2.NAMESPACE)
    refuse(wire([first],[7])+b"x",225,TRAIL)
    refuse(wire([first],[1]),226,ROOTS)
    refuse(wire(pair,[0,0]),226,ROOTS)
    refuse(wire(pair,[1,0]),226,ROOTS)
    refuse(wire(pair[::-1],[0,1]),227,ORDER)
    refuse(wire([first,first],[0,1]),227,ORDER)
    dup,_=version(1,variant=2026)
    refuse(wire(*ordered([first,dup],[first,dup])),228,"content lineage ambiguous legacy model alias")
    refuse(wire([second],[0]),229,MISSING)
    bad_gen,_=version(1,[root0])
    refuse(wire(*ordered([first,bad_gen],[bad_gen])),230,RELATION)
    bad_family,_=version(3,[root0],family=FAMILY.lower())
    refuse(wire(*ordered([first,bad_family],[bad_family])),230,RELATION)
    prefix_family,_=version(3,[root0],family=FAMILY+b"x")
    refuse(wire(*ordered([first,prefix_family],[prefix_family])),230,RELATION)
    refuse(wire(*ordered([first,second],[first])),231,ORPHAN)
    # An unresolved edge on an unselected node beats graph reachability.
    missing,_=version(3,[ident(166)])
    refuse(wire(*ordered([first,missing],[first])),229,MISSING)
    return cases


class PublishedContentBinding(unittest.TestCase):
    def test_immutable_tcv2_derivation(self):
        source=derived.SOURCE.read_bytes()
        self.assertEqual(SRC.read_text().split("fn c3_tcv_content",1)[1],
                         derived.derive(source).split("fn c3_tcv_content",1)[1])
        with self.assertRaisesRegex(ValueError,"published TCV2 source changed"):
            derived.derive(source+b"\n")


class CellVersionContentLineage(NativeManifestChecks,unittest.TestCase):
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
                    self.assertEqual(got.arguments[2][WORK:],w[WORK:])
                    if code==102 and nwork<WORK:
                        self.assertEqual(got.arguments[2],w)

    def test_actual_original_dag_and_validation_precedence(self):
        extra=at_bound(CAP+1)
        self.assertEqual(len(extra),CAP+1)
        cases=corpus()+[(extra,0,None,result(extra,1,1))]
        def checked():
            self.assertEqual({s:hashlib.sha256((OLD/s).read_bytes()).hexdigest() for s in PINS},PINS)
        checked()
        with tempfile.TemporaryDirectory(prefix="trnm-tcv3-locked-") as work:
            stream=b"".join(struct.pack("<I",len(w))+w for w,_,_,_ in cases)
            raw=locked_reference(Path(work),stream,caller=ORACLE)
        checked()
        pos=0
        actual=[]
        for index,(item,code,error,want) in enumerate(cases):
            n=raw[pos]
            pos+=1
            if error is None:
                self.assertEqual(n,0,(index,raw[pos:pos+n]))
                native=raw[pos:pos+72]
                pos+=72
                self.assertEqual(native,want)
            else:
                self.assertGreater(n,0)
                self.assertEqual(raw[pos:pos+n].decode(),error,index)
                pos+=n
                native=b""
            if len(item)<=CAP:
                actual.append((item,code,native,79,WORK+7))
        self.assertEqual(pos,len(raw))
        self.panel(actual)

    def test_atomic_output_and_exact_scratch_bound(self):
        versions=[version(1)[0]]
        data=wire(versions,[0])
        self.panel([(data,0,result(data,1,1),72,WORK),
                    (data,102,b"",71,WORK),
                    (data,102,b"",72,WORK-1),
                    (b"NOPE",222,b"",0,0)])
