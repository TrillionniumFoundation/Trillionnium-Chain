"""One read-only canonical TCV1 metadata call; no loader or authority."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import ENV
from hia.tests.test_cell_closure_manifest_relation import id_of, make_manifest
from hia.tests.test_cell_dependency_closure import closure, row
from hia.tests.test_cell_manifest import CHUNK, MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_cell_model_release_root import roster, wire as root
from hia.tests.test_cell_release_manifest import CAP, OPAQUE, ident, release
from hia.tests.test_cell_version_environment import (
    FAMILY, env_id, genuine_original, sized, version_fixture,
)

SRC = ROOT / "hia/src/data_availability/cell_complete_version.hepta"
OBSERVER = Path(__file__).with_name("rust_cell_complete_version_reference.rs")
WORK = 16032


def packet(a, b, cells, count=None):
    return b"TCV1"+sized(a)+sized(b)+struct.pack(">H",len(cells) if count is None else count)+b"".join(map(sized,cells))


def generated(pairs, *, extra_path=0, env_role=6, runtime=None, model_family=FAMILY,
              model_payload_change=False, model_size_change=False, shared=False):
    def side(context, sizes, prefix, role, family, marker, foreign=None, pad=0):
        records, cells, ids = [],[],[]
        for j,size in enumerate(sizes):
            payload=ident(marker+j)
            manifest=(foreign if foreign is not None else make_manifest(
                family,context,payload,size,CHUNK))
            cell_id=id_of(manifest)
            declared_payload=payload if foreign is None else ident(1024)
            if marker==4096 and model_payload_change and j==len(sizes)-1:
                declared_payload=ident(12)
            declared_size=size+(marker==4096 and model_size_change and j==len(sizes)-1)
            name=prefix+b"x"*pad+f"{j:03}.data".encode()
            records.append(row(name,int.from_bytes(cell_id,"big"),role=role,
                               payload=declared_payload,size=declared_size))
            cells.append(manifest)
            ids.append(cell_id)
        return closure(*records,roots=range(len(records)),
                       nested=release(family=family,context=context,cells=sorted(ids))),records,cells

    model_sizes,env_sizes = pairs
    td,_,right=side(OPAQUE,env_sizes,b"Runtime/",env_role,FAMILY,1024)
    rt=env_id(td) if runtime is None else runtime
    model_closure,model_rows,left=side(OPAQUE[:128]+rt,model_sizes,b"Model/",1,model_family,4096,
                                       right[0] if shared else None,extra_path)
    tm=root(model_closure,roster(model_rows))
    cells=sorted(set(left+right),key=id_of)
    return tm,td,cells


def bound_packet(extent):
    # A chunk record adds 36 bytes; the residual stays entirely inside the
    # ordinary lexical model path. Rebuild each original closure and ID.
    n=14000
    geometry=((CHUNK*n,), (CHUNK*n,))
    more,pad=divmod(extent-len(packet(*generated(geometry))),36)
    a,b,cells=generated(((CHUNK*(n+more),),geometry[1]),extra_path=pad)
    assert len(packet(a,b,cells))==extent
    return a,b,cells


def corpus():
    raw,model,env,manifests,vector=version_fixture()
    base=[(raw,0,None,env_id(env)+struct.pack("<I",len(manifests)))]
    def add(outer, native, original):
        base.append((outer,native,original,b""))
    def good(a,b,c):
        base.append((packet(a,b,c),0,None,env_id(b)+struct.pack("<I",len(c))))
    good(*generated(((CHUNK,), (CHUNK+1,))))
    good(*generated(((CHUNK,)*256, (CHUNK+1,)*256)))
    good(*bound_packet(CAP))
    add(b"",106,"version truncated field")
    add(b"EVB1"+raw[4:],104,"version magic")
    add(raw[:7],106,"version truncated field")
    add(raw[:8]+model[:-1],106,"version truncated field")
    add(packet(model,env,[]),87,"version manifest count")
    add(packet(model,env,[],513),87,"version manifest count")
    add(packet(model,env,manifests[:-1]),86,"version manifest coverage")
    add(packet(model,env,manifests[:-1],len(manifests)),106,"version truncated field")
    add(packet(model,env,manifests[::-1]),89,"version canonical manifests")
    add(packet(model,env,manifests[:-1]+[manifests[0]]),89,"version canonical manifests")
    add(packet(model,env,manifests)+b".",88,"version trailing bytes")
    add(packet(model,env,manifests[:-1]+[b"NOPE"]),131,"manifest version")
    add(packet(model,env,manifests[:-1]+[b"TCM"]),130,"unexpected eof")
    add(packet(b"NONE",env,manifests),52,"model root version")
    add(packet(model,b"NONE",manifests),3,"closure version")
    add(packet(model,env,[manifests[0]],0),87,"version manifest count")
    pairs=((CHUNK,), (CHUNK+1,))
    a,b,c=generated(pairs,env_role=5,runtime=ident(57))
    add(packet(a,b,c[:-1]),84,"version environment binding")
    add(packet(a,b,c)+b".",88,"version trailing bytes")
    add(packet(a,b,c[:-1]+[b"NOPE"]),131,"manifest version")
    a,b,c=generated(pairs,env_role=5)
    add(packet(a,b,c[:-1]),85,"version environment data role")
    a,b,c=generated(pairs,model_family=FAMILY.lower())
    add(packet(a,b,c),84,"version environment binding")
    a,b,c=generated(pairs,model_payload_change=True)
    add(packet(a,b,c),81,"closure manifest payload")
    a,b,c=generated(pairs,model_size_change=True)
    add(packet(a,b,c),81,"closure manifest payload")
    a,b,c=generated(((CHUNK,), (CHUNK,)),shared=True)
    assert len(c)==1
    add(packet(a,b,c),81,"closure manifest payload")
    add(packet(a,b,c*2),86,"version manifest coverage")
    return base, vector


class CellCompleteVersion(NativeManifestChecks,unittest.TestCase):
    source = SRC

    def panel(self, cases):
        for backend,mod in self.modules.items():
            for i,(data,code,payload,out_n,scratch_n) in enumerate(cases):
                with self.subTest(backend=backend,row=i,extent=len(data)):
                    out,work=MARK*out_n,SCRATCH*scratch_n
                    got=mod.call("f0",[data,out,work],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertTrue(got.arguments[0]==data,"immutable input changed")
                    self.assertEqual(got.arguments[1],payload+out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                    if code==102 and scratch_n<WORK:
                        self.assertEqual(got.arguments[2],work)

    def test_native_complete_metadata_and_capacities(self):
        cases,_=corpus()
        wire=cases[0][0]
        self.panel([(data,code,payload,43,WORK+9) for data,code,reason,payload in cases]
                   +[(wire,102,b"",35,WORK),(wire,102,b"",36,WORK-1)])

    @unittest.skipUnless(os.environ.get(ENV),"requires the genuine locked Rust SHA-2 graph")
    def test_complete_original_decode_order_and_shared_extent(self):
        cases,vector=corpus()
        over_a,over_b,over_cells=bound_packet(CAP+1)
        over=packet(over_a,over_b,over_cells)
        extra=(over,0,None,env_id(over_b)+struct.pack("<I",len(over_cells)))
        all_cases=cases+[extra]
        with tempfile.TemporaryDirectory(prefix="trnm-tcv1-rust-") as work:
            binary, originally=genuine_original(Path(work),observer=OBSERVER)
            pkt=b"".join(struct.pack("<I",len(data))+data for data,_,_,_ in all_cases)
            result=subprocess.run([binary],input=pkt,capture_output=True,check=True,timeout=45)
        self.assertFalse(result.stderr)
        self.assertIn("original_version_source_sha256",originally)
        offset=0
        real=[]
        for i,(data,code,reason,payload) in enumerate(all_cases):
            flag=result.stdout[offset]
            offset+=1
            if reason is None:
                self.assertEqual(flag,0)
                actual=result.stdout[offset:offset+36]
                self.assertEqual(actual,payload)
                if i==0:
                    self.assertEqual(result.stdout[offset+36:offset+100].hex(),vector["commitment_sha512"])
                offset+=100
            elif reason=="unexpected eof":
                self.assertEqual(flag,255)
                actual=b""
            else:
                self.assertNotIn(flag,(0,255))
                self.assertEqual(result.stdout[offset:offset+flag].decode(),reason)
                offset+=flag
                actual=b""
            if len(data)<=CAP:
                real.append((data,code,actual,36,WORK))
        self.assertEqual(offset,len(result.stdout))
        self.assertEqual(len(over),CAP+1)
        self.panel(real)
