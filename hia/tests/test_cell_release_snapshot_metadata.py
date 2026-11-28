"""Bounded same-loan CTS1 diagnostic; no supplied pins or actual files."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import (
    CLOSURE, CODEC, ENV, LOCK, MODEL_ROOT, TENSOR_CONTRACT, dependency_graph, regular, sha, source,
)
from hia.tests.cts_metadata_derivation import BEGIN, DATA, PINS, derive
from hia.tests.test_cell_complete_version import (
    FAMILY, OPAQUE, closure, env_id, id_of, ident, make_manifest, packet,
    release, root, roster, row,
)
from hia.tests.test_cell_manifest import CHUNK, MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_cell_release_manifest import CAP
from hia.tests.test_cell_tensor_contract import file as tensor_file, row as tensor_row
from hia.tests.test_cell_tensor_model_manifest import at_extent, contract, wire as tma
from hia.tests.test_cell_version_environment import VERSION, VERSION_SOURCE, sized
from hia.tests.test_verification_profile_registry import pick

SRC = ROOT/"hia/src/data_availability/cell_release_snapshot_metadata.hepta"
ORIGINAL = CLOSURE.with_name("release_snapshot.rs")
ORACLE = Path(__file__).with_name("rust_cell_release_snapshot_metadata_reference.rs")
ORIGINAL_PIN = "8b8ec738cfdc47b62b1686b833f36dc94618a7bff246c592c2fb61fcc9947869"
WORK = 131232
VALIDATION_SCRATCH = 16032
DOMAIN = b"TRNM/Cell/TensorReleaseSnapshot/v1\0"
PROFILE = ident(99)


def snapshot(cv,av,index=1,profile=PROFILE):
    return b"CTS1"+sized(cv)+sized(av)+struct.pack(">H",index)+profile


def model_metadata(base=14,count=2,era=2,rules_role=6,pad_chunks=0):
    # Only build the one genuine environment member. Its full original
    # declaration, size and context are included as ordinary fixture metadata.
    env_cell=make_manifest(FAMILY,OPAQUE,ident(12),7)
    eid=id_of(env_cell)
    environment=closure(row(b"Runtime.config",int.from_bytes(eid,"big"),
                            role=6,payload=ident(12),size=7),
                        nested=release(family=FAMILY,context=OPAQUE,cells=[eid]))
    ctx=OPAQUE[:128]+env_id(environment)
    layout=[(b"Model.bin",1,21,base)]
    for i in range(count-1):
        layout.append((f"Rules/{i:03}.cfg".encode(),rules_role,100+i,
                       4+pad_chunks*CHUNK if i==0 else 8))
    models=[make_manifest(FAMILY,ctx,ident(i),n) for _,_,i,n in layout]
    ids=[id_of(m) for m in models]
    rows=[row(name,int.from_bytes(h,"big"),role=role,payload=ident(k),size=n)
          for h,(name,role,k,n) in zip(ids,layout)]
    rd=root(closure(*rows,generation=era,roots=range(count),
                    nested=release(family=FAMILY,context=ctx,cells=sorted(ids))),roster(rows))
    return packet(rd,environment,sorted([env_cell,*models],key=id_of)),rd


def bounded(n):
    cv,rd=model_metadata(base=16384*4+10)
    tv=at_extent(rd,n-46-len(cv)-len(rd)-12)
    w=snapshot(cv,tma(rd,tv))
    assert len(w)==n
    return w


def corpus():
    cv,rd=model_metadata()
    tv=contract(rd,tensor_file(0,tensor_row(b"bias")))
    av=tma(rd,tv)
    _,other=model_metadata(era=3)
    different=tma(other,contract(other,tensor_file(0,tensor_row(b"bias"))))
    last_cv,last_rd=model_metadata(count=256)
    last_av=tma(last_rd,contract(last_rd,tensor_file(0,tensor_row(b"scalar"))))
    vlong,r2=model_metadata(pad_chunks=17)
    nested_move=tma(r2,contract(r2,tensor_file(0,tensor_row(b"longer"))))
    cases=[(w,0,None) for w in (snapshot(cv,av),
                               snapshot(cv,av,1,b"\0"*31+b"\1"),
                               snapshot(last_cv,last_av,255),
                               snapshot(vlong,nested_move,1),
                               bounded(CAP))]
    a=snapshot(cv,av)
    cases.extend([
        (b"",200,"snapshot wire length"),
        (a[:45],200,"snapshot wire length"),
        (b"WRNG"+a[4:],201,"snapshot wire version"),
        (a[:4]+struct.pack(">I",(8<<20)+1)+a[8:],203,"snapshot frame bound"),
        (a[:4]+struct.pack(">I",len(a))+a[8:],202,"snapshot truncated field"),
        (snapshot(b"",b""),106,"version truncated field"),
        (snapshot(b"NONE",b"NONE"),104,"version magic"),
        (a[:8+len(cv)]+b"\0",202,"snapshot truncated field"),
        (a[:8+len(cv)]+struct.pack(">I",2097718)+a[12+len(cv):],203,"snapshot frame bound"),
        (snapshot(cv,b""),90,"tensor model manifest length"),
        (snapshot(cv,b"NONE"+av[4:]),91,"tensor model manifest version"),
        (snapshot(cv,av+b"."),93,"tensor model manifest suffix"),
        (snapshot(cv,tma(rd,tv[:6]+ident(140)+tv[38:])),79,"tensor model root"),
        (a[:-34],202,"snapshot truncated field"),
        (a[:-33],202,"snapshot truncated field"),
        (a[:-1],202,"snapshot truncated field"),
        (a+b".",204,"snapshot trailing bytes"),
        (snapshot(cv,different,300,bytes(32))+b".",204,"snapshot trailing bytes"),
        (snapshot(cv,different,300,bytes(32)),205,"snapshot exact tensor/version model"),
        (snapshot(cv,different),205,"snapshot exact tensor/version model"),
        (snapshot(cv,av,300,bytes(32)),206,"snapshot composition profile"),
        (snapshot(cv,av,0),207,"snapshot composition rules file"),
        (snapshot(cv,av,2),207,"snapshot composition rules file"),
        (snapshot(last_cv,last_av,256),207,"snapshot composition rules file"),
    ])
    # All malformed TCV/TMA child cases have genuine bounded immutable spans.
    return [(w,c,r,(w[-34:]+hashlib.sha512(DOMAIN+w).digest()) if not c else b"")
            for w,c,r in cases]


def genuine_original(work):
    rlib=Path(os.environ[ENV]).absolute()
    rust,graph,bound=dependency_graph(rlib)
    v=VERSION.read_bytes()
    orig=ORIGINAL.read_bytes()
    if (sha(v),sha(orig))!=(VERSION_SOURCE,ORIGINAL_PIN):
        raise ValueError("original TCV1/CTS1 source changed")
    old=source(with_tensor_model_manifest=True)
    old=old[:old.index(b"#[allow(dead_code)]\nmod closure_observer")]
    vc=b"".join(pick(v,p) for p in (
        rb"^pub const MAX_CELL_VERSION_BYTES_V1:[^\n]+;\n",
        rb"^pub const MAX_CELL_VERSION_MANIFESTS_V1:[^\n]+;\n",
        rb"^pub type CellVersionCommitmentV1 = [^\n]+;\n",
    ))
    vdef=v[v.index(b"/// TCV1 includes"):v.index(b"/// Independent owner pins")]
    vinit=v[v.index(b"impl CellVersionManifestV1 {"):v.index(b"    pub fn verify_for_loader(")]
    vcodec=v[v.index(b"    pub fn encode("):v.index(b"    /// Re-read every declared manifest")]
    vinput=v[v.index(b"struct VersionInput<'a>"):v.index(b"#[cfg(test)]")]
    sd=orig[orig.index(b"pub const MAX_CELL_RELEASE_SNAPSHOT_BYTES_V1"):orig.index(b"/// Independent current owner")]
    sinit=orig[orig.index(b"impl CellReleaseSnapshotV1 {"):orig.index(b"    pub fn verify_for_loader(")]
    scodec=orig[orig.index(b"    pub fn encode("):orig.index(b"/// A complete borrowed task snapshot")]
    shash=orig[orig.index(b"fn wire_commitment("):orig.index(b"#[cfg(test)]")]
    raw=(old+b"use sha2::{Sha512,Digest};\nuse std::collections::BTreeSet;\n"
         b"use tensor_contract::{CellTensorModelManifestV1,MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1};\n"
         +vc+vdef+vinit+vcodec+b"}\n"+vinput+sd+sinit+scodec+shash+ORACLE.read_bytes())
    src,binary=work/"original.rs",work/"original"
    src.write_bytes(raw)
    r=subprocess.run(["rustc","--edition=2024","-Dwarnings","-L",f"dependency={rlib.parent}",
                      "--extern",f"sha2={rlib}",src,"-o",binary],
                     capture_output=True,timeout=45)
    if r.returncode:
        raise ValueError(r.stderr.decode()[:4096])
    if any(sha(regular(f))!=expected for f,expected in bound.items()):
        raise ValueError("locked oracle library changed during linking")
    return binary,{"rustc":rust,"locked_graph":graph,"cargo_lock_sha256":sha(LOCK.read_bytes()),
                   "original_snapshot_sha256":sha(orig),"original_version_sha256":sha(v),
                   "original_tensor_sha256":sha(TENSOR_CONTRACT.read_bytes()),
                   "original_model_sha256":sha(MODEL_ROOT.read_bytes()),
                   "original_closure_sha256":sha(CLOSURE.read_bytes()),
                   "original_manifest_sha256":sha(CODEC.read_bytes()),
                   "oracle_source_sha256":sha(raw),"oracle_sha256":sha(binary.read_bytes())}


class SnapshotSourceDerivation(unittest.TestCase):
    def test_old_span_source_pins_and_mechanical_boundary(self):
        known={name:(DATA/name).read_bytes() for name in PINS}
        d=derive(known)
        self.assertEqual(SRC.read_text().split("\n"+BEGIN,1)[1],d.split(BEGIN,1)[1])
        for filename in known:
            changed=dict(known)
            changed[filename]+=b"\n"
            with self.assertRaisesRegex(ValueError,"published CTS1 dependency differs"):
                derive(changed)


class CellReleaseSnapshotMetadata(NativeManifestChecks,unittest.TestCase):
    source=SRC

    def panel(self,cases):
        for backend,mod in self.modules.items():
            for i,(wire,code,want,out_n,work_n) in enumerate(cases):
                with self.subTest(backend=backend,row=i,extent=len(wire)):
                    out,w=MARK*out_n,SCRATCH*work_n
                    got=mod.call("f0",[wire,out,w],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertTrue(got.arguments[0]==wire,"changed immutable wire")
                    self.assertEqual(got.arguments[1],want+out[len(want):])
                    if code:
                        self.assertTrue(got.arguments[2][VALIDATION_SCRATCH:]==w[VALIDATION_SCRATCH:],
                                        "a refused snapshot started SHA-512")
                    self.assertEqual(got.arguments[2][WORK:],w[WORK:])

    def test_bounded_native_subspans_and_atomic_post_pin_metadata(self):
        rows=corpus()
        wire=rows[0][0]
        self.panel([(data,code,want,103,WORK+7) for data,code,_,want in rows]
                   +[(wire,102,b"",97,WORK),(wire,102,b"",98,WORK-1),
                     (wire,102,b"",98,VALIDATION_SCRATCH-1)])

    @unittest.skipUnless(os.environ.get(ENV),"requires genuine locked Rust SHA-2 graph")
    def test_actual_original_after_self_calculated_synthetic_pin(self):
        rows=corpus()
        over=bounded(CAP+1)
        extra=(over,0,None,over[-34:]+hashlib.sha512(DOMAIN+over).digest())
        with tempfile.TemporaryDirectory(prefix="trnm-cts1-original-") as work:
            binary,proof=genuine_original(Path(work))
            raw=b"".join(struct.pack("<I",len(w))+w for w,_,_,_ in rows+[extra])
            obs=subprocess.run([binary],input=raw,capture_output=True,check=True,timeout=45)
        self.assertEqual(obs.stderr,b"")
        self.assertEqual(proof["original_snapshot_sha256"],ORIGINAL_PIN)
        offset=0
        direct=[]
        for wire,code,reason,want in rows+[extra]:
            flag=obs.stdout[offset]
            offset+=1
            if reason is None:
                self.assertEqual(flag,0)
                observed=obs.stdout[offset:offset+98]
                self.assertEqual(observed,want)
                offset+=98
            elif reason=="unexpected eof":
                self.assertEqual(flag,255)
                observed=b""
            else:
                self.assertNotIn(flag,(0,255))
                self.assertEqual(obs.stdout[offset:offset+flag].decode(),reason)
                offset+=flag
                observed=b""
            if len(wire)<=CAP:
                direct.append((wire,code,observed,98,WORK))
        self.assertEqual(offset,len(obs.stdout))
        self.assertEqual(len(over),CAP+1)
        self.panel(direct)
