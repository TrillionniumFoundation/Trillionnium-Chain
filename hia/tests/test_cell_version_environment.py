"""Exact, offline TCV1 declared model/environment stage (not whole TCV1)."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import (
    CLOSURE, CODEC, ENV, LOCK, MODEL_ROOT, dependency_graph, regular, sha, source,
)
from hia.tests.test_cell_dependency_closure import DOMAIN, WORK, closure, row
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks
from hia.tests.test_cell_model_release_root import roster, wire as root
from hia.tests.test_cell_release_manifest import CAP, OPAQUE, ident, release
from hia.tests.test_verification_profile_registry import pick

SRC = ROOT / "hia/src/data_availability/cell_version_environment.hepta"
VERSION = CLOSURE.with_name("version.rs")
ORACLE = Path(__file__).with_name("rust_cell_version_environment_reference.rs")
VECTOR = ROOT / "formal/pon-nakamoto-v1/vectors/cell-complete-version-v1.json"
VERSION_SOURCE = "e0d11e7cddbb670af8411bed97612e738edf9a7c89b161e1ee4cdd9178cda832"
FAMILY = b"Model.Environment_v1"


def be32(n):
    return struct.pack(">I", n)


def sized(data):
    return be32(len(data)) + data


def frame(a, b):
    return b"EVB1" + sized(a) + sized(b)


def env_id(environment):
    return hashlib.sha256(DOMAIN + environment).digest()


def make_environment(family=FAMILY, context=OPAQUE, roles=(6, 6)):
    rows = [row(f"Environment/Item{i:03}.cfg".encode(), 1234 + i, role=role)
            for i, role in enumerate(roles)]
    nested = release(family=family, context=context,
                     cells=[ident(i) for i in range(1234, 1234 + len(rows))])
    return closure(*rows, roots=range(len(rows)), nested=nested)


def make_model(runtime, family=FAMILY, context=OPAQUE, lineage=()):
    files = [row(b"Base.tensor", 1, role=1, dependencies=(1,)),
             row(b"Router.index", 2, role=5)]
    nested = release(family=family, context=context[:128] + runtime, cells=[ident(1), ident(2)])
    return root(closure(*files, nested=nested), roster(files), lineage)


def version_fixture():
    vector = json.loads(VECTOR.read_text())
    wire = bytes.fromhex(vector["wire_hex"])
    assert wire[:4] == b"TCV1" and len(wire) == vector["wire_bytes"]
    def take(pos):
        n = int.from_bytes(wire[pos:pos+4], "big")
        return wire[pos+4:pos+4+n], pos+4+n
    model, at = take(4)
    env, at = take(at)
    count = int.from_bytes(wire[at:at+2], "big")
    at += 2
    manifests = []
    for _ in range(count):
        value, at = take(at)
        manifests.append(value)
    assert at == len(wire) and len(manifests) > 1
    return wire, model, env, manifests, vector


def fixtures():
    td = make_environment()
    tm = make_model(env_id(td))
    full, vector_model, vector_env, _, vector = version_fixture()
    assert env_id(vector_env).hex() == vector["environment_closure"]
    accept = [(tm, td), (vector_model, vector_env)]
    for family in (b"A", b"Z"*64, b"Model.Environment_v11"):
        x = make_environment(family, context=ident(77)*5, roles=(6,)*256)
        # Other context words can differ. Relation checks only declared runtime and family.
        accept.append((make_model(env_id(x), family, lineage=tuple(ident(i) for i in range(1,17))), x))
    cases = [(frame(a,b),0,env_id(b)) for a,b in accept]
    cases.extend((frame(a,b),code,b"") for a,b,code in (
        (make_model(ident(100)),td,84),
        (make_model(env_id(td),FAMILY.lower()),td,84),
        (make_model(env_id(td),FAMILY[:-1]),td,84),
        (make_model(env_id(td),FAMILY+b"1"),td,84),
        (tm,make_environment(context=ident(405)*5),84),
        (tm,make_environment(roles=(6,4)),84),
        (tm,b"",2),(b"",td,2),(b"NONE",b"NOPE",52),
        (tm,b"NONE",3),(tm,td+b".",10),(tm+b".",td,54),
    ))
    for position in (0,1,127,255):
        roles = tuple(2 if i == position else 6 for i in range(256))
        environment = make_environment(roles=roles)
        cases += [(frame(make_model(env_id(environment)),environment),85,b""),
                  (frame(make_model(ident(57),FAMILY[:-1]),environment),84,b"")]
    good = frame(tm,td)
    cases += [(q,100,b"") for q in (b"",good[:1],good[:8],good[:11],good[:-1],good+b".",
                                      b"TCV1"+good[4:],b"EVB1"+be32(0xffffffff)+good[8:],
                                      b"EVB1"+sized(tm)+be32(0xffffffff)+td,
                                      full,b"EVB1"+bytes(CAP-4))]
    return cases


def genuine_original(work):
    path = Path(os.environ[ENV]).absolute()
    rust, graph, bound = dependency_graph(path)
    original = VERSION.read_bytes()
    if sha(original) != VERSION_SOURCE:
        raise ValueError("original TCV1 source changed")
    start = original.index(b"    pub fn validate(&self) -> CellResultV1<()> {")
    body = original.index(b"        self.model.validate()?;", start)
    after = original.index(b"        require(\n            !self.manifests.is_empty()", body)
    prefix = original[body:after]
    assert prefix.endswith(b"        )?;\n")
    base = source(with_model_root=True)
    assert base.endswith(b'include!("model_root_observation.rs");\n')
    base = base.removesuffix(b'include!("model_root_observation.rs");\n')
    root_diag = Path(__file__).with_name("rust_cell_model_root_reference.rs").read_bytes().split(
        b"\nfn model_root_status(",1
    )[1]
    observer = Path(__file__).with_name("rust_cell_closure_reference.rs").read_bytes()
    (work / "closure_observation.rs").write_bytes(observer)
    constants = b"".join(pick(original,pattern) for pattern in (
        rb"^pub const MAX_CELL_VERSION_BYTES_V1:[^\n]+;\n",
        rb"^pub const MAX_CELL_VERSION_MANIFESTS_V1:[^\n]+;\n",
        rb"^pub type CellVersionCommitmentV1 = [^\n]+;\n",
    ))
    definition = original[original.index(b"/// TCV1 includes"):
                          original.index(b"/// Independent owner pins")]
    methods = original[original.index(b"impl CellVersionManifestV1 {"):
                       original.index(b"    pub fn verify_for_loader(")]
    codecs = original[original.index(b"    pub fn encode("):
                      original.index(b"    /// Re-read every declared manifest")]
    input_helper = original[original.index(b"struct VersionInput<'a>"):
                            original.index(b"#[cfg(test)]")]
    adapter = ORACLE.read_bytes()
    raw = (base + b"\nuse sha2::{Digest,Sha512};\nuse std::collections::BTreeSet;\n"
           b"use model_root::CellModelReleaseRootV1;\n" + constants + definition
           + methods + codecs + b"}\n" + input_helper
           + b"impl CellVersionManifestV1 {\n    fn declared_environment(&self) -> CellResultV1<()> {\n"
           + prefix + b"        Ok(())\n    }\n}\n\nfn model_root_status(" + root_diag + adapter)
    shell, binary = work / "original.rs", work / "original"
    shell.write_bytes(raw)
    run = subprocess.run(["rustc","--edition=2024","-Dwarnings","-L",f"dependency={path.parent}",
                          "--extern",f"sha2={path}",shell,"-o",binary],
                         capture_output=True, timeout=45)
    if run.returncode:
        raise ValueError(run.stderr.decode()[:4096])
    if any(sha(regular(p)) != expected for p, expected in bound.items()):
        raise ValueError("locked oracle library changed during build")
    return binary, {
        "rustc": rust, "locked_graph": graph, "cargo_lock_sha256": sha(LOCK.read_bytes()),
        "original_version_source_sha256": sha(original), "declared_prefix_sha256": sha(prefix),
        "original_manifest_source_sha256": sha(CODEC.read_bytes()),
        "original_model_source_sha256": sha(MODEL_ROOT.read_bytes()),
        "original_closure_source_sha256": sha(CLOSURE.read_bytes()),
        "oracle_source_sha256": sha(raw), "oracle_sha256": sha(binary.read_bytes()),
    }


def full_original_controls():
    good, model, env, manifests, vector = version_fixture()
    def packet(a,b,cells):
        return b"TCV1"+sized(a)+sized(b)+struct.pack(">H",len(cells))+b"".join(map(sized,cells))
    ne = make_environment(roles=(6,2))
    return [
        (good,0,bytes.fromhex(vector["commitment_sha512"])),
        (packet(model,env,manifests[:-1]),86,b""),
        (packet(model,env,manifests[::-1]),89,b""),
        (packet(make_model(ident(57)),ne,manifests[:-1]),84,b""),
        (packet(make_model(env_id(ne)),ne,manifests[:-1]),85,b""),
        (packet(make_model(env_id(ne)),ne,manifests)+b".",88,b""),
        (packet(model,env,[]),87,b""),
    ]


class CellVersionEnvironment(NativeManifestChecks, unittest.TestCase):
    source = SRC

    def panel(self, rows):
        for backend,module in self.modules.items():
            for i,(data,code,payload,out_n,work_n) in enumerate(rows):
                with self.subTest(backend=backend,case=i):
                    out,work = MARK*out_n,SCRATCH*work_n
                    got = module.call("f0",[data,out,work],timeout=35).require_returned()
                    self.assertEqual((got.value,got.arguments[0]),(code,data))
                    self.assertEqual(got.arguments[1],payload+out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                    if code in (100,102) and work_n < WORK:
                        self.assertEqual(got.arguments[2],work)

    def test_capacity_and_ordinary_original_geometry(self):
        rows = fixtures()
        self.panel([(data,code,payload,43,WORK+8) for data,code,payload in rows])
        good = rows[0][0]
        self.panel([(good,102,b"",31,WORK),(good,102,b"",32,WORK-1),
                    (b"EVB1"+bytes(8),2,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV),"requires verified locked real Rust SHA-256/SHA-512 oracle")
    def test_genuine_original_prefix_and_full_constructor_controls(self):
        tested = fixtures()
        full = full_original_controls()
        cases = [(0,*x) for x in tested]+[(1,*x) for x in full]
        with tempfile.TemporaryDirectory(prefix="trnm-evb1-") as d:
            binary, proof = genuine_original(Path(d))
            request = b"".join(bytes([mode])+struct.pack("<I",len(data))+data
                               for mode,data,_,_ in cases)
            run = subprocess.run([binary],input=request,capture_output=True,check=True,timeout=35)
        self.assertEqual(proof["original_version_source_sha256"],VERSION_SOURCE)
        self.assertEqual(run.stderr,b"")
        self.assertEqual(run.stdout,b"".join(bytes([code])+payload for _,_,code,payload in cases))
        at = 0
        observed = []
        for data,_,_ in tested:
            code = run.stdout[at]
            next_at = at+1+(0 if code else 32)
            observed.append((data,code,run.stdout[at+1:next_at],39,WORK))
            at = next_at
        self.panel(observed)
