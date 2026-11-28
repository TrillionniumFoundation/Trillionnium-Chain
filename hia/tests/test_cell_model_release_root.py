"""Offline TMR1 declared metadata only; no parents, files or payload are obtained."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import MODEL_ROOT, ENV, build, sha
from hia.tests.test_cell_dependency_closure import WORK, cases as closure_cases, closure, row
from hia.tests.test_cell_manifest import MARK, ROOT, SCRATCH, NativeManifestChecks, change
from hia.tests.test_cell_release_manifest import CAP, ident

SRC = ROOT / "hia/src/data_availability/cell_model_release_root.hepta"
ROSTER_DOMAIN = b"trnm.cell-model-router-roster.v1\0"
ROOT_DOMAIN = b"trnm.cell-model-release-root.v1\0"
MAX_WIRE = CAP+553


def roster(rows):
    fields = []
    for record in rows:
        length, = struct.unpack_from(">H", record)
        end = length+2
        if record[end] == 5:
            fields.append(record[:end] + record[end+1:end+73])
    return hashlib.sha256(ROSTER_DOMAIN+struct.pack(">H",len(fields))+b"".join(fields)).digest()


def wire(inner, declared, lineage=(), *, count=None):
    return (b"TMR1" + struct.pack(">I",len(inner)) + inner + declared
            + bytes([len(lineage) if count is None else count])
            + b"".join(lineage))


def value(data, routers, parents):
    return hashlib.sha256(ROOT_DOMAIN+data).digest()+routers+struct.pack("<I",parents)


def cases():
    ordinary = row(b"Cell.record",1)
    plain = closure(ordinary)
    empty_hash = roster([ordinary])
    empty = wire(plain,empty_hash)
    mixed_rows = [
        row(b"Main.record", 17, role=1, dependencies=(1,2)),
        row(b"Router/Alpha.record", 1, role=5, payload=ident(7), size=257),
        row(b"Router/Beta.record", 12, role=5, payload=ident(2), size=0x10203),
        row(b"Text.record", 9, role=2),
    ]
    alternate_rows = [*mixed_rows[:2],row(b"Router/Beta.record",12,role=5,payload=ident(2),
                                         size=0x10203,dependencies=(3,)),mixed_rows[3]]
    mixed_hash = roster(mixed_rows)
    assert mixed_hash == roster(alternate_rows)
    mixed_td = closure(*mixed_rows,roots=(0,3),cells=(1,9,12,17))
    alt_td = closure(*alternate_rows,roots=(0,),cells=(1,9,12,17))
    parents = tuple(ident(i) for i in (4,0x7f,0x80,0xff,0x100))
    mixed = wire(mixed_td,mixed_hash,parents)
    alt = wire(alt_td,mixed_hash,parents)
    highest = [row(f"Router/File{i:03}.record".encode(),i+1,role=5,
                   payload=ident(i+501),size=1000+i)
               for i in range(256)]
    full_hash = roster(highest)
    full = wire(closure(*highest,roots=range(256),cells=range(1,257)),full_hash,
                tuple(ident(i) for i in range(1,17)))
    one_row = row(b"a"*64+b"/"+b"b"*64+b"/"+b"c"*64+b"/"+b"d"*60,
                  444,role=5,payload=ident(301),size=68719476736)
    one_hash = roster([one_row])
    one = wire(closure(one_row,cells=(444,)),one_hash,(ident(2048),))
    rows = [(data,0,value(data,h,p)) for data,h,p in (
        (empty,empty_hash,0),(mixed,mixed_hash,len(parents)),(alt,mixed_hash,len(parents)),
        (full,full_hash,16),(one,one_hash,1))]
    rows.extend((d,c,b"") for d,c in (
        (b"",2),(b"TMR",2),(b"NONE",52),(b"TMR1",2),(b"TMR1"+bytes(3),2),
        (change(empty,4,struct.pack(">I",CAP+1)),53),(empty[:-1],53),
        (wire(b"",empty_hash),2),(wire(b"TCD1",empty_hash),2),(wire(b"NONE",empty_hash),3),
        (wire(plain,bytes(32)),56),
        (wire(mixed_td,empty_hash),56),
        # BE u16 count and the role-excluded exact wire spans are verified
        # through complete ID, not only status or roster size.
        (wire(mixed_td,roster(list(reversed(mixed_rows))),parents),56),
        (wire(plain,bytes(32),(ident(1),),count=0),54),
        (wire(plain,bytes(32),tuple(ident(i) for i in range(1,18))),54),
        (wire(plain,bytes(32),(bytes(32),)),55),
        (wire(plain,bytes(32),(ident(2),ident(1))),55),
        (wire(plain,bytes(32),(ident(1),ident(1))),55),
        (wire(plain,empty_hash,(bytes(32),ident(1))),55),
        (wire(plain,empty_hash,(ident(1),))[:-1],54),
        (mixed+b".",54),
        # An invalid embedded original has priority over a noncanonical
        # outer parent/empty false roster; no outer fallback is permitted.
        (wire(change(plain,4,bytes(8)),bytes(32),(bytes(32),)),11),
        (wire(change(plain,4,bytes(8)),bytes(32),(bytes(32),),count=0),11),
        (bytes(CAP),52),
    ))
    rows.extend((wire(inner,bytes(32)),status,b"") for inner,status,_ in closure_cases()
                if status and len(inner)+41<=CAP)
    return rows


class CellModelReleaseRoot(NativeManifestChecks, unittest.TestCase):
    source = SRC

    def panel(self, rows):
        for emitter, module in self.modules.items():
            for j,(data,code,payload,out_n,work_n) in enumerate(rows):
                with self.subTest(emitter=emitter,row=j):
                    out, scratch = MARK*out_n, SCRATCH*work_n
                    got = module.call("f0", [data,out,scratch], timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],payload+out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])

    def test_candidate_roster_and_no_early_output(self):
        self.panel([(data,code,payload,79,WORK+5) for data,code,payload in cases()])
        good,_,payload = cases()[0]
        self.panel([
            (good,0,payload,68,WORK),
            (good,102,b"",67,WORK),
            (good,102,b"",68,WORK-1),
            (b"NONE",52,b"",0,0),
            (change(good,len(good)-33,bytes(32)),56,b"",0,WORK),
        ])

    @unittest.skipUnless(os.environ.get(ENV), "requires genuine locked Rust+SHA-256")
    def test_unchanged_rust_original_tmr1_roster_and_outer_identity(self):
        rows = cases()
        over = [(bytes(MAX_WIRE+1),50,b""),(wire(bytes(CAP+1),bytes(32)),53,b"")]
        command = b"".join(struct.pack("<I",len(d))+d for d,_,_ in rows+over)
        with tempfile.TemporaryDirectory(prefix="trnm-tmr1-original-") as d:
            binary,proof = build(Path(d),with_model_root=True)
            observed = subprocess.run([binary],input=command,check=True,
                                      capture_output=True,timeout=55)
        self.assertEqual(proof["original_model_root_source_sha256"],sha(MODEL_ROOT.read_bytes()))
        self.assertEqual(observed.stderr,b"")
        self.assertEqual(observed.stdout,b"".join(bytes([code])+data for _,code,data in rows+over))
        measured = []
        pos = 0
        for data, code, _ in rows:
            stop = pos+(1 if code else 69)
            measured.append((data,observed.stdout[pos],observed.stdout[pos+1:stop],79,WORK+5))
            pos = stop
        self.panel(measured)
