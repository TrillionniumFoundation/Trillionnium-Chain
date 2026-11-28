"""Offline TCD1/TCM1 declared metadata equality on an immutable private frame."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import CLOSURE, ENV, build, sha
from hia.tests.test_cell_dependency_closure import (
    WORK, cases as closure_cases, closure, row,
)
from hia.tests.test_cell_manifest import (
    CHUNK, DOMAIN as MANIFEST_DOMAIN, MARK, MAX_CELL, MAX_CHUNK, ROOT, SCRATCH,
    NativeManifestChecks, cases as manifest_cases, change, wire,
)
from hia.tests.test_cell_release_manifest import CAP, OPAQUE, ident, release

SRC = ROOT / "hia/src/data_availability/cell_closure_manifest_relation.hepta"
FAMILY = b"Cell.Integration_v1"
PAYLOAD = ident(87342)


def frame(td, tm):
    return td + tm + struct.pack("<I", len(td)) + b"TCX1"


def id_of(tm):
    return hashlib.sha256(MANIFEST_DOMAIN + tm).digest()


def make_manifest(family=FAMILY, context=OPAQUE, payload=PAYLOAD, size=CHUNK+13, chunk_bytes=CHUNK):
    data = wire(family=family, size=size, chunk_bytes=chunk_bytes)
    data = change(data, 5+len(family), context)
    return change(data, 173+len(family), payload)


def selected(tm, path=b"Cell.data", role=6, payload=PAYLOAD, size=CHUNK+13, dependencies=()):
    return row(path, int.from_bytes(id_of(tm), "big"), role=role, payload=payload,
               size=size, dependencies=dependencies)


def plan(tm, index=1, width=2, members=None, context=OPAQUE, family=FAMILY, **kwargs):
    identity = int.from_bytes(id_of(tm), "big")
    entries = [identity if i == index else i+1 for i in range(width)]
    files = [selected(tm, f"cell{i:03}.data".encode(), dependencies=(), **kwargs)
             if i == index else row(f"cell{i:03}.data".encode(), i+1)
             for i in range(width)]
    nested = release(family=family, context=context,
                     cells=[ident(i) for i in sorted(entries if members is None else members)])
    return closure(*files, roots=range(width), nested=nested)


def cases():
    tm = make_manifest()
    td = plan(tm)
    good = frame(td, tm)
    big = make_manifest(family=b"Z"*64, size=MAX_CELL, chunk_bytes=MAX_CHUNK)
    big_plan = plan(big, index=255, width=256, family=b"Z"*64, size=MAX_CELL)
    assert len(big) == 590101
    at = 5+len(FAMILY)
    payload_at = at+168
    wrong_family = make_manifest(family=b"Another.Family")
    wrong_payload = change(tm, payload_at, ident(1))
    short_valid = make_manifest(size=CHUNK)
    all_zero_tm_context = make_manifest(context=bytes(160))
    cases = [
        (good, 0, id_of(tm)),
        (frame(plan(tm, index=0, width=256), tm), 0, id_of(tm)),
        (frame(big_plan, big), 0, id_of(big)),
        (frame(plan(wrong_family, family=b"Another.Family"), wrong_family), 0, id_of(wrong_family)),
        # TCM carries an ordinary valid but unlisted computed ID. Equality
        # inconsistency must not mask the fact that no row was selected.
        (frame(td, wrong_family), 80, b""),
        (frame(td, wrong_payload), 80, b""),
        (frame(td, short_valid), 80, b""),
        (frame(td, all_zero_tm_context), 80, b""),
        (frame(plan(wrong_family), wrong_family), 81, b""),
        (frame(plan(make_manifest(family=b"Cell.Integration_v2")), make_manifest(family=b"Cell.Integration_v2")), 81, b""),
        (frame(plan(wrong_payload), wrong_payload), 81, b""),
        (frame(plan(short_valid), short_valid), 81, b""),
        (frame(plan(all_zero_tm_context), all_zero_tm_context), 81, b""),
        (frame(plan(tm, payload=ident(1)), tm), 81, b""),
        (frame(plan(tm, size=CHUNK), tm), 81, b""),
        (frame(plan(tm, payload=ident(1), size=CHUNK), tm), 81, b""),
        (frame(plan(tm, members=(1, 2)), tm), 25, b""),
        # A valid second row with semantically matching context/payload
        # cannot substitute for the selected first row's different metadata.
        (frame(closure(selected(tm, b"A", payload=ident(1)),
                       row(b"B", 1, payload=PAYLOAD, size=CHUNK+13),
                       roots=(0,1), cells=sorted((1,int.from_bytes(id_of(tm),"big")))), tm), 81, b""),
        (frame(td+b"x", b""), 10, b""),
        (frame(td, b""), 66, b""),
        (b"", 100, b""),
        (good[:-1], 100, b""),
        (good[:-4]+b"TCY1", 100, b""),
        (good[:-8]+struct.pack("<I", (1<<32)-1)+b"TCX1", 100, b""),
    ]
    for position in range(5):
        for byte in (0, 67):
            bad_context = change(OPAQUE,position*32,bytes([byte])*32)
            other = make_manifest(context=bad_context)
            cases += [(frame(td,other),80,b""),(frame(plan(other),other),81,b"")]
    # Include the unchanged surrounding codecs' actual diagnostics in this
    # combined entry, including TCD1's nested TCR1 and deep graph priorities.
    cases += [(frame(invalid, b"TCM"), code, b"") for invalid,code,_ in closure_cases()
              if code and len(invalid)+11 <= CAP]
    cases += [(frame(td, invalid), 64+code, b"") for invalid,code in manifest_cases()
              if code and len(td)+len(invalid)+8 <= CAP]
    return cases


class CellClosureManifestRelation(NativeManifestChecks, unittest.TestCase):
    source = SRC

    def panel(self, rows):
        for emitter, module in self.modules.items():
            for ordinal,(data,code,payload,out_n,work_n) in enumerate(rows):
                with self.subTest(emitter=emitter,row=ordinal):
                    before_out, before_work = MARK*out_n, SCRATCH*work_n
                    got = module.call("f0", [data,before_out,before_work], timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],payload+before_out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:],before_work[WORK:])

    def test_private_atomic_output_and_one_call_relational_cases(self):
        self.panel([(data,code,payload,39,WORK+7) for data,code,payload in cases()])
        tm = make_manifest()
        td = plan(tm)
        self.panel([(frame(td,tm),0,id_of(tm),32,WORK),
                    (frame(td,tm),102,b"",31,WORK),
                    (frame(td,tm),102,b"",32,WORK-1),
                    (frame(td,b""),66,b"",0,WORK),
                    (frame(td,make_manifest(payload=ident(1))),80,b"",0,WORK),
                    (frame(td+b"x",b""),10,b"",0,0)])

    @unittest.skipUnless(os.environ.get(ENV), "requires genuine locked Rust+SHA-256")
    def test_unchanged_rust_original_verify_manifest_and_first_failure(self):
        rows = cases()
        tm = make_manifest()
        td = plan(tm)
        over = [(frame(bytes(CAP+1),b""),1,b""),(frame(td,bytes(CAP+1)),65,b"")]
        command = b"".join(struct.pack("<I",len(data))+data for data,_,_ in rows+over)
        with tempfile.TemporaryDirectory(prefix="trnm-tcx1-original-") as d:
            binary,proof = build(Path(d),with_closure=True)
            observed = subprocess.run([binary,"--relation"],input=command,check=True,
                                      capture_output=True,timeout=55)
        self.assertEqual(proof["original_closure_source_sha256"],sha(CLOSURE.read_bytes()))
        self.assertEqual(observed.stderr,b"")
        self.assertEqual(observed.stdout,b"".join(bytes([code])+payload for _,code,payload in rows+over))
        measured = []
        pos = 0
        for data, code, _ in rows:
            stop = pos+(1 if code else 33)
            measured.append((data,observed.stdout[pos],observed.stdout[pos+1:stop],39,WORK+7))
            pos = stop
        self.panel(measured)
