"""Read-only original RS46 manifest equality and indexed metadata, without payload."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.tests.cell_manifest_original import ENV, build
from hia.tests.test_cell_manifest import (
    CHUNK, MARK, MAX_CELL, MAX_CHUNK, MAX_ROWS, SCRATCH, SRC, WORK,
    NativeManifestChecks, change, result, wire,
)

SOURCE = SRC.with_name("cell_manifest_binding.hepta")


def request(manifest, index, *, expected=None, identity=None):
    if expected is None:
        expected = manifest[4:5+manifest[4]+160]
    if identity is None:
        identity = result(manifest)[:32]
    return b"TCB1"+struct.pack("<I",index)+identity+expected+manifest


def context(family, digests):
    if len(digests) != 160:
        raise ValueError("expected all five opaque context digests")
    return bytes([len(family)])+family+digests


def observed(data, index):
    row = 213+data[4]+36*index
    declared = struct.unpack_from(">I",data,row)[0]
    return result(data)[:32]+struct.pack("<II",index,declared)+data[row+4:row+36]


def cases():
    family = b"Cell-v1.1_x"
    base = wire(family,2*CHUNK+17,opaque=True)
    digests = bytes(range(160))
    base = change(base,5+len(family),digests)
    expected = context(family,digests)
    good_id = result(base)[:32]
    wrong_id = bytes([good_id[0]^1])+good_id[1:]
    rows = [(request(base,index),0,observed(base,index)) for index in (0,1,2)]
    rows += [(request(base,index),13,b"") for index in (3,16383,2**32-1)]
    rows += [(request(base,index,identity=wrong_id),15,b"") for index in (0,3,2**32-1)]
    for offset in (0,7,8,15,16,23,24,31):
        claimed = change(good_id,offset,bytes([good_id[offset]^0x80]))
        rows.append((request(base,1,identity=claimed),15,b""))
    for family_other in (b"",b"cell-v1.1_x",b"Cell-v1.1_xy",b"Cell-v1.1_",b"A"*255,
                         "é".encode("utf-8"),b"\0"):
        other = context(family_other,digests)
        rows.append((request(base,0,expected=other),14,b""))
        rows.append((request(base,2**32-1,expected=other,identity=wrong_id),14,b""))
    for offset in (0,31,32,63,64,95,96,127,128,159):
        changed = change(digests,offset,bytes([digests[offset]^0x80]))
        rows.append((request(base,2,expected=context(family,changed)),14,b""))
    # A changed but well-formed model-byte declaration leaves context intact;
    # an opaque caller ID cannot substitute for the computed original digest.
    changed = change(base,len(base)-1,bytes([base[-1]^0x80]))
    rows.append((request(changed,2,identity=good_id),15,b""))
    rows.append((request(changed,2),0,observed(changed,2)))
    # A bad last row outranks apparently matching pins and any index, just as
    # full original decode precedes the unchanged binding methods.
    broken = change(base,len(base)-36,bytes(4))
    rows += [(request(broken,0),12,b""),
             (request(broken,2**32-1,expected=context(b"Wrong",digests),identity=wrong_id),12,b""),
             (request(base[:-1],0,expected=context(b"Wrong",digests),identity=wrong_id),7,b""),
             (request(b"TCM1\x01\xff",0,expected=expected,identity=wrong_id),5,b"")]
    zero = wire(b"z",1)
    rows.append((request(zero,0),0,observed(zero,0)))
    full = wire(b"A"*64,MAX_CELL-1,MAX_CHUNK)
    rows += [(request(full,MAX_ROWS-1),0,observed(full,MAX_ROWS-1)),
             (request(full,MAX_ROWS),13,b""),
             (request(full,MAX_ROWS,identity=bytes(32)),15,b"")]
    return rows


class CellManifestBinding(NativeManifestChecks, unittest.TestCase):
    source = SOURCE

    def emitted_bound(self, panel):
        for name, module in self.modules.items():
            for index, (data, code, payload, out_n, scratch_n) in enumerate(panel):
                with self.subTest(backend=name, index=index):
                    out = MARK*out_n
                    scratch = SCRATCH*scratch_n
                    got = module.call("f0",[data,out,scratch],timeout=35).require_returned()
                    self.assertEqual(got.value,code)
                    self.assertEqual(got.arguments[0],data)
                    self.assertEqual(got.arguments[1],payload+out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])
                    if code in (2,5,7,12,14,100) or scratch_n < WORK:
                        self.assertEqual(got.arguments[2],scratch)

    def test_native_equality_and_index_projection(self):
        self.emitted_bound([(data,code,out,81,WORK+9) for data,code,out in cases()])

    def test_exact_abi_and_no_output_on_late_refusal(self):
        data, _, value = cases()[0]
        wrong_context = request(wire(b"e",1),0,expected=context(b"f",bytes(160)))
        bad_id = request(wire(b"e",1),2**32-1,identity=bytes(32))
        invalid_family = request(wire(b"e",1),0,expected=context(b"\xff",bytes(160)))
        self.emitted_bound([(data,0,value,72,WORK),(data,102,b"",71,WORK),
            (data,102,b"",72,WORK-1),(data[:200],100,b"",0,0),
            (b"BAD1"+data[4:],100,b"",0,0),(invalid_family,100,b"",0,0),
            (change(data[:201],40,b"\xff"),100,b"",0,0),
            (wrong_context,14,b"",0,0),(bad_id,15,b"",0,WORK)])

    @unittest.skipUnless(os.environ.get(ENV), "requires verified genuine original Rust SHA-256 oracle")
    def test_exact_unchanged_rust_binding_and_first_refusal(self):
        rows = cases()
        query = b"".join(struct.pack("<I",len(data))+data for data,_,_ in rows)
        with tempfile.TemporaryDirectory(prefix="trnm-tcb1-") as d:
            binary, proof = build(Path(d))
            run = subprocess.run([binary,"--binding"],input=query,check=True,capture_output=True,timeout=45)
        self.assertEqual(run.stderr,b"")
        self.assertEqual(proof["mode"],"verified-prebuilt-original-sha2")
        self.assertEqual(run.stdout,b"".join(bytes([code])+value for _,code,value in rows))
        at = 0
        observed_rows = []
        for data, code, _ in rows:
            after = at+1 if code else at+73
            observed_rows.append((data,run.stdout[at],run.stdout[at+1:after],81,WORK+9))
            at = after
        self.emitted_bound(observed_rows)
