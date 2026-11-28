"""Exact stock Cell source preprocessing versus the immutable original module."""
from functools import lru_cache
from pathlib import Path
from hashlib import sha256
import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import cell_held_rows_original as oracle
from hia.tests.native_support import NativeModule

HERE=Path(__file__).parent
SOURCE=HERE.parent/"src/model/cell_source_prepare.hepta"
HARNESS=HERE/"rust_cell_source_prepare_reference.rs"
FROZEN=oracle.NODE/"cell_native_v1/source.rs"
FROZEN_SHA="8c27cdadece9f1f9c26bd20869a74318bb7490aea436e6dc0140684c20cf6c3e"
BASE=4160
ARENA=19712
CANARY=b"\x9b"
WORK=b"\x74"


def pack(hexed,disabled=()):
    mask=bytearray(b"\x01"*257)
    for x in disabled:
        mask[x]=0
    return b"CSP00001"+mask+hexed


def raw(data,disabled=()):
    return pack(data.hex().encode(),disabled)


def fixtures():
    return [
        ("minimum",raw(b"a")),
        ("all-gap",raw(b"\t\x0b\r\n\x0c ")),
        ("fold",raw(b" \tA_91   _BB\r7c  9 \x00 z\x0b ")),
        ("non-ascii-delim",raw("aÉX\u00a0Z\U0001f33fX \u2028é".encode())),
        ("utf8-scalar-edges",raw("\u007f\u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff".encode())),
        ("excluded",raw(b"TRNMx Trnm m00 M04 m10 m100 m04x _trnm xtrnm")),
        ("digits-start",raw(b"1a9 _2 00 t_6 11 2TRNM2 m4 a/b-c+d")),
        ("sign-and-mask",raw(b"a "*40+b"B "*40,(62,202))),
        ("late-clipping",raw(b"a "*20+b"n472 "*13)),
        ("mask-all-nonbias",raw(b"B a safe",range(256))),
        ("after-quota",raw(b"trnm m00 "+b"a "*1024+b"b q trnm m10")),
        ("long-token",raw(b"A"*4096)),
        ("full-separators",raw(b"_!"*2048)),
        ("empty",pack(b"")),
        ("odd",pack(b"a")),
        ("over-max",raw(b"x"*4097)),
        ("uppercase",pack(b"4A")),
        ("nonhex",pack(b"xy")),
        ("hex-before-utf8",pack(b"ffg0")),
        ("truncated-utf8",raw(b"okay\xf0\x9f\x8c")),
        ("stray-continuation",raw(b"a\x80")),
        ("overlong",raw(b"\xc0\xaf")),
        ("surrogate",raw(b"\xed\xa0\x80")),
        ("above-scalar",raw(b"\xf4\x90\x80\x80")),
        ("late-utf8",raw((b"a "*1024)+b"\xff")),
        *[(f"padding-{n}",raw(b"Q"*n,(17,200))) for n in (55,56,63,64,65,127,128,129)],
    ]


@lru_cache(maxsize=1)
def original():
    original_source=oracle.execute_source
    def closure(harness=None):
        # Same exact typed declarations/helpers and frozen locked package
        # checks as the existing execution witness. Replace only the reduced
        # source declaration used there with the full unchanged source module.
        out=original_source(HARNESS.read_bytes() if harness is None else harness)
        real=FROZEN.read_bytes()
        if sha256(real).hexdigest()!=FROZEN_SHA:
            raise ValueError("Frozen original Cell source module changed")
        out["source.rs"]=real
        return out
    cases=fixtures()
    stream=b"".join(struct.pack("<I",len(f))+f for _,f in cases)
    with tempfile.TemporaryDirectory(prefix="trnm-cell-source-prepare-") as d, patch.object(oracle,"execute_source",closure):
        projected,pin=oracle.locked_original(Path(d),stream)
    assert pin["source"]["source.rs"]==FROZEN_SHA
    data=projected
    results=[]
    for name,frame in cases:
        status=data[0]
        data=data[1:]
        if status==0:
            n,=struct.unpack_from("<I",data)
            output=data[4:n+4]
            assert len(output)==n
            data=data[n+4:]
        else:
            assert status in (10,11)
            output=b""
        results.append((name,frame,status,output))
    assert data==b""
    store=os.environ.get("HIA_CELL_SOURCE_ORIGINAL_PROOF")
    if store is not None:
        def s(x): return sha256(x).hexdigest()
        Path(store).write_text(json.dumps(dict(pins=pin,source_bytes=len(FROZEN.read_bytes()),
                observation_bytes=len(projected),observation_sha=s(projected),
                cases=[[name,status,len(inp),s(inp),len(out),s(out)] for name,inp,status,out in results]),
                indent=2,sort_keys=True)+"\n")
    return results


class CellSourcePrepare(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock={role:cls.enterClassContext(NativeModule(SOURCE,backend=role,byte_exports=("f0",)))
                   for role in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.stock.values()})!=2:
            raise ValueError("Both exact stock backends must build physical artifacts")

    def invoke(self,m,frame,code,expected=b"",*,out=None,arena=ARENA+23,unwritten=False):
        if out is None:
            out=len(expected)+19
        value=m.call("f0",[frame,CANARY*out,WORK*arena],timeout=30).require_returned()
        self.assertEqual((value.abi_status,value.value),(0,code))
        self.assertEqual(value.arguments[:2],[frame,expected+CANARY*(out-len(expected))])
        if unwritten:
            self.assertEqual(value.arguments[2],WORK*arena)
        elif arena>=ARENA:
            self.assertEqual(value.arguments[2][ARENA:],WORK*(arena-ARENA))

    def test_original_hex_normalization_hash_counts_and_mask(self):
        obs=original()
        self.assertEqual(len(obs),33)
        lookup={name:(code,r) for name,_,code,r in obs}
        self.assertEqual([lookup[n][0] for n in ("hex-before-utf8","late-utf8")],[10,11])
        self.assertEqual(lookup["all-gap"][1][BASE:],b"")
        self.assertEqual(lookup["fold"][1][BASE:],b"A_91 _BB 7c 9 \x00 z")
        self.assertEqual(struct.unpack_from("<Q",lookup["excluded"][1],8),(4,))
        self.assertEqual(struct.unpack_from("<Q",lookup["after-quota"][1],8),(1024,))
        self.assertEqual(lookup["long-token"][1][BASE:],b"A"*4096)
        self.assertEqual(struct.unpack_from("<Q",lookup["full-separators"][1],8),(1024,))
        self.assertEqual(struct.unpack_from("<q",lookup["late-clipping"][1],48+8*202),(7,))
        self.assertEqual(struct.unpack_from("<257q",lookup["mask-all-nonbias"][1],48+8*257),(0,)*256+(8,))
        r=lookup["sign-and-mask"][1]
        v=struct.unpack_from("<514q",r,48)
        self.assertEqual((v[62],v[202],v[256],v[257+62],v[257+202],v[-1]),(-8,8,8,0,0,8))
        for name,frame,code,expected in obs:
            for role,m in self.stock.items():
                with self.subTest(case=name,backend=role):
                    self.invoke(m,frame,code,expected)

    def test_native_structural_precedence_and_unchanged_public_canaries(self):
        cases={n:(f,r) for n,f,status,r in original() if status==0}
        full,expected=cases["long-token"]
        self.assertEqual((len(full),len(expected)),(8457,8256))
        bad_mask=bytearray(full)
        bad_mask[8]=2
        masked_bias=bytearray(full)
        masked_bias[264]=0
        for role,m in self.stock.items():
            with self.subTest(backend=role):
                self.invoke(m,full[:264],100,unwritten=True)
                self.invoke(m,b"B"+full[1:],100,unwritten=True)
                self.invoke(m,bytes(bad_mask),101,unwritten=True)
                self.invoke(m,bytes(masked_bias),101,unwritten=True)
                self.invoke(m,full,102,out=len(expected),arena=ARENA-1,unwritten=True)
                self.invoke(m,full,102,out=len(expected)-1,arena=ARENA)
                self.invoke(m,raw(b"\xff"),11,out=0,arena=ARENA)
                self.invoke(m,full,0,expected,out=len(expected),arena=ARENA)
