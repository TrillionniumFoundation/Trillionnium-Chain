"""Actual unchanged bounded ancestry SELECT/fold versus both stock images."""
from pathlib import Path
from hashlib import sha256
import json
import os
import struct
import tempfile
import unittest
from functools import lru_cache

from hia.tests.history_page_fold_original import original
from hia.tests.native_support import NativeModule

SOURCE=Path(__file__).resolve().parents[1]/"src/node/history_page_fold.hepta"
O=b"\xb9"
W=b"\x71"


def sha(raw):
    return sha256(raw).hexdigest()


@lru_cache(maxsize=1)
def cases():
    with tempfile.TemporaryDirectory(prefix="trnm-held-history-page-") as d:
        stream,pins=original(Path(d))
    at=0
    out=[]
    while at<len(stream):
        dn,kn,status,rn,ln=struct.unpack_from("<5Q",stream,at)
        at+=40
        name=stream[at:at+dn].decode()
        at+=dn
        frame=stream[at:at+kn]
        at+=kn
        report=stream[at:at+rn]
        at+=rn
        local=stream[at:at+ln]
        at+=ln
        out.append((name,frame,status,report,local))
    assert at==len(stream)
    if path:=os.environ.get("HIA_HISTORY_HELD_PAGE_ORIGINAL_PROOF"):
        Path(path).write_text(json.dumps(dict(pins=pins,observation_sha=sha(stream),observation_bytes=len(stream),
          actual=[[name,len(f),sha(f),status,len(o),sha(o),list(struct.unpack_from("<4Q",l)),sha(l)]
                  for name,f,status,o,l in out]),indent=2,sort_keys=True)+"\n")
    return out


class HistoryHeldPageFold(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.machines={x:cls.enterClassContext(NativeModule(SOURCE,backend=x,byte_exports=("f0",)))
                      for x in ("direct","selfhost")}
        if len({m.artifact_sha256 for m in cls.machines.values()})!=2:
            raise ValueError("Both exact physical stock backends required")

    def same(self,m,f,status,report=b"",*,o=591,w=521):
        got=m.call("f0",[f,O*o,W*w]).require_returned()
        self.assertEqual((got.abi_status,got.value,got.arguments[:2]),
                         (0,status,[f,report+O*(o-len(report))]))
        self.assertEqual(got.arguments[2][512:],W*max(0,w-512))
        return got.arguments[2]

    def test_frozen_recursive_select_and_queue_matches_both_stock_artifacts(self):
        got=cases()
        self.assertEqual([k for _,_,k,_,_ in got],
          [40,40,40,0,0,0,0,0,0,0,41,41,42,42,12,30,53,54,31,0])
        idx={name:(f,k,o,local) for name,f,k,o,local in got}
        f,k,o,local=idx["full-batch-continuation"]
        self.assertEqual((k,struct.unpack_from("<Q",o)[0],struct.unpack_from("<Q",o,8)[0]),(0,64,11))
        self.assertEqual(struct.unpack_from("<4Q",o,40),(16,1,64,16))
        self.assertEqual(struct.unpack_from("<Q",o,72)[0],27)
        self.assertEqual(struct.unpack_from("<Q",o,72+15*32)[0],12)
        self.assertEqual(struct.unpack_from("<4Q",idx["missing-late"][3]),(1,2,2,2))
        self.assertEqual(struct.unpack_from("<4Q",idx["height-after-one"][3]),(1,1,1,1))
        self.assertEqual(struct.unpack_from("<4Q",idx["unknown-first"][3]),(1,0,0,0))
        for role,m in self.machines.items():
            for name,f,k,expected,local in got:
                with self.subTest(case=name,backend=role):
                    exact=name=="full-batch-continuation"
                    arena=self.same(m,f,k,expected,o=584 if exact else 591,w=512 if exact else 521)
                    if k==0:
                        self.assertEqual(arena[:len(expected)-72],expected[72:])
                    elif name in ("missing-late","height-after-one"):
                        # Original's operation-local queue mutations match the
                        # corresponding private prefix; no output is published.
                        self.assertEqual(arena[:len(local)-32],local[32:])

    def test_private_wire_guards_and_physical_sizes_are_atomic(self):
        all_rows={name:(f,k,o) for name,f,k,o,_ in cases()}
        f,_,out=all_rows["full-batch-stop-edge"]
        small,_,sm_out=all_rows["single-to-genesis"]
        def replace(packet,at,n):
            return packet[:at]+struct.pack("<Q",n)+packet[at+8:]
        second_data=128+64
        for role,m in self.machines.items():
            with self.subTest(backend=role):
                self.assertEqual(self.same(m,f[:127],100),W*521)
                self.assertEqual(self.same(m,replace(f,8,65),100),W*521)
                self.assertEqual(self.same(m,replace(f,16,0),100),W*521)
                self.assertEqual(self.same(m,replace(f,24,17),100),W*521)
                self.same(m,replace(small,second_data+32,1),42)
                self.same(m,replace(small,second_data,190),42)
                self.same(m,small[:64]+small[32:64]+small[96:],100)
                self.same(m,replace(small,128+48,16457),100)
                self.same(m,f+b"!",100)
                self.same(m,small[:-1],100)
                self.assertEqual(self.same(m,f,102,o=len(out),w=511),W*511)
                self.same(m,f,102,o=len(out)-1,w=512)
                self.same(m,small,0,sm_out,o=len(sm_out),w=512)
