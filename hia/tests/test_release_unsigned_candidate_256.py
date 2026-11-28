"""Private 256-slot original pre-signature and bounded membership controls."""
from dataclasses import replace as change
import struct
import time
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_unsigned_candidate_128 import SOURCE as OLD, WORK, large, rosters
from hia.tests.test_release_unsigned_candidate import (
    HEAD, MISSING, OUT, ROOT, ZERO, byte_digest, original, replace,
)

SOURCE=ROOT/"hia/src/release_bundle/unsigned_candidate_256.hepta"


class ReleaseUnsignedCandidate256(unittest.TestCase):
    def test_actual_original_full_frame_and_indexed_membership_precedence(self):
        a,s,p=rosters(256)
        keys=[r[:2] for r in s]
        # Exercise strict required-key ordering on equal names and unequal
        # versions without an artificial key fixture or a second digest.
        first=s[0]
        versioned=replace(first,1,b"v99")
        multi=[first,versioned]+s[2:]
        mk=[r[:2] for r in multi]
        bad_a=replace(a[-1],2,0)
        bad_s=replace(s[-1],4,b"")
        bad_p=replace(p[-1],2,ZERO)
        also_bad_duplicate_a=replace(a[0],2,0)
        also_bad_duplicate_s=replace(s[0],4,b"")
        also_bad_duplicate_p=replace(p[0],2,ZERO)
        rows=[
            large(128),large(129),large(191),large(255),large(256),
            large(256,artifacts=a[::-1],packages=s[::-1],required=keys[::-1],inputs=p[::-1]),
            large(256,packages=multi,required=mk[::-1]),
            large(256,header=change(HEAD,signature_label=ZERO),status=110),
            large(256,header=change(HEAD,source=HEAD.source[:-1]+b"\1"),status=101),
            large(256,artifacts=a[:-1]+[also_bad_duplicate_a],status=106),
            large(256,artifacts=[a[0],a[0]]+a[2:-1]+[bad_a],status=107),
            large(256,packages=s[:-1]+[also_bad_duplicate_s],status=116),
            large(256,packages=[s[0],s[0]]+s[2:-1]+[bad_s],status=117),
            large(256,packages=multi,required=mk[:-1]+[(first[0],b"v98")],status=108),
            large(256,required=keys[:-1]+[MISSING],inputs=p[:-1]+[bad_p],status=108),
            large(256,inputs=p[:-1]+[bad_p],prov_claim=ZERO,status=105),
            large(256,inputs=p[:-1]+[also_bad_duplicate_p],status=126),
            large(256,inputs=[p[0],replace(p[0],2,byte_digest(100))]+p[2:-1]+[bad_p],status=127),
            large(256,override_fixed=(6,byte_digest(204)),status=104),
            large(256,bundle_claim=ZERO,status=104),
        ]
        self.assertEqual(len(rows[4][0]),917357)
        self.assertEqual(rows[4][2],rows[5][2])
        self.assertNotEqual(rows[4][2],rows[6][2])
        self.assertEqual(original(rows),[(row[1],row[2]) for row in rows])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native, NativeModule(OLD,backend=backend,byte_exports=("f0",)) as old:
                out,work=b"U"*(OUT+7),b"J"*(WORK+7)
                bounds=[]
                for i,(inp,status,result,_,_) in enumerate(rows):
                    t0=time.perf_counter()
                    data=native.call("f0",[inp,out,work]).require_returned()
                    if i in (4,5,6):
                        bounds.append(time.perf_counter()-t0)
                    self.assertEqual((data.value,data.arguments[:2]),
                                     (status,[inp,result+out[len(result):]]))
                    self.assertEqual(data.arguments[2][WORK:],work[WORK:])
                # Observation includes serialization and subprocess overhead;
                # this is intentionally not a production deadline assertion.
                print(f"Private exact max native fixture {backend} max wall seconds: {max(bounds):.6f}")
                for i in (0,1):
                    inp=rows[i][0]
                    args=[inp,out,work]
                    data=old.call("f0",args).require_returned()
                    self.assertEqual(data.value,0 if i==0 else 100)
                    if i==1:
                        self.assertEqual(data.arguments,args)
                    else:
                        self.assertEqual(data.arguments[1],rows[i][2]+out[OUT:])

    def test_max_wire_refusal_and_private_capacities(self):
        inp=large(256)[0]
        invalid=[large(257)[0],inp[:-1],inp+b"x",
                 inp[:6]+struct.pack("<H",257)+inp[8:],
                 inp[:298]+b"\xff"+inp[299:]]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native:
                out,work=b"O"*OUT,b"W"*WORK
                for data in invalid:
                    args=[data,out,work]
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(100,args))
                args=[inp,out,work[:-1]]
                got=native.call("f0",args).require_returned()
                self.assertEqual((got.value,got.arguments),(102,args))
                args=[inp,out[:-1],work]
                got=native.call("f0",args).require_returned()
                self.assertEqual((got.value,got.arguments[:2]),(102,args[:2]))
