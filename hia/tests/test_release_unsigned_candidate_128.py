"""Actual original pre-signature status and byte parity at 0..128 private slots."""
from dataclasses import replace as change
import struct
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_unsigned_candidate import (
    ARTIFACT, BUILD_INPUT, HEAD, MISSING, OUT, PACKAGE, ROOT,
    SOURCE as LEGACY, WORK as LEGACY_WORK, ZERO, byte_digest,
    case, original, replace,
)

SOURCE=ROOT/"hia/src/release_bundle/unsigned_candidate_128.hepta"
WORK=16544


def rosters(n):
    art=[replace(ARTIFACT,0,b"a"*508+f"{i:04}".encode()) for i in range(n)]
    sbom=[replace(PACKAGE,0,b"p"*508+f"{i:04}".encode()) for i in range(n)]
    inp=[replace(BUILD_INPUT,0,b"b"*508+f"{i:04}".encode()) for i in range(n)]
    return art[::-1],sbom[::-1],inp[::-1]


def large(n, **kw):
    a,s,p=rosters(n)
    fields=dict(artifacts=a,packages=s,required=[row[:2] for row in s[::-1]],inputs=p)
    fields.update(kw)
    return case(**fields)


class ReleaseUnsignedCandidate128(unittest.TestCase):
    def test_actual_original_boundary_and_precedence_with_dual_native(self):
        a,s,inp=rosters(128)
        req=[x[:2] for x in s]
        no_src=change(HEAD,source=HEAD.source[:-1]+b"\1")
        invalid_art=replace(a[-1],2,0)
        invalid_sbom=replace(s[-1],4,b"")
        invalid_input=replace(inp[-1],2,ZERO)
        same_input=replace(inp[0],2,byte_digest(101))
        rows=[
            case(), large(64),large(65),large(97),large(127),large(128),
            large(128,artifacts=a[::-1],packages=s[::-1],required=req,inputs=inp[::-1]),
            large(128,header=change(no_src,signature_label=ZERO),status=110,footprint="none"),
            large(128,header=no_src,artifacts=a[:-1]+[invalid_art],status=101,footprint="none"),
            large(128,artifacts=a[:-1]+[invalid_art],packages=s[:-1]+[invalid_sbom],status=106,footprint="none"),
            large(128,artifacts=a[:-1]+[a[0]],packages=s[:-1]+[invalid_sbom],status=107,footprint="none"),
            large(128,packages=s[:-1]+[invalid_sbom],required=req[:-1]+[MISSING],status=116,footprint="none"),
            large(128,packages=s[:-1]+[s[0]],required=req[:-1]+[MISSING],status=117,footprint="none"),
            large(128,required=req[:-1]+[MISSING],inputs=inp[:-1]+[invalid_input],status=108,footprint="none"),
            large(128,inputs=inp[:-1]+[invalid_input],prov_claim=ZERO,status=105,footprint="provenance"),
            large(128,inputs=inp[:-1]+[invalid_input],override_fixed=(4,byte_digest(204)),status=126,footprint="provenance"),
            large(128,inputs=inp[:-1]+[same_input],override_fixed=(5,byte_digest(204)),status=127,footprint="provenance"),
            large(128,override_fixed=(6,byte_digest(204)),status=104,footprint="links"),
            large(128,bundle_claim=ZERO,status=104,footprint="links"),
        ]
        expected=[(row[1],row[2]) for row in rows]
        self.assertEqual(original(rows),expected)
        self.assertEqual(len(rows[5][0]),459373)
        self.assertEqual(rows[5][2],rows[6][2])
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native, NativeModule(LEGACY,backend=backend,byte_exports=("f0",)) as old:
                sentinel,work=b"O"*(OUT+9),b"W"*(WORK+7)
                for packet,status,digest,footprint,_ in rows:
                    args=[packet,sentinel,work]
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments[:2]),
                                     (status,[packet,digest+sentinel[len(digest):]]))
                    self.assertEqual(got.arguments[2][WORK:],work[WORK:])
                    if footprint=="none":
                        self.assertEqual(got.arguments,args)
                for i in (0,1,2):
                    packet=rows[i][0]
                    args=[packet,sentinel,work[:LEGACY_WORK]]
                    got=old.call("f0",args).require_returned()
                    self.assertEqual(got.value,0 if i<2 else 100)
                    if i==2:
                        self.assertEqual(got.arguments,args)
                    else:
                        self.assertEqual(got.arguments[1],rows[i][2]+sentinel[OUT:])

    def test_exact_large_extent_controls_and_original_order(self):
        full=large(128)[0]
        malformed=[
            large(129)[0], full[:-1], full+b"x",
            full[:4]+struct.pack("<H",129)+full[6:],
            full[:298]+b"\xff"+full[299:],
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE,backend=backend,byte_exports=("f0",),
            ) as native:
                out,work=b"O"*OUT,b"W"*WORK
                cases=[([x,out,work],100) for x in malformed]+[
                    ([full,out[:-1],work],102),([full,out,work[:-1]],102),
                    ([large(128,required=[MISSING])[0],b"",b""],108),
                ]
                for args,status in cases:
                    got=native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(status,args))
