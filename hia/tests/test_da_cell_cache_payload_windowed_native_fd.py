"""Actual fixed native descriptor transport compared from the same held bytes."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.platform.cell_cache_windowed_native.build import CARRIER, STOCK, build
from hia.tests.cache_payload_held_original import original
from hia.tests.test_cell_manifest import wire
from hia.tests.test_da_cell_cache_payload_held_read import (
    ABSENT, LENGTH, MAX, canonical, copied, data, request,
)
from hia.tests.test_da_cell_cache_payload_windowed import CHUNK, WINDOW
from hia.tests.test_da_cell_cache_payload_windowed_fd import link, observed
from hia.tests.test_worker_audit_sealed_query import check_nonpipe_sink
from hia.tests.test_worker_journal_audit_stdin import ALL_SEALS, SEAL_WRITE

IMAGE = "11a3bee46e93dc7253a14e538743c9a4e0d36d075f9f13b4ee4e9ed549b46b3f"


class DaCellCachePayloadWindowedNativeFd(unittest.TestCase):
    def test_fixed_native_transport_from_same_held_sealed_stream_to_original(self):
        full=data(CHUNK)
        m=canonical([full],width=CHUNK)
        left=WINDOW-1
        cases=[
            (m,full,left,WINDOW,0,copied(left,full[left:left+WINDOW])),
            (m,full,CHUNK-7,MAX,0,copied(CHUNK-7,full[-7:])),
            (m,full[:-1]+bytes([full[-1]^1]),left,32,ABSENT,b""),
            (canonical([full[:-1]],size=CHUNK,width=CHUNK),full[:-1],10,19,LENGTH,b""),
            (m,full[:-1],10,19,ABSENT,b""),
            (m,b"",0,1,ABSENT,b""),
            (m,b"",left,0,0,copied(left,b"")),
            (m,b"",CHUNK,2,0,copied(CHUNK,b"")),
        ]
        with tempfile.TemporaryDirectory(prefix="trnm-fixed-native-cache-window-") as tmp:
            root=Path(tmp)
            img,proof=build(root/"native")
            self.assertEqual((proof["elf"]["sha256"],proof["carrier_sha256"]),(IMAGE,CARRIER))
            self.assertEqual(proof["kernel"]["artifact_sha256"],STOCK[0])
            self.assertEqual(len(proof["carrier_roster"]["sites"]),13)
            prior=root/"prior_rust_transport"
            prior.mkdir()
            old=link(prior)
            inputs=[]
            for manifest,body,pos,want,code,value in cases:
                fixture=request(manifest,body,pos,want)
                result,raw,offset=observed(img,fixture)
                expect=(0 if code==0 else 74,value,len(fixture))
                self.assertEqual((result.returncode,result.stdout,offset),expect)
                reference,other,offset0=observed(old,fixture)
                self.assertEqual((reference.returncode,reference.stdout,offset0),expect)
                self.assertEqual(other,raw)
                inputs.append(struct.pack("<I",len(raw))+raw)
            rust=root/"locked_original"
            rust.mkdir()
            outputs,pin=original(rust,b"".join(inputs))
            self.assertEqual(outputs,b"".join(bytes([code])+value for _,_,_,_,code,value in cases))
            self.assertEqual(len(pin),64)
            tiny=request(m,b"",CHUNK,1)
            for fixture,seals,offset,status,final in (
                (tiny,0,0,70,0),(tiny,ALL_SEALS & ~SEAL_WRITE,0,70,0),
                (tiny,ALL_SEALS,1,72,1),(b"x"*19,ALL_SEALS,0,73,0),
                (request(m,full+b"x",left,WINDOW),ALL_SEALS,0,71,20),
                (b"x"*(CHUNK+WINDOW+1),ALL_SEALS,0,71,0),
                (tiny[:16]+struct.pack("<I",WINDOW)+tiny[20:],ALL_SEALS,0,73,20),
                (request(m,b"",0,WINDOW+1),ALL_SEALS,0,74,len(tiny)),
            ):
                q,raw,at=observed(img,fixture,seals=seals,offset=offset)
                self.assertEqual((q.returncode,q.stdout,at),(status,b"",final))
                self.assertEqual(raw,fixture)
            # Profile-only envelope controls: original logical no-read does not
            # inspect a trailing row, but this fixed transport admits no such row.
            for pos,want in ((left,0),(CHUNK,1)):
                with self.subTest(no_read_trailing=(pos,want)):
                    fixture=request(m,b"inert trailing bytes",pos,want)
                    result,held,at=observed(img,fixture)
                    self.assertEqual((result.returncode,result.stdout,at),(74,b"",len(fixture)))
                    self.assertEqual(held,fixture)
            self.assertEqual(check_nonpipe_sink(img,tiny)["status"],75)

    def test_synthetic_65_row_geometry_at_last_full_row_tail_and_eof(self):
        # Only the aggregate geometry comes from the published declarations.
        # All declared row digests and all bytes exercised here are synthetic.
        tail_start = 64 * CHUNK
        end = tail_start + 625_096
        self.assertEqual(end, 269_060_552)
        names = b"synthetic_geometry"
        full = data(CHUNK)
        tail = bytes(b ^ 0x5a for b in data(end - tail_start))
        entries = [
            hashlib.sha256(b"unmaterialized synthetic row " + bytes([i])).digest()
            for i in range(63)
        ] + [hashlib.sha256(full).digest(), hashlib.sha256(tail).digest()]
        self.assertEqual(len(set(entries)), 65)
        manifest = bytearray(wire(names, end, CHUNK))
        first = 213 + len(names)
        for i, digest in enumerate(entries):
            at = first + i * 36 + 4
            manifest[at:at+32] = digest
        manifest = bytes(manifest)
        self.assertEqual(len(manifest), first + 65 * 36)

        cases = (
            (tail_start-1, WINDOW, full, full[-1:]),
            (tail_start, WINDOW, tail, tail[:WINDOW]),
            (tail_start+WINDOW-1, WINDOW, tail, tail[WINDOW-1:2*WINDOW-1]),
            (end-1, WINDOW, tail, tail[-1:]),
            (end, WINDOW, b"", b""),
        )
        with tempfile.TemporaryDirectory(prefix="trnm-synthetic-tail-cache-window-") as tmp:
            root = Path(tmp)
            image, proof = build(root/"native")
            self.assertEqual((proof["elf"]["sha256"], proof["carrier_sha256"]), (IMAGE, CARRIER))
            self.assertEqual(proof["kernel"]["artifact_sha256"], STOCK[0])
            frames, expected = bytearray(), bytearray()
            for pos, want, body, value in cases:
                with self.subTest(position=pos):
                    frame = request(manifest, body, pos, want)
                    result, held, cursor = observed(image, frame)
                    exact = copied(pos, value)
                    self.assertEqual((result.returncode, result.stdout, cursor), (0, exact, len(frame)))
                    self.assertEqual(held, frame)
                    frames.extend(struct.pack("<I", len(held)))
                    frames.extend(held)
                    expected.extend(b"\0" + exact)
            locked = root/"locked_original"
            locked.mkdir()
            oracle, pin = original(locked, bytes(frames))
            self.assertEqual(oracle, expected)
            self.assertEqual(len(pin), 64)
