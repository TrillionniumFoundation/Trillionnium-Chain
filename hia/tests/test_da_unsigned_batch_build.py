"""Native one-call full unsigned result versus actual frozen Rust construction."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_da_batch_content_root import (
    domain_hash, frame, independent as content_projection, typed, u32,
)
from hia.tests.test_da_batch_chunk_root import independent as chunk_projection
from hia.tests.test_da_protocol_context import locked_reference

SOURCE = Path(__file__).resolve().parents[1] / "src/data_availability/unsigned_batch_build.hepta"
ADAPTER = Path(__file__).with_name("rust_da_unsigned_batch_build_reference.rs")
WORK, MAXIMUM = 757760, 262144
MARK = b"\xa7"


def observed(raw, count):
    at = 0
    for _ in range(count):
        code, n, m = struct.unpack_from("<BII", raw, at)
        a, b = at+9, at+9+n
        at = b+m
        if at > len(raw) or (code == 0) != bool(m) or not 0 < n <= MAXIMUM+1:
            raise ValueError("Bad original result record")
        yield code, raw[a:b], raw[b:at]
    if at != len(raw):
        raise ValueError("Trailing original result records")


def independent(value, raw, rows, step):
    size, = struct.unpack_from("<I",value)
    env = value[4:4+size]
    b = 4+size
    if value[b:b+32] != domain_hash(b"trnm.portable.v2.da-batch.v1",env):
        raise AssertionError("Batch ID differs")
    b += 32
    total, = struct.unpack_from("<I",value,b)
    contents = value[b+4:b+4+total]
    if contents != frame(rows):
        raise AssertionError("Returned original content differs")
    ce,pe,n = struct.unpack_from("<III",raw,len(raw)-12)
    chain, = struct.unpack_from("<I",raw,36)
    ctx = 2+74+chain
    epoch, = struct.unpack_from("<Q",raw,ctx+1)
    retention, = struct.unpack_from("<I",raw,ce-28)
    if n != total:
        raise AssertionError("Input/output content extent mismatch")
    prefix = (raw[:ctx+9] + domain_hash(b"trnm.portable.v2.da-committee.v1",raw[:ce])
              + raw[ce+pe:len(raw)-12-n])
    chunk = chunk_projection(contents,prefix,step)
    content = content_projection(rows)
    expected = (prefix + b"\0\0" + domain_hash(b"trnm.portable.v2.da-codec.v1",b"\x01\0\0")
                + content[32:] + content[:32] + chunk[:32] + chunk[-4:] + chunk[32:64]
                + struct.pack("<Q",epoch+retention))
    if env != expected:
        raise AssertionError("Complete original envelope differs from independent witness")
    cursor = b+4+total
    if value[cursor:cursor+4] != chunk[-4:]:
        raise AssertionError("Original count does not bind ordered chunks")
    cursor += 4
    for i,off in enumerate(range(0,total,step)):
        payload = contents[off:off+step]
        coord = prefix+chunk[:32]+struct.pack("<IQ",i,len(payload))
        record = (coord + domain_hash(b"trnm.portable.v2.da-chunk-id.v1",coord) + typed(payload)
                  + domain_hash(b"trnm.portable.v2.da-chunk-bytes.v1",typed(payload)))
        if value[cursor:cursor+len(record)] != record:
            raise AssertionError("Complete original chunk differs from independent witness")
        cursor += len(record)
    if cursor != len(value):
        raise AssertionError("Original full chunk list was not consumed")


class DaUnsignedBatchBuild(unittest.TestCase):
    def test_one_call_exact_original_borsh_and_both_native_backends(self):
        std=[b"a",b"b",b"1234"]
        cases=[]

        def add(rows=std, expected=0, *, variant=0, author=0, seq=1,
                step=8, chunks=64, max_bytes=1048576, max_items=64, malformed=None):
            content=frame(rows) if malformed is None else malformed
            request=struct.pack("<BBQIIQI",variant,author,seq,step,chunks,max_bytes,max_items)+content
            cases.append((request,expected,rows,step))

        for size in (1,3,4,6,7,8,9,10,99):
            add(step=size)
        add(std[::-1],step=7)
        add(variant=3,author=1,seq=3,step=7)
        add(author=1,seq=3)
        add(seq=10)
        add([b"M"*240000],step=80000)
        add([bytes([i]) for i in range(32)],step=24)
        add([b"M"*24],step=1,chunks=32)
        above_chunks=len(cases)
        add([b"M"*25],step=1)
        above_items=len(cases)
        add([bytes([i]) for i in range(33)],step=24)
        for tag,code in ((1,215),(2,215),(5,215),(6,216),(7,218),(8,3),(9,217),
                         (10,210),(11,215),(12,212),(13,7)):
            add(expected=code, variant=tag, author=2)
        add(expected=219,author=2,seq=0)
        add(expected=219,author=3)
        add(expected=220,author=0,seq=0)
        add(expected=220,author=1,seq=4)
        add([],40)
        add(expected=40,max_items=2)
        add([b"",b"a"],41)
        add([b"duplicate",b"a",b"duplicate"],41)
        add([b"M"*200],43,max_bytes=100)
        add(expected=42,step=1,chunks=2)
        add(expected=44,variant=4)
        add(expected=42,variant=4,step=1,chunks=2)
        add(expected=100,malformed=u32(1)+u32(6)+b"ab")
        add(expected=3,variant=16)
        add(expected=217,variant=17,seq=0)
        max_frame=len(cases)
        add(variant=14,step=87000)
        over_frame=len(cases)
        add(variant=15,step=87000)

        with tempfile.TemporaryDirectory(prefix="trnm-da-original-unsigned-batch-") as tmp:
            raw=locked_reference(Path(tmp),b"".join(typed(q) for q,_,_,_ in cases),caller=ADAPTER)
        ref=list(observed(raw,len(cases)))
        self.assertEqual([x[0] for x in ref],[x[1] for x in cases])
        self.assertGreater(len(ref[max_frame][2]),520000)
        trials=[]
        for i, ((_,status,rows,step),(code,wire,value)) in enumerate(zip(cases,ref,strict=True)):
            if i in (max_frame,over_frame):
                self.assertEqual(len(wire),MAXIMUM+(i==over_frame))
                n, = struct.unpack_from("<I",wire,len(wire)-4)
                content=wire[-12-n:-12]
                self.assertEqual(content[:8],u32(1)+u32(n-8))
                rows=[content[8:]]
            if status==0:
                independent(value,wire,rows,step)
            if i in (above_chunks,above_items,over_frame):
                code,value=100,b""
            trials.append((wire,code,value,len(value)+9,WORK+7))
        base,_,value,_,_=trials[0]
        trials += [
            (base,0,value,len(value),WORK),
            (base,102,b"",len(value)-1,WORK),
            (base,102,b"",len(value),WORK-1),
            (base[:-12]+u32(0)+base[-8:],100,b"",len(value),WORK),
            (base[:-4]+u32(0),100,b"",len(value),WORK),
        ]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                    SOURCE,byte_exports=("f0",),backend=backend) as native:
                for i in range(0,len(trials),4):
                    sample=trials[i:i+4]
                    calls=native.call_many([("f0",[wire,MARK*out,b"\xc3"*scratch])
                                            for wire,_,_,out,scratch in sample],timeout=60)
                    for j,((wire,code,value,out,scratch),run) in enumerate(zip(sample,calls,strict=True),i):
                        self.assertEqual(run.require_returned().value,code,(backend,j))
                        self.assertEqual(run.arguments[:2],[wire,value+MARK*(out-len(value))],(backend,j))
                        self.assertEqual(run.arguments[2][WORK:],b"\xc3"*max(0,scratch-WORK),(backend,j))
