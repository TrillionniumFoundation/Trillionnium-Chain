"""Native integer binary64 versus independent hardware round-to-nearest results."""
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import time
import unittest

from hia.tests.native_support import NativeModule

SOURCE = Path(__file__).resolve().parents[1] / 'src/math/binary64.hepta'
SIGN = 1 << 63
MASK = SIGN - 1


def from_bits(x):
    return struct.unpack('<d', struct.pack('<Q', x))[0]


def bits(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def frame(op, a, b=0):
    return b'EXFP0001' + struct.pack('<QQQ', op, a, b)


class Binary64NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        cls.invocations = 0
        cls.native = NativeModule(SOURCE, byte_exports=('f0',))
        cls.addClassCleanup(cls.native.close)

    @classmethod
    def tearDownClass(cls):
        destination = os.environ.get('HIA_BINARY64_OBSERVATIONS')
        if destination:
            Path(destination).write_text(json.dumps({
                'schema':'trnm.hia.binary64-development-observations.v1',
                'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                'artifact_sha256':cls.native.artifact_sha256,
                'build_receipt':cls.native.receipt,
                'native_invocations':cls.invocations,
                'wall_seconds':time.monotonic()-cls.started,
                'complete_signed_ieee754_library':False,
                'decimal_parser_qualified':False,
                'whole_chain_native':False},indent=2)+'\n')

    def check(self, rows):
        original = bytes([0xA7]) * 19
        for start in range(0, len(rows), 512):
            batch = rows[start:start+512]
            results = self.native.call_many([('f0', [frame(op,a,b), original, b'unchanged']) for op,a,b,want in batch])
            type(self).invocations += len(results)
            for row, result in zip(batch, results):
                result.require_returned()
                self.assertEqual(result.value, 0, row)
                self.assertEqual(result.arguments[1][:8], struct.pack('<Q', row[3]), row)
                self.assertEqual(result.arguments[1][8:], original[8:])
                self.assertEqual(result.arguments[2], b'unchanged')

    def test_u64_conversion_and_rounding_boundaries(self):
        rng = random.Random(0xF064)
        values = [0, (1 << 64)-1]
        for exponent in range(64):
            for displacement in (-3,-2,-1,0,1,2,3):
                value = (1 << exponent) + displacement
                if 0 <= value < 1 << 64:
                    values.append(value)
        values += [rng.getrandbits(64) for _ in range(600)]
        self.check([(0, value, 0, bits(float(value))) for value in values])

    def test_add_multiply_divide_full_finite_exponent_and_subnormal_domain(self):
        rng = random.Random(0xB1A64)
        boundary = [0, SIGN, 1,2,3, (1 << 51)-1, 1 << 51, (1 << 52)-1,
                    1 << 52, (1 << 52)+1, (1 << 53)-1, 1 << 53,
                    bits(0.22), bits(0.04), bits(0.0075), bits(0.01),
                    bits(0.5)-1, bits(0.5), bits(0.5)+1, bits(1.0)-1,
                    bits(1.0), bits(1.0)+1, bits(2.0), 0x7fefffffffffffff]
        pairs = [(a,b) for a in boundary for b in boundary]
        for exponent in (0,1,2,511,1022,1023,1024,1535,2045,2046):
            for fraction in (0,1,2,(1 << 51)-1,1 << 51,(1 << 52)-2,(1 << 52)-1):
                a = (exponent << 52) | fraction
                for b in (1, 1 << 52, bits(0.5), bits(1.0)-1, bits(1.0), bits(2.0),0x7fefffffffffffff):
                    pairs.append((a,b))
        for _ in range(2500):
            pairs.append(((rng.randrange(2047) << 52) | rng.getrandbits(52),
                          (rng.randrange(2047) << 52) | rng.getrandbits(52)))
        rows=[]
        for a,b in pairs:
            x,y = from_bits(a),from_bits(b)
            rows.extend(((1,a,b,bits(x+y)),(2,a,b,bits(x*y))))
            if b & MASK:
                rows.append((3,a,b,bits(x/y)))
        self.check(rows)

    def test_refusal_is_atomic_and_no_invalid_float_becomes_input(self):
        cases=[]
        out=b'unchanged-output'
        workspace=b'unchanged-workspace'
        for raw,code in ((b'',1),(frame(9,0),3),(b'badmagic'+frame(1,0)[8:],2),
                         (frame(1,bits(-1.0)),4),(frame(2,0x7ff0000000000000),4),
                         (frame(1,0x7ff8000000000001),4),(frame(3,bits(1.0),0),4),
                         (frame(3,bits(1.0),SIGN),4)):
            cases.append((raw,out,code))
        cases.append((frame(0,123),bytes(7),100))
        results=self.native.call_many([('f0',[raw,output,workspace]) for raw,output,_ in cases])
        type(self).invocations += len(results)
        for (raw,output,code),result in zip(cases,results):
            result.require_returned()
            self.assertEqual(result.value,code)
            self.assertEqual(result.arguments,[raw,output,workspace])


if __name__ == '__main__':
    unittest.main()
