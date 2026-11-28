"""End-to-end immutable original checkpoint/activation to numeric matrix bytes."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_activation_raw import activation, packet as activation_packet
from hia.tests.test_checkpoint_tile_activation_runtime_sequence import ROOT_FIELDS, runtime_array
from hia.tests.test_checkpoint_tile_assemble import packet as tile_fixture
from hia.tests.test_checkpoint_tile_checkpoint_extract import container
from hia.tests.test_checkpoint_tile_quantize import ROOT, original
from hia.tests.test_checkpoint_tile_tensor_header import N, TARGET, encode, record

SOURCE = ROOT / "hia/src/checkpoint/tile_model_numeric.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_model_numeric_reference.rs")
FRAGMENT_SHA = '0e226610ea434e885d3f9d49a65cfd7d281c66d2ae4416f4489ffefe3783079b'


def witness(frozen):
    first = b"    let (tokens, hidden) = activation(activation_raw, ctx, o)?;\n"
    end = b"    let bb = encode_matrix(&b);\n"
    assert frozen.count(first) == 1 and frozen.count(end) == 1
    lo = frozen.index(first)
    hi = frozen.index(end, lo) + len(end)
    body = frozen[lo:hi]
    assert hashlib.sha256(body).hexdigest() == FRAGMENT_SHA
    assert b"derive_observed" not in body and b"pon_work" not in body
    return b"""
pub(super) fn tile_model_numeric_witness(
    activation_raw:&[u8], raw:&[u8], actpin:[u8;32], cppin:[u8;32], cpsz:u64,
) -> MaterialResult<(Vec<u8>,Vec<u8>,usize,usize)> {
    let mut checkpoint=io::Cursor::new(raw);
    let mut callback=|_: MaterialProgress| Ok(());
    let o=&Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    let ctx=&PinnedTileContextV1 {
        network:[1;32],parameters:[2;32],checkpoint_sha256:cppin,checkpoint_bytes:cpsz,
        activation_sha256:actpin,model:[7;32],input:[8;32],
    };
""" + body + b"    Ok((aa,bb,ca,cb))\n}\n"


def checkpoint(piece, *, dtype="BF16", offset=0, pad=0, unselected_bf16=None):
    data = bytearray(N)
    for r in range(64):
        data[r*1152:r*1152+128] = piece[r*128:r*128+128]
    if unselected_bf16 is not None:
        data[-2:] = unselected_bf16
    entries = {TARGET: record(dtype, [576, 576], offset, offset + N)}
    if offset:
        entries["synthetic-byte-prefix"] = record("I8", [offset], 0, offset)
    return container(encode(entries) + b" " * pad, bytes(offset) + data)


def frame(act, cp, pin, *, cplen=None, bad_act_pin=False):
    if cplen is None:
        cplen = len(cp)
    return activation_packet(act, bad_act_pin) + cp + pin + struct.pack("<QQ", cplen, len(act))


def object_fixture(tokens, cp, *, hidden=None):
    v = json.loads(activation(tokens))
    v["checkpoint_sha256"] = hashlib.sha256(cp).hexdigest()
    if hidden is not None:
        v["hidden_hex"] = hidden.hex()
    return v


class CheckpointTileModelNumericTests(unittest.TestCase):
    def test_frozen_original_same_loan_exact_numeric_pair_both_stock(self):
        rows = []

        def emit(status, doc, cp, *, pin=None, **kw):
            if pin is None:
                pin = hashlib.sha256(cp).digest()
            if not isinstance(doc, bytes):
                doc = encode(doc)
            rows.append((status, frame(doc, cp, pin, **kw)))

        for t in (1, 2, 64):
            q = tile_fixture(t)
            cp = checkpoint(q[16:8208], offset=17, unselected_bf16=b"\x80\x7f")
            doc = object_fixture(t, cp, hidden=q[8208:])
            emit(0, doc, cp)
            po = runtime_array(doc)
            emit(0, [po[x] for x in ROOT_FIELDS], cp)
            if t == 64:
                self.assertLess(len(rows[-1][1]), 1 << 20)
                self.assertGreater(len(rows[-1][1]), 950000)

        bits = tile_fixture(2)
        simple = checkpoint(bits[16:8208])
        doc = object_fixture(2, simple, hidden=bits[8208:])
        pin = hashlib.sha256(simple).digest()
        emit(1, {**doc, "dtype": "wrong"}, simple, cplen=0, bad_act_pin=True)
        emit(2, b'{"a":0,"\\u0061":0}', simple, cplen=0)
        emit(4, {**doc, "schema": "wrong"}, simple, cplen=0)
        emit(6, {**doc, "shape": [1, 0, 576]}, simple, cplen=0)
        emit(7, {**doc, "positions": [1, 0]}, simple, cplen=0)
        emit(9, {**doc, "hidden_hex": "00"}, simple, cplen=0)
        emit(21, doc, simple, cplen=0)
        chopped = b"\0" * 7
        emit(32, object_fixture(2, chopped, hidden=bits[8208:]), chopped)
        invalid_prefix = struct.pack("<Q", 1) + b"0"
        emit(33, object_fixture(2, invalid_prefix, hidden=bits[8208:]), invalid_prefix)
        bad_target = checkpoint(bits[16:8208], dtype="I16")
        emit(29, object_fixture(2, bad_target, hidden=bits[8208:]), bad_target)
        mutated_cp = simple[:-1] + bytes([simple[-1] ^ 1])
        emit(34, doc, mutated_cp, pin=pin)
        for lane in (0, 4095):
            q = bytearray(bits[16:8208])
            q[lane*2:lane*2+2] = b"\x81\x7f"
            bad = checkpoint(q)
            emit(15, object_fixture(2, bad, hidden=bits[8208:]), bad)
        for lane in (0, 576 + 575):
            q = bytearray(bits[8208:])
            q[lane*4:lane*4+4] = b"\x01\0\x80\x7f"
            emit(15, object_fixture(2, simple, hidden=q), simple)
        stimulus = b"".join(struct.pack("<I", len(raw)) + raw for _, raw in rows)
        with tempfile.TemporaryDirectory(prefix="checkpoint-tile-model-numeric-") as temp:
            result = original(Path(temp), stimulus, reference=REFERENCE, witness=witness)
        expected = []
        while result:
            code, n = struct.unpack_from("<II", result)
            body = result[8:8+n]
            self.assertEqual(n, len(body))
            expected.append((code, body))
            result = result[8+n:]
        self.assertEqual([c for c, _ in expected], [c for c, _ in rows])
        for i in range(0, 6, 2):
            self.assertEqual(expected[i], expected[i+1])
            self.assertEqual(len(expected[i][1]), 32784)
            self.assertEqual(struct.unpack_from("<Q", expected[i][1])[0], 2048)
        matrix = [(s, raw, body) for (s, raw), (_, body) in zip(rows, expected, strict=True)]
        matrix += [(100, b"TAR1", b""), (100, rows[0][1][:-8] + b"\xff"*8, b"")]
        o, w = b"O" * 32791, b"W" * 500013
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for i in range(0, len(matrix), 2):
                    group = matrix[i:i+2]
                    calls = [("f0", [raw, o, w]) for _, raw, _ in group]
                    for (s, raw, body), q in zip(group, native.call_many(calls), strict=True):
                        got = q.require_returned()
                        self.assertEqual((got.value, got.arguments[:2]),
                                         (s, [raw, body + o[len(body):]]))
                        self.assertEqual(got.arguments[2][500000:], w[500000:])
                for out, scratch in ((o[:32783], w), (o, w[:499999])):
                    args = [rows[0][1], out, scratch]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (102, args))
