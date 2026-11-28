"""Synthetic same-loan byte replay and exact original detached hash checks."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_activation_runtime_sequence import ROOT_FIELDS, runtime_array
from hia.tests.test_checkpoint_tile_assemble import packet as tile_fixture
from hia.tests.test_checkpoint_tile_model_numeric import checkpoint, frame, object_fixture, witness as numeric_witness
from hia.tests.test_checkpoint_tile_quantize import ROOT, original
from hia.tests.test_checkpoint_tile_tensor_header import encode

SOURCE = ROOT / "hia/src/checkpoint/tile_model_binding.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_model_binding_reference.rs")
FRAGMENT = "7ca1dc60bf27b02236f187cf17f2aa5283f01550a524a5dcc7f20a2c5b3d6f2f"


def witness(frozen):
    first = b"    let (tokens, hidden) = activation(activation_raw, ctx, o)?;\n"
    last = b"    let av: Vec<_>"
    assert frozen.count(first) == frozen.count(last) == 1
    body = frozen[frozen.index(first):frozen.index(last)]
    assert hashlib.sha256(body).hexdigest() == FRAGMENT
    assert b"pon_work" not in body
    return numeric_witness(frozen) + b"""
pub(super) fn binding_fixture_pins(a:&[u8], b:&[u8]) -> (Hash,Hash) {
    (hash(b"artifact", &[a]),hash(b"qualified-task-input-v1", &[b]))
}
pub(super) fn tile_model_binding_witness(
    activation_raw:&[u8], raw:&[u8], actpin:[u8;32], cppin:[u8;32], cpsz:u64,
    expected_a:&[u8], expected_b:&[u8], model:[u8;32], input:[u8;32],
) -> MaterialResult<(Hash,Hash)> {
    let mut checkpoint=io::Cursor::new(raw);
    let mut callback=|_: MaterialProgress| Ok(());
    let o=&Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    let ctx=&PinnedTileContextV1 {
        network:[1;32],parameters:[2;32],checkpoint_sha256:cppin,checkpoint_bytes:cpsz,
        activation_sha256:actpin,model,input,
    };
""" + body + b"    Ok(binding_fixture_pins(&aa,&bb))\n}\n"


class CheckpointTileModelBindingTests(unittest.TestCase):
    def test_original_replay_then_material_pins_both_stock(self):
        rows = []

        def emit(mode, status, doc, cp, pin=None, **kw):
            rows.append((mode, status, frame(encode(doc), cp, pin or hashlib.sha256(cp).digest(), **kw)))

        for tokens in (1, 2, 64):
            q = tile_fixture(tokens)
            cp = checkpoint(q[16:8208], offset=17)
            doc = object_fixture(tokens, cp, hidden=q[8208:])
            emit(0, 0, doc, cp)
            po = runtime_array(doc)
            emit(0, 0, [po[k] for k in ROOT_FIELDS], cp)
            if tokens == 2:
                for mode, code in ((1, 40), (2, 40), (4, 41), (8, 41), (12, 41), (15, 40), (6, 40)):
                    emit(mode, code, doc, cp)
                emit(15, 1, doc, cp, bad_act_pin=True)
                wrong_cp = cp[:-1] + bytes([cp[-1] ^ 1])
                emit(15, 34, doc, wrong_cp, pin=hashlib.sha256(cp).digest())
                bad = bytearray(q[8208:])
                bad[-4:] = b"\0\0\x80\x7f"
                emit(15, 15, object_fixture(tokens, cp, hidden=bad), cp)
        request = b"".join(struct.pack("<BI", mode, len(base)) + base for mode, _, base in rows)
        with tempfile.TemporaryDirectory(prefix="checkpoint-tile-model-binding-") as tmp:
            original_rows = original(Path(tmp), request, reference=REFERENCE, witness=witness)
        cases = []
        at = 0
        for _, status, base in rows:
            code, n = struct.unpack_from("<II", original_rows, at)
            self.assertEqual((code, n), (status, 64 if status == 0 else 0))
            at += 8
            expected = original_rows[at:at+n]
            at += n
            suffix = original_rows[at:at+32832]
            self.assertEqual(len(suffix), 32832)
            at += 32832
            cases.append((base+suffix, status, expected))
        self.assertEqual(at, len(original_rows))
        self.assertEqual(cases[-1][2], cases[-2][2])
        self.assertGreater(len(cases[-1][0]), 990000)
        self.assertLess(len(cases[-1][0]), 1048576)
        first = cases[0][0]
        guard = [(b"", 100, b""), (first[:-32840]+b"\xff"*8+first[-32832:], 100, b"")]
        o, w = b"O"*71, b"W"*500013
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                matrix = cases + guard
                for offset in range(0,len(matrix),2):
                    group = matrix[offset:offset+2]
                    calls = [("f0", [raw,o,w]) for raw,_,_ in group]
                    for (raw,code,body), reply in zip(group,native.call_many(calls),strict=True):
                        got = reply.require_returned()
                        self.assertEqual((got.value,got.arguments[:2]), (code,[raw,body+o[len(body):]]))
                        self.assertEqual(got.arguments[2][500000:],w[500000:])
                for output, scratch in ((o[:63],w),(o,w[:499999])):
                    args = [first,output,scratch]
                    got = native.call("f0",args).require_returned()
                    self.assertEqual((got.value,got.arguments),(102,args))
