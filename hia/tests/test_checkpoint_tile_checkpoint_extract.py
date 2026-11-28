"""Frozen checkpoint prefix/header/full pin/BF16 extraction on inert Cursor bytes."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_quantize import ROOT, original
from hia.tests.test_checkpoint_tile_tensor_header import N, TARGET, encode, record

SOURCE = ROOT / "hia/src/checkpoint/tile_checkpoint_extract.hepta"
REFERENCE = Path(__file__).with_name("rust_checkpoint_tile_checkpoint_extract_reference.rs")
FRAGMENT_SHA = '5411f5426060bbde05da1590f1d94535a0576a6a0e53ac814804838710af5f49'


def witness(frozen):
    begin = frozen.index(b"    require(\n        checkpoint\n            .seek(SeekFrom::End(0))")
    end = frozen.index(b"    let mut a = Vec::with_capacity(4096);", begin)
    block = frozen[begin:end]
    assert hashlib.sha256(block).hexdigest() == FRAGMENT_SHA
    return b"""
pub(super) fn checkpoint_extract_witness(raw:&[u8],len:u64,pin:[u8;32])
    -> MaterialResult<Vec<u8>> {
    let mut checkpoint=io::Cursor::new(raw);
    let mut callback=|_: MaterialProgress| Ok(());
    let o=&Rc::new(RefCell::new(Observer {
        callback:&mut callback,first_error:None,checkpoint_bytes_read:0,
    }));
    let ctx=PinnedTileContextV1 {
        network:[1;32],parameters:[2;32],checkpoint_sha256:pin,checkpoint_bytes:len,
        activation_sha256:[3;32],model:[7;32],input:[8;32],
    };
""" + block + b"    Ok(tile)\n}\n"


def frame(raw, *, length=None, expected=None):
    if length is None:
        length = len(raw)
    if expected is None:
        expected = hashlib.sha256(raw).digest()
    return b"TCE1\0\0\0\0" + expected + struct.pack("<Q", length) + raw


def container(header, payload):
    return struct.pack("<Q", len(header)) + header + payload


class CheckpointTileCheckpointExtractTests(unittest.TestCase):
    def test_frozen_original_checkpoint_prefix_header_pin_and_exact_tile(self):
        data = bytes((i * 7 + i // 127) & 255 for i in range(N))
        simple_header = encode({TARGET: record("BF16", [576, 576], 0, N)})
        simple = container(simple_header, data)
        # Position the first selected row across the original 64-KiB chunk cut.
        cross_header = simple_header.ljust(65507 - 8, b" ")
        cross = container(cross_header, data)
        shifted_header = encode({"synthetic-q": record("U8", [19], 0, 19),
                                 TARGET: record("BF16", [576, 576], 19, N + 19),
                                 "__metadata__": {"generated": "one"}})
        shifted = container(shifted_header, b"X" * 19 + data)
        maximum = container(simple_header.ljust((1 << 20) - 48 - N - 8, b" "), data)
        self.assertEqual(len(frame(maximum)), 1 << 20)
        pin = hashlib.sha256(simple).digest()
        mutate_unselected = bytearray(simple)
        mutate_unselected[-1] ^= 1
        mutate_selected = bytearray(simple)
        mutate_selected[len(simple_header) + 8] ^= 1
        rows = [
            (0, frame(simple)), (0, frame(cross)), (0, frame(shifted)), (0, frame(maximum)),
            (14, frame(simple, expected=bytes(32))),
            (14, frame(bytes(mutate_unselected), expected=pin)),
            (14, frame(bytes(mutate_selected), expected=pin)),
            (1, frame(b"x", length=2, expected=bytes(32))),
            (1, frame(simple, length=len(simple) - 1)),
            (12, frame(b"")), (12, frame(b"\0" * 7)),
            (13, frame(struct.pack("<Q", 0))), (13, frame(struct.pack("<Q", 1) + b"0")),
            (13, frame(struct.pack("<Q", 4) + b"{}")), (13, frame(struct.pack("<Q", 0xffffffffffffffff))),
            (2, frame(container(b'{"a":0,"\\u0061":0}', b""), expected=bytes(32))),
            (10, frame(container(b"{}", data), expected=bytes(32))),
            (9, frame(container(encode({TARGET: record("I16", [576, 576], 0, N)}), data))),
            (11, frame(container(simple_header, data[:-1]), expected=bytes(32))),
            (10, frame(container(simple_header, data + b"x"), expected=pin)),
        ]
        stimulus = b"".join(struct.pack("<I", len(frame_)) + frame_ for _, frame_ in rows)
        with tempfile.TemporaryDirectory(prefix="checkpoint-tile-extract-") as temp:
            observed = original(Path(temp), stimulus, reference=REFERENCE, witness=witness)
        expected = []
        while observed:
            code, length = struct.unpack_from("<II", observed)
            body = observed[8:8 + length]
            self.assertEqual(len(body), length)
            expected.append((code, body))
            observed = observed[8 + length:]
        self.assertEqual([s for s, _ in expected], [s for s, _ in rows])
        self.assertEqual(expected[:4], [expected[0]] * 4)
        self.assertEqual(len(expected[0][1]), 8192)
        self.assertEqual(expected[0][1][:128], data[:128])
        self.assertEqual(expected[0][1][-128:], data[63*1152:63*1152+128])
        matrix = [(s, data, value) for (s, data), (_, value) in zip(rows, expected, strict=True)]
        matrix += [(100, b"TCE1", b""), (100, b"TCE2" + rows[0][1][4:], b"")]
        out, work = b"O" * 8201, b"W" * 18005
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                for start in range(0, len(matrix), 3):
                    group = matrix[start:start + 3]
                    for (s, bits, value), call in zip(group, native.call_many(
                        [("f0", [b, out, work]) for _, b, _ in group]
                    ), strict=True):
                        got = call.require_returned()
                        self.assertEqual((got.value, got.arguments[:2]),
                                         (s, [bits, value + out[len(value):]]))
                        self.assertEqual(got.arguments[2][18000:], work[18000:])
                for o, w in ((out[:8191], work), (out, work[:17999])):
                    args = [rows[0][1], o, w]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (102, args))
