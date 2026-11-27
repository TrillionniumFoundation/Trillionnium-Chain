"""Real one-loan readonly HIA observation vs original Rust callback boundaries."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_state_import_incremental_delta_header import change, u64
from hia.tests.test_state_import_incremental_delta_target_projection import encode, selected
from hia.tests.test_state_import_snapshot_shadow import CRATE, LOCK, MANIFEST, _build_original, _run

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "hia/src/state_import"
SOURCE = SOURCES / "incremental_delta_projection_chain.hepta"
ADAPTER = ROOT / "hia/tests/rust_state_import_incremental_delta_projection_chain_reference.rs"
WORK = 2896
OUT = b"\xa5" * 61
STAMP = {
    "incremental_delta_validate.hepta": "e6f6273ccfa658437e3adc70a4da14e1e1aefd5b5a7868d1fbe975df8b6fea56",
    "incremental_delta_base_witness.hepta": "e9f22979e7a83aca6d004171f7d7b4a29e56bf35eb6496dc8ada3cef59de7218",
    "incremental_delta_target_projection.hepta": "783ed21c1db0589c1592c744c023a42ee976cd76ae4332a6a384a86dd33444d5",
}


def body(name, function):
    return ("fn " + function + (SOURCES / name).read_text().split("fn " + function, 1)[1]
            .split("\nend\n", 1)[0] + "\nend\n")


def fixture(seed=(), ops=(), labels=(), flags=0, expected=0, actual=None):
    actual = seed if actual is None else actual
    golden = selected(seed, ops, labels)
    body = bytes(map(len, [seed, actual, golden, ops]))
    body += b"".join(map(encode, (*seed, *actual, *golden, *ops)))
    return struct.pack("<I", len(body) + 4) + struct.pack("<I", flags) + body, labels, golden, expected


def read_row(wire, cursor):
    ns, key, val, tag = struct.unpack_from("<4I", wire, cursor)
    assert tag == 1
    a = cursor + 16
    b = a + ns
    c = b + key
    d = c + val
    return (wire[a:b], wire[b:c], wire[c:d]), d


class StateImportIncrementalDeltaProjectionChain(unittest.TestCase):
    def test_frozen_mechanical_input_adapters(self):
        for filename, expected in STAMP.items():
            self.assertEqual(hashlib.sha256((SOURCES / filename).read_bytes()).hexdigest(), expected)
        delta = body("incremental_delta_validate.hepta", "f0(").replace(
            "fn f0(input:readbuf,unused:mutbuf,work:mutbuf)",
            "fn ic_delta(input:readbuf,work:mutbuf,checked_extent:u64)").replace(
            'block entry(input:readbuf,unused:mutbuf,work:mutbuf)\n'
            '  raw_in_extent:usize = buffer.len(input)\n'
            '  checked_extent:u64 = int.cast(raw_in_extent) {"mode":"wrap"}',
            "block entry(input:readbuf,work:mutbuf,checked_extent:u64)")
        self.assertEqual(body(SOURCE.name, "ic_delta("), delta)
        table = body("incremental_delta_target_projection.hepta", "tp_table(").replace(
            'fn tp_table(', 'fn ic_ops_table(').replace(
                'size1:u64 = const() {"value":16}', 'size1:u64 = const() {"value":48}')
        self.assertEqual(body(SOURCE.name, "ic_ops_table("), table)

    def test_locked_original_and_two_native_exact_same_loan(self):
        a = (b"a", b"k", b"old")
        b = (b"b", b"k", b"old")
        c = (b"c", b"\xff", b"keep")
        drop = (b"a", b"k", None)
        add_empty = (b"a", b"s", b"")
        update = (b"b", b"k", b"new")
        base = (a, b, c)
        ops = (drop, add_empty, update)
        mixed = (129, 130, 2)
        all_base = tuple((b"a", bytes([i]), b"base") for i in range(8))
        all_ops = tuple((b"z", bytes([i]), b"") for i in range(8))
        wide = MAX_EXTENT - 1256 - 48 - 2
        cases = [
            fixture(), fixture(base, (), (0, 1, 2)), fixture((), ops, (129, 130)),
            fixture(base, ops, mixed), fixture((a,), (drop,)), fixture((a,), (update,), (0, 128)),
            fixture((a,), ((b"a", b"k", b""),), (128,)),
            fixture(all_base, all_ops, tuple(range(8)) + tuple(range(128, 136))),
            fixture((), ((b"a", b"k", b"v" * wide),), (128,)),
            fixture((), ((b"a", b"k", b"v" * (wide + 1)),), (128,)),
            fixture(base, ops, mixed, 1 | 4 | 256 | 32, 101),
            fixture(base, ops, mixed, 2 | 4 | 16, 112),
            fixture(base, ops, mixed, 512 | 1024 | 4, 113),
            fixture(base, ops, mixed, 2048 | 1 | 4, 114),
            fixture(base, ops, mixed, 1024 | 1 | 4, 114),
            fixture(base, ops, mixed, 4 | 256 | 16 | 32, 117),
            fixture(base, ops, mixed, 8 | 16 | 32, 117),
            fixture(base, ops, mixed, 256 | 16 | 32, 118),
            fixture(base, ops, mixed, 16 | 32, 115),
            fixture(base, ops, mixed, 128 | 32, 115),
            fixture(base, ops, mixed, 0, 115, (a, c)),
            fixture(base, ops, mixed, 32, 119),
            fixture(base, ops, mixed, 64, 119),
            fixture((a,), (drop,), (), 64, 119),   # ceiling fits, but merge drops the row.
            fixture((a,), ((b"z", b"k", None),), (0,), 64, 119),  # ceiling itself fails.
            fixture(base, (update, drop), (), 4 | 256, 109),
            fixture(base, ops, mixed, 16, 109, (a, a, c)),
            fixture(base, ops, mixed, 0, 115, ((a[0], a[1], b"different"), b, c)),
        ]
        paths = (MANIFEST, LOCK, CRATE / "Cargo.toml", CRATE / "src/lib.rs", ADAPTER)
        fingerprints = [hashlib.sha256(p.read_bytes()).digest() for p in paths]
        with tempfile.TemporaryDirectory(prefix="m13-original-projection-chain-") as tmp:
            reference, _ = _build_original(Path(tmp), ADAPTER)
            result = _run([reference], input=b"".join(x[0] for x in cases)).stdout
        self.assertEqual([hashlib.sha256(p.read_bytes()).digest() for p in paths], fingerprints)
        cursor = 0
        wires = []
        for i, (_, labels, golden, expected) in enumerate(cases):
            status, calls, first_status, first_calls, count, width = struct.unpack_from("<6I", result, cursor)
            cursor += 24
            wire = result[cursor:cursor + width]
            cursor += width
            self.assertEqual(status, expected, i)
            self.assertEqual(calls, 2 if status == 0 else int(status == 119), i)
            self.assertEqual((first_status, first_calls), (1, 1) if calls else (status, 0), i)
            self.assertEqual(count, len(labels) if status == 0 else 0, i)
            observed = []
            for _ in range(count):
                row, cursor = read_row(result, cursor)
                observed.append(row)
            if status == 0:
                self.assertEqual(observed, golden, i)
            answer = struct.pack("<Q", count) + wire[608:640] + bytes(labels)
            wires.append((wire, status, answer))
        self.assertEqual(cursor, len(result))
        self.assertEqual([len(wires[i][0]) for i in (8, 9)], [MAX_EXTENT, MAX_EXTENT + 1])
        bare, normal = wires[0][0], wires[3][0]
        cut = int.from_bytes(normal[-8:], "big")
        controls = [
            (b"", 100, b"", WORK, len(OUT)),
            (bare[:-1], 100, b"", WORK, len(OUT)),
            (change(bare, (len(bare)-8, u64(759))), 100, b"", WORK, len(OUT)),
            (change(bare, (len(bare)-8, u64(761))), 100, b"", WORK, len(OUT)),
            (change(normal, (len(normal)-8, u64(cut+1))), 100, b"", WORK, len(OUT)),
            (change(normal, (len(normal)-8, u64(cut-1))), 100, b"", WORK, len(OUT)),
            (change(bare, (752, u64(9))), 102, b"", WORK, len(OUT)),
            (change(bare, (1240, u64(9))), 102, b"", WORK, len(OUT)),
            (bare, 102, b"", WORK-1, len(OUT)),
            (bare, 102, b"", WORK, 55),
            (bare[:-8] + b"\x00" + bare[-8:], 100, b"", WORK, len(OUT)),
            (change(normal, (cut+488+12, b"\x00")), 100, b"", WORK, len(OUT)),
        ]
        trials = [(wire, status, answer, WORK+7, len(OUT)) for i, (wire, status, answer)
                  in enumerate(wires) if i != 9] + controls
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                requests = [("f0", [wire, OUT[:output], b"\x6d" * work])
                            for wire, _, _, work, output in trials]
                responses = native.call_many(requests, timeout=55)
                self.assertEqual(len(responses), len(trials))
                for i, response in enumerate(responses):
                    wire, expected, exact, work, output = trials[i]
                    self.assertEqual(response.require_returned().value, expected, i)
                    self.assertEqual(response.arguments[0], wire, i)
                    initial = OUT[:output]
                    self.assertEqual(response.arguments[1], initial if expected else exact + initial[len(exact):], i)
                    self.assertEqual(response.arguments[2][WORK:], b"\x6d" * max(0, work-WORK), i)
