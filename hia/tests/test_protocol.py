"""Native HIA wire validation against frozen bytes and independent input families.

Only the test driver and fixture construction are Python. Every verdict is
produced by the HIA self-hosted compiler's native machine code. These functions
validate canonical byte encodings; they grant no signature, model or chain
admission authority and do not replace the complete protocol crate yet.
"""
from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "hia/src/protocol"
VECTORS = ROOT / "formal/pon-nakamoto-v1/vectors"
OK, LENGTH, VERSION, NONCANONICAL, LIMIT = range(5)


def changed(raw: bytes, index: int, value: int) -> bytes:
    out = bytearray(raw)
    out[index] = value
    return bytes(out)


def factor_bytes(rank: int) -> bytes:
    # Independently construct valid signed extrema, negative and zero values.
    values = [-32767, -1, 0, 1, 32767]
    return struct.pack("<" + "h" * (260 * rank),
                       *(values[i % len(values)] for i in range(260 * rank)))


def ilf2(rank=1, slot=0) -> bytes:
    return (b"ILF2" + struct.pack("<HBBH", 2, rank, slot, 1024)
            + bytes(range(224)) + struct.pack("<Q", (1 << 64) - 1)
            + factor_bytes(rank))


def ilf3(operations=((0, 1),), mask=7) -> bytes:
    out = (b"ILF3" + struct.pack("<HBBH", 3, mask, len(operations), 1024)
           + bytes(range(224)) + struct.pack("<Q", (1 << 64) - 1))
    for target, rank in operations:
        out += bytes((target, rank)) + factor_bytes(rank)
    return out


def operation_offsets(operations):
    position = 242
    for target, rank in operations:
        yield position, position + 2, 260 * rank
        position += 2 + 520 * rank


class ProtocolNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        cls.observations = {name: 0 for name in ("id", "hash", "pnh1", "pgh2", "ilf2", "ilf3")}
        try:
            for name in cls.observations:
                cls.modules[name] = NativeModule(SOURCES / (name + ".hepta"), byte_exports=("f0",))
        except BaseException:
            for module in cls.modules.values():
                module.close()
            raise

    @classmethod
    def tearDownClass(cls):
        report = {"schema": "trnm.hia.protocol-native-observation.v1",
                  "cases": cls.observations, "backend": "selfhost", "modules": {}}
        for name, module in cls.modules.items():
            report["modules"][name] = {
                "source_sha256": hashlib.sha256(module.source.read_bytes()).hexdigest(),
                "artifact_sha256": module.artifact_sha256,
                "compiler_sha256": module.receipt["compiler_sha256"],
            }
            module.close()
        print(json.dumps(report, sort_keys=True))

    def cases(self, name, values):
        values = list(values)
        # Bounded independent process batches; a fault/timeout is never an error-code pass.
        for start in range(0, len(values), 128):
            batch = values[start:start + 128]
            outputs = self.modules[name].call_many([
                ("f0", [raw, b"\xa5" * 11, b"\x5a" * 13]) for _, raw, _ in batch])
            self.assertEqual(len(outputs), len(batch))
            for (label, raw, expected), output in zip(batch, outputs):
                with self.subTest(module=name, case=label):
                    result = output.require_returned()
                    self.assertEqual(result.value, expected)
                    self.assertEqual(result.arguments, [raw, b"\xa5" * 11, b"\x5a" * 13])
                    self.observations[name] += 1

    def test_id_complete_byte_alphabet_and_extent_boundaries(self):
        allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.:/@"
        cases = [("single-" + str(b), bytes((b,)), OK if b in allowed else NONCANONICAL)
                 for b in range(256)]
        cases += [("last-" + str(b), b"a" * 159 + bytes((b,)),
                   OK if b in allowed else NONCANONICAL) for b in range(256)]
        cases += [("length-" + str(n), b"a" * n, OK if 1 <= n <= 160 else NONCANONICAL)
                  for n in [0, 1, 159, 160, 161, 1024]]
        cases += [("mixed", allowed, OK), ("utf8", "链".encode(), NONCANONICAL),
                  ("space-prefix", b" a", NONCANONICAL), ("space-suffix", b"a ", NONCANONICAL)]
        self.cases("id", cases)

    def test_hash_lowercase_alphabet_and_all_positions(self):
        alphabet = b"0123456789abcdef"
        cases = [("alphabet-" + str(b), bytes((b,)) * 64,
                  OK if b in alphabet else NONCANONICAL) for b in range(256)]
        cases += [("length-" + str(n), b"a" * n, OK if n == 64 else NONCANONICAL)
                  for n in range(67)]
        cases += [("uppercase-position-" + str(i), changed(b"a" * 64, i, ord("A")), NONCANONICAL)
                  for i in range(64)]
        cases += [("mixed", alphabet * 4, OK), ("zero", b"0" * 64, OK)]
        self.cases("hash", cases)

    def test_pnh1_matches_retained_independent_header_oracle(self):
        path = ROOT / "formal/pon-nakamoto-v1/contract_wire.py"
        spec = importlib.util.spec_from_file_location("trnm_hia_independent_wire", path)
        oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oracle)
        golden = (VECTORS / "header.bin").read_bytes()
        self.assertEqual(len(golden), 318)
        corpus = [golden[:n] for n in range(319)] + [golden + b"\0"]
        corpus += [changed(golden, index, golden[index] ^ 1) for index in range(318)]
        corpus += [(VECTORS / filename).read_bytes()
                   for filename in ["header-short.bin", "header-version.bin", "header-trailing.bin"]]
        expected = []
        for index, raw in enumerate(corpus):
            try:
                decoded = oracle.header_decode(raw)
                self.assertEqual(oracle.header_encode(decoded), raw)
                code = OK
            except ValueError as error:
                code = {"LENGTH": LENGTH, "VERSION": VERSION}[str(error)]
            expected.append((str(index), raw, code))
        self.cases("pnh1", expected)

    def test_growth_header_strict_outer_and_nested_header(self):
        raw = b"PGH2" + (VECTORS / "header.bin").read_bytes() + bytes(range(32))
        cases = [("length-" + str(n), raw[:n], LENGTH) for n in range(354)]
        cases += [("valid", raw, OK), ("trailing", raw + b"\0", LENGTH)]
        cases += [("mutate-" + str(i), changed(raw, i, raw[i] ^ 1), VERSION if i < 10 else OK)
                  for i in range(354)]
        cases += [("pnh1-is-distinct", raw[4:322], LENGTH)]
        self.cases("pgh2", cases)

    def test_factor_all_ranks_slots_and_truncations(self):
        cases = [(f"rank{rank}-slot{slot}", ilf2(rank, slot), OK)
                 for rank in [1, 2] for slot in range(3)]
        raw = ilf2(2)
        cases += [("truncated-" + str(n), raw[:n], LENGTH) for n in range(len(raw))]
        cases += [("appended-" + str(n), raw + bytes(n), LENGTH) for n in [1, 2, 257]]
        self.cases("ilf2", cases)

    def test_factor_complete_coefficient_positions_and_shape_errors(self):
        raw = ilf2(2)
        cases = []
        for i in range(520):
            bad = bytearray(raw)
            bad[242 + 2 * i:244 + 2 * i] = b"\0\x80"
            cases.append(("min-coefficient-" + str(i), bytes(bad), NONCANONICAL))
        cases += [("rank-" + str(rank), changed(raw, 6, rank), LIMIT)
                  for rank in range(256) if rank not in [1, 2]]
        cases += [("slot-" + str(slot), changed(raw, 7, slot), LIMIT) for slot in range(3, 256)]
        cases += [("version-" + str(i), changed(raw, i, raw[i] ^ 1), VERSION)
                  for i in [0, 1, 2, 3, 4, 5, 8, 9]]
        cases += [("metadata-" + str(i), changed(raw, i, raw[i] ^ 1), OK) for i in range(10, 242)]
        self.cases("ilf2", cases)

    def test_factor_error_precedence(self):
        raw = ilf2()
        bad = bytearray(raw)
        bad[242:244] = b"\0\x80"
        cases = [("short-before-magic", b"bad", LENGTH),
                 ("magic-before-rank", changed(changed(raw, 0, 0), 6, 0), VERSION),
                 ("rank-before-extent", changed(raw[:-1], 6, 0), LIMIT),
                 ("extent-before-coefficient", bytes(bad[:-1]), LENGTH),
                 ("canonical-coefficient", bytes(bad), NONCANONICAL)]
        self.cases("ilf2", cases)

    def test_evolution_all_canonical_graphs_and_masks(self):
        cases = []
        for count in range(4):
            for targets in itertools.combinations(range(5), count):
                for ranks in itertools.product([1, 2], repeat=count):
                    if sum(ranks) <= 3:
                        for mask in range(1, 8):
                            operations = tuple(zip(targets, ranks))
                            cases.append((str((operations, mask)), ilf3(operations, mask), OK))
        self.cases("ilf3", cases)

    def test_evolution_original_independent_model_vectors(self):
        original = json.loads((VECTORS / "model-evolution-v5.json").read_text())
        self.cases("ilf3", [(name, bytes.fromhex(original[name]["payload"]), OK)
                            for name in ["first", "second", "neutral"]])
        # A graph-mask-only update is canonical wire even with no factor operation.
        self.cases("ilf3", [("no-operations-mask-" + str(mask), ilf3((), mask), OK)
                            for mask in range(1, 8)])

    def test_evolution_truncation_and_coefficient_boundaries(self):
        operations = ((0, 1), (2, 1), (4, 1))
        raw = ilf3(operations)
        self.assertEqual(len(raw), 1808)
        cases = [("truncated-" + str(n), raw[:n], LENGTH) for n in range(len(raw))]
        cases += [("appended", raw + b"\0", LENGTH)]
        for op, (_, begin, count) in enumerate(operation_offsets(operations)):
            for i in range(count):
                bad = bytearray(raw)
                bad[begin + 2 * i:begin + 2 * i + 2] = b"\0\x80"
                cases.append((f"operation{op}-coefficient{i}", bytes(bad), NONCANONICAL))
        self.cases("ilf3", cases)

    def test_evolution_shape_version_order_and_rank_budget(self):
        raw = ilf3(((0, 1), (2, 1), (4, 1)))
        cases = [("mask-" + str(mask), changed(raw, 6, mask), LIMIT)
                 for mask in range(256) if not 1 <= mask <= 7]
        cases += [("count-" + str(count), changed(raw, 7, count), LIMIT) for count in range(4, 256)]
        cases += [("version-" + str(i), changed(raw, i, raw[i] ^ 1), VERSION)
                  for i in [0, 1, 2, 3, 4, 5, 8, 9]]
        for op, (begin, _, _) in enumerate(operation_offsets(((0, 1), (2, 1), (4, 1)))):
            cases += [(f"op{op}-target{target}", changed(raw, begin, target), LIMIT)
                      for target in range(5, 256)]
            cases += [(f"op{op}-rank{rank}", changed(raw, begin + 1, rank), LIMIT)
                      for rank in range(256) if rank not in [1, 2]]
        cases += [("duplicate-target", ilf3(((1, 1), (1, 1))), NONCANONICAL),
                  ("descending-target", ilf3(((3, 1), (1, 1))), NONCANONICAL),
                  ("sum4-exceeds-outer-limit", ilf3(((0, 2), (1, 2))), LENGTH),
                  ("sum6-exceeds-outer-limit", ilf3(((0, 2), (1, 2), (2, 2))), LENGTH),
                  ("unused-tail", ilf3(()) + b"\0", LENGTH)]
        self.cases("ilf3", cases)

    def test_evolution_deferred_canonicality_preserves_decoder_error_priority(self):
        operations = ((0, 1), (1, 1))
        raw = bytearray(ilf3(operations))
        raw[244:246] = b"\0\x80"
        second_header = 242 + 522
        cases = [("early-coefficient", bytes(raw), NONCANONICAL),
                 ("later-target-beats-early-coefficient", changed(raw, second_header, 5), LIMIT),
                 ("later-rank-beats-early-coefficient", changed(raw, second_header + 1, 0), LIMIT),
                 ("later-short-body-beats-early-coefficient", bytes(raw[:-1]), LENGTH),
                 ("trailing-beats-early-coefficient", bytes(raw) + b"\0", LENGTH),
                 ("trailing-beats-order", ilf3(((1, 1), (0, 1))) + b"\0", LENGTH),
                 ("version-before-mask", changed(changed(raw, 0, 0), 6, 0), VERSION),
                 ("mask-before-header", changed(ilf3(())[:-1] + b"\0", 6, 0), LIMIT)]
        self.cases("ilf3", cases)


class Pnh1EncoderNativeTests(unittest.TestCase):
    """A byte-producing component, independent of the PNH1 grammar checker."""

    @classmethod
    def setUpClass(cls):
        from contextlib import ExitStack
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        cls.modules = {
            backend: cls.stack.enter_context(NativeModule(
                SOURCES / "pnh1_encode.hepta", byte_exports=("f0",), backend=backend))
            for backend in ("direct", "selfhost")
        }
        cls.golden = (VECTORS / "header.bin").read_bytes()
        path = ROOT / "formal/pon-nakamoto-v1/contract_wire.py"
        spec = importlib.util.spec_from_file_location("trnm_hia_independent_pnh1_encoder", path)
        cls.oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.oracle)

    @classmethod
    def descriptor(cls, fields):
        hashes = ("network", "parameters", "parent", "target", "miner",
                  "transactions", "state", "receipts", "work_task")
        return (b"".join(fields[name] for name in hashes)
                + struct.pack("<QQQ", fields["height"], fields["timestamp"], fields["nonce"]))

    @classmethod
    def accepted(cls):
        base = cls.oracle.header_decode(cls.golden)
        yield "historical", base, cls.golden
        # Test independently addressed fields rather than passing preencoded wire.
        for index in range(6, len(cls.golden)):
            raw = changed(cls.golden, index, cls.golden[index] ^ 0xA5)
            yield f"field-byte-{index}", cls.oracle.header_decode(raw), raw
        for value in (0, 1, (1 << 32) - 1, 1 << 63, (1 << 64) - 1):
            fields = dict(base, height=value, timestamp=value ^ (1 << 63),
                          nonce=value ^ ((1 << 64) - 1))
            yield f"scalar-{value}", fields, cls.oracle.header_encode(fields)

    def check_native(self, cases):
        cases = list(cases)
        scratch = b"\x5a" * 13
        for backend, module in self.modules.items():
            for start in range(0, len(cases), 128):
                batch = cases[start:start + 128]
                results = module.call_many([("f0", [source, output, scratch])
                                            for _, source, output, _, _ in batch])
                self.assertEqual(len(batch), len(results))
                for case, result in zip(batch, results):
                    name, source, _, code, output = case
                    with self.subTest(backend=backend, case=name):
                        result = result.require_returned()
                        self.assertEqual(result.value, code)
                        self.assertEqual(result.arguments, [source, output, scratch])

    def test_exact_bytes_and_output_tail(self):
        cases = []
        for index, (name, fields, raw) in enumerate(self.accepted()):
            tail = b"\xa5" * (0 if index % 2 else 17)
            cases.append((name, self.descriptor(fields), b"\xa5" * 318 + tail, OK, raw + tail))
        self.check_native(cases)

    def test_wrong_extent_never_writes(self):
        cases = []
        source = self.descriptor(self.oracle.header_decode(self.golden))
        for n in (*range(312), 313, 318, 1024):
            sentinel = b"\x6a" * 335
            cases.append((f"input-{n}", source[:n].ljust(n, b"\0"), sentinel, LENGTH, sentinel))
        for n in range(318):
            sentinel = b"\x6a" * n
            cases.append((f"output-{n}", source, sentinel, LENGTH, sentinel))
        self.check_native(cases)

    def test_original_rust_encoder(self):
        import os
        import subprocess
        configured = os.environ.get("TRNM_HIA_RUST_PROTOCOL_REFERENCE")
        if not configured:
            self.skipTest("NOT_RUN: configure the compiled original Rust protocol reference")
        reference = Path(configured).resolve(strict=True)
        self.assertTrue(reference.is_file() and os.access(reference, os.X_OK))
        operands = [(self.descriptor(fields), f"0 {raw.hex()}")
                    for _, fields, raw in self.accepted()]
        operands += [(b"\0" * n, f"{LENGTH} -") for n in (0, 1, 311, 313, 318, 1024)]
        result = subprocess.run([str(reference)],
                                input="".join(f"H {raw.hex() or '-'}\n" for raw, _ in operands),
                                check=True, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.stdout.splitlines(), [reply for _, reply in operands])


if __name__ == "__main__":
    unittest.main()
