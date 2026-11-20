"""Complete current PNX1 envelope grammar, with actual native execution.

The independent reference is a byte-level Python specification here and, when
configured, the unchanged original Rust Envelope::decode/encode implementation.
No successful parse is transaction-signature or account-admission authority.
"""
from __future__ import annotations

import os
from pathlib import Path
import random
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_protocol import ilf2, ilf3

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/protocol/pnx1.hepta"
CANARY = b"output-unchanged"
SCRATCH = b"\xa5" * 2048
FIXED = {1: 40, 3: 32, 4: 64, 6: 176, 7: 104, 10: 112, 11: 136,
         12: 32, 13: 652, 14: 96, 15: 168, 17: 128, 18: 344, 19: 344,
         20: 144, 21: 684, 22: 1028}


def envelope(tag, payload, *, nonce=1, fee=10_000_000, expiry=0):
    return (b"PNX1" + bytes(range(64)) + struct.pack("<QQQBH", nonce, expiry, fee, tag, len(payload))
            + payload + bytes(reversed(range(64))))


def reservation():
    return (b"TSC1" + b"t" * 32 + b"".join(bytes([i]) * 32 for i in range(1, 11))
            + struct.pack("<QQQ", 7, 11, 13))


def decision(verdict=1):
    return b"TSD1" + b"t" * 32 + b"c" * 32 + b"o" * 32 + b"e" * 32 + bytes([verdict])


def allocations(keys):
    return b"x" * 144 + bytes([len(keys)]) + b"".join(key + struct.pack("<Q", i) for i, key in enumerate(keys))


def equivocation(first=159, second=159):
    return b"x" * 32 + struct.pack("<H", first) + b"a" * first + struct.pack("<H", second) + b"b" * second


def example_payloads():
    values = [(tag, bytes([tag]) * size) for tag, size in FIXED.items()]
    values += [(2, b"\0" * 80), (2, reservation()), (5, b"\0" * 64), (5, decision()),
               (8, allocations([b"a" * 32, b"b" * 32])),
               (9, b"x" * 72 + b"\x02" + b"p" * 64), (16, equivocation()),
               (23, ilf2()), (24, ilf3())]
    return values


def factor_reference(raw, *, evolution):
    # Decode integer arrays independently of the HIA scalar/CFG implementation.
    if len(raw) < 242 or evolution and len(raw) > 1808:
        return 1
    if raw[:6] != (b"ILF3\x03\0" if evolution else b"ILF2\x02\0") or raw[8:10] != b"\0\x04":
        return 2
    if not evolution:
        rank, slot = raw[6:8]
        if rank not in (1, 2) or slot >= 3:
            return 4
        if len(raw) != 242 + 520 * rank:
            return 1
        return 3 if -32768 in struct.unpack("<" + "h" * (260 * rank), raw[242:]) else 0
    mask, count = raw[6:8]
    if not 1 <= mask <= 7 or count > 3:
        return 4
    pos, ranks, targets, values = 242, [], [], []
    for _ in range(count):
        if pos + 2 > len(raw):
            return 1
        target, rank = raw[pos:pos + 2]
        pos += 2
        if target >= 5 or rank not in (1, 2):
            return 4
        if pos + 520 * rank > len(raw):
            return 1
        values.extend(struct.unpack_from("<" + "h" * (260 * rank), raw, pos))
        targets.append(target)
        ranks.append(rank)
        pos += 520 * rank
    if pos != len(raw):
        return 1
    if -32768 in values or any(a >= b for a, b in zip(targets, targets[1:])):
        return 3
    return 4 if sum(ranks) > 3 else 0


def payload_reference(tag, p):
    if tag in FIXED:
        return 0 if len(p) == FIXED[tag] else 1
    if tag == 2:
        if len(p) == 80:
            return 0
        if len(p) != 380:
            return 1
        if p[:4] != b"TSC1":
            return 2
        commitments = [p[4 + 32 * i:36 + 32 * i] for i in range(11)]
        budget, delivery, dispute = struct.unpack_from("<QQQ", p, 356)
        return 3 if (any(c == bytes(32) for c in commitments) or not budget or not delivery
                     or dispute <= delivery or p[68:100] == p[324:356]) else 0
    if tag == 5:
        if len(p) == 64:
            return 0
        if len(p) != 133:
            return 1
        if p[:4] != b"TSD1":
            return 2
        if p[132] not in (1, 2):
            return 3
        return 3 if (any(p[i:i + 32] == bytes(32) for i in (4, 36, 100))
                     or p[132] == 1 and p[68:100] == bytes(32)) else 0
    if tag == 8:
        if len(p) < 145:
            return 1
        count = p[144]
        if not 1 <= count <= 16:
            return 4
        if len(p) != 145 + count * 40:
            return 1
        keys = [p[145 + i * 40:177 + i * 40] for i in range(count)]
        return 0 if all(a < b for a, b in zip(keys, keys[1:])) else 3
    if tag == 9:
        if len(p) < 73:
            return 1
        if p[72] > 8:
            return 4
        return 0 if len(p) == 73 + p[72] * 32 else 1
    if tag == 16:
        if len(p) < 36:
            return 1
        a = int.from_bytes(p[32:34], "little")
        if not 159 <= a <= 512 or len(p) < 36 + a:
            return 1
        b = int.from_bytes(p[34 + a:36 + a], "little")
        return 0 if 159 <= b <= 512 and len(p) == 36 + a + b else 1
    if tag in (23, 24):
        return factor_reference(p, evolution=tag == 24)
    return 2


def reference(raw):
    if len(raw) > 2048:
        return 4
    if len(raw) < 159:
        return 1
    if raw[:4] != b"PNX1":
        return 2
    size = int.from_bytes(raw[93:95], "little")
    if len(raw) != 159 + size:
        return 1
    result = payload_reference(raw[92], raw[95:95 + size])
    if result:
        return result
    nonce, _, fee = struct.unpack_from("<QQQ", raw, 68)
    return 3 if not nonce or fee > 10_000_000 else 0


def corpus():
    rng = random.Random(202611150949)
    values = []
    for tag, payload in example_payloads():
        good = envelope(tag, payload)
        values += [good, good[:-1], good + b"\0", envelope(tag, payload[:-1]), envelope(tag, payload + b"\0")]
        values += [envelope(tag, payload, nonce=n, fee=fee, expiry=(1 << 64) - 1)
                   for n in (0, 1, (1 << 64) - 1) for fee in (0, 10_000_000, 10_000_001, (1 << 64) - 1)]
        for _ in range(32):
            changed = bytearray(good)
            for _ in range(rng.randrange(1, 5)):
                changed[rng.randrange(len(changed))] = rng.randrange(256)
            values.append(bytes(changed))
    values += [envelope(tag, b"") for tag in range(256)]
    values += [bytes(n) for n in range(160)]
    values += [bytes(n) for n in (2047, 2048, 2049, 65536)]
    return values


class Pnx1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check(self, rows):
        rows = list(rows)
        for pos in range(0, len(rows), 64):
            batch = rows[pos:pos + 64]
            results = self.native.call_many([("f0", [raw, CANARY, SCRATCH]) for raw in batch])
            for raw, result in zip(batch, results):
                result.require_returned()
                self.assertEqual(result.value, reference(raw), (raw[:100].hex(), len(raw)))
                self.assertEqual(result.arguments[:2], [raw, CANARY])
                # Only a successfully framed ILF envelope may use the scratch prefix.
                if len(raw) <= 2048 and len(raw) >= 159 and raw[:4] == b"PNX1" and raw[92] in (23, 24):
                    n = int.from_bytes(raw[93:95], "little")
                    if len(raw) == 159 + n:
                        self.assertEqual(result.arguments[2], raw[95:95 + n] + SCRATCH[n:])
                        continue
                self.assertEqual(result.arguments[2], SCRATCH)

    def test_all_current_tags_and_outer_error_precedence(self):
        self.check(corpus())

    def test_fixed_payloads_are_opaque_at_this_decoder(self):
        rng = random.Random(971)
        self.check(envelope(tag, rng.randbytes(size)) for tag, size in FIXED.items())
        # No extra semantic policy is silently added to the original decoder.
        self.check([envelope(2, bytes(80)), envelope(5, bytes(64)),
                    envelope(13, bytes(652)), envelope(21, bytes(684)), envelope(22, bytes(1028))])

    def test_funded_contract_all_commitments_and_u64_boundaries(self):
        rows = []
        base = reservation()
        for i in range(11):
            p = bytearray(base);p[4 + 32 * i:36 + 32 * i] = bytes(32);rows.append(envelope(2, p))
        p = bytearray(base);p[324:356] = p[68:100];rows.append(envelope(2, p))
        for budget in (0, 1, (1 << 64) - 1):
            for delivery, dispute in [(0, 0), (0, 1), (1, 1), (1, 2), ((1 << 64) - 2, (1 << 64) - 1), ((1 << 64) - 1, 0)]:
                rows.append(envelope(2, base[:356] + struct.pack("<QQQ", budget, delivery, dispute)))
        self.check(rows)

    def test_funded_decision_verdict_and_zero_output(self):
        rows = []
        for verdict in range(256):
            p = decision(verdict)
            rows += [envelope(5, p), envelope(5, p[:68] + bytes(32) + p[100:])]
        for start in (4, 36, 100):
            p = bytearray(decision(2));p[start:start + 32] = bytes(32);rows.append(envelope(5, p))
        self.check(rows)

    def test_allocation_exact_order_count_and_first_differing_key_byte(self):
        rows = [envelope(8, allocations([bytes([i]) * 32 for i in range(n)])) for n in range(18)]
        for position in range(32):
            a, b = bytearray(b"x" * 32), bytearray(b"x" * 32)
            a[position], b[position] = 0, 255
            rows += [envelope(8, allocations(keys)) for keys in ([bytes(a), bytes(b)], [bytes(b), bytes(a)], [bytes(a), bytes(a)])]
        rows += [envelope(8, b"x" * 144 + bytes([n])) for n in range(256)]
        self.check(rows)

    def test_proof_list_and_nested_opaque_envelope_extents(self):
        rows = [envelope(9, b"x" * 72 + bytes([n]) + b"y" * (n * 32)) for n in range(10)]
        for a in (0, 158, 159, 160, 511, 512, 513):
            for b in (0, 158, 159, 512, 513):
                rows.append(envelope(16, equivocation(a, b)))
        p = equivocation(159, 512)
        rows += [envelope(16, p[:n]) for n in range(len(p))]
        self.check(rows)

    def test_both_shared_factor_grammars_and_scratch_extent(self):
        rows = []
        for tag, p in ((23, ilf2(2, 2)), (24, ilf3(((0, 1), (2, 1), (4, 1))))):
            rows += [envelope(tag, p[:n]) for n in range(len(p) + 1)]
            for n in (0, len(p) - 1):
                raw, scratch = envelope(tag, p), bytes(n)
                r = self.native.call("f0", [raw, CANARY, scratch]).require_returned()
                self.assertEqual((r.value, r.arguments), (100, [raw, CANARY, scratch]))
            r = self.native.call("f0", [envelope(tag, p), b"", bytes(len(p))]).require_returned()
            self.assertEqual((r.value, r.arguments[1:]), (0, [b"", p]))
        self.check(rows)


class Pnx1RustDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("TRNM_HIA_RUST_PROTOCOL_REFERENCE")
        if not configured:
            raise unittest.SkipTest("NOT_RUN: configure the compiled original Rust protocol reference")
        cls.reference = Path(configured).resolve(strict=True)
        if not cls.reference.is_file() or not os.access(cls.reference, os.X_OK):
            raise AssertionError("Configured original Rust protocol reference is not executable")
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def test_original_decode_encode_and_error_order(self):
        values = corpus()
        request = "".join((raw.hex() or "-") + "\n" for raw in values)
        result = subprocess.run([str(self.reference)], input=request, capture_output=True, text=True, check=True, timeout=30)
        self.assertEqual(result.stderr, "")
        statuses = [int(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(statuses), len(values))
        for start in range(0, len(values), 64):
            outputs = self.native.call_many([("f0", [raw, CANARY, SCRATCH]) for raw in values[start:start + 64]])
            for raw, expected, output in zip(values[start:start + 64], statuses[start:start + 64], outputs):
                output.require_returned()
                self.assertEqual(output.value, expected, (raw[:100].hex(), len(raw)))
                self.assertEqual(reference(raw), expected)
                self.assertEqual(output.arguments[:2], [raw, CANARY])


if __name__ == "__main__":
    unittest.main()
