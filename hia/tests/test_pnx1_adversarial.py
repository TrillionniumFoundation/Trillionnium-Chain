"""Independent PNX1 probes for opaque fields, byte order and borrowed spans.

These tests use explicit outcomes derived from the retained Rust contracts;
they do not import test_pnx1's policy oracle or its payload builders. They focus
on gaps that ordinary valid samples and zero-filled scratch can conceal.
Parsing remains separate from signature, account, model and source authority.
"""
from pathlib import Path
import struct
import unittest

from hia.tests.native_support import NativeModule


SOURCE = Path(__file__).resolve().parents[1] / "src/protocol/pnx1.hepta"
MAX_U64 = (1 << 64) - 1
OUTPUT = b"unchanged independent PNX1 output\0\xff"
SCRATCH = b"\xa5" * 3072


def packet(tag, payload, *, nonce=1, fee=0, expiry=MAX_U64, identity=bytes(64), signature=bytes(64)):
    return (b"PNX1" + identity + struct.pack("<QQQBH", nonce, expiry, fee, tag, len(payload))
            + payload + signature)


def replace(raw, offset, value):
    assert offset + len(value) <= len(raw)
    return raw[:offset] + value + raw[offset + len(value):]


def factor(rank=1, slot=0):
    return (b"ILF2" + struct.pack("<HBBH", 2, rank, slot, 1024) + bytes(224)
            + struct.pack("<Q", MAX_U64) + b"\xff\x7f" * (260 * rank))


def evolution(operations=((0, 1), (2, 1)), mask=1):
    prefix = (b"ILF3" + struct.pack("<HBBH", 3, mask, len(operations), 1024)
              + bytes(224) + struct.pack("<Q", MAX_U64))
    return prefix + b"".join(bytes([target, rank]) + b"\xff\xff" * (260 * rank)
                              for target, rank in operations)


def funded(*, delivery=255, dispute=256, budget=MAX_U64):
    return (b"TSC1" + b"".join(bytes([index + 1]) * 32 for index in range(11))
            + struct.pack("<QQQ", budget, delivery, dispute))


def case(raw, code, *, scratch=SCRATCH, copied=None):
    after = scratch if copied is None else copied + scratch[len(copied):]
    return raw, code, scratch, after


class Pnx1AdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost")
        cls.addClassCleanup(cls.native.close)

    def check(self, cases):
        for start in range(0, len(cases), 48):
            batch = cases[start:start + 48]
            results = self.native.call_many([("f0", [raw, OUTPUT, scratch])
                                            for raw, _, scratch, _ in batch])
            self.assertEqual(len(results), len(batch))
            for index, (result, (raw, code, _, after)) in enumerate(zip(results, batch), start):
                with self.subTest(case=index, tag=raw[92] if len(raw) > 92 else None):
                    result.require_returned()
                    self.assertEqual((result.abi_status, result.value), (0, code))
                    self.assertEqual(result.arguments, [raw, OUTPUT, after])

    def test_opaque_payload_identity_signature_and_legacy_length_dispatch(self):
        # These exact sizes come from pon_wire::payload_len, including the
        # original qualified-work constants 584+68,344,144,584+100,344+684.
        sizes = {1: 40, 3: 32, 4: 64, 6: 176, 7: 104, 10: 112, 11: 136,
                 12: 32, 13: 652, 14: 96, 15: 168, 17: 128, 18: 344,
                 19: 344, 20: 144, 21: 684, 22: 1028}
        cases = []
        for tag, size in sizes.items():
            for fill in (0, 255):
                raw = packet(tag, bytes([fill]) * size, identity=bytes([fill]) * 64,
                             signature=bytes([fill]) * 64)
                cases.append(case(raw, 0, scratch=b""))
        # Legacy dispatch is solely by length; a recognizable funded magic
        # inside the legacy extent must not activate the funded decoder.
        cases.extend([
            case(packet(2, b"TSC1" + bytes(76)), 0, scratch=b""),
            case(packet(5, b"TSD1" + bytes(60)), 0, scratch=b""),
            case(packet(9, bytes(73)), 0, scratch=b""),
        ])
        # Tag8 values and its first 32-byte key may be zero; only strict key
        # order/count are enforced here, never an allocation-sum rule.
        allocations = bytes(144) + b"\x02" + bytes(32) + struct.pack("<Q", MAX_U64)
        allocations += b"\xff" * 32 + struct.pack("<Q", MAX_U64)
        cases.append(case(packet(8, allocations), 0, scratch=b""))
        # Nested evidence has opaque bytes, despite being sized like envelopes.
        evidence = (bytes(32) + struct.pack("<H", 159) + bytes(159)
                    + struct.pack("<H", 512) + b"\xff" * 512)
        cases.append(case(packet(16, evidence), 0, scratch=b""))
        self.check(cases)

    def test_funded_deadline_carries_and_only_provider_arbitrator_inequality(self):
        cases = []
        for lower, higher in ((255, 256), (65535, 65536), ((1 << 32) - 1, 1 << 32),
                              ((1 << 63) - 1, 1 << 63), (MAX_U64 - 1, MAX_U64)):
            cases.append(case(packet(2, funded(delivery=lower, dispute=higher)), 0, scratch=b""))
            cases.append(case(packet(2, funded(delivery=higher, dispute=lower)), 3, scratch=b""))
        base = funded()
        for source_index in range(11):
            source = base[4 + source_index * 32:36 + source_index * 32]
            changed = replace(base, 324, source)
            cases.append(case(packet(2, changed), 3 if source_index == 2 else 0, scratch=b""))
        # Eleven commitments can share data except the exact provider/arbiter
        # pair; there is no undeclared distinctness requirement for other roles.
        same = b"TSC1" + b"\x61" * (32 * 10) + b"\x62" * 32 + struct.pack("<QQQ", 1, 255, 256)
        cases.append(case(packet(2, same), 0, scratch=b""))
        for offset in (0, 15, 31):
            one = bytes(offset) + b"\x01" + bytes(31 - offset)
            changed = b"TSC1" + one * 10 + b"\x02" * 32 + struct.pack("<QQQ", 1, 255, 256)
            cases.append(case(packet(2, changed), 0, scratch=b""))
        self.check(cases)

    def test_inner_refusals_precede_nonce_fee_and_outer_limits_precede_all(self):
        cases = []
        for tag, payload, expected in (
            (2, b"BAD!" + funded()[4:], 2),
            (5, b"BAD!" + bytes(129), 2),
            (8, bytes(144) + b"\x00", 4),
            (8, bytes(144) + b"\x01", 1),
            (9, bytes(72) + b"\x09", 4),
            (9, bytes(72) + b"\x01", 1),
            (16, bytes(32) + struct.pack("<HH", 158, 159), 1),
            (255, b"", 2),
        ):
            cases.append(case(packet(tag, payload, nonce=0, fee=MAX_U64), expected, scratch=b""))
        good = evolution()
        early_bad = replace(good, 244, b"\0\x80")
        later_bad_header = replace(early_bad, 764, b"\x05")
        for payload, expected in (
            (replace(factor(), 0, b"BAD!"), 2),
            (replace(factor(), 6, b"\x03"), 4),
            (factor()[:-1], 1),
            (early_bad, 3), (later_bad_header, 4),
            (early_bad[:767], 1), (early_bad + b"\0", 1),
        ):
            tag = 23 if payload[:4] in (b"ILF2", b"BAD!") else 24
            cases.append(case(packet(tag, payload, nonce=0, fee=MAX_U64), expected, copied=payload))
        # 2048 is admitted to grammar checking, 2049 fails Limit even when
        # magic, nonce, length declaration and inner payload are all invalid.
        oversized = bytearray(packet(24, b"\0" * 1890, nonce=0, fee=MAX_U64))
        oversized[:4] = b"BAD!"
        cases.append(case(bytes(oversized), 4, scratch=b""))
        bounded = packet(24, b"\0" * 1889, nonce=0, fee=MAX_U64)
        cases.append(case(bounded, 1, copied=b"\0" * 1889))
        mismatch = replace(packet(255, b""), 93, b"\xff\xff")
        cases.append(case(mismatch, 1, scratch=b""))
        self.check(cases)

    def test_stale_scratch_cannot_complete_a_truncated_factor_payload(self):
        cases = []
        for tag, full in ((23, factor()), (24, evolution())):
            # The suffix contains the precise bytes needed to complete the
            # original valid witness. They are outside the declared span.
            scratch = full + b"\0\x80" * 500
            cut_points = (0, 5, 9, 241, 242, 243, 244, len(full) - 1)
            if tag == 24:
                cut_points += (764, 765, 766, 767)
            for cut in cut_points:
                payload = full[:cut]
                cases.append(case(packet(tag, payload), 1, scratch=scratch, copied=payload))
        self.check(cases)

    def test_empty_evolution_ignores_live_and_poisoned_scratch_suffixes(self):
        cases = []
        for mask in range(1, 8):
            empty = evolution((), mask)
            self.assertEqual(len(empty), 242)
            scratch = empty + evolution()[242:] + b"\0\x80" * 800
            cases.append(case(packet(24, empty), 0, scratch=scratch, copied=empty))
            cases.append(case(packet(24, empty, nonce=0), 3, scratch=scratch, copied=empty))
        self.check(cases)

    def test_scratch_extent_error_is_local_and_outer_failures_do_not_write(self):
        cases = []
        for tag, payload in ((23, factor(2, 2)), (24, evolution(((0, 1), (2, 1), (4, 1))))):
            for bad_payload in (payload, replace(payload, 0, b"BAD!")):
                short = b"\xa7" * (len(payload) - 1)
                cases.append(case(packet(tag, bad_payload), 100, scratch=short))
            cases.append(case(packet(tag, payload), 0, scratch=bytes(len(payload)), copied=payload))
            # A misleading u16 length and an unknown tag cannot enter the copy.
            incorrect = replace(packet(tag, payload), 93, struct.pack("<H", len(payload) - 1))
            cases.append(case(incorrect, 1, scratch=b""))
            cases.append(case(packet(255, payload), 2, scratch=b""))
        for tag in (23, 24):
            # Empty buffers are real borrowed ABI values, not a missing result.
            cases.append(case(packet(tag, b""), 1, scratch=b"", copied=b""))
            cases.append(case(packet(tag, b"x"), 100, scratch=b""))
        self.check(cases)


if __name__ == "__main__":
    unittest.main()
