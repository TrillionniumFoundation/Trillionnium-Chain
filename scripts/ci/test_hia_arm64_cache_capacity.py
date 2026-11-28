"""Static/receipt controls; synthetic ELF headers never claim execution."""
import hashlib
import json
from pathlib import Path
import platform
import struct
import tempfile
import unittest

import hia_arm64_cache_capacity as x


class StaticChecks(unittest.TestCase):
    def test_exact_corpus(self):
        rows = x.corpus().splitlines()
        self.assertEqual(len(rows), 553)
        self.assertEqual(len(rows[0].split()), 4)
        self.assertEqual(rows[0], b"262144 1 1 1")
        self.assertEqual(hashlib.sha256(x.corpus()).hexdigest(), "e32e43f493c4dd8f00bc9a165bf25cdcc9bd1945a2197e110adf0aa79e8d02e0")

    def test_wrong_elf_type_and_machine_refused(self):
        b = bytearray(64)
        b[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", b, 16, 1, 62, 1)
        with self.assertRaises(ValueError):
            x.elf(b, {1})
        struct.pack_into("<HHI", b, 16, 2, 183, 1)
        with self.assertRaises(ValueError):
            x.elf(b, {1})
        with self.assertRaises(ValueError):
            x.elf(bytes(b[:63]), {2})

    def test_raw_output_refusals(self):
        a = [b"1 1"] * 553
        a[0] = b"329632 65536"
        a[20] = b"2211908223392 4295032832"
        a[23:41] = [b"0 0"] * 18
        a[-256:] = [b"0 0"] * 256
        raw = b"\n".join(a) + b"\n"
        for original, native in ((raw, raw[:-1]), (raw[:-2], raw[:-2]), (raw+b"0 0\n",)*2,
                                 (b"9"+raw,)*2, (raw.replace(b"1 1",b"1 +1"),)*2,
                                 (raw.replace(b"1 1",b"18446744073709551616 1"),)*2):
            with self.subTest(), self.assertRaises(ValueError):
                x.compare(original, native)

    def test_packet_rejects_binding_before_opening_artifacts(self):
        with tempfile.TemporaryDirectory() as raw:
            p = Path(raw)
            (p / "report.json").write_text(json.dumps({
                "schema": "trnm-hia-arm64-cache-capacity-v1",
                "status": "PASS_DIAGNOSTIC_ONLY", "head": "a"*40, "tree": "b"*40,
                "run": "123", "attempt": "1",
            }))
            for args in (dict(head="z"*40), dict(tree="z"*40), dict(run_id="124"), dict(attempt="2")):
                expected = dict(head="a"*40, tree="b"*40, run_id="123", attempt="1")
                expected.update(args)
                with self.subTest(args=args), self.assertRaisesRegex(ValueError, "mismatched source/run/attempt"):
                    x.verify_packet(p, **expected)

    def test_x64_cannot_claim_arm_execution(self):
        if platform.machine() != "aarch64":
            with self.assertRaises(ValueError):
                x.require_arm()

    def test_wrong_binding_refused(self):
        with self.assertRaises(ValueError):
            x.bound_sources(Path.cwd(), "not a hash")


if __name__ == "__main__":
    unittest.main()
