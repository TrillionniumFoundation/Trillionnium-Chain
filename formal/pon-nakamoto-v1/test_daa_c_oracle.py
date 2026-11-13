"""Independent C/OpenSSL BIGNUM ASERT differential (research-only).

Not a cryptographic hardness proof, live consensus implementation, or a
production safety/availability test. The frozen 512-case seed matrix is shared
with the Go and Python campaigns, but the C arithmetic implementation is
independent of those two oracles.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from daa_go_differential import run
from daa_research_oracle import asert_target

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "daa_reference_c.c"


class NativeCAsertReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("cc"):
            raise unittest.SkipTest("requires C compiler")
        cls._tempdir = tempfile.TemporaryDirectory(prefix="trnm-asert-c-")
        cls.binary = Path(cls._tempdir.name) / "asert-c"
        # Compilation is a real prerequisite. Missing OpenSSL BIGNUM headers
        # or linker is a test failure, never a fallback to the Python oracle.
        subprocess.run(
            ["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(SOURCE), "-lcrypto", "-o", str(cls.binary)],
            check=True, text=True, capture_output=True, timeout=45,
        )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "_tempdir"):
            cls._tempdir.cleanup()

    def test_512_cases_each_of_three_seeded_campaigns(self):
        for seed in (20261025, 42, 99173):
            with self.subTest(seed=seed):
                receipt = run(self.binary, 512, seed)
                self.assertTrue(receipt["all_equal"])
                self.assertEqual(receipt["compared"] + receipt["rejected"], 512)
                self.assertEqual(receipt["valid_w1_proofs"], 0)
                self.assertFalse(receipt["consensus_activation"])

    def test_invalid_arguments_never_default_to_valid_targets(self):
        result = subprocess.run(
            [str(self.binary), "--anchor", "f" * 64],
            check=False, text=True, capture_output=True, timeout=3,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.strip(), "ASERT_RESEARCH_ARGUMENTS")

    def test_high_magnitude_reference_cases_match_python(self):
        anchor = (1 << 255) - 1
        cap = (1 << 256) - 1
        for time in (0, 1, 600, 7200, (1 << 64) - 1):
            args = [str(self.binary), "--anchor", f"{anchor:064x}",
                    "--limit", f"{cap:064x}", "--anchor-parent-time", "0",
                    "--parent-time", str(time), "--anchor-height", "1",
                    "--height", "2", "--spacing", "10", "--half-life", "7200"]
            r = subprocess.run(args, text=True, capture_output=True, timeout=3, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), f"{asert_target(anchor,0,time,1,2,10,7200,cap):064x}")


if __name__ == "__main__":
    unittest.main()
