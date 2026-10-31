#!/usr/bin/env python3
"""Actual local Git remote tests; no access to a network or live repository."""
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("ensure_checkout_origin.sh")
CANONICAL = "https://github.com/TrillionniumFoundation/Trillionnium-Chain"


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


class CheckoutOriginTests(unittest.TestCase):
    def verify_case(self, origin, accept):
        with tempfile.TemporaryDirectory() as work:
            root = pathlib.Path(work)
            git(root, "init", "-q")
            git(root, "remote", "add", "origin", origin)
            result = subprocess.run(["bash", str(SCRIPT)], cwd=root,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode == 0, accept)
            self.assertEqual(git(root, "remote", "get-url", "origin"),
                             CANONICAL + ".git" if accept else origin)

    def test_expected_checkout_spelling_is_normalized(self):
        self.verify_case(CANONICAL, True)

    def test_near_miss_and_untrusted_origins_fail_without_mutation(self):
        bad = (
            CANONICAL + ".git", CANONICAL + "/", CANONICAL + ".evil",
            CANONICAL + "?q=1", "http://github.com/TrillionniumFoundation/Trillionnium-Chain",
            "https://evil.example/TrillionniumFoundation/Trillionnium-Chain",
            "https://github.com/evil/Trillionnium-Chain",
            "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git/",
            "git@github.com:TrillionniumFoundation/Trillionnium-Chain.git",
        )
        for origin in bad:
            with self.subTest(origin=origin):
                self.verify_case(origin, False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
