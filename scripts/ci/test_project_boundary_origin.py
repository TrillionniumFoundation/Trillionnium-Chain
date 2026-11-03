#!/usr/bin/env python3
"""Exact-origin admission regression for the protected Chain source boundary."""
import unittest

from project_boundary import is_authorized_origin

REPO = "TrillionniumFoundation/Trillionnium-Chain"


class OriginAdmissionTests(unittest.TestCase):
    def test_exact_github_checkout_https_and_git_ssh(self):
        for value in (
            f"https://github.com/{REPO}",
            f"https://github.com/{REPO}.git",
            f"git@github.com:{REPO}.git",
        ):
            with self.subTest(value=value):
                self.assertTrue(is_authorized_origin(value))

    def test_rejects_redirects_aliases_and_repository_confusion(self):
        for value in (
            f"https://github.com/{REPO}/",
            f"https://github.com/{REPO}.git/",
            f"http://github.com/{REPO}.git",
            f"https://github.com.evil.test/{REPO}.git",
            f"https://evil@github.com/{REPO}.git",
            f"https://github.com:443/{REPO}.git",
            f"https://github.com/{REPO}.git?token=evil",
            "https://github.com/TrillionniumFoundation/Hepta.git",
            "https://github.com/TrillionniumFoundation/Trillionnium-Chain-evil.git",
            "https://github.com/trillionniumfoundation/Trillionnium-Chain.git",
            f"ssh://git@github.com/{REPO}.git",
            f"git@github.com:{REPO}",
            f"git@evil.test:{REPO}.git",
            "/tmp/Trillionnium-Chain",
            "",
            REPO,
        ):
            with self.subTest(value=value):
                self.assertFalse(is_authorized_origin(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
