#!/usr/bin/env python3
"""Retain the real Git attacks for the pinned SDK and captured-source loader."""
from __future__ import annotations

import argparse
from pathlib import Path
import unittest

from mldsa_native_differential import checked_source
from test_mldsa_native_source import NativeSourcePinTests
from tuf_sdk_differential import PinnedSdkLoader, SDK_COMMIT


class TufSdkSourcePinTests(NativeSourcePinTests):
    pinned_commit = SDK_COMMIT
    source_subtree = "securesystemslib"
    source_file = "securesystemslib/signer/_key.py"
    extra_file = "securesystemslib/untracked_module.py"

    @staticmethod
    def check_source(source):
        return checked_source(source, commit=SDK_COMMIT, subtree="securesystemslib")

    def test_changed_source_between_verification_and_capture_is_rejected(self):
        expected = self.check_source(self.checkout)
        path = self.checkout / self.source_file
        path.write_bytes(path.read_bytes() + b"\n# capture race\n")
        with self.assertRaises(ValueError):
            PinnedSdkLoader(self.checkout, expected)

    def test_added_bytecode_cannot_substitute_for_pinned_source(self):
        path = self.checkout / "securesystemslib/__pycache__/__init__.cpython-312.pyc"
        path.parent.mkdir()
        path.write_bytes(b"not an authenticated upstream input")
        with self.assertRaises(ValueError):
            self.check_source(self.checkout)

    def test_import_outside_captured_sdk_cannot_fall_back_to_another_install(self):
        loader = PinnedSdkLoader(self.checkout, self.check_source(self.checkout))
        self.assertIsNotNone(loader.find_spec("securesystemslib.signer._key"))
        with self.assertRaises(ModuleNotFoundError):
            loader.find_spec("securesystemslib.untracked_module")

    def test_upstream_namespace_packages_require_captured_descendants(self):
        loader = PinnedSdkLoader(self.checkout, self.check_source(self.checkout))
        spec = loader.find_spec("securesystemslib._internal")
        self.assertIsNotNone(spec.submodule_search_locations)
        self.assertIn("securesystemslib._internal.utils", loader.modules)
        with self.assertRaises(ModuleNotFoundError):
            loader.find_spec("securesystemslib._internal.external_namespace")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    TufSdkSourcePinTests.upstream = args.source.resolve(strict=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TufSdkSourcePinTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and result.testsRun == 13 and not result.skipped else 1


if __name__ == "__main__":
    raise SystemExit(main())
