#!/usr/bin/env python3
"""Tests the auxiliary lexical checker; never Rust type/behavior acceptance."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


def load_checker(path: Path):
    spec = importlib.util.spec_from_file_location("authority_checker_under_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import checker: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# A delivery copy may specify the sibling patched checker. Inside the repo,
# the actual existing checker is selected. No production artifacts are read.
HERE = Path(__file__).resolve().parent
TARGET = HERE / "check_authenticated_authority_ports_v0.py"
if not TARGET.is_file():
    TARGET = HERE / "patched_authority_checker.py"
CHECKER = load_checker(TARGET)
DECLARATION = "pub struct VerifiedAuthorityIngressV0 {"
BODY = DECLARATION + "\n    field: u64,\n}\n"


class SourceHygieneTests(unittest.TestCase):
    def test_no_attributes_is_accepted(self):
        CHECKER.require_linear_token(BODY, DECLARATION)

    def test_must_use_without_derive_is_accepted(self):
        CHECKER.require_linear_token('#[must_use]\n' + BODY, DECLARATION)

    def test_debug_without_clone_is_accepted(self):
        CHECKER.require_linear_token('#[derive(Debug)]\n' + BODY, DECLARATION)

    def test_comments_are_not_clone_implementations(self):
        CHECKER.require_linear_token('/// deliberately not Clone\n' + BODY, DECLARATION)

    def test_ordinary_clone_derive_rejected(self):
        with self.assertRaises(CHECKER.GateError):
            CHECKER.require_linear_token('#[derive(Debug, Clone)]\n' + BODY, DECLARATION)

    def test_qualified_clone_derive_rejected(self):
        with self.assertRaises(CHECKER.GateError):
            CHECKER.require_linear_token('#[derive(Debug, core::clone::Clone)]\n' + BODY, DECLARATION)

    def test_multiline_clone_derive_rejected(self):
        with self.assertRaises(CHECKER.GateError):
            CHECKER.require_linear_token('#[derive(\n Debug,\n Clone,\n)]\n' + BODY, DECLARATION)

    def test_conditional_clone_derive_rejected(self):
        with self.assertRaises(CHECKER.GateError):
            CHECKER.require_linear_token('#[cfg_attr(test, derive(Clone))]\n' + BODY, DECLARATION)

    def test_manual_clone_rejected(self):
        with self.assertRaises(CHECKER.GateError):
            CHECKER.require_linear_token(BODY + 'impl Clone for VerifiedAuthorityIngressV0 {}\n', DECLARATION)

    def test_manual_qualified_clone_rejected(self):
        for namespace in ('core', 'std'):
            with self.subTest(namespace=namespace), self.assertRaises(CHECKER.GateError):
                CHECKER.require_linear_token(
                    BODY + f'impl {namespace}::clone::Clone for VerifiedAuthorityIngressV0 {{}}\n',
                    DECLARATION,
                )

    def test_missing_declaration_rejected(self):
        with self.assertRaises(CHECKER.GateError):
            CHECKER.require_linear_token('', DECLARATION)

    def test_existing_self_test_retains_all_real_clone_mutants(self):
        CHECKER.self_test()


if __name__ == '__main__':
    unittest.main()
