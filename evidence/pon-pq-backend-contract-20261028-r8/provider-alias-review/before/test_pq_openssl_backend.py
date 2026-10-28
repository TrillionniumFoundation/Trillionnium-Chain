"""Backend selection/failure controls; no successful cryptographic substitute.

The local fault driver reports only a version and refuses every crypto command.
Real ML-DSA success remains in the original native and reference owner tests.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from pq_operation_budget import OperationBudget
from pq_openssl_backend import BackendError, binding, run


class PQOpenSSLBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pq-backend-fault-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "bin").mkdir()
        self.exe = self.root / "bin/openssl"
        self.marker = self.root / "invocations.jsonl"
        self.env = {
            "OPENSSL_DIR": str(self.root),
            "TRNM_PQ_OPENSSL": str(self.exe),
            "TRNM_PQ_OPENSSL_VERSION": "3.5.9",
            "OPENSSL_CONF": "/unexpected/config",
            "OPENSSL_MODULES": "/unexpected/modules",
        }
        self.write_driver()
        self.environment = patch.dict(os.environ, self.env)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def write_driver(self, version="3.5.9", *, pause=False):
        self.exe.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys, time\n"
            f"with pathlib.Path({str(self.marker)!r}).open('a') as output:\n"
            "    output.write(json.dumps({'args':sys.argv[1:], 'conf':os.environ.get('OPENSSL_CONF'),"
            "'modules':os.environ.get('OPENSSL_MODULES')})+'\\n')\n"
            + ("time.sleep(60)\n" if pause else "")
            + "if sys.argv[1:] == ['version']:\n"
            f"    print('OpenSSL {version} test metadata only'); sys.exit(0)\n"
            "sys.stderr.write('FAULT_PRIVATE_INPUT_MARKER ' + 'x'*2048)\n"
            "sys.exit(23)\n"
        )
        self.exe.chmod(0o700)
        self.env["TRNM_PQ_OPENSSL_SHA256"] = hashlib.sha256(self.exe.read_bytes()).hexdigest()

    def rows(self):
        return [json.loads(x) for x in self.marker.read_text().splitlines()] if self.marker.exists() else []

    def test_pinned_failure_uses_absolute_cli_default_provider_and_isolated_config(self):
        self.assertEqual(binding().executable, self.exe)
        with self.assertRaises(BackendError) as result:
            run(["pkey", "-pubin", "-in", "/unused-public-input"])
        self.assertIn("exit=23", str(result.exception))
        rows = self.rows()
        self.assertEqual([x["args"] for x in rows],
                         [["version"], ["pkey", "-provider", "default", "-pubin", "-in", "/unused-public-input"]])
        self.assertTrue(all(x["conf"] == os.devnull for x in rows))
        self.assertTrue(all(x["modules"] == str(self.root / "lib/ossl-modules") for x in rows))

    def test_missing_declaration_never_uses_path(self):
        for key in ("OPENSSL_DIR", "TRNM_PQ_OPENSSL", "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION"):
            with self.subTest(key=key), patch.dict(os.environ, {key: "", "PATH": str(self.root / "bin")}):
                with self.assertRaises(BackendError):
                    run(["pkey", "-pubin"])
        self.assertEqual(self.rows(), [])

    def test_relative_or_noncanonical_or_symlink_cli_rejects(self):
        alias = self.root / "alias"
        alias.symlink_to(self.exe)
        for raw in ("openssl", str(alias), str(self.root / "bin/../bin/openssl"), str(self.exe)+"\n"):
            with self.subTest(path=raw), patch.dict(os.environ, {"TRNM_PQ_OPENSSL": raw}):
                with self.assertRaises(BackendError):
                    run(["genpkey"])
        self.assertEqual(self.rows(), [])

    def test_cli_and_rust_prefix_mismatch_rejects_before_child(self):
        with patch.dict(os.environ, {"OPENSSL_DIR": str(self.root / "bin")}):
            with self.assertRaisesRegex(BackendError, "prefix differ"):
                run(["pkey"])
        self.assertEqual(self.rows(), [])

    def test_executable_digest_mismatch_rejects_before_child(self):
        for value in ("0"*64, "a"*63, "A"*64):
            with self.subTest(value=value), patch.dict(os.environ, {"TRNM_PQ_OPENSSL_SHA256": value}):
                with self.assertRaises(BackendError):
                    run(["pkey"])
        self.assertEqual(self.rows(), [])

    def test_unsupported_declared_version_rejects_before_child(self):
        for value in ("3.4.9", "3.5", "latest", "3.5.9\n"):
            with self.subTest(version=value), patch.dict(os.environ, {"TRNM_PQ_OPENSSL_VERSION": value}):
                with self.assertRaises(BackendError):
                    run(["pkey"])
        self.assertEqual(self.rows(), [])

    def test_actual_version_mismatch_never_reaches_crypto(self):
        self.write_driver(version="3.4.9")
        with patch.dict(os.environ, self.env), self.assertRaisesRegex(BackendError, "actual version differs"):
            run(["pkey"])
        self.assertEqual([x["args"] for x in self.rows()], [["version"]])

    def test_provider_configuration_and_command_shape_overrides_reject(self):
        for args in ([], ["s_client"], ["pkey", 7], ["pkey", "\x00"],
                     ["pkey", "-provider", "legacy"], ["pkey", "-engine=x"],
                     ["pkey", "-provider-path=/tmp"], ["pkey", "-config", "/tmp/x"]):
            with self.subTest(args=args), self.assertRaises(BackendError):
                run(args)
        self.assertEqual(self.rows(), [])

    def test_signing_failure_never_exposes_private_input_diagnostic(self):
        with self.assertRaises(BackendError) as result:
            run(["pkeyutl", "-sign"], input_data=b"ephemeral test message")
        message = str(result.exception)
        self.assertIn("stderr_sha256=", message)
        self.assertNotIn("FAULT_PRIVATE_INPUT_MARKER", message)
        self.assertNotIn("public_diagnostic", message)

    def test_public_failure_diagnostic_is_bounded(self):
        with self.assertRaises(BackendError) as result:
            run(["pkeyutl", "-verify", "-pubin"])
        message = str(result.exception)
        self.assertIn("public_diagnostic", message)
        self.assertLess(len(message), 1300)

    def test_expired_original_budget_never_launches_backend(self):
        with self.assertRaises(BackendError):
            run(["pkey"], budget=OperationBudget(time.monotonic()-1))
        self.assertEqual(self.rows(), [])

    def test_version_lookup_consumes_the_original_absolute_budget(self):
        self.write_driver(pause=True)
        started = time.monotonic()
        with patch.dict(os.environ, self.env), self.assertRaises(BackendError):
            run(["pkey"], budget=OperationBudget(started+0.2))
        self.assertLess(time.monotonic()-started, 1)
        self.assertEqual([x["args"] for x in self.rows()], [["version"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
