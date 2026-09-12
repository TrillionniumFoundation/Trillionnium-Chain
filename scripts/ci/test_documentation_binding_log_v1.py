#!/usr/bin/env python3
"""M17 negative corpus for complete documentation-binding retention."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import documentation_binding_log_v1 as codec

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/documentation_binding_log_v1.py"


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.data = json.dumps({"source_commit": "a" * 40, "payload": "x" * 4000}).encode()
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.log = codec.encode_binding(self.data, self.digest, "source")

    def recover(self, log=None, digest=None, mode="source"):
        return codec.recover_binding(self.log if log is None else log,
                                     self.digest if digest is None else digest, mode)

    def test_exact_source_roundtrip(self):
        self.assertEqual(self.recover(), self.data)

    def test_exact_merge_roundtrip(self):
        self.assertEqual(self.recover(self.log.replace(" source ", " merge "), mode="merge"), self.data)

    def test_timestamped_log(self):
        log = "setup complete\n" + "".join("2026-09-12T15:00:00.123Z " + x + "\n" for x in self.log.splitlines())
        self.assertEqual(self.recover(log), self.data)

    def test_other_mode_is_not_credited(self):
        with self.assertRaises(ValueError):
            self.recover(mode="merge")

    def test_wrong_digest(self):
        with self.assertRaises(ValueError):
            self.recover(digest="f" * 64)

    def test_digest_only_log_is_insufficient(self):
        with self.assertRaises(ValueError):
            self.recover("TRNM_DOCUMENTATION_SOURCE_BINDING_SHA256=" + self.digest)

    def test_missing_chunk(self):
        with self.assertRaises(ValueError):
            self.recover(self.log.splitlines()[0])

    def test_duplicate_chunk(self):
        with self.assertRaises(ValueError):
            self.recover(self.log + self.log)

    def test_reordered_chunks(self):
        with self.assertRaises(ValueError):
            self.recover("\n".join(reversed(self.log.splitlines())))

    def test_mixed_digest(self):
        lines = self.log.splitlines()
        lines[1] = lines[1].replace(self.digest, "b" * 64)
        with self.assertRaises(ValueError):
            self.recover("\n".join(lines))

    def test_mixed_size(self):
        lines = self.log.splitlines()
        lines[1] = lines[1].replace(str(len(self.data)), str(len(self.data) + 1))
        with self.assertRaises(ValueError):
            self.recover("\n".join(lines))

    def test_zero_chunk_count(self):
        with self.assertRaises(ValueError):
            self.recover(self.log.replace("/2 ", "/0 "))

    def test_changed_payload(self):
        lines = self.log.splitlines()
        lines[0] = lines[0][:-1] + ("A" if lines[0][-1] != "A" else "B")
        with self.assertRaises(ValueError):
            self.recover("\n".join(lines))

    def test_noncanonical_chunk_size(self):
        with self.assertRaises(ValueError):
            self.recover(self.log.replace("1/2 ", "1/2 A"))

    def test_malformed_record(self):
        with self.assertRaises(ValueError):
            self.recover("TRNM_DOC_BINDING_V1 source invalid")

    def test_invalid_mode(self):
        with self.assertRaises(ValueError):
            self.recover(mode="local")

    def test_changed_file_after_hash(self):
        with self.assertRaises(ValueError):
            codec.encode_binding(self.data + b" ", self.digest, "source")

    def test_invalid_json_rejected(self):
        for data in (b"", b"[]", b"null", b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":"\xff"}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                codec.encode_binding(data, hashlib.sha256(data).hexdigest(), "source")

    def test_maximum_binding_roundtrip(self):
        data = b'{"x":"' + b"x" * (codec.MAX_BYTES - 8) + b'"}'
        self.assertEqual(len(data), codec.MAX_BYTES)
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(codec.recover_binding(codec.encode_binding(data, digest, "source"), digest, "source"), data)

    def test_oversized_binding(self):
        data = b'{"x":"' + b"x" * codec.MAX_BYTES + b'"}'
        with self.assertRaises(ValueError):
            codec.encode_binding(data, hashlib.sha256(data).hexdigest(), "source")

    def test_log_bound(self):
        with patch.object(codec, "MAX_LOG_BYTES", 10), self.assertRaises(ValueError):
            self.recover()

    def test_unicode_and_original_whitespace_retained(self):
        data = '{ "note": "验证" }\n'.encode()
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(codec.recover_binding(codec.encode_binding(data, digest, "source"), digest, "source"), data)

    def test_cli_exclusive_output_and_no_output_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, log, output = root / "binding.json", root / "job.log", root / "out.json"
            source.write_bytes(self.data)
            emitted = subprocess.run([sys.executable, str(SCRIPT), "emit", "--binding", str(source),
                "--expected-sha256", self.digest, "--mode", "source"], capture_output=True)
            self.assertEqual(emitted.returncode, 0, emitted.stderr)
            log.write_bytes(emitted.stdout)
            args = [sys.executable, str(SCRIPT), "recover", "--log", str(log), "--output", str(output),
                "--expected-sha256", self.digest, "--mode", "source"]
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertEqual(output.read_bytes(), self.data)
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)
            self.assertEqual(output.read_bytes(), self.data)
            output.unlink()
            log.write_text("digest only")
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)
            self.assertFalse(output.exists())

    def test_workflow_retains_both_payloads(self):
        workflow = (ROOT / ".github/workflows/trnm-documentation-truth.yml").read_text()
        for mode in ("source", "merge"):
            self.assertIn(f'--expected-sha256 "${{digest}}" --mode {mode}', workflow)
        self.assertEqual(workflow.count("python3 scripts/ci/documentation_binding_log_v1.py emit"), 2)
        self.assertEqual(workflow.count("runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]"), 2)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("continue-on-error:", workflow)

    def test_hosted_baseline_executes_regression(self):
        workflow = (ROOT / ".github/workflows/trnm-required-baseline.yml").read_text()
        self.assertIn("python3 scripts/ci/test_documentation_binding_log_v1.py", workflow)


if __name__ == "__main__":
    unittest.main()
