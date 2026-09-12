#!/usr/bin/env python3
"""M17 negative corpus for complete documentation-binding retention."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import documentation_binding_log_v1 as codec
import check_documentation_contracts_v1 as contracts
import check_documentation_reference_closure_v1 as closure

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



class WorkflowSourceBindingTests(unittest.TestCase):
    """A same-tree merge is still a different source commit from the PR head."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        self.root = self.parent / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "M17 test fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / "source.txt").write_text("same tree, distinct commit identities\n")
        self.git("add", "source.txt")
        self.tree = self.git("write-tree")
        self.base = self.git("commit-tree", self.tree, "-m", "base fixture")
        self.head = self.git("commit-tree", self.tree, "-p", self.base, "-m", "head fixture")
        self.merge = self.git("commit-tree", self.tree, "-p", self.base, "-p", self.head,
                              "-m", "prospective merge fixture")
        self.event = self.parent / "event.json"
        self.event.write_text(json.dumps({"number": 128, "pull_request": {
            "number": 128, "head": {"sha": self.head}, "base": {"sha": self.base}}}))
        root_patch = patch.object(closure, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        env_patch = patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(self.event),
                                           "GITHUB_SHA": self.merge})
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True,
                              capture_output=True, text=True).stdout.strip()

    def checkout(self, sha):
        self.git("checkout", "--detach", "--force", sha)

    def test_workflow_keeps_source_head_binding(self):
        workflow = (ROOT / ".github/workflows/trnm-documentation-truth.yml").read_text()
        global_env, jobs = workflow.split("\njobs:\n", 1)
        self.assertIn("  TRNM_EXPECTED_SOURCE_SHA: ${{ github.event_name == 'pull_request' "
                      "&& github.event.pull_request.head.sha || github.sha }}", global_env)
        source = jobs.split("  prospective-merge:\n", 1)[0]
        self.assertIn("ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}", source)
        self.assertNotIn("\n    env:\n", source.split("    steps:\n", 1)[0])

    def test_workflow_merge_overrides_inherited_head_binding(self):
        workflow = (ROOT / ".github/workflows/trnm-documentation-truth.yml").read_text()
        merge = workflow.split("  prospective-merge:\n", 1)[1]
        job_scope, steps = merge.split("    steps:\n", 1)
        self.assertIn("    env:\n      TRNM_EXPECTED_SOURCE_SHA: ${{ github.sha }}\n", job_scope)
        self.assertIn("ref: ${{ github.sha }}", steps)
        self.assertIn("TRNM_DOC_BINDING_MODE: merge", steps)

    def test_source_contract_accepts_pr_head_not_event_merge(self):
        self.checkout(self.head)
        self.assertEqual(contracts.source_identity(self.root, self.head), (self.head, self.tree))
        binding = closure.runtime_binding("source")
        self.assertEqual(binding["source_commit"], self.head)
        self.assertEqual(binding["pull_request_head"], self.head)
        self.assertEqual(binding["event_merge_commit"], self.merge)

    def test_merge_contract_accepts_exact_event_and_ordered_parents(self):
        self.checkout(self.merge)
        self.assertNotEqual(self.head, self.merge)
        self.assertEqual(contracts.source_identity(self.root, self.merge), (self.merge, self.tree))
        binding = closure.runtime_binding("merge")
        self.assertEqual(binding["prospective_merge_commit"], self.merge)
        self.assertEqual(binding["source_tree"], self.tree)
        self.assertEqual(binding["pull_request_head"], self.head)
        self.assertEqual(binding["pull_request_base"], self.base)

    def test_merge_contract_rejects_inherited_head_even_with_identical_tree(self):
        self.checkout(self.merge)
        with self.assertRaises(contracts.DocumentationError) as caught:
            contracts.source_identity(self.root, self.head)
        self.assertEqual(caught.exception.code, "DOC-SOURCE")

    def test_merge_contract_rejects_different_event_commit(self):
        self.checkout(self.merge)
        with patch.dict(os.environ, {"GITHUB_SHA": self.head}):
            with self.assertRaisesRegex(closure.DocumentationTruthError, "not the event commit"):
                closure.runtime_binding("merge")

    def test_merge_contract_rejects_reversed_parent_order(self):
        reversed_merge = self.git("commit-tree", self.tree, "-p", self.head, "-p", self.base,
                                  "-m", "reversed parents fixture")
        self.checkout(reversed_merge)
        with patch.dict(os.environ, {"GITHUB_SHA": reversed_merge}):
            with self.assertRaisesRegex(closure.DocumentationTruthError, "base and head in order"):
                closure.runtime_binding("merge")

    def test_merge_contract_requires_pr_metadata(self):
        self.checkout(self.merge)
        self.event.write_text("{}")
        with self.assertRaisesRegex(closure.DocumentationTruthError, "pull-request metadata"):
            closure.runtime_binding("merge")


if __name__ == "__main__":
    unittest.main()
