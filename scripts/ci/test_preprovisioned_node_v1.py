#!/usr/bin/env python3
"""M17 negative corpus: exact runner cache selection, no bootstrap fallback."""
from __future__ import annotations
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("check_preprovisioned_node_v1.py")
SPEC = importlib.util.spec_from_file_location("pinned_node", SCRIPT)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class PinnedNodeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / "cache"
        self.tool = self.cache / "node/24.18.0/x64"
        (self.tool / "bin").mkdir(parents=True)
        self.marker = self.tool.with_name("x64.complete")
        self.marker.touch()
        for name in ("node", "npm", "npx"):
            p = self.tool / "bin" / name
            p.write_text("fixture", encoding="utf-8")
            p.chmod(0o755)
        self.path_file = self.root / "path"
        self.path_file.write_text("existing\n")
        self.environment = mock.patch.dict(os.environ, {
            "RUNNER_TOOL_CACHE": str(self.cache), "NODE_OPTIONS": "", "NODE_PATH": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.which = mock.patch.object(M.shutil, "which", side_effect=lambda name: str(self.tool / "bin" / name)).start()
        self.run = mock.patch.object(M.subprocess, "run", side_effect=self.probe).start()
        self.addCleanup(mock.patch.stopall)

    def probe(self, args, **kwargs):
        if args[1] == "-p":
            output = json.dumps({"version": "24.18.0", "arch": "x64", "platform": "linux"})
        else:
            output = "11.16.0\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    def call(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return M.main(["--version", "24.18.0", *args])

    def assert_rejected(self):
        self.assertEqual(self.call(), 2)
        self.assertEqual(self.path_file.read_text(), "existing\n")

    def test_complete_exact_cache(self):
        self.assertEqual(self.call(), 0)
        self.assertEqual(self.path_file.read_text(), "existing\n")
        self.assertEqual(self.run.call_count, 2)
        self.assertEqual(self.run.call_args.args[0][0], str(self.tool / "bin/node"))

    def test_numeric_versions_only(self):
        for value in ("24", "v24.18.0", "latest", "24.x", "24.18.0\n/path", "../24.18.0", "024.18.0"):
            with self.subTest(value=value), self.assertRaises(M.NodeProvisionError):
                M.exact_version(value)

    def test_no_completion_marker(self):
        self.marker.unlink(); self.assert_rejected(); self.run.assert_not_called()

    def test_missing_cache_environment(self):
        os.environ.pop("RUNNER_TOOL_CACHE"); self.assert_rejected(); self.run.assert_not_called()

    def test_relative_cache_rejected(self):
        os.environ["RUNNER_TOOL_CACHE"] = "cache"; self.assert_rejected(); self.run.assert_not_called()

    def test_missing_node(self):
        (self.tool / "bin/node").unlink(); self.assert_rejected()

    def test_nonexecutable_node(self):
        (self.tool / "bin/node").chmod(0o644); self.assert_rejected()

    def test_missing_npm(self):
        (self.tool / "bin/npm").unlink(); self.assert_rejected()

    def test_missing_npx(self):
        (self.tool / "bin/npx").unlink(); self.assert_rejected()

    def test_outside_npm_symlink(self):
        p = self.tool / "bin/npm"; p.unlink(); p.symlink_to(self.path_file); self.assert_rejected()

    def test_internal_npm_symlink_allowed(self):
        p = self.tool / "bin/npm"; p.unlink()
        dest = self.tool / "lib/npm-cli.js"; dest.parent.mkdir(); dest.write_text("fixture")
        p.symlink_to("../lib/npm-cli.js"); self.assertEqual(self.call(), 0)

    def test_symlink_completion_marker_rejected(self):
        self.marker.unlink(); self.marker.symlink_to(self.path_file); self.assert_rejected()

    def test_identity_mismatch(self):
        for key, value in (("version", "22.18.0"), ("arch", "arm64"), ("platform", "darwin")):
            identity = {"version": "24.18.0", "arch": "x64", "platform": "linux", key: value}
            self.run.side_effect = lambda *a, **kw: subprocess.CompletedProcess(a, 0, json.dumps(identity), "")
            with self.subTest(key=key): self.assert_rejected()

    def test_probe_failure(self):
        self.run.side_effect = subprocess.CalledProcessError(1, "node"); self.assert_rejected()

    def test_probe_timeout(self):
        self.run.side_effect = subprocess.TimeoutExpired("node", 15); self.assert_rejected()

    def test_malformed_identity(self):
        self.run.side_effect = lambda *a, **kw: subprocess.CompletedProcess(a, 0, "not-json", "")
        self.assert_rejected()

    def test_node_hooks_rejected(self):
        for key in ("NODE_OPTIONS", "NODE_PATH"):
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: "untrusted"}): self.assert_rejected()
        self.run.assert_not_called()

    def test_current_command_mismatch(self):
        self.which.side_effect = lambda name: "/usr/bin/" + name
        self.assert_rejected()
        self.run.assert_not_called()

    def test_current_command_missing(self):
        self.which.return_value = None
        self.which.side_effect = None
        self.assert_rejected()
        self.run.assert_not_called()

    def test_environment_not_mutated(self):
        before = dict(os.environ)
        self.assertEqual(self.call(), 0)
        self.assertEqual(dict(os.environ), before)

    def test_version_file(self):
        version = self.root / "version"; version.write_text("24.18.0\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(["--version-file", str(version)]), 0)

    def test_missing_version_file(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(M.main(["--version-file", str(self.root / "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
