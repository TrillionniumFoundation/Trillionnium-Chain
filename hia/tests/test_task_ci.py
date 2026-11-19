"""Bounded orchestration controls; these do not substitute for either native gate."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "tools/qualify_task_ci.py"
SPEC = importlib.util.spec_from_file_location("task_ci_under_test", SOURCE)
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class TaskCiControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="task-ci-controls-")
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)

    def metadata(self):
        repo = self.root / "repo"
        manifest = repo / "trillionnium/crates/trnm-task-kernel/Cargo.toml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("[package]\nname='trnm-task-kernel'\nversion='0.1.0'\n")
        dependency = self.root / "registry/libsqlite3-sys-0.39.1/Cargo.toml"
        dependency.parent.mkdir(parents=True)
        dependency.write_text("[package]\nname='libsqlite3-sys'\nversion='0.39.1'\n")
        source = "registry+https://github.com/rust-lang/crates.io-index"
        metadata = {"packages": [
            {"id": "task", "name": "trnm-task-kernel", "manifest_path": str(manifest)},
            {"id": "sqlite", "name": "libsqlite3-sys", "version": "0.39.1", "manifest_path": str(dependency), "source": source},
        ], "workspace_members": ["task"], "resolve": {"nodes": [
            {"id": "task", "dependencies": ["sqlite"], "deps": [{"pkg": "sqlite"}]},
            {"id": "sqlite", "dependencies": [], "deps": []},
        ]}}
        lock = {"package": [{"name": "libsqlite3-sys", "version": "0.39.1", "source": source, "checksum": "a" * 64}]}
        return metadata, lock, repo, dependency.parent

    def qualification(self, component="task-boundary"):
        return CI.Qualification(component, self.root / "output", Path(sys.executable).resolve().parent)

    def test_actual_graph_selects_only_reachable_dependency(self):
        metadata, lock, repo, dependency = self.metadata()
        metadata["packages"].append({"id": "unused", "name": "libsqlite3-sys", "version": "0.1.0",
                                     "manifest_path": "/unrelated/Cargo.toml"})
        actual, selection = CI.select_dependency(metadata, lock, repo)
        self.assertEqual(actual, dependency)
        self.assertEqual(selection["reachable_packages"], ["sqlite", "task"])

    def test_ambiguous_reachable_dependency_is_rejected(self):
        metadata, lock, repo, _ = self.metadata()
        extra = copy.deepcopy(metadata["packages"][1]); extra["id"] = "duplicate"
        metadata["packages"].append(extra)
        metadata["resolve"]["nodes"].append({"id": "duplicate", "dependencies": [], "deps": []})
        metadata["resolve"]["nodes"][0]["dependencies"].append("duplicate")
        metadata["resolve"]["nodes"][0]["deps"].append({"pkg": "duplicate"})
        with self.assertRaisesRegex(ValueError, "Exactly one"):
            CI.select_dependency(metadata, lock, repo)

    def test_incomplete_and_inconsistent_graphs_are_rejected(self):
        metadata, lock, repo, _ = self.metadata()
        for kind in ("resolve", "edge", "node", "duplicate"):
            changed = copy.deepcopy(metadata)
            if kind == "resolve": changed["resolve"] = None
            if kind == "edge": changed["resolve"]["nodes"][0]["deps"] = []
            if kind == "node": changed["resolve"]["nodes"].pop()
            if kind == "duplicate": changed["packages"].append(changed["packages"][0])
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                CI.select_dependency(changed, lock, repo)

    def test_lock_and_task_manifest_identity_are_required(self):
        metadata, lock, repo, _ = self.metadata()
        for kind in ("lock-source", "checksum", "task-manifest", "version", "workspace"):
            changed, locked = copy.deepcopy(metadata), copy.deepcopy(lock)
            if kind == "lock-source": locked["package"][0]["source"] = "registry+https://unrelated.invalid"
            if kind == "checksum": locked["package"][0].pop("checksum")
            if kind == "task-manifest": changed["packages"][0]["manifest_path"] = "/unrelated/Cargo.toml"
            if kind == "version": changed["packages"][1]["version"] = "0.39.2"
            if kind == "workspace": changed["workspace_members"] = []
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                CI.select_dependency(changed, locked, repo)

    def test_external_bytes_are_preserved_and_deduplicated(self):
        a, b = self.root / "first", self.root / "second"
        a.write_bytes(b"actual original bytes\x00\xff"); b.write_bytes(a.read_bytes()); b.chmod(0o700)
        gate = self.qualification()
        expected = identity(a.read_bytes())
        gate.capture(a, expected); gate.capture(b, expected)
        self.assertEqual(len(gate.objects), 1)
        self.assertEqual(len(gate.references), 2)
        self.assertEqual(gate.references[str(b)]["mode"], 0o700)
        preserved = gate.output / gate.references[str(a)]["path"]
        a.write_bytes(b"changed source")
        with self.assertRaisesRegex(ValueError, "Captured input changed"):
            gate.capture(a)
        self.assertEqual(preserved.read_bytes(), b"actual original bytes\x00\xff")

    def test_output_bytes_are_mapped_without_second_copy(self):
        gate = self.qualification()
        artifact = gate.output / "actual-elf"
        artifact.write_bytes(b"\x7fELF actual retained bytes")
        gate.capture(artifact)
        self.assertEqual(gate.references[str(artifact)]["location"], "output")
        self.assertEqual(gate.references[str(artifact)]["path"], "actual-elf")
        self.assertFalse(gate.objects)

    def test_expected_identity_mismatch_preserves_observed_bytes_and_fails(self):
        source = self.root / "source"; source.write_bytes(b"observed bytes")
        gate = self.qualification()
        with self.assertRaisesRegex(ValueError, "Referenced source identity differs"):
            gate.capture(source, identity(b"different recorded bytes"))
        self.assertEqual((gate.output / gate.references[str(source)]["path"]).read_bytes(), b"observed bytes")

    def test_symlink_cannot_substitute_for_regular_input(self):
        source, link = self.root / "source", self.root / "link"
        source.write_bytes(b"source"); link.symlink_to(source)
        with self.assertRaisesRegex(ValueError, "Regular evidence input"):
            CI.file_identity(link)
        with self.assertRaisesRegex(ValueError, "Canonical captured input"):
            self.qualification().capture(link)

    def test_missing_reference_does_not_discard_other_actual_sources(self):
        gate = self.qualification()
        source = self.root / "present"; source.write_bytes(b"available original bytes")
        provider = gate.output / "provider"; provider.mkdir()
        (provider / "build.json").write_text(json.dumps({"source_before": {
            str(self.root / "absent"): identity(b"unavailable"), str(source): identity(source.read_bytes())}}))
        gate.capture_all()
        self.assertEqual(len(gate.capture_errors), 1)
        self.assertIn(str(source), gate.references)
        self.assertFalse(json.loads((gate.output / "captured-inputs.json").read_text())["complete"])

    def test_consumed_report_cannot_disappear_before_capture(self):
        gate = self.qualification()
        provider = gate.output / "provider"; provider.mkdir()
        report = provider / "build.json"
        report.write_text(json.dumps({"status": "PASS", "finalized": True}))
        gate.passed(report)
        report.unlink()
        gate.capture_all()
        self.assertFalse(gate.report["captured_inputs"]["complete"])
        self.assertTrue(any("disappeared" in row["failure"] for row in gate.capture_errors))

    def test_altered_preserved_object_is_not_complete_capture(self):
        gate = self.qualification()
        source = self.root / "original"; source.write_bytes(b"qualified source")
        gate.capture(source)
        (gate.output / gate.references[str(source)]["path"]).write_bytes(b"altered object")
        gate.capture_all()
        self.assertFalse(gate.report["captured_inputs"]["complete"])

    def test_cleanup_timeout_does_not_receive_a_second_window(self):
        gate = self.qualification()
        class UnreapableProcess:
            pid = 12345
            returncode = None
            def __init__(self): self.waits = []
            def poll(self): return None
            def wait(self, timeout):
                self.waits.append(timeout)
                raise subprocess.TimeoutExpired("unreapable qualification fixture", timeout)
        process = UnreapableProcess()
        with mock.patch.object(CI.subprocess, "Popen", return_value=process), mock.patch.object(CI.os, "killpg") as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                gate.stage("unreapable", ["qualification-fixture"], 1)
        self.assertEqual(len(process.waits), 2)
        self.assertLessEqual(process.waits[1], CI.CLEANUP_SECONDS)
        self.assertEqual(kill.call_count, 1)
        self.assertFalse(gate.report["stages"][0]["cleanup"]["complete"])

    def test_actual_nonzero_exit_keeps_both_raw_streams(self):
        gate = self.qualification()
        with self.assertRaisesRegex(ValueError, "Stage exited unsuccessfully"):
            gate.stage("failure", [sys.executable, "-c", "import sys;print('actual stdout');print('actual stderr',file=sys.stderr);sys.exit(7)"], 3)
        row = gate.report["stages"][0]
        self.assertTrue(row["completed"]); self.assertEqual(row["exit_code"], 7)
        self.assertEqual((gate.output / "stages/failure/stdout.raw").read_bytes(), b"actual stdout\n")
        self.assertEqual((gate.output / "stages/failure/stderr.raw").read_bytes(), b"actual stderr\n")
        self.assertEqual(gate.report["status"], "FAIL")

    def test_actual_timeout_is_killed_and_preserved(self):
        gate = self.qualification()
        with self.assertRaises(subprocess.TimeoutExpired):
            gate.stage("timeout", [sys.executable, "-u", "-c", "import time;print('before timeout');time.sleep(10)"], 0.5)
        row = gate.report["stages"][0]
        self.assertTrue(row["timed_out"]); self.assertFalse(row["completed"])
        self.assertTrue(row["cleanup"]["complete"])
        self.assertEqual(row["exit_code"], -9)
        self.assertEqual((gate.output / "stages/timeout/stdout.raw").read_bytes(), b"before timeout\n")

    def test_missing_executable_and_exhausted_deadline_are_not_passes(self):
        gate = self.qualification()
        with self.assertRaises(FileNotFoundError):
            gate.stage("absent", [str(self.root / "no-executable")], 1)
        self.assertFalse(gate.report["stages"][0]["started"])
        gate.started -= CI.COMPONENT_SECONDS + 1
        with self.assertRaisesRegex(ValueError, "deadline exhausted"):
            gate.stage("expired", [sys.executable, "-c", "raise AssertionError('must not start')"], 1)
        self.assertFalse(gate.report["stages"][1]["started"])
        self.assertEqual((gate.output / "stages/expired/stdout.raw").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
