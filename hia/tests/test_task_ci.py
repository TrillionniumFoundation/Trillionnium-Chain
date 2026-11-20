"""Bounded orchestration controls; these do not substitute for either native gate."""
from __future__ import annotations
import copy
from contextlib import ExitStack
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

    def provider_fixture(self, change=None, component="task-boundary"):
        """Exercise real orchestration admission; no native gate runs in this fixture.

        Both component methods deliberately throw, so even the admitted fixture
        cannot produce a successful qualification report. Process launch is the
        sole substituted operation; passed() reads the actual isolated JSON.
        """
        base = self.root / ("provider-fixture-" + str(len(list(self.root.iterdir()))))
        repo, rust = base / "repo", base / "rust-bin"
        task = repo / "hia/platform/task_kernel";controls = task / "qualification"
        controls.mkdir(parents=True);rust.mkdir()
        for name in ("rustc", "cargo"):(rust / name).write_bytes(b"non-executable bounded orchestration fixture")
        for name in ("trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "scripts/project-preflight.sh", "scripts/ci/project_boundary.py"):
            path = repo / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_text("# bounded fixture\n")
        for path in (task / "readback_provider.py", controls / "provider_readback_controls.py"):
            path.write_text("# bounded identity fixture; never executed\n")
        dependency = base / "libsqlite3-sys-0.39.1";dependency.mkdir();(dependency / "Cargo.toml").write_text("# fixture\n")
        reports = {
            "provider/build.json": {},
            "provider-native-qualification/report.json": {
                "schema": "bounded-orchestration-fixture", "actual_original_native_pairs": 1182,
                "actual_allocation_failure_pairs": 143, "actual_constructor_failure_pairs": 2,
                "actual_close_error_pairs": 2, "concurrent_provider_calls": 256,
                "operation_coverage": list(range(1, 30)),
            },
            "provider-readback/report.json": {"build": {"bounded_fixture_only": True}},
            "provider-reader-controls/report.json": {
                "negative_controls": 46,
                "cases": [{"name": name, "status": "PASS"} for name in CI.PROVIDER_READER_NEGATIVES],
                "positive_source_unchanged": True, "source_before": {}, "source_after": {},
                "reader": CI.file_identity(task / "readback_provider.py"),
                "harness": CI.file_identity(controls / "provider_readback_controls.py"),
            },
        }
        for report in reports.values():report.update(status="PASS", finalized=True)
        if change is not None:change(reports)
        class ComponentReached(RuntimeError):pass
        observed = []
        with ExitStack() as stack:
            for name, value in (("ROOT", repo), ("TASK", task), ("Q", controls)):
                stack.enter_context(mock.patch.object(CI, name, value))
            gate = CI.Qualification(component, base / "output", rust)
            for name, report in reports.items():
                path = gate.output / name;path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(report))
            def stage(name, argv, limit):
                observed.append((name, list(map(str, argv)), limit))
                if name.startswith("version-"):return (name[8:] + " 1.95.0 bounded-fixture\n").encode()
                return b"{}" if name == "locked-cargo-metadata" else b""
            stack.enter_context(mock.patch.object(gate, "stage", side_effect=stage))
            stack.enter_context(mock.patch.object(CI, "select_dependency", return_value=(dependency, {})))
            stack.enter_context(mock.patch.object(gate, "capture_all"))
            store = stack.enter_context(mock.patch.object(gate, "store", side_effect=ComponentReached("bounded fixture reached Task Store")))
            boundary = stack.enter_context(mock.patch.object(gate, "boundary", side_effect=ComponentReached("bounded fixture reached boundary")))
            error = None
            try:gate.run()
            except (KeyError, ValueError, ComponentReached) as exception:error = exception
        self.assertIsNotNone(error)
        self.assertEqual(gate.report["status"], "FAIL")
        self.assertFalse(gate.report["finalized"])
        return gate, error, observed, store.call_count, boundary.call_count, ComponentReached

    def test_both_components_must_execute_complete_provider_stages_first(self):
        expected = ["preflight", "version-rustc", "version-cargo", "locked-cargo-metadata", "provider-build",
                    "provider-native-original", "provider-independent-readback", "provider-reader-negative-controls"]
        for component in ("task-store", "task-boundary"):
            with self.subTest(component=component):
                gate, error, stages, store, boundary, reached = self.provider_fixture(component=component)
                self.assertIsInstance(error, reached)
                self.assertEqual([name for name, argv, limit in stages], expected)
                self.assertEqual((store, boundary), (1, 0) if component == "task-store" else (0, 1))
                self.assertEqual([limit for name, argv, limit in stages[-4:]], [1200, 600, 120, 120])
                self.assertEqual([Path(argv[1]).name for name, argv, limit in stages[-4:]],
                    ["build_provider.py", "qualify_provider_native.py", "readback_provider.py", "provider_readback_controls.py"])
                for name, argv, limit in stages[-2:]:
                    self.assertEqual(argv[argv.index("--qualification") + 1], str(gate.output / "provider-native-qualification"))
                    self.assertEqual(argv[argv.index("--provider") + 1], str(gate.output / "provider"))
                self.assertEqual(gate.report["native_provider"]["reader_refusal_controls"], 46)
                self.assertEqual(len(CI.READER_NEGATIVES), 37)
                self.assertEqual(len(CI.PROVIDER_NEGATIVES), 8)
                self.assertEqual((CI.COMPONENT_SECONDS, CI.CLEANUP_SECONDS), (1200, 3))

    def test_every_native_provider_qualification_field_is_required(self):
        names = ("actual_original_native_pairs", "actual_allocation_failure_pairs", "actual_constructor_failure_pairs",
                 "actual_close_error_pairs", "concurrent_provider_calls", "operation_coverage", "schema")
        for name in names:
            with self.subTest(missing=name):
                gate, error, stages, store, boundary, reached = self.provider_fixture(lambda reports:
                    reports["provider-native-qualification/report.json"].pop(name))
                self.assertIsInstance(error, KeyError)
                self.assertEqual((store, boundary), (0, 0))
        for name in names[:-1]:
            with self.subTest(changed=name):
                gate, error, stages, store, boundary, reached = self.provider_fixture(lambda reports:
                    reports["provider-native-qualification/report.json"].update({name: [] if name == "operation_coverage" else 0}))
                self.assertIsInstance(error, ValueError)
                self.assertIn("Complete native provider differential/resource gate differs", str(error))
                self.assertEqual((store, boundary), (0, 0))
                self.assertNotIn("provider-independent-readback", [row[0] for row in stages])

    def test_legacy_or_partial_provider_reader_reports_are_rejected(self):
        fields = ("negative_controls", "cases", "positive_source_unchanged", "source_before", "source_after", "reader", "harness")
        for field in fields:
            with self.subTest(missing=field):
                gate, error, stages, store, boundary, reached = self.provider_fixture(lambda reports:
                    reports["provider-reader-controls/report.json"].pop(field))
                self.assertIsInstance(error, KeyError)
                self.assertEqual((store, boundary), (0, 0))
        changes = {
            "old-eight-controls": lambda report: report.update(negative_controls=8),
            "missing-case": lambda report: report["cases"].pop(),
            "duplicate-case": lambda report: report["cases"].__setitem__(1, copy.deepcopy(report["cases"][0])),
            "renamed-case": lambda report: report["cases"][0].update(name="unrelated-refusal"),
            "unexecuted-case": lambda report: report["cases"][0].update(status="SKIP"),
            "dirty-source": lambda report: report.update(positive_source_unchanged=False),
            "changed-source-fence": lambda report: report["source_after"].update({"foreign": {}}),
            "foreign-reader": lambda report: report["reader"].update(sha256="0" * 64),
            "foreign-harness": lambda report: report["harness"].update(sha256="0" * 64),
        }
        for name, change in changes.items():
            with self.subTest(changed=name):
                gate, error, stages, store, boundary, reached = self.provider_fixture(lambda reports:
                    change(reports["provider-reader-controls/report.json"]))
                self.assertIsInstance(error, ValueError)
                self.assertIn("Qualification source fence differs" if name == "changed-source-fence" else
                              "Canonical provider reader did not reject", str(error))
                self.assertEqual((store, boundary), (0, 0))

    def test_provider_reports_require_actual_finalized_success(self):
        for name in ("provider/build.json", "provider-native-qualification/report.json",
                     "provider-readback/report.json", "provider-reader-controls/report.json"):
            for field, value in (("status", "FAIL"), ("finalized", False)):
                with self.subTest(report=name, field=field):
                    gate, error, stages, store, boundary, reached = self.provider_fixture(lambda reports:
                        reports[name].update({field: value}))
                    self.assertIsInstance(error, ValueError)
                    self.assertIn("Incomplete qualification", str(error))
                    self.assertEqual((store, boundary), (0, 0))
        gate, error, stages, store, boundary, reached = self.provider_fixture(lambda reports:
            reports["provider-readback/report.json"].pop("build"))
        self.assertIsInstance(error, KeyError)
        self.assertEqual((store, boundary), (0, 0))

    def test_new_provider_reports_cannot_be_omitted_from_complete_capture(self):
        paths = ["provider/build.json", "provider/native-witness/build.json",
                 "provider-native-qualification/report.json", "provider-native-qualification/original/build.json",
                 "provider-readback/report.json", "provider-reader-controls/report.json"]
        stages = ["provider-build", "provider-native-original", "provider-independent-readback", "provider-reader-negative-controls"]
        for omitted in paths:
            with self.subTest(omitted=omitted):
                gate = CI.Qualification("task-boundary", self.root / ("capture-" + str(paths.index(omitted))), Path(sys.executable).resolve().parent)
                gate.report["stages"] = [{"name": name, "completed": True, "exit_code": 0} for name in stages]
                for name in paths:
                    if name == omitted:continue
                    path = gate.output / name;path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps({"status": "PASS", "finalized": True}))
                gate.capture_all()
                self.assertFalse(gate.report["captured_inputs"]["complete"])
                self.assertEqual(len(gate.capture_errors), 1)
                self.assertEqual(gate.capture_errors[0]["report"], str(gate.output / omitted))
                self.assertIn("disappeared", gate.capture_errors[0]["failure"])


if __name__ == "__main__":
    unittest.main()
