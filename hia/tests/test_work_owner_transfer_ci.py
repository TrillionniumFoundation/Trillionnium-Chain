"""Transport-only controls; fixture bytes never represent HIA/Rust execution."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from hia.tools import qualify_work_owner_ci as q
from hia.tools import work_owner_transfer_ci as t

LINEAGE = {"git_head": "a" * 40, "run_id": "42", "attempt": 1}
SOURCES = {"hia/platform/work_owner/reader-fixture.py": q.bytes_id(b"source")}
ORIGINALS = {"trillionnium/reader-fixture.rs": q.bytes_id(b"original")}
READERS = {name: q.bytes_id(name.encode()) for name in q.READERS}


class CompleteTransfers(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="work-transfer-control-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def file(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def context(self):
        return mock.patch.multiple(
            q, reader_manifest=mock.Mock(return_value=READERS))

    def phase(self, phase, name, predecessor=None):
        parent = self.root / name
        roots = {"observations": parent / "observations", "capture": parent / "capture",
                 phase: parent / phase}
        common = {"observations/source-before.json", "observations/source-after.json",
                  "capture/source-inputs/reader-fixture.py"}
        if phase == "native":
            common |= {"native/report.json", "native/artifacts.json", "native/build/fixture.elf",
                       "native/primitives/raw-buffers/manifest.json",
                       "native/primitives/raw-buffers/calls.jsonl",
                       "observations/source-controls/report.json",
                       "observations/source-controls/stdout.raw",
                       "observations/source-controls/stderr.raw"}
            roots["bootstrap"] = parent / "bootstrap"
            common.add("bootstrap/bootstrap.json")
        else:
            common |= {"original/report.json", "original/original-test-binary",
                       "original/source-before.json", "original/source-after.json",
                       "original/controlled-clock/report.json",
                       "original/controlled-clock/actual-reader-controls/report.json",
                       "original/actual-sqlite-qualification.json"}
        for member in sorted(common):
            self.file(parent / member, ("transport fixture only:" + member).encode())
        if phase == "original":
            (parent / "original/original-test-binary").chmod(0o500)
        files, special = q.evidence_inventory(roots)
        self.assertFalse(special)
        binding = {"schema": t.BINDING, "phase": phase, "status": "PASS",
                   "lineage": copy.deepcopy(LINEAGE), "final_qualification_claimed": False,
                   "source_inputs": SOURCES, "original_sources": ORIGINALS, "ci_reader_sources": READERS,
                   "source_set_sha256": q.object_hash(SOURCES),
                   "original_source_set_sha256": q.object_hash(ORIGINALS),
                   "evidence_files": files, "evidence_set_sha256": q.object_hash(files),
                   **{key: False for key in q.SCOPES},
                   **(t.NATIVE_COUNTS if phase == "native" else t.ORIGINAL_COUNTS)}
        if phase == "native":
            binding.update(primitive_raw_readback="PASS", physical_trace="PASS",
                           primitive_raw_guard_arenas_retained=True, native_snapshot={})
        else:
            binding.update(original_rust="PASS", original_controlled_CLOCK1_fault_comparison="PASS",
                           native_replayed_in_this_capture=False, native_predecessor=predecessor or {},
                           original_binary=files["original/original-test-binary"])
        q.write_new(parent / "observations/binding.json", binding)
        return roots, binding

    def check(self, value, phase):
        return t.check_binding(q, value, phase, LINEAGE, SOURCES, ORIGINALS, READERS)

    def package(self, phase, name, predecessor=None):
        roots, binding = self.phase(phase, name, predecessor)
        output = self.root / (name + "-package")
        with mock.patch.object(q.base, "lineage", return_value=LINEAGE), \
             mock.patch.object(q.build, "source_manifest", return_value=SOURCES), \
             mock.patch.object(q.bundle, "original_manifest", return_value=ORIGINALS), \
             mock.patch.object(q, "reader_manifest", return_value=READERS):
            record = t.make_package(q, roots, output, binding, phase)
        self.assertEqual(record["packing_status"], "PASS")
        self.assertIs(record["final_qualification_claimed"], False)
        return output, binding

    def unpack(self, package, phase, output):
        with mock.patch.object(t, "current_context", return_value=(LINEAGE, SOURCES, ORIGINALS, READERS)):
            result = t.read_transfer(q, package, output, phase)
        self.assertEqual(result["status"], "VERIFIED_BYTES_TRANSFERRED_NOT_FINAL_QUALIFICATION")
        return q.read(output / "transfer-receipt.json")

    def test_phase_counts_are_exact_and_cannot_hide_skips_or_changed_run(self):
        for phase in t.PHASES:
            _, binding = self.phase(phase, phase + "-shape")
            self.check(binding, phase)
            for key in t.NATIVE_COUNTS if phase == "native" else t.ORIGINAL_COUNTS:
                for value in (True, float(binding[key]), binding[key] - 1):
                    changed = copy.deepcopy(binding)
                    changed[key] = value
                    with self.subTest(phase=phase, key=key, value=value), self.assertRaises(ValueError):
                        self.check(changed, phase)
            for fields in ({"status": "FAIL"}, {"phase": "other"},
                           {"final_qualification_claimed": True},
                           {"lineage": {**LINEAGE, "attempt": 1.0}},
                           {"lineage": {**LINEAGE, "attempt": 2}},
                           {"lineage": {**LINEAGE, "run_id": "43"}},
                           {"lineage": {**LINEAGE, "git_head": "b" * 40}}):
                with self.subTest(fields=fields), self.assertRaises(ValueError):
                    self.check({**binding, **fields}, phase)

    def test_complete_source_and_reader_maps_are_not_digest_only(self):
        _, binding = self.phase("native", "source-shape")
        for key in ("source_inputs", "original_sources", "ci_reader_sources"):
            changed = copy.deepcopy(binding)
            changed[key] = {}
            if key != "ci_reader_sources":
                changed["source_set_sha256" if key == "source_inputs"
                        else "original_source_set_sha256"] = q.object_hash({})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(changed, "native")
        changed = copy.deepcopy(binding)
        name = next(iter(changed["source_inputs"]))
        changed["source_inputs"][name]["bytes"] = float(changed["source_inputs"][name]["bytes"])
        changed["source_set_sha256"] = q.object_hash(changed["source_inputs"])
        with self.assertRaises(ValueError):
            self.check(changed, "native")

    def test_full_raw_arena_and_original_binary_are_required_after_coherent_reindex(self):
        for phase, missing in (("native", "native/primitives/raw-buffers/calls.jsonl"),
                               ("native", "native/primitives/raw-buffers/manifest.json"),
                               ("original", "original/original-test-binary"),
                               ("original", "original/controlled-clock/actual-reader-controls/report.json")):
            _, binding = self.phase(phase, missing.replace("/", "-"))
            del binding["evidence_files"][missing]
            binding["evidence_set_sha256"] = q.object_hash(binding["evidence_files"])
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                self.check(binding, phase)

    def test_real_archive_roundtrip_is_a_transport_not_final_qualification(self):
        for phase in t.PHASES:
            package, _ = self.package(phase, phase + "-roundtrip")
            output = self.root / (phase + "-roundtrip-extracted")
            receipt = self.unpack(package, phase, output)
            self.assertEqual(receipt["lineage"], LINEAGE)
            self.assertEqual(receipt["archive"], q.identity(package / "complete-evidence.tar.xz"))
            if phase == "original":
                binary = output / "original/original-test-binary"
                self.assertEqual(binary.stat().st_mode & 0o777, 0o500)
                self.assertTrue(binary.read_bytes().startswith(b"transport fixture only:"))

    def test_failure_pack_preserves_available_bytes_without_creating_success_binding(self):
        roots, _ = self.phase("original", "failed-stage")
        output = self.root / "failed-stage-package"
        with self.assertRaisesRegex(ValueError, "Work transfer failed"):
            t.make_package(q, roots, output, None, "original", "actual original command failed")
        record = q.read(output / "package-manifest.json")
        self.assertEqual(record["packing_status"], "FAIL")
        self.assertEqual(record["predecessor_status"], "FAIL")
        self.assertFalse((output / "binding.json").exists())
        self.assertTrue(record["capture_errors"])
        q.verify_archive(output / "complete-evidence.tar.xz", record["entries"])

    def test_package_binding_and_complete_archive_identity_are_independently_checked(self):
        package, binding = self.package("native", "mutants")
        original = (package / "package-manifest.json").read_bytes()
        for key, value in (("predecessor_status", "FAIL"), ("packing_status", "FAIL"),
                           ("final_qualification_claimed", True),
                           ("complete_primitive_bytes_is_not_excluded", 1),
                           ("lineage", {**LINEAGE, "attempt": 1.0})):
            record = json.loads(original)
            record[key] = value
            (package / "package-manifest.json").write_text(json.dumps(record))
            with mock.patch.object(t, "current_context", return_value=(LINEAGE, SOURCES, ORIGINALS, READERS)):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    t.read_transfer(q, package, self.root / ("bad-" + key), "native")
            self.assertFalse((self.root / ("bad-" + key)).exists())
        (package / "package-manifest.json").write_bytes(original)
        archive = package / "complete-evidence.tar.xz"
        raw = archive.read_bytes()
        archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with mock.patch.object(t, "current_context", return_value=(LINEAGE, SOURCES, ORIGINALS, READERS)):
            with self.assertRaisesRegex(ValueError, "archive changed"):
                t.read_transfer(q, package, self.root / "bad-archive", "native")
        self.assertFalse((self.root / "bad-archive").exists())

    def chain(self, suffix, *, wrong_predecessor=False):
        native_package, _ = self.package("native", suffix + "-native")
        native = self.root / (suffix + "-native-prior")
        native_receipt = self.unpack(native_package, "native", native)
        consumed = copy.deepcopy(native_receipt)
        if wrong_predecessor:
            consumed["archive"]["sha256"] = "0" * 64
        original_package, _ = self.package("original", suffix + "-original", consumed)
        original = self.root / (suffix + "-original-prior")
        original_receipt = self.unpack(original_package, "original", original)
        final = self.root / (suffix + "-final")
        roots = {name: final / name for name in q.ROOT_LABELS}
        t.copy_tree(q, native / "native", roots["native"])
        t.copy_tree(q, original / "original", roots["original"])
        t.copy_tree(q, native / "bootstrap", roots["bootstrap"])
        t.copy_tree(q, original / "capture", roots["capture"])
        for phase, prior, package in (("native", native, native_package),
                                      ("original", original, original_package)):
            destination = roots["capture"] / ("predecessor-" + phase)
            t.copy_tree(q, prior / "observations", destination)
            for name in ("transfer-receipt.json", "transferred-binding.json", "transferred-package-manifest.json"):
                q.capture_file(prior / name, destination / name, q.identity(prior / name))
            for name in ("binding.json", "package-manifest.json", "complete-evidence.tar.xz"):
                q.capture_file(package / name, destination / "transport" / name, q.identity(package / name))
        binding = {"pipeline": "native-original-qualification-readback-v1",
                   "complete_predecessor_regular_bytes_retained": True,
                   "complete_predecessor_archives_retained": True,
                   "native_predecessor": native_receipt, "original_predecessor": original_receipt,
                   "source_inputs": SOURCES, "original_sources": ORIGINALS, "ci_reader_sources": READERS}
        return roots, binding

    def test_whole_two_archive_chain_replays_both_actual_transport_members(self):
        roots, binding = self.chain("good-chain")
        with mock.patch.object(q.base, "lineage", return_value=LINEAGE):
            actual = t.validate_chain(q, roots, binding)
        self.assertEqual(actual["whole_predecessor_archives"], 2)
        self.assertIs(actual["actual_runtime_reexecuted"], False)

    def test_original_cannot_consume_another_native_predecessor(self):
        roots, binding = self.chain("wrong-chain", wrong_predecessor=True)
        with mock.patch.object(q.base, "lineage", return_value=LINEAGE):
            with self.assertRaisesRegex(ValueError, "another native archive"):
                t.validate_chain(q, roots, binding)

    def test_original_binary_or_whole_archive_cannot_be_omitted_after_transfer(self):
        for name, target in (("binary", "original/original-test-binary"),
                             ("archive", "capture/predecessor-native/transport/complete-evidence.tar.xz")):
            roots, binding = self.chain("missing-" + name)
            label, relative = target.split("/", 1)
            (roots[label] / relative).unlink()
            with mock.patch.object(q.base, "lineage", return_value=LINEAGE):
                with self.subTest(name=name), self.assertRaises((ValueError, FileNotFoundError)):
                    t.validate_chain(q, roots, binding)

    def test_mutated_final_member_cannot_hide_behind_intact_prior_archive(self):
        roots, binding = self.chain("changed-member")
        path = roots["original"] / "report.json"
        path.write_bytes(b"coherent-looking replacement")
        with mock.patch.object(q.base, "lineage", return_value=LINEAGE):
            with self.assertRaisesRegex(ValueError, "full member differs"):
                t.validate_chain(q, roots, binding)

    def test_final_scope_and_receipt_types_cannot_be_coerced(self):
        roots, binding = self.chain("typed-final")
        for key in ("complete_predecessor_regular_bytes_retained", "complete_predecessor_archives_retained"):
            with mock.patch.object(q.base, "lineage", return_value=LINEAGE):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    t.validate_chain(q, roots, {**binding, key: 1})
        changed = copy.deepcopy(binding)
        changed["native_predecessor"]["lineage"]["attempt"] = 1.0
        with mock.patch.object(q.base, "lineage", return_value=LINEAGE):
            with self.assertRaises(ValueError):
                t.validate_chain(q, roots, changed)

    def cli(self, args, env):
        roots = [str(Path(q.__file__).resolve().parents[2]), str(q.ROOT)]
        return subprocess.run([sys.executable, "-P", "-B", "-m", "hia.tools.qualify_work_owner_ci", *args],
                              cwd=q.ROOT, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                              "PYTHONPATH": os.pathsep.join(dict.fromkeys(roots)), **env},
                              capture_output=True, timeout=30)

    def test_public_cli_requires_actual_upstream_success_before_any_unpack(self):
        env = {"RUNNER_TEMP": str(self.root), "TRNM_WORK_NATIVE_RESULT": "",
               "TRNM_WORK_ORIGINAL_RESULT": "", "TRNM_WORK_QUALIFICATION_RESULT": ""}
        for action, key in (("native-unpack", "TRNM_WORK_NATIVE_RESULT"),
                            ("original-unpack", "TRNM_WORK_ORIGINAL_RESULT"),
                            ("original-pack", "TRNM_WORK_NATIVE_RESULT"),
                            ("qualify-pack", "TRNM_WORK_NATIVE_RESULT")):
            for failure in ("failure", "cancelled", "skipped", ""):
                child = self.cli([action], {**env, key: failure})
                with self.subTest(action=action, failure=failure):
                    self.assertNotEqual(child.returncode, 0)
                    self.assertIn(b"Actual prerequisite CI job did not succeed", child.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_public_qualified_readback_rejects_not_bound_development_package(self):
        package = self.root / "development-package"
        package.mkdir()
        q.write_new(package / "package-manifest.json", {
            "schema": q.PACKAGE, "stage": q.STAGE, "packing_status": "PASS",
            "capture_errors": [], "special_entries": {},
            "complete_original_test_binary_is_not_excluded": True,
            "complete_isolated_original_source_is_not_excluded": True,
            "qualification_status_not_changed_by_packaging": True,
            "qualification_status": "NOT_BOUND", "lineage": None})
        output = self.root / "must-not-extract"
        child = self.cli(["readback", "--package", str(package), "--output", str(output),
                          "--require-qualified"], {"TRNM_WORK_QUALIFICATION_RESULT": "success"})
        self.assertNotEqual(child.returncode, 0)
        self.assertIn(b"requires an actually qualified complete package", child.stderr)
        self.assertFalse(output.exists())

    def test_public_action_cannot_silently_ignore_qualification_requirement(self):
        for action in ("controls", "native-pack", "original-pack", "qualify-pack", "review"):
            child = self.cli([action, "--require-qualified"], {})
            with self.subTest(action=action):
                self.assertNotEqual(child.returncode, 0)
                self.assertIn(b"requirement applies only to complete final readback", child.stderr)


if __name__ == "__main__":
    unittest.main()
