"""Transport-only controls; fixture bytes never represent HIA/Rust execution."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from hia.tools import qualify_work_owner_ci as q
from hia.tools import work_owner_transfer_ci as t
from hia.tools import work_owner_clock_ci as clock

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

    def dependency_fixture(self, home, capture):
        """Small real files for transport controls, never a Rust toolchain claim."""
        sysroot = home / "sysroot"
        source = self.file(sysroot / "lib/rustlib/src/rust/library/std/src/lib.rs", b"std source fixture")
        library = self.file(sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-fixture.so",
                            b"std binary fixture")
        compiler = self.file(sysroot / "bin/rustc", b"compiler fixture")
        cargo = self.file(sysroot / "bin/cargo", b"cargo fixture")
        rustdoc = self.file(sysroot / "bin/rustdoc", b"rustdoc fixture")
        loader = self.file(home / "host/ld-linux-x86-64.so.2", b"loader fixture")
        libc = self.file(home / "host/libc.so.6", b"libc fixture")
        named = lambda path: {"path": str(path), **q.identity(path)}
        standard = {"sysroot": str(sysroot), "sources": {"library/std/src/lib.rs": q.identity(source)},
                    "binaries": {library.name: named(library)},
                    "compiler_executable": named(compiler), "cargo_executable": named(cargo),
                    "actual_host_dynamic_libraries": {str(path): q.identity(path) for path in (loader, libc)}}
        expected = q.dependencies(standard)
        expected["derived-rustdoc"] = (rustdoc, q.identity(rustdoc))
        for name, (path, wanted) in expected.items():
            q.capture_file(path, capture / "original-dependencies" / name, wanted)
        return standard, named(rustdoc), named(loader), {name: row for name, (_, row) in expected.items()}

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
            standard, rustdoc, interpreter, deps = self.dependency_fixture(parent / "external", roots["capture"])
            live = {"schema": t.ORIGINAL_LIVE, "status": "CAPTURED_LIVE_INPUTS",
                    "observed_directory": str(roots["original"]),
                    "executable": {"path": str(roots["original"] / "original-test-binary"),
                                   **q.identity(roots["original"] / "original-test-binary")},
                    "standard_library_sha256": q.object_hash(standard), "interpreter": interpreter,
                    "derived_normal_compiler_loader": q.oracle.capture_loader(standard),
                    "actual_rustdoc": rustdoc, "dependencies": deps}
            q.write_new(roots["capture"] / "original-live-capture.json", live)
        files, special = q.evidence_inventory(roots)
        self.assertFalse(special)
        binding = {"schema": t.BINDING, "phase": phase, "status": "PASS",
                   "lineage": copy.deepcopy(LINEAGE), "final_qualification_claimed": False,
                   "source_inputs": SOURCES, "original_sources": ORIGINALS, "ci_reader_sources": READERS,
                   "source_set_sha256": q.object_hash(SOURCES),
                   "original_source_set_sha256": q.object_hash(ORIGINALS),
                   "evidence_files": files, "evidence_set_sha256": q.object_hash(files),
                   **{key: False for key in q.SCOPES},
                   **(t.NATIVE_COUNTS if phase == "native" else {})}
        if phase == "native":
            binding.update(primitive_raw_readback="PASS", physical_trace="PASS",
                           primitive_raw_guard_arenas_retained=True, native_snapshot={})
        else:
            binding.update(schema=t.ORIGINAL_BINDING, status="CAPTURED", required_original_counts=dict(t.ORIGINAL_COUNTS),
                           original_execution_report_status="PASS", full_original_readback="PENDING",
                           original_rust="PENDING", original_controlled_CLOCK1_fault_comparison="PENDING",
                           original_paid_CLOCK_fault_comparison="PENDING",
                           native_replayed_in_this_capture=False, native_predecessor=predecessor or {},
                           original_binary=files["original/original-test-binary"], original_dependency=standard,
                           original_live_capture=live, original_artifacts=q.file_tree(roots["original"]))
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
        self.assertEqual(record["predecessor_status"], "CAPTURED" if phase == "original" else "PASS")
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
                counts = binding if phase == "native" else binding["required_original_counts"]
                for value in (True, float(counts[key]), counts[key] - 1):
                    changed = copy.deepcopy(binding)
                    target = changed if phase == "native" else changed["required_original_counts"]
                    target[key] = value
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

    def test_transfer_counts_match_complete_qualification_and_actual_clock_roster(self):
        for phase, counts in (("native", t.NATIVE_COUNTS), ("original", t.ORIGINAL_COUNTS)):
            self.assertEqual(counts, {name: q.COUNTS[name] for name in counts})
            _, binding = self.phase(phase, phase + "-full-qualifier-counts")
            target = binding if phase == "native" else binding["required_original_counts"]
            target.update({name: q.COUNTS[name] for name in counts})
            self.check(binding, phase)
        self.assertEqual(len(clock.CONTROL_SPECS), 32)
        self.assertEqual(sum(wanted is True for _, _, wanted in clock.CONTROL_SPECS), 2)
        self.assertEqual(sum(wanted is False for _, _, wanted in clock.CONTROL_SPECS), 30)
        _, binding = self.phase("original", "stale-original-raw-counts")
        binding["required_original_counts"].update(original_clock_raw_controls=20,
            original_clock_raw_positive_controls=2, original_clock_raw_negative_controls=18)
        with self.assertRaisesRegex(ValueError, "actual stage count"):
            self.check(binding, "original")

    def test_pending_capture_cannot_claim_completed_original_or_final_qualification(self):
        _, binding = self.phase("original", "pending-status")
        self.check(binding, "original")
        for field in ("full_original_readback", "original_rust",
                      "original_controlled_CLOCK1_fault_comparison", "original_paid_CLOCK_fault_comparison"):
            for value in ("PASS", "FAIL", None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.check({**binding, field: value}, "original")
        for fields in ({"schema": t.BINDING}, {"status": "PASS"}, {"original_execution_report_status": "FAIL"},
                       {"final_qualification_claimed": True}, {"native_replayed_in_this_capture": True},
                       {"original_histories": 57}, {"original_process_stages": 48}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.check({**binding, **fields}, "original")
        with self.assertRaises(ValueError):
            q.check_binding(binding, LINEAGE)
        from hia.tests.test_work_owner_ci import EvidenceAdmission
        final = EvidenceAdmission().binding()
        for field in ("original_rust", "original_controlled_CLOCK1_fault_comparison",
                      "original_paid_CLOCK_fault_comparison"):
            with self.subTest(final_field=field), self.assertRaises(ValueError):
                q.check_binding({**final, field: "PENDING"}, LINEAGE)

    def reindex_capture(self, binding):
        raw = (json.dumps(binding["original_live_capture"], sort_keys=True, indent=2) + "\n").encode()
        binding["evidence_files"]["capture/original-live-capture.json"] = q.bytes_id(raw)
        binding["evidence_set_sha256"] = q.object_hash(binding["evidence_files"])

    def test_each_external_dependency_is_required_even_after_coherent_reindex(self):
        _, binding = self.phase("original", "dependency-omissions")
        deps = binding["original_live_capture"]["dependencies"]
        self.assertEqual(len(deps), 7)
        for name in deps:
            for alter_certificate in (False, True):
                changed = copy.deepcopy(binding)
                del changed["evidence_files"]["capture/original-dependencies/" + name]
                if alter_certificate:
                    del changed["original_live_capture"]["dependencies"][name]
                self.reindex_capture(changed)
                with self.subTest(name=name, altered=alter_certificate), self.assertRaises(ValueError):
                    self.check(changed, "original")
        changed = copy.deepcopy(binding)
        changed["evidence_files"]["capture/original-live-capture.json"] = q.bytes_id(b"another certificate")
        changed["evidence_set_sha256"] = q.object_hash(changed["evidence_files"])
        with self.assertRaises(ValueError):
            self.check(changed, "original")

    def test_five_live_identity_records_and_full_original_tree_cannot_be_omitted(self):
        _, binding = self.phase("original", "live-omissions")
        fields = ("observed_directory", "executable", "standard_library_sha256", "interpreter",
                  "derived_normal_compiler_loader", "actual_rustdoc", "dependencies")
        for field in fields:
            changed = copy.deepcopy(binding)
            del changed["original_live_capture"][field]
            self.reindex_capture(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(changed, "original")
        for field in ("device", "inode", "mode", "uid", "gid"):
            changed = copy.deepcopy(binding)
            changed["original_live_capture"]["derived_normal_compiler_loader"][field] = True
            self.reindex_capture(changed)
            with self.subTest(loader=field), self.assertRaises(ValueError):
                self.check(changed, "original")
        for field in ("original_artifacts", "original_dependency"):
            changed = copy.deepcopy(binding)
            del changed[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(changed, "original")
        changed = copy.deepcopy(binding)
        del changed["original_artifacts"]["source-after.json"]
        with self.assertRaises(ValueError):
            self.check(changed, "original")

    def live_fixture(self, name):
        parent = self.root / name
        directory, capture = parent / "original", parent / "capture"
        standard, rustdoc, interpreter, _ = self.dependency_fixture(parent / "external", capture)
        raw_path = interpreter["path"].encode() + b"\0"
        # Real ELF64/PT_INTERP parsing is exercised; this data is never executable.
        header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                             2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        program = struct.pack("<IIQQQQQQ", 3, 4, 120, 0, 0, len(raw_path), len(raw_path), 1)
        binary = self.file(directory / "original-test-binary", header + program + raw_path)
        binary.chmod(0o500)
        report = {"executable": {"path": str(binary), **q.identity(binary)},
                  "compiled_executable": {"path": str(parent / "target/original"), **q.identity(binary)},
                  "interpreter": interpreter}
        before = {"standard_library": standard, "actual_rustdoc": rustdoc,
                  "derived_normal_compiler_loader": q.oracle.capture_loader(standard)}
        return directory, capture, before, report

    def test_live_capture_retains_actual_files_elf_loader_and_relocates_without_live_probes(self):
        directory, capture, before, report = self.live_fixture("actual-live-capture")
        from hia.platform.paid_cpu import dependency
        with mock.patch.object(dependency, "captured_std", return_value=before["standard_library"]):
            record = q.original_live_capture(directory, before, report, capture)
        self.assertEqual(q.read(capture / "original-live-capture.json"), record)
        destination = self.root / "relocated"
        shutil.copytree(directory, destination / "original")
        shutil.copytree(capture, destination / "capture")
        shutil.rmtree(directory.parent)
        with mock.patch.object(dependency, "captured_std", side_effect=AssertionError("unexpected live toolchain")), \
             mock.patch.object(dependency, "executable_interpreter", side_effect=AssertionError("unexpected live loader")), \
             mock.patch.object(q.oracle, "capture_loader", side_effect=AssertionError("unexpected live inode")):
            actual = q.original_live_capture(destination / "original", before, report,
                                             destination / "capture", live=False)
        self.assertEqual(actual, record)
        self.assertEqual(actual["status"], "CAPTURED_LIVE_INPUTS")

    def test_live_capture_rejects_actual_missing_or_changed_dependencies(self):
        from hia.platform.paid_cpu import dependency
        for fault in ("captured-file-missing", "captured-file-changed", "actual-file-changed",
                      "actual-rustdoc-missing", "loader-inode-changed", "observed-path-changed",
                      "interpreter-changed", "selected-toolchain-changed"):
            directory, capture, before, report = self.live_fixture(fault)
            selected = copy.deepcopy(before["standard_library"])
            if fault == "captured-file-missing":
                (capture / "original-dependencies/derived-rustdoc").unlink()
            elif fault == "captured-file-changed":
                (capture / "original-dependencies/tools/cargo_executable").write_bytes(b"changed")
            elif fault == "actual-file-changed":
                Path(before["standard_library"]["cargo_executable"]["path"]).write_bytes(b"changed")
            elif fault == "actual-rustdoc-missing":
                Path(before["actual_rustdoc"]["path"]).unlink()
            elif fault == "loader-inode-changed":
                before["derived_normal_compiler_loader"]["inode"] += 1
            elif fault == "observed-path-changed":
                report["executable"]["path"] = str(self.root / "another/original-test-binary")
            elif fault == "interpreter-changed":
                report["interpreter"]["sha256"] = "0" * 64
            else:
                selected["compiler_executable"]["sha256"] = "0" * 64
            with mock.patch.object(dependency, "captured_std", return_value=selected):
                with self.subTest(fault=fault), self.assertRaises((ValueError, FileNotFoundError)):
                    q.original_live_capture(directory, before, report, capture)
            self.assertFalse((capture / "original-live-capture.json").exists())

    def test_transferred_live_capture_is_bound_to_actual_original_source_and_report(self):
        directory, capture, before, report = self.live_fixture("offline-capture-binding")
        from hia.platform.paid_cpu import dependency
        with mock.patch.object(dependency, "captured_std", return_value=before["standard_library"]):
            record = q.original_live_capture(directory, before, report, capture)
        target = capture / "original-live-capture.json"
        for field in ("observed_directory", "executable", "interpreter", "derived_normal_compiler_loader",
                      "standard_library_sha256", "actual_rustdoc", "dependencies"):
            changed = copy.deepcopy(record)
            changed[field] = {} if isinstance(changed[field], dict) else "another"
            target.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "actual original report/source fence"):
                q.original_live_capture(directory, before, report, capture, live=False)
        target.write_text(json.dumps(record))
        changed = copy.deepcopy(before)
        changed["derived_normal_compiler_loader"]["inode"] += 1
        with self.assertRaisesRegex(ValueError, "actual original report/source fence"):
            q.original_live_capture(directory, changed, report, capture, live=False)

    def test_capture_mode_requires_live_runner_capture_and_exact_target_before_reading(self):
        absent = self.root / "not-read"
        for args in ({"capture_only": 1}, {"capture_only": True, "live": False},
                     {"capture_only": True, "capture": absent},
                     {"capture_only": True, "expected_target": absent},
                     {"capture_only": True, "capture": absent, "expected_target": absent, "live": 1}):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, "Transport capture requires"):
                q.original(absent, absent, {}, **args)

    def test_mandatory_assessor_selects_full_original_validation_and_propagates_failure(self):
        admitted = {"source_inputs": {}, "original_sources": {}, "snapshot": {}}
        with mock.patch.object(q, "native", return_value=(admitted, {})), \
             mock.patch.object(q, "original", side_effect=ValueError("full original replay refused")) as full:
            with self.assertRaisesRegex(ValueError, "full original replay refused"):
                q.assess(self.root, self.root / "native", self.root / "original",
                         capture=self.root / "capture", live=False)
        self.assertEqual(full.call_args.kwargs["capture_only"], False)
        self.assertIs(full.call_args.kwargs["live"], False)
        native, original = self.root / "prior-native", self.root / "prior-original"
        receipt = {"lineage": LINEAGE}
        with mock.patch.object(t, "current_context", return_value=(LINEAGE, SOURCES, ORIGINALS, READERS)), \
             mock.patch.object(t, "prior", side_effect=[(native, {}, receipt),
                               (original, {"native_predecessor": receipt}, receipt)]), \
             mock.patch.object(q, "source_pair", return_value={}), \
             mock.patch.object(q, "assess", side_effect=ValueError("full original replay refused")) as assess, \
             mock.patch.object(q, "pack_roots") as pack:
            with self.assertRaisesRegex(ValueError, "full original replay refused"):
                t.qualify_pack(q, self.root)
        assess.assert_called_once_with(q.ROOT, native / "native", original / "original",
                                       capture=original / "capture", live=False)
        pack.assert_not_called()

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
