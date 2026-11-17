"""Boundary tests for complete Work/Host evidence transfer, independent of native behavior."""
from __future__ import annotations
import copy
import hashlib
import io
import json
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from hia.tools import qualify_work_owner_ci as q


class EvidenceAdmission(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="work-owner-ci-test-")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def binding(self):
        tiny = q.bytes_id(b"x")
        sources = {"hia/platform/work_owner/" + name: tiny for name in q.build.OWNED}
        original = {"trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs": tiny}
        retained = sorted(set(q.oracle.REQUIRED_TESTS) |
                          {"host_kernel_parent::kernel_parent::test_" + str(i).zfill(3)
                           for i in range(44 - len(set(q.oracle.REQUIRED_TESTS)))})
        self.assertEqual(len(retained), 44)
        files = {name: tiny for name in ("native/report.json", "original/report.json",
                 "original/original-test-binary", "original/source-before.json", "original/source-after.json",
                 "original/controlled-clock/report.json", "original/controlled-clock/actual-reader-controls/report.json",
                 "original/actual-sqlite-qualification.json",
                 "native/primitives/raw-buffers/manifest.json", "native/primitives/raw-buffers/calls.jsonl")}
        value = {"schema": q.SCHEMA, "stage": q.STAGE, "status": "PASS",
                 "lineage": {"git_head": "a" * 40, "run_id": "42", "attempt": 1},
                 "pipeline": "native-original-qualification-readback-v1",
                 "complete_predecessor_regular_bytes_retained": True,
                 "complete_predecessor_archives_retained": True,
                 **q.COUNTS, **{name: False for name in q.SCOPES},
                 "physical_trace": "PASS", "original_rust": "PASS",
                 "original_controlled_CLOCK1_fault_comparison": "PASS",
                 "primitive_raw_guard_arenas_retained": True, "primitive_raw_readback": "PASS",
                 "original_sqlite_build_fence": "sqlite-3.54.1-normal-native-linux-layout-v4",
                 "primitive_raw_evidence": {**q.next_evidence.RAW_COUNTS,
                     "guards_and_complete_bodies_retained": True, "manifest": tiny, "calls": tiny},
                 "source_inputs": sources, "original_sources": original,
                 "source_set_sha256": q.object_hash(sources),
                 "original_source_set_sha256": q.object_hash(original),
                 "retained_original_tests": retained,
                 "evidence_files": files, "evidence_set_sha256": q.object_hash(files),
                 "ci_reader_sources": {name: tiny for name in q.READERS}}
        for name, field in (("native/report.json", "native_report"), ("original/report.json", "original_report"),
                            ("original/original-test-binary", "original_binary"),
                            ("original/source-before.json", "original_source_before"),
                            ("original/source-after.json", "original_source_after"),
                            ("original/controlled-clock/report.json", "original_clock_report"),
                            ("original/controlled-clock/actual-reader-controls/report.json", "original_clock_raw_controls_report"),
                            ("original/actual-sqlite-qualification.json", "original_sqlite_qualification")):
            value[field] = files[name]
        return value

    def archive(self, path, members, *, raw_tail=b""):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:") as tar:
            for name, raw, changes in members:
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = 0o500 if name == "original/original-test-binary" else 0o600
                for key, value in changes.items():
                    setattr(member, key, value)
                tar.addfile(member, io.BytesIO(raw) if member.isfile() else None)
        path.write_bytes(lzma.compress(stream.getvalue() + raw_tail, preset=1))

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        path = self.directory / "data.json"
        for raw in (b'{"a":1,"a":2}', b'{"nested":{"x":1,"x":1}}', b'{"value":NaN}', b'{"value":Infinity}'):
            path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                q.read(path)
        path.write_bytes(b'{"a":1,"b":false}')
        self.assertEqual(q.read(path), {"a": 1, "b": False})

    def test_canonical_paths_and_identity_types(self):
        self.assertEqual(str(q.member_name("native/build/owner.elf")), "native/build/owner.elf")
        for name in ("../x", "/absolute", "a/../b", "a//b", "./x", "a\\b", "x\nq", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                q.member_name(name)
        for value in (True, -1, 1.0, q.MAX_BYTES + 1):
            self.assertFalse(q.file_id({"bytes": value, "sha256": "0" * 64}))
        self.assertFalse(q.same({"n": True}, {"n": 1}))
        self.assertFalse(q.same({"n": 1.0}, {"n": 1}))

    def test_binding_rejects_wrong_head_attempt_and_boolean_counts(self):
        value = self.binding()
        q.check_binding(value, value["lineage"])
        for change in ({"git_head": "b" * 40}, {"attempt": 2}, {"run_id": "43"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                q.check_binding(value, {**value["lineage"], **change})
        for key in q.COUNTS:
            wrong = copy.deepcopy(value)
            wrong[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                q.check_binding(wrong, value["lineage"])

    def test_scope_and_complete_retained_roster_cannot_expand(self):
        value = self.binding()
        for key in q.SCOPES:
            wrong = copy.deepcopy(value)
            wrong[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                q.check_binding(wrong, value["lineage"])
        for wrong in ({"original_controlled_CLOCK1_fault_comparison": "OPEN"},
                      {"primitive_raw_guard_arenas_retained": False},
                      {"retained_original_tests": value["retained_original_tests"][:-1]},
                      {"retained_original_tests": value["retained_original_tests"][:-1] +
                          [value["retained_original_tests"][0]]}):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                q.check_binding({**value, **wrong}, value["lineage"])

    def test_binding_requires_full_binary_and_source_closure(self):
        value = self.binding()
        for name in ("original/original-test-binary", "original/source-after.json", "native/report.json"):
            wrong = copy.deepcopy(value)
            del wrong["evidence_files"][name]
            wrong["evidence_set_sha256"] = q.object_hash(wrong["evidence_files"])
            with self.subTest(name=name), self.assertRaises(ValueError):
                q.check_binding(wrong, value["lineage"])
        wrong = copy.deepcopy(value)
        del wrong["source_inputs"]["hia/platform/work_owner/owner_policy.hepta"]
        wrong["source_set_sha256"] = q.object_hash(wrong["source_inputs"])
        with self.assertRaises(ValueError):
            q.check_binding(wrong, value["lineage"])
        wrong = copy.deepcopy(value)
        wrong["original_binary"] = q.bytes_id(b"")
        wrong["evidence_files"]["original/original-test-binary"] = q.bytes_id(b"")
        wrong["evidence_set_sha256"] = q.object_hash(wrong["evidence_files"])
        with self.assertRaises(ValueError):
            q.check_binding(wrong, value["lineage"])

    def test_complete_archive_positive_and_independent_extraction(self):
        path = self.directory / "good.tar.xz"
        members = [("native/report.json", b"{}", {}), ("original/original-test-binary", b"\x7fELFtest", {})]
        self.archive(path, members)
        entries = {name: q.bytes_id(raw) for name, raw, _ in members}
        destination = self.directory / "readback"
        result = q.verify_archive(path, entries, destination=destination)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["members"], 2)
        self.assertEqual((destination / "original/original-test-binary").read_bytes(), b"\x7fELFtest")
        self.assertEqual((destination / "original/original-test-binary").stat().st_mode & 0o777, 0o500)

    def test_archive_rejects_roster_metadata_and_content_mutants(self):
        expected = {"native/result.raw": q.bytes_id(b"raw")}
        variants = [
            [("native/another.raw", b"raw", {})],
            [("native/result.raw", b"raw", {}), ("native/result.raw", b"raw", {})],
            [("native/result.raw", b"raw", {}), ("native/extra", b"x", {})],
            [("native/result.raw", b"RAW", {})],
            [("native/result.raw", b"raw", {"mode": 0o755})],
            [("native/result.raw", b"raw", {"uid": 1})],
            [("native/result.raw", b"raw", {"mtime": 1})],
            [("native/result.raw", b"raw", {"pax_headers": {"comment": "not allowed"}})],
            [("native/result.raw", b"", {"type": tarfile.SYMTYPE, "linkname": "/tmp/outside"})],
            [("native/result.raw", b"", {"type": tarfile.LNKTYPE, "linkname": "native/another"})],
        ]
        for i, members in enumerate(variants):
            path = self.directory / ("mutant-" + str(i) + ".xz")
            self.archive(path, members)
            with self.subTest(i=i), self.assertRaises((ValueError, tarfile.TarError)):
                q.verify_archive(path, expected)

    def test_archive_rejects_truncated_concatenated_or_hidden_stream(self):
        path = self.directory / "baseline.xz"
        self.archive(path, [("native/value", b"x", {})])
        expected = {"native/value": q.bytes_id(b"x")}
        original = path.read_bytes()
        for i, raw in enumerate((original[:-1], original + b"x", original + original)):
            mutant = self.directory / ("stream-" + str(i) + ".xz")
            mutant.write_bytes(raw)
            with self.subTest(i=i), self.assertRaises((ValueError, lzma.LZMAError, tarfile.TarError, EOFError)):
                q.verify_archive(mutant, expected)
        hidden = self.directory / "hidden.xz"
        self.archive(hidden, [("native/value", b"x", {})], raw_tail=b"x")
        with self.assertRaises(ValueError):
            q.verify_archive(hidden, expected)

    def test_original_named_test_does_not_count_ignored_or_other_test(self):
        name = "host_kernel_parent::kernel_parent::specific"
        good = ("running 1 test\ntest " + name + " ... ok\n\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n").encode()
        q.positive_test(good, name)
        for raw in (good.replace(b"1 passed; 0 failed; 0 ignored", b"0 passed; 0 failed; 1 ignored"),
                    good.replace(name.encode(), b"some_other_test"), b"test result: ok. 1 passed; 0 failed; 0 ignored;"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                q.positive_test(raw, name)

    def test_failed_binding_still_retains_actual_full_bytes_without_qualification(self):
        roots = {"native": self.directory / "native"}
        roots["native"].mkdir()
        (roots["native"] / "actual.raw").write_bytes(b"actual failed process output")
        output = self.directory / "package"
        with self.assertRaises(ValueError):
            q.pack_roots(roots, output, precondition_error="source fence failed")
        report = q.read(output / "package-manifest.json")
        self.assertEqual(report["packing_status"], "FAIL")
        self.assertEqual(report["qualification_status"], "NOT_BOUND")
        self.assertIn("native/actual.raw", report["entries"])
        self.assertEqual(report["archive_verification"]["status"], "PASS")
        self.assertTrue(report["capture_errors"])

    def test_unbound_pack_never_claims_a_CI_pass(self):
        roots = {"native": self.directory / "native"}
        roots["native"].mkdir()
        (roots["native"] / "raw").write_bytes(b"private")
        report = q.pack_roots(roots, self.directory / "package")
        self.assertEqual(report["packing_status"], "PASS")
        self.assertEqual(report["qualification_status"], "NOT_BOUND")
        self.assertIsNone(report["lineage"])

    def test_regular_reader_rejects_symlink_and_archive_preexisting_destination(self):
        path = self.directory / "raw"
        path.write_bytes(b"raw")
        link = self.directory / "alias"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            q.identity(link)
        archive = self.directory / "data.xz"
        self.archive(archive, [("native/raw", b"raw", {})])
        with self.assertRaises(ValueError):
            q.verify_archive(archive, {"native/raw": q.bytes_id(b"raw")}, destination=self.directory)


    def original_worker_row(self):
        return {"name": "actual-original-format", "domain": 0, "code": 0, "error_text": None,
                "work_code": 0, "progress": [[64, 0, 0, 0, 1]], "product_hex": "00" * 16384,
                "challenge_hex": "00" * 32, "task_hex": "00" * 32, "ticket_hex": "00" * 32,
                "main_tid": 101, "worker_tid": 102, "joined": True, "host_calls": 3,
                "worker_checks": 3, "before_checks": 3, "after_checks": 5,
                "before_values": [0] * 6, "after_values": [0] * 6, "delta_values": [0] * 4,
                "gate_observed": False, "input_sha256": "00" * 32, "actual_original_W1": True,
                "actual_original_Host_primitives": True,
                "actual_original_task_alive_and_final_resource": True,
                "fixture_uses_actual_AtomicBool_cancel_inputs": True,
                "production_fixed_parent_authority": False, "complete_Node_or_paid_checkpoint": False}

    def test_original_actual_json_types_do_not_use_python_number_equality(self):
        good = self.original_worker_row()
        q.original_shape(good)
        mutants = []
        for key, value in (("domain", False), ("code", 0.0), ("main_tid", "101"),
                           ("worker_tid", 102.0), ("host_calls", 3.0), ("worker_checks", True),
                           ("joined", 1), ("gate_observed", 0), ("actual_original_W1", 1)):
            wrong = copy.deepcopy(good)
            wrong[key] = value
            mutants.append((key, wrong))
        for key, index, value in (("before_values", 0, False), ("after_values", 0, 0.0),
                                  ("delta_values", 0, False)):
            wrong = copy.deepcopy(good)
            wrong[key][index] = value
            mutants.append((key, wrong))
        wrong = copy.deepcopy(good)
        wrong["progress"][0][4] = True
        mutants.append(("actual-first-progress-sequence", wrong))
        mutants.append(("unknown-field", {**good, "unbound": 0}))
        for name, wrong in mutants:
            with self.subTest(name=name), self.assertRaises(ValueError):
                q.original_shape(wrong)

    def test_original_pre_worker_shape_is_distinct_from_worker_results(self):
        good = {"name": "pre-worker", "domain": 3, "code": 1, "progress": [],
                "product_hex": None, "worker_tid": None}
        q.original_shape(good)
        q.original_shape({**good, "main_tid": 101, "before_checks": 0})
        for wrong in ({**good, "code": True}, {**good, "main_tid": "101", "before_checks": 0},
                      {**good, "joined": True}, {**good, "worker_tid": 101},
                      {**good, "main_tid": 101}, {**good, "progress": [[64, 0, 0, 0, 1]]}):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                q.original_shape(wrong)

    def test_binding_cannot_omit_new_full_raw_or_clock_artifacts(self):
        value = self.binding()
        q.check_binding(value, value["lineage"])
        for name in ("original/controlled-clock/report.json",
                     "original/controlled-clock/actual-reader-controls/report.json",
                     "original/actual-sqlite-qualification.json",
                     "native/primitives/raw-buffers/manifest.json",
                     "native/primitives/raw-buffers/calls.jsonl"):
            wrong = copy.deepcopy(value)
            wrong["evidence_files"].pop(name)
            wrong["evidence_set_sha256"] = q.object_hash(wrong["evidence_files"])
            with self.subTest(name=name), self.assertRaises(ValueError):
                q.check_binding(wrong, value["lineage"])
        for field, bad in (("primitive_raw_readback", "NOT_RUN"),
                           ("original_sqlite_build_fence", "unqualified")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                q.check_binding({**value, field: bad}, value["lineage"])

    def test_primitive_complete_raw_summary_has_exact_integer_types(self):
        raw = {**q.next_evidence.RAW_COUNTS,
               "schema": "trnm.hia.work-owner-primitive-bytes.v1",
               "guards_and_complete_bodies_retained": True,
               "native_cpu_ns": 0, "native_wall_ns": 0,
               "manifest": q.bytes_id(b"manifest"), "calls": q.bytes_id(b"calls")}
        report = {"primitives": {"raw_readback": "PASS", "raw_evidence": raw}}
        self.assertTrue(q.next_evidence.primitive_summary(q, report)["primitive_raw_guard_arenas_retained"])
        for key in (*q.next_evidence.RAW_COUNTS, "native_cpu_ns", "native_wall_ns"):
            for value in (False, float(raw[key]), -1):
                wrong = copy.deepcopy(report)
                wrong["primitives"]["raw_evidence"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    q.next_evidence.primitive_summary(q, wrong)
        for value in (1, "true", False):
            wrong = copy.deepcopy(report)
            wrong["primitives"]["raw_evidence"]["guards_and_complete_bodies_retained"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                q.next_evidence.primitive_summary(q, wrong)

    def test_clock_patch_exact_stream_bytes_and_empty_patch(self):
        path = self.directory / "patch.xz"
        self.archive(path, [("events.jsonl", b'{"actual":1}\n', {})])
        result = q.next_evidence.patch_bytes(q, path, {"events.jsonl": q.bytes_id(b'{"actual":1}\n')})
        self.assertEqual(result, {"events.jsonl": b'{"actual":1}\n'})
        empty = self.directory / "empty.xz"
        self.archive(empty, [])
        self.assertEqual(q.next_evidence.patch_bytes(q, empty, {}), {})
        original = path.read_bytes()
        for i, data in enumerate((original[:-1], original + b"x", original + original)):
            bad = self.directory / ("patch-stream-" + str(i))
            bad.write_bytes(data)
            with self.subTest(i=i), self.assertRaises((ValueError, lzma.LZMAError, tarfile.TarError, EOFError)):
                q.next_evidence.patch_bytes(q, bad, {"events.jsonl": q.bytes_id(b'{"actual":1}\n')})

    def test_clock_patch_rejects_replacement_paths_types_and_duplicate_members(self):
        variants = [
            [("../events.jsonl", b"x", {})],
            [("events.jsonl", b"x", {}), ("events.jsonl", b"x", {})],
            [("events.jsonl", b"x", {"mode": 0o755})],
            [("events.jsonl", b"x", {"uid": 1})],
            [("events.jsonl", b"x", {"pax_headers": {"comment": "hidden"}})],
            [("events.jsonl", b"", {"type": tarfile.SYMTYPE, "linkname": "/outside"})],
            [("events.jsonl", b"X", {})],
        ]
        for i, members in enumerate(variants):
            path = self.directory / ("patch-metadata-" + str(i) + ".xz")
            self.archive(path, members)
            with self.subTest(i=i), self.assertRaises((ValueError, tarfile.TarError)):
                q.next_evidence.patch_bytes(q, path, {"events.jsonl": q.bytes_id(b"x")})
        path = self.directory / "good-patch.xz"
        self.archive(path, [("events.jsonl", b"x", {})])
        with self.assertRaises(ValueError):
            q.next_evidence.patch_bytes(q, path, {"arbitrary": q.bytes_id(b"x")})
        with self.assertRaises(ValueError):
            q.next_evidence.patch_bytes(q, path, {"events.jsonl": {"bytes": True, "sha256": hashlib.sha256(b"x").hexdigest()}})

    def test_clock_raw_roster_and_types_reject_before_opening_files(self):
        report = {"schema": "trnm.hia.work-owner-actual-clock-reader-controls.v1",
                  "status": "PASS", "source_after": "MATCH", "baseline_after": "MATCH",
                  "source_inputs": {}, "actual_native_or_Rust_processes_executed_by_controls": 0,
                  "public_actual_reader_api": "hia.platform.work_owner.clock_evidence.audit",
                  "full_source_qualification_claimed_by_these_controls": False,
                  "count": 20, "positive": 2, "negative": 18,
                  "rows": [{"name": name} for name, _, _ in q.next_evidence.CONTROL_SPECS]}
        mutations = []
        for key in ("count", "positive", "negative", "actual_native_or_Rust_processes_executed_by_controls"):
            wrong = copy.deepcopy(report); wrong[key] = float(report[key]); mutations.append(wrong)
            wrong = copy.deepcopy(report); wrong[key] = False; mutations.append(wrong)
        wrong = copy.deepcopy(report); wrong["rows"] = wrong["rows"][:-1]; mutations.append(wrong)
        wrong = copy.deepcopy(report); wrong["rows"][0] = wrong["rows"][1]; mutations.append(wrong)
        wrong = copy.deepcopy(report); wrong["full_source_qualification_claimed_by_these_controls"] = 0; mutations.append(wrong)
        with mock.patch.object(q, "regular", side_effect=AssertionError("Must refuse before raw I/O")):
            for wrong in mutations:
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    q.next_evidence.clock_reader_controls(q, self.directory, wrong, {}, {}, {}, {}, [], {})


if __name__ == "__main__":
    unittest.main()
