#!/usr/bin/env python3
"""File-boundary controls; synthetic failures are not prior CI observations."""
import errno
import hashlib
import itertools
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collect_pinned_codeql_metadata_v1 as collector

HEAD = "39e865f453926a2b86565bf69e197a621e74b93c"


class MetadataControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "input"
        self.source.mkdir()
        self.output = self.base / "diagnostics"

    def put(self, name, raw):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def collect(self, *, sarif_only=False):
        summary = collector.collect(self.source, self.output, HEAD, "rust", 40836515003, 1,
                                    sarif_only=sarif_only)
        manifest = json.loads((self.output / "manifest.json").read_bytes())
        self.assertFalse(summary["analysis_outcome_inferred"])
        self.assertFalse(manifest["analysis_outcome_inferred"])
        self.assertFalse(manifest["official_security_gate_qualified"])
        self.assertFalse(manifest["production_qualified"])
        self.assertNotIn("passed", manifest)
        self.assertNotIn("finding_count", manifest)
        files = [p for p in self.output.rglob("*") if p.is_file()]
        self.assertLess(sum(p.stat().st_size for p in files),
                        collector.SARIF_ARTIFACT_LIMIT if sarif_only else collector.ARTIFACT_LIMIT)
        return manifest, {row["source_path"]: row for row in manifest["files"]}

    def test_synthetic_failure_bytes_and_returncode_are_not_promoted(self):
        # This is a new fixture, not a reconstruction of inaccessible C logs.
        phase = b'{"name":"analyze","complete":false,"returncode":100,"failure_code":"synthetic failure","stderr_truncated":true}\n'
        result = b'{"analysis_execution_complete":false,"finding_count":null,"failure":{"code":"synthetic failure"}}\n'
        self.put("analysis/analyze.execution.json", phase)
        self.put("analysis/result.json", result)
        options = b'{"name":"extractor-options","complete":true,"returncode":0}\n'
        inventory = b'{"extractor_options":{"cargo_target":{"type":"string"}}}\n'
        self.put("analysis/extractor-options.execution.json", options)
        self.put("analysis/extractor-options.stdout.log", inventory)
        manifest, rows = self.collect()
        for name, raw in (("analysis/analyze.execution.json", phase), ("analysis/result.json", result),
                          ("analysis/extractor-options.execution.json", options),
                          ("analysis/extractor-options.stdout.log", inventory)):
            self.assertEqual((self.output / rows[name]["artifact_member"]).read_bytes(), raw)
            self.assertEqual(rows[name]["sampled_bytes"], collector.fingerprint(raw))
        self.assertTrue(manifest["inventory_collected"])
        self.assertEqual(rows["analysis/create.execution.json"]["status"], "missing")

    def test_binary_tail_has_exact_range_and_no_full_stream_claim(self):
        raw = b"not retained prefix" + bytes(range(256)) * 1024
        source = self.put("analysis/analyze.stderr.log", raw)
        _, rows = self.collect()
        row = rows["analysis/analyze.stderr.log"]
        expected = raw[-collector.TAIL_LIMIT:]
        self.assertEqual(row["byte_start"], len(raw) - len(expected))
        self.assertEqual(row["byte_end_exclusive"], len(raw))
        self.assertEqual(row["retained_file_bytes_observed"], len(raw))
        self.assertEqual(row["sampled_bytes"]["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual((self.output / row["artifact_member"]).read_bytes(), expected)
        self.assertFalse(row["covers_retained_file"])
        self.assertFalse(row["complete_process_stream_claim"])
        self.assertEqual(source.read_bytes(), raw)

    def test_short_and_empty_retained_files_are_not_complete_process_streams(self):
        for name, raw in (("analysis/create.stdout.log", b"short"), ("analysis/create.stderr.log", b"")):
            self.put(name, raw)
        _, rows = self.collect()
        for name in ("analysis/create.stdout.log", "analysis/create.stderr.log"):
            self.assertTrue(rows[name]["covers_retained_file"])
            self.assertFalse(rows[name]["complete_process_stream_claim"])
            self.assertEqual(rows[name]["byte_start"], 0)

    def test_missing_root_stays_unavailable_in_every_row(self):
        self.source.rmdir()
        manifest, rows = self.collect()
        self.assertEqual(set(row["status"] for row in rows.values()), {"input_root_unavailable"})
        self.assertEqual(manifest["payload_bytes"], {"json": 0, "tails": 0})
        self.assertEqual({p.name for p in self.output.iterdir()}, {"manifest.json"})

    def test_full_json_file_limit_is_not_silent_truncation(self):
        path = self.put("analysis/result.json", b"{}")
        with path.open("ab") as file:
            file.truncate(collector.FULL_FILE_LIMIT + 1)
        _, rows = self.collect()
        self.assertEqual(rows["analysis/result.json"]["status"], "file_size_limit")
        self.assertNotIn("artifact_member", rows["analysis/result.json"])
        self.assertEqual(path.stat().st_size, collector.FULL_FILE_LIMIT + 1)

    def test_exact_full_file_limit_is_preserved(self):
        raw = b"{}" + b" " * (collector.FULL_FILE_LIMIT - 2)
        self.put("analysis/result.json", raw)
        _, rows = self.collect()
        row = rows["analysis/result.json"]
        self.assertEqual(row["status"], "copied")
        self.assertTrue(row["json_syntax_valid"])
        self.assertEqual((self.output / row["artifact_member"]).read_bytes(), raw)

    def test_json_total_budget_does_not_consume_reserved_log_budget(self):
        self.put("source-checkout.json", b"{}  ")
        self.put("source-final.json", b"{}  ")
        self.put("analysis/create.stderr.log", b"real tail bytes")
        with patch.object(collector, "JSON_TOTAL_LIMIT", 4):
            manifest, rows = self.collect()
        self.assertEqual(manifest["payload_bytes"]["json"], 4)
        self.assertEqual(rows["source-final.json"]["status"], "aggregate_size_limit")
        self.assertEqual(rows["analysis/create.stderr.log"]["status"], "copied")

    def test_log_total_budget_is_explicit(self):
        self.put("runner.log", b"1234")
        self.put("reader-controls.log", b"1234")
        with patch.object(collector, "TAIL_TOTAL_LIMIT", 4):
            manifest, rows = self.collect()
        self.assertEqual(manifest["payload_bytes"]["tails"], 4)
        self.assertEqual(rows["reader-controls.log"]["status"], "aggregate_size_limit")
        self.assertNotIn("artifact_member", rows["reader-controls.log"])

    def test_leaf_symlink_is_not_read(self):
        other = self.base / "outside.json"
        other.write_bytes(b'{"outside":true}')
        (self.source / "source-checkout.json").symlink_to(other)
        _, rows = self.collect()
        self.assertEqual(rows["source-checkout.json"]["status"], "unsafe_or_unreadable")
        self.assertNotIn("artifact_member", rows["source-checkout.json"])

    def test_intermediate_symlink_is_not_read(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "result.json").write_bytes(b"{}")
        (self.source / "analysis").symlink_to(outside, target_is_directory=True)
        _, rows = self.collect()
        self.assertEqual(rows["analysis/result.json"]["status"], "unsafe_or_unreadable")

    def test_input_root_symlink_is_not_read(self):
        original = self.base / "real-input"
        self.source.rename(original)
        self.source.symlink_to(original, target_is_directory=True)
        _, rows = self.collect()
        self.assertEqual(set(row["status"] for row in rows.values()), {"input_root_unavailable"})

    def test_directory_fifo_and_hardlink_are_not_regular_single_link_inputs(self):
        (self.source / "source-checkout.json").mkdir()
        os.mkfifo(self.source / "source-final.json")
        original = self.put("unlisted.json", b"{}")
        (self.source / "analysis").mkdir()
        os.link(original, self.source / "analysis/result.json")
        _, rows = self.collect()
        for name in ("source-checkout.json", "source-final.json", "analysis/result.json"):
            self.assertEqual(rows[name]["status"], "not_single_link_regular_file")

    def test_changed_file_is_not_copied(self):
        source = self.put("source-checkout.json", b'{"before":1}')
        pread = os.pread
        def changed(descriptor, count, offset):
            raw = pread(descriptor, count, offset)
            source.write_bytes(b'{"after":200}')
            return raw
        with patch.object(collector.os, "pread", side_effect=changed):
            _, rows = self.collect()
        self.assertEqual(rows["source-checkout.json"]["status"], "changed_during_read")
        self.assertNotIn("artifact_member", rows["source-checkout.json"])

    def test_read_error_stays_unknown_not_empty_success(self):
        self.put("source-checkout.json", b"{}")
        with patch.object(collector.os, "pread", side_effect=OSError(errno.EIO, "synthetic read error")):
            _, rows = self.collect()
        self.assertEqual(rows["source-checkout.json"]["status"], "file_read_error")
        self.assertNotIn("sampled_bytes", rows["source-checkout.json"])

    def test_malformed_duplicate_and_nonfinite_json_are_retained_without_validation_claim(self):
        raws = [b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b"\xff"]
        for name, raw in zip(collector.JSON_FILES, raws):
            self.put(name, raw)
        _, rows = self.collect()
        for name, raw in zip(collector.JSON_FILES, raws):
            self.assertFalse(rows[name]["json_syntax_valid"])
            self.assertEqual((self.output / rows[name]["artifact_member"]).read_bytes(), raw)

    def test_reported_success_does_not_promote_collector_security_flags(self):
        raw = b'{"passed":true,"official_security_gate_qualified":true,"finding_count":0}'
        self.put("analysis/result.json", raw)
        manifest, rows = self.collect()
        self.assertFalse(manifest["official_security_gate_qualified"])
        self.assertEqual((self.output / rows["analysis/result.json"]["artifact_member"]).read_bytes(), raw)

    def test_unlisted_files_and_database_are_not_enumerated_or_copied(self):
        self.put("arbitrary-extra.json", b"not part of declared diagnostic inventory")
        self.put("analysis/database/large.json", b"not part of declared diagnostic inventory")
        _, rows = self.collect()
        self.assertEqual(set(rows), set(collector.JSON_FILES + collector.LOG_FILES))
        self.assertFalse(any(row["status"] == "copied" for row in rows.values()))

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_output_inside_input_is_refused(self):
        self.output = self.source / "diagnostics"
        with self.assertRaisesRegex(ValueError, "separate absolute"):
            self.collect()

    def test_traversal_and_output_parent_symlink_are_refused(self):
        with self.assertRaisesRegex(ValueError, "without traversal"):
            collector.directory(self.base / "absent/../input")
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        self.output = alias / "diagnostics"
        with self.assertRaises(OSError):
            self.collect()

    def test_cooperative_deadline_keeps_unread_rows_explicit(self):
        self.put("source-checkout.json", b"{}")
        with patch.object(collector.time, "monotonic", side_effect=itertools.chain([0], itertools.repeat(31))):
            _, rows = self.collect()
        self.assertEqual(set(row["status"] for row in rows.values()), {"read_deadline_exceeded"})

    def test_invalid_requested_identity_is_refused_before_output(self):
        for head, language, run, attempt in (("short", "rust", 1, 1), (HEAD, "unknown", 1, 1),
                                              (HEAD, "rust", 0, 1), (HEAD, "rust", True, 1),
                                              (HEAD, "rust", 1, 2**64)):
            with self.subTest(head=head, language=language, run=run, attempt=attempt), self.assertRaises(ValueError):
                collector.collect(self.source, self.output, head, language, run, attempt)
        self.assertFalse(self.output.exists())

    def test_separate_sarif_retains_complete_bytes_above_metadata_limit(self):
        raw = b'{"version":"2.1.0","runs":[]}' + b" " * collector.FULL_FILE_LIMIT
        self.put("analysis/analysis.sarif", raw)
        failure = b'{"passed":false,"finding_count":780,"extraction_coverage_complete":false}'
        self.put("analysis/result.json", failure)
        self.put("analysis/database/unlisted.bqrs", b"must stay in the original full artifact")
        manifest, rows = self.collect(sarif_only=True)
        self.assertEqual(manifest["schema"], collector.SARIF_SCHEMA)
        self.assertEqual(set(rows), set(collector.SARIF_FILES))
        row = rows["analysis/analysis.sarif"]
        self.assertEqual(row["status"], "copied")
        self.assertTrue(row["covers_retained_file"])
        self.assertEqual((self.output / row["artifact_member"]).read_bytes(), raw)
        self.assertEqual(row["sampled_bytes"], collector.fingerprint(raw))
        self.assertEqual((self.output / rows["analysis/result.json"]["artifact_member"]).read_bytes(), failure)

    def test_oversized_sarif_remains_refused_and_never_truncated(self):
        source = self.put("analysis/analysis.sarif", b"{}").open("ab")
        with source:
            source.truncate(collector.SARIF_FILE_LIMIT + 1)
        _, rows = self.collect(sarif_only=True)
        row = rows["analysis/analysis.sarif"]
        self.assertEqual(row["status"], "file_size_limit")
        self.assertEqual(row["file_size_limit"], collector.SARIF_FILE_LIMIT)
        self.assertNotIn("artifact_member", row)

    def test_separate_sarif_still_refuses_links_and_records_missing_source(self):
        external = self.base / "other.sarif"
        external.write_bytes(b'{"runs":[]}')
        (self.source / "analysis").mkdir()
        (self.source / "analysis/analysis.sarif").symlink_to(external)
        _, rows = self.collect(sarif_only=True)
        self.assertEqual(rows["analysis/analysis.sarif"]["status"], "unsafe_or_unreadable")
        self.assertEqual(rows["analysis/source-before.json"]["status"], "missing")

    def test_sarif_profile_does_not_relax_other_json_size_bounds(self):
        path = self.put("analysis/result.json", b"{}")
        with path.open("ab") as file:
            file.truncate(collector.FULL_FILE_LIMIT + 1)
        _, rows = self.collect(sarif_only=True)
        self.assertEqual(rows["analysis/result.json"]["status"], "file_size_limit")
        self.assertEqual(rows["analysis/result.json"]["file_size_limit"], collector.FULL_FILE_LIMIT)


if __name__ == "__main__":
    unittest.main()
