#!/usr/bin/env python3
"""Parser counterexamples; these fixtures are not native performance evidence."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "sqlite_syscall_profile", Path(__file__).with_name("sqlite_syscall_profile.py")
)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
WAL = "/tmp/owned-node/native.sqlite-wal"


class SyscallProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.trace, self.binary = root / "trace.log", root / "native-test"
        self.source, self.capture = root / "source.json", root / "capture.json"
        self.binary.write_bytes(b"parser-fixture-not-an-executed-native-binary")
        self.source.write_text('{"scope":"unit fixture only"}\n')

    def prepare(self, rows, exit_code=0, close=True):
        events = [(10, f'execve("{self.binary}", ["n"...], 0x1) = 0 <0.000100>')]
        events.extend(rows)
        if close:
            events.append((10, f"+++ exited with {exit_code} +++"))
        self.trace.write_text("".join(
            f"{tid} 1000.{index:06d} {body}\n" for index, (tid, body) in enumerate(events)
        ))
        receipt = {
            "schema": PROFILE.CAPTURE_SCHEMA,
            "command": PROFILE.command_for(self.trace, self.binary, ["--exact", "test"]),
            "binary_sha256": PROFILE.sha256_file(self.binary),
            "source_receipt_sha256": PROFILE.sha256_file(self.source),
            "trace_sha256": PROFILE.sha256_file(self.trace),
            "source_commit": "1" * 40,
            "source_tree": "2" * 40,
            "capture_started_unix_ns": 999_999_000_000,
            "capture_finished_unix_ns": 1_001_000_000_000,
            "strace_returncode": exit_code,
        }
        self.capture.write_text(json.dumps(receipt))
        return receipt

    def read(self):
        return PROFILE.read_profile(self.trace, self.binary, self.source, self.capture, [WAL])

    def row(self, report, name="pwrite64"):
        return report["observed"]["wal_by_exact_path"][WAL][name]

    def test_complete_trace_keeps_failed_native_exit_and_fsync_error_denominator(self):
        self.prepare([
            (10, f'pwrite64(7<{WAL}>, "x"..., 64, 0) = 64 <0.000012>'),
            (10, f"fsync(7<{WAL}>) = 0 <0.000004>"),
            (10, f"fdatasync(7<{WAL}>) = -1 EIO (Input/output error) <0.000006>"),
        ], exit_code=7)
        result = self.read()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["capture"]["root_termination"], {"exit_code": 7})
        self.assertEqual(self.row(result)["returned_write_bytes_known"], 64)
        self.assertEqual(self.row(result)["duration_ns_known_sum"], 12_000)
        failed = self.row(result, "fdatasync")
        self.assertEqual(failed["attempt_starts_observed"], 1)
        self.assertEqual(failed["failures_observed"], 1)
        self.assertEqual(failed["errors_observed"], {"EIO": 1})
        self.assertFalse(result["limits"]["original_4s_contract_accepted"])
        self.assertFalse(result["limits"]["campaign_30s_contract_accepted"])

    def test_interleaved_resume_counts_once_and_fd_reuse_uses_each_calls_path(self):
        self.prepare([
            (10, f'pwrite64(7<{WAL}>, "x"..., 64, 0 <unfinished ...>'),
            (11, 'pwrite64(7</tmp/other>, "y"..., 999, 0) = 999 <0.000002>'),
            (10, "<... pwrite64 resumed>) = 64 <0.000010>"),
            (10, 'pwrite64(7</tmp/reused>, "z"..., 800, 0) = 800 <0.000003>'),
            (11, "+++ exited with 0 +++"),
        ])
        result = self.read()
        self.assertEqual(result["status"], "complete")
        wal = self.row(result)
        self.assertEqual(wal["attempt_starts_observed"], 1)
        self.assertEqual(wal["terminal_records_observed"], 1)
        self.assertEqual(wal["returned_write_bytes_known"], 64)
        self.assertEqual(wal["duration_ns_known_sum"], 10_000)
        other = result["observed"]["other_annotated_fds"]["pwrite64"]
        self.assertEqual(other["returned_write_bytes_known"], 1799)

    def test_unmatched_wrong_name_and_ambiguous_resumes_never_inherit_fd(self):
        cases = [
            [(10, "<... pwrite64 resumed>) = 64 <0.000010>")],
            [(10, f'pwrite64(7<{WAL}>, "x", 1, 0 <unfinished ...>'),
             (11, "<... pwrite64 resumed>) = 1 <0.000010>"),
             (11, "+++ exited with 0 +++")],
            [(10, f'pwrite64(7<{WAL}>, "x", 1, 0 <unfinished ...>'),
             (10, "<... fsync resumed>) = 0 <0.000010>")],
            [(10, f'pwrite64(7<{WAL}>, "x", 1, 0 <unfinished ...>'),
             (10, 'pwrite64(7</tmp/reused>, "x", 1, 0 <unfinished ...>'),
             (10, "<... pwrite64 resumed>) = 1 <0.000010>")],
            [(10, f'pwrite64(7<{WAL}>, "x", 1, 0 <unfinished ...>'),
             (10, "unknown event could hide a new entry"),
             (10, "<... pwrite64 resumed>) = 1 <0.000010>")],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                self.prepare(rows)
                result = self.read()
                self.assertEqual(result["status"], "partial")
                self.assertIsNone(result["complete_selected_wal_totals"])
                self.assertEqual(self.row(result)["returned_write_bytes_known"], 0)
                self.assertGreater(result["observed"]["unmatched_resumes"], 0)

    def test_partial_unknown_and_restart_results_are_not_successful_zero(self):
        cases = [
            [(10, f'fsync(7<{WAL}> <unfinished ...>')],
            [(10, f"fsync(7<{WAL}>) = ? ERESTARTSYS (To be restarted) <0.000001>")],
            [(10, 'pwrite64(7, "x", 1, 0) = -1 EBADF (Bad file descriptor) <0.000001>')],
            [(10, f'pwrite64(7<{WAL} (deleted)>, "x", 1, 0) = 1 <0.000001>')],
            [(10, 'pwrite64(7</tmp/a\\040b-wal>, "x", 1, 0) = 1 <0.000001>')],
            [(10, f"fsync(7<{WAL}>) = 0")],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                self.prepare(rows)
                result = self.read()
                self.assertEqual(result["status"], "partial")
                self.assertIsNone(result["complete_selected_wal_totals"])
        self.prepare([
            (10, f'pwrite64(7<{WAL}>, "x", 1, 0) = ? ERESTARTSYS (To be restarted) <0.000001>'),
            (10, f'pwrite64(7<{WAL}>, "x", 1, 0) = 1 <0.000002>'),
        ])
        row = self.row(self.read())
        self.assertEqual(row["attempt_starts_observed"], 2)
        self.assertEqual(row["unknown_results_observed"], 1)
        self.assertEqual(row["failures_observed"], 0)
        self.assertEqual(row["successes_observed"], 1)
        self.assertEqual(row["returned_write_bytes_known"], 1)

    def test_pid_reuse_truncation_missing_exits_and_unknown_lines_force_partial(self):
        base = (10, f'pwrite64(7<{WAL}>, "x", 1, 0) = 1 <0.000001>')
        for rows, close in [
            ([base], False),
            ([base, (10, "+++ exited with 0 +++"), base], False),
            ([base, (10, "strace event not understood")], True),
            ([], True),
        ]:
            with self.subTest(rows=rows):
                self.prepare(rows, close=close)
                result = self.read()
                self.assertEqual(result["status"], "partial")
                self.assertIsNone(result["complete_selected_wal_totals"])

    def test_all_write_families_use_returned_bytes_and_preserve_errors(self):
        rows = [(10, f'{name}(7<{WAL}>, 0x1, 64) = 3 <0.000001>') for name in PROFILE.WRITES]
        rows.append((10, f'pwrite64(7<{WAL}>, "x", 1, 0) = -1 ENOSPC (No space) <0.000002>'))
        self.prepare(rows)
        result = self.read()
        self.assertEqual(result["status"], "complete")
        for name in PROFILE.WRITES:
            self.assertEqual(self.row(result, name)["returned_write_bytes_known"], 3)
        self.assertEqual(self.row(result)["failures_observed"], 1)

    def test_unparseable_line_quarantines_pending_call_and_duplicate_receipt_refuses(self):
        receipt = self.prepare([
            (10, f'pwrite64(7<{WAL}>, "x", 1, 0 <unfinished ...>'),
            (10, "<... pwrite64 resumed>) = 1 <0.000010>"),
        ])
        lines = self.trace.read_text().splitlines(keepends=True)
        lines.insert(2, "unidentified partial line\n")
        self.trace.write_text("".join(lines))
        receipt["trace_sha256"] = PROFILE.sha256_file(self.trace)
        self.capture.write_text(json.dumps(receipt))
        result = self.read()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(self.row(result)["returned_write_bytes_known"], 0)
        self.assertEqual(self.row(result)["uncompleted_calls_observed"], 1)
        self.capture.write_text('{"schema":"x","schema":"y"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.read()

    def test_capture_hashes_filtered_commands_and_binary_exec_must_match(self):
        rows = [(10, f"fsync(7<{WAL}>) = 0 <0.000001>")]
        for path in (self.trace, self.binary, self.source):
            with self.subTest(path=path):
                self.prepare(rows)
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.assertRaisesRegex(ValueError, "hash binding mismatch"):
                    self.read()
                path.write_bytes(original)
        for change in ("filtered", "completion", "returncode"):
            receipt = self.prepare(rows)
            if change == "filtered":
                receipt["command"].insert(1, "-z")
            elif change == "completion":
                receipt["capture_finished_unix_ns"] = None
            else:
                receipt["strace_returncode"] = 7
            self.capture.write_text(json.dumps(receipt))
            if change == "filtered":
                with self.assertRaisesRegex(ValueError, "all-status"):
                    self.read()
            else:
                self.assertEqual(self.read()["status"], "partial")
        receipt = self.prepare(rows)
        self.trace.write_text(self.trace.read_text().replace(str(self.binary), "/tmp/other-binary"))
        receipt["trace_sha256"] = PROFILE.sha256_file(self.trace)
        self.capture.write_text(json.dumps(receipt))
        self.assertEqual(self.read()["status"], "partial")

    def test_unknown_exec_result_cannot_inherit_previously_bound_binary(self):
        for call in ('execve("/tmp/other", ["o"], 0x1)',
                     'execveat(9</tmp/other>, "", ["o"], 0x1, AT_EMPTY_PATH)'):
            for result in ("?", "? ERESTARTSYS (To be restarted)", "1"):
                with self.subTest(call=call, result=result):
                    self.prepare([
                        (10, f"{call} = {result} <0.000001>"),
                        (10, f"fsync(7<{WAL}>) = 0 <0.000001>"),
                    ])
                    report = self.read()
                    self.assertEqual(report["status"], "partial")
                    self.assertIn("executable_result_unresolved", report["issues"]["counts"])
                    self.assertIsNone(report["complete_selected_wal_totals"])
            # A real failed exec retains the known image and is not an unknown
            # successful switch to the unbound pathname in its arguments.
            self.prepare([
                (10, f"{call} = -1 ENOENT (No such file or directory) <0.000001>"),
                (10, f"fsync(7<{WAL}>) = 0 <0.000001>"),
            ])
            self.assertEqual(self.read()["status"], "complete")


if __name__ == "__main__":
    unittest.main()
