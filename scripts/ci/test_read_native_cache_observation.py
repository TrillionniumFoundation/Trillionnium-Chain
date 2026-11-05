"""Negative receipt controls; synthetic records are never native evidence."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import read_native_cache_observation as reader

from read_native_cache_observation import PREFIX, SELECTOR, Rejected, main, strict_json, validate


class NativeCacheReceiptTests(unittest.TestCase):
    def setUp(self):
        self.source = {"schema": "trnm-ci-source-v1", "kind": "head", "candidate": "a" * 40,
                       "tested_commit": "a" * 40, "tested_tree": "b" * 40, "base": None,
                       "prospective_merge": None, "tracked_worktree_verified": True,
                       "tests_executed_by_identity_check": False}
        self.rows = []
        for rows in (1, 257, 4096):
            for round_ in range(4):
                self.rows.append({"delta_root": "c" * 64, "elapsed_ns": 100 + round_,
                                  "full_checks_preserved": True, "independent_operator": False,
                                  "progress_calls": 50 * (3 + rows // 256), "repetitions": 50,
                                  "round": round_, "rows": rows,
                                  "statement_cache_capacity": (0, 16, 16, 0)[round_],
                                  "whole_node_throughput_measured": False, "width": 12})

    def log(self):
        return "\n".join([f"test {SELECTOR} ... ok"] +
                         [PREFIX + json.dumps(row) for row in self.rows] +
                         ["test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 403 filtered out; finished in 1.48s"])

    def check(self, log=None, **kwargs):
        return validate(self.log() if log is None else log, self.source,
                        kwargs.pop("after", copy.deepcopy(self.source)),
                        head=kwargs.pop("head", "a" * 40), kind=kwargs.pop("kind", "head"), **kwargs)

    def rejected(self):
        with self.assertRaises(Rejected):
            self.check()

    def test_complete_head(self):
        result = self.check()
        self.assertEqual(result["complete_calls"], 600)
        self.assertEqual(len(result["observations"]), 12)
        self.assertFalse(result["speed_qualification"])

    def test_complete_merge_and_wrong_merge(self):
        self.source.update(kind="prospective-merge", base="d" * 40, prospective_merge="e" * 40, tested_commit="e" * 40)
        self.check(kind="prospective-merge", base="d" * 40, merge="e" * 40)
        with self.assertRaises(Rejected):
            self.check(kind="prospective-merge", base="d" * 40, merge="f" * 40)

    def test_missing_measurement(self):
        self.rows.pop()
        self.rejected()

    def test_duplicate_measurement(self):
        self.rows[-1] = self.rows[-2]
        self.rejected()

    def test_reordered_measurements(self):
        self.rows[0], self.rows[1] = self.rows[1], self.rows[0]
        self.rejected()

    def test_invalid_integer_fields(self):
        for key in ("elapsed_ns", "progress_calls", "repetitions", "round", "rows", "statement_cache_capacity", "width"):
            for value in (True, "1", 1.0):
                with self.subTest(key=key, value=value):
                    original = self.rows[0][key]
                    self.rows[0][key] = value
                    self.rejected()
                    self.rows[0][key] = original

    def test_invalid_elapsed(self):
        for value in (0, -1, 2**128):
            self.rows[0]["elapsed_ns"] = value
            self.rejected()

    def test_progress_and_dimensions(self):
        for key in ("progress_calls", "repetitions", "width", "statement_cache_capacity"):
            original = self.rows[0][key]
            self.rows[0][key] += 1
            self.rejected()
            self.rows[0][key] = original

    def test_scope_promotions(self):
        for key in ("full_checks_preserved", "independent_operator", "whole_node_throughput_measured"):
            original = self.rows[0][key]
            self.rows[0][key] = not original
            self.rejected()
            self.rows[0][key] = original

    def test_different_or_invalid_roots(self):
        for value in ("d" * 64, "bad", 7):
            self.rows[1]["delta_root"] = value
            self.rejected()

    def test_unknown_and_missing_fields(self):
        self.rows[0]["external_acceptance"] = True
        self.rejected()
        del self.rows[0]["external_acceptance"]
        del self.rows[0]["width"]
        self.rejected()

    def test_failed_and_ambiguous_test_receipts(self):
        good = self.log()
        for log in (good.replace("1 passed; 0 failed", "0 passed; 1 failed"),
                    good + "\ntest result: FAILED. 0 passed; 1 failed;",
                    good + "\nerror: test failed", good + "\nfailures:",
                    good.replace(" ... ok", " ... ignored"), good.replace(SELECTOR, "wrong")):
            with self.subTest(log=log[-80:]), self.assertRaises(Rejected):
                self.check(log)

    def test_wrong_source_and_changed_checkout(self):
        with self.assertRaises(Rejected):
            self.check(head="f" * 40)
        with self.assertRaises(Rejected):
            self.check(after={**self.source, "tested_tree": "e" * 40})
        self.source["tracked_worktree_verified"] = 1
        self.rejected()

    def test_head_cannot_borrow_merge(self):
        with self.assertRaises(Rejected):
            self.check(base="d" * 40, merge="e" * 40)

    def test_invalid_json_duplicate_and_nonfinite(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{'):
            with self.subTest(raw=raw), self.assertRaises(Rejected):
                strict_json(raw)

    def test_unknown_version(self):
        with self.assertRaises(Rejected):
            self.check(self.log().replace(PREFIX, PREFIX.replace("v1", "v2"), 1))

    def test_cli_create_new_and_missing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "log").write_text(self.log())
            (root / "source").write_text(json.dumps(self.source))
            args = [str(root / "log"), "--source", str(root / "source"),
                    "--source-after", str(root / "source"), "--expected-head", "a" * 40,
                    "--kind", "head", "--output", str(root / "out")]
            self.assertEqual(main(args), 0)
            original = (root / "out").read_bytes()
            with self.assertRaises(SystemExit):
                main(args)
            self.assertEqual((root / "out").read_bytes(), original)
            (root / "log").unlink()
            with self.assertRaises(SystemExit):
                main(args)

    def test_cli_oversized_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "log").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            with self.assertRaises(SystemExit):
                main([str(root / "log"), "--source", str(root / "absent"),
                      "--source-after", str(root / "absent"), "--expected-head", "a" * 40,
                      "--kind", "head", "--output", str(root / "out")])
            self.assertFalse((root / "out").exists())


class NativeCacheInputTests(unittest.TestCase):
    """Real local file/pipe controls, not native execution or external evidence."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "input"
        self.path.write_bytes(b"abcd")

    def test_regular_exact_limit_and_chunked_bytes(self):
        for data in (b"abcd", b"\x00\xff\r\n" * 20000):
            self.path.write_bytes(data)
            self.assertEqual(reader.read_bounded(self.path, len(data)), data)

    def test_empty_oversized_and_invalid_limits_do_not_read(self):
        for data in (b"", b"x" * 17):
            self.path.write_bytes(data)
            with mock.patch.object(reader.os, "open") as opened:
                with self.assertRaises(Rejected):
                    reader.read_bounded(self.path, 16)
                opened.assert_not_called()
        for limit in (0, -1, True, 2.5, "4", 2**31):
            with mock.patch.object(reader.os, "open") as opened:
                with self.assertRaises(Rejected):
                    reader.read_bounded(self.path, limit)
                opened.assert_not_called()

    def test_directory_symlink_and_device_do_not_open(self):
        link = self.root / "link"
        link.symlink_to(self.path)
        for path in (self.root, link, Path(os.devnull)):
            with self.subTest(path=path), mock.patch.object(reader.os, "open") as opened:
                with self.assertRaises(Rejected):
                    reader.read_bounded(path, 16)
                opened.assert_not_called()

    def test_fifo_without_writer_cli_rejects_without_output(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        result = subprocess.run(
            [sys.executable, reader.__file__, str(fifo), "--source", str(self.path),
             "--source-after", str(self.path), "--expected-head", "a" * 40,
             "--kind", "head", "--output", str(self.root / "output")],
            capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"NATIVE_CACHE_RECEIPT_REJECTED", result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse((self.root / "output").exists())

    def test_fifo_substituted_at_open_does_not_block(self):
        code = '''
import os, sys
from unittest.mock import patch
import read_native_cache_observation as reader
path = sys.argv[1]
original = os.open
def replace(path, flags):
    assert flags & os.O_NONBLOCK
    os.unlink(path)
    os.mkfifo(path)
    return original(path, flags)
with patch.object(reader.os, "open", side_effect=replace):
    try:
        reader.read_bounded(path, 16)
    except reader.Rejected:
        raise SystemExit(0)
raise SystemExit(2)
'''
        result = subprocess.run([sys.executable, "-c", code, str(self.path)],
                                cwd=Path(reader.__file__).parent,
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_symlink_substituted_at_open_is_rejected(self):
        target = self.root / "target"
        target.write_bytes(b"abcd")
        original = os.open

        def replace(path, flags):
            self.path.unlink()
            self.path.symlink_to(target)
            return original(path, flags)

        with mock.patch.object(reader.os, "open", side_effect=replace):
            with self.assertRaises((OSError, Rejected)):
                reader.read_bounded(self.path, 16)

    def test_same_bytes_replacement_before_open_is_rejected(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(b"abcd")
        original = os.open

        def replace(path, flags):
            os.replace(replacement, self.path)
            return original(path, flags)

        with mock.patch.object(reader.os, "open", side_effect=replace):
            with self.assertRaises(Rejected):
                reader.read_bounded(self.path, 16)

    def test_same_bytes_replacement_after_open_is_rejected(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(b"abcd")
        original = os.read

        def replace(descriptor, limit):
            data = original(descriptor, limit)
            if replacement.exists():
                os.replace(replacement, self.path)
            return data

        with mock.patch.object(reader.os, "read", side_effect=replace):
            with self.assertRaises(Rejected):
                reader.read_bounded(self.path, 16)

    def test_growth_stops_at_one_extra_byte_and_closes(self):
        original = os.read
        consumed = []

        def grow(descriptor, limit):
            if not consumed:
                with self.path.open("ab") as stream:
                    stream.write(b"x" * 128)
            data = original(descriptor, limit)
            consumed.append(len(data))
            return data

        with mock.patch.object(reader.os, "read", side_effect=grow):
            with mock.patch.object(reader.os, "close", wraps=os.close) as closed:
                with self.assertRaises(Rejected):
                    reader.read_bounded(self.path, 16)
                closed.assert_called_once()
        self.assertEqual(sum(consumed), 17)

    def test_truncation_during_read_is_rejected(self):
        original = os.read
        changed = False

        def truncate(descriptor, limit):
            nonlocal changed
            if not changed:
                changed = True
                self.path.write_bytes(b"a")
            return original(descriptor, limit)

        with mock.patch.object(reader.os, "read", side_effect=truncate):
            with self.assertRaises(Rejected):
                reader.read_bounded(self.path, 16)

    def test_same_length_mutation_during_read_is_rejected(self):
        original = os.read
        changed = False

        def rewrite(descriptor, limit):
            nonlocal changed
            data = original(descriptor, limit)
            if not changed:
                changed = True
                before = self.path.stat()
                self.path.write_bytes(b"wxyz")
                os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
            return data

        with mock.patch.object(reader.os, "read", side_effect=rewrite):
            with self.assertRaises(Rejected):
                reader.read_bounded(self.path, 16)

    def test_unlink_during_read_is_rejected(self):
        original = os.read

        def unlink(descriptor, limit):
            data = original(descriptor, limit)
            if self.path.exists():
                self.path.unlink()
            return data

        with mock.patch.object(reader.os, "read", side_effect=unlink):
            with self.assertRaises((OSError, Rejected)):
                reader.read_bounded(self.path, 16)

    def test_read_and_fstat_errors_close_the_descriptor(self):
        for operation in ("read", "fstat"):
            with self.subTest(operation=operation):
                with mock.patch.object(reader.os, operation, side_effect=OSError("injected I/O")):
                    with mock.patch.object(reader.os, "close", wraps=os.close) as closed:
                        with self.assertRaisesRegex(OSError, "injected I/O"):
                            reader.read_bounded(self.path, 16)
                        closed.assert_called_once()
                        descriptor = closed.call_args.args[0]
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_short_reads_return_complete_bytes_and_close_once(self):
        original = os.read
        with mock.patch.object(reader.os, "read", side_effect=lambda fd, n: original(fd, min(n, 1))):
            with mock.patch.object(reader.os, "close", wraps=os.close) as closed:
                self.assertEqual(reader.read_bounded(self.path, 4), b"abcd")
                closed.assert_called_once()

    def test_fifo_in_each_cli_input_position_never_creates_receipt(self):
        fixture = NativeCacheReceiptTests()
        fixture.setUp()
        log = self.root / "log"
        source = self.root / "source"
        log.write_text(fixture.log(), encoding="utf-8")
        source.write_text(json.dumps(fixture.source), encoding="utf-8")
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for index in range(3):
            paths = [log, source, source]
            paths[index] = fifo
            output = self.root / f"out-{index}"
            result = subprocess.run(
                [sys.executable, reader.__file__, str(paths[0]), "--source", str(paths[1]),
                 "--source-after", str(paths[2]), "--expected-head", "a" * 40,
                 "--kind", "head", "--output", str(output)],
                capture_output=True, timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn(b"NATIVE_CACHE_RECEIPT_REJECTED", result.stderr)
            self.assertFalse(output.exists())

    def test_cli_read_error_keeps_existing_output_unchanged(self):
        output = self.root / "output"
        output.write_bytes(b"retained prior receipt")
        with mock.patch.object(reader.os, "read", side_effect=OSError("injected I/O")):
            with self.assertRaises(SystemExit) as failure:
                main([str(self.path), "--source", str(self.path), "--source-after", str(self.path),
                      "--expected-head", "a" * 40, "--kind", "head", "--output", str(output)])
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(output.read_bytes(), b"retained prior receipt")


if __name__ == "__main__":
    unittest.main()
