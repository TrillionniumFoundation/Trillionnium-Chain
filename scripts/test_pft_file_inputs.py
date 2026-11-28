"""Real filesystem controls for the PFT CLI's bounded input boundary."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import pft_candidate_readback as identity

ROOT = Path(__file__).resolve().parents[1]
OBSERVATIONS = []


def tearDownModule():
    target = os.environ.get("TRNM_PFT_FILE_CONTROL_RECORDS")
    if target:
        with Path(target).open("xb") as output:
            output.write(identity.canonical(OBSERVATIONS) + b"\n")


class FileInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def observe(self, path, maximum):
        record = dict(test=self.id(), maximum=maximum)
        try:
            raw = identity.read_bounded(path, maximum)
            record.update(status="READ", bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            return raw
        except Exception as error:
            record.update(status="REFUSED", error_type=type(error).__name__,
                          error_code=str(error) if isinstance(error, ValueError) else "OS_ERROR",
                          errno=getattr(error, "errno", None))
            raise
        finally:
            OBSERVATIONS.append(record)

    def test_regular_exact_bound_and_empty_file(self):
        for raw in (b"", b"frozen input"):
            path = self.root / "input"
            path.write_bytes(raw)
            self.assertEqual(self.observe(path, len(raw)), raw)

    def test_oversized_regular_file_refuses_before_data_read(self):
        path = self.root / "input"
        path.write_bytes(b"a" * 1025)
        with mock.patch.object(identity.os, "read", side_effect=AssertionError("data read before size refusal")):
            with self.assertRaisesRegex(ValueError, "PFT_BYTE_LIMIT"):
                self.observe(path, 1024)

    def test_real_fifo_without_writer_refuses_in_owned_child(self):
        path = self.root / "fifo"
        os.mkfifo(path)
        code = ("import json,sys;sys.path.insert(0,sys.argv[1]);import pft_candidate_readback as p\n"
                "try:p.read_bounded(sys.argv[2],1024)\n"
                "except Exception as e:print(json.dumps({'type':type(e).__name__,'code':str(e)}));sys.exit(2)\n")
        began = time.monotonic_ns()
        child = subprocess.Popen([sys.executable, "-B", "-c", code, str(ROOT / "scripts"), str(path)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timed_out = False
        try:
            stdout, stderr = child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            stdout, stderr = child.communicate(timeout=2)
        record = dict(test=self.id(), input_kind="real FIFO without writer", timed_out=timed_out,
                      child_reaped=child.returncode is not None, returncode=child.returncode,
                      wall_ns=time.monotonic_ns() - began, stdout_bytes=len(stdout), stderr_bytes=len(stderr))
        OBSERVATIONS.append(record)
        self.assertFalse(timed_out)
        self.assertEqual(child.returncode, 2)
        record["refusal"] = json.loads(stdout)
        self.assertEqual(record["refusal"], dict(type="ValueError", code="PFT_FILE_TYPE"))

    def test_real_directory_refuses(self):
        with self.assertRaisesRegex(ValueError, "PFT_FILE_TYPE"):
            self.observe(self.root, 1024)

    def test_final_symlink_refuses_even_with_regular_target(self):
        target, link = self.root / "target", self.root / "link"
        target.write_bytes(b"ordinary bytes")
        link.symlink_to(target)
        with self.assertRaises(OSError):
            self.observe(link, 1024)

    def test_same_size_actual_rewrite_during_read_refuses(self):
        path = self.root / "input"
        original = b"a" * (2 * 65536)
        path.write_bytes(original)
        before = path.stat()
        begun, finished = threading.Event(), threading.Event()
        errors = []

        def writer():
            try:
                if not begun.wait(2):
                    raise AssertionError("reader never reached the first real read")
                with path.open("r+b") as stream:
                    stream.write(b"b" * len(original))
                    stream.flush()
                    os.fsync(stream.fileno())
                # Real metadata change is deterministic even on coarse filesystems.
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                finished.set()

        worker = threading.Thread(target=writer)
        worker.start()
        real_read = os.read

        def read_then_rewrite(fd, size):
            raw = real_read(fd, size)
            if not begun.is_set():
                begun.set()
                if not finished.wait(2):
                    raise AssertionError("actual writer did not complete")
            return raw

        try:
            with mock.patch.object(identity.os, "read", side_effect=read_then_rewrite):
                with self.assertRaisesRegex(ValueError, "PFT_FILE_CHANGED"):
                    self.observe(path, len(original))
        finally:
            begun.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(path.read_bytes(), b"b" * len(original))

    def test_independent_candidate_digest_still_refuses_changed_bytes(self):
        fixture = ROOT / "evidence/pft-candidate-readback-20261128"
        expected = identity.decode((fixture / "EXPECTED.json").read_bytes())
        original = (fixture / "SYNTHETIC_CANDIDATE.json").read_bytes()
        path = self.root / "candidate"
        path.write_bytes(original + b" ")
        raw = self.observe(path, identity.MAX_BYTES)
        with self.assertRaisesRegex(ValueError, "PFT_CANDIDATE_PIN"):
            identity.review_candidate(raw, expected)
        OBSERVATIONS.append(dict(test=self.id(), status="REFUSED", error_code="PFT_CANDIDATE_PIN",
                                 submitted_sha256=identity.sha(raw), expected_sha256=expected["candidate_sha256"]))


if __name__ == "__main__":
    unittest.main()
