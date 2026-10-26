#!/usr/bin/env python3
"""Byte preservation and adversarial bounded-decompression controls."""
import gzip
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from w1_lossless_raw import bounded_raw_lines, compress_completed_stdout, verified_raw_stream


class LosslessRawTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.raw = (b'{"proof":"' + b'a' * 70001 + b'"}\n') * 3
        self.path = self.root / 'job.stdout'
        self.path.write_bytes(self.raw)
        self.step = dict(complete_success=True, stdout_truncated=False, stdout=self.path.name,
                         stdout_bytes=len(self.raw), stdout_sha256=hashlib.sha256(self.raw).hexdigest())
    def tearDown(self):
        self.directory.cleanup()
    def test_verified_roundtrip_preserves_step_and_removes_only_original(self):
        before = dict(self.step)
        receipt = compress_completed_stdout(self.root, self.step)
        self.assertEqual(self.step, before)
        self.assertFalse(self.path.exists())
        archive = self.root / receipt['path']
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), receipt['compressed_sha256'])
        self.assertEqual(b''.join(verified_raw_stream(archive, len(self.raw), self.step['stdout_sha256'])), self.raw)
        self.assertEqual(b''.join(bounded_raw_lines(archive)), self.raw)
    def test_bad_original_digest_retains_source(self):
        self.step['stdout_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'RAW_SHA256_MISMATCH'):
            compress_completed_stdout(self.root, self.step)
        self.assertEqual(self.path.read_bytes(), self.raw)
    def test_truncated_or_failed_command_is_not_deleted(self):
        for key in ('stdout_truncated', 'complete_success'):
            bad = dict(self.step, **{key: not self.step[key]})
            with self.assertRaisesRegex(ValueError, 'COMPRESSION_REQUIRES_COMPLETE_STDOUT'):
                compress_completed_stdout(self.root, bad)
        self.assertTrue(self.path.exists())
    def test_decompression_output_and_line_bounds(self):
        path = self.root / 'bomb.gz'
        path.write_bytes(gzip.compress(b'z' * 1000000, mtime=0))
        with self.assertRaisesRegex(ValueError, 'RAW_DECOMPRESSED_LIMIT'):
            list(verified_raw_stream(path, max_output_bytes=4096))
        with self.assertRaisesRegex(ValueError, 'RAW_LINE_TOO_LONG'):
            list(bounded_raw_lines(path, max_output_bytes=1000000, max_line_bytes=1024))
    def test_truncated_gzip_rejected(self):
        path = self.root / 'truncated.gz'
        path.write_bytes(gzip.compress(self.raw, mtime=0)[:-1])
        with self.assertRaisesRegex(ValueError, 'GZIP_TRUNCATED'):
            list(verified_raw_stream(path))
    def test_extra_member_and_trailing_bytes_rejected(self):
        path = self.root / 'extra.gz'
        for extra in (b'X', gzip.compress(b'\n', mtime=0)):
            path.write_bytes(gzip.compress(self.raw, mtime=0) + extra)
            with self.assertRaisesRegex(ValueError, 'GZIP_TRAILING_BYTES_OR_MEMBER'):
                list(verified_raw_stream(path))
    def test_bool_length_and_symlink_rejected(self):
        with self.assertRaisesRegex(ValueError, 'RAW_EXPECTED_BYTES'):
            list(verified_raw_stream(self.path, True))
        link = self.root / 'linked.stdout'
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'RAW_NOT_REGULAR'):
            list(verified_raw_stream(link))
    def test_existing_archive_and_path_escape_leave_original(self):
        (self.root / (self.path.name + '.gz')).write_bytes(b'previous')
        with self.assertRaises(FileExistsError):
            compress_completed_stdout(self.root, self.step)
        with self.assertRaisesRegex(ValueError, 'STDOUT_BASENAME'):
            compress_completed_stdout(self.root, dict(self.step, stdout='../outside'))
        self.assertTrue(self.path.exists())
    def test_plain_exact_length_and_hash_checked(self):
        with self.assertRaisesRegex(ValueError, 'RAW_LENGTH_MISMATCH'):
            list(verified_raw_stream(self.path, len(self.raw) - 1))
        with self.assertRaisesRegex(ValueError, 'RAW_SHA256_MISMATCH'):
            list(verified_raw_stream(self.path, len(self.raw), '0' * 64))

if __name__ == '__main__':
    unittest.main()
