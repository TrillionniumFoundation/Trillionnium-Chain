#!/usr/bin/env python3
"""Independent tiny packages exercise consistency and adversarial boundaries."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import verify_bundle as verifier


def meta(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'archives').mkdir()
        (self.root / 'inventories').mkdir()
        self.rows = [('native/stdout', b'actual retained output\n'), ('native/elf', b'\x7fELF\x00\xff')]
        self.inventory = {name: meta(data) for name, data in self.rows}
        self.manifest = {'schema': verifier.SCHEMA, **dict.fromkeys(verifier.FALSE_FLAGS, False)}
        self.archive()

    def archive(self, rows=None, suffix=b''):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name, data in self.rows if rows is None else rows:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        import lzma
        data = lzma.compress(stream.getvalue() + suffix)
        path = 'archives/tiny.part-0000'
        (self.root / path).write_bytes(data)
        inv = 'inventories/tiny.json'
        (self.root / inv).write_text(json.dumps(self.inventory))
        self.manifest['archives'] = [{'name': 'tiny', 'format': 'tar.xz',
            **meta(data), 'inventory': inv, 'members': len(self.inventory),
            'uncompressed_member_bytes': sum(x['bytes'] for x in self.inventory.values()),
            'parts': [{'path': path, **meta(data)}]}]
        self.pin()

    def pin(self):
        self.manifest['files'] = {p.relative_to(self.root).as_posix(): meta(p.read_bytes())
            for p in self.root.rglob('*') if p.is_file() and p.name != 'manifest.json'}
        (self.root / 'manifest.json').write_text(json.dumps(self.manifest))

    def fails(self):
        with self.assertRaises((ValueError, OSError, tarfile.TarError, EOFError)):
            verifier.verify(self.root)

    def test_complete_bytes_pass_without_execution_or_qualification(self):
        result = verifier.verify(self.root)
        self.assertEqual((result['consistency'], result['original_archive_members']), ('PASS', 2))
        self.assertFalse(result['native_tests_executed'])
        self.assertTrue(all(result[flag] is False for flag in verifier.FALSE_FLAGS))

    def test_external_manifest_anchor(self):
        with self.assertRaises(ValueError):
            verifier.verify(self.root, '0' * 64)

    def test_changed_part(self):
        p = self.root / 'archives/tiny.part-0000'
        p.write_bytes(p.read_bytes()[:-1] + b'X')
        self.fails()

    def test_missing_part(self):
        (self.root / 'archives/tiny.part-0000').unlink()
        self.fails()

    def test_unlisted_top_level_file(self):
        (self.root / 'unlisted').write_bytes(b'extra')
        self.fails()

    def test_symlink_even_with_same_bytes(self):
        p = self.root / 'archives/tiny.part-0000'
        target = self.root / 'target'
        p.rename(target)
        p.symlink_to(target)
        self.fails()

    def test_false_qualification_flag_cannot_be_promoted(self):
        self.manifest['qualified'] = True
        self.pin()
        self.fails()

    def test_wrong_member_despite_valid_new_archive_hash(self):
        self.archive([self.rows[0], (self.rows[1][0], b'changed bytes')])
        self.fails()

    def test_unknown_member_with_valid_archive_hash(self):
        self.archive(self.rows + [('unknown', b'x')])
        self.fails()

    def test_duplicate_member_with_valid_archive_hash(self):
        self.archive(self.rows + [self.rows[0]])
        self.fails()

    def test_missing_member_with_valid_archive_hash(self):
        self.archive(self.rows[:1])
        self.fails()

    def test_hidden_second_tar_stream(self):
        self.archive(suffix=b'hidden nonzero bytes')
        self.fails()

    def test_parent_traversal_member(self):
        self.archive([('../outside', b'x')])
        self.fails()


if __name__ == '__main__':
    unittest.main()
