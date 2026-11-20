"""Real filesystem regressions for complete failure/success archive preservation."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from hia.tools.archive_runtime_observations import archive_observations, verify_archive


class ObservationArchives(unittest.TestCase):
    def test_actual_hard_links_are_copied_with_original_identity_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'raw'
            root.mkdir()
            content = bytes(range(256)) * 8193
            (root / 'one').write_bytes(content)
            os.link(root / 'one', root / 'two')
            os.mkfifo(root / 'never-open-fifo')
            (root / 'outside-link').symlink_to('/must-not-be-opened')
            report = archive_observations({'raw': root}, base / 'archive')
            self.assertEqual(report['original_hardlinked_paths'], 2)
            self.assertEqual(report['regular_content_members'], 2)
            self.assertEqual(report['regular_logical_bytes'], len(content) * 2)
            self.assertEqual(report, verify_archive(base / 'archive/complete-observations.tar.gz'))
            with tarfile.open(base / 'archive/complete-observations.tar.gz', 'r:gz') as archive:
                manifest = json.load(archive.extractfile('manifest.json'))
                regular = [row for row in manifest['entries'] if row['kind'] == 'regular']
                self.assertEqual(regular[0]['inode'], regular[1]['inode'])
                self.assertEqual([row['links'] for row in regular], [2, 2])
                self.assertEqual(len({row['member'] for row in regular}), 2)
                for row in regular:
                    self.assertEqual(archive.extractfile(row['member']).read(), content)
                self.assertTrue(any(row['kind'] == 'special-metadata' for row in manifest['entries']))
                self.assertTrue(any(row.get('target') == '/must-not-be-opened' for row in manifest['entries']))
            self.assertEqual((root / 'one').stat().st_nlink, 2)

    def test_symlinked_root_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            (base / 'raw').mkdir()
            (base / 'alias').symlink_to(base / 'raw', target_is_directory=True)
            with self.assertRaises(ValueError):
                archive_observations({'raw': base / 'alias'}, base / 'archive')

    def test_output_inside_captured_root_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaises(ValueError):
                archive_observations({'raw': root}, root / 'archive')

    def test_source_mutation_during_capture_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'raw'
            root.mkdir()
            (root / 'one').write_bytes(b'first')
            original_read = os.read
            mutated = False
            def change_after_read(fd, count):
                nonlocal mutated
                block = original_read(fd, count)
                if block and not mutated:
                    mutated = True
                    (root / 'one').write_bytes(b'changed after the actual read')
                return block
            with patch('hia.tools.archive_runtime_observations.os.read', change_after_read):
                with self.assertRaises(ValueError):
                    archive_observations({'raw': root}, base / 'archive')
            self.assertTrue(mutated)
            failure = json.loads((base / 'archive/archive-failure.json').read_text())
            self.assertEqual(failure['status'], 'ARCHIVE_FAILED')
            self.assertFalse(failure['runtime_qualification_inferred_from_packaging'])
            self.assertTrue((base / 'archive/complete-observations.tar.gz').is_file())

    def test_changed_archived_content_is_not_a_successful_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'raw'
            root.mkdir()
            (root / 'one').write_bytes(b'original')
            archive_observations({'raw': root}, base / 'archive')
            source = base / 'archive/complete-observations.tar.gz'
            changed = base / 'changed.tar.gz'
            import io
            with tarfile.open(source, 'r:gz') as before, tarfile.open(changed, 'w:gz') as after:
                for member in before:
                    content = before.extractfile(member).read()
                    if member.name.startswith('files/'):
                        content = b'X' + content[1:]
                    after.addfile(member, io.BytesIO(content))
            with self.assertRaises(ValueError):
                verify_archive(changed)

    def test_existing_archive_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'raw'
            root.mkdir()
            (root / 'one').write_bytes(b'original')
            archive_observations({'raw': root}, base / 'archive')
            old = (base / 'archive/complete-observations.tar.gz').read_bytes()
            with self.assertRaises(FileExistsError):
                archive_observations({'raw': root}, base / 'archive')
            self.assertEqual((base / 'archive/complete-observations.tar.gz').read_bytes(), old)


if __name__ == '__main__':
    unittest.main()
