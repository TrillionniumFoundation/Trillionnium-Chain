#!/usr/bin/env python3
"""Isolated tamper controls for the offline source mapper; no prover or network."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_profile_source_map as mapper


STARK_SOURCE = """pub const MIN_CYCLES_PO2: usize = 13;
pub const MAX_CYCLES_PO2: usize = 24;
pub const QUERIES: usize = 50;
pub const INV_RATE: usize = 4;
const FRI_FOLD_PO2: usize = 4;
pub const FRI_FOLD: usize = 1 << FRI_FOLD_PO2;
const FRI_MIN_DEGREE: usize = 256;
"""


class SourceMapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.src = self.root / 'src'
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.package = 'risc0-core-3.0.2'
        # Small synthetic archive: these tests check custody, not crate semantics.
        self.payloads = {
            'src/field/baby_bear.rs': b'pub const P: u32 = 15 * (1 << 27) + 1;\n',
            '.cargo_vcs_info.json': b'{"git":{"sha1":"0000000000000000000000000000000000000000"},"path_in_vcs":"fixture"}\n',
        }
        for relative, data in self.payloads.items():
            path = self.src / self.package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.archive = self.cache / f'{self.package}.crate'
        self.write_archive()

    def write_archive(self, duplicate=False):
        entries = list(self.payloads.items())
        if duplicate:
            entries.append(entries[0])
        with tarfile.open(self.archive, 'w:gz') as archive:
            for relative, data in entries:
                info = tarfile.TarInfo(f'{self.package}/{relative}')
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        self.lock = {
            'name': 'risc0-core', 'version': '3.0.2',
            'source': mapper.REGISTRY_SOURCE, 'checksum': mapper.sha_file(self.archive),
        }

    def write_lock(self, names):
        path = self.root / 'Cargo.lock'
        rows = ['version = 4\n']
        for package in names:
            name, version = package.rsplit('-', 1)
            rows.append(
                f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
                f'source = "{mapper.REGISTRY_SOURCE}"\nchecksum = "{"1" * 64}"\n'
            )
        path.write_text('\n'.join(rows))
        return path

    def test_archive_and_selected_members_match_locked_checksum(self):
        record, files = mapper.inspect_package(self.src, self.cache, self.package, self.lock)
        self.assertTrue(record['archive_matches_lock'])
        self.assertEqual(len(files), 2)
        self.assertEqual(record['observed_archive_sha256'], self.lock['checksum'])

    def test_locked_archive_checksum_drift_is_refused(self):
        changed = dict(self.lock, checksum='0' * 64)
        with self.assertRaisesRegex(mapper.SourceMapError, 'archive differs from Cargo.lock'):
            mapper.inspect_package(self.src, self.cache, self.package, changed)

    def test_modified_extracted_source_is_refused(self):
        (self.src / self.package / 'src/field/baby_bear.rs').write_text('// altered after extraction\n')
        with self.assertRaisesRegex(mapper.SourceMapError, 'local source differs'):
            mapper.inspect_package(self.src, self.cache, self.package, self.lock)

    def test_duplicate_archive_member_is_refused(self):
        self.write_archive(duplicate=True)
        with self.assertRaisesRegex(mapper.SourceMapError, 'duplicate or nonregular'):
            mapper.inspect_package(self.src, self.cache, self.package, self.lock)

    def test_duplicate_and_missing_locked_packages_are_refused(self):
        names = list(mapper.SELECTED)
        self.assertEqual(len(mapper.load_locked_packages(self.write_lock(names))), 7)
        for changed, message in [(names + [names[0]], 'duplicate selected'),
                                 (names[:-1], 'missing selected')]:
            with self.subTest(message=message), self.assertRaisesRegex(mapper.SourceMapError, message):
                mapper.load_locked_packages(self.write_lock(changed))

    def test_stark_value_or_declaration_drift_is_refused(self):
        self.assertEqual(mapper.extract_stark_parameters(STARK_SOURCE)['QUERIES'], 50)
        for changed in [STARK_SOURCE.replace('QUERIES: usize = 50', 'QUERIES: usize = 49'),
                        STARK_SOURCE + 'pub const QUERIES: usize = 50;\n',
                        STARK_SOURCE.replace('pub const QUERIES: usize = 50;\n', '')]:
            with self.subTest(source=changed), self.assertRaises(mapper.SourceMapError):
                mapper.extract_stark_parameters(changed)

    def test_existing_output_is_never_overwritten(self):
        path = self.root / 'retained.json'
        original = b'{"retained":"original evidence"}\n'
        path.write_bytes(original)
        out, error = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(error):
            code = mapper.main(['--cargo-home', str(self.root), '--repo-root', str(self.root),
                                '--out', str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(error.getvalue())['status'], 'REFUSED')
        self.assertIn('output already exists', error.getvalue())
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(path.read_bytes(), original)
        # The write primitive itself also refuses a race after the CLI precheck.
        with self.assertRaises(FileExistsError):
            mapper.write_new_json(path, {'replacement': True})
        self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
