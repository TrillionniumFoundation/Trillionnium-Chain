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
from unittest import mock

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

    def replacement_archive(self):
        payloads = dict(self.payloads)
        payloads['src/field/baby_bear.rs'] = b'// replacement after the archive checksum check\n'
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for relative, data in payloads.items():
                info = tarfile.TarInfo(f'{self.package}/{relative}')
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return output.getvalue(), payloads

    def test_archive_and_selected_members_match_locked_checksum(self):
        record, files = mapper.inspect_package(self.src, self.cache, self.package, self.lock)
        self.assertTrue(record['archive_matches_lock'])
        self.assertEqual(len(files), 2)
        self.assertEqual(record['observed_archive_sha256'], self.lock['checksum'])

    def test_locked_archive_checksum_drift_is_refused(self):
        changed = dict(self.lock, checksum='0' * 64)
        with self.assertRaisesRegex(mapper.SourceMapError, 'archive differs from Cargo.lock'):
            mapper.inspect_package(self.src, self.cache, self.package, changed)

    def test_archive_replacement_with_matching_changed_sources_is_refused(self):
        replacement, payloads = self.replacement_archive()
        open_archive = tarfile.open

        def replace_before_parse(*args, **kwargs):
            # Deterministically replace the path after hashing, at the parser boundary.
            self.archive.write_bytes(replacement)
            for relative, data in payloads.items():
                (self.src / self.package / relative).write_bytes(data)
            return open_archive(*args, **kwargs)

        with mock.patch.object(mapper.tarfile, 'open', side_effect=replace_before_parse):
            with self.assertRaisesRegex(mapper.SourceMapError, 'local source differs from locked archive'):
                mapper.inspect_package(self.src, self.cache, self.package, self.lock)
        self.assertNotEqual(mapper.sha_file(self.archive), self.lock['checksum'])

    def test_archive_replacement_does_not_change_the_inspected_snapshot(self):
        replacement, _ = self.replacement_archive()
        open_archive = tarfile.open

        def replace_before_parse(*args, **kwargs):
            self.archive.write_bytes(replacement)
            return open_archive(*args, **kwargs)

        with mock.patch.object(mapper.tarfile, 'open', side_effect=replace_before_parse):
            record, files = mapper.inspect_package(self.src, self.cache, self.package, self.lock)
        self.assertTrue(record['archive_matches_lock'])
        self.assertEqual(record['observed_archive_sha256'], self.lock['checksum'])
        self.assertNotEqual(mapper.sha_file(self.archive), self.lock['checksum'])
        relative = 'src/field/baby_bear.rs'
        self.assertEqual(files[f'{self.package}/{relative}']['sha256'],
                         mapper.sha_bytes(self.payloads[relative]))

    def test_source_size_and_digest_describe_the_same_read(self):
        relative = 'src/field/baby_bear.rs'
        path = self.src / self.package / relative
        original = self.payloads[relative]
        replacement = b'// a differently sized source installed after the read\n' * 3
        read_bytes = mapper.bounded_bytes

        def replace_after_read(selected, limit):
            value = read_bytes(selected, limit)
            if selected == path:
                path.write_bytes(replacement)
            return value

        with mock.patch.object(mapper, 'bounded_bytes', side_effect=replace_after_read):
            _, files = mapper.inspect_package(self.src, self.cache, self.package, self.lock)
        self.assertEqual(path.read_bytes(), replacement)
        self.assertEqual(files[f'{self.package}/{relative}']['bytes'], len(original))
        self.assertEqual(files[f'{self.package}/{relative}']['sha256'], mapper.sha_bytes(original))

    def test_provenance_is_parsed_from_the_hashed_source_snapshot(self):
        relative = '.cargo_vcs_info.json'
        path = self.src / self.package / relative
        original = self.payloads[relative]
        replacement = b'{"git":{"sha1":"1111111111111111111111111111111111111111"}}\n'
        read_bytes = mapper.bounded_bytes

        def replace_after_read(selected, limit):
            value = read_bytes(selected, limit)
            if selected == path:
                path.write_bytes(replacement)
            return value

        with mock.patch.object(mapper, 'bounded_bytes', side_effect=replace_after_read):
            record, files = mapper.inspect_package(self.src, self.cache, self.package, self.lock)
        self.assertEqual(path.read_bytes(), replacement)
        self.assertEqual(record['crate_vcs'], json.loads(original))
        self.assertEqual(files[f'{self.package}/{relative}']['bytes'], len(original))
        self.assertEqual(files[f'{self.package}/{relative}']['sha256'], mapper.sha_bytes(original))

    def test_modified_extracted_source_is_refused(self):
        (self.src / self.package / 'src/field/baby_bear.rs').write_text('// altered after extraction\n')
        with self.assertRaisesRegex(mapper.SourceMapError, 'local source differs'):
            mapper.inspect_package(self.src, self.cache, self.package, self.lock)

    def test_duplicate_archive_member_is_refused(self):
        self.write_archive(duplicate=True)
        with self.assertRaisesRegex(mapper.SourceMapError, 'duplicate or nonregular'):
            mapper.inspect_package(self.src, self.cache, self.package, self.lock)

    def test_oversized_selected_archive_member_is_refused(self):
        relative = 'src/field/baby_bear.rs'
        self.payloads[relative] = b'x' * (2 * 1024 * 1024 + 1)
        (self.src / self.package / relative).write_bytes(self.payloads[relative])
        self.write_archive()
        with self.assertRaisesRegex(mapper.SourceMapError, 'archive member exceeds bound'):
            mapper.inspect_package(self.src, self.cache, self.package, self.lock)

    def test_duplicate_and_missing_locked_packages_are_refused(self):
        names = list(mapper.SELECTED)
        self.assertEqual(len(mapper.load_locked_packages(self.write_lock(names))), 7)
        for changed, message in [(names + [names[0]], 'duplicate selected'),
                                 (names[:-1], 'missing selected')]:
            with self.subTest(message=message), self.assertRaisesRegex(mapper.SourceMapError, message):
                mapper.load_locked_packages(self.write_lock(changed))

    def test_lock_snapshot_keeps_the_digest_of_the_parsed_bytes(self):
        path = self.write_lock(list(mapper.SELECTED))
        original = path.read_bytes()
        replacement = original.replace(b'1' * 64, b'2' * 64)
        parse_toml = mapper.tomllib.loads

        def replace_before_parse(data):
            path.write_bytes(replacement)
            return parse_toml(data)

        with mock.patch.object(mapper.tomllib, 'loads', side_effect=replace_before_parse):
            locked, digest = mapper.load_locked_packages_snapshot(path)
        self.assertTrue(all(item['checksum'] == '1' * 64 for item in locked.values()))
        self.assertEqual(digest, mapper.sha_bytes(original))
        self.assertEqual(path.read_bytes(), replacement)
        self.assertNotEqual(digest, mapper.sha_file(path))

    def test_json_snapshot_keeps_the_digest_of_the_parsed_bytes(self):
        for name in ['stdout.log', 'manifest.json']:
            with self.subTest(name=name):
                path = self.root / name
                original = b'{"source_commit":"retained","segments":[1,2]}\n'
                replacement = b'{"source_commit":"substituted","segments":[]}\n'
                path.write_bytes(original)
                parse_json = json.loads

                def replace_before_parse(data, **kwargs):
                    path.write_bytes(replacement)
                    return parse_json(data, **kwargs)

                with mock.patch.object(mapper.json, 'loads', side_effect=replace_before_parse):
                    value, digest = mapper.read_json_snapshot(path)
                self.assertEqual(value, parse_json(original))
                self.assertEqual(digest, mapper.sha_bytes(original))
                self.assertEqual(path.read_bytes(), replacement)
                self.assertNotEqual(digest, mapper.sha_file(path))

    def test_json_snapshot_preserves_duplicate_key_refusal(self):
        path = self.root / 'manifest.json'
        path.write_bytes(b'{"source_commit":"original","source_commit":"replacement"}')
        with self.assertRaisesRegex(mapper.SourceMapError, 'duplicate JSON key'):
            mapper.read_json_snapshot(path)

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
