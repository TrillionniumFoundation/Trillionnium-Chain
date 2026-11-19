"""Structural controls for the real-original Settings qualifier.

Cargo JSON fixtures test executable selection only. They are never observations
that Cargo compiled or that the Rust constructor ran.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hia.tools import qualify_settings_original as gate


class SettingsOriginalGateControls(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='settings-cargo-json-')
        self.addCleanup(self.work.cleanup)
        root = Path(self.work.name)
        self.target = root / 'fresh-target'
        self.manifest = root / 'original/crates/trnm-pon-node/Cargo.toml'
        self.source = root / 'original/crates/trnm-pon-node/src/lib.rs'
        self.binary = self.target / 'debug/deps/trnm_pon_node-captured'
        self.event = {'reason': 'compiler-artifact', 'manifest_path': str(self.manifest),
                      'target': {'name': 'trnm_pon_node', 'kind': ['lib'], 'src_path': str(self.source)},
                      'profile': {'test': True}, 'executable': str(self.binary)}
        self.done = {'reason': 'build-finished', 'success': True}

    def select(self, events):
        raw = b'\n'.join(json.dumps(event).encode() for event in events) + b'\n'
        return gate.select_original_executable(raw, self.target, self.manifest, self.source)

    def test_actual_event_path_is_selected_without_directory_scan(self):
        noise = {'reason': 'compiler-artifact', 'target': {'name': 'dependency'},
                 'profile': {'test': False}, 'filenames': ['/unrelated/cache/object.rlib']}
        self.assertEqual(self.select([noise, self.event, self.done]), self.binary)
        self.assertFalse(self.target.exists())

    def test_identical_duplicate_and_conflicting_artifacts_are_refused(self):
        other = copy.deepcopy(self.event)
        other['executable'] = str(self.target / 'other-candidate')
        for duplicate in (self.event, other):
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                self.select([self.event, duplicate, self.done])

    def test_missing_or_incomplete_cargo_build_is_refused(self):
        for events in ([self.event], [self.done], [self.event, self.done, self.done],
                       [self.event, {'reason': 'build-finished', 'success': False}]):
            with self.assertRaises(ValueError):
                self.select(events)

    def test_wrong_library_source_identity_is_refused(self):
        for field in ('manifest_path', 'source'):
            other = copy.deepcopy(self.event)
            if field == 'source':
                other['target']['src_path'] = str(self.source.parent / 'different.rs')
            else:
                other[field] = str(self.manifest.parent / 'other.toml')
            with self.assertRaisesRegex(ValueError, 'source identity'):
                self.select([other, self.done])

    def test_bin_non_test_missing_executable_and_path_escape_are_refused(self):
        mutations = [('kind', ['bin']), ('test', False), ('executable', None),
                     ('executable', str(self.target.parent / 'old-cache')),
                     ('executable', str(self.target / '../escape')),
                     ('executable', 'relative/target')]
        for field, value in mutations:
            other = copy.deepcopy(self.event)
            if field == 'kind':
                other['target']['kind'] = value
            elif field == 'test':
                other['profile']['test'] = value
            else:
                other[field] = value
            with self.assertRaises(ValueError):
                self.select([other, self.done])

    def test_duplicate_json_fields_and_non_json_text_are_refused(self):
        for raw in (b'{"reason":"build-finished","success":false,"success":true}\n',
                    b'not a Cargo JSON event\n', b'[]\n'):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                gate.select_original_executable(raw, self.target, self.manifest, self.source)

    def test_original_source_drift_and_symlink_are_refused(self):
        root = Path(self.work.name)
        source = root / 'source.rs'
        source.write_bytes(b'original function body\n')
        expected = {'schema': 'trnm.hia.settings-original-sources.v1', 'files': [
            {'path': 'source.rs', 'bytes': source.stat().st_size,
             'sha256': gate.digest(source.read_bytes())}]}
        pins = root / 'pins.json'
        pins.write_text(json.dumps(expected))
        with patch.object(gate, 'SOURCE_PINS', pins):
            self.assertEqual(gate.verify_original(root), expected)
            source.write_bytes(b'changed function body\n')
            with self.assertRaisesRegex(ValueError, 'input changed'):
                gate.verify_original(root)
            source.unlink()
            actual = root / 'elsewhere.rs'
            actual.write_bytes(b'original function body\n')
            source.symlink_to(actual)
            with self.assertRaisesRegex(ValueError, 'Symlinked'):
                gate.verify_original(root)

    def test_corpus_retains_full_unsigned_time_values_and_none(self):
        rows = gate.corpus()
        self.assertEqual(len(rows), 30)
        self.assertEqual(len({row['name'] for row in rows}), len(rows))
        values = [row['timestamp'] for row in rows]
        self.assertIn(None, values)
        for time in (0, 1800000000, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
            self.assertIn(str(time), values)
        self.assertTrue(all(value is None or isinstance(value, str) for value in values))


if __name__ == '__main__':
    unittest.main()
