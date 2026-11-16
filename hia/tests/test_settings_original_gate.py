"""Structural controls for the real-original Settings qualifier.

Cargo JSON fixtures test executable selection only. They are never observations
that Cargo compiled or that the Rust constructor ran.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
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

    def test_original_repository_cannot_shadow_current_python_harness(self):
        root = Path(self.work.name)
        original = root / 'original-chain'
        library = original / gate.LIB
        library.parent.mkdir(parents=True)
        library.write_bytes(b'// original Rust fixture; never compiled\n')
        # A distinct reference checkout may contain an older HIA namespace.
        # Neither its process helper nor its late-loaded toolchain may execute.
        for relative in ('hia/platform/transport_request/rust_oracle.py',
                         'hia/tools/toolchain.py'):
            source = original / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("raise RuntimeError('original checkout Python was imported')\n")
        child = textwrap.dedent('''
            import importlib, json, subprocess, sys
            from pathlib import Path
            from unittest.mock import patch
            sys.path.insert(0, sys.argv[1])
            from hia.tools import qualify_settings_original as gate
            from hia.tests.native_support import NativeModule

            class StopBeforeRust(RuntimeError):
                pass

            oracle = object.__new__(gate.RustOracle)
            with patch.object(subprocess, 'Popen', side_effect=StopBeforeRust) as launch:
                try:
                    oracle.__init__(Path(sys.argv[2]), Path(sys.argv[3]))
                except StopBeforeRust:
                    pass
                else:
                    raise RuntimeError('did not reach the current process helper')
            # NativeModule performs this import lazily, after RustOracle setup.
            toolchain = importlib.import_module('hia.tools.toolchain')
            print(json.dumps({
                'helper': str(oracle.command_source),
                'helper_code': str(Path(oracle.command.__code__.co_filename).resolve()),
                'toolchain_root': str(toolchain.HIA_ROOT),
                'native_support_root': str(Path(sys.modules[NativeModule.__module__].__file__).resolve().parents[2]),
                'original_lib_preserved': oracle.original_lib == (Path(sys.argv[2]) / gate.LIB).read_bytes(),
                'isolated_lib_preserved': (oracle.isolated / gate.LIB).read_bytes() == oracle.original_lib + gate.DECLARATION,
                'attempts': launch.call_count,
                'command': launch.call_args.args[0],
            }))
        ''')
        completed = subprocess.run(
            [sys.executable, '-I', '-S', '-B', '-c', child, str(gate.ROOT),
             str(original), str(root / 'observation')],
            capture_output=True, text=True, check=False, timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        helper = str(gate.ROOT / 'hia/platform/transport_request/rust_oracle.py')
        self.assertEqual(json.loads(completed.stdout), {
            'helper': helper, 'helper_code': helper,
            'toolchain_root': str(gate.ROOT / 'hia'),
            'native_support_root': str(gate.ROOT),
            'original_lib_preserved': True, 'isolated_lib_preserved': True,
            'attempts': 1, 'command': ['rustc', '-Vv'],
        })

    def test_cached_foreign_helper_module_or_function_is_refused_before_execution(self):
        from hia.platform.transport_request import rust_oracle as process_receipts

        def foreign_command(*args, **kwargs):
            raise AssertionError('a foreign helper must never execute')

        root = Path(self.work.name)
        for index, (attribute, value) in enumerate((
            ('__file__', str(root / 'foreign-rust-oracle.py')),
            ('command', foreign_command),
        )):
            with (self.subTest(attribute=attribute),
                  patch.object(sys, 'path', list(sys.path)),
                  patch.object(process_receipts, attribute, value),
                  patch.object(subprocess, 'Popen') as launch):
                with self.assertRaisesRegex(ValueError, 'not from the current HIA candidate'):
                    gate.RustOracle(root / 'original-chain', root / f'refused-{index}')
                launch.assert_not_called()

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
