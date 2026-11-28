"""Cargo JSON and rustc command controls; these tests do not execute Rust."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hia.tools import qualify_executor_original as qualifier


def artifact(name, filenames, kind='lib', package=None):
    return {'reason': 'compiler-artifact',
            'package_id': package or 'fixture#'+name+'@1.0.0',
            'target': {'name': name, 'kind': [kind], 'crate_types': [kind]},
            'filenames': [str(path) for path in filenames]}


class CargoLibraryDiscovery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='trnm-executor-link-test-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.target = self.work/'target'
        self.profile = self.target/'debug'
        self.deps = self.profile/'deps'
        self.executor = self.profile/'libtrnm_executor.rlib'
        self.types = self.deps/'libtrnm_types-7fcc731398f5304c.rlib'
        self.events = [
            artifact('serde', [self.deps/'libserde-9a8d1b937236b4c3.rlib',
                               self.deps/'libserde-9a8d1b937236b4c3.rmeta']),
            artifact('trnm_types', [self.types, self.types.with_suffix('.rmeta')]),
            artifact('trnm_executor', [self.executor,
                                      self.deps/'libtrnm_executor-db55e9633c1deb42.rmeta']),
            {'reason': 'build-finished', 'success': True},
        ]

    def raw(self, events=None):
        return ''.join(json.dumps(event)+'\n' for event in
                       (self.events if events is None else events))

    def test_profile_root_rlib_does_not_hide_transitive_deps_directory(self):
        artifacts, directories = qualifier.cargo_link_inputs(self.raw(), self.target)
        self.assertEqual(artifacts, {'trnm_executor': self.executor, 'trnm_types': self.types})
        self.assertEqual(directories, [self.profile, self.deps])
        self.assertNotEqual(directories, [self.executor.parent])

    def test_all_reported_library_outputs_contribute_without_assuming_debug_deps(self):
        other = self.target/'aarch64-unknown-linux-gnu'/'custom-profile'/'reported-libraries'
        macro = self.target/'host-profile'/'macro-artifacts'
        events = self.events[:-1]+[
            artifact('a_dependency', [other/'libdependency-123.rlib', other/'libdependency-123.rmeta']),
            artifact('derive_helper', [macro/'libderive_helper-456.so'], kind='proc-macro'),
            self.events[-1],
        ]
        with (patch.object(Path, 'glob', side_effect=AssertionError('no cache scan')),
              patch.object(Path, 'rglob', side_effect=AssertionError('no cache scan'))):
            _, directories = qualifier.cargo_link_inputs(self.raw(events), self.target)
        self.assertEqual(directories, sorted([self.profile, self.deps, other, macro], key=str))

    def test_repeated_dependency_names_for_distinct_versions_are_not_extern_ambiguity(self):
        events = self.events[:-1]+[
            artifact('syn', [self.deps/'libsyn-v2.rlib'], package='registry#syn@2.0.117'),
            artifact('syn', [self.deps/'libsyn-v3.rlib'], package='registry#syn@3.0.9'),
            self.events[-1],
        ]
        _, directories = qualifier.cargo_link_inputs(self.raw(events), self.target)
        self.assertEqual(directories, [self.profile, self.deps])

    def test_build_script_and_binary_outputs_do_not_add_dependency_directories(self):
        ignored = self.work/'not-a-library'
        events = self.events[:-1]+[
            artifact('build-script-build', [ignored/'build-script-build'], kind='custom-build'),
            artifact('tool', [ignored/'tool'], kind='bin'),
            {'reason': 'build-script-executed', 'out_dir': str(ignored)}, self.events[-1],
        ]
        _, directories = qualifier.cargo_link_inputs(self.raw(events), self.target)
        self.assertEqual(directories, [self.profile, self.deps])

    def test_repeated_required_target_is_refused_even_when_filename_matches(self):
        for different_path in (False, True):
            duplicate = copy.deepcopy(self.events[2])
            if different_path:
                duplicate['package_id'] = 'unexpected#trnm_executor@99.0.0'
                duplicate['filenames'] = [str(self.deps/'libtrnm_executor-other.rlib')]
            events = self.events[:-1]+[duplicate, self.events[-1]]
            with self.subTest(different_path=different_path), self.assertRaisesRegex(
                    AssertionError, 'duplicate or ambiguous'):
                qualifier.cargo_link_inputs(self.raw(events), self.target)

    def test_multiple_rlibs_or_duplicate_filenames_are_refused(self):
        for filename in (self.executor, self.deps/'libtrnm_executor-second.rlib'):
            events = copy.deepcopy(self.events)
            events[2]['filenames'].append(str(filename))
            with self.subTest(filename=filename), self.assertRaises(AssertionError):
                qualifier.cargo_link_inputs(self.raw(events), self.target)

    def test_missing_required_library_or_rlib_is_refused(self):
        events = copy.deepcopy(self.events)
        events[2]['filenames'] = [str(self.executor.with_suffix('.rmeta'))]
        for data in (self.events[:1]+self.events[2:], events):
            with self.assertRaises(AssertionError):
                qualifier.cargo_link_inputs(self.raw(data), self.target)

    def test_missing_failed_or_repeated_build_completion_is_refused(self):
        for events in (self.events[:-1], self.events[:-1]+[{'reason':'build-finished','success':False}],
                       self.events+[self.events[-1]]):
            with self.assertRaises(AssertionError):
                qualifier.cargo_link_inputs(self.raw(events), self.target)

    def test_outside_relative_and_parent_traversal_library_paths_are_refused(self):
        for path in (self.work/'old-cache/libserde.rlib', Path('target/debug/libserde.rlib'),
                     self.target/'debug/../old/libserde.rlib'):
            events = copy.deepcopy(self.events)
            events[0]['filenames'] = [str(path)]
            with self.subTest(path=path), self.assertRaisesRegex(AssertionError, 'outside this build target'):
                qualifier.cargo_link_inputs(self.raw(events), self.target)

    def test_malformed_library_metadata_is_refused(self):
        for field, value in [('target', None), ('filenames', []), ('filenames', 'not a list')]:
            events = copy.deepcopy(self.events)
            events[0][field] = value
            with self.assertRaises(AssertionError):
                qualifier.cargo_link_inputs(self.raw(events), self.target)
        for field, value in [('name', []), ('kind', ['lib', 3])]:
            events = copy.deepcopy(self.events)
            events[0]['target'][field] = value
            with self.assertRaises(AssertionError):
                qualifier.cargo_link_inputs(self.raw(events), self.target)

    def test_compile_command_uses_reported_directories_and_preserves_logs_and_budgets(self):
        # Only subprocess plumbing is mocked. No compiled-Rust result is claimed.
        for path in (self.executor, self.types):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('fixture artifact '+path.name).encode())
        cargo = subprocess.CompletedProcess(['fixture-cargo'], 0, self.raw(), 'cargo diagnostic\n')
        rustc = subprocess.CompletedProcess(['fixture-rustc'], 0, '', 'rustc diagnostic\n')
        with patch.object(qualifier.subprocess, 'run', side_effect=[cargo, rustc]) as run:
            executable, artifacts = qualifier.compile_original(self.work/'repository', self.work,
                                                                'fixture-cargo', 'fixture-rustc')
        self.assertEqual(executable, self.work/'executor-original')
        self.assertEqual(set(artifacts), {'trnm_executor', 'trnm_types'})
        cargo_call, rustc_call = run.call_args_list
        self.assertIn('--locked', cargo_call.args[0])
        self.assertEqual(cargo_call.kwargs['timeout'], 600)
        self.assertEqual(rustc_call.kwargs['timeout'], 120)
        command = rustc_call.args[0]
        self.assertEqual([command[i+1] for i, value in enumerate(command) if value == '-L'],
                         ['dependency='+str(self.profile), 'dependency='+str(self.deps)])
        self.assertEqual([command[i+1] for i, value in enumerate(command) if value == '--extern'],
                         ['trnm_executor='+str(self.executor), 'trnm_types='+str(self.types)])
        self.assertIn('overflow-checks=yes', command)
        self.assertIn('debug-assertions=yes', command)
        self.assertEqual(json.loads((self.work/'adapter-build.command.json').read_text()), command)
        self.assertEqual((self.work/'cargo-build.jsonl').read_text(), self.raw())
        self.assertEqual((self.work/'cargo-build.stderr').read_text(), 'cargo diagnostic\n')
        self.assertEqual((self.work/'adapter-build.stderr').read_text(), 'rustc diagnostic\n')

    def test_cargo_failure_or_ambiguous_output_never_invokes_rustc(self):
        for status, output in [(1, ''), (0, self.raw(self.events[:-1]+[self.events[2], self.events[-1]]))]:
            result = subprocess.CompletedProcess(['fixture-cargo'], status, output, 'original failure\n')
            with (patch.object(qualifier.subprocess, 'run', return_value=result) as run,
                  self.assertRaises((AssertionError, RuntimeError))):
                qualifier.compile_original(self.work/'repository', self.work, 'fixture-cargo', 'fixture-rustc')
            self.assertEqual(run.call_count, 1)
            self.assertEqual((self.work/'cargo-build.stderr').read_text(), 'original failure\n')


if __name__ == '__main__':
    unittest.main()
