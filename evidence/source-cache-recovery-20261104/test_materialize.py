"""Synthetic offline Git and tempfile recovery tests; no task-set inputs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('materialize', HERE / 'materialize.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'synthetic@example.invalid')
        self.git('config', 'user.name', 'Synthetic test')
        self.git('remote', 'add', 'origin', m.ORIGIN)
        (self.repo / 'config').mkdir()
        (self.repo / 'src').mkdir()
        self.inventory = json.dumps({'packages': [{'module': 'M00', 'path': 'src'}]}).encode()
        (self.repo / 'config/portability-inventory-v1.json').write_bytes(self.inventory)
        (self.repo / 'src/example.rs').write_bytes(b'fn example() {}\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic fixture')
        self.base = self.git('rev-parse', 'HEAD').decode().strip()
        entries = []
        for line in self.git('ls-tree', '-r', '-t', self.base, '--', 'src', 'config/portability-inventory-v1.json').decode().splitlines():
            meta, path = line.split('\t')
            mode, kind, object_id = meta.split()
            entries.append(dict(path=path, mode=mode, type=kind, oid=object_id))
        self.blob = next(x['oid'] for x in entries if x['path'].endswith('.rs'))
        self.manifest = dict(baseline=self.base, baseline_root_tree=self.git('rev-parse', 'HEAD^{tree}').decode().strip(),
                             inventory_blob=next(x['oid'] for x in entries if x['path'].endswith('.json')),
                             package_paths=['src'], baseline_entries=entries, candidates=[{'oid': self.blob}])
        self.decoded = {'owner-discovery.json': b'{}\n', 'history-filter.json': b'{}\n'}
        self.cache = self.root / 'cache'

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, stderr=subprocess.DEVNULL)

    def recover(self, check=False):
        with mock.patch.object(m, 'load_inputs', return_value=(self.manifest, self.decoded)), mock.patch.object(m, 'BASE', self.base):
            return m.recover(self.repo, self.cache, self.root, check)

    def test_positive_and_idempotent(self):
        report = self.recover()
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual((self.cache / 'blobs' / self.blob).read_bytes(), b'fn example() {}\n')
        before = (self.cache / 'blobs' / self.blob).stat().st_ino
        self.assertEqual(self.recover()['new_files'], 0)
        self.assertEqual((self.cache / 'blobs' / self.blob).stat().st_ino, before)

    def test_missing_fails_without_partial_cache(self):
        self.manifest['candidates'].append({'oid': '1' * 40})
        report = self.recover()
        self.assertEqual(report['result'], 'MISSING')
        self.assertEqual(report['missing_objects'], [{'oid': '1' * 40, 'type': 'blob'}])
        self.assertFalse(self.cache.exists())

    def test_conflict_preserved(self):
        (self.cache / 'blobs').mkdir(parents=True)
        bad = self.cache / 'blobs' / self.blob
        bad.write_bytes(b'wrong')
        with self.assertRaises(m.RecoveryError):
            self.recover()
        self.assertEqual(bad.read_bytes(), b'wrong')
        self.assertFalse((self.cache / 'owner-discovery.json').exists())

    def test_metadata_conflict_preserved(self):
        self.cache.mkdir()
        bad = self.cache / 'history-filter.json'
        bad.write_bytes(b'wrong')
        with self.assertRaises(m.RecoveryError):
            self.recover()
        self.assertEqual(bad.read_bytes(), b'wrong')

    def test_wrong_repository(self):
        self.git('remote', 'set-url', 'origin', 'https://example.invalid/wrong.git')
        with self.assertRaises(m.RecoveryError):
            self.recover()
        self.assertFalse(self.cache.exists())

    def test_symlink_cache_root(self):
        target = self.root / 'target'
        target.mkdir()
        self.cache.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            self.recover()
        self.assertEqual(list(target.iterdir()), [])

    def test_symlink_blob_file(self):
        (self.cache / 'blobs').mkdir(parents=True)
        target = self.root / 'target'
        target.write_text('untouched')
        (self.cache / 'blobs' / self.blob).symlink_to(target)
        with self.assertRaises(OSError):
            self.recover()
        self.assertEqual(target.read_text(), 'untouched')

    def test_symlink_blob_directory(self):
        self.cache.mkdir()
        target = self.root / 'target'
        target.mkdir()
        (self.cache / 'blobs').symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            self.recover()
        self.assertEqual(list(target.iterdir()), [])

    def test_check_does_not_write(self):
        self.assertEqual(self.recover(True)['result'], 'PASS')
        self.assertFalse(self.cache.exists())

    def test_corrupt_blob_rejected(self):
        git = m.Git(self.repo)
        with mock.patch.object(git, 'run', return_value=b'corrupt'):
            with self.assertRaises(m.RecoveryError):
                git.object('blob', self.blob)

    def test_wrong_object_type_rejected(self):
        self.assertIsNone(m.Git(self.repo).object('blob', self.base))

    def test_traversal_and_invalid_oid(self):
        for value in ('../outside', '/absolute', 'a/../b', 'a//b', 'a\\b', './a'):
            with self.assertRaises(m.RecoveryError):
                m.safe_relative(value)
        with self.assertRaises(m.RecoveryError):
            m.open_directory(self.root / 'a/../b', create=True)
        for value in ('--help', 'HEAD', 'a' * 39):
            with self.assertRaises(m.RecoveryError):
                m.oid(value)

    def test_frozen_package_tampering_rejected(self):
        source = HERE.parent / 'source-development-freeze-20261103'
        manifest = json.loads((HERE / 'required-objects.json').read_bytes())
        package = self.root / 'package'
        package.mkdir()
        for name in manifest['package_sha256']:
            shutil.copyfile(source / name, package / name)
        m.load_inputs(package)
        with (package / 'owner-discovery.json.gz').open('ab') as stream:
            stream.write(b'tamper')
        with self.assertRaises(m.RecoveryError):
            m.load_inputs(package)

    def test_network_disabled_even_with_environment_overrides(self):
        with mock.patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'protocol.allow',
                                         'GIT_CONFIG_VALUE_0': 'always', 'GIT_NO_LAZY_FETCH': '0'}):
            git = m.Git(self.repo)
        self.assertEqual(git.env['GIT_NO_LAZY_FETCH'], '1')
        self.assertEqual(git.env['GIT_ALLOW_PROTOCOL'], '')
        self.assertNotIn('GIT_CONFIG_COUNT', git.env)
        with mock.patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as run:
            git.run('cat-file', 'blob', self.blob)
        self.assertIn('protocol.allow=never', run.call_args.args[0])

    def test_manifest_tampering_rejected(self):
        original = m.read_file
        def changed(path):
            if Path(path) == HERE / 'required-objects.json':
                return original(path) + b' '
            return original(path)
        with mock.patch.object(m, 'read_file', side_effect=changed):
            with self.assertRaises(m.RecoveryError):
                m.load_inputs(HERE.parent / 'source-development-freeze-20261103')

    def test_missing_metadata_rejected(self):
        original = m.read_file
        def missing(path):
            if Path(path).name == 'history-filter.json.gz':
                raise FileNotFoundError(path)
            return original(path)
        with mock.patch.object(m, 'read_file', side_effect=missing):
            with self.assertRaises(FileNotFoundError):
                m.load_inputs(HERE.parent / 'source-development-freeze-20261103')

    def test_symlink_ancestor_rejected(self):
        target = self.root / 'target'
        target.mkdir()
        ancestor = self.root / 'ancestor'
        ancestor.symlink_to(target, target_is_directory=True)
        self.cache = ancestor / 'new-cache'
        with self.assertRaises(OSError):
            self.recover()
        self.assertEqual(list(target.iterdir()), [])

    def test_resume_partial_valid_cache(self):
        (self.cache / 'blobs').mkdir(parents=True)
        (self.cache / 'blobs' / self.blob).write_bytes(b'fn example() {}\n')
        self.assertEqual(self.recover()['result'], 'PASS')
        self.assertEqual(self.recover()['new_files'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
