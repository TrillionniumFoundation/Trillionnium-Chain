"""Source and output controls for the private General C target directory."""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from hia.tests import locked_cargo_target as pool


class LockedCargoTargetTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.cargo_home = self.root / 'cargo-home'
        self.cargo_home.mkdir()
        self.adapter_calls = []
        tree = self.root / 'trillionnium'
        tree.mkdir()
        for file in ('Cargo.toml', 'Cargo.lock'):
            (tree / file).write_text(file + '\n')
        (self.root / 'rust-toolchain.toml').write_text('pinned\n')
        for args in (('init', '-q'), ('add', '--', 'trillionnium', 'rust-toolchain.toml'),
                     ('-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-qm', 'base')):
            subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True, timeout=10)
        self.enterContext(patch.object(pool, '_LOCAL', threading.local()))
        self.enterContext(patch.dict(os.environ, {'CARGO_HOME': str(self.cargo_home)}))

    def execute(self, argv, *, timeout, env):
        self.assertEqual(timeout, 160)
        self.assertEqual(argv[1:6], ['build', '--locked', '--offline', '--manifest-path',
                                      str(self.root / 'trillionnium/Cargo.toml')])
        self.assertEqual(argv[6], '--target-dir')
        self.assertEqual(argv[-1], '--message-format=json')
        self.assertEqual((env['RUSTC'], env['CARGO_BUILD_JOBS']), (sys.executable, '2'))
        target = Path(argv[7])
        file = target / 'output.rlib'
        fresh = file.exists()
        if not fresh:
            file.write_bytes(b'locked fixture original')
        self.adapter_calls.append((target, fresh))
        e = {'reason': 'compiler-artifact', 'filenames': [str(file)], 'fresh': fresh}
        return SimpleNamespace(stdout=json.dumps(e).encode() + b'\n')

    def build(self, pkg='trnm-service-settlement', execute=None):
        return pool.locked_cargo_build(self.root, rustc=sys.executable, cargo=sys.executable,
                                       package=pkg, execute=self.execute if execute is None else execute)

    def test_each_warm_request_still_executes_and_reparses(self):
        a, cold = self.build()
        b, warm = self.build()
        c, fresh_other = self.build('trnm-sqlite-io-boundary')
        self.assertEqual(a, b)
        self.assertNotEqual(c, a)
        self.assertEqual([cold[0]['fresh'], warm[0]['fresh'], fresh_other[0]['fresh']], [False, True, False])
        self.assertEqual(len(self.adapter_calls), 3)

    def test_changed_output_is_not_used_by_later_cargo(self):
        target, _ = self.build()
        (target / 'output.rlib').write_bytes(b'mutated')
        with self.assertRaisesRegex(ValueError, 'artifacts changed'):
            self.build()
        self.assertEqual(len(self.adapter_calls), 1)
        with self.assertRaisesRegex(ValueError, 'context changed or failed'):
            self.build()

    def test_changed_workspace_lock_config_and_environment_do_not_reuse(self):
        self.build()
        with patch.dict(os.environ, {'CARGO_PROFILE_DEV_OPT_LEVEL': '2'}):
            with self.assertRaisesRegex(ValueError, 'context changed'):
                self.build()
        (self.cargo_home / 'config.toml').write_text('[net]\noffline = true\n')
        with self.assertRaisesRegex(ValueError, 'context changed'):
            self.build()
        (self.root / 'trillionnium' / 'Cargo.lock').write_text('changed\n')
        with self.assertRaises(subprocess.CalledProcessError):
            self.build()
        self.assertEqual(len(self.adapter_calls), 1)

    def test_outside_artifact_and_failed_build_do_not_use_prior_events(self):
        unsafe = {'reason': 'compiler-artifact', 'filenames': [str(self.root / 'rust-toolchain.toml')]}
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.build(execute=lambda *a, **k: SimpleNamespace(stdout=json.dumps(unsafe).encode()))
        with self.assertRaisesRegex(ValueError, 'context changed or failed'):
            self.build()
        pkg = 'trnm-sqlite-io-boundary'
        self.build(pkg)

        def fail(*a, **k):
            raise RuntimeError('locked cargo subprocess failed')

        with self.assertRaisesRegex(RuntimeError, 'locked cargo subprocess failed'):
            self.build(pkg, execute=fail)
        with self.assertRaisesRegex(ValueError, 'context changed or failed'):
            self.build(pkg)

    def test_new_pid_does_not_inherit_target(self):
        self.build()
        with patch.object(pool.os, 'getpid', return_value=-1):
            self.build()
        self.assertNotEqual(self.adapter_calls[0][0], self.adapter_calls[1][0])
        self.assertFalse(self.adapter_calls[1][1])
        self.addCleanup(shutil.rmtree, self.adapter_calls[1][0])
