#!/usr/bin/env python3
"""Ordinary local controls for optional GNU time usage and real owner timeout rows.

The actual nested execute functions are compiled from their owner source. The
test harness supplies fixed source-observer metadata and local scratch paths;
the child launch, process-group kill, wait, logs and result rows are real. This
does not execute or certify the complete qualification matrix.
"""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from qualification_runtime import read_gnu_time_peak_rss


ROOT = Path(__file__).resolve().parents[1]
OWNERS = ('run_evaluation_qualification.py', 'run_public_readiness_qualification.py')


class QualificationRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evidence = os.environ.get('QUALIFICATION_RUNTIME_EVIDENCE_DIR')
        cls.temporary = None
        if evidence:
            cls.evidence = Path(evidence).resolve()
            cls.evidence.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='trnm-qualification-runtime-')
            cls.evidence = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def scratch(self, name):
        path = self.evidence / name
        path.mkdir()
        return path

    def test_usage_measurements(self):
        path = self.scratch('usage-measurements') / 'usage'
        controls = (
            ('valid', b'12345 0.01 0.02\n', 12345),
            ('valid-nonzero-exit', b'Command exited with non-zero status 7\n12345 0.01 0.02\n', 12345),
            ('recorded-zero', b'0 0.00 0.00\n', 0),
            ('empty', b'', None),
            ('blank', b'\n', None),
            ('partial', b'12345 0.01\n', None),
            ('bad-rss', b'invalid 0.01 0.02\n', None),
            ('negative-rss', b'-1 0.01 0.02\n', None),
            ('bad-cpu', b'12345 invalid 0.02\n', None),
            ('nonfinite-cpu', b'12345 nan inf\n', None),
            ('negative-cpu', b'12345 -0.01 0.02\n', None),
            ('extra-field', b'12345 0.01 0.02 extra\n', None),
            ('invalid-encoding', b'\xff', None),
        )
        results = []
        for name, data, expected in controls:
            with self.subTest(control=name):
                path.write_bytes(data)
                actual = read_gnu_time_peak_rss(path)
                self.assertEqual(actual, expected)
                results.append(dict(control=name, result=actual))
        path.unlink()
        self.assertIsNone(read_gnu_time_peak_rss(path))
        self.assertIsNone(read_gnu_time_peak_rss(path.parent))
        results.extend((dict(control='missing', result=None), dict(control='unreadable-directory', result=None)))
        (path.parent / 'controls.json').write_text(json.dumps(results, indent=2) + '\n')

    def owner_execute(self, owner, out, records):
        parsed = ast.parse((ROOT / 'scripts' / owner).read_text())
        functions = [node for node in ast.walk(parsed)
                     if isinstance(node, ast.FunctionDef) and node.name == 'execute']
        self.assertEqual(len(functions), 1)
        # Only source-observer metadata is controlled; no process or measurement
        # API is mocked. The complete matrix entry point is deliberately unused.
        def observed_git(*args):
            if args == ('rev-parse', 'HEAD'):
                return 'test-source-observer'
            if args == ('status', '--porcelain'):
                return ''
            raise AssertionError('unexpected source-observer query')
        namespace = dict(ROOT=ROOT, out=out, env=dict(os.environ), records=records,
                         commit='test-source-observer', git=observed_git,
                         read_gnu_time_peak_rss=read_gnu_time_peak_rss,
                         os=os, signal=signal, subprocess=subprocess, time=time,
                         json=json, re=re)
        module = ast.Module(body=functions, type_ignores=[])
        exec(compile(module, str(ROOT / 'scripts' / owner), 'exec'), namespace)
        return namespace['execute']

    def run_owner_control(self, owner, name, script, timeout, expected_code, expired):
        out = self.scratch(owner.removesuffix('.py') + '-' + name)
        (out / 'logs').mkdir()
        records = []
        execute = self.owner_execute(owner, out, records)
        command = [sys.executable, '-u', '-c', script]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            if expected_code or expired:
                with self.assertRaisesRegex(RuntimeError, 'QUALIFICATION_FAILED'):
                    execute(name, command, timeout=timeout)
            else:
                execute(name, command, timeout=timeout)
        self.assertEqual(len(records), 1)
        row = records[0]
        self.assertEqual(row['command'], command)
        self.assertEqual(row['returncode'], expected_code)
        self.assertIs(row['timed_out'], expired)
        self.assertGreater(row['elapsed_ns'], 0)
        self.assertEqual(json.loads(output.getvalue()), row)
        log = out / row['log']
        self.assertIn('ordinary-child-started', log.read_text())
        usage = out / 'logs' / (name + '.usage')
        if expired:
            self.assertEqual(usage.read_bytes(), b'')
            self.assertIsNone(row['peak_rss_kib'])
        else:
            self.assertIsInstance(row['peak_rss_kib'], int)
            self.assertGreater(row['peak_rss_kib'], 0)
        (out / 'result.json').write_text(json.dumps(row, indent=2) + '\n')

    def test_actual_normal_exit_rows(self):
        for owner in OWNERS:
            with self.subTest(owner=owner):
                self.run_owner_control(owner, 'normal', "print('ordinary-child-started')", 10, 0, False)

    def test_actual_nonzero_exit_rows(self):
        for owner in OWNERS:
            with self.subTest(owner=owner):
                self.run_owner_control(owner, 'nonzero',
                    "import sys; print('ordinary-child-started'); sys.exit(7)", 10, 7, False)

    def test_actual_group_timeout_empty_usage_rows(self):
        for owner in OWNERS:
            with self.subTest(owner=owner):
                self.run_owner_control(owner, 'timeout',
                    "import time; print('ordinary-child-started'); time.sleep(30)", 0.5, -signal.SIGKILL, True)


if __name__ == '__main__':
    unittest.main()
