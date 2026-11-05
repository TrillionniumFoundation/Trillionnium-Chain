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
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from qualification_runtime import (GNU_TIME_EXECUTABLE_LIMIT, bind_gnu_time,
                                   read_gnu_time_peak_rss, verify_gnu_time)


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

    def owner_execute(self, owner, out, records, observer=None):
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
        environment, actual_observer = bind_gnu_time(os.environ)
        namespace = dict(ROOT=ROOT, out=out, env=environment, records=records,
                         resource_observer=observer or actual_observer,
                         commit='test-source-observer', git=observed_git,
                         read_gnu_time_peak_rss=read_gnu_time_peak_rss,
                         verify_gnu_time=verify_gnu_time,
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
        _, observer = bind_gnu_time(os.environ)
        self.assertEqual(row['resource_observer'], observer)
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

    def test_actual_observer_identity(self):
        environment, observer = bind_gnu_time(os.environ)
        self.assertEqual(environment['TRNM_GNU_TIME'], observer['executable'])
        self.assertTrue(Path(observer['executable']).is_absolute())
        self.assertRegex(observer['sha256'], r'^[0-9a-f]{64}$')
        self.assertRegex(observer['identity'], r'^time \(GNU [Tt]ime\)')
        nested_env, nested_observer = bind_gnu_time(environment)
        self.assertEqual(observer, nested_observer)
        self.assertEqual(environment, nested_env)

    def test_invalid_observer_selection(self):
        for selected in ('time', '', '/nonexistent/trnm-gnu-time'):
            with self.subTest(selected=selected):
                with self.assertRaises((ValueError, OSError)):
                    bind_gnu_time({'TRNM_GNU_TIME': selected})
        invalid = self.scratch('invalid-identity') / 'not-gnu-time'
        invalid.write_text('#!' + sys.executable + '\nprint("not a GNU observer")\n')
        invalid.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'GNU_TIME_IDENTITY_REQUIRED'):
            bind_gnu_time(dict(os.environ, TRNM_GNU_TIME=str(invalid)))

    def test_nested_runner_observer_sanitization(self):
        # Execute the actual owner sanitization loops, not a substitute copy.
        for owner in OWNERS:
            with self.subTest(owner=owner):
                parsed = ast.parse((ROOT / 'scripts' / owner).read_text())
                run = next(node for node in parsed.body
                           if isinstance(node, ast.FunctionDef) and node.name == 'run')
                sanitize = next(node for node in run.body if isinstance(node, ast.For))
                environment, observer = bind_gnu_time(os.environ)
                environment['TRNM_UNRELATED_TEST_CONTROL'] = 'must-be-removed'
                namespace = dict(env=environment)
                exec(compile(ast.Module(body=[sanitize], type_ignores=[]), owner, 'exec'), namespace)
                self.assertEqual(environment['TRNM_GNU_TIME'], observer['executable'])
                self.assertNotIn('TRNM_UNRELATED_TEST_CONTROL', environment)
                _, nested = bind_gnu_time(environment)
                self.assertEqual(observer, nested)

    def test_actual_observer_launch_failure(self):
        for owner in OWNERS:
            with self.subTest(owner=owner):
                out = self.scratch(owner.removesuffix('.py') + '-launch-failure')
                (out / 'logs').mkdir()
                records = []
                execute = self.owner_execute(owner, out, records,
                                             dict(executable=str(out / 'absent-time')))
                with self.assertRaises(FileNotFoundError):
                    execute('launch-failure', [sys.executable, '-c', 'pass'])
                self.assertEqual(records, [])
                self.assertFalse((out / 'logs' / 'launch-failure.usage').exists())

    def test_oversize_observer_executable_rejected(self):
        executable = self.scratch('oversize-executable') / 'time'
        with executable.open('wb') as stream:
            stream.truncate(GNU_TIME_EXECUTABLE_LIMIT + 1)
        executable.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'GNU_TIME_EXECUTABLE_LIMIT'):
            bind_gnu_time(dict(os.environ, TRNM_GNU_TIME=str(executable)))

    def test_probe_output_caps(self):
        # Deliberately invalid probe fixtures; never used for resource measurement.
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream):
                executable = self.scratch('oversize-probe-' + stream) / 'invalid-observer'
                executable.write_text('#!' + sys.executable + '\nimport sys\n'
                                      + 'sys.' + stream + '.write("x" * 65536)\n')
                executable.chmod(0o700)
                with self.assertRaisesRegex(ValueError, 'NATIVE_' + stream.upper() + '_LIMIT'):
                    bind_gnu_time(dict(os.environ, TRNM_GNU_TIME=str(executable)))

    def test_observer_replacement_before_launch_rejected(self):
        _, actual = bind_gnu_time(os.environ)
        for owner in OWNERS:
            with self.subTest(owner=owner):
                out = self.scratch(owner.removesuffix('.py') + '-replacement-before')
                (out / 'logs').mkdir()
                executable = out / 'time'
                shutil.copy2(actual['executable'], executable)
                _, observer = bind_gnu_time(dict(os.environ, TRNM_GNU_TIME=str(executable)))
                executable.write_bytes(b'replaced')
                records = []
                execute = self.owner_execute(owner, out, records, observer)
                with self.assertRaisesRegex(ValueError, 'GNU_TIME_EXECUTABLE_CHANGED'):
                    execute('replacement-before', [sys.executable, '-c', 'pass'])
                self.assertEqual(records, [])

    def test_observer_replacement_after_launch_retains_rows(self):
        _, actual = bind_gnu_time(os.environ)
        for owner in OWNERS:
            for name, ending, timeout, expected, expired in (
                ('normal', '', 10, 0, False),
                ('nonzero', '; sys.exit(7)', 10, 7, False),
                ('timeout', '; time.sleep(30)', 0.5, -signal.SIGKILL, True),
            ):
                with self.subTest(owner=owner, control=name):
                    out = self.scratch(owner.removesuffix('.py') + '-replacement-' + name)
                    (out / 'logs').mkdir()
                    executable = out / 'time'
                    shutil.copy2(actual['executable'], executable)
                    _, observer = bind_gnu_time(dict(os.environ, TRNM_GNU_TIME=str(executable)))
                    replacement = out / 'replacement'
                    replacement.write_bytes(b'replaced observer')
                    records = []
                    execute = self.owner_execute(owner, out, records, observer)
                    script = ('import os, sys, time; os.replace(' + repr(str(replacement))
                              + ', ' + repr(str(executable)) + ')' + ending)
                    with contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(RuntimeError, 'OBSERVER_CHANGED'):
                            execute(name, [sys.executable, '-c', script], timeout=timeout)
                    self.assertEqual(len(records), 1)
                    row = records[0]
                    self.assertEqual(row['returncode'], expected)
                    self.assertEqual(row['timed_out'], expired)
                    self.assertEqual(row['resource_observer_error'], 'GNU_TIME_EXECUTABLE_CHANGED')
                    if expired:
                        self.assertIsNone(row['peak_rss_kib'])
                    else:
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
