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
                # copy2 retains a read-only installed tool's mode. Mutate only this
                # private fixture, and establish its mode before identity binding.
                executable.chmod(0o700)
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


class QualificationIoBoundaryTests(unittest.TestCase):
    """Real bounded files/pipes; fixtures are not independent runtime evidence."""
    def setUp(self):
        import qualification_runtime as runtime
        from unittest import mock
        self.runtime = runtime
        self.mock = mock
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-qualification-io-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.interpreter = sys.executable
        self.usage_limit = 16 * 1024
        self.probe_limit = 16 * 1024
        self.observation = dict(executable=self.interpreter, python='test-python',
                                numpy='test-numpy', cryptography='test-cryptography')

    def probe(self, body, environment=None):
        # Keep the executable path inside the fixture venv, including its parent
        # PATH selection. Only this setup is substituted; pipe I/O is real.
        bin_path = self.directory / 'venv' / 'bin'
        bin_path.mkdir(parents=True, exist_ok=True)
        entry = bin_path / 'python3'
        entry.write_text('#!' + self.interpreter + '\n' + body + '\n')
        entry.chmod(0o700)
        supplied = dict(os.environ if environment is None else environment)
        with self.mock.patch.object(self.runtime.sys, 'executable', str(bin_path / 'python')):
            return self.runtime.bind_python_runtime(supplied)

    def valid_body(self):
        return 'import json; print(json.dumps(' + repr(self.observation) + '))'

    def test_usage_fifo_without_writer_never_blocks(self):
        fifo = self.directory / 'usage'
        os.mkfifo(fifo)
        code = ('import sys; sys.path.insert(0, ' + repr(str(ROOT / 'scripts')) + '); '
                'from qualification_runtime import read_gnu_time_peak_rss; '
                'assert read_gnu_time_peak_rss(' + repr(str(fifo)) + ') is None')
        # The outer deadline guards the original blocking implementation.
        result = subprocess.run([self.interpreter, '-c', code], capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_usage_symlink_cannot_supply_a_measurement(self):
        target = self.directory / 'target'
        target.write_bytes(b'123 0.01 0.02\n')
        link = self.directory / 'usage'
        link.symlink_to(target)
        self.assertIsNone(self.runtime.read_gnu_time_peak_rss(link))

    def test_usage_oversized_valid_tail_is_unavailable(self):
        usage = self.directory / 'usage'
        usage.write_bytes(b'x' * self.usage_limit + b'\n123 0.01 0.02\n')
        self.assertIsNone(self.runtime.read_gnu_time_peak_rss(usage))

    def test_usage_exact_bound_and_zero_remain_real_values(self):
        usage = self.directory / 'usage'
        for tail, expected in ((b'123 0.01 0.02\n', 123), (b'0 0.00 0.00\n', 0)):
            usage.write_bytes(b'x' * (self.usage_limit - len(tail) - 1) + b'\n' + tail)
            self.assertEqual(usage.stat().st_size, self.usage_limit)
            self.assertEqual(self.runtime.read_gnu_time_peak_rss(usage), expected)

    def test_usage_growth_during_read_is_unavailable(self):
        from ci import read_native_cache_observation as reader
        usage = self.directory / 'usage'
        usage.write_bytes(b'123 0.01 0.02\n')
        original = reader.os.read
        changed = []
        def grow(descriptor, size):
            chunk = original(descriptor, size)
            if chunk and not changed:
                changed.append(True)
                with usage.open('ab') as stream:
                    stream.write(b'x' * self.usage_limit)
            return chunk
        with self.mock.patch.object(reader.os, 'read', grow):
            self.assertIsNone(self.runtime.read_gnu_time_peak_rss(usage))
        self.assertEqual(changed, [True])

    def test_usage_path_replacement_during_read_is_unavailable(self):
        from ci import read_native_cache_observation as reader
        usage = self.directory / 'usage'
        replacement = self.directory / 'replacement'
        usage.write_bytes(b'123 0.01 0.02\n')
        replacement.write_bytes(b'456 0.01 0.02\n')
        original = reader.os.read
        changed = []
        def replace(descriptor, size):
            chunk = original(descriptor, size)
            if chunk and not changed:
                changed.append(True)
                os.replace(replacement, usage)
            return chunk
        with self.mock.patch.object(reader.os, 'read', replace):
            self.assertIsNone(self.runtime.read_gnu_time_peak_rss(usage))
        self.assertEqual(changed, [True])
        self.assertEqual(self.runtime.read_gnu_time_peak_rss(usage), 456)

    def test_usage_repeated_success_and_failure_close_descriptors(self):
        from ci import read_native_cache_observation as reader
        usage = self.directory / 'usage'
        usage.write_bytes(b'123 0.01 0.02\n')
        original_open, original_close = reader.os.open, reader.os.close
        opened, closed = [], []
        def observe_open(*args, **kwargs):
            descriptor = original_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor
        def observe_close(descriptor):
            closed.append(descriptor)
            return original_close(descriptor)
        with self.mock.patch.object(reader.os, 'open', observe_open), \
                self.mock.patch.object(reader.os, 'close', observe_close):
            for _ in range(16):
                self.assertEqual(self.runtime.read_gnu_time_peak_rss(usage), 123)
                with self.mock.patch.object(reader.os, 'read', side_effect=OSError('read fault')):
                    self.assertIsNone(self.runtime.read_gnu_time_peak_rss(usage))
        self.assertEqual(len(opened), 32)
        self.assertEqual(opened, closed)

    def test_probe_keeps_environment_and_venv_path(self):
        supplied = dict(os.environ, TRNM_TEST_PROBE='preserved', PATH='/unused-original-path')
        original = dict(supplied)
        body = ('import os; assert os.environ["TRNM_TEST_PROBE"] == "preserved"\n'
                + self.valid_body())
        environment, observation = self.probe(body, supplied)
        self.assertEqual(supplied, original)
        self.assertEqual(environment['PATH'], str(self.directory / 'venv/bin')
                         + os.pathsep + '/unused-original-path')
        self.assertEqual(observation, self.observation)

    def test_probe_stdout_flood_is_bounded(self):
        body = ('import sys; sys.stdout.write(" " * 65536)\n' + self.valid_body())
        with self.assertRaisesRegex(ValueError, 'NATIVE_STDOUT_LIMIT') as error:
            self.probe(body)
        self.assertLessEqual(len(error.exception.stdout), self.probe_limit)
        self.assertTrue(error.exception.stdout_truncated)

    def test_probe_stderr_flood_is_bounded(self):
        body = ('import sys; sys.stderr.write("x" * 65536)\n' + self.valid_body())
        with self.assertRaisesRegex(ValueError, 'NATIVE_STDERR_LIMIT') as error:
            self.probe(body)
        self.assertLessEqual(len(error.exception.stderr), self.probe_limit)
        self.assertTrue(error.exception.stderr_truncated)

    def test_probe_nonzero_exit_preserves_bounded_diagnostics(self):
        with self.assertRaises(subprocess.CalledProcessError) as error:
            self.probe('import sys; print("partial"); print("refused", file=sys.stderr); sys.exit(7)')
        self.assertEqual(error.exception.returncode, 7)
        self.assertIn(b'partial', error.exception.output)
        self.assertIn(b'refused', error.exception.stderr)

    def test_probe_duplicate_json_keys_rejected(self):
        raw = json.dumps(self.observation)
        raw = raw[:-1] + ', "python": "substitution"}'
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            self.probe('print(' + repr(raw) + ')')

    def test_probe_nonfinite_json_rejected(self):
        raw = json.dumps(dict(self.observation, python=float('nan')))
        with self.assertRaisesRegex(ValueError, 'nonfinite JSON number'):
            self.probe('print(' + repr(raw) + ')')

    def test_probe_closed_identity_shape_required(self):
        for value in ([], None, dict(self.observation, extra='unowned'),
                      {key: value for key, value in self.observation.items() if key != 'numpy'},
                      dict(self.observation, python=''), dict(self.observation, numpy=True)):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'PYTHON_RUNTIME_IDENTITY_REQUIRED'):
                    self.probe('print(' + repr(json.dumps(value)) + ')')

    def test_probe_timeout_uses_existing_owner_and_original_budget(self):
        original = self.runtime.run_bounded
        seen = []
        def finite_control(argv, data, **kwargs):
            seen.append((data, dict(kwargs)))
            self.assertEqual(kwargs['timeout'], 30)
            kwargs['timeout'] = 0.25
            return original(argv, data, **kwargs)
        with self.mock.patch.object(self.runtime, 'run_bounded', finite_control):
            with self.assertRaisesRegex(ValueError, 'NATIVE_EXECUTOR_TIMEOUT'):
                self.probe('import time; time.sleep(1)\n' + self.valid_body())
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], b'')
        self.assertEqual(seen[0][1]['stdout_limit'], self.probe_limit)
        self.assertEqual(seen[0][1]['stderr_limit'], self.probe_limit)

    def test_probe_inherited_pipe_is_not_zero_exit_success(self):
        original = self.runtime.run_bounded
        def finite_control(argv, data, **kwargs):
            self.assertEqual(kwargs['timeout'], 30)
            kwargs['timeout'] = 0.3
            return original(argv, data, **kwargs)
        body = ('import os,time\n'
                'if os.fork() == 0:\n'
                '    time.sleep(1)\n'
                '    os._exit(0)\n' + self.valid_body())
        with self.mock.patch.object(self.runtime, 'run_bounded', finite_control):
            with self.assertRaisesRegex(ValueError, 'NATIVE_EXECUTOR_TIMEOUT'):
                self.probe(body)

    def test_probe_receives_empty_closed_stdin(self):
        body = ('import sys; assert sys.stdin.buffer.read() == b""\n' + self.valid_body())
        _, observation = self.probe(body)
        self.assertEqual(observation, self.observation)

    def test_probe_invalid_utf8_is_not_a_measurement(self):
        with self.assertRaises(UnicodeError):
            self.probe('import os; os.write(1,b"\\xff")')

    def test_probe_trailing_json_is_rejected(self):
        with self.assertRaises(ValueError):
            self.probe(self.valid_body() + '\nprint("{}")')

    def test_probe_exact_output_cap_is_accepted(self):
        raw = json.dumps(self.observation)
        body = ('import sys; sys.stdout.write(" " * '
                + str(self.probe_limit - len(raw.encode('utf-8'))) + ' + ' + repr(raw) + ')')
        _, observation = self.probe(body)
        self.assertEqual(observation, self.observation)


if __name__ == '__main__':
    unittest.main()
