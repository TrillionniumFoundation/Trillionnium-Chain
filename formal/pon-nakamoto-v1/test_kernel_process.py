"""Portable logic controls. Mocks are not kernel-enforcement measurements."""
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from bounded_process import Result, ProcessFailure
from kernel_process import KernelEnvelope, KernelFailure, Limits, ParentIdentity, PinnedExecutable, _fields


class KernelContractTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        env = object.__new__(KernelEnvelope)
        env.path = Path(temporary.name)
        env.slice_name = 'trnmponfixture.slice'
        env.unavailable = threading.Event()
        env.snapshot = Mock(return_value={'parent_inode': 42})
        executable = Mock(spec=PinnedExecutable)
        executable.checked_path.return_value = '/usr/bin/true'
        return env, executable

    def test_limits_reject_types_overflow_and_unbounded_values(self):
        valid = (25000, 100000, 268435456, 24)
        Limits(*valid).validate()
        for index, bad in [(0,True),(0,0),(0,999999),(1,0),(2,2**63),(2,0),(3,257),(3,3)]:
            values=list(valid);values[index]=bad
            with self.assertRaises(KernelFailure):Limits(*values).validate()

    def test_unknown_negative_or_duplicate_counters_refuse(self):
        self.assertEqual(_fields('usage_usec 4\nnr_throttled 2'),{'usage_usec':4,'nr_throttled':2})
        for value in ['x -1','x 1\nx 2','x 2 3','x NaN']:
            with self.assertRaises(ValueError):_fields(value)

    def test_unprivileged_attach_never_calls_manager(self):
        with patch('kernel_process.os.geteuid', return_value=1000, create=True), patch('kernel_process._systemctl') as manager:
            with self.assertRaisesRegex(KernelFailure,'PRIVILEGED'):
                KernelEnvelope('trnmponfixture.slice',Limits(25000,100000,268435456,24),ParentIdentity('boot',1,2))
            manager.assert_not_called()

    def test_input_bounds_precede_executable_and_process(self):
        env,exe=self.fixture()
        for kwargs in [{'runtime':float('nan')},{'runtime':0},{'runtime':31},{'runtime':True},
                       {'data':b'x'*65537},{'args':['bad\0arg']},{'args':['x']*21},
                       {'stdout_limit':-1},{'stderr_limit':True}]:
            with self.assertRaisesRegex(KernelFailure,'REQUEST_BOUNDS'):env.run(exe,**kwargs)
        exe.checked_path.assert_not_called();env.snapshot.assert_not_called()

    def test_binary_mismatch_precedes_parent_and_launch(self):
        env,exe=self.fixture();exe.checked_path.side_effect=KernelFailure('KERNEL_EXECUTABLE_CHANGED')
        with patch('kernel_process.run_bounded') as execute:
            with self.assertRaisesRegex(KernelFailure,'EXECUTABLE_CHANGED'):env.run(exe)
            execute.assert_not_called();env.snapshot.assert_not_called()

    def test_same_fixed_slice_and_no_guest_properties(self):
        env,_=self.fixture();cmd=env.command('trnmponjobfixture.service','/bin/true',['literal'],2)
        props=[cmd[i+1] for i,v in enumerate(cmd) if v=='--property']
        for required in ['DynamicUser=yes','Delegate=no','ProtectControlGroups=yes','KillMode=control-group',
                         'NoNewPrivileges=yes','PrivateNetwork=yes','Restart=no','RuntimeMaxSec=2s']:
            self.assertIn(required,props)
        self.assertIn('--slice=trnmponfixture.slice',cmd)
        self.assertIn('--collect',cmd)
        self.assertFalse(any(p.startswith('CPUQuota=') for p in props))
        self.assertEqual(cmd[-3:],['--','/bin/true','literal'])

    def test_success_keeps_exact_bounded_native_result(self):
        env,exe=self.fixture();native=Result(0,b'exact',b'')
        with patch('kernel_process.run_bounded',return_value=native),patch('kernel_process._systemctl') as manager:
            result=env.run(exe,data=b'proof')
        self.assertIs(result.native,native);self.assertTrue(result.cleanup_confirmed)
        self.assertEqual(env.snapshot.call_count,2);self.assertEqual(manager.call_args.args[0],'stop')

    def test_native_rejection_does_not_become_success(self):
        env,exe=self.fixture();native=Result(2,b'',b'WORK\n')
        with patch('kernel_process.run_bounded',return_value=native),patch('kernel_process._systemctl'):
            result=env.run(exe)
        self.assertIs(result.native,native);self.assertEqual(result.native.returncode,2)

    def test_already_collected_requires_both_manager_and_group_absence(self):
        env,exe=self.fixture();missing=subprocess.CalledProcessError(5,['systemctl','stop'])
        with patch('kernel_process.run_bounded',return_value=Result(0,b'',b'')),patch('kernel_process._systemctl',side_effect=[missing,Mock(stdout='not-found\n')]):
            self.assertTrue(env.run(exe).cleanup_confirmed)

    def test_still_loaded_unit_failure_retains_prior_native_success(self):
        env,exe=self.fixture();native=Result(0,b'committed-outcome',b'')
        denied=subprocess.CalledProcessError(1,['systemctl','stop'])
        with patch('kernel_process.run_bounded',return_value=native),patch('kernel_process._systemctl',side_effect=[denied,Mock(stdout='loaded\n')]):
            with self.assertRaises(KernelFailure) as result:env.run(exe)
        self.assertIs(result.exception.native,native);self.assertTrue(env.unavailable.is_set())
        self.assertTrue(result.exception.unit.startswith("trnmponjob"))

    def test_pipe_failure_is_uncertain_even_after_an_empty_cleanup(self):
        env,exe=self.fixture()
        failure=ProcessFailure('NATIVE_STDOUT_LIMIT',returncode=-9,stdout=b'x',stderr=b'',stdin_written=0)
        with patch('kernel_process.run_bounded',side_effect=failure),patch('kernel_process._systemctl') as manager:
            with self.assertRaisesRegex(KernelFailure,'EXCHANGE_UNCERTAIN') as result:env.run(exe)
        self.assertIs(result.exception.native,failure);self.assertEqual(manager.call_count,1)
        self.assertTrue(result.exception.unit.endswith(".service"))
        self.assertTrue(env.unavailable.is_set())

    def test_parent_failure_before_launch_never_falls_back(self):
        env,exe=self.fixture();env.snapshot.side_effect=KernelFailure('KERNEL_PARENT_REPLACED')
        with patch('kernel_process.run_bounded') as execute:
            with self.assertRaisesRegex(KernelFailure,'PARENT_REPLACED'):env.run(exe)
            execute.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
