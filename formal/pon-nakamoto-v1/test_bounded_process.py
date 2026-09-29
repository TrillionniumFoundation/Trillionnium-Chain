"""Real child pipe/cancellation regressions; no server or provider is launched."""
import os,sys,tempfile,time,unittest
from pathlib import Path
from bounded_process import run_bounded

class BoundedProcessTests(unittest.TestCase):
    def command(self,code):return [sys.executable,'-c',code]
    def test_concurrent_pipe_drain_before_large_input(self):
        code="import sys;sys.stderr.buffer.write(b'e'*50000);sys.stderr.flush();data=sys.stdin.buffer.read();sys.stdout.buffer.write(data)"
        payload=b'x'*200000
        result=run_bounded(self.command(code),payload)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,payload);self.assertEqual(len(result.stderr),50000)
    def test_stdout_flood_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory()as path:
            marker=Path(path)/'pid'
            code=f"import os,sys;open({str(marker)!r},'w').write(str(os.getpid()));sys.stdout.buffer.write(b'x'*1048576);sys.stdout.flush()"
            with self.assertRaisesRegex(ValueError,'NATIVE_STDOUT_LIMIT'):
                run_bounded(self.command(code),b'',stdout_limit=65536)
            with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)
    def test_stderr_flood_rejected(self):
        with self.assertRaisesRegex(ValueError,'NATIVE_STDERR_LIMIT'):
            run_bounded(self.command("import sys;sys.stderr.buffer.write(b'e'*100000)"),b'',stderr_limit=4096)
    def test_timeout_reaps_own_child(self):
        with tempfile.TemporaryDirectory()as path:
            marker=Path(path)/'pid'
            code=f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));time.sleep(5)"
            with self.assertRaisesRegex(ValueError,'NATIVE_EXECUTOR_TIMEOUT'):
                run_bounded(self.command(code),b'',timeout=.2)
            with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)
    def test_child_failure_is_not_success_or_reference_fallback(self):
        result=run_bounded(self.command("import sys;sys.stderr.write('STATE');sys.exit(17)"),b'input')
        self.assertEqual(result.returncode,17);self.assertEqual(result.stderr,b'STATE')
    def test_exact_output_boundary(self):
        result=run_bounded(self.command("import sys;sys.stdout.buffer.write(b'x'*4096)"),b'',stdout_limit=4096)
        self.assertEqual(len(result.stdout),4096)
    def test_missing_binary_is_explicit(self):
        with self.assertRaisesRegex(ValueError,'NATIVE_EXECUTOR_UNAVAILABLE'):run_bounded(['/no/such/trnm-executable'],b'')

if __name__=='__main__':unittest.main(verbosity=2)
