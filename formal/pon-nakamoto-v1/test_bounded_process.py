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

class CompleteInputTests(unittest.TestCase):
    """Real pipe fixtures; successful writes do not prove application consumption."""

    # Exceeds pipe capacity on the supported local POSIX test platforms. The
    # receiver closes its input, so the owner actually observes BrokenPipeError.
    payload=b'x'*(2*1024*1024)

    def command(self,code):return [sys.executable,'-c',code]

    def test_zero_exit_without_input_is_not_success(self):
        code="import os;os.close(0);os.write(1,b'claimed-success')"
        with self.assertRaisesRegex(ValueError,'^NATIVE_STDIN_INCOMPLETE$'):
            run_bounded(self.command(code),self.payload)

    def test_zero_exit_after_partial_read_is_not_success(self):
        code="import os;prefix=os.read(0,4096);os.close(0);os.write(1,str(len(prefix)).encode())"
        with self.assertRaisesRegex(ValueError,'^NATIVE_STDIN_INCOMPLETE$'):
            run_bounded(self.command(code),self.payload)

    def test_early_nonzero_rejection_preserves_actual_diagnostics(self):
        code="import os;os.close(0);os.write(1,b'partial');os.write(2,b'STATE');os._exit(17)"
        result=run_bounded(self.command(code),self.payload)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(17,b'partial',b'STATE'))

    def test_complete_delivery_keeps_exact_response(self):
        code="import sys;data=sys.stdin.buffer.read();sys.stderr.buffer.write(b'drained');sys.stdout.buffer.write(data[::-1])"
        payload=bytes(range(256))*8192
        result=run_bounded(self.command(code),payload)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,payload[::-1],b'drained'))

    def test_empty_request_and_exact_output_limit_are_unchanged(self):
        code="import os;os.close(0);os.write(1,b'x'*4096)"
        result=run_bounded(self.command(code),b'',stdout_limit=4096)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'x'*4096,b''))

    def test_closed_input_does_not_waive_output_caps(self):
        for fd,argument,code in [(1,'stdout_limit','NATIVE_STDOUT_LIMIT'),
                                  (2,'stderr_limit','NATIVE_STDERR_LIMIT')]:
            with self.subTest(stream=fd):
                child=f"import os;os.close(0);os.write({fd},b'x'*65536)"
                with self.assertRaisesRegex(ValueError,'^'+code+'$'):
                    run_bounded(self.command(child),self.payload,**{argument:4096})

    def test_closed_input_does_not_waive_deadline_or_reaping(self):
        with tempfile.TemporaryDirectory()as path:
            marker=Path(path)/'pid'
            code=f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));os.close(0);time.sleep(5)"
            with self.assertRaisesRegex(ValueError,'^NATIVE_EXECUTOR_TIMEOUT$'):
                run_bounded(self.command(code),self.payload,timeout=.5)
            with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)

    def test_failure_reaps_closed_pipe_writer(self):
        # The zero-exit child is reaped even though success is rejected after wait.
        with tempfile.TemporaryDirectory()as path:
            marker=Path(path)/'pid'
            code=f"import os;open({str(marker)!r},'w').write(str(os.getpid()));os.close(0);os.write(1,b'ok')"
            with self.assertRaisesRegex(ValueError,'^NATIVE_STDIN_INCOMPLETE$'):
                run_bounded(self.command(code),self.payload)
            with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)

if __name__=='__main__':unittest.main(verbosity=2)
