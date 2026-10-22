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


class RetainedFailureTests(unittest.TestCase):
    def command(self,code):return [sys.executable,'-c',code]

    def test_nonfinite_or_boolean_timeout_refuses_before_spawn(self):
        with tempfile.TemporaryDirectory() as path:
            marker=Path(path)/'entered'
            for timeout in (float('nan'),float('inf'),-float('inf'),True,False,'1',1<<4096):
                with self.subTest(timeout=timeout):
                    with self.assertRaisesRegex(ValueError,'^NATIVE_PROCESS_ARGUMENT$'):
                        run_bounded(self.command(f"open({str(marker)!r},'w').write('entered')"),b'',timeout=timeout)
                    self.assertFalse(marker.exists())

    def test_explicit_cwd_environment_do_not_mutate_parent(self):
        import json
        before_cwd=os.getcwd();before_env=dict(os.environ)
        with tempfile.TemporaryDirectory(prefix="pon ' cwd ") as path:
            environment={'PON_OWNER_TEST':'exact'}
            code="import os,json;print(json.dumps([os.getcwd(),os.environ.get('PON_OWNER_TEST'),os.environ.get('PATH')]))"
            result=run_bounded(self.command(code),b'',cwd=path,env=environment)
            self.assertEqual(json.loads(result.stdout),[os.path.realpath(path),'exact',None])
            self.assertEqual(environment,{'PON_OWNER_TEST':'exact'})
        self.assertEqual(os.getcwd(),before_cwd);self.assertEqual(dict(os.environ),before_env)

    def test_output_failure_retains_bounded_observed_prefix(self):
        for fd,argument,error in ((1,'stdout_limit','NATIVE_STDOUT_LIMIT'),(2,'stderr_limit','NATIVE_STDERR_LIMIT')):
            with self.subTest(fd=fd):
                with self.assertRaisesRegex(ValueError,'^'+error+'$') as raised:
                    run_bounded(self.command(f"import os;os.write({fd},b'x'*65536)"),b'',**{argument:4096})
                failure=raised.exception
                self.assertEqual(getattr(failure,'stdout' if fd==1 else 'stderr'),b'x'*4096)
                self.assertIs(getattr(failure,'stdout_truncated' if fd==1 else 'stderr_truncated'),True)
                self.assertIsInstance(failure.returncode,int)

    def test_timeout_retains_actual_both_streams_and_reaps(self):
        with tempfile.TemporaryDirectory() as path:
            marker=Path(path)/'pid'
            code=f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));os.write(1,b'OUT');os.write(2,b'ERR');time.sleep(5)"
            with self.assertRaisesRegex(ValueError,'^NATIVE_EXECUTOR_TIMEOUT$') as raised:
                run_bounded(self.command(code),b'',timeout=.2)
            failure=raised.exception
            self.assertEqual((failure.stdout,failure.stderr),(b'OUT',b'ERR'))
            self.assertFalse(failure.stdout_truncated or failure.stderr_truncated)
            self.assertNotEqual(failure.returncode,0)
            with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)

    def test_zero_exit_incomplete_input_retains_failure_identity(self):
        payload=b'x'*(2*1024*1024)
        with self.assertRaisesRegex(ValueError,'^NATIVE_STDIN_INCOMPLETE$') as raised:
            run_bounded(self.command("import os;os.close(0);os.write(1,b'claimed');os.write(2,b'diagnostic')"),payload)
        failure=raised.exception
        self.assertEqual((failure.returncode,failure.stdout,failure.stderr),(0,b'claimed',b'diagnostic'))
        self.assertLess(failure.stdin_written,len(payload))


class CampaignProcessOwnerTests(unittest.TestCase):
    """Execute the actual nested owner with real children, not a native-result double."""
    def owner(self,root,out,manifest,environment):
        import ast
        import bounded_process
        source=Path(__file__).resolve().parents[2]/'scripts/run_public_v3_service_campaign.py'
        parsed=ast.parse(source.read_text())
        functions=[node for node in ast.walk(parsed) if isinstance(node,ast.FunctionDef) and node.name=='execute']
        self.assertEqual(len(functions),1)
        # Source metadata and scratch directories only; no process, clock,
        # stream, wait or cleanup API is mocked. Use the real source cap.
        constants=[node for node in parsed.body if isinstance(node,ast.Assign)
                   and any(isinstance(target,ast.Name) and target.id=='STAGE_STREAM_LIMIT' for target in node.targets)]
        namespace=dict(ROOT=root,out=out,env=environment,manifest=manifest,time=time,os=os,
                       subprocess=__import__('subprocess'),signal=__import__('signal'),
                       run_bounded=bounded_process.run_bounded,
                       ProcessFailure=getattr(bounded_process,'ProcessFailure',ValueError))
        exec(compile(ast.Module(body=constants+functions,type_ignores=[]),str(source),'exec'),namespace)
        return namespace['execute']

    def test_real_success_and_nonzero_keep_exact_streams_and_context(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path);out=root/'logs';out.mkdir();manifest={'timed_out':False,'commands':[]}
            before=dict(os.environ)
            execute=self.owner(root,out,manifest,{'PON_OWNER_TEST':'exact'})
            for name,code in [('success',0),('refusal',17)]:
                script="import os,sys;assert os.environ.get('PON_OWNER_TEST')=='exact';assert os.environ.get('PATH') is None;os.write(1,b'OUT');os.write(2,b'ERR');sys.exit("+str(code)+")"
                self.assertEqual(execute(name,[sys.executable,'-c',script],5),code)
                self.assertEqual((out/(name+'.stdout.log')).read_bytes(),b'OUT')
                self.assertEqual((out/(name+'.stderr.log')).read_bytes(),b'ERR')
                self.assertEqual((out/(name+'.log')).read_bytes(),b'OUTERR')
                row=manifest['commands'][-1]
                self.assertEqual(row['returncode'],code);self.assertIsNone(row['error'])
            self.assertFalse(manifest['timed_out']);self.assertEqual(dict(os.environ),before)

    def test_actual_timeout_preserves_failure_row_logs_and_reaping(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path);manifest={'timed_out':False,'commands':[]};marker=root/'pid'
            execute=self.owner(root,root,manifest,dict(os.environ))
            code=f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));os.write(1,b'OUT');os.write(2,b'ERR');time.sleep(5)"
            with self.assertRaisesRegex(ValueError,'^NATIVE_EXECUTOR_TIMEOUT$'):
                execute('timeout',[sys.executable,'-c',code],.2)
            self.assertTrue(manifest['timed_out']);self.assertEqual(len(manifest['commands']),1)
            self.assertEqual(manifest['commands'][0]['error'],'NATIVE_EXECUTOR_TIMEOUT')
            self.assertEqual((root/'timeout.log').read_bytes(),b'OUTERR')
            with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)

    def test_real_stdout_and_stderr_floods_are_bounded_not_success(self):
        for fd in (1,2):
            with self.subTest(fd=fd),tempfile.TemporaryDirectory() as path:
                root=Path(path);manifest={'timed_out':False,'commands':[]};marker=root/'pid'
                execute=self.owner(root,root,manifest,dict(os.environ))
                # Exceed the real 8 MiB cap without allocating a huge child buffer.
                code=f"import os;open({str(marker)!r},'w').write(str(os.getpid()))\nfor _ in range(2049): os.write({fd},b'x'*4096)"
                stream='stdout' if fd==1 else 'stderr'
                with self.assertRaisesRegex(ValueError,'^NATIVE_'+stream.upper()+'_LIMIT$'):
                    execute('flood',[sys.executable,'-c',code],5)
                self.assertEqual((root/('flood.'+stream+'.log')).stat().st_size,8*1024*1024)
                self.assertLessEqual((root/'flood.log').stat().st_size,16*1024*1024)
                self.assertTrue(manifest['commands'][0][stream+'_truncated'])
                self.assertFalse(manifest['timed_out'])
                with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)

    def test_create_new_output_refuses_before_child_entry(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path);manifest={'timed_out':False,'commands':[]};marker=root/'entered'
            (root/'duplicate.stdout.log').write_bytes(b'original')
            execute=self.owner(root,root,manifest,dict(os.environ))
            with self.assertRaises(FileExistsError):
                execute('duplicate',[sys.executable,'-c',f"open({str(marker)!r},'w').write('entered')"],5)
            self.assertFalse(marker.exists());self.assertEqual(manifest['commands'],[])
            self.assertEqual((root/'duplicate.stdout.log').read_bytes(),b'original')

    def test_absent_executable_retains_nonexecution_row(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path);manifest={'timed_out':False,'commands':[]}
            execute=self.owner(root,root,manifest,dict(os.environ))
            with self.assertRaisesRegex(ValueError,'^NATIVE_EXECUTOR_UNAVAILABLE$'):
                execute('absent',['/no/such/trnm-executable'],5)
            row=manifest['commands'][0]
            self.assertIsNone(row['returncode']);self.assertEqual(row['error'],'NATIVE_EXECUTOR_UNAVAILABLE')
            self.assertFalse(row['timed_out']);self.assertEqual((root/'absent.log').read_bytes(),b'')

    def test_exact_deadlines_commands_and_source_limits_remain(self):
        import ast
        source=Path(__file__).resolve().parents[2]/'scripts/run_public_v3_service_campaign.py'
        parsed=ast.parse(source.read_text())
        calls=[node for node in ast.walk(parsed) if isinstance(node,ast.Call)
               and isinstance(node.func,ast.Name) and node.func.id=='execute']
        self.assertEqual([(ast.literal_eval(c.args[0]),ast.literal_eval(c.args[2])) for c in calls],
                         [('build',600),('run',90),('negative',60)])
        function=next(node for node in ast.walk(parsed) if isinstance(node,ast.FunctionDef) and node.name=='execute')
        self.assertFalse(any(isinstance(node,ast.Attribute) and node.attr=='Popen' for node in ast.walk(function)))
        self.assertEqual(sum(isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                             and node.func.id=='run_bounded' for node in ast.walk(function)),1)


if __name__=='__main__':unittest.main(verbosity=2)
