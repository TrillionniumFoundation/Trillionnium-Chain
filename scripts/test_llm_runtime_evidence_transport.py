"""Ordinary children/FDs; aggregate limits/raw and native birth are synthetic."""
import errno
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_aggregate as aggregate
import llm_runtime_kernel_owned as kernel
import llm_runtime_evidence_pipe as transport
import llm_runtime_pilot as runtime
import test_llm_runtime_evidence_pipe as ownership

# Each real child needs the exact source directory; unittest's in-process
# import path is not inherited by either python -c interpreter.
IMPORT_SOURCE = f'import sys\nsys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n'
PAYLOAD = IMPORT_SOURCE + """import os,sys,resource
from pathlib import Path
import llm_runtime_evidence_frames as f
pages=bytearray(1048576);pages[0]=1
f.borrow_evidence_stdout(int(sys.argv[1]),'payload').emit(f.KINDS[0],dict(
 pid=os.getpid(),ppid=os.getppid(),membership=Path('/proc/self/cgroup').read_text(),
 anonymous_bytes=len(pages),iterations=1,checksum=1,own_peak_rss_kib=resource.getrusage(0).ru_maxrss,
 model_loaded=False,descendants_spawned=False))
"""
WRAPPER = IMPORT_SOURCE + """import os,sys
from pathlib import Path
import llm_runtime_evidence_frames as f
import llm_runtime_pilot as r
deadline=int(sys.argv[-1]);before=Path('/proc/self/cgroup').read_text()
writer=f.borrow_evidence_stdout(deadline,'supervisor')
result=r.supervise([sys.executable,'-c',PAYLOAD,str(deadline)],Path(sys.argv[1]),
 dict(wall_seconds=2,rss_bytes=64*1024**2),_evidence_pipe=writer)
writer.emit(f.KINDS[2],dict(pid=os.getpid(),ppid=os.getppid(),membership_before=before,
 membership_after=Path('/proc/self/cgroup').read_text(),result=result,model_loaded=False))
""".replace('PAYLOAD',repr(PAYLOAD))


@unittest.skipUnless(sys.implementation.name=='cpython' and sys.version_info[:3]==(3,12,3),
    'controlled native ABI requires3.12.3')
class EvidenceTransportTests(unittest.TestCase):
    setUp = ownership.EvidencePipeOwnershipTests.setUp
    cleanup = ownership.EvidencePipeOwnershipTests.cleanup
    fixture = ownership.EvidencePipeOwnershipTests.fixture
    prepare = ownership.EvidencePipeOwnershipTests.prepare

    def bind(self):
        cap=self.fixture();cap.memory=8*1024**3;cap.fact=cap.child=None
        member=Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]
        cap.operation=kernel._ROOT/member.lstrip('/')
        pipe=self.prepare(cap);self.children=[]
        self.addCleanup(self.collect)
        def spawn(group,output,exe,argv,environment,slots):
            # Test-only ordinary spawn; actual native INTO_CGROUP is NOT_RUN.
            child=subprocess.Popen([os.fsdecode(value) for value in argv if value],
                stdout=output,stderr=subprocess.STDOUT)
            self.children.append(child)
            slots[:]=(child.pid,os.pidfd_open(child.pid),-1,-1)
            return 0
        def admitted(owner,deadline):
            self.assertLessEqual(abs(deadline-pipe.deadline_ns/10**9),math.ulp(deadline))
            cap.child=(owner.pid,owner.termination_fd,kernel.proc._signature(owner.termination_fd))
        self.native.spawn=spawn;cap.allow_exec=Mock(side_effect=admitted)
        return cap,pipe

    def collect(self):
        owner=getattr(self.cap,'spawn_owner',None)
        if owner is not None and getattr(owner,'termination_fd',None) is not None:owner.finish()
        for child in self.children:
            with self.assertRaises(ChildProcessError):os.waitpid(child.pid,os.WNOHANG)
            child.returncode=0

    def run_outer(self,cap,pipe,script=WRAPPER):
        self.ignored=Path(self.temporary.name)/'A-must-not-create'
        self.run=Path(self.temporary.name)/'C-run'
        return runtime.supervise([sys.executable,'-c',script,str(self.ignored)],self.run,
            dict(wall_seconds=8,rss_bytes=8*1024**3),_aggregate_operation=cap,_evidence_pipe=pipe)

    def test_two_original_wait4_owners_no_A_files_and_close_before_both_raw_reads(self):
        cap,pipe=self.bind();snapshots=[]
        def raw(fd):
            self.assertTrue(cap.spawn_owner.reaped);self.assertTrue(pipe.eof)
            self.assertEqual(pipe.read_slot[1],-1);self.assertEqual(pipe.write_slot[1],-1)
            snapshots.append(True);return {'memory.current':'0\n'}  # Synthetic raw, never kernel evidence.
        with patch.object(aggregate,'_raw',side_effect=raw):result=self.run_outer(cap,pipe)
        self.assertEqual(len(snapshots),2);self.assertFalse(self.ignored.exists())
        self.assertEqual(result['stop_reason'],'kernel-outer-reconciliation-required')
        self.assertEqual(result['outcome'],'failed');self.assertTrue(pipe.terminal_complete)
        self.assertTrue(pipe.frames.records[1]['result']['waited_child_reaped'])
        self.assertEqual(pipe.frames.records[1]['result']['budget'],dict(wall_seconds=2,rss_bytes=64*1024**2))
        self.assertEqual(pipe.frames.records[0]['pid'],pipe.frames.records[1]['owned_child_pid'])
        self.assertEqual((self.run/'process.log').stat().st_size,pipe.frames.received)
        self.assertTrue(self.native.operation is cap);self.assertFalse(result['tiny_evidence_transport']['authority'])
        with self.assertRaisesRegex(ValueError,'outer-reconciliation'):cap.close(cap.owner)

    def test_wrong_frames_stop_first_and_keep_original_owner_and_IO_slots(self):
        cap,pipe=self.bind()
        with patch.object(aggregate,'_raw') as raw:
            result=self.run_outer(cap,pipe,'import os,time;os.write(1,b"bad!");time.sleep(.2)')
        raw.assert_not_called();self.assertTrue(cap.failed);self.assertIsNone(cap.fact)
        self.assertEqual(result['stop_reason'],'evidence-pipe-transport-unavailable')
        self.assertEqual(result['tiny_evidence_transport']['first_error'],'evidence-pipe-frame-bound')
        self.assertIsNone(cap.spawn_owner.termination_fd);self.assertGreaterEqual(pipe.read_slot[1],3)

    def test_parse_memoryerror_and_keyboardinterrupt_cleanup_same_actual_child(self):
        for fault in (MemoryError,KeyboardInterrupt):
            with self.subTest(fault=fault.__name__):
                cap,pipe=self.bind()
                with patch.object(pipe.frames,'feed',side_effect=fault),patch.object(aggregate,'_raw') as raw:
                    with self.assertRaises(fault):self.run_outer(cap,pipe,'import os,time;os.write(1,b"abcd");time.sleep(.2)')
                raw.assert_not_called();owner=cap.spawn_owner
                self.assertTrue(owner.reaped);self.assertIsNone(owner.termination_fd)
                self.assertEqual(owner.observation_error,'evidence-pipe-transport-unavailable')
                self.assertIs(self.native.operation,cap);self.assertGreaterEqual(pipe.read_slot[1],3)
                self.collect();self.cleanup();self.setUp()

    def test_terminal_memoryerror_and_keyboardinterrupt_cannot_skip_original_pidfd_close(self):
        for fault in (MemoryError,KeyboardInterrupt):
            with self.subTest(fault=fault.__name__):
                cap,pipe=self.bind()
                with patch.object(pipe,'drain'),patch.object(pipe.frames,'feed',side_effect=fault), \
                        patch.object(aggregate,'_raw') as raw:result=self.run_outer(cap,pipe)
                raw.assert_not_called();self.assertIsNone(cap.spawn_owner.termination_fd)
                self.assertTrue(cap.spawn_owner.reaped);self.assertTrue(cap.failed)
                self.assertEqual(result['tiny_evidence_transport']['terminal_failure_type'],fault.__name__)
                self.assertFalse(pipe.terminal_complete);self.assertIs(self.native.operation,cap)
                self.collect();self.cleanup();self.setUp()

    def test_final_read_close_error_and_original_deadline_refuse_before_raw(self):
        for mode in ('close','deadline'):
            with self.subTest(mode=mode):
                cap,pipe=self.bind();original=self.native.release_owned
                def release(slot):
                    if slot is pipe.read_slot:slot[0]=errno.EIO
                    else:original(slot)
                def finish(child):
                    if mode=='deadline':
                        with patch.object(transport,'monotonic_ns',return_value=pipe.deadline_ns+1):
                            return original_finish(child)
                    return original_finish(child)
                original_finish=pipe._finish_locked
                with patch.object(pipe,'_finish_locked',side_effect=finish),patch.object(aggregate,'_raw') as raw:
                    if mode=='close':self.native.release_owned=release
                    result=self.run_outer(cap,pipe)
                raw.assert_not_called();self.assertIsNone(cap.spawn_owner.termination_fd)
                self.assertTrue(cap.failed);self.assertFalse(pipe.terminal_complete)
                self.assertEqual(result['outcome'],'failed');self.assertGreaterEqual(pipe.read_slot[1],3)
                self.native.release_owned=original
                self.collect();self.cleanup();self.setUp()

    def test_EOF_while_actual_supervisor_live_never_authorizes_wait4_or_read_close(self):
        cap,pipe=self.bind();original=pipe.drain;seen=[]
        def drain(child):
            original(child)
            if pipe.eof and not seen:
                seen.append(True)
                with self.assertRaisesRegex(ValueError,'exact-owned-wait4'):
                    cap.terminal_record(child.pid,child.termination_fd)
                self.assertGreaterEqual(pipe.read_slot[1],3)
        script=WRAPPER+'\nos.close(1);os.close(2);import time;time.sleep(.2)'
        with patch.object(pipe,'drain',side_effect=drain),patch.object(aggregate,'_raw') as raw:
            result=self.run_outer(cap,pipe,script)
        self.assertEqual(seen,[True]);raw.assert_not_called();self.assertFalse(pipe.terminal_complete)
        self.assertEqual(result['outcome'],'failed');self.assertIsNone(cap.spawn_owner.termination_fd)

    def test_invalid_sink_or_mixed_capability_refuses_before_mkdir_or_spawn(self):
        cap,pipe=self.bind()
        for sink,controlled in ((object(),None),(pipe,cap)):
            with patch.object(Path,'mkdir') as mkdir,patch.object(self.native,'spawn') as spawn:
                with self.assertRaisesRegex(ValueError,'INTERFACE'):
                    runtime.supervise(['/bin/true'],Path(self.temporary.name)/'never',
                        dict(wall_seconds=8,rss_bytes=8*1024**3),_aggregate_operation=cap,
                        _controlled_operation=controlled,_evidence_pipe=sink)
                mkdir.assert_not_called();spawn.assert_not_called()

    def test_writer_unsupported_and_failed_child_receipts_never_create_A_paths(self):
        for mode in ('unsupported','failed-child'):
            with self.subTest(mode=mode):
                cap,pipe=self.bind()
                if mode=='unsupported':
                    script=WRAPPER.replace('deadline=int',
                        "def unavailable(*args,**kwargs):raise r._Wait4Unsupported('fixture')\n"
                        'r._Wait4Child=unavailable\ndeadline=int')
                else:script=WRAPPER.replace(repr(PAYLOAD),repr('raise SystemExit(7)'))
                with patch.object(aggregate,'_raw') as raw:result=self.run_outer(cap,pipe,script)
                raw.assert_not_called();self.assertFalse(self.ignored.exists())
                data=(self.run/'process.log').read_bytes();size=int.from_bytes(data[:4],'little')
                receipt=json.loads(data[4:4+size])
                self.assertEqual(receipt['kind'],'inner-supervisor')
                self.assertEqual(receipt['data']['result']['outcome'],'failed')
                self.assertEqual(receipt['data']['result']['child_spawned'],mode!='unsupported')
                self.assertEqual(result['outcome'],'failed')
                self.collect();self.cleanup();self.setUp()

    def test_writer_exception_path_creates_no_A_log_or_partial_result(self):
        cap,pipe=self.bind()
        script=WRAPPER.replace('deadline=int',
            "def unavailable(*args,**kwargs):raise RuntimeError('fixture startup failed')\n"
            'r._Wait4Child=unavailable\ndeadline=int')
        with patch.object(aggregate,'_raw') as raw:result=self.run_outer(cap,pipe,script)
        raw.assert_not_called();self.assertFalse(self.ignored.exists())
        self.assertEqual(result['outcome'],'failed');self.assertIsNone(cap.spawn_owner.termination_fd)

    def test_reused_read_fd_is_not_closed_or_read_as_a_pipe(self):
        cap,pipe=self.bind();adopted=pipe.adopted
        def replace(child):
            adopted(child);descriptor=pipe.read_slot[1];os.close(descriptor)
            new=os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
            if new!=descriptor:os.dup2(new,descriptor);os.close(new)
        with patch.object(pipe,'adopted',side_effect=replace),patch.object(aggregate,'_raw') as raw:
            result=self.run_outer(cap,pipe)
        raw.assert_not_called();os.fstat(pipe.read_slot[1]);self.assertTrue(cap.failed)
        self.assertEqual(result['outcome'],'failed');self.assertIsNone(cap.spawn_owner.termination_fd)

    def test_terminal_projection_and_post_native_readclose_interrupt_keep_cleanup_order(self):
        for mode in ('projection','post-native-close'):
            with self.subTest(mode=mode):
                cap,pipe=self.bind();release=self.native.release_owned
                def interrupted(slot):
                    release(slot)
                    if slot is pipe.read_slot:raise KeyboardInterrupt
                def project(child):
                    child._retain_kernel_counter_diagnostic=Mock(side_effect=MemoryError)
                    raise aggregate.AggregateCounterError('aggregate-counter-format','aggregate/cpu.stat','bad.x 0\n')
                with patch.object(aggregate,'_raw') as raw:
                    if mode=='projection':pipe._finish_locked=project
                    else:self.native.release_owned=interrupted
                    result=self.run_outer(cap,pipe)
                self.native.release_owned=release;raw.assert_not_called()
                self.assertIsNone(cap.spawn_owner.termination_fd);self.assertTrue(cap.failed)
                self.assertIsNone(result['tiny_evidence_transport']['terminal_io_closed'])
                if mode=='post-native-close':self.assertEqual(pipe.read_slot[1],-1)
                else:self.assertTrue(cap.spawn_owner.kernel_counter_diagnostic_projection_failed)
                self.collect();self.cleanup();self.setUp()


if __name__=='__main__':unittest.main()
