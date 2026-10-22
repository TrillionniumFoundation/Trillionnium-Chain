"""Pure framing and ordinary borrowed-FIFO tests; no unit/cgroup/model."""
import fcntl
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import tempfile
import time
import unittest

import llm_runtime_evidence_frames as frames


def records():
    result = dict(outcome='success', child_spawned=True, waited_child_reaped=True,
        cleanup_method='wait4', budget=dict(wall_seconds=2, rss_bytes=64*1024**2))
    return [dict(pid=103, ppid=102, membership='0::/example/aggregate\n', anonymous_bytes=1048576,
        iterations=10, checksum=22, own_peak_rss_kib=100, model_loaded=False, descendants_spawned=False),
        dict(result=result, owned_child_pid=103, supervisor_pid=102),
        dict(pid=102, ppid=101, membership_before='0::/example/aggregate\n',
             membership_after='0::/example/aggregate\n', result=result, model_loaded=False)]


def wire(values=None):
    return b''.join(frames.encode_frame(kind, value) for kind, value in zip(frames.KINDS, values or records()))


class EvidenceFrameTests(unittest.TestCase):
    def decode(self, raw, size=4096):
        parser = frames._TinyFrames()
        for offset in range(0, len(raw), size): parser.feed(raw[offset:offset+size])
        parser.complete()
        return parser

    def json_frame(self, raw): return struct.pack('<I', len(raw))+raw

    def test_round_trip_one_byte_chunks_and_three_fixed_destinations(self):
        parser = self.decode(wire(), 1)
        self.assertEqual(parser.records, records())
        self.assertEqual(len(parser.records), 3)
        self.assertEqual(parser.received, len(wire()))
        self.assertIsNone(parser.failure)

    def test_large_valid_frames_never_require_more_than_one_bounded_partial_body(self):
        values = records(); values[1]['result']['padding'] = 'x'*60000
        parser = self.decode(wire(values), 4096)
        self.assertEqual(parser.records, values)
        self.assertEqual(parser.body, bytearray()); self.assertEqual(parser.header, bytearray())

    def test_split_at_each_header_boundary(self):
        raw = wire()
        for first in range(5):
            parser = frames._TinyFrames(); parser.feed(raw[:first]); parser.feed(raw[first:])
            parser.complete(); self.assertEqual(parser.records, records())

    def test_length_zero_and_above_bound_are_sticky_with_bounded_fragment(self):
        for size in (0, frames.MAX_FRAME+1, 2**32-1):
            parser = frames._TinyFrames()
            with self.assertRaisesRegex(ValueError, 'frame-bound'): parser.feed(struct.pack('<I', size))
            first = parser.error_ns
            with self.assertRaisesRegex(ValueError, 'frame-bound'): parser.feed(wire())
            self.assertEqual(parser.error_ns, first); self.assertLessEqual(len(parser.fragment), 4096)

    def test_read_and_total_byte_bounds_are_sticky(self):
        parser = frames._TinyFrames()
        with self.assertRaisesRegex(ValueError, 'read-bound'): parser.feed(b'x'*4097)
        with self.assertRaisesRegex(ValueError, 'read-bound'): parser.feed(b'')
        parser = frames._TinyFrames(); parser.received = frames.MAX_TOTAL
        with self.assertRaisesRegex(ValueError, 'total-bound'): parser.feed(b'\x01')
        self.assertEqual(parser.received, frames.MAX_TOTAL)

    def test_missing_truncated_header_and_truncated_body_refuse_completion(self):
        for raw in (b'', b'\x20', struct.pack('<I', 20)+b'{', wire()[:-1]):
            parser = frames._TinyFrames(); parser.feed(raw)
            with self.assertRaisesRegex(ValueError, 'truncated-or-missing'): parser.complete()
            with self.assertRaisesRegex(ValueError, 'truncated-or-missing'): parser.feed(b'')

    def test_extra_frame_or_unframed_stderr_never_becomes_success(self):
        for raw in (wire()+b'\0', b'Traceback\n', wire()+wire()):
            parser = frames._TinyFrames()
            with self.assertRaises(ValueError): parser.feed(raw)
            with self.assertRaises(ValueError): parser.complete()

    def test_wrong_order_wrong_schema_and_extra_wrapper_key_refuse(self):
        for value in (dict(schema=frames.SCHEMA, kind=frames.KINDS[1], data=records()[1]),
                      dict(schema='other', kind=frames.KINDS[0], data=records()[0]),
                      dict(schema=frames.SCHEMA, kind=frames.KINDS[0], data=records()[0], extra=True)):
            with self.assertRaisesRegex(ValueError, 'order-schema'):
                frames._TinyFrames().feed(self.json_frame(json.dumps(value).encode()))

    def test_duplicate_top_level_and_nested_keys_nonfinite_and_invalid_utf8_refuse(self):
        good = frames.encode_frame(frames.KINDS[0], records()[0])[4:]
        raws = [good.replace(b'"schema":', b'"schema":"duplicate","schema":'),
            good.replace(b'"pid":103', b'"pid":1,"pid":103'),
            good.replace(b'"checksum":22', b'"checksum":NaN'), b'\xff', b'{']
        for raw in raws:
            with self.assertRaises(ValueError): frames._TinyFrames().feed(self.json_frame(raw))

    def test_json_depth_node_and_finite_tree_constraints_refuse(self):
        values = records()
        for bad in ([None]*8200, [[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]], float('inf'), object()):
            values[1]['result']['extra'] = bad
            with self.assertRaises(ValueError): frames.encode_frame(frames.KINDS[1], values[1])

    def test_exact_payload_size_types_and_no_model_schema(self):
        for key, bad in (('anonymous_bytes', True), ('anonymous_bytes', 2), ('pid', True),
                         ('checksum', -1), ('model_loaded', True), ('descendants_spawned', True)):
            value = records()[0]; value[key] = bad
            with self.assertRaisesRegex(ValueError, 'payload-schema'):
                frames.encode_frame(frames.KINDS[0], value)
        value = records()[0]; value['extra'] = True
        with self.assertRaisesRegex(ValueError, 'payload-schema'): frames.encode_frame(frames.KINDS[0], value)

    def test_result_budget_and_child_schema_refuse_public_or_alternate_owner_claims(self):
        for budget in (dict(wall_seconds=True, rss_bytes=64*1024**2),
                       dict(wall_seconds=3, rss_bytes=64*1024**2), dict(wall_seconds=2, rss_bytes=1)):
            value = records()[1]; value['result']['budget'] = budget
            with self.assertRaisesRegex(ValueError, 'result-schema'): frames.encode_frame(frames.KINDS[1], value)
        value = records()[1]; value['result']['controlled_kernel_spawn'] = {}
        with self.assertRaisesRegex(ValueError, 'result-schema'): frames.encode_frame(frames.KINDS[1], value)
        value = records()[1]; value['owned_child_pid'] = None
        with self.assertRaisesRegex(ValueError, 'inner-child'): frames.encode_frame(frames.KINDS[1], value)

    def test_unsupported_failed_nochild_record_can_only_report_evidence(self):
        values = records(); result = values[1]['result']
        result.update(outcome='failed', child_spawned=False, waited_child_reaped=False,
                      cleanup_method='no-child-spawned')
        values[1]['owned_child_pid'] = None
        parser = self.decode(wire(values)); self.assertEqual(parser.records[1]['result']['outcome'], 'failed')
        self.assertFalse(hasattr(parser, 'terminal_record'))

    def test_encoder_bounds_include_atomic_tiny_frame(self):
        value = records()[0]; value['membership'] = '0::/'+'x'*3900+'\n'
        with self.assertRaisesRegex(ValueError, 'frame-bound'): frames.encode_frame(frames.KINDS[0], value)
        value = records()[1]; value['result']['padding'] = 'x'*65536
        with self.assertRaisesRegex(ValueError, 'frame-bound'): frames.encode_frame(frames.KINDS[1], value)


@unittest.skipUnless(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3,12,3),
    'borrowed controlled writer requires3.12.3')
class EvidenceWriterTests(unittest.TestCase):
    def script(self, suffix):
        return ('import os,sys,time,json,signal,threading\n'
                'import llm_runtime_evidence_frames as f\n'
                'values='+repr(records())+'\n'+suffix)

    def run_pipe(self, script, drain=True):
        read, write = os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
        child = None; raw = bytearray()
        try:
            # Smaller ordinary test pipe forces backpressure; production never resizes.
            self.assertEqual(fcntl.fcntl(write,fcntl.F_SETPIPE_SZ,4096),4096)
            child = subprocess.Popen([sys.executable, '-c', self.script(script)], stdout=write,
                stderr=subprocess.PIPE, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            os.close(write); write = -1
            deadline = time.monotonic()+3
            poll = select.poll(); poll.register(read, select.POLLIN|select.POLLHUP)
            while drain and time.monotonic() < deadline:
                try:
                    chunk = os.read(read, 4096)
                    if not chunk: break
                    raw.extend(chunk); self.assertLessEqual(len(raw), frames.MAX_TOTAL)
                except BlockingIOError: poll.poll(10)
            _, error = child.communicate(timeout=max(.1,deadline-time.monotonic()))
            self.assertEqual(child.returncode, 0, error.decode(errors='replace'))
            return bytes(raw), error
        finally:
            if child is not None and child.poll() is None: child.kill(); child.wait()
            os.close(read)
            if write >= 0: os.close(write)

    def test_actual_nonblocking_fifo_writer_emits_three_ordered_frames_without_closing_stdout(self):
        raw, error = self.run_pipe("""deadline=time.monotonic_ns()+2_000_000_000
p=f.borrow_evidence_stdout(deadline,'payload');p.emit(f.KINDS[0],values[0])
s=f.borrow_evidence_stdout(deadline,'supervisor')
for i in (1,2):s.emit(f.KINDS[i],values[i])
assert os.fstat(1) and s.sent==2 and not s.failed
""")
        self.assertEqual(EvidenceFrameTests().decode(raw).records, records()); self.assertEqual(error,b'')

    def test_actual_backpressure_large_frames_complete_under_same_deadline(self):
        raw, _ = self.run_pipe("""deadline=time.monotonic_ns()+2_000_000_000
values[1]['result']['padding']='x'*60000
values[2]['result']['padding']='x'*60000
f.borrow_evidence_stdout(deadline,'payload').emit(f.KINDS[0],values[0])
s=f.borrow_evidence_stdout(deadline,'supervisor')
for i in (1,2):s.emit(f.KINDS[i],values[i])
""")
        self.assertGreater(len(raw), 120000); EvidenceFrameTests().decode(raw)

    def test_writer_order_fault_is_sticky_and_borrowed_fd_remains_open(self):
        raw, _ = self.run_pipe("""s=f.borrow_evidence_stdout(time.monotonic_ns()+1_000_000_000,'supervisor')
try:s.emit(f.KINDS[2],values[2]);raise AssertionError('accepted order')
except f.EvidencePipeError:pass
assert s.failed and os.fstat(1)
try:s.emit(f.KINDS[1],values[1]);raise AssertionError('accepted retry')
except f.EvidencePipeError:pass
""")
        self.assertEqual(raw,b'')

    def test_actual_full_pipe_expired_deadline_is_failure_without_new_allowance(self):
        _, _ = self.run_pipe("""s=f.borrow_evidence_stdout(time.monotonic_ns()+100_000_000,'supervisor')
values[1]['result']['padding']='x'*60000
try:s.emit(f.KINDS[1],values[1]);raise AssertionError('accepted full pipe')
except f.EvidencePipeError:pass
assert s.failed and os.fstat(1)
""", drain=False)

    def test_signal_reentry_and_cross_thread_reject_without_borrowed_fd_close(self):
        raw, _ = self.run_pipe("""s=f.borrow_evidence_stdout(time.monotonic_ns()+1_000_000_000,'payload')
errors=[]
def other():
 try:s.emit(f.KINDS[0],values[0])
 except f.EvidencePipeError as e:errors.append(str(e))
t=threading.Thread(target=other);t.start();t.join()
signal.signal(signal.SIGUSR1,lambda *_:other())
with s._busy:signal.raise_signal(signal.SIGUSR1)
assert errors==['evidence-pipe-writer-thread','evidence-pipe-writer-reentry']
assert s._busy._recursion_count()==0 and not s.failed and os.fstat(1)
s.emit(f.KINDS[0],values[0])
""")
        parser = frames._TinyFrames(); parser.feed(raw); self.assertEqual(parser.index,1)

    def test_regular_stdout_is_not_a_borrowable_transport(self):
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([sys.executable,'-c',self.script("""try:
 f.borrow_evidence_stdout(time.monotonic_ns()+1_000_000_000,'payload')
except f.EvidencePipeError:sys.exit(0)
raise AssertionError('accepted regular file')
""")], stdout=output, stderr=subprocess.PIPE, timeout=2)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_read_endpoint_or_blocking_fifo_refuses_without_closing_borrowed_stdout(self):
        for direction, flags in (('read',os.O_NONBLOCK),('write',0)):
            read, write = os.pipe2(flags|os.O_CLOEXEC)
            try:
                result = subprocess.run([sys.executable,'-c',self.script("""try:
 f.borrow_evidence_stdout(time.monotonic_ns()+1_000_000_000,'payload')
except f.EvidencePipeError:
 assert os.fstat(1);sys.exit(0)
raise AssertionError('accepted endpoint')
""")], stdout=read if direction=='read' else write,stderr=subprocess.PIPE,timeout=2)
                self.assertEqual(result.returncode,0,result.stderr)
            finally: os.close(read);os.close(write)

    def test_actual_epipe_is_sticky_and_never_closes_borrowed_write_endpoint(self):
        read, write = os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
        os.close(read)
        try:
            result = subprocess.run([sys.executable,'-c',self.script("""s=f.borrow_evidence_stdout(time.monotonic_ns()+1_000_000_000,'payload')
try:s.emit(f.KINDS[0],values[0]);raise AssertionError('accepted EPIPE')
except BrokenPipeError:pass
assert s.failed and os.fstat(1)
try:s.emit(f.KINDS[0],values[0]);raise AssertionError('accepted retry')
except f.EvidencePipeError:pass
""")], stdout=write,stderr=subprocess.PIPE,timeout=2)
            self.assertEqual(result.returncode,0,result.stderr)
        finally: os.close(write)

    def test_python_exception_after_real_write_never_resends_or_claims_record_completion(self):
        for fault in ('KeyboardInterrupt','MemoryError'):
            raw, _ = self.run_pipe("""s=f.borrow_evidence_stdout(time.monotonic_ns()+1_000_000_000,'payload')
original=os.write;calls=[]
def injected(fd,raw):
 size=original(fd,raw);calls.append(size);raise FAULT
os.write=injected
try:s.emit(f.KINDS[0],values[0]);raise AssertionError('accepted interruption')
except FAULT:pass
assert s.failed and s.sent==0 and len(calls)==1 and os.fstat(1)
try:s.emit(f.KINDS[0],values[0]);raise AssertionError('accepted resend')
except f.EvidencePipeError:pass
assert len(calls)==1
""".replace('FAULT',fault))
            self.assertEqual(raw,frames.encode_frame(frames.KINDS[0],records()[0]))


if __name__ == '__main__': unittest.main()
