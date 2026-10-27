"""Explicitly synthetic byte/process controls, never genuine proof evidence."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import _loopback_tcp as tcp
import measure_loopback as owner


class LoopbackControls(unittest.TestCase):
    def setUp(self):
        root = os.environ.get('PON_W1_LOOPBACK_TEST_EVIDENCE')
        if root:
            self.directory = Path(root)/self._testMethodName
            self.directory.mkdir(mode=0o700)
        else:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)

    def _receive(self,wire,expected,nonce,*,deadline_seconds=2,existing=None):
        output = self.directory/'receiver'
        output.mkdir()
        if existing is not None: (output/'received.bin').write_bytes(existing)
        record = dict(synthetic_bytes_only=True,cryptographic_proof_verified=False)
        deadline = time.monotonic_ns()+int(deadline_seconds*10**9)
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1',0)); listener.listen(1)
            def receive():
                listener.settimeout(tcp.remaining(deadline))
                connection,_ = listener.accept()
                with connection:
                    tcp.receive_stream(connection,output,expected,nonce,deadline,record)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(receive)
                with socket.create_connection(listener.getsockname(),timeout=2) as connection:
                    if wire is not None:
                        connection.sendall(wire); connection.shutdown(socket.SHUT_WR)
                    try: future.result(timeout=3)
                    except Exception as error:
                        record.update(error_type=type(error).__name__,error=str(error))
                    else: record['error'] = None
        tcp.write_json(self.directory/'control.json',record)
        return record,output

    def _frame(self,payload=b'test',length=None,digest=None,nonce=b'7'*32):
        expected = dict(bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest())
        return (tcp.FRAME.pack(tcp.MAGIC,len(payload) if length is None else length,
                               bytes.fromhex(expected['sha256']) if digest is None else digest,nonce),
                expected)

    def test_two_real_processes_stream_and_close_with_measured_rss(self):
        source = self.directory/'synthetic.bin'
        source.write_bytes(bytes(range(256))*8192)
        identity = tcp.file_identity(source)
        expected = {key:identity[key] for key in ('bytes','sha256')}
        record = {'test_material':'synthetic byte pattern; not a proof'}
        received = owner._transfer(source,expected,self.directory/'transfer',record)
        self.assertEqual(tcp.file_identity(received)['sha256'],expected['sha256'])
        self.assertEqual(record['outcome'],'complete')
        self.assertFalse(record['cryptographic_proof_verified'])
        self.assertFalse(record['public_ingress_qualified'])
        self.assertEqual(record['application_payload_bytes'],2*1024**2)
        self.assertEqual(record['application_framing_bytes'],160)
        for role in ('receiver','sender'):
            process = record['roles'][role]['process']
            self.assertTrue(process['waited_child_reaped'])
            self.assertTrue(process['owned_child_reap_resolved'])
            self.assertEqual(process['cleanup_method'],'wait4')
            self.assertGreater(process['waited_child_peak_rss_bytes'],0)
            self.assertLessEqual(process['waited_child_peak_rss_bytes'],tcp.MAX_BYTES)
            self.assertEqual(record['roles'][role]['worker']['address_space_limit_bytes'],tcp.MAX_BYTES)

    def test_short_frame_refuses_without_materialization(self):
        frame,expected = self._frame()
        record,output = self._receive(frame[:17],expected,b'7'*32)
        self.assertEqual(record['error'],'loopback-short-frame')
        self.assertFalse((output/'received.bin').exists())

    def test_short_payload_retains_failure(self):
        frame,expected = self._frame()
        record,output = self._receive(frame+b'te',expected,b'7'*32)
        self.assertEqual(record['error'],'loopback-short-payload')
        self.assertEqual((output/'received.partial').read_bytes(),b'te')
        self.assertFalse((output/'received.bin').exists())

    def test_trailing_byte_refuses(self):
        frame,expected = self._frame()
        record,output = self._receive(frame+b'testX',expected,b'7'*32)
        self.assertEqual(record['error'],'loopback-trailing-bytes')
        self.assertFalse(record['file_fsync_completed'])
        self.assertFalse((output/'received.bin').exists())

    def test_wrong_hash_refuses(self):
        frame,expected = self._frame()
        record,output = self._receive(frame+b'evil',expected,b'7'*32)
        self.assertEqual(record['error'],'loopback-payload-hash')
        self.assertEqual(record['payload_bytes_received'],4)
        self.assertFalse((output/'received.bin').exists())

    def test_over_cap_rejects_header_before_allocating_payload(self):
        frame,expected = self._frame(length=tcp.MAX_BYTES+1)
        record,output = self._receive(frame,expected,b'7'*32)
        self.assertEqual(record['error'],'loopback-payload-cap')
        self.assertFalse((output/'received.partial').exists())

    def test_wrong_connection_nonce_refuses(self):
        frame,expected = self._frame(nonce=b'8'*32)
        record,output = self._receive(frame,expected,b'7'*32)
        self.assertEqual(record['error'],'loopback-frame-identity')
        self.assertFalse((output/'received.partial').exists())

    def test_socket_timeout_is_failure_not_empty_success(self):
        _,expected = self._frame()
        record,output = self._receive(None,expected,b'7'*32,deadline_seconds=.15)
        self.assertEqual(record['error_type'],'TimeoutError')
        self.assertFalse((output/'received.bin').exists())

    def test_existing_final_is_never_replaced(self):
        frame,expected = self._frame()
        record,output = self._receive(frame+b'test',expected,b'7'*32,existing=b'original')
        self.assertEqual(record['error_type'],'FileExistsError')
        self.assertEqual((output/'received.bin').read_bytes(),b'original')
        self.assertEqual((output/'received.partial').read_bytes(),b'test')

    def test_timeout_exact_child_is_reaped(self):
        result = owner.supervise([sys.executable,'-I','-c','import time;time.sleep(10)'],
            self.directory/'process',dict(wall_seconds=.15,rss_bytes=tcp.MAX_BYTES))
        self.assertEqual(result['outcome'],'failed')
        self.assertEqual(result['stop_reason'],'wall-budget-exceeded')
        self.assertTrue(result['waited_child_reaped'])
        self.assertTrue(result['owned_child_reap_resolved'])
        self.assertEqual(result['cleanup_method'],'wait4')
        self.assertIsInstance(result['child_cpu_ns'],int)
        self.assertIsInstance(result['waited_child_peak_rss_bytes'],int)

    def test_measured_rss_breach_remains_failure_with_closed_wait4(self):
        result = owner.supervise([sys.executable,'-I','-c',
            'import time;x=bytearray(64*1024**2);time.sleep(2)'],
            self.directory/'process',dict(wall_seconds=3,rss_bytes=32*1024**2))
        self.assertEqual(result['outcome'],'failed')
        self.assertEqual(result['stop_reason'],'rss-budget-exceeded')
        self.assertTrue(result['waited_child_reaped'])
        self.assertEqual(result['cleanup_method'],'wait4')
        self.assertGreater(result['waited_child_peak_rss_bytes'],32*1024**2)

    def test_successful_nonverifier_without_result_cannot_verify(self):
        record = {}
        with self.assertRaisesRegex(ValueError,'expected exactly one'):
            owner._verify(Path('/bin/true'),Path('synthetic-guest'),Path('synthetic-input'),
                          Path('synthetic-receipt'),self.directory/'verify',
                          {'bytes':4},{'guest_image_id':'0'*64},record)
        self.assertEqual(record['process']['exit_code'],0)
        self.assertEqual(record['process']['outcome'],'success')
        self.assertTrue(record['process']['waited_child_reaped'])
        self.assertEqual(record['outcome'],'failed')
        self.assertIsNone(record['result'])
        tcp.write_json(self.directory/'control.json',dict(
            synthetic_negative_only=True,cryptographic_proof_verified=False,record=record))

    def test_public_cli_has_no_skip_or_supplied_result_mode(self):
        for flag in ('--skip-verify','--synthetic','--verification-result'):
            command = [sys.executable,str(owner.BACKEND/'measure_loopback.py')]
            for name in ('host','elf','input','receipt','out'):
                command += ['--'+name,str(self.directory/name)]
            completed = subprocess.run(command+[flag],
                                       capture_output=True,text=True,timeout=5)
            self.assertEqual(completed.returncode,2)
            self.assertIn('unrecognized arguments',completed.stderr)
            self.assertFalse((self.directory/'out').exists())
        self.assertEqual(owner.TRANSFER_SECONDS,30)
        self.assertEqual(owner.VERIFY_SECONDS,900)
        self.assertEqual(tcp.MAX_BYTES,128*1024**2)

    def test_source_snapshot_checks_original_guest_and_includes_both_owners(self):
        snapshot = owner._source_snapshot()
        self.assertIn('scripts/llm_runtime_pilot.py',snapshot)
        for name in ('host/src/main.rs','host/src/receipt_bounds.rs','measure_loopback.py','_loopback_tcp.py'):
            self.assertIn(str((owner.BACKEND/name).relative_to(owner.REPOSITORY)),snapshot)


if __name__ == '__main__':
    unittest.main()
