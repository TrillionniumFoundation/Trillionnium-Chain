"""OS-process tests for the narrow single-host W2-C research epoch lease."""
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contract_wire import H
from w2c_receiver_admission import solve
from w2c_local_epoch_lease import epoch_lock_path, LocalEpochLeasedReceiver


RECEIVER = bytes([0x52]) * 32
CALLER = bytes([0x41]) * 32
PROPOSAL = H('single-host-real-process-p5')


def _child_try_lease(path, receiver, result):
    try:
        with LocalEpochLeasedReceiver(path, receiver , policy_bits=8) as node:
            result.put(('ACQUIRED', node.epoch.hex()))
    except Exception as error:
        result.put(('REFUSED', str(error)))


def _child_reuse_parent(parent, result):
    try:
        parent.offer(PROPOSAL, CALLER, 8)
        result.put('UNSAFE_PARENT_REUSE')
    except Exception as error:
        result.put(str(error))


class LocalEpochLeaseTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.path = epoch_lock_path(Path(self.root.name), RECEIVER)

    def tearDown(self):
        self.root.cleanup()

    def _ticket(self, node):
        grant = node.offer(PROPOSAL, CALLER, 8)
        nonce, raw = solve(grant, 65536)
        self.assertEqual(raw['status'], 'TARGET_HIT_UNVERIFIED')
        self.assertIsNotNone(nonce)
        return grant, nonce

    def _fork(self, target, *args):
        if not hasattr(os, 'fork'):
            self.skipTest('Linux fork controls')
        ctx = multiprocessing.get_context('fork')
        q = ctx.Queue(maxsize=1)
        p = ctx.Process(target=target, args=(*args, q))
        p.start()
        p.join(timeout=6)
        if p.is_alive():
            p.kill()
            p.join()
            self.fail('subprocess did not terminate within finite deadline')
        self.assertEqual(p.exitcode, 0)
        value = q.get(timeout=2)
        q.close()
        return value

    def test_two_real_processes_cannot_share_one_live_receiver_epoch(self):
        with LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8) as parent:
            outcome = self._fork(_child_try_lease, self.path, RECEIVER)
            self.assertEqual(outcome[0], 'REFUSED')
            self.assertEqual(outcome[1], 'EPOCH_ALREADY_OWNED')
            self.assertEqual(parent.paid_count(), 0)

    def test_crash_style_reopen_rekeys_and_refuses_predecessor_paid_ticket(self):
        parent = LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8)
        old_epoch = parent.epoch
        grant, nonce = self._ticket(parent)
        self.assertEqual(parent.consume(grant, PROPOSAL, CALLER, nonce),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(parent.consume(grant, PROPOSAL, CALLER, nonce),
                         'REPLAY')
        parent.close()
        with LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8) as fresh:
            self.assertNotEqual(fresh.epoch, old_epoch)
            self.assertEqual(fresh.consume(grant, PROPOSAL, CALLER, nonce),
                             'CONTEXT')
            self.assertEqual(fresh.paid_count(), 0)
            grant2, nonce2 = self._ticket(fresh)
            self.assertEqual(fresh.consume(grant2, PROPOSAL, CALLER, nonce2),
                             'READY_RESOURCE_ONLY')

    def test_fork_inherited_python_object_cannot_reissue_old_credentials(self):
        with LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8) as parent:
            failure = self._fork(_child_reuse_parent, parent)
            self.assertEqual(failure, 'EPOCH_PROCESS_OWNER')
            ticket, nonce = self._ticket(parent)
            self.assertEqual(parent.consume(ticket, PROPOSAL, CALLER, nonce),
                             'READY_RESOURCE_ONLY')

    def test_file_replacement_is_detected_before_any_paid_grant(self):
        with LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8) as parent:
            self.path.unlink()
            self.path.write_bytes(b'')
            os.chmod(self.path, 0o600)
            with self.assertRaisesRegex(ValueError, 'EPOCH_LOCK_REPLACED'):
                parent.offer(PROPOSAL, CALLER, 8)

    def test_untrusted_permission_symlink_and_path_alias_refused(self):
        with LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8):
            pass
        os.chmod(self.path, 0o666)
        with self.assertRaisesRegex(ValueError, 'EPOCH_LOCK_UNTRUSTED'):
            LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8)
        self.path.unlink()
        other = self.path.with_name('real.lock')
        other.write_bytes(b'')
        os.chmod(other, 0o600)
        self.path.symlink_to(other)
        with self.assertRaises(OSError):
            LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8)
        with self.assertRaisesRegex(ValueError, 'EPOCH_LOCK_IDENTITY'):
            LocalEpochLeasedReceiver(other, RECEIVER , policy_bits=8)
        self.path.unlink()
        os.chmod(self.root.name, 0o777)
        with self.assertRaisesRegex(ValueError, 'EPOCH_PARENT_UNTRUSTED'):
            LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8)

    def test_cost_bits_and_live_parent_lock_metadata_cannot_downgrade(self):
        with LocalEpochLeasedReceiver(self.path, RECEIVER, policy_bits=12) as node:
            with self.assertRaisesRegex(ValueError, 'EPOCH_BITS_POLICY'):
                node.offer(PROPOSAL, CALLER, 8)
            grant = node.offer(PROPOSAL, CALLER, 12)
            self.assertEqual(grant.bits, 12)
            os.chmod(self.root.name, 0o777)
            try:
                with self.assertRaisesRegex(ValueError, 'EPOCH_PARENT_UNTRUSTED'):
                    node.offer(PROPOSAL, CALLER, 12)
            finally:
                os.chmod(self.root.name, 0o700)
            os.chmod(self.path, 0o666)
            with self.assertRaisesRegex(ValueError, 'EPOCH_LOCK_UNTRUSTED'):
                node.offer(PROPOSAL, CALLER, 12)
            os.chmod(self.path, 0o600)

    def test_closed_epoch_owner_and_secret_not_retained_by_global_fork_callback(self):
        import gc
        import weakref
        node = LocalEpochLeasedReceiver(self.path, RECEIVER, policy_bits=8)
        owner = weakref.ref(node)
        node.close()
        del node
        gc.collect()
        self.assertIsNone(
            owner(),
            'process-global at-fork registration must not keep old Epoch secrets alive',
        )

    def test_close_does_not_leave_a_reusable_live_epoch(self):
        node = LocalEpochLeasedReceiver(self.path, RECEIVER , policy_bits=8)
        node.close()
        node.close()
        with self.assertRaisesRegex(ValueError, 'EPOCH_PROCESS_OWNER'):
            node.offer(PROPOSAL, CALLER, 8)


if __name__ == '__main__':
    unittest.main(verbosity=2)
