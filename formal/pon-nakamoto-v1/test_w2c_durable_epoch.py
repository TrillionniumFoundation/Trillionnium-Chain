"""Actual filesystem owner tests. No private host/cgroup or Node assertions."""
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from w2c_durable_epoch import (
    DurableEpochOwner, EpochOwnerError, NAME, RECORD_BYTES, _read_exact_records, ScopedResearchReceiver,
)


class DurableEpochControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.tmp.name)/'epoch'
        self.root.mkdir(mode=0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def open(self, marker):
        return DurableEpochOwner(str(self.root),entropy=lambda n:bytes([marker])*n)

    def test_actual_stateless_receiver_old_paid_ticket_denied_after_durable_restart(self):
        from contract_wire import H
        from w2c_receiver_admission import solve
        receiver, secret, caller = bytes([0x52])*32, bytes([0x53])*32, bytes([0x41])*32
        proposal = H('durable-epoch-same-proposal')
        with self.open(1) as owner:
            instance = ScopedResearchReceiver(owner, receiver, secret, capacity=2,
                                              entropy=lambda n:bytes([0x71])*n)
            grant=instance.offer(proposal, caller, 8, 100)
            nonce,_=solve(grant,65536)
            self.assertIsNotNone(nonce)
            self.assertEqual(instance.consume(grant,proposal,caller,nonce,120),'READY_RESOURCE_ONLY')
        with self.open(2) as owner2:
            restarted=ScopedResearchReceiver(owner2,receiver,secret,capacity=2,
                                             entropy=lambda n:bytes([0x71])*n)
            self.assertEqual(restarted.consume(grant,proposal,caller,nonce,130),'CONTEXT')
            fresh=restarted.offer(proposal, caller, 8, 130)
            n2,_=solve(fresh,65536)
            self.assertIsNotNone(n2)
            self.assertEqual(restarted.consume(fresh,proposal,caller,n2,140),'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(EpochOwnerError,'EPOCH_OWNER_NOT_LIVE'):
            instance.offer(proposal,caller,8,145)

    def test_a_clean_restart_never_reuses_an_issued_epoch(self):
        with self.open(1) as first:
            a=first.epoch()
            with self.assertRaisesRegex(EpochOwnerError, 'EPOCH_OWNER_BUSY'):
                self.open(2)
        with self.open(2) as second:
            self.assertNotEqual(a, second.epoch())
        raw=(self.root/NAME).read_bytes()
        self.assertEqual(len(raw), 2*RECORD_BYTES)
        self.assertEqual(_read_exact_records(raw)[0], 2)

    def test_old_epoch_cannot_survive_new_startup(self):
        with self.open(1) as first:
            a=first.epoch()
        with self.open(2) as second:
            b=second.epoch()
            self.assertNotEqual(a,b)
            self.assertEqual(len(a),32)

    def test_same_startup_fails_if_owner_is_forked(self):
        with self.open(3) as owner:
            child=os.fork()
            if child==0:
                try:
                    try: owner.epoch()
                    except EpochOwnerError: os._exit(0)
                    os._exit(1)
                except BaseException: os._exit(2)
            _,status=os.waitpid(child,0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status),0)

    def test_live_owner_refuses_permission_widening(self):
        with self.open(1) as owner:
            os.chmod(self.root,0o770)
            with self.assertRaisesRegex(EpochOwnerError,'EPOCH_DIRECTORY_OWNER'):
                owner.epoch()
            os.chmod(self.root,0o700)
            os.chmod(self.root/NAME,0o666)
            with self.assertRaisesRegex(EpochOwnerError,'EPOCH_FILE_OWNER'):
                owner.epoch()
            os.chmod(self.root/NAME,0o600)
            self.assertEqual(len(owner.epoch()),32)

    def test_parent_directory_replacement_fences_previous_process(self):
        with self.open(1) as owner:
            hidden=self.root.with_name('old-owner')
            self.root.rename(hidden)
            self.root.mkdir(mode=0o700)
            with self.assertRaisesRegex(EpochOwnerError,'EPOCH_DIRECTORY_REPLACED'):
                owner.epoch()
            self.root.rmdir()
            hidden.rename(self.root)

    def test_partial_torn_log_refuses_restart_instead_of_reset(self):
        with self.open(1): pass
        with (self.root/NAME).open('ab') as f:
            f.write(b'PARTIAL')
        with self.assertRaisesRegex(EpochOwnerError, 'EPOCH_CORRUPT'):
            self.open(2)

    def test_old_log_replacement_and_hardlink_detected(self):
        with self.open(1) as owner:
            p=self.root/NAME
            other=self.root/'old'
            p.rename(other)
            p.write_bytes(b'REPLACED')
            with self.assertRaisesRegex(EpochOwnerError,'EPOCH_FILE_REPLACED'):
                owner.assert_live()
        (self.root/NAME).unlink()
        other.rename(self.root/NAME)
        hard=self.root/'copy'
        os.link(self.root/NAME,hard)
        with self.assertRaisesRegex(EpochOwnerError,'EPOCH_FILE_OWNER'):
            self.open(2)
        hard.unlink()

    def test_symlink_weak_directory_and_world_writable_file_fail(self):
        link=pathlib.Path(self.tmp.name)/'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            DurableEpochOwner(str(link))
        os.chmod(self.root,0o770)
        with self.assertRaisesRegex(EpochOwnerError,'EPOCH_DIRECTORY_OWNER'):
            self.open(2)
        os.chmod(self.root,0o700)
        with self.open(1): pass
        os.chmod(self.root/NAME,0o666)
        with self.assertRaisesRegex(EpochOwnerError,'EPOCH_FILE_OWNER'):
            self.open(2)

    def test_bad_random_and_fsync_failure_never_returns_usable_epoch(self):
        with self.assertRaisesRegex(EpochOwnerError,'EPOCH_RANDOM_UNAVAILABLE'):
            DurableEpochOwner(str(self.root), entropy=lambda n:b'bad')
        # Torn/uninitialised log deliberately remains unusable.
        with self.assertRaisesRegex(EpochOwnerError,'EPOCH_CORRUPT'):
            self.open(4)
        (self.root/NAME).unlink()
        with patch('os.fsync',side_effect=OSError('simulated fsync loss')):
            with self.assertRaises(OSError):
                self.open(1)
        # The valid record might have been written, but was not returned to
        # the caller; next startup must commit a *different* record.
        with self.open(2) as second:
            self.assertEqual(len(second.epoch()),32)

    def test_counter_corruption_rejected(self):
        with self.open(1): pass
        p=self.root/NAME
        buf=bytearray(p.read_bytes())
        buf[8]^=1
        p.write_bytes(buf)
        with self.assertRaisesRegex(EpochOwnerError,'EPOCH_CORRUPT'):
            self.open(2)

    def test_manual_filesystem_snapshot_rollback_remains_a_documented_nonclosure(self):
        with self.open(1): pass
        image=(self.root/NAME).read_bytes()
        with self.open(2) as second:
            second_epoch=second.epoch()
        # A storage administrator silently restores the prior snapshot, and
        # cloned entropy repeats: a byte-identical next epoch can arise.
        (self.root/NAME).write_bytes(image)
        with self.open(2) as vulnerable:
            self.assertEqual(second_epoch,vulnerable.epoch())
        # This is a retained known FAILURE, not a rollback-defense PASS.

if __name__=='__main__':unittest.main(verbosity=2)
