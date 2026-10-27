"""Real SQLite/fail-closed cross-process tests of *research-only* W2-C spending.

No native W1, real V3 Cookie, GPU pricing, chainwork, or independent custodian.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from contract_wire import H
from w2c_durable_spent import DurableReceiverAdmission as Receiver, DB_NAME
from w2c_receiver_admission import Grant, solve

THIS = Path(__file__).resolve().parent
CHILD = """
import json, os, sys
from w2c_durable_spent import DurableReceiverAdmission
from w2c_receiver_admission import Grant
a=json.loads(sys.argv[2])
g=Grant(*(bytes.fromhex(a[k]) if k in ('receiver','epoch','proposal','token','mac')
          else a[k] for k in ('receiver','epoch','proposal','token','bits','issued_ms','expires_ms','mac')))
owner=DurableReceiverAdmission(bytes([1])*32, bytes([2])*32, bytes([3])*32,
                               sys.argv[1], create=False, capacity=2)
out=owner.consume(g, bytes([4])*32, bytes([5])*32, int(sys.argv[3]), 130)
if sys.argv[4]=='crash':
    assert out=='READY_RESOURCE_ONLY', out
    os._exit(17)  # after durable commit, before any claimed W1 execution
print(out, flush=True)
"""


class DurablePaidSpendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.proposal = bytes([4]) * 32
        self.caller = bytes([5]) * 32
        self.receiver = bytes([1]) * 32
        self.secret = bytes([2]) * 32
        self.epoch = bytes([3]) * 32
        self.seed = 0
        def fresh(n):
            self.assertEqual(n, 32)
            self.seed += 1
            return self.seed.to_bytes(8, 'little') + bytes(24)
        self.entropy = fresh

    def owner(self, *, create=False, directory=None, epoch=None):
        return Receiver(self.receiver, self.secret, epoch or self.epoch,
                        directory or self.directory, create=create,
                        capacity=2, entropy=self.entropy)

    def ticket(self, owner, now=100):
        grant = owner.offer(self.proposal, self.caller, 8, now)
        nonce, result = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(result['status'], 'TARGET_HIT_UNVERIFIED')
        return grant, nonce

    def child(self, grant, nonce, action='replay', directory=None):
        payload = asdict(grant)
        for key in ('receiver', 'epoch', 'proposal', 'token', 'mac'):
            payload[key] = payload[key].hex()
        environment = dict(os.environ)
        environment['PYTHONPATH'] = str(THIS)
        return subprocess.run(
            [sys.executable, '-c', CHILD, str(directory or self.directory),
             json.dumps(payload), str(nonce), action],
            env=environment, capture_output=True, text=True, timeout=10,
        )

    def test_restart_same_store_rejects_paid_ticket(self):
        owner = self.owner(create=True)
        grant, nonce = self.ticket(owner)
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, nonce, 120),
                         'READY_RESOURCE_ONLY')
        owner.close()
        reopened = self.owner()
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.pending_paid(), 1)
        self.assertEqual(reopened.consume(grant, self.proposal, self.caller, nonce, 130),
                         'REPLAY')

    def test_paid_spend_survives_abrupt_process_exit_after_commit(self):
        first = self.owner(create=True)
        grant, nonce = self.ticket(first)
        first.close()
        child = self.child(grant, nonce, action='crash')
        self.assertEqual(child.returncode, 17, child.stderr)
        parent = self.owner()
        self.addCleanup(parent.close)
        self.assertEqual(parent.consume(grant, self.proposal, self.caller, nonce, 140),
                         'REPLAY')
        self.assertEqual(parent.pending_paid(), 1)

    def test_two_distinct_instances_one_original_db_have_only_one_ready(self):
        primary = self.owner(create=True)
        secondary = self.owner()
        self.addCleanup(primary.close)
        self.addCleanup(secondary.close)
        grant, nonce = self.ticket(primary)
        participants = [primary, secondary]
        with ThreadPoolExecutor(max_workers=12) as executor:
            replies = list(executor.map(
                lambda n: participants[n % 2].consume(
                    grant, self.proposal, self.caller, nonce, 125),
                range(32),
            ))
        self.assertEqual(replies.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(replies.count('REPLAY'), 31)
        self.assertEqual(primary.pending_paid(), 1)

    def test_unpaid_offers_consume_no_disk_spend_capacity(self):
        owner = self.owner(create=True)
        self.addCleanup(owner.close)
        grants = [owner.offer(self.proposal, self.caller, 8, 100)
                  for _ in range(256)]
        self.assertEqual(len({grant.token for grant in grants}), 256)
        self.assertEqual(owner.pending_paid(), 0)

    def test_shared_capacity_and_expiry_survive_restart(self):
        original = self.owner(create=True)
        a, na = self.ticket(original)
        b, nb = self.ticket(original)
        c, nc = self.ticket(original)
        self.assertEqual(original.consume(a, self.proposal, self.caller, na, 130),
                         'READY_RESOURCE_ONLY')
        original.close()
        next_owner = self.owner()
        self.addCleanup(next_owner.close)
        self.assertEqual(next_owner.consume(b, self.proposal, self.caller, nb, 140),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(next_owner.consume(c, self.proposal, self.caller, nc, 150),
                         'PAID_CAPACITY_BUSY')
        later, nl = self.ticket(next_owner, now=2100)
        self.assertEqual(next_owner.consume(later, self.proposal, self.caller, nl, 2110),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(next_owner.pending_paid(), 1)

    def test_bad_target_and_mac_do_not_spend(self):
        from dataclasses import replace
        from w2c_receiver_admission import qualifies, ticket
        owner = self.owner(create=True)
        self.addCleanup(owner.close)
        grant, nonce = self.ticket(owner)
        miss = next(n for n in range(256) if not qualifies(ticket(grant,n), 8))
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, miss, 120),
                         'TARGET')
        self.assertEqual(owner.consume(replace(grant, mac=bytes(32)),
                                       self.proposal, self.caller, nonce, 120),
                         'GRANT_MAC')
        self.assertEqual(owner.pending_paid(), 0)
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, nonce, 120),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, nonce, 120),
                         'REPLAY')

    def test_a_paid_ticket_still_rejects_false_w1_without_refund(self):
        import work_oracle as W
        zeros = [0] * W.CELLS
        header = H('w2c-durable-false-W1-header') * 9 + bytes(30)
        self.assertEqual(len(header), 318)
        challenge = H('challenge', header)
        false_proof = (b'PNW1' + W.field_bytes(zeros) * 3
                       + H('durable-false-transcript', challenge))
        proposal = H('w2c-proposal', b'w2c-research-security-v0',
                     header, false_proof)
        owner = self.owner(create=True)
        self.addCleanup(owner.close)
        grant = owner.offer(proposal, self.caller, 8, 100)
        nonce, _ = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(owner.consume(grant, proposal, self.caller, nonce, 130),
                         'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError, '^TRANSCRIPT
        original = self.owner(create=True)
        original.close()
        with self.assertRaisesRegex(ValueError, 'OWNER_CONTEXT'):
            self.owner(epoch=bytes([6])*32)
        with self.assertRaises(FileNotFoundError):
            self.owner(directory=self.directory / 'missing')
        with self.assertRaises(FileExistsError):
            self.owner(create=True)

    def test_local_file_replace_refuses_new_paid_replay(self):
        owner = self.owner(create=True)
        self.addCleanup(owner.close)
        grant, nonce = self.ticket(owner)
        store = self.directory / DB_NAME
        held = self.directory / 'held.sqlite'
        os.rename(store, held)
        store.write_bytes(b'not a valid spent store')
        os.chmod(store, 0o600)
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, nonce, 120),
                         'DURABLE_UNAVAILABLE')

    def test_directory_symlink_and_world_readable_policy_refuse(self):
        first = self.owner(create=True)
        first.close()
        link = self.directory.parent / (self.directory.name + '-link')
        os.symlink(self.directory, link)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(ValueError, 'OWNER_DIRECTORY'):
            self.owner(directory=link)
        os.chmod(self.directory, 0o755)
        self.addCleanup(os.chmod, self.directory, 0o700)
        with self.assertRaisesRegex(ValueError, 'OWNER_DIRECTORY'):
            self.owner()

    def test_sqlite_lock_timeout_refuses_without_entering_w1(self):
        import sqlite3
        owner = self.owner(create=True)
        self.addCleanup(owner.close)
        grant, nonce = self.ticket(owner)
        blocker = sqlite3.connect(
            str(self.directory / DB_NAME), timeout=1, isolation_level=None
        )
        self.addCleanup(blocker.close)
        blocker.execute('BEGIN EXCLUSIVE')
        try:
            self.assertEqual(
                owner.consume(grant, self.proposal, self.caller, nonce, 130),
                'DURABLE_UNAVAILABLE'
            )
        finally:
            blocker.execute('ROLLBACK')
        self.assertEqual(owner.pending_paid(), 0)
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, nonce, 140),
                         'READY_RESOURCE_ONLY')

    def test_reopen_refuses_rollback_clock_and_missing_durable_file(self):
        owner = self.owner(create=True)
        grant, nonce = self.ticket(owner)
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, nonce, 140),
                         'READY_RESOURCE_ONLY')
        owner.close()
        reopened = self.owner()
        self.assertEqual(reopened.consume(grant, self.proposal, self.caller, nonce, 130),
                         'CLOCK_REGRESSION')
        reopened.close()
        # A missing source is never silently bootstrapped as a new old epoch.
        (self.directory / DB_NAME).unlink()
        with self.assertRaises(FileNotFoundError):
            self.owner(create=False)

    def test_copying_database_before_spend_is_not_global_replay_protection(self):
        # This deliberate negative control must CONTINUE to show two READYs.
        # A host can copy the DB, secret and epoch; no local SQLite algorithm
        # can prove unique global custody of those cloned physical owners.
        original = self.owner(create=True)
        grant, nonce = self.ticket(original)
        other_dir = self.directory / 'clone'
        other_dir.mkdir(mode=0o700)
        shutil.copy2(self.directory / DB_NAME, other_dir / DB_NAME)
        clone = self.owner(directory=other_dir)
        self.addCleanup(clone.close)
        self.addCleanup(original.close)
        self.assertEqual(original.consume(grant, self.proposal, self.caller, nonce, 130),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(clone.consume(grant, self.proposal, self.caller, nonce, 130),
                         'READY_RESOURCE_ONLY')


if __name__ == '__main__':
    unittest.main(verbosity=2)
):
            W.verify(challenge, W.task_id(zeros, zeros),
                     bytes([255]) * 32, false_proof)
        self.assertEqual(owner.consume(grant, proposal, self.caller, nonce, 140),
                         'REPLAY')
        self.assertEqual(owner.pending_paid(), 1)

    def test_existing_mismatched_epoch_or_key_fails_closed(self):
        original = self.owner(create=True)
        original.close()
        with self.assertRaisesRegex(ValueError, 'OWNER_CONTEXT'):
            self.owner(epoch=bytes([6])*32)
        with self.assertRaises(FileNotFoundError):
            self.owner(directory=self.directory / 'missing')
        with self.assertRaises(FileExistsError):
            self.owner(create=True)

    def test_local_file_replace_refuses_new_paid_replay(self):
        owner = self.owner(create=True)
        self.addCleanup(owner.close)
        grant, nonce = self.ticket(owner)
        store = self.directory / DB_NAME
        held = self.directory / 'held.sqlite'
        os.rename(store, held)
        store.write_bytes(b'not a valid spent store')
        os.chmod(store, 0o600)
        self.assertEqual(owner.consume(grant, self.proposal, self.caller, nonce, 120),
                         'DURABLE_UNAVAILABLE')

    def test_directory_symlink_and_world_readable_policy_refuse(self):
        first = self.owner(create=True)
        first.close()
        link = self.directory.parent / (self.directory.name + '-link')
        os.symlink(self.directory, link)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(ValueError, 'OWNER_DIRECTORY'):
            self.owner(directory=link)
        os.chmod(self.directory, 0o755)
        self.addCleanup(os.chmod, self.directory, 0o700)
        with self.assertRaisesRegex(ValueError, 'OWNER_DIRECTORY'):
            self.owner()

    def test_copying_database_before_spend_is_not_global_replay_protection(self):
        # This deliberate negative control must CONTINUE to show two READYs.
        # A host can copy the DB, secret and epoch; no local SQLite algorithm
        # can prove unique global custody of those cloned physical owners.
        original = self.owner(create=True)
        grant, nonce = self.ticket(original)
        other_dir = self.directory / 'clone'
        other_dir.mkdir(mode=0o700)
        shutil.copy2(self.directory / DB_NAME, other_dir / DB_NAME)
        clone = self.owner(directory=other_dir)
        self.addCleanup(clone.close)
        self.addCleanup(original.close)
        self.assertEqual(original.consume(grant, self.proposal, self.caller, nonce, 130),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(clone.consume(grant, self.proposal, self.caller, nonce, 130),
                         'READY_RESOURCE_ONLY')


if __name__ == '__main__':
    unittest.main(verbosity=2)
