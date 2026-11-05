"""Actual old+new signatures and concurrency-safe offline migration reference."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pq_envelope import Reject, public_key_id
from pq_account_migration import (MigrationStatement, SignedMigration,
    OfflineMigrationJournal, make_signed_migration, verify_migration)


class DualPossessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="trnm-pq-migrate-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.new_private, cls.new_public = cls.directory / "pq.priv", cls.directory / "pq.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", str(cls.new_private)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["openssl", "pkey", "-in", str(cls.new_private), "-pubout", "-out", str(cls.new_public)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.pem = cls.new_public.read_bytes()
        cls.old = Ed25519PrivateKey.generate()
        cls.old_public = cls.old.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        cls.network, cls.head = bytes(range(32)), bytes(range(32, 64))
        cls.statement = MigrationStatement(cls.network, cls.old_public, public_key_id(cls.pem),
                                           cls.head, 17, 2, 6000)
        cls.proof = make_signed_migration(cls.statement, old_signer=cls.old,
                                          new_pq_private=cls.new_private)

    def args(self, **override):
        params = dict(new_public_pem=self.pem, expected_network=self.network,
                      expected_old_pub=self.old_public, expected_authority_head=self.head,
                      expected_generation=17, expected_sequence=2, now=5900)
        params.update(override)
        return params

    def test_two_real_signers_and_identical_receipt(self):
        r1 = verify_migration(self.proof, **self.args())
        self.assertEqual(len(r1), 48)
        r2 = make_signed_migration(self.statement, old_signer=self.old,
                                   new_pq_private=self.new_private)
        self.assertEqual(verify_migration(r2, **self.args()), r1)

    def test_reject_old_signature_pq_signature_and_wrong_key(self):
        wrong_old = bytearray(self.proof.old_signature)
        wrong_old[-1] ^= 1
        with self.assertRaises(Reject):
            verify_migration(replace(self.proof, old_signature=bytes(wrong_old)), **self.args())
        wrong_pq = bytearray(self.proof.new_pq_frame)
        wrong_pq[-1] ^= 1
        with self.assertRaises(Reject):
            verify_migration(replace(self.proof, new_pq_frame=bytes(wrong_pq)), **self.args())
        with self.assertRaises(Reject):
            verify_migration(self.proof, **self.args(expected_old_pub=bytes(32)))

    def test_reject_wrong_network_owner_head_generation_sequence_expiry(self):
        for mutated in (
            {"expected_network": bytes(32)}, {"expected_authority_head": bytes(32)},
            {"expected_generation": 16}, {"expected_sequence": 3}, {"now": 6001},
            {"expected_generation": True},
        ):
            with self.subTest(mutated=mutated), self.assertRaises(Reject):
                verify_migration(self.proof, **self.args(**mutated))

    def test_cannot_reinterpret_legitimate_signatures_for_new_head(self):
        changed = replace(self.statement, authorized_head=bytes([0xFA] * 32))
        with self.assertRaises(Reject):
            verify_migration(replace(self.proof, statement=changed),
                             **self.args(expected_authority_head=changed.authorized_head))

    def test_local_acked_retry_cold_reopen_and_conflicting_replacement(self):
        with tempfile.TemporaryDirectory(prefix="trnm-pq-journal-") as d:
            filename = Path(d) / "owned.sqlite"
            first = OfflineMigrationJournal(filename)
            state, receipt = first.consume(self.proof, **self.args())
            self.assertEqual(state, "FIRST_RECORD")
            state, other_receipt = first.consume(self.proof, **self.args())
            self.assertEqual((state, other_receipt), ("ALREADY_RECORDED", receipt))
            first.close()
            reopened = OfflineMigrationJournal(filename)
            state, other_receipt = reopened.consume(self.proof, **self.args())
            self.assertEqual((state, other_receipt), ("ALREADY_RECORDED", receipt))
            # Same old account, different signed operation: conflict despite valid signatures.
            new_stmt = replace(self.statement, operation_sequence=3)
            different = make_signed_migration(new_stmt, old_signer=self.old,
                                               new_pq_private=self.new_private)
            with self.assertRaises(Reject):
                reopened.consume(different, **self.args(expected_sequence=3))
            reopened.close()

    def test_same_new_pq_key_cannot_be_assigned_to_two_old_accounts(self):
        with tempfile.TemporaryDirectory(prefix="trnm-pq-unique-") as d:
            writer = OfflineMigrationJournal(Path(d) / "migrations.sqlite")
            writer.consume(self.proof, **self.args())
            other_signer = Ed25519PrivateKey.generate()
            other_public = other_signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            second = replace(self.statement, old_ed25519_pub=other_public)
            new_proof = make_signed_migration(second, old_signer=other_signer,
                                              new_pq_private=self.new_private)
            with self.assertRaises(Reject):
                writer.consume(new_proof, **self.args(expected_old_pub=other_public))
            writer.close()

    def test_multiple_real_sqlite_writers_one_first_commit(self):
        with tempfile.TemporaryDirectory(prefix="trnm-pq-concurrency-") as d:
            path = Path(d) / "owned.sqlite"
            # Owned single-writer schema/WAL bootstrap precedes concurrent users.
            bootstrap = OfflineMigrationJournal(path)
            bootstrap.close()
            def attempt(_):
                writer = OfflineMigrationJournal(path)
                try:
                    return writer.consume(self.proof, **self.args())[0]
                finally:
                    writer.close()
            with ThreadPoolExecutor(max_workers=8) as pool:
                outcomes = list(pool.map(attempt, range(8)))
            self.assertEqual(outcomes.count("FIRST_RECORD"), 1)
            self.assertEqual(outcomes.count("ALREADY_RECORDED"), 7)


if __name__ == "__main__":
    unittest.main()
