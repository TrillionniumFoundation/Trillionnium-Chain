"""Deterministic adversarial full-DB rollback cases; external witness is separate."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pq_external_rollback_oracle import (Checkpoint, ExternalMonotonicWitness,
                                         MAX_SEQUENCE, Refuse, authorize_restore)

NETWORK = b'n' * 32
KEY = b'k' * 64   # Test-only isolated reference key, never a deployment key.
CHALLENGE = b'c' * 32
NEXT_CHALLENGE = b'd' * 32


def cp(sequence, state=1, journal=1, network=NETWORK):
    return Checkpoint(network, sequence, bytes([state]) * 32, bytes([journal]) * 32)


class TestExternalRollback(unittest.TestCase):
    def setUp(self):
        self.witness = ExternalMonotonicWitness(NETWORK, KEY)
        self.first = cp(1)
        self.witness.publish(self.first)

    def accepted(self, checkpoint, challenge=CHALLENGE):
        authorize_restore(checkpoint, challenge=challenge,
                          fresh_witness_reply=self.witness.respond_to_fresh_challenge(challenge),
                          pinned_external_verification_key=KEY)

    def rejected(self, checkpoint, reply, challenge=CHALLENGE):
        with self.assertRaises(Refuse):
            authorize_restore(checkpoint, challenge=challenge,
                              fresh_witness_reply=reply,
                              pinned_external_verification_key=KEY)

    def test_fresh_and_idempotent_witness(self):
        self.witness.publish(self.first)
        self.accepted(self.first)

    def test_self_consistent_old_database_nonce_and_journal_cannot_hide_rollback(self):
        saved_entire_old_db = self.first
        latest = cp(2, state=2, journal=2)
        self.witness.publish(latest)
        # The local snapshot is internally consistent, including its journal.
        self.rejected(saved_entire_old_db,
                      self.witness.respond_to_fresh_challenge(CHALLENGE))
        self.accepted(latest)

    def test_stale_receipt_is_not_a_live_external_query(self):
        old_reply = self.witness.respond_to_fresh_challenge(CHALLENGE)
        self.witness.publish(cp(2, state=2, journal=2))
        self.rejected(self.first, old_reply, NEXT_CHALLENGE)
        self.accepted(cp(2, state=2, journal=2), NEXT_CHALLENGE)

    def test_missing_witness_fails_closed(self):
        self.rejected(self.first, None)
        self.rejected(self.first, b'')

    def test_tampered_tag_and_wrong_verifier_key_fail(self):
        original = self.witness.respond_to_fresh_challenge(CHALLENGE)
        edited = bytearray(original)
        edited[50] ^= 1
        self.rejected(self.first, bytes(edited))
        with self.assertRaises(Refuse):
            authorize_restore(self.first, challenge=CHALLENGE,
                              fresh_witness_reply=original,
                              pinned_external_verification_key=b'x'*64)

    def test_wrong_network_and_journal_or_state_root_fail(self):
        reply = self.witness.respond_to_fresh_challenge(CHALLENGE)
        for altered in (cp(1, network=b'z'*32), cp(1, journal=9), cp(1, state=9)):
            with self.subTest(altered=altered):
                self.rejected(altered, reply)

    def test_witness_rejects_rollback_fork_skip_and_bad_genesis(self):
        for altered in (cp(1, state=2), cp(3, state=3), cp(0),
                        cp(-1), cp(MAX_SEQUENCE + 1)):
            with self.subTest(sequence=altered.sequence):
                with self.assertRaises(Refuse):
                    self.witness.publish(altered)
        self.accepted(self.first)

    def test_legitimate_reorganization_uses_new_external_sequence(self):
        # Chain tip may move backwards; external observation order must not.
        second = cp(2, state=2, journal=2)
        third = cp(3, state=3, journal=3)  # reorg tip could be at smaller height
        self.witness.publish(second)
        self.witness.publish(third)
        self.accepted(third)
        self.rejected(second, self.witness.respond_to_fresh_challenge(CHALLENGE))

    def test_ahead_of_witness_or_missing_publication_is_a_hold(self):
        self.rejected(cp(2, state=2),
                      self.witness.respond_to_fresh_challenge(CHALLENGE))

    def test_version_trailing_bytes_and_wrong_nonce_fail(self):
        reply = self.witness.respond_to_fresh_challenge(CHALLENGE)
        self.rejected(self.first, reply + b'\x00')
        self.rejected(self.first, reply, NEXT_CHALLENGE)
        self.rejected(self.first, b'PQR2' + reply[4:])

    def test_bool_sequence_and_bad_roots_cannot_be_checkpoints(self):
        for bad in (cp(True), cp(1, state=0), cp(1, journal=0)):
            with self.subTest(bad=bad):
                self.rejected(bad, self.witness.respond_to_fresh_challenge(CHALLENGE))

    def test_witness_head_and_key_outside_db_are_required(self):
        new_witness = ExternalMonotonicWitness(NETWORK, KEY)
        with self.assertRaises(Refuse):
            new_witness.respond_to_fresh_challenge(CHALLENGE)
        with self.assertRaises(Refuse):
            ExternalMonotonicWitness(NETWORK, b'short')
        with self.assertRaises(Refuse):
            self.witness.respond_to_fresh_challenge(bytes(32))


if __name__ == '__main__':
    unittest.main()
