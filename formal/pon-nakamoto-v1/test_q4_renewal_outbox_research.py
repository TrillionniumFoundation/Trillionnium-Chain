"""Fault/reorg/unknown-outcome controls: no source keys, real node, or network dispatch."""
from __future__ import annotations
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from q4_renewal_outbox_research import (RenewalOutbox, RenewalIntent, ChainObservation,
                                         OutboxError, UnknownEffect, transaction_id)

def h(x: bytes) -> bytes: return hashlib.sha256(x).digest()
N,P,G = h(b'network'),h(b'parameters'),h(b'genesis')
TX = b'T' * 1187  # deliberately NOT an authenticated Q4/PNX1 transaction

def intent(tx: bytes=TX, seq: int=1):
    return RenewalIntent(h(b'operation'), N,P,G,h(b'parent'),h(b'old'),h(b'next'),
                         17,900,1000,seq,seq,tx)

def observation(kind: str='included',generation: int=1,seed: bytes=b'one'):
    return ChainObservation(generation,h(b'tip'+seed),950,kind,
                            h(b'included') if kind in ('included','confirmed') else None,
                            h(b'external-receipt'+seed))

class RenewalOutboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.file = Path(self.tmp.name)/'q4.sqlite'
    def tearDown(self): self.tmp.cleanup()
    def open(self,**kw): return RenewalOutbox(self.file,N,P,G,**kw)

    def test_prepared_is_not_dispatched_ownership_or_signing(self):
        with self.open() as db:
            key=db.prepare(intent())
            self.assertEqual(db.prepare(intent()),key)
            self.assertTrue(db.status(key)['has_no_durable_dispatch_fence'])
            self.assertFalse(db.status(key)['dispatch_unknown'])
            self.assertEqual(db.audit(),0)
            with self.assertRaisesRegex(OutboxError,'OBSERVATION_BEFORE_DISPATCH'):
                db.observe(key,observation())

    def test_unknown_ack_reorg_and_reopen_never_grant_redispatch(self):
        with self.open() as db:
            key=db.prepare(intent())
            db.dispatch_unknown(key)
            db.observe(key,observation('included',2))
            db.observe(key,observation('confirmed',3))
            db.observe(key,observation('reorged',4))
            db.observe(key,observation('unavailable',5))
            with self.assertRaisesRegex(OutboxError,'NO_REDISPATCH'):
                db.dispatch_unknown(key)
            self.assertEqual(db.status(key)['last_untrusted_observation'],'unavailable')
        with self.open() as db:
            self.assertEqual(db.audit(),5)
            self.assertEqual(db.prepare(intent()),key)
            with self.assertRaisesRegex(OutboxError,'NO_REDISPATCH'):
                db.dispatch_unknown(key)
            db.observe(key,observation('expired',6))
            self.assertTrue(db.status(key)['dispatch_unknown'])
            self.assertEqual(db.status(key)['last_untrusted_observation'],'expired')

    def test_unsafe_new_nonce_or_operation_for_same_packet_is_refused(self):
        with self.open() as db:
            db.prepare(intent())
            with self.assertRaisesRegex(OutboxError,'SIGNED_PACKET_RENAMED'):
                db.prepare(replace(intent(),operation_id=h(b'new operation')))
            with self.assertRaisesRegex(OutboxError,'SIGNED_PACKET_RENAMED'):
                db.prepare(replace(intent(),requester_sequence=2))
            with self.assertRaisesRegex(OutboxError,'SIGNED_PACKET_RENAMED'):
                db.prepare(replace(intent(),original_parent=h(b'other branch')))

    def test_same_operation_modified_packet_cannot_be_resubmitted(self):
        with self.open() as db:
            db.prepare(intent())
            with self.assertRaisesRegex(OutboxError,'SIGNED_PACKET_RENAMED'):
                db.prepare(intent(tx=b'X'*1187))
            alternate=replace(intent(tx=b'X'*1187),operation_id=h(b'other operation'))
            self.assertNotEqual(db.prepare(alternate),intent().digest())

    def test_precommit_fault_does_not_claim_intent_or_dispatch(self):
        with self.open() as db:
            with self.assertRaisesRegex(OutboxError,'INJECTED_BEFORE_COMMIT'):
                db.prepare(intent(),fail_at='before_commit')
            key=db.prepare(intent())
            with self.assertRaisesRegex(OutboxError,'INJECTED_BEFORE_COMMIT'):
                db.dispatch_unknown(key,fail_at='before_commit')
            self.assertEqual(db.audit(),0)
            self.assertTrue(db.status(key)['has_no_durable_dispatch_fence'])
            db.dispatch_unknown(key)

    def test_postcommit_unknown_cannot_create_new_identity_or_retry(self):
        with self.open() as db:
            with self.assertRaises(UnknownEffect):
                db.prepare(intent(),fail_at='after_commit')
            key=db.prepare(intent())
            with self.assertRaises(UnknownEffect):
                db.dispatch_unknown(key,fail_at='after_commit')
            with self.assertRaisesRegex(OutboxError,'NO_REDISPATCH'):
                db.dispatch_unknown(key)
        with self.open() as db:
            self.assertEqual(db.audit(),1)
            self.assertTrue(db.status(key)['dispatch_unknown'])

    def test_faulted_observation_preserves_previous_complete_prefix(self):
        with self.open() as db:
            key=db.prepare(intent());db.dispatch_unknown(key)
            with self.assertRaisesRegex(OutboxError,'INJECTED_BEFORE_COMMIT'):
                db.observe(key,observation(),fail_at='before_commit')
            self.assertEqual(db.audit(),1)
            with self.assertRaises(UnknownEffect):
                db.observe(key,observation(),fail_at='after_commit')
            self.assertEqual(db.audit(),2)
            self.assertEqual(db.status(key)['last_untrusted_observation'],'included')

    def test_generation_and_membership_are_bounded(self):
        with self.open() as db:
            key=db.prepare(intent());db.dispatch_unknown(key)
            db.observe(key,observation(generation=12))
            with self.assertRaisesRegex(OutboxError,'OBSERVATION_REGRESSION'):
                db.observe(key,observation(generation=11))
            with self.assertRaisesRegex(OutboxError,'OBSERVATION_MEMBERSHIP'):
                db.observe(key,replace(observation('confirmed'),included_block=None))
            with self.assertRaisesRegex(OutboxError,'OBSERVATION_MEMBERSHIP'):
                db.observe(key,replace(observation('expired'),included_block=h(b'block')))
            self.assertEqual(db.audit(),2)

    def test_mutating_historical_observation_fails_cold_audit(self):
        with self.open() as db:
            key=db.prepare(intent());db.dispatch_unknown(key)
            db.observe(key,observation())
        with sqlite3.connect(self.file) as raw:
            raw.execute("UPDATE q4_outbox_events_v1 SET observation=? WHERE ordinal=2",(b'forged',))
        with self.assertRaisesRegex(OutboxError,'EVENT_DIGEST'):
            self.open()

    def test_foreign_schema_context_symlink_and_oversized_inputs_refuse(self):
        with self.open() as db:
            db.prepare(intent())
        with self.assertRaisesRegex(OutboxError,'CONTEXT_MISMATCH'):
            RenewalOutbox(self.file,h(b'foreign'),P,G)
        with self.open() as db:
            with self.assertRaisesRegex(OutboxError,'SIGNED_PACKET_LENGTH'):
                db.prepare(intent(tx=b'bad'))
            with self.assertRaisesRegex(OutboxError,'LEASE_WINDOW_OR_SEQUENCE'):
                db.prepare(replace(intent(),signed_from=1001))
        link=Path(self.tmp.name)/'alias.sqlite'
        link.symlink_to(self.file)
        with self.assertRaisesRegex(OutboxError,'DATABASE_PATH'):
            RenewalOutbox(link,N,P,G)

    def test_record_and_event_limits_fail_closed(self):
        with self.open(max_intents=1,max_events=1) as db:
            key=db.prepare(intent())
            with self.assertRaisesRegex(OutboxError,'INTENT_BUDGET'):
                db.prepare(replace(intent(tx=b'Z'*1187),operation_id=h(b'another op')))
            db.dispatch_unknown(key)
            with self.assertRaisesRegex(OutboxError,'EVENT_BUDGET'):
                db.observe(key,observation())
            self.assertEqual(db.audit(),1)

    def test_second_sqlite_owner_cannot_duplicate_dispatch_fence(self):
        with self.open() as first, self.open() as second:
            key = first.prepare(intent())
            first.dispatch_unknown(key)
            with self.assertRaisesRegex(OutboxError,'NO_REDISPATCH'):
                second.dispatch_unknown(key)
            self.assertEqual(second.audit(),1)
            second.observe(key,observation('included',2))
            self.assertEqual(first.audit(),2)

    def test_noncanonical_types_and_context_do_not_mutate_history(self):
        with self.open() as db:
            key = db.prepare(intent())
            cases = [
                replace(intent(), original_generation=True),
                replace(intent(), signed_from=-1),
                replace(intent(), requester_sequence=1 << 64),
                replace(intent(), network=h(b'other chain')),
                replace(intent(), old_lease_digest=intent().next_lease_digest),
                replace(intent(), signed_transaction=bytearray(TX)),
            ]
            for case in cases:
                with self.assertRaises(OutboxError):
                    db.prepare(case)
            self.assertEqual(db.audit(),0)
            self.assertFalse(db.status(key)['dispatch_unknown'])

    def test_transaction_id_matches_explicit_pon_hash_domain(self):
        raw=TX
        manual=h(b'TRNM-PON1\0'+(5).to_bytes(2,'little')+b'tx-id'
                 +len(raw).to_bytes(4,'little')+raw)
        self.assertEqual(transaction_id(raw),manual)
        self.assertNotEqual(transaction_id(raw),h(raw))


    def test_raw_observation_append_cannot_bypass_full_canonical_grammar(self):
        # Directly call the internal append boundary to prove that even a
        # future owner bypassing observe() cannot journal unparseable facts.
        with self.open() as db:
            key = db.prepare(intent())
            db.dispatch_unknown(key)
            good = observation().wire()
            variants = []
            for start, length in ((0, 8), (8, 32), (81, 32)):
                bad = bytearray(good)
                bad[start:start+length] = bytes(length)
                variants.append(bytes(bad))
            missing = bytearray(good)
            missing[49:81] = bytes(32)
            variants.append(bytes(missing))
            wrong_tag = bytearray(good)
            wrong_tag[48] = 5
            variants.append(bytes(wrong_tag))
            variants += [good[:-1], bytearray(good)]
            for malformed in variants:
                with self.subTest(malformed=str(malformed[:9])):
                    with self.assertRaises(OutboxError):
                        db._event(key, 'OBSERVED_INCLUDED', malformed)
            # A future internal caller must not insert a DISPATCH fence for an
            # unknown/relabelled intent even when it bypasses the public API.
            with self.assertRaisesRegex(OutboxError, 'UNKNOWN_INTENT'):
                db._event(h(b'nonexistent-owner'), 'DISPATCH_UNKNOWN')
            with self.assertRaisesRegex(OutboxError, 'UNKNOWN_INTENT'):
                db._event(h(b'nonexistent-owner'), 'OBSERVED_INCLUDED', good)
            self.assertEqual(db.audit(), 1)
            db.observe(key, observation())
            self.assertEqual(db.audit(), 2)

    def test_cold_replay_rejects_rehashed_semantically_invalid_observations(self):
        # This is a parser/grammar boundary, not an adversarial hash-chain
        # security claim. Recompute the local row checksum deliberately to
        # ensure the audit does not accept malformed fields on checksum alone.
        from q4_renewal_outbox_research import EVENT_DOMAIN
        with self.open() as db:
            key = db.prepare(intent())
            db.dispatch_unknown(key)
            db.observe(key, observation())
        with sqlite3.connect(self.file) as raw:
            n, ident, kind, original, prev, previous_digest = raw.execute(
                'SELECT ordinal,intent_id,kind,observation,prev,digest '
                'FROM q4_outbox_events_v1 WHERE ordinal=2'
            ).fetchone()
            for start, size in ((0,8),(8,32),(49,32),(81,32)):
                malformed = bytearray(original)
                malformed[start:start+size] = bytes(size)
                bad = bytes(malformed)
                digest = h(EVENT_DOMAIN + n.to_bytes(8,'big') + ident
                           + kind.encode('ascii') + bad + prev)
                raw.execute('UPDATE q4_outbox_events_v1 '
                            'SET observation=?,digest=? WHERE ordinal=2',
                            (bad, digest))
                raw.commit()
                with self.subTest(start=start):
                    with self.assertRaisesRegex(OutboxError, 'OBSERVATION_'):
                        self.open()
                raw.execute('UPDATE q4_outbox_events_v1 '
                            'SET observation=?,digest=? WHERE ordinal=2',
                            (original, previous_digest))
                raw.commit()
        with self.open() as db:
            self.assertEqual(db.audit(), 2)
            self.assertTrue(db.status(key)['dispatch_unknown'])

    def test_audit_uses_one_snapshot_and_fences_an_original_writer(self):
        # The original journal permits a separate writer.  Once the reader
        # pins its first SQLite page it must not mix newly committed events
        # and intents in a moving second query.  No authority is inferred.
        another = replace(intent(), operation_id=h(b'fresh op'),
                          signed_transaction=b'R' * 1187)
        with self.open() as reader, self.open() as writer:
            reader.prepare(intent())
            original = reader._audit_snapshot
            attempted = []
            def concurrent_writer():
                # Force a real read snapshot before the writer attempts commit.
                self.assertEqual(reader.db.execute(
                    'SELECT COUNT(*) FROM q4_outbox_intents_v1'
                ).fetchone()[0], 1)
                with self.assertRaises(sqlite3.OperationalError):
                    writer.prepare(another)
                attempted.append(True)
                return original()
            reader._audit_snapshot = concurrent_writer
            self.assertEqual(reader.audit(), 0)
            self.assertEqual(attempted, [True])
            reader._audit_snapshot = original
            # The read lock was released even after the other owner's Busy.
            writer.prepare(another)
            self.assertEqual(reader.audit(), 0)

    def test_nested_audit_refuses_without_rolling_back_writer_intent(self):
        with self.open() as db:
            db.db.execute('BEGIN IMMEDIATE')
            try:
                with self.assertRaisesRegex(OutboxError, 'AUDIT_REENTRANT'):
                    db.audit()
                self.assertTrue(db.db.in_transaction)
            finally:
                db.db.execute('ROLLBACK')
            self.assertEqual(db.audit(), 0)


class OutboxStatusSnapshotTests(unittest.TestCase):
    setUp = RenewalOutboxTests.setUp
    tearDown = RenewalOutboxTests.tearDown
    open = RenewalOutboxTests.open
    """Status is a checked local projection, not independent chain authority."""

    def test_status_rejects_corruption_committed_after_open(self):
        with self.open() as db:
            key = db.prepare(intent())
            db.dispatch_unknown(key)
            db.observe(key, observation())
            self.assertEqual(db.status(key)['observations'], 1)
            # An external writer damages a stored row AFTER the owner opened.
            with sqlite3.connect(self.file) as raw:
                raw.execute(
                    'UPDATE q4_outbox_events_v1 SET observation=? WHERE ordinal=2',
                    (b'forged',),
                )
            with self.assertRaisesRegex(OutboxError, 'EVENT_DIGEST'):
                db.status(key)
            self.assertFalse(db.db.in_transaction)

    def test_status_snapshot_pins_writer_until_finished(self):
        with self.open() as reader, self.open() as writer:
            key = reader.prepare(intent())
            reader.dispatch_unknown(key)
            another = writer.prepare(replace(intent(tx=b'Z'*1187), operation_id=h(b'another-operation')))
            original_audit = reader._audit_snapshot

            def pinned_audit():
                value = original_audit()
                # Reader already began its snapshot. A second owner cannot
                # commit a new event between auditing and projecting status.
                with self.assertRaises(sqlite3.OperationalError):
                    writer.dispatch_unknown(another)
                return value

            reader._audit_snapshot = pinned_audit
            self.assertTrue(reader.status(key)['dispatch_unknown'])
            self.assertFalse(reader.db.in_transaction)
            writer.dispatch_unknown(another)
            self.assertEqual(reader.audit(), 2)

    def test_status_fails_closed_on_reentrant_transaction(self):
        with self.open() as db:
            key = db.prepare(intent())
            db.db.execute('BEGIN')
            try:
                with self.assertRaisesRegex(OutboxError, 'STATUS_REENTRANT'):
                    db.status(key)
                self.assertTrue(db.db.in_transaction)
            finally:
                db.db.execute('ROLLBACK')
            self.assertTrue(db.status(key)['has_no_durable_dispatch_fence'])

if __name__ == '__main__': unittest.main()
