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

    def test_status_snapshot_blocks_competing_dispatch_until_read_is_complete(self):
        # A competing writer tries to publish DISPATCH_UNKNOWN between the two
        # status SELECTs.  A moving autocommit reader permits that interleave;
        # this read-only snapshot must not report mixed table generations.
        with self.open() as reader, self.open() as writer:
            key = reader.prepare(intent())
            observations = []
            def trace(sql):
                if sql.startswith('SELECT kind,observation FROM q4_outbox_events_v1'):
                    try:
                        writer.dispatch_unknown(key)
                    except sqlite3.OperationalError:
                        observations.append('write_busy')
                    else:
                        observations.append('unexpected_commit')
            reader.db.set_trace_callback(trace)
            try:
                view = reader.status(key)
            finally:
                reader.db.set_trace_callback(None)
            self.assertEqual(observations, ['write_busy'])
            self.assertTrue(view['has_no_durable_dispatch_fence'])
            self.assertFalse(view['dispatch_unknown'])
            self.assertEqual(reader.audit(), 0)
            writer.dispatch_unknown(key)
            self.assertTrue(reader.status(key)['dispatch_unknown'])
            self.assertFalse(reader.status(key)['has_no_durable_dispatch_fence'])
            self.assertEqual(reader.audit(), 1)

    def test_status_reentrant_read_refuses_without_rolling_back_writer(self):
        with self.open() as db:
            key = db.prepare(intent())
            db.db.execute('BEGIN IMMEDIATE')
            try:
                with self.assertRaisesRegex(OutboxError, 'STATUS_REENTRANT'):
                    db.status(key)
                self.assertTrue(db.db.in_transaction)
            finally:
                db.db.execute('ROLLBACK')
            self.assertTrue(db.status(key)['has_no_durable_dispatch_fence'])
            self.assertEqual(db.audit(), 0)

    def test_status_refuses_corrupted_intent_in_same_durable_snapshot(self):
        # An old status implementation could return a misleading diagnostic
        # after a corrupted intent was visible in SQLite.  The entire bounded
        # journal must pass canonical cold-style audit in the *same* snapshot.
        with self.open() as db:
            key = db.prepare(intent())
            db.dispatch_unknown(key)
            good = db.status(key)
            self.assertTrue(good['dispatch_unknown'])
            with sqlite3.connect(self.file) as raw:
                raw.execute('UPDATE q4_outbox_intents_v1 SET wire=? WHERE id=?',
                            (intent().wire() + b'forged', key))
            with self.assertRaisesRegex(OutboxError, 'INTENT_CORRUPT'):
                db.status(key)
            self.assertFalse(db.db.in_transaction)

    def test_status_refuses_tampered_dispatch_event_even_without_reopen(self):
        with self.open() as db:
            key = db.prepare(intent())
            db.dispatch_unknown(key)
            self.assertTrue(db.status(key)['dispatch_unknown'])
            with sqlite3.connect(self.file) as raw:
                raw.execute('UPDATE q4_outbox_events_v1 SET kind=? WHERE ordinal=1',
                            ('OBSERVED_UNAVAILABLE',))
            with self.assertRaisesRegex(OutboxError, 'EVENT_DIGEST'):
                db.status(key)
            self.assertFalse(db.db.in_transaction)
            # Reconcile exact stored identity; never create another dispatch.
            with sqlite3.connect(self.file) as raw:
                raw.execute('UPDATE q4_outbox_events_v1 SET kind=? WHERE ordinal=1',
                            ('DISPATCH_UNKNOWN',))
            self.assertTrue(db.status(key)['dispatch_unknown'])
            with self.assertRaisesRegex(OutboxError, 'NO_REDISPATCH'):
                db.dispatch_unknown(key)

    def test_corrupt_previous_observation_refuses_new_event_before_commit(self):
        with self.open() as db:
            key = db.prepare(intent())
            db.dispatch_unknown(key)
            original = observation('included', 3).wire()
            db.observe(key, observation('included', 3))
            malformed = bytes(8) + original[8:]
            with sqlite3.connect(self.file) as raw:
                raw.execute('UPDATE q4_outbox_events_v1 SET observation=? WHERE ordinal=2',
                            (malformed,))
            # Old code read only the first eight bytes as an integer and
            # could append after invalid prior bytes.
            with self.assertRaisesRegex(OutboxError, 'OBSERVATION_WIRE'):
                db.observe(key, observation('confirmed', 4))
            self.assertFalse(db.db.in_transaction)
            with sqlite3.connect(self.file) as raw:
                self.assertEqual(raw.execute(
                    'SELECT COUNT(*) FROM q4_outbox_events_v1').fetchone()[0], 2)
                raw.execute('UPDATE q4_outbox_events_v1 SET observation=? WHERE ordinal=2',
                            (original,))
            db.observe(key, observation('confirmed', 4))
            self.assertEqual(db.audit(), 3)

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


    def test_corrupt_earlier_event_blocks_new_intent_and_observation_before_write(self):
        with self.open() as db:
            key = db.prepare(intent())
            db.dispatch_unknown(key)
            db.observe(key, observation('included', 3))
            with sqlite3.connect(self.file) as raw:
                raw.execute('UPDATE q4_outbox_events_v1 SET kind=? WHERE ordinal=1',
                            ('OBSERVED_CONFIRMED',))
            next_intent = replace(intent(tx=b'Y' * 1187),
                                  operation_id=h(b'another durable operation'))
            # The corrupt event is not the latest one: last-generation checks
            # alone would allow both mutations of an already invalid prefix.
            with self.assertRaisesRegex(OutboxError, 'EVENT_DIGEST'):
                db.observe(key, observation('confirmed', 4))
            with self.assertRaisesRegex(OutboxError, 'EVENT_DIGEST'):
                db.prepare(next_intent)
            self.assertFalse(db.db.in_transaction)
            with sqlite3.connect(self.file) as raw:
                self.assertEqual(raw.execute('SELECT COUNT(*) FROM q4_outbox_events_v1').fetchone()[0], 2)
                self.assertEqual(raw.execute('SELECT COUNT(*) FROM q4_outbox_intents_v1').fetchone()[0], 1)
                raw.execute('UPDATE q4_outbox_events_v1 SET kind=? WHERE ordinal=1',
                            ('DISPATCH_UNKNOWN',))
            self.assertEqual(db.audit(), 2)
            db.observe(key, observation('confirmed', 4))
            other_key = db.prepare(next_intent)
            self.assertNotEqual(other_key, key)
            self.assertEqual(db.audit(), 3)

    def test_corrupt_earlier_intent_blocks_dispatch_and_new_prepare_atomically(self):
        with self.open() as db:
            original = intent()
            key = db.prepare(original)
            with sqlite3.connect(self.file) as raw:
                raw.execute('UPDATE q4_outbox_intents_v1 SET wire=? WHERE id=?',
                            (original.wire() + b'corrupt', key))
            with self.assertRaisesRegex(OutboxError, 'INTENT_CORRUPT'):
                db.dispatch_unknown(key)
            new_intent = replace(intent(tx=b'Z' * 1187),
                                 operation_id=h(b'new independent operation'))
            with self.assertRaisesRegex(OutboxError, 'INTENT_CORRUPT'):
                db.prepare(new_intent)
            self.assertFalse(db.db.in_transaction)
            with sqlite3.connect(self.file) as raw:
                self.assertEqual(raw.execute('SELECT COUNT(*) FROM q4_outbox_events_v1').fetchone()[0], 0)
                self.assertEqual(raw.execute('SELECT COUNT(*) FROM q4_outbox_intents_v1').fetchone()[0], 1)
                raw.execute('UPDATE q4_outbox_intents_v1 SET wire=? WHERE id=?',
                            (original.wire(), key))
            self.assertEqual(db.audit(), 0)
            db.dispatch_unknown(key)
            self.assertEqual(db.audit(), 1)

    def test_local_trigger_cannot_eat_new_intent_and_claim_prepared(self):
        with self.open() as db:
            # Local schema mutation, not remote packet or real source authority.
            db.db.execute(
                'CREATE TRIGGER eat_intent AFTER INSERT ON q4_outbox_intents_v1 '
                'BEGIN DELETE FROM q4_outbox_intents_v1 WHERE id=NEW.id; END'
            )
            with self.assertRaisesRegex(OutboxError, 'INTENT_POSTWRITE'):
                db.prepare(intent())
            self.assertFalse(db.db.in_transaction)
            self.assertEqual(db.audit(), 0)
            self.assertEqual(
                db.db.execute('SELECT COUNT(*) FROM q4_outbox_intents_v1').fetchone()[0], 0
            )
            db.db.execute('DROP TRIGGER eat_intent')
            original = db.prepare(intent())
            self.assertEqual(db.prepare(intent()), original)
            self.assertEqual(db.audit(), 0)

    def test_local_trigger_cannot_eat_dispatch_event_and_claim_fenced(self):
        with self.open() as db:
            original = db.prepare(intent())
            db.db.execute(
                'CREATE TRIGGER eat_event AFTER INSERT ON q4_outbox_events_v1 '
                'BEGIN DELETE FROM q4_outbox_events_v1 WHERE ordinal=NEW.ordinal; END'
            )
            with self.assertRaisesRegex(OutboxError, 'EVENT_POSTWRITE'):
                db.dispatch_unknown(original)
            self.assertFalse(db.db.in_transaction)
            self.assertEqual(db.audit(), 0)
            self.assertTrue(db.status(original)['has_no_durable_dispatch_fence'])
            db.db.execute('DROP TRIGGER eat_event')
            db.dispatch_unknown(original)
            self.assertTrue(db.status(original)['dispatch_unknown'])
            with self.assertRaisesRegex(OutboxError, 'RECONCILE_ORIGINAL_NO_REDISPATCH'):
                db.dispatch_unknown(original)
            self.assertEqual(db.audit(), 1)

    def test_local_trigger_corruption_of_observation_is_rolled_back(self):
        with self.open() as db:
            original = db.prepare(intent())
            db.dispatch_unknown(original)
            db.db.execute(
                'CREATE TRIGGER corrupt_observation AFTER INSERT ON q4_outbox_events_v1 '
                "WHEN NEW.kind LIKE 'OBSERVED_%' BEGIN "
                "UPDATE q4_outbox_events_v1 SET observation=X'00' "
                'WHERE ordinal=NEW.ordinal; END'
            )
            with self.assertRaisesRegex(OutboxError, 'EVENT_DIGEST'):
                db.observe(original, observation('included', 2))
            self.assertFalse(db.db.in_transaction)
            self.assertEqual(db.audit(), 1)
            self.assertEqual(db.status(original)['observations'], 0)
            db.db.execute('DROP TRIGGER corrupt_observation')
            db.observe(original, observation('included', 2))
            self.assertEqual(db.status(original)['observations'], 1)
            self.assertEqual(db.audit(), 2)

if __name__ == '__main__': unittest.main()
