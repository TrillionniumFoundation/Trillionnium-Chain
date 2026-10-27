"""Fault/reorg/unknown-outcome controls: no source keys, real node, or network dispatch."""
from __future__ import annotations
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from q4_renewal_outbox_research import (RenewalOutbox, RenewalIntent, ChainObservation,
                                         OutboxError, UnknownEffect, transaction_id, EVENT_DOMAIN)

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

    def test_weakened_same_name_table_refuses_hot_and_cold_dispatch(self):
        # Keep all row contents, original names and indexes; weaken only DDL.
        with self.open() as owner:
            key = owner.prepare(intent())
            with sqlite3.connect(self.file) as external:
                external.execute('ALTER TABLE q4_outbox_meta_v1 RENAME TO old_meta_v1')
                external.execute('CREATE TABLE q4_outbox_meta_v1 (key TEXT, value BLOB)')
                external.execute('INSERT INTO q4_outbox_meta_v1 SELECT key,value FROM old_meta_v1')
                external.execute('DROP TABLE old_meta_v1')
            with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
                owner.dispatch_unknown(key)
            with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
                owner.status(key)
            with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
                owner.prepare(intent(tx=b'B' * 1187))
            self.assertFalse(owner.db.in_transaction)
            with sqlite3.connect(self.file) as external:
                self.assertEqual(external.execute(
                    'SELECT COUNT(*) FROM q4_outbox_events_v1').fetchone()[0], 0)
        with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
            self.open()

    def test_sqlite_ephemeral_targets_refused_before_outbox_open(self):
        for target in (':memory:', 'file::memory:?cache=shared'):
            with self.subTest(target=target):
                with self.assertRaisesRegex(OutboxError, 'DATABASE_PATH'):
                    RenewalOutbox(Path(target), N, P, G)

    def test_untrusted_sql_triggers_and_missing_dispatch_index_refuse(self):
        # Neither a hostile trigger nor a removed uniqueness guard can be
        # trusted even when every original table and row digest is unchanged.
        with self.open() as db:
            key = db.prepare(intent())
        with sqlite3.connect(self.file) as raw:
            raw.execute(
                "CREATE TRIGGER rewrite_dispatch AFTER INSERT ON q4_outbox_events_v1 "
                "BEGIN DELETE FROM q4_outbox_events_v1 WHERE ordinal=NEW.ordinal; END"
            )
        with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
            self.open()
        with sqlite3.connect(self.file) as raw:
            raw.execute("DROP TRIGGER rewrite_dispatch")
            raw.execute("DROP INDEX q4_outbox_once_v1")
        with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
            self.open()
        with sqlite3.connect(self.file) as raw:
            raw.execute(
                "CREATE UNIQUE INDEX q4_outbox_once_v1 "
                "ON q4_outbox_events_v1(intent_id) "
                "WHERE kind='DISPATCH_UNKNOWN'"
            )
        with self.open() as db:
            self.assertTrue(db.status(key)['has_no_durable_dispatch_fence'])
            db.dispatch_unknown(key)
            self.assertEqual(db.audit(), 1)

    def test_live_schema_trigger_injection_is_fenced_before_event_write(self):
        with self.open() as db:
            key = db.prepare(intent())
            with sqlite3.connect(self.file) as raw:
                raw.execute(
                    "CREATE TRIGGER rewrite_dispatch AFTER INSERT ON q4_outbox_events_v1 "
                    "BEGIN DELETE FROM q4_outbox_events_v1 WHERE ordinal=NEW.ordinal; END"
                )
            with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
                db.dispatch_unknown(key)
            self.assertEqual(
                db.db.execute('SELECT COUNT(*) FROM q4_outbox_events_v1').fetchone()[0],
                0,
            )
            with self.assertRaisesRegex(OutboxError, 'SCHEMA_DRIFT'):
                db.status(key)

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

    def test_conflicting_signed_successors_share_one_old_lease_dispatch_fence(self):
        first = intent()
        alternate = replace(first, operation_id=h(b'other signed operation'),
                            next_lease_digest=h(b'other successor lease'),
                            signed_transaction=b'B' * 1187)
        independent = replace(first, operation_id=h(b'distinct old lease operation'),
                              old_lease_digest=h(b'distinct old lease'),
                              next_lease_digest=h(b'distinct successor lease'),
                              signed_transaction=b'C' * 1187)
        with self.open() as db:
            a, b, c = (db.prepare(x) for x in (first, alternate, independent))
            self.assertNotEqual(a, b)
            db.dispatch_unknown(a)
            db.observe(a, observation('reorged', 2))
            with self.assertRaisesRegex(OutboxError, 'LEASE_DISPATCH_CONFLICT'):
                db.dispatch_unknown(b)
            self.assertFalse(db.status(b)['has_no_durable_dispatch_fence'])
            self.assertTrue(db.status(b)['old_lease_dispatch_fenced'])
            db.dispatch_unknown(c)
            self.assertEqual(db.audit(), 3)
        with self.open() as reopened:
            with self.assertRaisesRegex(OutboxError, 'LEASE_DISPATCH_CONFLICT'):
                reopened.dispatch_unknown(b)
            self.assertEqual(reopened.audit(), 3)

    def test_competing_writers_cannot_dispatch_two_successors_of_same_old_lease(self):
        first = intent()
        second = replace(first, operation_id=h(b'competing writer operation'),
                         signed_transaction=b'D' * 1187)
        with self.open() as left, self.open() as right:
            a = left.prepare(first)
            b = right.prepare(second)
            right.dispatch_unknown(b)
            with self.assertRaisesRegex(OutboxError, 'LEASE_DISPATCH_CONFLICT'):
                left.dispatch_unknown(a)
            self.assertEqual(left.audit(), 1)
            self.assertFalse(left.status(a)['dispatch_unknown'])
            self.assertTrue(right.status(b)['dispatch_unknown'])

    def test_rehashed_second_old_lease_dispatch_refused_on_cold_replay(self):
        first = intent()
        second = replace(first, operation_id=h(b'mutated replayer operation'),
                         next_lease_digest=h(b'replayed replacement'),
                         signed_transaction=b'E' * 1187)
        with self.open() as owner:
            a = owner.prepare(first)
            b = owner.prepare(second)
            owner.dispatch_unknown(a)
            self.assertEqual(owner.audit(), 1)
        # Syntactically valid hash-chained rows alone do not make this safe.
        with sqlite3.connect(self.file) as raw:
            previous = raw.execute(
                'SELECT digest FROM q4_outbox_events_v1 ORDER BY ordinal DESC LIMIT 1'
            ).fetchone()[0]
            ordinal = 2
            digest = hashlib.sha256(
                EVENT_DOMAIN + ordinal.to_bytes(8, 'big') + b
                + b'DISPATCH_UNKNOWN' + previous
            ).digest()
            raw.execute(
                'INSERT INTO q4_outbox_events_v1 VALUES (?,?,?,?,?,?)',
                (ordinal, b, 'DISPATCH_UNKNOWN', b'', previous, digest)
            )
        with self.assertRaisesRegex(OutboxError, 'LEASE_DISPATCH_CONFLICT'):
            self.open()


    def test_status_reads_other_operation_old_lease_fence_from_one_snapshot(self):
        first = intent()
        alternate = replace(first, operation_id=h(b'alias-status-operation'),
                            signed_transaction=b'F' * 1187)
        independent = replace(first, operation_id=h(b'independent-status-operation'),
                              old_lease_digest=h(b'independent-status-old-lease'),
                              signed_transaction=b'G' * 1187)
        with self.open() as a, self.open() as b:
            original = a.prepare(first)
            alias = b.prepare(alternate)
            separate = b.prepare(independent)
            self.assertTrue(b.status(alias)['has_no_durable_dispatch_fence'])
            self.assertFalse(b.status(alias)['old_lease_dispatch_fenced'])
            a.dispatch_unknown(original)
            report = b.status(alias)
            self.assertFalse(report['dispatch_unknown'])
            self.assertFalse(report['has_no_durable_dispatch_fence'])
            self.assertTrue(report['old_lease_dispatch_fenced'])
            self.assertEqual(report['observations'], 0)
            self.assertFalse(report['last_untrusted_observation'])
            self.assertTrue(b.status(separate)['has_no_durable_dispatch_fence'])
            self.assertFalse(b.status(separate)['old_lease_dispatch_fenced'])
            with self.assertRaisesRegex(OutboxError, 'LEASE_DISPATCH_CONFLICT'):
                b.dispatch_unknown(alias)
        with self.open() as cold:
            self.assertFalse(cold.status(alias)['has_no_durable_dispatch_fence'])
            self.assertTrue(cold.status(alias)['old_lease_dispatch_fenced'])


    def test_same_native_generation_cannot_change_tip_height_or_membership(self):
        with self.open() as db:
            original = db.prepare(intent())
            db.dispatch_unknown(original)
            included = observation('included', generation=4, seed=b'same-view')
            db.observe(original, included)
            db.observe(original, observation('confirmed', generation=4, seed=b'same-view'))
            # Transient inability to retrieve evidence need not rewrite a
            # previously observed inclusion; it is not a negative certificate.
            db.observe(original, observation('unavailable', generation=4, seed=b'same-view'))
            bad = (
                observation('included', generation=4, seed=b'other-tip'),
                replace(included, observed_height=included.observed_height+1),
                replace(included, included_block=h(b'another-included-block')),
                observation('reorged', generation=4, seed=b'same-view'),
            )
            for candidate in bad:
                with self.assertRaisesRegex(
                    OutboxError, r'OBSERVATION_(VIEW|MEMBERSHIP)_CONFLICT'
                ):
                    db.observe(original, candidate)
            # Reorganization after an actually changed active generation
            # retains the original irreversible dispatch fence.
            db.observe(original, observation('reorged', generation=5, seed=b'new-view'))
            self.assertEqual(db.audit(), 5)
            self.assertEqual(db.status(original)['observations'], 4)
            self.assertTrue(db.status(original)['old_lease_dispatch_fenced'])
        with self.open() as cold:
            self.assertEqual(cold.audit(), 5)
            self.assertEqual(cold.status(original)['last_untrusted_observation'], 'reorged')

    def test_rehashed_same_generation_membership_conflict_refuses_cold_open(self):
        with self.open() as owner:
            original = owner.prepare(intent())
            owner.dispatch_unknown(original)
            owner.observe(original, observation('included', generation=7, seed=b'fixed'))
        # Bypass application methods to simulate a corrupted, validly rehashed
        # historical SQLite row. A digest chain is not a semantic proof.
        with sqlite3.connect(self.file) as raw:
            prior = raw.execute(
                'SELECT ordinal,digest FROM q4_outbox_events_v1 ORDER BY ordinal DESC LIMIT 1'
            ).fetchone()
            ordinal = prior[0] + 1
            prior_digest = prior[1]
            name = 'OBSERVED_REORGED'
            wire = observation('reorged', generation=7, seed=b'fixed').wire()
            digest = hashlib.sha256(
                EVENT_DOMAIN + ordinal.to_bytes(8,'big') + original
                + name.encode('ascii') + wire + prior_digest
            ).digest()
            raw.execute(
                'INSERT INTO q4_outbox_events_v1 VALUES (?,?,?,?,?,?)',
                (ordinal, original, name, wire, prior_digest, digest)
            )
        with self.assertRaisesRegex(OutboxError, 'OBSERVATION_MEMBERSHIP_CONFLICT'):
            self.open()

if __name__ == '__main__': unittest.main()
