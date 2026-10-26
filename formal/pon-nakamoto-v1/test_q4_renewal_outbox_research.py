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

    def test_cold_audit_rejects_semantic_observation_with_recomputed_event_hash(self):
        # Local adversarial SQLite rewrite, not an external chain or signature claim.
        # Both event checksum and event predecessor are valid after mutation.
        from q4_renewal_outbox_research import EVENT_DOMAIN
        cases = (
            ('zero-gen','included',0,8,bytes(8),'OBSERVATION_WIRE'),
            ('zero-tip','included',8,40,bytes(32),'OBSERVATION_WIRE'),
            ('zero-receipt','included',81,113,bytes(32),'OBSERVATION_WIRE'),
            ('missing-block','confirmed',49,81,bytes(32),'OBSERVATION_MEMBERSHIP'),
            ('invented-block','reorged',49,81,bytes([9])*32,'OBSERVATION_MEMBERSHIP'),
            ('unknown-class','included',48,49,bytes([255]),'OBSERVATION_MISMATCH'),
        )
        for name, observed_kind, first, end, replacement, expected in cases:
            with self.subTest(name=name):
                path = Path(self.tmp.name) / (name + '.sqlite')
                with RenewalOutbox(path,N,P,G) as db:
                    key = db.prepare(intent())
                    db.dispatch_unknown(key)
                    db.observe(key,observation(observed_kind))
                    self.assertEqual(db.audit(),2)
                with sqlite3.connect(path) as raw:
                    ident,kind,prior,wire=raw.execute(
                        'SELECT intent_id,kind,prev,observation FROM q4_outbox_events_v1 WHERE ordinal=2'
                    ).fetchone()
                    changed=wire[:first]+replacement+wire[end:]
                    self.assertEqual(len(changed),113)
                    altered_digest=hashlib.sha256(
                        EVENT_DOMAIN + (2).to_bytes(8,'big') + ident
                        + kind.encode('ascii') + changed + prior
                    ).digest()
                    raw.execute('UPDATE q4_outbox_events_v1 SET observation=?,digest=? WHERE ordinal=2',
                                (changed,altered_digest))
                    row=raw.execute('SELECT digest FROM q4_outbox_events_v1 WHERE ordinal=2').fetchone()
                    self.assertEqual(row[0],altered_digest)
                with self.assertRaisesRegex(OutboxError,expected):
                    RenewalOutbox(path,N,P,G)

    def test_transaction_id_matches_explicit_pon_hash_domain(self):
        raw=TX
        manual=h(b'TRNM-PON1\0'+(5).to_bytes(2,'little')+b'tx-id'
                 +len(raw).to_bytes(4,'little')+raw)
        self.assertEqual(transaction_id(raw),manual)
        self.assertNotEqual(transaction_id(raw),h(raw))

if __name__ == '__main__': unittest.main()
