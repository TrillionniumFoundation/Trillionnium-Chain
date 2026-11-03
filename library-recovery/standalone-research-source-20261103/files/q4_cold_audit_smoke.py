"""Independent local smoke for PR #383's new observation/SQLite invariants.

This is NOT a test of fetched exact GitHub bytes or Rust native owner.
"""
from dataclasses import dataclass
import hashlib
import sqlite3
import unittest

ZERO = bytes(32)
FROZEN_SCHEMA_DDL = {
    'q4_outbox_meta_v1': ('table', 'CREATE TABLE q4_outbox_meta_v1 (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID'),
    'q4_outbox_intents_v1': ('table', 'CREATE TABLE q4_outbox_intents_v1 (id BLOB PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, packet_id BLOB NOT NULL UNIQUE, wire BLOB NOT NULL) WITHOUT ROWID'),
    'q4_outbox_events_v1': ('table', 'CREATE TABLE q4_outbox_events_v1 (ordinal INTEGER PRIMARY KEY, intent_id BLOB NOT NULL, kind TEXT NOT NULL, observation BLOB NOT NULL, prev BLOB NOT NULL, digest BLOB NOT NULL)'),
    'q4_outbox_once_v1': ('index', "CREATE UNIQUE INDEX q4_outbox_once_v1 ON q4_outbox_events_v1(intent_id) WHERE kind='DISPATCH_UNKNOWN'"),
}

class OutboxError(ValueError):
    pass

def identity(v, name):
    if type(v) is not bytes or len(v) != 32 or v == ZERO:
        raise OutboxError(name + '_IDENTITY')
    return v

def u64(v, name):
    if type(v) is not int or not 0 <= v < 1 << 64:
        raise OutboxError(name + '_RANGE')
    return v.to_bytes(8, 'big')

@dataclass(frozen=True)
class ChainObservation:
    generation: int
    observed_tip: bytes
    observed_height: int
    kind: str
    included_block: bytes | None
    source_receipt_digest: bytes

    def wire(self):
        if self.kind not in {'included','confirmed','reorged','unavailable','expired'}:
            raise OutboxError('OBSERVATION_KIND')
        if ((self.kind in {'included','confirmed'} and self.included_block is None)
                or (self.kind in {'reorged','unavailable','expired'} and self.included_block is not None)):
            raise OutboxError('OBSERVATION_MEMBERSHIP')
        if self.generation == 0:
            raise OutboxError('OBSERVATION_GENERATION')
        return (u64(self.generation,'generation') + identity(self.observed_tip,'tip')
                +u64(self.observed_height,'height')
                +bytes([{'included':1,'confirmed':2,'reorged':3,'unavailable':4,'expired':5}[self.kind]])
                +(identity(self.included_block,'block') if self.included_block else ZERO)
                +identity(self.source_receipt_digest,'receipt'))

    @classmethod
    def from_wire(cls, raw: bytes) -> 'ChainObservation':
        if type(raw) is not bytes or len(raw) != 113:
            raise OutboxError('OBSERVATION_WIRE')
        kinds = {1:'included',2:'confirmed',3:'reorged',4:'unavailable',5:'expired'}
        kind = kinds.get(raw[48])
        if kind is None:
            raise OutboxError('OBSERVATION_WIRE')
        result = cls(int.from_bytes(raw[:8],'big'),raw[8:40],int.from_bytes(raw[40:48],'big'),kind,
                     raw[49:81] if kind in {'included','confirmed'} else None,raw[81:113])
        try:
            if result.wire() != raw:
                raise OutboxError('OBSERVATION_WIRE')
        except OutboxError as exc:
            raise OutboxError('OBSERVATION_WIRE') from exc
        return result


def schema_is_exact(db):
    actual={name:(kind,sql) for kind,name,sql in db.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
    return actual == FROZEN_SCHEMA_DDL

class ColdAuditSmoke(unittest.TestCase):
    def sample(self,kind='included'):
        h=lambda s:hashlib.sha256(s.encode()).digest()
        return ChainObservation(2,h('tip'),950,kind,h('included') if kind in ('included','confirmed') else None,h('receipt'))

    def test_observation_roundtrip_all_five_states(self):
        for k in ('included','confirmed','reorged','unavailable','expired'):
            with self.subTest(k=k):
                o=self.sample(k)
                self.assertEqual(ChainObservation.from_wire(o.wire()),o)

    def test_rehashed_bad_observation_cannot_become_canonical(self):
        good=self.sample().wire()
        changes=((0,8,ZERO[:8]),(8,40,ZERO),(49,81,ZERO),(81,113,ZERO),
                 (48,49,b'\xff'),(48,49,b'\x03'))
        for a,b,patch in changes:
            with self.subTest(field=(a,b)):
                mutated=good[:a]+patch+good[b:]
                self.assertEqual(len(mutated),113)
                # An attacker can rewrite the local event digest; the codec still rejects.
                _=hashlib.sha256(mutated).digest()
                with self.assertRaisesRegex(OutboxError,'OBSERVATION_WIRE'):
                    ChainObservation.from_wire(mutated)

    def test_schema_objects_and_trigger_rejection(self):
        for alt in ('none','view','table','trigger','index'):
            with self.subTest(alt=alt):
                db=sqlite3.connect(':memory:')
                for kind,sql in FROZEN_SCHEMA_DDL.values():
                    db.execute(sql)
                self.assertTrue(schema_is_exact(db))
                if alt=='view': db.execute('CREATE VIEW q4_shadow AS SELECT 1')
                if alt=='table': db.execute('CREATE TABLE q4_shadow (v BLOB)')
                if alt=='trigger': db.executescript('CREATE TRIGGER q4_shadow AFTER INSERT ON q4_outbox_events_v1 BEGIN DELETE FROM q4_outbox_events_v1; END')
                if alt=='index':
                    db.execute('DROP INDEX q4_outbox_once_v1')
                    db.execute('CREATE INDEX q4_outbox_once_v1 ON q4_outbox_events_v1(intent_id)')
                self.assertEqual(schema_is_exact(db),alt=='none')
                db.close()

if __name__=='__main__':unittest.main()
