"""Isolated SQLite engine probe for the GitHub research pre-read predicates.

Does not execute the GitHub exact-head modules or authenticate PoN facts.
"""
import sqlite3, tempfile
from pathlib import Path

LIMIT=4096
with tempfile.TemporaryDirectory() as root:
    path=Path(root)/'bound.db'
    a=sqlite3.connect(path, isolation_level=None)
    a.executescript('''
    CREATE TABLE q4_outbox_meta_v1 (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
    CREATE TABLE q4_outbox_intents_v1 (id BLOB PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, packet_id BLOB NOT NULL UNIQUE, wire BLOB NOT NULL) WITHOUT ROWID;
    CREATE TABLE q4_outbox_events_v1 (ordinal INTEGER PRIMARY KEY, intent_id BLOB NOT NULL, kind TEXT NOT NULL, observation BLOB NOT NULL, prev BLOB NOT NULL, digest BLOB NOT NULL);
    CREATE UNIQUE INDEX q4_outbox_once_v1 ON q4_outbox_events_v1(intent_id) WHERE kind='DISPATCH_UNKNOWN';
    CREATE TABLE daa_shadow_meta_v1 (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
    ''')
    a.execute('INSERT INTO q4_outbox_meta_v1 VALUES (?,?)',('network', bytes(32)))
    a.execute('INSERT INTO q4_outbox_intents_v1 VALUES (?,?,?,?)',(b'a'*32,b'o'*32,b'p'*32,b'w'*1475))
    a.execute('INSERT INTO q4_outbox_events_v1 VALUES (?,?,?,?,?,?)',(1,b'a'*32,'DISPATCH_UNKNOWN',b'',bytes(32),bytes(32)))
    a.execute('INSERT INTO daa_shadow_meta_v1 VALUES (?,?)',('context',b'c'*32))
    def oversized(table, cols):
        where=' OR '.join(f'length({c}) > ?' for c in cols)
        return a.execute(f'SELECT 1 FROM {table} WHERE {where} LIMIT 1', (LIMIT,)*len(cols)).fetchone() is not None
    q4=[('q4_outbox_meta_v1',('key','value')),('q4_outbox_intents_v1',('id','operation_id','packet_id','wire')),('q4_outbox_events_v1',('intent_id','kind','observation','prev','digest'))]
    assert not any(oversized(*x) for x in q4)
    assert not oversized('daa_shadow_meta_v1',('key','value'))
    a.execute('BEGIN IMMEDIATE')
    a.execute('UPDATE q4_outbox_intents_v1 SET wire=zeroblob(65536)')
    assert oversized(*q4[1])
    a.execute('ROLLBACK')
    assert not oversized(*q4[1])
    a.execute('UPDATE q4_outbox_events_v1 SET observation=zeroblob(65536)')
    assert oversized(*q4[2])
    a.execute('UPDATE q4_outbox_events_v1 SET observation=?',(b'',))
    assert not oversized(*q4[2])
    a.execute('UPDATE q4_outbox_meta_v1 SET value=zeroblob(65536)')
    assert oversized(*q4[0])
    a.execute('UPDATE daa_shadow_meta_v1 SET value=zeroblob(65536)')
    assert oversized('daa_shadow_meta_v1',('key','value'))
    a.close()
print('SQLite predicate probe 8/8 PASS (isolated SQL, not exact-head repository suite)')
