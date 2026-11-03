"""Research-only SQLite post-write trigger fault reproduction; not real PoN authority."""
import sqlite3
import tempfile
from pathlib import Path


def exercise(kind):
    with tempfile.TemporaryDirectory() as directory:
        db = sqlite3.connect(str(Path(directory) / 'fault.sqlite'), isolation_level=None)
        db.execute('CREATE TABLE intents(id BLOB PRIMARY KEY, data BLOB)')
        db.execute('CREATE TABLE events(id INTEGER PRIMARY KEY, kind TEXT)')
        if kind == 'intent':
            table = 'intents'
            db.execute('CREATE TRIGGER fault AFTER INSERT ON intents BEGIN DELETE FROM intents WHERE id=NEW.id; END')
        else:
            table = 'events'
            db.execute('CREATE TRIGGER fault AFTER INSERT ON events BEGIN DELETE FROM events WHERE id=NEW.id; END')
        # Existing pattern: a successful SQL INSERT can coexist with an absent row
        # if external local schema mutation supplies an AFTER INSERT trigger.
        db.execute('BEGIN IMMEDIATE')
        if kind == 'intent':
            db.execute('INSERT INTO intents VALUES (?,?)',(b'x',b'signed-original'))
        else:
            db.execute('INSERT INTO events VALUES (?,?)',(1,'DISPATCH_UNKNOWN'))
        db.execute('COMMIT')
        assert db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
        # New rule: fail BEFORE COMMIT when write did not durably create the intended row.
        db.execute('BEGIN IMMEDIATE')
        if kind == 'intent':
            db.execute('INSERT INTO intents VALUES (?,?)',(b'x',b'signed-original'))
            changed = db.execute('SELECT id,data FROM intents WHERE id=?',(b'x',)).fetchone()
            expected = (b'x',b'signed-original')
        else:
            db.execute('INSERT INTO events VALUES (?,?)',(1,'DISPATCH_UNKNOWN'))
            changed = db.execute('SELECT id,kind FROM events WHERE id=?',(1,)).fetchone()
            expected = (1,'DISPATCH_UNKNOWN')
        refused = changed != expected
        db.execute('ROLLBACK')
        assert refused
        db.execute('DROP TRIGGER fault')
        db.execute('BEGIN IMMEDIATE')
        if kind == 'intent':
            db.execute('INSERT INTO intents VALUES (?,?)',(b'x',b'signed-original'))
        else:
            db.execute('INSERT INTO events VALUES (?,?)',(1,'DISPATCH_UNKNOWN'))
        db.execute('COMMIT')
        assert db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 1
        db.close()
        return kind, 'reproduced missing-row false-success; atomic readback refuses; clean retry succeeds'


if __name__ == '__main__':
    for name in ('intent','event'):
        print(*exercise(name))
