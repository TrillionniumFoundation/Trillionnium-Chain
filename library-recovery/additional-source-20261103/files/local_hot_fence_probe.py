"""Isolated SQLite negative probe for PR research hot-tail fences.

This runs an independent minimal reproduction of the intended O(1) SQL/fence
logic, NOT the complete exact-source repository test suite or native PoN node.
"""
import hashlib
import sqlite3
import unittest

EVENT_DOMAIN = b'TRNM-Q4-OUTBOX-EVENT-V1\0'
ZERO = bytes(32)
INTENT = b'I' * 32


def digest(n, ident, kind, obs, previous):
    return hashlib.sha256(EVENT_DOMAIN + n.to_bytes(8, 'big') + ident + kind.encode('ascii') + obs + previous).digest()


class HotFenceResearchTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.db.execute('create table e(ordinal integer primary key, intent_id blob, kind text, observation blob, prev blob, digest blob)')
        self.db.execute('create table headers(block_id blob primary key, canonical blob, digest blob)')
        self.db.execute('create table meta(key text primary key, value blob)')
        self.genesis = hashlib.sha256(b'genesis').digest()
        self.db.execute('insert into meta values (?,?)', ('tip', self.genesis))

    def append(self, kind, obs):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            tail = self.db.execute('select ordinal,intent_id,kind,observation,prev,digest from e order by ordinal desc limit 1').fetchone()
            if tail is None:
                n, previous = 1, ZERO
            else:
                i, ident, k, observation, previous, stored = tail
                if not isinstance(i, int) or not isinstance(k, str) or not isinstance(observation, bytes):
                    raise ValueError('EVENT_TAIL_CORRUPT')
                if digest(i, ident, k, observation, previous) != stored:
                    raise ValueError('EVENT_TAIL_CORRUPT')
                if i == 1 and previous != ZERO:
                    raise ValueError('EVENT_TAIL_CORRUPT')
                if i > 1:
                    penultimate = self.db.execute('select ordinal,digest from e order by ordinal desc limit 1 offset 1').fetchone()
                    if penultimate != (i - 1, previous):
                        raise ValueError('EVENT_TAIL_CORRUPT')
                n, previous = i + 1, stored
            row = (n, INTENT, kind, obs, previous, digest(n, INTENT, kind, obs, previous))
            self.db.execute('insert into e values (?,?,?,?,?,?)', row)
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def checked_tip(self, tip):
        if tip == self.genesis:
            return tip
        row = self.db.execute('select canonical,digest from headers where block_id=?', (tip,)).fetchone()
        if row is None:
            raise ValueError('ACTIVE_TIP_UNAVAILABLE')
        if hashlib.sha256(row[0]).digest() != row[1]:
            raise ValueError('HEADER_ROW_DIGEST')
        if hashlib.sha256(row[0]).digest() != tip:
            raise ValueError('HEADER_INDEX_DRIFT')
        return tip

    def test_valid_chain_and_append(self):
        self.append('DISPATCH_UNKNOWN', b'')
        self.append('OBSERVED_INCLUDED', b'1' * 113)
        self.append('OBSERVED_CONFIRMED', b'2' * 113)
        self.assertEqual(self.db.execute('select count(*) from e').fetchone()[0], 3)

    def test_mutated_last_digest_refuses_new_event(self):
        self.append('DISPATCH_UNKNOWN', b'')
        self.db.execute('update e set digest=? where ordinal=1', (b'X' * 32,))
        with self.assertRaisesRegex(ValueError, 'EVENT_TAIL_CORRUPT'):
            self.append('OBSERVED_INCLUDED', b'1' * 113)
        self.assertEqual(self.db.execute('select count(*) from e').fetchone()[0], 1)

    def test_mutated_predecessor_refuses_new_event(self):
        self.append('DISPATCH_UNKNOWN', b'')
        self.append('OBSERVED_INCLUDED', b'1' * 113)
        self.db.execute('update e set digest=? where ordinal=1', (b'X' * 32,))
        with self.assertRaisesRegex(ValueError, 'EVENT_TAIL_CORRUPT'):
            self.append('OBSERVED_CONFIRMED', b'2' * 113)
        self.assertEqual(self.db.execute('select count(*) from e').fetchone()[0], 2)

    def test_corrupt_selected_tip_refused_without_publication(self):
        canonical = b'block' * 9
        block = hashlib.sha256(canonical).digest()
        self.db.execute('insert into headers values (?,?,?)', (block, canonical, hashlib.sha256(canonical).digest()))
        self.assertEqual(self.checked_tip(block), block)
        self.db.execute('update headers set digest=? where block_id=?', (b'Y' * 32, block))
        with self.assertRaisesRegex(ValueError, 'HEADER_ROW_DIGEST'):
            self.checked_tip(block)
        self.assertEqual(self.db.execute("select value from meta where key='tip'").fetchone()[0], self.genesis)


if __name__ == '__main__':
    unittest.main()
