"""Research-only crash/reorg/fault controls; zero authentic native W1 proofs."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from daa_shadow_journal import ShadowHeader, ShadowJournal, JournalError, UnknownEffect, ZERO


def sha(blob: bytes) -> bytes:
    return hashlib.sha256(blob).digest()

CTX = sha(b'non-authoritative-context')
GEN = sha(b'nonce-free-genesis')
TGT = (1 << 220).to_bytes(32, 'big')


def candidate(parent: bytes, h: int, marker: int = 0) -> tuple[ShadowHeader, bytes]:
    # These are LABORATORY BYTES; not work-checked PoN packets.
    packet = b'RESEARCH_ONLY_NOT_W1:' + h.to_bytes(8, 'big') + marker.to_bytes(4, 'big')
    block = sha(parent + packet)
    derived = sha(b'projection-outside-authority:' + parent + packet)
    return (ShadowHeader(block, parent, h, 1_700_000_000 + h * 10 + marker,
                         TGT, sha(packet), derived), packet)


class ShadowJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'research-only.sqlite'

    def tearDown(self):
        self.tmp.cleanup()

    def test_reboot_exact_identity_replay_cas_and_branch_retention(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet1 = candidate(GEN, 1)
            journal.append(first, packet1)
            self.assertEqual(journal.append(first, packet1), first)
            fork1, packet_f1 = candidate(first.block_id, 2, 1)
            fork2, packet_f2 = candidate(first.block_id, 2, 2)
            journal.append(fork1, packet_f1)
            journal.append(fork2, packet_f2)
            self.assertEqual(journal.activate(fork1.block_id, GEN), fork1.block_id)
            with self.assertRaisesRegex(JournalError, 'ACTIVE_GENERATION_CONFLICT'):
                journal.activate(fork2.block_id, GEN)
        with ShadowJournal(self.path, CTX, GEN) as journal:
            self.assertEqual(journal.audit(), 3)
            self.assertEqual(journal.active(), fork1.block_id)
            self.assertEqual(journal.get(fork2.block_id), fork2)
            journal.activate(fork2.block_id, fork1.block_id)
        with ShadowJournal(self.path, CTX, GEN) as journal:
            self.assertEqual(journal.active(), fork2.block_id)
            self.assertEqual(journal.get(fork1.block_id), fork1)

    def test_crash_cuts_do_not_publish_partial_headers(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            for stage in ('before_insert', 'after_insert', 'before_commit'):
                entry, packet = candidate(GEN, 1, len(stage))
                with self.assertRaisesRegex(JournalError, 'INJECTED_'):
                    journal.append(entry, packet, fail_at=stage)
                with self.assertRaisesRegex(JournalError, 'UNKNOWN_PARENT_OR_HEADER'):
                    journal.get(entry.block_id)
                self.assertEqual(journal.audit(), 0)
            entry, packet = candidate(GEN, 1, 9)
            with self.assertRaises(UnknownEffect):
                journal.append(entry, packet, fail_at='after_commit')
            self.assertEqual(journal.get(entry.block_id), entry)
        with ShadowJournal(self.path, CTX, GEN) as journal:
            self.assertEqual(journal.audit(), 1)
            self.assertEqual(journal.append(entry, packet), entry)

    def test_cas_fault_before_and_after_commit_preserves_unknowns(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            entry, packet = candidate(GEN, 1)
            journal.append(entry, packet)
            with self.assertRaisesRegex(JournalError, 'INJECTED_BEFORE_COMMIT'):
                journal.activate(entry.block_id, GEN, fail_at='before_commit')
            self.assertEqual(journal.active(), GEN)
            with self.assertRaises(UnknownEffect):
                journal.activate(entry.block_id, GEN, fail_at='after_commit')
            self.assertEqual(journal.active(), entry.block_id)
            with self.assertRaisesRegex(JournalError, 'ACTIVE_GENERATION_CONFLICT'):
                journal.activate(entry.block_id, GEN)

    def test_immutable_context_foreign_schema_packet_and_collision(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            one, packet = candidate(GEN, 1)
            with self.assertRaisesRegex(JournalError, 'PACKET_DIGEST_OR_LENGTH'):
                journal.append(one, packet + b'change')
            journal.append(one, packet)
            changed = ShadowHeader(one.block_id, one.parent_id, one.height,
                                   one.timestamp + 1, one.target, one.packet_hash,
                                   one.projection_hash)
            with self.assertRaisesRegex(JournalError, 'HEADER_COLLISION'):
                journal.append(changed, packet)
            unknown, p2 = candidate(sha(b'unknown'), 2)
            with self.assertRaisesRegex(JournalError, 'UNKNOWN_PARENT_OR_HEADER'):
                journal.append(unknown, p2)
        with self.assertRaisesRegex(JournalError, 'DATABASE_CONTEXT'):
            ShadowJournal(self.path, sha(b'other'), GEN)
        with ShadowJournal(self.path, CTX, GEN) as journal:
            self.assertEqual(journal.audit(), 1)

    def test_tampered_original_row_refuses_cold_open(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet = candidate(GEN, 1)
            journal.append(first, packet)
            second, raw = candidate(first.block_id, 2)
            journal.append(second, raw)
        with sqlite3.connect(self.path) as db:
            raw = bytearray(db.execute('SELECT canonical FROM daa_shadow_headers_v1 WHERE block_id=?',
                                       (first.block_id,)).fetchone()[0])
            raw[72] ^= 1  # changes earliest timestamp without updating identity/witness
            db.execute('UPDATE daa_shadow_headers_v1 SET canonical=? WHERE block_id=?',
                       (bytes(raw), first.block_id))
        with self.assertRaisesRegex(JournalError, 'DATABASE_ROW_DIGEST'):
            ShadowJournal(self.path, CTX, GEN)

    def test_corrupt_digest_refused_even_on_identical_replay(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            one, packet = candidate(GEN, 1)
            journal.append(one, packet)
            journal.db.execute('UPDATE daa_shadow_headers_v1 SET digest=? WHERE block_id=?',
                               (sha(b'wrong-row'), one.block_id))
            with self.assertRaisesRegex(JournalError, 'HEADER_ROW_DIGEST'):
                journal.append(one, packet)
            with self.assertRaisesRegex(JournalError, 'HEADER_ROW_DIGEST'):
                journal.get(one.block_id)

    def test_upstream_callback_cannot_reenter_original_writer(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet = candidate(GEN, 1)
            journal.append(first, packet)
            second, next_packet = candidate(first.block_id, 2)
            observed = []
            def hostile_reader(header):
                # Attempts to mutate same original SQLite writer during the
                # read snapshot are blocked; the callback has no new budget.
                with self.assertRaises(sqlite3.OperationalError):
                    journal.append(second, next_packet)
                observed.append(header.block_id)
                return packet
            projection = lambda h, raw: sha(b'projection-outside-authority:' + h.parent_id + raw)
            self.assertEqual(journal.audit_against_upstream(
                hostile_reader, projection, max_rows=1), 1)
            self.assertEqual(observed, [first.block_id])
            self.assertEqual(journal.audit(), 1)
            with self.assertRaisesRegex(JournalError, 'UNKNOWN_PARENT_OR_HEADER'):
                journal.get(second.block_id)
            # Successful auditing releases the original snapshot lock.
            journal.append(second, next_packet)
            self.assertEqual(journal.audit(), 2)

    def test_hot_read_refuses_noncanonical_height_index(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            one, packet = candidate(GEN, 1)
            journal.append(one, packet)
            journal.db.execute('UPDATE daa_shadow_headers_v1 SET height=? WHERE block_id=?',
                               ((42).to_bytes(8, 'big'), one.block_id))
            with self.assertRaisesRegex(JournalError, 'HEADER_INDEX_DRIFT'):
                journal.get(one.block_id)
            with self.assertRaisesRegex(JournalError, 'HEADER_INDEX_DRIFT'):
                journal.append(one, packet)

    def test_missing_parent_and_orphan_active_rejected(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet = candidate(GEN, 1)
            journal.append(first, packet)
            second, raw = candidate(first.block_id, 2)
            journal.append(second, raw)
            journal.activate(second.block_id, GEN)
        with sqlite3.connect(self.path) as db:
            db.execute('DELETE FROM daa_shadow_headers_v1 WHERE block_id=?', (first.block_id,))
        with self.assertRaisesRegex(JournalError, 'DATABASE_BRANCH_OR_PARENT'):
            ShadowJournal(self.path, CTX, GEN)

    def test_bounded_budget_and_high_64bit_height_encoding(self):
        with ShadowJournal(self.path, CTX, GEN, max_headers=1) as journal:
            first, packet = candidate(GEN, 1)
            journal.append(first, packet)
            second, raw = candidate(first.block_id, 2)
            with self.assertRaisesRegex(JournalError, 'HEADER_BUDGET'):
                journal.append(second, raw)
            bad = ShadowHeader(first.block_id, GEN, 1 << 64, 0, TGT,
                               sha(packet), sha(b'shadow'))
            with self.assertRaisesRegex(JournalError, 'height_RANGE'):
                bad.wire()
        with self.assertRaisesRegex(JournalError, 'HEADER_BUDGET'):
            ShadowJournal(self.path, CTX, GEN, max_headers=0)

    def test_graph_audit_pins_one_snapshot_against_competing_branch_append(self):
        # Scanning rows and selecting the active tip must share ONE SQLite
        # snapshot. A second writer cannot insert a new branch at that cut.
        with ShadowJournal(self.path, CTX, GEN) as reader, ShadowJournal(self.path, CTX, GEN) as writer:
            first, original_packet = candidate(GEN, 1)
            reader.append(first, original_packet)
            next_block, next_packet = candidate(first.block_id, 2)
            attempted = []
            def trace(sql):
                if sql.startswith("SELECT value FROM daa_shadow_meta_v1 WHERE key='active_tip'"):
                    try:
                        writer.append(next_block, next_packet)
                    except sqlite3.OperationalError:
                        attempted.append('busy')
                    else:
                        attempted.append('unexpected_commit')
            reader.db.set_trace_callback(trace)
            try:
                self.assertEqual(reader.audit(), 1)
            finally:
                reader.db.set_trace_callback(None)
            self.assertEqual(attempted, ['busy'])
            with self.assertRaisesRegex(JournalError, 'UNKNOWN_PARENT_OR_HEADER'):
                reader.get(next_block.block_id)
            writer.append(next_block, next_packet)
            writer.activate(next_block.block_id, GEN)
            self.assertEqual(reader.audit(), 2)
            self.assertEqual(reader.active(), next_block.block_id)

    def test_reentrant_audit_refuses_without_rolling_back_owner_write(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            journal.db.execute('BEGIN IMMEDIATE')
            try:
                with self.assertRaisesRegex(JournalError, 'AUDIT_REENTRANT'):
                    journal.audit()
                with self.assertRaisesRegex(JournalError, 'OWNER_AUDIT_REENTRANT'):
                    journal.audit_against_upstream(
                        lambda _: b'proof', lambda *_: bytes(32), max_rows=1
                    )
                self.assertTrue(journal.db.in_transaction)
            finally:
                journal.db.execute('ROLLBACK')
            self.assertEqual(journal.audit(), 0)

    def test_external_owner_byte_and_projection_audit_accepts_exact_replay(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet_a = candidate(GEN, 1)
            second, packet_b = candidate(first.block_id, 2)
            journal.append(first, packet_a)
            journal.append(second, packet_b)
            packets = {first.block_id: packet_a, second.block_id: packet_b}
            def read(header):
                return packets[header.block_id]
            def derive(header, raw):
                return sha(b'projection-outside-authority:' + header.parent_id + raw)
            self.assertEqual(journal.audit_against_upstream(read, derive, max_rows=2), 2)
            self.assertEqual(journal.active(), GEN)  # audit must not select a tip
            with self.assertRaisesRegex(JournalError, 'OWNER_AUDIT_BUDGET'):
                journal.audit_against_upstream(read, derive, max_rows=1)
            self.assertEqual(journal.audit(), 2)

    def test_external_owner_refuses_missing_changed_or_fake_evidence(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            header, packet = candidate(GEN, 1)
            journal.append(header, packet)
            good = lambda h: packet
            derived = lambda h, raw: sha(b'projection-outside-authority:' + h.parent_id + raw)
            with self.assertRaisesRegex(JournalError, 'OWNER_PACKET_UNAVAILABLE'):
                journal.audit_against_upstream(lambda _: None, derived, max_rows=1)
            with self.assertRaisesRegex(JournalError, 'OWNER_PACKET_MISMATCH'):
                journal.audit_against_upstream(lambda _: packet + b'x', derived, max_rows=1)
            with self.assertRaisesRegex(JournalError, 'OWNER_PROJECTION_MISMATCH'):
                journal.audit_against_upstream(good, lambda *_: sha(b'wrong'), max_rows=1)
            with self.assertRaisesRegex(JournalError, 'OWNER_PROJECTION_UNAVAILABLE'):
                journal.audit_against_upstream(good, lambda *_: b'a', max_rows=1)
            with self.assertRaisesRegex(JournalError, 'OWNER_AUDIT_BUDGET_OR_CALLBACK'):
                journal.audit_against_upstream(good, derived, max_rows=0)
            self.assertEqual(journal.audit(), 1)

    def test_symlink_and_preexisting_foreign_database_fail_closed(self):
        other = Path(self.tmp.name) / 'foreign'
        with sqlite3.connect(other) as db:
            db.execute('CREATE TABLE owner_secret(a INTEGER)')
        with self.assertRaisesRegex(JournalError, 'FOREIGN_SCHEMA'):
            ShadowJournal(other, CTX, GEN)
        link = Path(self.tmp.name) / 'link'
        link.symlink_to(other)
        with self.assertRaisesRegex(JournalError, 'DATABASE_PATH'):
            ShadowJournal(link, CTX, GEN)



    def test_live_context_mutation_refuses_append_activation_and_audit(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet1 = candidate(GEN, 1)
            journal.append(first, packet1)
            another, packet2 = candidate(first.block_id, 2)
            # Mutate immutable metadata AFTER the original Node-like journal
            # opened. Old hot paths would accept headers/CAS under wrong context.
            with sqlite3.connect(self.path) as raw:
                raw.execute("UPDATE daa_shadow_meta_v1 SET value=? WHERE key='context'",
                            (sha(b'foreign-network-context'),))
            with self.assertRaisesRegex(JournalError, 'DATABASE_CONTEXT'):
                journal.append(another, packet2)
            with self.assertRaisesRegex(JournalError, 'DATABASE_CONTEXT'):
                journal.activate(first.block_id, GEN)
            with self.assertRaisesRegex(JournalError, 'DATABASE_CONTEXT'):
                journal.audit()
            self.assertFalse(journal.db.in_transaction)
            with sqlite3.connect(self.path) as raw:
                self.assertEqual(raw.execute(
                    'SELECT COUNT(*) FROM daa_shadow_headers_v1').fetchone()[0], 1)
                self.assertEqual(raw.execute(
                    "SELECT value FROM daa_shadow_meta_v1 WHERE key='active_tip'"
                ).fetchone()[0], GEN)
                raw.execute("UPDATE daa_shadow_meta_v1 SET value=? WHERE key='context'",
                            (CTX,))
            self.assertEqual(journal.audit(), 1)
            journal.append(another, packet2)
            self.assertEqual(journal.activate(another.block_id, GEN), another.block_id)
            self.assertEqual(journal.audit(), 2)

    def test_live_genesis_and_schema_loss_never_mutate_branch_history(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet = candidate(GEN, 1)
            for key in ('schema', 'genesis'):
                with sqlite3.connect(self.path) as raw:
                    raw.execute('DELETE FROM daa_shadow_meta_v1 WHERE key=?', (key,))
                with self.assertRaisesRegex(JournalError, 'DATABASE_CONTEXT'):
                    journal.append(first, packet)
                with self.assertRaisesRegex(JournalError, 'DATABASE_CONTEXT'):
                    journal.activate(GEN, GEN)
                self.assertFalse(journal.db.in_transaction)
                with sqlite3.connect(self.path) as raw:
                    self.assertEqual(raw.execute(
                        'SELECT COUNT(*) FROM daa_shadow_headers_v1').fetchone()[0], 0)
                    raw.execute('INSERT INTO daa_shadow_meta_v1 VALUES (?,?)',
                                (key, SCHEMA if key == 'schema' else GEN))
                self.assertEqual(journal.audit(), 0)
            journal.append(first, packet)
            self.assertEqual(journal.audit(), 1)


    def test_live_trigger_schema_change_rejected_before_append_and_cas(self):
        with ShadowJournal(self.path, CTX, GEN) as journal:
            first, packet1 = candidate(GEN, 1)
            journal.append(first, packet1)
            second, packet2 = candidate(first.block_id, 2)
            with sqlite3.connect(self.path) as raw:
                raw.execute(
                    "CREATE TRIGGER foreign_rewrite AFTER INSERT ON daa_shadow_headers_v1 "
                    "BEGIN UPDATE daa_shadow_meta_v1 SET value=x'00' WHERE key='context'; END"
                )
            # An opened journal must refuse the foreign trigger before it can
            # mutate header rows or publish the active-tip CAS.
            with self.assertRaisesRegex(JournalError, 'DATABASE_SCHEMA'):
                journal.append(second, packet2)
            with self.assertRaisesRegex(JournalError, 'DATABASE_SCHEMA'):
                journal.activate(first.block_id, GEN)
            with self.assertRaisesRegex(JournalError, 'DATABASE_SCHEMA'):
                journal.audit()
            self.assertFalse(journal.db.in_transaction)
            with sqlite3.connect(self.path) as raw:
                self.assertEqual(raw.execute(
                    'SELECT COUNT(*) FROM daa_shadow_headers_v1').fetchone()[0], 1)
                self.assertEqual(raw.execute(
                    "SELECT value FROM daa_shadow_meta_v1 WHERE key='context'"
                ).fetchone()[0], CTX)
                self.assertEqual(raw.execute(
                    "SELECT value FROM daa_shadow_meta_v1 WHERE key='active_tip'"
                ).fetchone()[0], GEN)
                raw.execute('DROP TRIGGER foreign_rewrite')
            self.assertEqual(journal.audit(), 1)
            journal.append(second, packet2)
            journal.activate(second.block_id, GEN)
            self.assertEqual(journal.active(), second.block_id)
        with ShadowJournal(self.path, CTX, GEN) as cold:
            self.assertEqual(cold.audit(), 2)

if __name__ == '__main__':
    unittest.main()
