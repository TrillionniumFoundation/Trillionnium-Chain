"""PQL4 actual SQLite / ML-DSA-65 negative and rollback observations."""
from __future__ import annotations

from dataclasses import replace
from contextlib import contextmanager
from pathlib import Path
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

from pq_pql4_signed_frontier import (
    DOMAIN, Frontier, FrontierObservation, LocalSnapshot, Reject, SIGNED_BYTES,
    SQL, UNSIGNED_BYTES, ZERO32, ZERO48, frontier_id, node_id,
    observe_pql3_store, parse_frontier, sign_fixture, signer_key_id,
    verify_checkpoint,
)


def be(v):
    return v.to_bytes(8, "big")


@contextmanager
def opened(path):
    conn = sqlite3.connect(path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


class PQL4ActualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_context = tempfile.TemporaryDirectory(prefix="trnm-pql4-keys-")
        cls.addClassCleanup(cls.root_context.cleanup)
        cls.keyroot = Path(cls.root_context.name)
        cls.keys = {}
        for label in ("observer", "attacker"):
            private = cls.keyroot / (label + ".private.pem")
            public = cls.keyroot / (label + ".public.pem")
            subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65",
                            "-out", str(private)], capture_output=True, check=True, timeout=15)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout",
                            "-out", str(public)], capture_output=True, check=True, timeout=15)
            cls.keys[label] = (private, public.read_bytes())
        old_private = cls.keyroot / "ed25519.private.pem"
        old_public = cls.keyroot / "ed25519.public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(old_private)],
                       capture_output=True, check=True, timeout=15)
        subprocess.run(["openssl", "pkey", "-in", str(old_private), "-pubout", "-out", str(old_public)],
                       capture_output=True, check=True, timeout=15)
        cls.classical_key = old_public.read_bytes()
        cls.network = bytes(range(1, 33))
        cls.import_root = bytes([0x22])*48
        cls.nonces = be(23) + be(91)
        cls.migrated = (True, False)
        cls.genesis = node_id(cls.import_root, ZERO48, 0, -1, ZERO32, cls.nonces)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="trnm-pql4-db-")
        self.addCleanup(self.work.cleanup)
        self.db_path = Path(self.work.name) / "pql3.sqlite"
        with opened(self.db_path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            for ddl in SQL.values():
                db.execute(ddl)
            db.executemany("INSERT INTO meta VALUES (?,?)",
                           [("import", self.import_root), ("genesis", self.genesis)])
            db.execute("INSERT INTO nodes VALUES (?,?,?,?,?,?)",
                       (self.genesis, ZERO48, 0, -1, ZERO32, self.nonces))
            db.execute("INSERT INTO active VALUES (1,?,1)", (self.genesis,))
        self.snapshot = self.inspect()

    def inspect(self, **override):
        args=dict(path=self.db_path, expected_import_root=self.import_root,
                  expected_genesis=self.genesis, original_nonces=self.nonces,
                  migrated=self.migrated)
        args.update(override)
        return observe_pql3_store(**args)

    def frame(self, snapshot=None, *, sequence=1, previous=ZERO48, signer="observer", expiry=2000):
        snapshot = self.snapshot if snapshot is None else snapshot
        f = Frontier(self.network, self.import_root, self.genesis, snapshot.tip,
                     snapshot.generation, sequence, previous, snapshot.state_digest,
                     expiry, signer_key_id(self.keys[signer][1]))
        return f, sign_fixture(f, self.keys[signer][0])

    def check(self, frame, snapshot=None, *, expected_sequence=1, previous=ZERO48, **kw):
        args=dict(frame=frame, public_pem=self.keys["observer"][1],
                  expected_observer_key_id=signer_key_id(self.keys["observer"][1]),
                  expected_network=self.network,
                  expected_snapshot=self.snapshot if snapshot is None else snapshot,
                  expected_sequence=expected_sequence,
                  expected_prior_frontier_id=previous, now=1500)
        args.update(kw)
        return verify_checkpoint(**args)

    def advance(self, op=bytes([0x41])*32):
        updated_nonces = be(24) + be(91)
        child = node_id(self.import_root, self.genesis, 1, 0, op, updated_nonces)
        with opened(self.db_path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?)",
                       (child, self.genesis, 1, 0, op, updated_nonces))
            db.execute("UPDATE active SET tip=?,generation=2 WHERE slot=1", (child,))
            db.execute("INSERT INTO effects VALUES(?,?)", (bytes([0xC4])*32, child))
        return child

    def backup(self, target):
        with opened(self.db_path) as src, opened(target) as dest:
            src.backup(dest)

    def test_real_ml_dsa_signature_and_exact_storage_snapshot(self):
        f, signed = self.frame()
        self.assertEqual(len(f.encode()), UNSIGNED_BYTES)
        self.assertEqual(len(signed), SIGNED_BYTES)
        self.assertEqual(parse_frontier(f.encode()), f)
        result = self.check(signed)
        self.assertIsInstance(result, FrontierObservation)
        self.assertEqual(result.frontier_id, frontier_id(f))
        self.assertEqual(result.state_digest, self.snapshot.state_digest)
        self.assertEqual(self.snapshot.node_count, 1)
        self.assertEqual(self.snapshot.effect_count, 0)
        self.assertFalse(hasattr(result, "chainwork"))
        self.assertFalse(hasattr(result, "final_use"))
        self.assertFalse(hasattr(result, "rollback_authorized"))

    def test_new_tip_and_effects_are_signed_into_same_read_snapshot(self):
        old = self.snapshot
        child = self.advance()
        new = self.inspect()
        self.assertEqual(new.generation, 2)
        self.assertEqual(new.tip, child)
        self.assertEqual((new.node_count, new.effect_count), (2, 1))
        self.assertNotEqual(new.state_digest, old.state_digest)
        old_f, old_sig = self.frame(old)
        new_f, new_sig = self.frame(new, sequence=2, previous=frontier_id(old_f))
        o = self.check(new_sig, new, expected_sequence=2, previous=frontier_id(old_f))
        self.assertEqual(o.observed_sequence, 2)
        with self.assertRaises(Reject):
            self.check(old_sig, new, expected_sequence=2, previous=frontier_id(old_f))
        with self.assertRaises(Reject):
            self.check(new_sig, old, expected_sequence=2, previous=frontier_id(old_f))

    def test_whole_database_clone_rollback_detected_against_fresh_external_frontier(self):
        old_snapshot = self.snapshot
        copy = Path(self.work.name) / "old.sqlite"
        self.backup(copy)
        old_f, old_frame = self.frame(old_snapshot)
        self.advance()
        new_snapshot = self.inspect()
        _, latest_frame = self.frame(new_snapshot, sequence=2, previous=frontier_id(old_f))
        self.check(latest_frame, new_snapshot, expected_sequence=2, previous=frontier_id(old_f))
        # A complete, internally consistent older database is restored, not a corrupt page.
        for suffix in ("-wal", "-shm"):
            (Path(str(self.db_path)+suffix)).unlink(missing_ok=True)
        os.replace(copy, self.db_path)
        restored = self.inspect()
        self.assertEqual(restored.state_digest, old_snapshot.state_digest)
        with self.assertRaises(Reject):
            self.check(latest_frame, restored, expected_sequence=2, previous=frontier_id(old_f))
        with self.assertRaises(Reject):
            self.check(old_frame, restored, expected_sequence=2, previous=frontier_id(old_f))
        # Intentional negative: attacker also rolls back the EXTERNAL trust pin.
        # An old genuine signed witness + stale trusted seq still passes.
        self.assertEqual(self.check(old_frame, restored, expected_sequence=1).observed_sequence, 1)

    def test_signature_mutation_wrong_key_and_classical_downgrade(self):
        _, signed = self.frame()
        bad = signed[:-1] + bytes([signed[-1] ^ 1])
        with self.assertRaises(Reject):
            self.check(bad)
        with self.assertRaises(Reject):
            self.check(signed, public_pem=self.keys["attacker"][1])
        with self.assertRaises(Reject):
            self.check(signed, public_pem=self.classical_key)
        with self.assertRaises(Reject):
            signer_key_id(self.classical_key)
        with self.assertRaises(Reject):
            self.check(signed, expected_observer_key_id=bytes(32))

    def test_every_signed_header_byte_mutation_refused(self):
        _, signed = self.frame()
        for off in range(UNSIGNED_BYTES):
            bad = bytearray(signed)
            bad[off] ^= 1
            with self.subTest(byte=off), self.assertRaises(Reject):
                self.check(bytes(bad))

    def test_nonce_quarantine_parent_effect_and_generation_attacks(self):
        illegal_op=bytes([0x77])*32
        illegal_nonces=be(23)+be(92)
        illegal_node=node_id(self.import_root,self.genesis,1,1,illegal_op,illegal_nonces)
        with opened(self.db_path) as db:
            db.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?)",
                       (illegal_node,self.genesis,1,1,illegal_op,illegal_nonces))
        with self.assertRaises(Reject):
            self.inspect()
        with opened(self.db_path) as db:
            db.execute("DELETE FROM nodes WHERE id=?", (illegal_node,))
            db.execute("INSERT INTO effects VALUES(?,?)", (bytes([9])*32, bytes([8])*48))
        with self.assertRaises(Reject):
            self.inspect()
        with opened(self.db_path) as db:
            db.execute("DELETE FROM effects")
            db.execute("UPDATE active SET generation=0")
        with self.assertRaises(Reject):
            self.inspect()

    def test_nonce_gap_and_import_floor_reset_refused(self):
        op=bytes([0x51])*32
        future_nonces=be(25)+be(91)
        id_bad=node_id(self.import_root,self.genesis,1,0,op,future_nonces)
        with opened(self.db_path) as db:
            db.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?)",
                       (id_bad,self.genesis,1,0,op,future_nonces))
        with self.assertRaises(Reject):
            self.inspect()
        with self.assertRaises(Reject):
            self.inspect(original_nonces=be(1)+be(91))
        with self.assertRaises(Reject):
            self.inspect(migrated=(False, False))

    def test_foreign_schema_trigger_view_and_wrong_import_metadata_refused(self):
        with opened(self.db_path) as db:
            db.execute("CREATE TRIGGER hostile AFTER UPDATE ON active BEGIN DELETE FROM meta; END")
        with self.assertRaises(Reject):
            self.inspect()
        with opened(self.db_path) as db:
            db.execute("DROP TRIGGER hostile")
            db.execute("CREATE VIEW impostor AS SELECT * FROM active")
        with self.assertRaises(Reject):
            self.inspect()
        with opened(self.db_path) as db:
            db.execute("DROP VIEW impostor")
            db.execute("UPDATE meta SET value=? WHERE key='import'", (bytes([5])*48,))
        with self.assertRaises(Reject):
            self.inspect()

    def test_symlink_and_wrong_file_kind_and_missing_refused(self):
        link=Path(self.work.name)/"impostor.sqlite"
        link.symlink_to(self.db_path)
        with self.assertRaises(Reject):
            self.inspect(path=link)
        with self.assertRaises(Reject):
            self.inspect(path=Path(self.work.name))
        with self.assertRaises(Reject):
            self.inspect(path=Path(self.work.name)/"absent")
        with self.assertRaises(Reject):
            self.inspect(path=Path("relative.sqlite"))

    def test_stale_previous_sequence_expiry_and_network_refused(self):
        _, signed=self.frame()
        args=[dict(expected_sequence=2),dict(previous=bytes([1])*48),
              dict(now=2001),dict(expected_network=bytes([1])*32),
              dict(expected_snapshot=replace(self.snapshot,generation=2)),
              dict(expected_snapshot=replace(self.snapshot,state_digest=bytes([3])*48))]
        for case in args:
            with self.subTest(case=case),self.assertRaises(Reject):
                self.check(signed, **case)

    def test_strict_codec_types_and_no_signature_ambiguity(self):
        f,signed=self.frame()
        for broken in (replace(f, generation=True),replace(f,sequence=0),
                       replace(f,import_root=b"bad"),replace(f,observer_key_id=ZERO32),
                       replace(f,prior_frontier_id=b"wrong"), replace(f,network=ZERO32)):
            with self.assertRaises(Reject):
                broken.encode()
        for bad in (signed[:-1],signed+b"x",signed[:UNSIGNED_BYTES]+b"\x00\x00"+signed[UNSIGNED_BYTES+2:],
                    b"PQL3"+signed[4:],signed[:4]+b"\x02"+signed[5:],signed[:5]+b"\x01"+signed[6:]):
            with self.assertRaises(Reject):
                self.check(bad)
        with self.assertRaises(Reject):
            self.check(signed,expected_sequence=True)
        with self.assertRaises(Reject):
            self.check(signed,now=True)

    def test_effect_bookkeeping_changes_state_digest_even_with_same_active_tip(self):
        old=self.snapshot
        with opened(self.db_path) as db:
            db.execute("INSERT INTO effects VALUES (?,?)", (bytes([0x99])*32,self.genesis))
        current=self.inspect()
        self.assertEqual(current.tip,old.tip)
        self.assertEqual(current.generation,old.generation)
        self.assertNotEqual(current.state_digest,old.state_digest)
        _,signed=self.frame(old)
        with self.assertRaises(Reject):
            self.check(signed,current)


if __name__ == "__main__":
    unittest.main()
