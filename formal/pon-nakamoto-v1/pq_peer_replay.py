"""Research-only PPH1 per-peer monotonic SQLite receiver observation journal.

NOT a Chain ledger, a network identity authority, a global anti-rollback anchor,
or a grant. All signed bytes and channel bindings must be checked before recording.
One local database cannot stop an attacker cloning its filesystem to a second host.
"""
from __future__ import annotations
from pathlib import Path
import sqlite3
from pq_envelope import Reject
from pq_peer_session import parse_hello, verify_hello

SCHEMA = """CREATE TABLE peer_current (
 network BLOB NOT NULL,
 remote_key_id BLOB NOT NULL,
 generation INTEGER NOT NULL CHECK(generation > 0),
 sequence INTEGER NOT NULL CHECK(sequence > 0),
 statement_digest BLOB NOT NULL CHECK(length(statement_digest) = 48),
 channel_tag BLOB NOT NULL CHECK(length(channel_tag) = 32),
 PRIMARY KEY(network, remote_key_id)
) WITHOUT ROWID, STRICT"""
MAX_PEERS=1024
I63_MAX=(1<<63)-1


class LocalPeerReplayJournal:
    """One local sqlite domain; must be owned and anchored separately by a real host."""
    def __init__(self, path: Path):
        p=Path(path)
        if p.is_symlink() or not p.parent.is_dir():
            raise Reject("journal path/owner")
        self.db=sqlite3.connect(str(p),timeout=10,isolation_level=None)
        try:
            self.db.execute("PRAGMA busy_timeout=10000")
            existing=self.db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
            if existing:
                self._audit()
            else:
                # Local research init only, not a protected production owner namespace.
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    rows=self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
                    if rows:raise Reject("race installing journal schema")
                    self.db.execute(SCHEMA)
                    self.db.execute("COMMIT")
                except BaseException:
                    if self.db.in_transaction:self.db.execute("ROLLBACK")
                    raise
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower()!="wal":
                raise Reject("journal WAL unavailable")
            self.db.execute("PRAGMA synchronous=FULL")
            if self.db.execute("PRAGMA synchronous").fetchone()[0]!=2:
                raise Reject("journal FULL unavailable")
            self._audit()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _audit(self):
        schema=self.db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
        if schema != [("table","peer_current",SCHEMA)]:
            raise Reject("foreign/modified journal schema")
        good=self.db.execute("PRAGMA quick_check").fetchone()[0]
        if good!="ok":raise Reject("database integrity")
        count=self.db.execute("SELECT count(*) FROM peer_current").fetchone()[0]
        if count>MAX_PEERS:raise Reject("journal capacity exceeded")
        rows=self.db.execute("SELECT network,remote_key_id,generation,sequence,statement_digest,channel_tag FROM peer_current").fetchall()
        for n,p,g,s,h,c in rows:
            if (not isinstance(n,bytes) or len(n)!=32 or n==bytes(32) or
                not isinstance(p,bytes) or len(p)!=32 or p==bytes(32) or
                type(g) is not int or not 1<=g<=I63_MAX or
                type(s) is not int or not 1<=s<=I63_MAX or
                not isinstance(h,bytes) or len(h)!=48 or
                not isinstance(c,bytes) or len(c)!=32 or c==bytes(32)):
                raise Reject("journal row invalid")

    def record(self, frame: bytes, **verification):
        """Verify fresh cryptographic context, THEN serialize a local observation.

        A duplicate returns ALREADY_RECORDED, not a second first-observation.
        New higher generation or sequence is a local observation, NOT proof a
        remote peer was authorized to advance its generation or global head.
        """
        observation=verify_hello(frame,**verification)
        h=parse_hello(frame[:256])
        if h.generation>I63_MAX or h.sequence>I63_MAX:
            raise Reject("SQLite integer range")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._audit()
            old=self.db.execute(
                "SELECT generation,sequence,statement_digest,channel_tag FROM peer_current WHERE network=? AND remote_key_id=?",
                (h.network,h.sender_key_id)).fetchone()
            if old:
                g,s,d,c=old
                if h.generation==g and h.sequence==s:
                    if d!=observation.statement_digest or c!=h.channel_tag:
                        raise Reject("same monotonic position, different signed statement")
                    outcome="ALREADY_RECORDED"
                else:
                    if (h.generation,h.sequence) <= (g,s) or (h.generation==g and h.sequence<=s):
                        raise Reject("stale peer generation/sequence")
                    # Sequence can reset only when the independently verified generation advances.
                    self.db.execute("UPDATE peer_current SET generation=?,sequence=?,statement_digest=?,channel_tag=? WHERE network=? AND remote_key_id=?",
                                    (h.generation,h.sequence,observation.statement_digest,h.channel_tag,h.network,h.sender_key_id))
                    outcome="FIRST_RECORD"
            else:
                if self.db.execute("SELECT count(*) FROM peer_current").fetchone()[0]>=MAX_PEERS:
                    raise Reject("peer journal full")
                self.db.execute("INSERT INTO peer_current(network,remote_key_id,generation,sequence,statement_digest,channel_tag) VALUES(?,?,?,?,?,?)",
                                (h.network,h.sender_key_id,h.generation,h.sequence,
                                 observation.statement_digest,h.channel_tag))
                outcome="FIRST_RECORD"
            self.db.execute("COMMIT")
            return outcome,observation.statement_digest
        except BaseException:
            if self.db.in_transaction:self.db.execute("ROLLBACK")
            raise
