"""Research-only M07/M08 branch-local DAA shadow journal.

No PoN work verification, block admission, native state authority, signer, or
consensus activation. An upstream verified-packet owner must supply exact packet
bytes and an independently derived local projection commitment. On cold open this
journal verifies its own durable graph, not the truth of upstream W1 packets.
The schema deliberately has a fresh namespace and is not compatible with Node DBs.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sqlite3
from typing import Callable

ZERO = b'\0' * 32
MAX_U64 = (1 << 64) - 1
SCHEMA = b'trnm-daa-shadow-journal-research-v1'
MAX_PACKET = 1_048_576

def row_digest(wire: bytes) -> bytes:
    return hashlib.sha256(b'TRNM-DAA-SHADOW-ROW-V1\0' + wire).digest()


class JournalError(ValueError):
    """Never a consensus-invalid block verdict."""


class UnknownEffect(JournalError):
    """COMMIT may have succeeded: the original identity must be read back."""


def _id(value: bytes, name: str, *, zero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != 32 or (not zero and value == ZERO):
        raise JournalError(f'{name}_IDENTITY')
    return value


def _u64(value: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise JournalError(f'{name}_RANGE')
    return value.to_bytes(8, 'big')


def _unpack_u64(value: bytes, name: str) -> int:
    if type(value) is not bytes or len(value) != 8:
        raise JournalError(f'{name}_NONCANONICAL')
    return int.from_bytes(value, 'big')


@dataclass(frozen=True)
class ShadowHeader:
    block_id: bytes
    parent_id: bytes
    height: int
    timestamp: int
    target: bytes
    packet_hash: bytes
    projection_hash: bytes

    def validate(self) -> None:
        for name in ('block_id', 'parent_id', 'target', 'packet_hash', 'projection_hash'):
            _id(getattr(self, name), name)
        _u64(self.height, 'height')
        _u64(self.timestamp, 'timestamp')
        if self.height == 0 or self.block_id == self.parent_id:
            raise JournalError('HEADER_HEIGHT_OR_ID')

    def wire(self) -> bytes:
        self.validate()
        return (self.block_id + self.parent_id + _u64(self.height, 'height')
                + _u64(self.timestamp, 'timestamp') + self.target
                + self.packet_hash + self.projection_hash)

    @classmethod
    def decode(cls, raw: bytes) -> 'ShadowHeader':
        if type(raw) is not bytes or len(raw) != 176:
            raise JournalError('HEADER_LENGTH')
        item = cls(raw[:32], raw[32:64], _unpack_u64(raw[64:72], 'height'),
                   _unpack_u64(raw[72:80], 'timestamp'), raw[80:112],
                   raw[112:144], raw[144:176])
        item.validate()
        if item.wire() != raw:
            raise JournalError('HEADER_CANONICAL')
        return item


class ShadowJournal:
    """Single owner for *research only*. No part is imported by native Node."""

    def __init__(self, path: Path, context_id: bytes, genesis_id: bytes,
                 *, max_headers: int = 20_000):
        self.context = _id(context_id, 'context')
        self.genesis = _id(genesis_id, 'genesis')
        if type(max_headers) is not int or not 1 <= max_headers <= 100_000:
            raise JournalError('HEADER_BUDGET')
        self.max_headers = max_headers
        path = Path(path)
        # A research crash journal must never silently use an ephemeral SQLite DB.
        if str(path) == ':memory:' or str(path).startswith('file:'):
            raise JournalError('DATABASE_PATH')
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise JournalError('DATABASE_PATH')
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=0.1)
        try:
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA foreign_keys=ON')
            self._initialize()
            self.audit()
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _initialize(self) -> None:
        # These tables are deliberately not the native Node ledger namespace.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            tables = {row[0] for row in self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if tables:
                if tables != {'daa_shadow_meta_v1', 'daa_shadow_headers_v1'}:
                    raise JournalError('FOREIGN_SCHEMA')
            else:
                self.db.execute('CREATE TABLE daa_shadow_meta_v1 ('
                                'key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID')
                self.db.execute('CREATE TABLE daa_shadow_headers_v1 ('
                                'block_id BLOB PRIMARY KEY CHECK(length(block_id)=32), '
                                'parent_id BLOB NOT NULL CHECK(length(parent_id)=32), '
                                'height BLOB NOT NULL CHECK(length(height)=8), '
                                'canonical BLOB NOT NULL CHECK(length(canonical)=176), '
                                'digest BLOB NOT NULL CHECK(length(digest)=32)) WITHOUT ROWID')
                for key, value in (('schema', SCHEMA), ('context', self.context),
                                   ('genesis', self.genesis), ('active_tip', self.genesis)):
                    self.db.execute('INSERT INTO daa_shadow_meta_v1 VALUES (?, ?)', (key, value))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        expected = {'schema': SCHEMA, 'context': self.context, 'genesis': self.genesis}
        actual = dict(self.db.execute('SELECT key, value FROM daa_shadow_meta_v1'))
        if set(actual) != {*expected, 'active_tip'} or any(actual[k] != v for k, v in expected.items()):
            raise JournalError('DATABASE_CONTEXT')
        self._valid_tip(actual['active_tip'])

    def _valid_tip(self, tip: bytes) -> None:
        _id(tip, 'active_tip')
        if tip != self.genesis and self.db.execute(
                'SELECT 1 FROM daa_shadow_headers_v1 WHERE block_id=?', (tip,)).fetchone() is None:
            raise JournalError('ACTIVE_TIP_UNAVAILABLE')

    def _check_context_snapshot(self) -> None:
        """Read the COMPLETE immutable namespace before any hot mutation.

        This detects foreign/corrupt metadata in the caller's current SQLite
        snapshot. It authenticates neither a remote packet nor native W1 work.
        """
        # Block schema-injected triggers/views/indexes before any DAA research
        # writer operation; the check shares its existing SQLite snapshot.
        # Exact DDL matters: a table with the original name but no uniqueness
        # or canonical-byte CHECK constraints is a foreign storage owner.
        objects = self.db.execute(
            "SELECT type,name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if set(objects) != {
            ('table', 'daa_shadow_meta_v1',
             'CREATE TABLE daa_shadow_meta_v1 '
             '(key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID'),
            ('table', 'daa_shadow_headers_v1',
             'CREATE TABLE daa_shadow_headers_v1 '
             '(block_id BLOB PRIMARY KEY CHECK(length(block_id)=32), '
             'parent_id BLOB NOT NULL CHECK(length(parent_id)=32), '
             'height BLOB NOT NULL CHECK(length(height)=8), '
             'canonical BLOB NOT NULL CHECK(length(canonical)=176), '
             'digest BLOB NOT NULL CHECK(length(digest)=32)) WITHOUT ROWID'),
        }:
            raise JournalError('DATABASE_SCHEMA_DRIFT')
        expected = {'schema': SCHEMA, 'context': self.context,
                    'genesis': self.genesis}
        actual = dict(self.db.execute(
            'SELECT key, value FROM daa_shadow_meta_v1'))
        if (set(actual) != {*expected, 'active_tip'}
                or any(actual[k] != value for k, value in expected.items())):
            raise JournalError('DATABASE_CONTEXT')

    def active(self) -> bytes:
        self._check_context_snapshot()
        value = self.db.execute("SELECT value FROM daa_shadow_meta_v1 WHERE key='active_tip'").fetchone()
        if value is None:
            raise JournalError('ACTIVE_TIP_MISSING')
        self._valid_tip(value[0])
        return value[0]

    def get(self, block_id: bytes) -> ShadowHeader:
        _id(block_id, 'block_id')
        # A hash-consistent header in a foreign-schema or changed-context
        # journal must not be returned as a trustworthy research readback.
        self._check_context_snapshot()
        result = self.db.execute('SELECT parent_id,height,canonical,digest '
                                 'FROM daa_shadow_headers_v1 WHERE block_id=?',
                                 (block_id,)).fetchone()
        if result is None:
            raise JournalError('UNKNOWN_PARENT_OR_HEADER')
        if row_digest(result[2]) != result[3]:
            raise JournalError('HEADER_ROW_DIGEST')
        value = ShadowHeader.decode(result[2])
        if (value.block_id != block_id or value.parent_id != result[0]
                or _u64(value.height, 'height') != result[1]):
            raise JournalError('HEADER_INDEX_DRIFT')
        return value

    def append(self, header: ShadowHeader, raw_packet: bytes, *,
               fail_at: str | None = None) -> ShadowHeader:
        """Header/projection facts are supplied by upstream, NOT certified here.

        A real native caller must authenticate W1, context, target, roots and the
        upstream projection before calling. `raw_packet` is hashed as received;
        neither this method nor its successful return grants that authority.
        """
        header.validate()
        if (type(raw_packet) is not bytes or not 1 <= len(raw_packet) <= MAX_PACKET
                or hashlib.sha256(raw_packet).digest() != header.packet_hash
                or header.block_id == self.genesis):
            raise JournalError('PACKET_DIGEST_OR_LENGTH')
        if fail_at not in (None, 'before_insert', 'after_insert', 'before_commit', 'after_commit'):
            raise JournalError('UNKNOWN_FAULT_POINT')
        self.db.execute('BEGIN IMMEDIATE')
        committed = False
        try:
            # Detect drift in immutable context and active-tip identity inside
            # the original BEGIN IMMEDIATE writer snapshot, before any append.
            self.active()
            prior = self.db.execute('SELECT canonical FROM daa_shadow_headers_v1 WHERE block_id=?',
                                    (header.block_id,)).fetchone()
            if prior is not None:
                self.get(header.block_id)  # reject a corrupted digest/index even on exact replay
                if prior[0] != header.wire():
                    raise JournalError('HEADER_COLLISION')
                self.db.execute('COMMIT')
                committed = True
                return header  # exact replay; no refreshed budget or new fact
            number = self.db.execute('SELECT COUNT(*) FROM daa_shadow_headers_v1').fetchone()[0]
            if number >= self.max_headers:
                raise JournalError('HEADER_BUDGET')
            if header.parent_id == self.genesis:
                if header.height != 1:
                    raise JournalError('HEADER_HEIGHT')
            else:
                parent = self.get(header.parent_id)
                if parent.height == MAX_U64 or header.height != parent.height + 1:
                    raise JournalError('HEADER_HEIGHT')
            if fail_at == 'before_insert':
                raise JournalError('INJECTED_BEFORE_INSERT')
            self.db.execute('INSERT INTO daa_shadow_headers_v1 VALUES (?,?,?,?,?)',
                            (header.block_id, header.parent_id,
                             _u64(header.height, 'height'), header.wire(),
                             row_digest(header.wire())))
            if fail_at == 'after_insert':
                raise JournalError('INJECTED_AFTER_INSERT')
            if fail_at == 'before_commit':
                raise JournalError('INJECTED_BEFORE_COMMIT')
            self.db.execute('COMMIT')
            committed = True
            if fail_at == 'after_commit':
                raise UnknownEffect('INJECTED_AFTER_COMMIT_RECONCILE_ORIGINAL_ID')
            # Read-after-write: a caller never receives an unverified success.
            if self.get(header.block_id) != header:
                raise JournalError('HEADER_READBACK')
            return header
        except BaseException:
            if not committed:
                self.db.execute('ROLLBACK')
            raise

    def activate(self, tip: bytes, expected_active: bytes, *, fail_at: str | None = None) -> bytes:
        """Compare-and-swap of research-only active tip, never PoN fork choice."""
        _id(tip, 'tip')
        _id(expected_active, 'expected_active')
        if fail_at not in (None, 'before_commit', 'after_commit'):
            raise JournalError('UNKNOWN_FAULT_POINT')
        self.db.execute('BEGIN IMMEDIATE')
        committed = False
        try:
            old = self.active()
            if old != expected_active:
                raise JournalError('ACTIVE_GENERATION_CONFLICT')
            self._valid_tip(tip)
            self.db.execute("UPDATE daa_shadow_meta_v1 SET value=? WHERE key='active_tip'", (tip,))
            if fail_at == 'before_commit':
                raise JournalError('INJECTED_BEFORE_COMMIT')
            self.db.execute('COMMIT')
            committed = True
            if fail_at == 'after_commit':
                raise UnknownEffect('INJECTED_AFTER_COMMIT_RECONCILE_ORIGINAL_ID')
            if self.active() != tip:
                raise JournalError('ACTIVE_TIP_READBACK')
            return tip
        except BaseException:
            if not committed:
                self.db.execute('ROLLBACK')
            raise

    def audit(self) -> int:
        """Read graph and active tip in one durable SQLite read snapshot.

        A concurrent writer may append/activate a branch while an audit runs.
        Without an explicit transaction, the final active-tip SELECT can see
        a later generation than the graph rows already scanned.
        """
        if self.db.in_transaction:
            raise JournalError('AUDIT_REENTRANT')
        self.db.execute('BEGIN')
        try:
            count = self._audit_snapshot()
        finally:
            self.db.execute('ROLLBACK')
        return count

    def _audit_snapshot(self) -> int:
        """Cold graph and canonical-identity check; NOT packet/W1 proof replay.

        An attacker able to rewrite the entire local database may recompute all
        checks. Native trusted packet/state replay remains required at startup.
        """
        rows = self.db.execute('SELECT block_id,parent_id,height,canonical,digest '
                               'FROM daa_shadow_headers_v1 ORDER BY height,block_id')
        seen = {self.genesis: 0}
        count = 0
        for block_id, parent_id, height, canonical, digest in rows:
            if row_digest(canonical) != digest:
                raise JournalError('DATABASE_ROW_DIGEST')
            count += 1
            if count > self.max_headers:
                raise JournalError('HEADER_BUDGET')
            decoded = ShadowHeader.decode(canonical)
            if (decoded.block_id != block_id or decoded.parent_id != parent_id
                    or _u64(decoded.height, 'height') != height):
                raise JournalError('DATABASE_ROW_MISMATCH')
            predecessor = seen.get(decoded.parent_id)
            if predecessor is None or decoded.height != predecessor + 1:
                raise JournalError('DATABASE_BRANCH_OR_PARENT')
            if decoded.block_id in seen:
                raise JournalError('DATABASE_DUPLICATE')
            seen[decoded.block_id] = decoded.height
        if self.active() not in seen:
            raise JournalError('ACTIVE_TIP_UNAVAILABLE')
        return count

    def audit_against_upstream(
        self,
        read_packet: Callable[[ShadowHeader], bytes],
        derive_projection: Callable[[ShadowHeader, bytes], bytes],
        *,
        max_rows: int,
    ) -> int:
        """Compare all local rows to independently supplied upstream bytes/facts.

        Neither callback is authenticated here. Only the original native Node
        verifier may decide work/state/target authority. A forged callback can
        still make forged research receipts; this method issues no such token.
        No owner effects or repairs are dispatched in this read-only audit.
        """
        if (not callable(read_packet) or not callable(derive_projection)
                or type(max_rows) is not int or not 1 <= max_rows <= self.max_headers):
            raise JournalError('OWNER_AUDIT_BUDGET_OR_CALLBACK')
        # One read snapshot: the application must not let the upstream owner
        # advance a branch or append a row while an audit is being assembled.
        if self.db.in_transaction:
            raise JournalError('OWNER_AUDIT_REENTRANT')
        self.db.execute('BEGIN')
        try:
            if self.db.execute('SELECT COUNT(*) FROM daa_shadow_headers_v1').fetchone()[0] > max_rows:
                raise JournalError('OWNER_AUDIT_BUDGET')
            self._audit_snapshot()  # graph and tip in the same upstream read snapshot
            scanned = 0
            cursor = self.db.execute('SELECT canonical FROM daa_shadow_headers_v1 '
                                     'ORDER BY height,block_id')
            for (encoded,) in cursor:
                scanned += 1
                if scanned > max_rows:
                    raise JournalError('OWNER_AUDIT_BUDGET')
                header = ShadowHeader.decode(encoded)
                packet = read_packet(header)
                if type(packet) is not bytes or not 1 <= len(packet) <= MAX_PACKET:
                    raise JournalError('OWNER_PACKET_UNAVAILABLE')
                if hashlib.sha256(packet).digest() != header.packet_hash:
                    raise JournalError('OWNER_PACKET_MISMATCH')
                projection = derive_projection(header, packet)
                if type(projection) is not bytes or len(projection) != 32:
                    raise JournalError('OWNER_PROJECTION_UNAVAILABLE')
                if projection != header.projection_hash:
                    raise JournalError('OWNER_PROJECTION_MISMATCH')
            return scanned
        finally:
            # SELECT state is never published and a failed callback cannot leave
            # an original SQLite read transaction/lock alive.
            self.db.execute('ROLLBACK')

