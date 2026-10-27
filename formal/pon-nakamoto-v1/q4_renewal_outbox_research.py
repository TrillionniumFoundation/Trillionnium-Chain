"""Q4 signed-renewal lost-ACK/reorg research outbox; NO signer, dispatcher or consensus authority.

The caller alone owns legitimate source/requester signatures, real verified chain queries
and authorization. This journal never sends a transaction or constructs a new lease.
It persists DispatchUnknown BEFORE a separately owned external submit attempt: after
that transition only the ORIGINAL operation/transaction may be reconciled; a reorg,
expiry or lost ACK never resets this fence or authorizes another payment/nonce.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sqlite3
import struct

SCHEMA = b'trnm-q4-outbox-research-v1'
DOMAIN = b'TRNM-Q4-RENEWAL-INTENT-V1\0'
EVENT_DOMAIN = b'TRNM-Q4-OUTBOX-EVENT-V1\0'
UINT64 = (1 << 64) - 1
ZERO = bytes(32)
TX_BYTES = 1187  # historical PNX1(tag22) envelope length, NOT signature verification

class OutboxError(ValueError):
    pass

class UnknownEffect(OutboxError):
    """COMMIT may have succeeded; reconcile original identity before any action."""

def _validate_observation_wire(kind: str, obs: bytes) -> int:
    """Check complete canonical observation bytes on input AND cold journal replay.

    Only syntax and exact event identity are checked. The caller still owns
    verification of genuine native chain membership and confirmation.
    """
    tags = {'OBSERVED_INCLUDED': 1, 'OBSERVED_CONFIRMED': 2,
            'OBSERVED_REORGED': 3, 'OBSERVED_UNAVAILABLE': 4,
            'OBSERVED_EXPIRED': 5}
    if kind not in tags:
        raise OutboxError('OBSERVATION_KIND')
    if type(obs) is not bytes or len(obs) != 113:
        raise OutboxError('OBSERVATION_WIRE')
    generation = int.from_bytes(obs[:8], 'big')
    tip, tag, block, receipt = obs[8:40], obs[48], obs[49:81], obs[81:113]
    if generation == 0 or tip == ZERO or receipt == ZERO:
        raise OutboxError('OBSERVATION_WIRE')
    if tag != tags[kind]:
        raise OutboxError('OBSERVATION_MISMATCH')
    if (tag in (1, 2) and block == ZERO) or (tag in (3, 4, 5) and block != ZERO):
        raise OutboxError('OBSERVATION_MEMBERSHIP')
    return generation

def identity(value: bytes, name: str) -> bytes:
    if type(value) is not bytes or len(value) != 32 or value == ZERO:
        raise OutboxError(name + '_IDENTITY')
    return value

def u64(value: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value <= UINT64:
        raise OutboxError(name + '_RANGE')
    return struct.pack('>Q', value)

def transaction_id(raw: bytes) -> bytes:
    """PoN's H('tx-id', transaction bytes), distinct from bare SHA256."""
    if type(raw) is not bytes or len(raw) != TX_BYTES:
        raise OutboxError('SIGNED_PACKET_LENGTH')
    return hashlib.sha256(b'TRNM-PON1\0' + struct.pack('<H', 5) + b'tx-id'
                          + struct.pack('<I', len(raw)) + raw).digest()

@dataclass(frozen=True)
class RenewalIntent:
    operation_id: bytes
    network: bytes
    parameters: bytes
    genesis: bytes
    original_parent: bytes
    old_lease_digest: bytes
    next_lease_digest: bytes
    original_generation: int
    signed_from: int
    last_legal_height: int
    requester_sequence: int
    source_sequence: int
    signed_transaction: bytes

    def wire(self) -> bytes:
        fields = (self.operation_id, self.network, self.parameters, self.genesis,
                  self.original_parent, self.old_lease_digest, self.next_lease_digest)
        for f, name in zip(fields, ('operation', 'network', 'parameters', 'genesis',
                                    'parent', 'old_lease', 'next_lease')):
            identity(f, name)
        if self.old_lease_digest == self.next_lease_digest:
            raise OutboxError('UNCHANGED_LEASE')
        if (self.original_generation == 0 or self.source_sequence == 0
                or self.requester_sequence == 0 or self.signed_from > self.last_legal_height):
            raise OutboxError('LEASE_WINDOW_OR_SEQUENCE')
        numbers = (u64(self.original_generation, 'generation'),
                   u64(self.signed_from, 'signed_from'),
                   u64(self.last_legal_height, 'last_legal_height'),
                   u64(self.requester_sequence, 'requester_sequence'),
                   u64(self.source_sequence, 'source_sequence'))
        # No constructed signing message: only exact externally provided bytes.
        transaction_id(self.signed_transaction)
        return DOMAIN + b''.join(fields) + b''.join(numbers) + self.signed_transaction

    def digest(self) -> bytes:
        return hashlib.sha256(self.wire()).digest()

    def tx_id(self) -> bytes:
        return transaction_id(self.signed_transaction)

@dataclass(frozen=True)
class ChainObservation:
    """Untrusted research observation; caller must independently verify native client proof."""
    generation: int
    observed_tip: bytes
    observed_height: int
    kind: str  # included / confirmed / reorged / unavailable / expired
    included_block: bytes | None
    source_receipt_digest: bytes

    def wire(self) -> bytes:
        if self.kind not in {'included','confirmed','reorged','unavailable','expired'}:
            raise OutboxError('OBSERVATION_KIND')
        if ((self.kind in {'included', 'confirmed'} and self.included_block is None)
                or (self.kind in {'reorged','unavailable','expired'} and self.included_block is not None)):
            raise OutboxError('OBSERVATION_MEMBERSHIP')
        if self.generation == 0:
            raise OutboxError('OBSERVATION_GENERATION')
        return (u64(self.generation,'generation') + identity(self.observed_tip, 'tip')
                + u64(self.observed_height,'height')
                + bytes([{'included':1,'confirmed':2,'reorged':3,'unavailable':4,'expired':5}[self.kind]])
                + (identity(self.included_block, 'block') if self.included_block else ZERO)
                + identity(self.source_receipt_digest, 'receipt'))

class RenewalOutbox:
    """Bounded SINGLE LOCAL RESEARCH owner. Its facts grant no publication authority."""
    def __init__(self, path: Path, network: bytes, parameters: bytes, genesis: bytes,
                 *, max_intents: int = 128, max_events: int = 4096):
        self.context = (identity(network, 'network'),identity(parameters,'parameters'),
                        identity(genesis,'genesis'))
        if (type(max_intents) is not int or not 1 <= max_intents <= 1024
                or type(max_events) is not int or not 1 <= max_events <= 65536):
            raise OutboxError('BUDGET')
        self.max_intents, self.max_events = max_intents, max_events
        path = Path(path)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise OutboxError('DATABASE_PATH')
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=0.2)
        try:
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                tables = {x[0] for x in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                expected = {'q4_outbox_meta_v1', 'q4_outbox_intents_v1', 'q4_outbox_events_v1'}
                if tables and tables != expected:
                    raise OutboxError('FOREIGN_SCHEMA')
                if not tables:
                    self.db.execute('CREATE TABLE q4_outbox_meta_v1 (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID')
                    self.db.execute('CREATE TABLE q4_outbox_intents_v1 (id BLOB PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, packet_id BLOB NOT NULL UNIQUE, wire BLOB NOT NULL) WITHOUT ROWID')
                    self.db.execute('CREATE TABLE q4_outbox_events_v1 (ordinal INTEGER PRIMARY KEY, intent_id BLOB NOT NULL, kind TEXT NOT NULL, observation BLOB NOT NULL, prev BLOB NOT NULL, digest BLOB NOT NULL)')
                    self.db.execute("CREATE UNIQUE INDEX q4_outbox_once_v1 ON q4_outbox_events_v1(intent_id) WHERE kind='DISPATCH_UNKNOWN'")
                    for k,v in [('schema',SCHEMA),('network',self.context[0]),('parameters',self.context[1]),('genesis',self.context[2])]:
                        self.db.execute('INSERT INTO q4_outbox_meta_v1 VALUES (?,?)',(k,v))
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise
            actual = dict(self.db.execute('SELECT key,value FROM q4_outbox_meta_v1'))
            if actual != dict([('schema',SCHEMA),('network',self.context[0]),('parameters',self.context[1]),('genesis',self.context[2])]):
                raise OutboxError('CONTEXT_MISMATCH')
            self.audit()
        except BaseException:
            self.db.close()
            raise

    def __enter__(self): return self
    def __exit__(self,*_): self.db.close()
    def close(self): self.db.close()

    def audit(self) -> int:
        """Audit one durable SQLite read snapshot, never a moving pair of scans.

        A distinct owner may commit intents/events during an unfenced audit.
        Both tables and the pinned namespace must be read under the SAME
        transaction; a concurrent writer must wait or receive Busy.  This
        journal remains research-only and authenticates no chain receipt.
        """
        if self.db.in_transaction:
            raise OutboxError('AUDIT_REENTRANT')
        self.db.execute('BEGIN')
        try:
            result = self._audit_snapshot()
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        self.db.execute('ROLLBACK')
        return result

    def _check_schema_snapshot(self) -> None:
        """Reject altered SQL DDL, removed uniqueness and injected triggers.

        Research-local SQLite schema matching cannot certify any Q4 signature,
        native client observation, signer, dispatcher or consensus authority.
        """
        expected = {
            ('table', 'q4_outbox_meta_v1', 'q4_outbox_meta_v1'):
                'CREATE TABLE q4_outbox_meta_v1 (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID',
            ('table', 'q4_outbox_intents_v1', 'q4_outbox_intents_v1'):
                'CREATE TABLE q4_outbox_intents_v1 (id BLOB PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, '
                'packet_id BLOB NOT NULL UNIQUE, wire BLOB NOT NULL) WITHOUT ROWID',
            ('table', 'q4_outbox_events_v1', 'q4_outbox_events_v1'):
                'CREATE TABLE q4_outbox_events_v1 (ordinal INTEGER PRIMARY KEY, intent_id BLOB NOT NULL, '
                'kind TEXT NOT NULL, observation BLOB NOT NULL, prev BLOB NOT NULL, digest BLOB NOT NULL)',
            ('index', 'q4_outbox_once_v1', 'q4_outbox_events_v1'):
                "CREATE UNIQUE INDEX q4_outbox_once_v1 ON q4_outbox_events_v1(intent_id) WHERE kind='DISPATCH_UNKNOWN'",
        }
        actual = {
            (kind, name, table): sql
            for kind, name, table, sql in self.db.execute(
                'SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL'
            )
        }
        if actual != expected:
            raise OutboxError('DATABASE_SCHEMA')

    def _audit_snapshot(self) -> int:
        self._check_schema_snapshot()
        pinned = dict([('schema',SCHEMA),('network',self.context[0]),
                       ('parameters',self.context[1]),('genesis',self.context[2])])
        actual = dict(self.db.execute('SELECT key,value FROM q4_outbox_meta_v1'))
        if actual != pinned:
            raise OutboxError('CONTEXT_MISMATCH')
        intents = {}
        operation_ids = set()
        for ident,op_id,packet_id,wire in self.db.execute('SELECT id,operation_id,packet_id,wire FROM q4_outbox_intents_v1'):
            if type(ident) is not bytes or type(wire) is not bytes or hashlib.sha256(wire).digest() != ident:
                raise OutboxError('INTENT_CORRUPT')
            if len(wire) != len(DOMAIN) + 7*32 + 5*8 + TX_BYTES or not wire.startswith(DOMAIN):
                raise OutboxError('INTENT_GRAMMAR')
            if transaction_id(wire[-TX_BYTES:]) != packet_id:
                raise OutboxError('PACKET_ID_CORRUPT')
            cursor = len(DOMAIN)
            fields = [wire[cursor+i*32:cursor+(i+1)*32] for i in range(7)]
            cursor += 7*32
            numbers = [int.from_bytes(wire[cursor+i*8:cursor+(i+1)*8],'big') for i in range(5)]
            decoded = RenewalIntent(*fields,*numbers,wire[-TX_BYTES:])
            try:
                if decoded.wire() != wire or (decoded.network,decoded.parameters,decoded.genesis) != self.context:
                    raise OutboxError('INTENT_CONTEXT')
            except OutboxError as error:
                raise OutboxError('INTENT_GRAMMAR') from error
            if wire[len(DOMAIN):len(DOMAIN)+32] != op_id or op_id in operation_ids:
                raise OutboxError('OPERATION_ID_CORRUPT')
            operation_ids.add(op_id)
            intents[ident] = packet_id
            if len(intents) > self.max_intents: raise OutboxError('INTENT_BUDGET')
        prior = ZERO
        count = 0
        dispatch = set()
        last_generation = {}
        for ordinal, ident,kind,obs,prev,digest in self.db.execute('SELECT ordinal,intent_id,kind,observation,prev,digest FROM q4_outbox_events_v1 ORDER BY ordinal'):
            count += 1
            if count > self.max_events: raise OutboxError('EVENT_BUDGET')
            if ordinal != count or ident not in intents or prev != prior:
                raise OutboxError('EVENT_SEQUENCE')
            computed = hashlib.sha256(EVENT_DOMAIN + u64(ordinal, 'ordinal') + ident + kind.encode('ascii') + obs + prior).digest()
            if computed != digest: raise OutboxError('EVENT_DIGEST')
            if kind == 'DISPATCH_UNKNOWN':
                if ident in dispatch or obs: raise OutboxError('DISPATCH_DUPLICATE')
                dispatch.add(ident)
            elif kind.startswith('OBSERVED_'):
                if ident not in dispatch: raise OutboxError('OBSERVATION_BEFORE_DISPATCH')
                generation = _validate_observation_wire(kind, obs)
                if generation < last_generation.get(ident,0): raise OutboxError('OBSERVATION_REGRESSION')
                last_generation[ident] = generation
            else:
                raise OutboxError('UNKNOWN_EVENT')
            prior = digest
        return count

    def _event(self, ident: bytes, kind: str, obs: bytes=b'', *, fail_at: str | None=None) -> None:
        if fail_at not in (None,'before_commit','after_commit'):
            raise OutboxError('FAULT_POINT')
        if kind.startswith('OBSERVED_'):
            _validate_observation_wire(kind, obs)
        elif kind == 'DISPATCH_UNKNOWN':
            if obs: raise OutboxError('DISPATCH_DUPLICATE')
        else:
            raise OutboxError('UNKNOWN_EVENT')
        identity(ident, 'operation')
        self.db.execute('BEGIN IMMEDIATE')
        committed = False
        try:
            if self.db.execute('SELECT 1 FROM q4_outbox_intents_v1 WHERE id=?', (ident,)).fetchone() is None:
                raise OutboxError('UNKNOWN_INTENT')
            latest = self.db.execute('SELECT ordinal,digest FROM q4_outbox_events_v1 ORDER BY ordinal DESC LIMIT 1').fetchone()
            n,prev = (latest[0]+1,latest[1]) if latest else (1,ZERO)
            if n > self.max_events: raise OutboxError('EVENT_BUDGET')
            if kind == 'DISPATCH_UNKNOWN':
                if self.db.execute("SELECT 1 FROM q4_outbox_events_v1 WHERE intent_id=? AND kind='DISPATCH_UNKNOWN'",(ident,)).fetchone():
                    raise OutboxError('RECONCILE_ORIGINAL_NO_REDISPATCH')
            elif kind.startswith('OBSERVED_'):
                if self.db.execute("SELECT 1 FROM q4_outbox_events_v1 WHERE intent_id=? AND kind='DISPATCH_UNKNOWN'",(ident,)).fetchone() is None:
                    raise OutboxError('OBSERVATION_BEFORE_DISPATCH')
                last = self.db.execute("SELECT kind,observation FROM q4_outbox_events_v1 WHERE intent_id=? AND kind LIKE 'OBSERVED_%' ORDER BY ordinal DESC LIMIT 1",(ident,)).fetchone()
                # Never derive the next local generation from malformed prior
                # bytes. The last observation is re-validated INSIDE the same
                # SQLite write transaction before any new event is appended.
                if last and _validate_observation_wire(last[0], last[1]) > int.from_bytes(obs[:8],'big'):
                    raise OutboxError('OBSERVATION_REGRESSION')
            else: raise OutboxError('UNKNOWN_EVENT')
            # Preserve the original immediate-predecessor semantic error before
            # the full prefix digest verdict. Still audit the entire original
            # SQLite writer snapshot BEFORE inserting any new event.
            self._audit_snapshot()
            digest = hashlib.sha256(EVENT_DOMAIN + u64(n,'ordinal') + ident + kind.encode('ascii') + obs + prev).digest()
            self.db.execute('INSERT INTO q4_outbox_events_v1 VALUES (?,?,?,?,?,?)',(n,ident,kind,obs,prev,digest))
            if fail_at == 'before_commit': raise OutboxError('INJECTED_BEFORE_COMMIT')
            self.db.execute('COMMIT');committed = True
            if fail_at == 'after_commit': raise UnknownEffect('INJECTED_AFTER_COMMIT')
        except BaseException:
            if not committed: self.db.execute('ROLLBACK')
            raise

    def prepare(self, intent: RenewalIntent, *,fail_at: str | None=None) -> bytes:
        if intent.network != self.context[0] or intent.parameters != self.context[1] or intent.genesis != self.context[2]:
            raise OutboxError('INTENT_CONTEXT')
        wire = intent.wire()
        ident,packet = intent.digest(),intent.tx_id()
        if fail_at not in (None,'before_commit','after_commit'): raise OutboxError('FAULT_POINT')
        self.db.execute('BEGIN IMMEDIATE'); committed=False
        try:
            # Even a new unrelated operation cannot append after corrupt prior
            # durable history. This is a bounded research journal, not hot-path RPC.
            self._audit_snapshot()
            row = self.db.execute('SELECT id,wire FROM q4_outbox_intents_v1 WHERE packet_id=? OR operation_id=?',(packet,intent.operation_id)).fetchone()
            if row:
                if row != (ident,wire): raise OutboxError('SIGNED_PACKET_RENAMED')
                self.db.execute('COMMIT');committed=True
                return ident
            count = self.db.execute('SELECT COUNT(*) FROM q4_outbox_intents_v1').fetchone()[0]
            if count >= self.max_intents: raise OutboxError('INTENT_BUDGET')
            self.db.execute('INSERT INTO q4_outbox_intents_v1 VALUES (?,?,?,?)',(ident,intent.operation_id,packet,wire))
            if fail_at == 'before_commit': raise OutboxError('INJECTED_BEFORE_COMMIT')
            self.db.execute('COMMIT');committed=True
            if fail_at == 'after_commit': raise UnknownEffect('INJECTED_AFTER_COMMIT')
            return ident
        except BaseException:
            if not committed: self.db.execute('ROLLBACK')
            raise

    def dispatch_unknown(self, ident: bytes, *,fail_at: str | None=None) -> None:
        identity(ident,'operation')
        if self.db.execute('SELECT 1 FROM q4_outbox_intents_v1 WHERE id=?',(ident,)).fetchone() is None:
            raise OutboxError('UNKNOWN_INTENT')
        if self.db.execute("SELECT 1 FROM q4_outbox_events_v1 WHERE intent_id=? AND kind='DISPATCH_UNKNOWN'",(ident,)).fetchone():
            raise OutboxError('RECONCILE_ORIGINAL_NO_REDISPATCH')
        self._event(ident,'DISPATCH_UNKNOWN',fail_at=fail_at)

    def observe(self, ident: bytes, observation: ChainObservation, *,fail_at: str | None=None) -> None:
        identity(ident,'operation')
        if self.db.execute('SELECT 1 FROM q4_outbox_intents_v1 WHERE id=?',(ident,)).fetchone() is None:
            raise OutboxError('UNKNOWN_INTENT')
        dispatch = self.db.execute("SELECT 1 FROM q4_outbox_events_v1 WHERE intent_id=? AND kind='DISPATCH_UNKNOWN'",(ident,)).fetchone()
        if not dispatch: raise OutboxError('OBSERVATION_BEFORE_DISPATCH')
        wire = observation.wire()
        last = self.db.execute('SELECT observation FROM q4_outbox_events_v1 WHERE intent_id=? AND kind LIKE \'OBSERVED_%\' ORDER BY ordinal DESC LIMIT 1',(ident,)).fetchone()
        if last and int.from_bytes(last[0][:8],'big') > observation.generation:
            raise OutboxError('OBSERVATION_REGRESSION')
        kind = 'OBSERVED_' + observation.kind.upper()
        self._event(ident,kind,wire,fail_at=fail_at)

    def status(self, ident: bytes) -> dict:
        """Read intent and dispatch history in ONE SQLite read snapshot.

        This is diagnostic only. Even an empty snapshot never authorizes
        external submission: another owner may commit a dispatch immediately
        after this read transaction releases its lock.
        """
        identity(ident,'operation')
        if self.db.in_transaction:
            raise OutboxError('STATUS_REENTRANT')
        self.db.execute('BEGIN')
        try:
            # A diagnostic must not present an unaudited corrupt intent or
            # event history as a trustworthy negative dispatch observation.
            # This audit shares the SAME read snapshot as the following rows.
            self._audit_snapshot()
            row = self.db.execute(
                'SELECT packet_id,wire FROM q4_outbox_intents_v1 WHERE id=?',
                (ident,)
            ).fetchone()
            if row is None:
                raise OutboxError('UNKNOWN_INTENT')
            events = self.db.execute(
                'SELECT kind,observation FROM q4_outbox_events_v1 '
                'WHERE intent_id=? ORDER BY ordinal',
                (ident,)
            ).fetchall()
            result = {
                'intent_id': ident.hex(),
                'transaction_id': row[0].hex(),
                'dispatch_unknown': any(x[0]=='DISPATCH_UNKNOWN' for x in events),
                'last_untrusted_observation': next(
                    (x[0].replace('OBSERVED_','').lower()
                     for x in reversed(events) if x[0].startswith('OBSERVED_')),
                    None
                ),
                'observations': sum(1 for x in events if x[0].startswith('OBSERVED_')),
                'has_no_durable_dispatch_fence': len(events)==0,
            }
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        self.db.execute('ROLLBACK')
        return result
