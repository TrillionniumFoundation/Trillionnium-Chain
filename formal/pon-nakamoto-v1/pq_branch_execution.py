"""PQL1: fail-closed experimental, fork-local QTX1 state replay.

Research oracle ONLY: this is NOT M02 fork choice, M05/M06 product admission,
M07 persistence authority, W1 verification, a Node service, or a Final-use grant.
The caller-supplied genesis account roster and block timestamps are NOT independent
Chain authority. All PQL1 branches remain simulated and production flags unchanged.

This reference reuses exact genuine TPQ1/QTX1 ML-DSA-65 verification from pq_transaction;
there is no unsigned/classical fallback. Each child computes state from its *own*
immutable parent snapshot; activation is an explicit observation, not a vote or work.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3

from pq_envelope import Reject, public_key_id
from pq_transaction import (AccountView, RESEARCH_MAX_TX_BYTES, U64_MAX,
                            parse_signed_transfer, preflight_transfer)

DOMAIN = b"TRNM/PoN/PQL1/v1\x00"
MAX_TX_PER_BLOCK = 16
MAX_HISTORY = 512
MAX_BYTES = MAX_TX_PER_BLOCK * (4 + RESEARCH_MAX_TX_BYTES) + 2
SCHEMA = (
    "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), network BLOB NOT NULL, genesis BLOB NOT NULL, genesis_state BLOB NOT NULL)",
    "CREATE TABLE blocks (id BLOB PRIMARY KEY, parent BLOB NOT NULL, height INTEGER NOT NULL, stamp INTEGER NOT NULL, tx_data BLOB NOT NULL, tx_root BLOB NOT NULL, state_root BLOB NOT NULL, state_data BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE active (id INTEGER PRIMARY KEY CHECK(id=1), tip BLOB NOT NULL, generation INTEGER NOT NULL)",
)


def digest(label: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha384(DOMAIN + label + b"\x00")
    for part in parts:
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)
    return h.digest()


def u64(n: int, label: str, *, positive=False) -> int:
    if type(n) is not int or n < int(positive) or n > U64_MAX:
        raise Reject(label)
    return n


def canonical(state: dict) -> bytes:
    return json.dumps(state, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")


def state_hash(state: dict) -> bytes:
    return digest(b"state", canonical(state))


def _decode_state(value: bytes) -> dict:
    try:
        obj = json.loads(value)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise Reject("state invalid") from exc
    if not isinstance(obj, dict) or canonical(obj) != value:
        raise Reject("state noncanonical")
    return obj


def _encode_txs(txs: tuple[bytes, ...]) -> bytes:
    if type(txs) is not tuple or len(txs) > MAX_TX_PER_BLOCK:
        raise Reject("transaction batch bound")
    output = bytearray(len(txs).to_bytes(2, "big"))
    for raw in txs:
        if type(raw) is not bytes or not 1 <= len(raw) <= RESEARCH_MAX_TX_BYTES:
            raise Reject("transaction byte bound")
        output.extend(len(raw).to_bytes(4, "big"))
        output.extend(raw)
    if len(output) > MAX_BYTES:
        raise Reject("block bytes")
    return bytes(output)


def _decode_txs(raw: bytes) -> tuple[bytes, ...]:
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_BYTES:
        raise Reject("block frame size")
    count = int.from_bytes(raw[:2], "big")
    if count > MAX_TX_PER_BLOCK:
        raise Reject("too many transactions")
    p, out = 2, []
    for _ in range(count):
        if len(raw) - p < 4:
            raise Reject("truncated transaction length")
        n = int.from_bytes(raw[p:p + 4], "big")
        p += 4
        if not 1 <= n <= RESEARCH_MAX_TX_BYTES or n > len(raw) - p:
            raise Reject("transaction framing")
        out.append(raw[p:p + n]);p += n
    if p != len(raw):
        raise Reject("trailing block data")
    return tuple(out)


@dataclass(frozen=True)
class GenesisAccount:
    account: bytes
    public_pem: bytes
    balance: int
    generation: int = 1


@dataclass(frozen=True)
class Observation:
    """Pure readback: NEVER approval, chainwork, confirmed inclusion, or grant."""
    block_id: bytes
    parent: bytes
    height: int
    state_root: bytes
    tx_ids: tuple[bytes, ...]
    current_active: bool


class ResearchBranchState:
    def __init__(self, path: Path, *, network: bytes, genesis_accounts: tuple[GenesisAccount, ...],
                 expected_active_tip: bytes | None = None):
        if type(network) is not bytes or len(network) != 32 or network == bytes(32):
            raise Reject("network")
        if type(genesis_accounts) is not tuple or not 2 <= len(genesis_accounts) <= 16:
            raise Reject("genesis roster")
        self.network = network
        self.signers: dict[str, bytes] = {}
        accounts = {}
        for a in genesis_accounts:
            if not isinstance(a, GenesisAccount) or type(a.account) is not bytes or len(a.account) != 32 or a.account == bytes(32):
                raise Reject("genesis account")
            k = a.account.hex()
            if k in accounts:
                raise Reject("duplicate genesis account")
            kid = public_key_id(a.public_pem)
            if any(v["signer_key_id"] == kid.hex() for v in accounts.values()):
                raise Reject("duplicate PQ account key")
            accounts[k] = {"balance": u64(a.balance, "genesis balance"),
                           "generation": u64(a.generation, "genesis generation", positive=True),
                           "next_nonce": 1, "signer_key_id": kid.hex()}
            self.signers[k] = a.public_pem
        if sum(a["balance"] for a in accounts.values()) > U64_MAX:
            raise Reject("total genesis amount")
        self.initial = {"accounts": accounts, "fees": 0}
        self.genesis_state = canonical(self.initial)
        self.genesis = digest(b"genesis", network, state_hash(self.initial))
        path = Path(path)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise Reject("unsafe storage leaf")
        existed = path.exists()
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=10)
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        if not existed:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                for sql in SCHEMA:
                    self.db.execute(sql)
                self.db.execute("INSERT INTO metadata VALUES(1,?,?,?)", (network,self.genesis,self.genesis_state))
                self.db.execute("INSERT INTO active VALUES(1,?,1)", (self.genesis,))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        try:
            self.audit(expected_active_tip=expected_active_tip)
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _state_at(self, block: bytes) -> dict:
        if block == self.genesis:
            return _decode_state(self.genesis_state)
        row = self.db.execute("SELECT state_data,state_root FROM blocks WHERE id=?", (block,)).fetchone()
        if row is None:
            raise Reject("parent unknown")
        data, root = row
        v = _decode_state(data)
        if state_hash(v) != root:
            raise Reject("stored state hash mismatch")
        return v

    def _head(self, block: bytes) -> tuple[int, int]:
        if block == self.genesis:
            return 0, 0
        row = self.db.execute("SELECT height,stamp FROM blocks WHERE id=?", (block,)).fetchone()
        if row is None:
            raise Reject("unknown branch")
        return row

    def active(self) -> tuple[bytes, int]:
        row = self.db.execute("SELECT tip,generation FROM active WHERE id=1").fetchone()
        if row is None:
            raise Reject("missing active generation")
        return row

    def balances(self, block: bytes) -> dict[str, int]:
        return {k:v["balance"] for k,v in self._state_at(block)["accounts"].items()}

    def _execute(self, parent: bytes, stamp: int, txs: tuple[bytes, ...]) -> tuple[dict, tuple[bytes, ...]]:
        u64(stamp, "timestamp", positive=True)
        _, parent_stamp = self._head(parent)
        if stamp <= parent_stamp:
            raise Reject("timestamp not monotonic on branch")
        state = self._state_at(parent)
        original_total = sum(x["balance"] for x in state["accounts"].values()) + state["fees"]
        ids: list[bytes] = []
        for raw in txs:
            t,_,_ = parse_signed_transfer(raw)
            if t.network != self.network:
                raise Reject("wrong network")
            account_id = t.sender.hex()
            sender = state["accounts"].get(account_id)
            recipient = state["accounts"].get(t.recipient.hex())
            if sender is None or recipient is None:
                raise Reject("unknown account (no implicit key registration)")
            key = self.signers[account_id]
            observation = preflight_transfer(raw, public_pem=key,
                account=AccountView(self.network, t.sender, bytes.fromhex(sender["signer_key_id"]),
                                    sender["generation"], sender["next_nonce"], sender["balance"], True),
                now=stamp, base_fee=100, byte_fee=1)
            if observation.identity in ids:
                raise Reject("repeated logical transaction")
            if sender["next_nonce"] == U64_MAX or state["fees"] > U64_MAX - observation.required_fee:
                raise Reject("nonce/fees overflow")
            if recipient["balance"] > U64_MAX - t.amount:
                raise Reject("recipient overflow")
            sender["balance"] = observation.remaining_units
            sender["next_nonce"] += 1
            recipient["balance"] += t.amount
            state["fees"] += observation.required_fee
            ids.append(observation.identity)
        if sum(x["balance"] for x in state["accounts"].values()) + state["fees"] != original_total:
            raise Reject("balance conservation")
        return state, tuple(ids)

    def _assert_schema(self) -> None:
        """Reject a post-open trigger, index, table or view BEFORE any state write."""
        def ddl(conn):
            return conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name").fetchall()
        reference = sqlite3.connect(":memory:")
        try:
            for sql in SCHEMA:
                reference.execute(sql)
            if ddl(self.db) != ddl(reference):
                raise Reject("foreign or downgraded SQLite DDL")
        finally:
            reference.close()

    def _validate_parent_path(self, parent: bytes) -> None:
        """Recheck exact signed ancestors; hashes alone are not a trusted store owner."""
        if parent == self.genesis:
            return
        path, visited = [], set()
        current = parent
        while current != self.genesis:
            if current in visited or len(path) >= MAX_HISTORY:
                raise Reject("parent cycle/depth")
            visited.add(current)
            row = self.db.execute(
                "SELECT id,parent,height,stamp,tx_data,tx_root,state_root,state_data FROM blocks WHERE id=?",
                (current,)).fetchone()
            if row is None:
                raise Reject("missing ancestor")
            path.append(row)
            current = row[1]
        prior_height, prior_stamp = 0, 0
        for block,par,height,stamp,tx_data,txroot,root,encoded_state in reversed(path):
            if height != prior_height + 1 or stamp <= prior_stamp:
                raise Reject("parent height or time")
            state,ids = self._execute(par,stamp,_decode_txs(tx_data))
            computed_txroot=digest(b"txids",len(ids).to_bytes(2,"big"),*ids)
            computed_state=state_hash(state)
            expected_id=digest(b"block",par,height.to_bytes(8,"big"),
                               stamp.to_bytes(8,"big"),computed_txroot,computed_state)
            if (txroot != computed_txroot or root != computed_state or block != expected_id
                    or encoded_state != canonical(state)):
                raise Reject("parent signed replay mismatch")
            prior_height, prior_stamp = height,stamp

    def admit(self, parent: bytes, stamp: int, txs: tuple[bytes, ...]) -> Observation:
        if type(parent) is not bytes or len(parent) != 48:
            raise Reject("parent id")
        encoded = _encode_txs(txs)
        # Atomic parent read / verification / persisted result. This is an expensive
        # research oracle, not a production hot-path or an authorized consensus result.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._assert_schema()
            self._validate_parent_path(parent)
            if self.db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] >= MAX_HISTORY:
                raise Reject("bounded research history")
            height, _ = self._head(parent)
            if height >= 2 ** 63 - 1:
                raise Reject("height bound")
            state, ids = self._execute(parent, stamp, txs)
            tx_root = digest(b"txids", len(ids).to_bytes(2,"big"), *ids)
            root = state_hash(state)
            block_id = digest(b"block", parent, (height+1).to_bytes(8,"big"), stamp.to_bytes(8,"big"), tx_root, root)
            previous = self.db.execute("SELECT parent,height,stamp,tx_root,state_root FROM blocks WHERE id=?", (block_id,)).fetchone()
            if previous is not None:
                if previous != (parent,height+1,stamp,tx_root,root):
                    raise Reject("block collision")
            else:
                self.db.execute("INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?)",
                    (block_id,parent,height+1,stamp,encoded,tx_root,root,canonical(state)))
            tip,_ = self.active()
            self.db.execute("COMMIT")
            return Observation(block_id, parent, height+1, root, ids, tip==block_id)
        except BaseException:
            if self.db.in_transaction:self.db.execute("ROLLBACK")
            raise

    def observe_selected_tip(self, block: bytes, *, expected_prior: bytes) -> int:
        """Simulate an EXTERNAL branch decision; no fork-choice/work authority supplied."""
        if type(expected_prior) is not bytes or len(expected_prior)!=48:
            raise Reject("prior tip")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._assert_schema()
            self._validate_parent_path(block)
            current,generation=self.active()
            if current!=expected_prior:
                raise Reject("observed tip stale")
            self._state_at(block)
            if block == current:
                self.db.execute("COMMIT");return generation
            if generation >= 2**63 - 1:
                raise Reject("generation exhausted")
            self.db.execute("UPDATE active SET tip=?,generation=? WHERE id=1",(block,generation+1))
            self.db.execute("COMMIT");return generation+1
        except BaseException:
            if self.db.in_transaction:self.db.execute("ROLLBACK")
            raise

    def audit(self, *, expected_active_tip: bytes | None = None) -> None:
        """Rebuild every research branch from verified PQ bytes on one pinned read snapshot."""
        self.db.execute("BEGIN")
        try:
            self._assert_schema()
            meta=self.db.execute("SELECT id,network,genesis,genesis_state FROM metadata").fetchall()
            if meta != [(1,self.network,self.genesis,self.genesis_state)]:
                raise Reject("genesis anchor changed")
            rows=self.db.execute("SELECT id,parent,height,stamp,tx_data,tx_root,state_root,state_data FROM blocks ORDER BY height,id").fetchall()
            if len(rows)>MAX_HISTORY:
                raise Reject("history bound")
            current_records = {}
            for block,parent,height,stamp,tx_data,tx_root,root,serialized in rows:
                prev_height,prev_stamp=(0,0) if parent==self.genesis else current_records.get(parent,(None,None))
                if prev_height is None or height != prev_height+1 or stamp<=prev_stamp:
                    raise Reject("broken ancestry")
                txs=_decode_txs(tx_data)
                rebuilt,ids=self._execute(parent,stamp,txs)
                check_tx=digest(b"txids",len(ids).to_bytes(2,"big"),*ids)
                check_root=state_hash(rebuilt)
                check_id=digest(b"block",parent,height.to_bytes(8,"big"),stamp.to_bytes(8,"big"),check_tx,check_root)
                if check_tx!=tx_root or check_root!=root or block!=check_id or serialized!=canonical(rebuilt):
                    raise Reject("signed history/state mismatch")
                current_records[block]=(height,stamp)
            tip, generation=self.active()
            if tip != self.genesis and tip not in current_records:
                raise Reject("active tip missing")
            if type(generation) is not int or generation<=0 or generation>2**63-1:
                raise Reject("active generation")
            if expected_active_tip is not None and tip!=expected_active_tip:
                raise Reject("pinned active tip mismatch")
        finally:
            self.db.execute("ROLLBACK")
