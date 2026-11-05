"""PQL3: crash-atomic fork/reorg reference over independently pinned PQL2 bytes.

RESEARCH / HOLD_NO_GO. No signatures or old-chain history are verified here.
No native Chain owner, transaction admission, fork choice, VerifiedWork, spend,
liability settlement, remote operation, or Hepta FinalUse is implemented. Caller
must independently authenticate the PQG1 source, PQS1 projection, PQL2 root and
all cryptographic ownership before any eventual product migration.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
from dataclasses import dataclass

PQL2_DOMAIN = b"TRNM/PQ/PQL2State/v1\x00"
NODE_DOMAIN = b"TRNM/PQ/PQL3NonceSnapshot/v1\x00"
MAX_ACCOUNT = 128
MAX_LIABILITY = 256
MAX_BYTES = 65536
MAX_U64 = (1 << 64) - 1
MAX_SQL_INT = (1 << 63) - 1
ZERO32 = bytes(32)
ZERO48 = bytes(48)
SCHEMA = {
    "meta": "CREATE TABLE meta (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL) WITHOUT ROWID",
    "nodes": "CREATE TABLE nodes (id BLOB PRIMARY KEY NOT NULL, parent BLOB NOT NULL, height INTEGER NOT NULL, account_idx INTEGER NOT NULL, op BLOB NOT NULL, nonces BLOB NOT NULL) WITHOUT ROWID",
    "active": "CREATE TABLE active (slot INTEGER PRIMARY KEY CHECK(slot=1), tip BLOB NOT NULL, generation INTEGER NOT NULL)",
    "effects": "CREATE TABLE effects (op BLOB PRIMARY KEY NOT NULL, tip BLOB NOT NULL) WITHOUT ROWID",
}

class Reject(ValueError):
    pass


def b(v, n, name, *, nonzero=False):
    if type(v) is not bytes or len(v) != n or (nonzero and v == bytes(n)):
        raise Reject(name)
    return v


def u64(v, name):
    if type(v) is not int or not 0 <= v <= MAX_U64:
        raise Reject(name)
    return v.to_bytes(8, "big")


def framed(domain, content):
    return hashlib.sha384(domain + len(content).to_bytes(8, "big") + content).digest()


def digest_node(pql2_root, parent, height, idx, op, nonces):
    return framed(NODE_DOMAIN, pql2_root + parent + u64(height, "height")
                  + (idx + 1).to_bytes(2, "big") + op + nonces)


@dataclass(frozen=True)
class Account:
    status: int
    account_id: bytes
    pq_key_id: bytes
    old_key: bytes
    balance: int
    nonce_floor: int
    original_generation: int
    generation: int


@dataclass(frozen=True)
class ImportView:
    """No authorization; inspect only externally authenticated immutable PQL2 bytes."""
    state: bytes
    root: bytes
    source_digest: bytes
    genesis_id: bytes
    accounts: tuple[Account, ...]
    liabilities: tuple[bytes, ...]
    issued: int
    quarantine: int
    locked: int

    @property
    def original_nonces(self):
        return b"".join(u64(a.nonce_floor, "nonce") for a in self.accounts)


def check_import(raw, *, expected_root, expected_source_digest, expected_genesis_id,
                 expected_network, expected_profile, expected_old_head,
                 expected_withdrawal_head, expected_issued):
    """Fail closed on all 129-byte account and 81-byte liability identities.

    Expected pins MUST come from an independently admitted, trusted source, never
    from the raw input or a peer-controlled manifest. Re-hashed forged anchors are
    deliberately outside this reference's ability to detect.
    """
    b(raw, len(raw) if type(raw) is bytes else -1, "PQL2 type")
    for name, value, length in (("root", expected_root, 48),
                                ("source", expected_source_digest, 48),
                                ("genesis", expected_genesis_id, 48),
                                ("network", expected_network, 32),
                                ("profile", expected_profile, 32),
                                ("old head", expected_old_head, 32),
                                ("withdrawal", expected_withdrawal_head, 32)):
        b(value, length, name, nonzero=True)
    u64(expected_issued, "expected issued")
    if not 231 + 129 + 2 + 24 <= len(raw) <= MAX_BYTES or raw[:5] != b"PQL2\x01":
        raise Reject("PQL2 length/version")
    if (framed(PQL2_DOMAIN, raw) != expected_root or raw[5:37] != expected_network
            or raw[37:69] != expected_profile or raw[69:101] != expected_old_head
            or raw[101:133] != expected_withdrawal_head
            or raw[133:181] != expected_source_digest
            or raw[181:229] != expected_genesis_id):
        raise Reject("independent pin/context mismatch")
    count = int.from_bytes(raw[229:231], "big")
    if not 1 <= count <= MAX_ACCOUNT:
        raise Reject("account count")
    pos = 231
    accounts, old_keys, new_keys, account_ids = [], [], set(), set()
    spendable = quarantined = 0
    for _ in range(count):
        row = raw[pos:pos + 129]
        if len(row) != 129:
            raise Reject("account truncated")
        status, aid, pqid, old = row[0], row[1:33], row[33:65], row[65:97]
        balance = int.from_bytes(row[97:105], "big")
        nonce = int.from_bytes(row[105:113], "big")
        original_gen = int.from_bytes(row[113:121], "big")
        gen = int.from_bytes(row[121:129], "big")
        if (status not in (0, 1) or old == ZERO32 or nonce == 0
                or original_gen == 0 or original_gen == MAX_U64 or gen != original_gen + 1):
            raise Reject("account fields/nonce/generation")
        if old_keys and old <= old_keys[-1]:
            raise Reject("old account order/uniqueness")
        old_keys.append(old)
        if status == 0:
            if pqid != ZERO32:
                raise Reject("quarantined account has a signer")
            intended = hashlib.sha256(b"TRNM/PQ/Quarantine/v1\x00" + expected_network + old).digest()
            quarantined += balance
        else:
            if pqid == ZERO32 or pqid in new_keys:
                raise Reject("PQ signer absent/reused")
            new_keys.add(pqid)
            intended = hashlib.sha256(b"TRNM/PQ/Account/v1\x00" + expected_network + old + pqid).digest()
            spendable += balance
        if aid != intended or aid in account_ids:
            raise Reject("derived account identity/duplicate")
        account_ids.add(aid)
        accounts.append(Account(status, aid, pqid, old, balance, nonce, original_gen, gen))
        pos += 129
    if pos + 2 > len(raw):
        raise Reject("liability count missing")
    lc = int.from_bytes(raw[pos:pos+2], "big")
    pos += 2
    if lc > MAX_LIABILITY or len(raw) != pos + lc * 81 + 24:
        raise Reject("liability frame/size")
    liabilities, liability_ids, locked = [], [], 0
    for _ in range(lc):
        row = raw[pos:pos+81]
        lid, owner = row[:32], row[32:64]
        amount = int.from_bytes(row[64:72], "big")
        if (lid == ZERO32 or owner not in old_keys or amount == 0
                or row[80] not in (1,2,3,4)
                or (liability_ids and lid <= liability_ids[-1])):
            raise Reject("liability identity/owner/kind/amount")
        liability_ids.append(lid)
        liabilities.append(row)
        locked += amount
        pos += 81
    issued = int.from_bytes(raw[pos:pos+8], "big")
    quarantined_claim = int.from_bytes(raw[pos+8:pos+16], "big")
    locked_claim = int.from_bytes(raw[pos+16:pos+24], "big")
    if (issued != expected_issued or quarantined != quarantined_claim
            or locked != locked_claim or spendable + quarantined + locked != issued
            or any(v > MAX_U64 for v in (spendable, quarantined, locked))):
        raise Reject("issued/quarantined/locked conservation")
    return ImportView(raw, expected_root, expected_source_digest, expected_genesis_id,
                      tuple(accounts), tuple(liabilities), issued, quarantined, locked)


class ResearchForkStore:
    """Reference simulation only: never treats branch choice as consensus authority."""
    def __init__(self, path: Path, imported: ImportView):
        if not isinstance(path, Path) or not isinstance(imported, ImportView):
            raise Reject("path/import type")
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise Reject("untrusted DB leaf")
        self.imported = imported
        self.root = imported.root
        self.genesis = digest_node(self.root, ZERO48, 0, -1, ZERO32, imported.original_nonces)
        existed = path.exists()
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        try:
            self.db.execute("PRAGMA busy_timeout=10000")
            # Refuse an alien existing namespace BEFORE a writable PRAGMA or DDL.
            if existed:
                known = self.db.execute("SELECT name,type,sql FROM sqlite_master ORDER BY name").fetchall()
                if known != sorted((name,"table",sql) for name,sql in SCHEMA.items()):
                    raise Reject("foreign database schema before mutation")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            if not existed:
                # A new DB is a local reference object, not an existing chain namespace.
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    for create in SCHEMA.values(): self.db.execute(create)
                    self.db.executemany("INSERT INTO meta VALUES (?,?)",
                                        (("import", self.root), ("genesis", self.genesis)))
                    self.db.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?)",
                                    (self.genesis, ZERO48, 0, -1, ZERO32, imported.original_nonces))
                    self.db.execute("INSERT INTO active VALUES (1,?,1)", (self.genesis,))
                    self.db.execute("COMMIT")
                except BaseException:
                    self.db.execute("ROLLBACK")
                    raise
            self.audit()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def audit(self):
        """Cold or concurrent read uses ONE snapshot; never mixes two DB generations."""
        self.db.execute("BEGIN")
        try:
            actual = self.db.execute("SELECT name,type,sql FROM sqlite_master ORDER BY name").fetchall()
            expected = sorted((name,"table",sql) for name,sql in SCHEMA.items())
            if actual != expected:
                raise Reject("schema/trigger/view/index substitution")
            meta = self.db.execute("SELECT key,value FROM meta ORDER BY key").fetchall()
            if meta != [("genesis",self.genesis),("import",self.root)]:
                raise Reject("external import/genesis pin mismatch")
            nodes = self.db.execute("SELECT id,parent,height,account_idx,op,nonces FROM nodes ORDER BY height,id").fetchall()
            if not 1 <= len(nodes) <= 32768:
                raise Reject("bounded branch node history")
            visited = {}
            for nid,parent,h,idx,op,nonces in nodes:
                if (type(h) is not int or not 0 <= h <= MAX_SQL_INT
                        or type(idx) is not int or type(op) is not bytes or len(op) != 32
                        or type(nonces) is not bytes or len(nonces) != len(self.imported.accounts)*8
                        or nid != digest_node(self.root,parent,h,idx,op,nonces)):
                    raise Reject("branch hash/bytes invalid")
                if h == 0:
                    if (nid != self.genesis or parent != ZERO48 or idx != -1 or op != ZERO32
                            or nonces != self.imported.original_nonces):
                        raise Reject("genesis reset/foreign")
                else:
                    if parent not in visited or visited[parent][0] != h-1 or not 0 <= idx < len(self.imported.accounts):
                        raise Reject("branch parent/height/account")
                    prev = visited[parent][1]
                    if self.imported.accounts[idx].status != 1:
                        raise Reject("quarantined identity advanced")
                    v = int.from_bytes(prev[idx*8:idx*8+8], "big")
                    if v == MAX_U64 or nonces != prev[:idx*8] + (v+1).to_bytes(8,"big") + prev[(idx+1)*8:]:
                        raise Reject("nonce floor/branch transition changed")
                visited[nid] = (h,nonces)
            tip = self.db.execute("SELECT tip,generation FROM active WHERE slot=1").fetchall()
            if len(tip)!=1 or tip[0][0] not in visited or not 1 <= tip[0][1] <= MAX_SQL_INT:
                raise Reject("active pointer/generation")
            ops = self.db.execute("SELECT op,tip FROM effects ORDER BY op").fetchall()
            if any(op == ZERO32 or t not in visited for op,t in ops):
                raise Reject("effect evidence corrupt")
            return tip[0]
        finally:
            if self.db.in_transaction: self.db.execute("ROLLBACK")

    def active(self):
        return self.audit()

    def simulate_append(self, parent: bytes, account_idx: int, op: bytes):
        """Hypothetical already-validated transaction's nonce effect, no signature/fee/spend."""
        b(parent,48,"parent")
        b(op,32,"simulation op",nonzero=True)
        if type(account_idx) is not int or not 0 <= account_idx < len(self.imported.accounts):
            raise Reject("account index")
        if self.imported.accounts[account_idx].status != 1:
            raise Reject("quarantined/old signer cannot advance")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._assert_schema()
            result=self.db.execute("SELECT height,nonces FROM nodes WHERE id=?", (parent,)).fetchone()
            if result is None or result[0]>=MAX_SQL_INT:
                raise Reject("parent unknown/height overflow")
            if self.db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] >= 32768:
                raise Reject("branch node history full")
            height, previous = result
            number=int.from_bytes(previous[account_idx*8:(account_idx+1)*8],"big")
            if number == MAX_U64:
                raise Reject("nonce overflow")
            updated=(previous[:account_idx*8]+(number+1).to_bytes(8,"big")
                     +previous[(account_idx+1)*8:])
            identity=digest_node(self.root,parent,height+1,account_idx,op,updated)
            prior=self.db.execute("SELECT parent,height,account_idx,op,nonces FROM nodes WHERE id=?",(identity,)).fetchone()
            if prior is None:
                self.db.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?)",
                                (identity,parent,height+1,account_idx,op,updated))
            elif prior != (parent,height+1,account_idx,op,updated):
                raise Reject("node identity collision/substitution")
            self.db.execute("COMMIT")
            return identity
        except BaseException:
            if self.db.in_transaction:self.db.execute("ROLLBACK")
            raise

    def _assert_schema(self):
        actual=self.db.execute("SELECT name,type,sql FROM sqlite_master ORDER BY name").fetchall()
        if actual != sorted((name,"table",sql) for name,sql in SCHEMA.items()):
            raise Reject("foreign schema")
        pins=self.db.execute("SELECT key,value FROM meta ORDER BY key").fetchall()
        if pins != [("genesis",self.genesis),("import",self.root)]:
            raise Reject("metadata pin changed post-open")

    def simulate_choose_tip(self, proposed_tip: bytes, *, expected_generation: int):
        """External branch-choice observation, never local work/finality decision."""
        b(proposed_tip,48,"candidate tip")
        if type(expected_generation) is not int or not 1 <= expected_generation < MAX_SQL_INT:
            raise Reject("expected generation")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._assert_schema()
            tip,gen=self.db.execute("SELECT tip,generation FROM active WHERE slot=1").fetchone()
            if gen != expected_generation:
                raise Reject("stale branch generation")
            if self.db.execute("SELECT 1 FROM nodes WHERE id=?",(proposed_tip,)).fetchone() is None:
                raise Reject("unknown candidate branch")
            if tip != proposed_tip:
                self.db.execute("UPDATE active SET tip=?,generation=? WHERE slot=1",
                                (proposed_tip,gen+1))
            self.db.execute("COMMIT")
            return gen if tip == proposed_tip else gen+1
        except BaseException:
            if self.db.in_transaction:self.db.execute("ROLLBACK")
            raise

    def observe_irreversible_effect(self, operation: bytes):
        """An append-only local observation, not permission to execute any effect."""
        b(operation,32,"operation",nonzero=True)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._assert_schema()
            tip=self.db.execute("SELECT tip FROM active WHERE slot=1").fetchone()[0]
            previous=self.db.execute("SELECT tip FROM effects WHERE op=?",(operation,)).fetchone()
            if previous is not None:
                self.db.execute("COMMIT")
                return "ALREADY_OBSERVED"
            self.db.execute("INSERT INTO effects VALUES (?,?)",(operation,tip))
            self.db.execute("COMMIT")
            return "FIRST_OBSERVATION"
        except BaseException:
            if self.db.in_transaction:self.db.execute("ROLLBACK")
            raise

    def inspect_nonces(self, node: bytes):
        b(node,48,"node")
        row=self.db.execute("SELECT nonces FROM nodes WHERE id=?",(node,)).fetchone()
        if row is None:raise Reject("unknown node")
        return tuple(int.from_bytes(row[0][8*i:8*i+8],"big") for i in range(len(self.imported.accounts)))

    def inspect_liabilities(self):
        return self.imported.liabilities
