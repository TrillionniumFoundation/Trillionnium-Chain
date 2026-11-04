"""PQL5 research-only: three independently keyed, durable PQL4 frontier witnesses.

This is NOT a non-rollbackable quorum, chain authority, HSM, finality or FinalUse.
All expected network/import/genesis/observer/roster trust originates outside this module.
An attacker controlling two witness stores and their credentials can still rewind quorum.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from pq_openssl_backend import BackendError, run as run_pinned_openssl

PREFIX = b"TRNM/PQ/PQL5Witness/v1\0"
PQL4_SIGN = b"TRNM/PQ/PQL4SignedFrontier/v1\0"
PQL4_ID = b"TRNM/PQ/PQL4FrontierId/v1\0"
KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\0"
OID = bytes.fromhex("0609608648016503040312")
PQL4_UNSIGNED = 336
PQL4_SIGNED = 3647
SIG_SIZE = 3309
RESP_UNSIGNED = 269
RESP_SIGNED = RESP_UNSIGNED + 2 + SIG_SIZE
ZERO48 = bytes(48)
MAX_EVENTS = 4096
SCHEMA = {
    "pins": "CREATE TABLE pins (slot INTEGER PRIMARY KEY CHECK(slot=1), network BLOB NOT NULL, import_root BLOB NOT NULL, genesis BLOB NOT NULL, observer BLOB NOT NULL, witness BLOB NOT NULL)",
    "events": "CREATE TABLE events (seq INTEGER PRIMARY KEY NOT NULL, fid BLOB NOT NULL, signed_frame BLOB NOT NULL)",
}

class Reject(ValueError):
    pass


def exact(v, n, label, nonzero=False):
    if type(v) is not bytes or len(v) != n or (nonzero and v == bytes(n)):
        raise Reject(label)
    return v


def u64(v, label, nonzero=False):
    if type(v) is not int or not int(nonzero) <= v < 1 << 64:
        raise Reject(label)
    return v.to_bytes(8, "big")


def run(argv):
    if not argv or argv[0] != "openssl":
        raise Reject("PQ OpenSSL command shape")
    try:
        return run_pinned_openssl(argv[1:])
    except BackendError as exc:
        raise Reject(str(exc)) from exc


def der_length(b, i):
    if i >= len(b): raise Reject("DER truncated")
    f = b[i]
    if f < 128: return f, i+1
    n = f & 127
    if not 1 <= n <= 4 or i+1+n > len(b): raise Reject("DER length")
    value = int.from_bytes(b[i+1:i+1+n], "big")
    if value < 128 or b[i+1] == 0: raise Reject("DER noncanonical")
    return value, i+1+n


def key_id(pem):
    if type(pem) is not bytes or not 0 < len(pem) <= 16384: raise Reject("public key PEM")
    with tempfile.TemporaryDirectory(prefix="pql5-public-") as d:
        p = Path(d)/"public.pem"; p.write_bytes(pem)
        der = run(["openssl", "pkey", "-pubin", "-in", str(p), "-outform", "DER"])
    if not der or der[0] != 0x30: raise Reject("SPKI tag")
    outer, a = der_length(der, 1)
    if a + outer != len(der) or der[a] != 0x30: raise Reject("SPKI outer")
    alg, b = der_length(der, a+1)
    if der[b:b+alg] != OID: raise Reject("ML-DSA-65 key mandatory")
    pos = b+alg
    if pos >= len(der) or der[pos] != 3: raise Reject("SPKI BIT STRING")
    n, off = der_length(der, pos+1)
    if n != 1953 or off+n != len(der) or der[off] != 0: raise Reject("ML-DSA key length")
    return hashlib.sha256(KEY_DOMAIN + der).digest()


def verify_sig(pub, msg, signature):
    exact(signature, SIG_SIZE, "signature")
    with tempfile.TemporaryDirectory(prefix="pql5-verify-") as d:
        p = Path(d)
        (p/"pub").write_bytes(pub)
        (p/"msg").write_bytes(msg)
        (p/"sig").write_bytes(signature)
        run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(p/"pub"),
             "-rawin", "-in", str(p/"msg"), "-sigfile", str(p/"sig")])


def sign_fixture(secret, msg):
    """Local development key ONLY; never wire this subprocess to a production endpoint."""
    with tempfile.TemporaryDirectory(prefix="pql5-sign-") as d:
        p = Path(d); (p/"msg").write_bytes(msg)
        run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", os.fspath(secret),
             "-in", str(p/"msg"), "-out", str(p/"sig")])
        return exact((p/"sig").read_bytes(), SIG_SIZE, "real signature")


@dataclass(frozen=True)
class PQL4Head:
    network: bytes
    import_root: bytes
    genesis: bytes
    tip: bytes
    generation: int
    sequence: int
    previous: bytes
    snapshot_digest: bytes
    observer_id: bytes
    frontier_id: bytes


def parse_pql4(frame, observer_pub, *, now=None):
    if type(frame) is not bytes or len(frame) != PQL4_SIGNED:
        raise Reject("PQL4 signed length")
    raw = frame[:PQL4_UNSIGNED]
    if raw[:8] != b"PQL4\x01\x65\x00\x00" or frame[336:338] != SIG_SIZE.to_bytes(2,"big"):
        raise Reject("PQL4 grammar or PQ-only algorithm")
    network, root, genesis, tip = raw[8:40], raw[40:88], raw[88:136], raw[136:184]
    generation, seq = int.from_bytes(raw[184:192],"big"), int.from_bytes(raw[192:200],"big")
    previous, digest = raw[200:248], raw[248:296]
    expiry = int.from_bytes(raw[296:304], "big")
    observer = raw[304:336]
    if (network == bytes(32) or root == ZERO48 or genesis == ZERO48 or tip == ZERO48
            or digest == ZERO48 or generation == 0 or seq == 0 or expiry == 0
            or observer != key_id(observer_pub)):
        raise Reject("PQL4 zero or observer mismatch")
    if now is not None and (type(now) is not int or not 0 <= now < 1<<64 or now > expiry):
        raise Reject("PQL4 expired")
    verify_sig(observer_pub, PQL4_SIGN+raw, frame[338:])
    return PQL4Head(network, root, genesis, tip, generation, seq, previous, digest,
                    observer, hashlib.sha384(PQL4_ID+raw).digest())


@dataclass(frozen=True)
class WitnessHead:
    sequence: int
    frontier_id: bytes


class LocalWitness:
    """A single local SQLite signer. Different files != independent custodians."""
    def __init__(self, path, *, network, import_root, genesis, observer_pub, witness_pub):
        self.network = exact(network, 32, "network", True)
        self.root = exact(import_root, 48, "import root", True)
        self.genesis = exact(genesis, 48, "genesis", True)
        self.observer_pub = observer_pub
        self.observer_id = key_id(observer_pub)
        self.witness_id = key_id(witness_pub)
        path = Path(path)
        if not path.is_absolute() or path.is_symlink(): raise Reject("witness owned file")
        fresh = not path.exists()
        if path.exists() and not stat.S_ISREG(path.lstat().st_mode): raise Reject("witness file kind")
        self.path = path
        self.db = sqlite3.connect(path, isolation_level=None, timeout=10)
        try:
            leaf = os.lstat(path)
            if not stat.S_ISREG(leaf.st_mode):
                raise Reject("witness inode is not regular")
            self._inode = (leaf.st_dev, leaf.st_ino)
            if not fresh:
                self.db.execute("BEGIN")
                try: self._audit()  # verify before ANY writable PRAGMA
                finally: self.db.execute("ROLLBACK")
            self.db.execute("PRAGMA busy_timeout=10000")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            if fresh:
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    for sql in SCHEMA.values(): self.db.execute(sql)
                    self.db.execute("INSERT INTO pins VALUES (1,?,?,?,?,?)",
                                    (self.network,self.root,self.genesis,self.observer_id,self.witness_id))
                    self.db.execute("COMMIT")
                except BaseException:
                    if self.db.in_transaction: self.db.execute("ROLLBACK")
                    raise
            self.db.execute("BEGIN")
            try: self._audit()
            finally: self.db.execute("ROLLBACK")
        except BaseException:
            self.db.close()
            raise

    def close(self): self.db.close()

    def _audit(self):
        schema = self.db.execute("SELECT name,type,sql FROM sqlite_master ORDER BY name").fetchall()
        if schema != sorted((name,"table",sql) for name,sql in SCHEMA.items()):
            raise Reject("foreign witness DDL")
        # Per-connection TEMP triggers/tables do not appear in sqlite_master.
        # Both signed observation and append must reject namespace shadowing.
        if self.db.execute("SELECT name FROM sqlite_temp_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").fetchone():
            raise Reject("temporary witness SQLite schema forbidden")
        try:
            leaf = os.lstat(self.path)
        except FileNotFoundError:
            raise Reject("witness journal disappeared") from None
        if not stat.S_ISREG(leaf.st_mode) or (leaf.st_dev, leaf.st_ino) != self._inode:
            raise Reject("witness journal inode replaced")
        pins = self.db.execute("SELECT slot,network,import_root,genesis,observer,witness FROM pins").fetchall()
        if pins != [(1,self.network,self.root,self.genesis,self.observer_id,self.witness_id)]:
            raise Reject("witness context substitution")
        rows = self.db.execute("SELECT seq,fid,signed_frame FROM events ORDER BY seq").fetchall()
        if len(rows) > MAX_EVENTS: raise Reject("witness history bound")
        prior = ZERO48
        generation = 0
        observed_ids = set()
        for expected,(seq,fid,frame) in enumerate(rows,1):
            head = parse_pql4(frame,self.observer_pub)  # historical expiry is not re-evaluated
            if (seq != expected or fid in observed_ids or fid != head.frontier_id or head.sequence != expected
                    or head.previous != prior or head.generation < generation
                    or (head.network,head.import_root,head.genesis) !=
                       (self.network,self.root,self.genesis)):
                raise Reject("witness monotone history corrupted")
            observed_ids.add(fid)
            prior, generation = fid, head.generation
        return WitnessHead(len(rows),prior)

    def _acknowledge_committed_head(self, candidate):
        """A committed append on a detached inode is UNKNOWN, never accepted."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            persisted = self._audit()
            if (persisted.sequence, persisted.frontier_id) != (
                    candidate.sequence, candidate.frontier_id):
                raise Reject("witness committed head readback mismatch")
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        try:
            leaf = os.lstat(self.path)
        except FileNotFoundError:
            raise Reject("witness journal disappeared before ACK") from None
        if (leaf.st_dev, leaf.st_ino) != self._inode:
            raise Reject("witness journal replaced before ACK")

    def append(self, pql4_signed, *, now):
        candidate = parse_pql4(pql4_signed,self.observer_pub,now=now)
        if (candidate.network,candidate.import_root,candidate.genesis) != (
                self.network,self.root,self.genesis):
            raise Reject("different checkpoint network/import/genesis")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self._audit()
            if candidate.sequence == prior.sequence and candidate.frontier_id == prior.frontier_id:
                self.db.execute("COMMIT")
                self._acknowledge_committed_head(candidate)
                return "ALREADY_RECORDED"
            if (candidate.sequence != prior.sequence+1 or candidate.previous != prior.frontier_id
                    or prior.sequence >= MAX_EVENTS):
                raise Reject("stale, conflicting or skipped frontier")
            self.db.execute("INSERT INTO events VALUES (?,?,?)",
                            (candidate.sequence,candidate.frontier_id,pql4_signed))
            self.db.execute("COMMIT")
            self._acknowledge_committed_head(candidate)
            return "FIRST_RECORD"
        except BaseException:
            if self.db.in_transaction: self.db.execute("ROLLBACK")
            raise

    def observe(self, *, challenge, now, witness_pub, witness_secret):
        challenge = exact(challenge,32,"fresh challenge",True)
        wid = key_id(witness_pub)
        if wid != self.witness_id: raise Reject("untrusted local witness key")
        if type(now) is not int or not 0 <= now < (1<<64)-30: raise Reject("witness time")
        self.db.execute("BEGIN")
        try: head = self._audit()
        finally: self.db.execute("ROLLBACK")
        # Caller MUST separately provision witness keys and independently verify roster.
        unsigned = (b"PQL5"+b"\x01"+wid+self.network+self.root+self.genesis
                    +u64(head.sequence,"witness sequence")+head.frontier_id
                    +challenge+u64(now,"now")+u64(now+30,"expiry"))
        if len(unsigned) != RESP_UNSIGNED: raise Reject("witness codec")
        sig = sign_fixture(witness_secret,PREFIX+unsigned)
        return unsigned+SIG_SIZE.to_bytes(2,"big")+sig


def verify_fresh_response(frame, *, witness_pub, expected_key_id, network, root, genesis,
                          challenge, now):
    if type(frame) is not bytes or len(frame) != RESP_SIGNED: raise Reject("witness reply length")
    raw = frame[:RESP_UNSIGNED]
    if raw[:5] != b"PQL5\x01" or frame[RESP_UNSIGNED:RESP_UNSIGNED+2] != SIG_SIZE.to_bytes(2,"big"):
        raise Reject("witness framing/version")
    kid=key_id(witness_pub)
    if (kid != exact(expected_key_id,32,"witness roster ID",True)
            or raw[5:37] != kid or raw[37:69] != exact(network,32,"network",True)
            or raw[69:117] != exact(root,48,"root",True)
            or raw[117:165] != exact(genesis,48,"genesis",True)
            or raw[221:253] != exact(challenge,32,"challenge",True)):
        raise Reject("witness roster/context/challenge")
    seq = int.from_bytes(raw[165:173],"big")
    fid = raw[173:221]
    observed = int.from_bytes(raw[253:261],"big")
    expiry = int.from_bytes(raw[261:269],"big")
    if (type(now) is not int or not 0 <= now < 1<<64 or observed > now
            or expiry < now or expiry != observed+30 or (seq==0) != (fid==ZERO48)):
        raise Reject("witness time/empty history")
    verify_sig(witness_pub,PREFIX+raw,frame[RESP_UNSIGNED+2:])
    return WitnessHead(seq,fid)


@dataclass(frozen=True)
class QuorumObservation:
    """A conditional 2/3 live witness observation. Not consensus or rollback authority."""
    head: WitnessHead
    responding: tuple[bytes,...]


def verify_quorum(replies, *, roster, network, root, genesis, challenge, now,
                  expected_sequence, expected_frontier_id):
    """Reject stale/predicted frontier unless >=2 fresh known signers agree on latest observed head.

    A corrupt/offline/rewound *majority* can still fool this reference: HOLD_NO_GO.
    """
    if type(roster) is not dict or len(roster) != 3: raise Reject("fixed three witness roster")
    for kid,pub in roster.items():
        if key_id(pub)!=exact(kid,32,"external trusted witness key",True):
            raise Reject("roster invalid/duplicate")
    if type(replies) not in (list,tuple) or not 2<=len(replies)<=3:
        raise Reject("insufficient live witnesses")
    seen={}
    for entry in replies:
        if type(entry) is not tuple or len(entry)!=2:
            raise Reject("witness response grammar")
        kid,frame=entry
        if type(kid) is not bytes or kid not in roster or kid in seen:
            raise Reject("unknown or duplicate witness")
        seen[kid]=verify_fresh_response(frame,witness_pub=roster[kid],expected_key_id=kid,
                                        network=network,root=root,genesis=genesis,
                                        challenge=challenge,now=now)
    highest=max(v.sequence for v in seen.values())
    if highest==0: raise Reject("empty witness history cannot anchor a chain")
    counts={}
    for kid,head in seen.items():
        if head.sequence == highest:
            counts.setdefault(head.frontier_id,[]).append(kid)
    majority=[(fid,signers) for fid,signers in counts.items() if len(signers)>=2]
    if len(majority)!=1: raise Reject("no live latest 2-of-3 frontier quorum")
    fid, signers = majority[0]
    if (type(expected_sequence) is not int or highest!=expected_sequence
            or fid != exact(expected_frontier_id,48,"expected local frontier")):
        raise Reject("local state rolled back or frontier mismatch")
    return QuorumObservation(WitnessHead(highest,fid),tuple(sorted(signers)))
