"""PQL4: independent, signed, externally pinned observation of PQL3 state.

RESEARCH ONLY / HOLD_NO_GO: verifies a *local* SQLite reference snapshot and a
real ML-DSA-65 observer signature. Neither the source PQL2 pins, independently
monotone witness head nor the signer's authority can be derived from this DB.
No native consensus, signer custody, FinalUse, fork choice or spend is implemented.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
from urllib.parse import quote

DOMAIN = b"TRNM/PQ/PQL4SignedFrontier/v1\x00"
SNAPSHOT_DOMAIN = b"TRNM/PQ/PQL4StorageSnapshot/v1\x00"
IDENTITY_DOMAIN = b"TRNM/PQ/PQL4FrontierId/v1\x00"
KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\x00"  # matches TPQ1 key identity
PQL3_NODE_DOMAIN = b"TRNM/PQ/PQL3NonceSnapshot/v1\x00"
ML_DSA_65_OID_DER = bytes.fromhex("0609608648016503040312")
ZERO32 = bytes(32)
ZERO48 = bytes(48)
MAX_SQL_INT = (1 << 63) - 1
MAX_U64 = (1 << 64) - 1
MAX_NODES = 32768
MAX_EFFECTS = 32768
MAX_ACCOUNTS = 128
SIG_BYTES = 3309
UNSIGNED_BYTES = 336
SIGNED_BYTES = UNSIGNED_BYTES + 2 + SIG_BYTES
SQL = {
    "meta": "CREATE TABLE meta (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL) WITHOUT ROWID",
    "nodes": "CREATE TABLE nodes (id BLOB PRIMARY KEY NOT NULL, parent BLOB NOT NULL, height INTEGER NOT NULL, account_idx INTEGER NOT NULL, op BLOB NOT NULL, nonces BLOB NOT NULL) WITHOUT ROWID",
    "active": "CREATE TABLE active (slot INTEGER PRIMARY KEY CHECK(slot=1), tip BLOB NOT NULL, generation INTEGER NOT NULL)",
    "effects": "CREATE TABLE effects (op BLOB PRIMARY KEY NOT NULL, tip BLOB NOT NULL) WITHOUT ROWID",
}


class Reject(ValueError):
    """An invalid encoding, false state observation or untrusted witness."""


def exact(v: bytes, n: int, name: str, *, nonzero: bool = False) -> bytes:
    if type(v) is not bytes or len(v) != n or (nonzero and v == bytes(n)):
        raise Reject(name)
    return v


def u64(v: int, name: str, *, nonzero: bool = False) -> bytes:
    if type(v) is not int or not int(nonzero) <= v <= MAX_U64:
        raise Reject(name)
    return v.to_bytes(8, "big")


def _framed(domain: bytes, content: bytes) -> bytes:
    return hashlib.sha384(domain + len(content).to_bytes(8, "big") + content).digest()


def node_id(import_root: bytes, parent: bytes, height: int, idx: int,
            operation: bytes, nonces: bytes) -> bytes:
    exact(import_root, 48, "node root", nonzero=True)
    exact(parent, 48, "node parent")
    exact(operation, 32, "node op")
    if type(idx) is not int or not -1 <= idx < MAX_ACCOUNTS:
        raise Reject("node account index")
    if type(nonces) is not bytes or not 8 <= len(nonces) <= MAX_ACCOUNTS * 8 or len(nonces) % 8:
        raise Reject("node nonce grammar")
    return _framed(PQL3_NODE_DOMAIN, import_root + parent + u64(height, "height")
                   + (idx + 1).to_bytes(2, "big") + operation + nonces)


def _read_length(data: bytes, at: int) -> tuple[int, int]:
    if at >= len(data):
        raise Reject("SPKI truncated")
    first = data[at]
    if first < 128:
        return first, at + 1
    count = first & 127
    if not 1 <= count <= 4 or at + 1 + count > len(data):
        raise Reject("SPKI length")
    v = int.from_bytes(data[at + 1:at + 1 + count], "big")
    if v < 128 or data[at + 1] == 0:
        raise Reject("SPKI noncanonical")
    return v, at + 1 + count


def _run(argv: list[str]) -> bytes:
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject("OpenSSL unavailable") from exc
    if done.returncode:
        raise Reject("cryptographic verification failed")
    return done.stdout


def signer_key_id(public_pem: bytes) -> bytes:
    if type(public_pem) is not bytes or not 0 < len(public_pem) <= 16384:
        raise Reject("observer public key PEM")
    with tempfile.TemporaryDirectory(prefix="pql4-key-") as d:
        key = Path(d) / "public.pem"
        key.write_bytes(public_pem)
        der = _run(["openssl", "pkey", "-pubin", "-in", str(key), "-outform", "DER"])
    if not der or der[0] != 0x30:
        raise Reject("SPKI outer")
    outer, off = _read_length(der, 1)
    if off + outer != len(der) or der[off] != 0x30:
        raise Reject("SPKI frame")
    alg, off2 = _read_length(der, off + 1)
    if der[off2:off2 + alg] != ML_DSA_65_OID_DER:
        raise Reject("observer must use exact ML-DSA-65")
    at = off2 + alg
    if at >= len(der) or der[at] != 0x03:
        raise Reject("SPKI BIT STRING")
    rawlen, rawat = _read_length(der, at + 1)
    if rawlen != 1953 or rawat + rawlen != len(der) or der[rawat] != 0:
        raise Reject("ML-DSA-65 public key length/padding")
    return hashlib.sha256(KEY_DOMAIN + der).digest()


def _feed(h, kind: bytes, fields: tuple[bytes, ...]) -> None:
    h.update(len(kind).to_bytes(2, "big")); h.update(kind)
    for item in fields:
        h.update(len(item).to_bytes(4, "big")); h.update(item)


@dataclass(frozen=True)
class LocalSnapshot:
    """Structural facts only; never a consensus-validated or trusted state root."""
    import_root: bytes
    genesis: bytes
    tip: bytes
    generation: int
    state_digest: bytes
    node_count: int
    effect_count: int


def observe_pql3_store(path: Path, *, expected_import_root: bytes,
                       expected_genesis: bytes, original_nonces: bytes,
                       migrated: tuple[bool, ...]) -> LocalSnapshot:
    """Read exact PQL3 SQLite state under ONE snapshot, refusing alternate DDL.

    Imported account/withdrawal/source pins MUST come from an independent owner;
    this function does not authenticate the caller's imported PQL2 data.
    """
    root = exact(expected_import_root, 48, "import root", nonzero=True)
    genesis = exact(expected_genesis, 48, "genesis", nonzero=True)
    if (type(original_nonces) is not bytes or not 8 <= len(original_nonces) <= 8 * MAX_ACCOUNTS
            or len(original_nonces) % 8):
        raise Reject("imported nonce floors")
    count = len(original_nonces) // 8
    if any(int.from_bytes(original_nonces[i:i+8], "big") == 0
           for i in range(0, len(original_nonces), 8)):
        raise Reject("imported nonce floor zero")
    if (type(migrated) is not tuple or len(migrated) != count
            or any(type(flag) is not bool for flag in migrated)):
        raise Reject("imported migrated/quarantine flags")
    if node_id(root, ZERO48, 0, -1, ZERO32, original_nonces) != genesis:
        raise Reject("independent genesis identity")
    if not isinstance(path, Path) or not path.is_absolute():
        raise Reject("absolute database path required")
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise Reject("database file unavailable") from exc
    if not stat.S_ISREG(mode):
        raise Reject("database must be regular, not a symlink")
    uri = "file:" + quote(os.fspath(path), safe="/") + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=3)
    except sqlite3.Error as exc:
        raise Reject("cannot open read-only database") from exc
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        try:
            schema = db.execute("SELECT name,type,sql FROM sqlite_master ORDER BY name").fetchall()
            if schema != sorted((name, "table", sql) for name,sql in SQL.items()):
                raise Reject("foreign schema/triggers/views/indices")
            pins = db.execute("SELECT key,value FROM meta ORDER BY key").fetchall()
            if pins != [("genesis", genesis), ("import", root)]:
                raise Reject("import context changed")
            counts = (db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
                      db.execute("SELECT COUNT(*) FROM effects").fetchone()[0])
            if (type(counts[0]) is not int or not 1 <= counts[0] <= MAX_NODES
                    or type(counts[1]) is not int or not 0 <= counts[1] <= MAX_EFFECTS):
                raise Reject("bounded PQL3 rows")
            active = db.execute("SELECT tip,generation FROM active WHERE slot=1").fetchall()
            if (len(active) != 1 or type(active[0][1]) is not int
                    or not 1 <= active[0][1] <= MAX_SQL_INT):
                raise Reject("active tip/generation")
            tip, generation = active[0]
            exact(tip, 48, "active tip")
            h = hashlib.sha384()
            _feed(h, SNAPSHOT_DOMAIN, (root, genesis, original_nonces,
                  bytes([1 if f else 0 for f in migrated]),
                  counts[0].to_bytes(4, "big"), counts[1].to_bytes(4, "big")))
            visited: dict[bytes, tuple[int, bytes]] = {}
            for (nid, parent, height, idx, op, nonces) in db.execute(
                    "SELECT id,parent,height,account_idx,op,nonces FROM nodes ORDER BY height,id"):
                exact(nid, 48, "node id")
                exact(parent, 48, "node parent")
                exact(op, 32, "node operation")
                if (type(height) is not int or not 0 <= height <= MAX_SQL_INT
                        or type(idx) is not int or not -1 <= idx < count
                        or type(nonces) is not bytes or len(nonces) != len(original_nonces)):
                    raise Reject("node types/range")
                if node_id(root, parent, height, idx, op, nonces) != nid:
                    raise Reject("node root changed")
                if height == 0:
                    if (nid != genesis or parent != ZERO48 or idx != -1 or op != ZERO32
                            or nonces != original_nonces):
                        raise Reject("genesis node tampered")
                else:
                    if parent not in visited or visited[parent][0] != height - 1 or idx < 0 or not migrated[idx]:
                        raise Reject("fork parent or quarantined signer")
                    prior = visited[parent][1]
                    old = int.from_bytes(prior[idx * 8:(idx + 1) * 8], "big")
                    if old == MAX_U64 or nonces != (prior[:idx * 8]
                            + (old + 1).to_bytes(8, "big") + prior[(idx + 1) * 8:]):
                        raise Reject("nonce gap/reset/replay")
                if nid in visited:
                    raise Reject("duplicate branch")
                visited[nid] = (height, nonces)
                _feed(h, b"node", (nid, parent, u64(height, "height"),
                      (idx + 1).to_bytes(2, "big"), op, nonces))
            if genesis not in visited or tip not in visited or len(visited) != counts[0]:
                raise Reject("unknown active/branch")
            _feed(h, b"active", (tip, u64(generation, "generation")))
            seen_effects = 0
            for op, effect_tip in db.execute("SELECT op,tip FROM effects ORDER BY op"):
                exact(op, 32, "effect operation", nonzero=True)
                exact(effect_tip, 48, "effect tip")
                if effect_tip not in visited:
                    raise Reject("effect points to absent branch")
                seen_effects += 1
                _feed(h, b"effect", (op, effect_tip))
            if seen_effects != counts[1]:
                raise Reject("partial effect snapshot")
            return LocalSnapshot(root, genesis, tip, generation, h.digest(), *counts)
        finally:
            if db.in_transaction:
                db.execute("ROLLBACK")
    except sqlite3.Error as exc:
        raise Reject("database read/audit rejected") from exc
    finally:
        db.close()


@dataclass(frozen=True)
class Frontier:
    network: bytes
    import_root: bytes
    genesis: bytes
    tip: bytes
    generation: int
    sequence: int
    prior_frontier_id: bytes
    snapshot_digest: bytes
    expires_at: int
    observer_key_id: bytes

    def encode(self) -> bytes:
        return (b"PQL4" + bytes([1, 0x65, 0, 0])
                + exact(self.network, 32, "network", nonzero=True)
                + exact(self.import_root, 48, "import root", nonzero=True)
                + exact(self.genesis, 48, "genesis", nonzero=True)
                + exact(self.tip, 48, "active tip", nonzero=True)
                + u64(self.generation, "generation", nonzero=True)
                + u64(self.sequence, "sequence", nonzero=True)
                + exact(self.prior_frontier_id, 48, "prior frontier")
                + exact(self.snapshot_digest, 48, "snapshot", nonzero=True)
                + u64(self.expires_at, "expiry", nonzero=True)
                + exact(self.observer_key_id, 32, "observer key", nonzero=True))


def parse_frontier(raw: bytes) -> Frontier:
    if type(raw) is not bytes or len(raw) != UNSIGNED_BYTES:
        raise Reject("frontier unsigned length")
    if raw[:8] != b"PQL4\x01\x65\x00\x00":
        raise Reject("PQL4 version/algorithm/reserved")
    pos = 8
    network = raw[pos:pos+32]; pos += 32
    root = raw[pos:pos+48]; pos += 48
    genesis = raw[pos:pos+48]; pos += 48
    tip = raw[pos:pos+48]; pos += 48
    gen = int.from_bytes(raw[pos:pos+8], "big"); pos += 8
    seq = int.from_bytes(raw[pos:pos+8], "big"); pos += 8
    prior = raw[pos:pos+48]; pos += 48
    digest = raw[pos:pos+48]; pos += 48
    expiry = int.from_bytes(raw[pos:pos+8], "big"); pos += 8
    observer = raw[pos:pos+32]
    out = Frontier(network, root, genesis, tip, gen, seq, prior, digest, expiry, observer)
    if out.encode() != raw:
        raise Reject("noncanonical frontier")
    return out


def frontier_id(value: Frontier) -> bytes:
    return hashlib.sha384(IDENTITY_DOMAIN + value.encode()).digest()


def sign_fixture(frontier: Frontier, private_key: Path) -> bytes:
    """Local fixture only; NOT a deployed independently owned signer."""
    raw = frontier.encode()
    if len(raw) != UNSIGNED_BYTES:
        raise Reject("internal wire length")
    with tempfile.TemporaryDirectory(prefix="pql4-sign-") as tmp:
        msg = Path(tmp) / "msg"; sig = Path(tmp) / "sig"
        msg.write_bytes(DOMAIN + raw)
        _run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
              "-in", str(msg), "-out", str(sig)])
        signed = sig.read_bytes()
    if len(signed) != SIG_BYTES:
        raise Reject("unexpected ML-DSA signature size")
    return raw + SIG_BYTES.to_bytes(2, "big") + signed


@dataclass(frozen=True)
class FrontierObservation:
    """A matching PQ signature and local bytes, never state authority or finality."""
    frontier_id: bytes
    observed_tip: bytes
    observed_generation: int
    observed_sequence: int
    state_digest: bytes


def verify_checkpoint(frame: bytes, *, public_pem: bytes,
                      expected_observer_key_id: bytes, expected_network: bytes,
                      expected_snapshot: LocalSnapshot, expected_sequence: int,
                      expected_prior_frontier_id: bytes, now: int) -> FrontierObservation:
    """All expected fields MUST originate outside the rewindable database and frame."""
    if type(frame) is not bytes or len(frame) != SIGNED_BYTES:
        raise Reject("signed frontier length")
    f = parse_frontier(frame[:UNSIGNED_BYTES])
    if int.from_bytes(frame[UNSIGNED_BYTES:UNSIGNED_BYTES+2], "big") != SIG_BYTES:
        raise Reject("signature framing")
    if not isinstance(expected_snapshot, LocalSnapshot):
        raise Reject("caller expected snapshot")
    kid = signer_key_id(public_pem)
    if (kid != exact(expected_observer_key_id, 32, "trusted observer key", nonzero=True)
            or f.observer_key_id != kid
            or f.network != exact(expected_network, 32, "trusted network", nonzero=True)
            or f.import_root != expected_snapshot.import_root
            or f.genesis != expected_snapshot.genesis
            or f.tip != expected_snapshot.tip
            or f.generation != expected_snapshot.generation
            or f.snapshot_digest != expected_snapshot.state_digest
            or type(expected_sequence) is not int or f.sequence != expected_sequence
            or f.prior_frontier_id != exact(expected_prior_frontier_id, 48, "prior trusted head")
            or type(now) is not int or not 0 <= now <= MAX_U64 or now > f.expires_at):
        raise Reject("independent witness pin/time/state mismatch")
    with tempfile.TemporaryDirectory(prefix="pql4-verify-") as tmp:
        root = Path(tmp)
        (root / "pub").write_bytes(public_pem)
        (root / "msg").write_bytes(DOMAIN + frame[:UNSIGNED_BYTES])
        (root / "sig").write_bytes(frame[UNSIGNED_BYTES+2:])
        _run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(root / "pub"),
              "-rawin", "-in", str(root / "msg"), "-sigfile", str(root / "sig")])
    return FrontierObservation(frontier_id(f), f.tip, f.generation, f.sequence, f.snapshot_digest)
