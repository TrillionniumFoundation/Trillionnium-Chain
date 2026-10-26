"""PCQ1/PCR1: offline ML-DSA-65-signed Cell chunk retrieval research.

This verifies exact bytes and one response to a caller-anchored challenge. It
DOES NOT prove continuous storage, geographic independence, export permission,
real provider identity, blockchain availability, payment, adoption or Final-use.
OpenSSL is used only by pq_envelope's offline fixture helper.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sqlite3

from pq_envelope import (Reject, SIGNED_BYTES, make_unsigned, public_key_id,
                         sign_reference, verify_reference)

CAT_MAGIC = b"PCC1"
CHALLENGE_MAGIC = b"PCQ1"
RESPONSE_MAGIC = b"PCR1"
DOMAIN = b"TRNM/PoN/PQCellCustody/v1\x00"
MAX_CHUNK_BYTES = 1 << 20
MAX_OBJECT_BYTES = 64 << 20
MAX_CHUNKS = 4096
MAX_CHALLENGE_TTL = 300
CATALOG_BYTES = 157
CHALLENGE_BYTES = 217


def _exact(v: bytes, n: int, label: str, nonzero: bool = False) -> bytes:
    if type(v) is not bytes or len(v) != n or (nonzero and v == bytes(n)):
        raise Reject(label)
    return v


def _int(v: int, n: int, label: str, minimum: int = 0) -> bytes:
    if type(v) is not int or not minimum <= v < (1 << (8*n)):
        raise Reject(label)
    return v.to_bytes(n, "big")


def _h(tag: bytes, *parts: bytes) -> bytes:
    return hashlib.sha384(DOMAIN + tag + b"".join(parts)).digest()


def _leaf(index: int, total: int, data: bytes) -> bytes:
    if type(data) is not bytes or not 0 < len(data) <= MAX_CHUNK_BYTES:
        raise Reject("chunk type/size")
    return _h(b"leaf\x00", _int(index, 4, "index"), _int(total, 4, "total", 1),
              _int(len(data), 4, "length", 1), data)


def _parent(left: bytes, right: bytes) -> bytes:
    return _h(b"node\x00", _exact(left, 48, "left"), _exact(right, 48, "right"))


def _layers(chunks: tuple[bytes, ...]) -> list[list[bytes]]:
    if type(chunks) is not tuple or not 1 <= len(chunks) <= MAX_CHUNKS:
        raise Reject("chunk count")
    levels = [[_leaf(i, len(chunks), b) for i, b in enumerate(chunks)]]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([_parent(cur[i], cur[i + 1] if i + 1 < len(cur) else cur[i])
                       for i in range(0, len(cur), 2)])
    return levels


def chunk_proof(chunks: tuple[bytes, ...], index: int) -> tuple[bytes, ...]:
    levels = _layers(chunks)
    if type(index) is not int or not 0 <= index < len(chunks):
        raise Reject("index")
    path = []
    for level in levels[:-1]:
        partner = index ^ 1
        path.append(level[partner] if partner < len(level) else level[index])
        index //= 2
    return tuple(path)


@dataclass(frozen=True)
class Catalog:
    network: bytes
    release_manifest: bytes
    generation: int
    total_bytes: int
    chunk_size: int
    chunk_count: int
    root: bytes

    def encode(self) -> bytes:
        if (type(self.total_bytes) is not int or not 1 <= self.total_bytes <= MAX_OBJECT_BYTES
                or type(self.chunk_size) is not int or not 1 <= self.chunk_size <= MAX_CHUNK_BYTES
                or type(self.chunk_count) is not int or not 1 <= self.chunk_count <= MAX_CHUNKS
                or not (self.chunk_count-1)*self.chunk_size < self.total_bytes <= self.chunk_count*self.chunk_size):
            raise Reject("catalog dimensions")
        return (CAT_MAGIC + b"\x01" + _exact(self.network, 32, "network", True)
                + _exact(self.release_manifest, 48, "release", True)
                + _int(self.generation, 8, "generation", 1)
                + _int(self.total_bytes, 8, "total_bytes", 1)
                + _int(self.chunk_size, 4, "chunk_size", 1)
                + _int(self.chunk_count, 4, "chunk_count", 1)
                + _exact(self.root, 48, "root", True))


def catalog_from_chunks(network: bytes, release: bytes, generation: int,
                        chunks: tuple[bytes, ...], chunk_size: int) -> Catalog:
    levels = _layers(chunks)
    if any(len(c) != chunk_size for c in chunks[:-1]) or not 0 < len(chunks[-1]) <= chunk_size:
        raise Reject("chunk partition")
    c = Catalog(network, release, generation, sum(map(len, chunks)),
                chunk_size, len(chunks), levels[-1][0])
    c.encode()
    return c


def parse_catalog(raw: bytes) -> Catalog:
    if type(raw) is not bytes or len(raw) != CATALOG_BYTES or raw[:5] != CAT_MAGIC + b"\x01":
        raise Reject("catalog frame")
    c = Catalog(raw[5:37], raw[37:85], int.from_bytes(raw[85:93], "big"),
                int.from_bytes(raw[93:101], "big"), int.from_bytes(raw[101:105], "big"),
                int.from_bytes(raw[105:109], "big"), raw[109:157])
    if c.encode() != raw:
        raise Reject("catalog noncanonical")
    return c


def catalog_id(c: Catalog) -> bytes:
    return _h(b"catalog\x00", c.encode())


def verify_chunk(c: Catalog, index: int, data: bytes, proof: tuple[bytes, ...]) -> bytes:
    c.encode()
    if type(index) is not int or not 0 <= index < c.chunk_count or type(proof) is not tuple:
        raise Reject("chunk index/proof type")
    needed = c.chunk_size if index < c.chunk_count-1 else c.total_bytes - (c.chunk_count-1)*c.chunk_size
    if type(data) is not bytes or len(data) != needed:
        raise Reject("chunk length")
    expected_levels, count = 0, c.chunk_count
    while count > 1:
        expected_levels += 1
        count = (count+1)//2
    if len(proof) != expected_levels:
        raise Reject("merkle depth")
    digest = _leaf(index, c.chunk_count, data)
    position, width = index, c.chunk_count
    for sibling in proof:
        _exact(sibling, 48, "merkle sibling")
        if position ^ 1 >= width and sibling != digest:
            raise Reject("noncanonical duplicate-last")
        digest = _parent(sibling, digest) if position & 1 else _parent(digest, sibling)
        position //= 2
        width = (width+1)//2
    if digest != c.root:
        raise Reject("merkle root")
    return _leaf(index, c.chunk_count, data)


@dataclass(frozen=True)
class Challenge:
    network: bytes
    catalog_digest: bytes
    nonce: bytes
    requester_id: bytes
    provider_key_id: bytes
    generation: int
    sequence: int
    chunk_index: int
    issued_at: int
    expires_at: int

    def encode(self) -> bytes:
        if (type(self.issued_at) is not int or type(self.expires_at) is not int
                or self.expires_at < self.issued_at
                or self.expires_at-self.issued_at > MAX_CHALLENGE_TTL):
            raise Reject("challenge time/ttl")
        return (CHALLENGE_MAGIC + b"\x01"
                + _exact(self.network, 32, "network", True)
                + _exact(self.catalog_digest, 48, "catalog digest", True)
                + _exact(self.nonce, 32, "nonce", True)
                + _exact(self.requester_id, 32, "requester", True)
                + _exact(self.provider_key_id, 32, "provider", True)
                + _int(self.generation, 8, "generation", 1)
                + _int(self.sequence, 8, "sequence", 1)
                + _int(self.chunk_index, 4, "chunk_index")
                + _int(self.issued_at, 8, "issued")
                + _int(self.expires_at, 8, "expiry", 1))


def parse_challenge(raw: bytes) -> Challenge:
    if type(raw) is not bytes or len(raw) != CHALLENGE_BYTES or raw[:5] != CHALLENGE_MAGIC + b"\x01":
        raise Reject("challenge frame")
    fields = Challenge(raw[5:37], raw[37:85], raw[85:117], raw[117:149], raw[149:181],
                       int.from_bytes(raw[181:189], "big"), int.from_bytes(raw[189:197], "big"),
                       int.from_bytes(raw[197:201], "big"), int.from_bytes(raw[201:209], "big"),
                       int.from_bytes(raw[209:217], "big"))
    if fields.encode() != raw:
        raise Reject("challenge canonical")
    return fields


def _check_challenge(c: Catalog, q: Challenge, now: int) -> None:
    _int(now, 8, "now")
    if (q.network != c.network or q.catalog_digest != catalog_id(c)
            or q.generation != c.generation or q.chunk_index >= c.chunk_count
            or now < q.issued_at or now > q.expires_at):
        raise Reject("stale/wrong challenge")
    q.encode()


def _payload(c: Catalog, q: Challenge, leaf: bytes, path: tuple[bytes, ...]) -> bytes:
    return (DOMAIN + b"signed-retrieval\x00" + catalog_id(c)
            + _h(b"challenge\x00", q.encode()) + leaf
            + bytes([len(path)]) + b"".join(path))


def _context(c: Catalog, q: Challenge) -> bytes:
    return hashlib.sha256(DOMAIN + b"context\x00" + catalog_id(c) + q.encode()).digest()


def sign_response_fixture(c: Catalog, q: Challenge, *, chunk: bytes,
                          path: tuple[bytes, ...], public_pem: bytes,
                          private_key_path: Path, now: int) -> bytes:
    """Local fixture: signs an actual valid response, not a durable storage claim."""
    _check_challenge(c, q, now)
    if q.provider_key_id != public_key_id(public_pem):
        raise Reject("wrong signer")
    leaf = verify_chunk(c, q.chunk_index, chunk, path)
    statement = make_unsigned(purpose=5, network=c.network, context=_context(c,q),
                              signer_key_id=q.provider_key_id,
                              owner_generation=q.generation, operation_sequence=q.sequence,
                              expires_at=q.expires_at, payload=_payload(c,q,leaf,path))
    signed = sign_reference(statement, private_key_path=private_key_path)
    return (RESPONSE_MAGIC + _int(q.chunk_index,4,"index")
            + _int(len(chunk),4,"chunk len",1) + chunk
            + bytes([len(path)]) + b"".join(path) + signed)


@dataclass(frozen=True)
class RetrievalObservation:
    """Diagnostic: no consensus, custody reward, Final-use or availability authority."""
    challenge_id: bytes
    chunk_leaf: bytes
    provider_key_id: bytes
    response_digest: bytes


def verify_response_research(raw: bytes, *, catalog_bytes: bytes, challenge_bytes: bytes,
                             provider_public_pem: bytes, expected_release: bytes,
                             expected_catalog_digest: bytes, expected_requester: bytes, expected_nonce: bytes,
                             expected_provider_key_id: bytes, now: int) -> RetrievalObservation:
    c, q = parse_catalog(catalog_bytes), parse_challenge(challenge_bytes)
    _check_challenge(c, q, now)
    if (c.release_manifest != _exact(expected_release,48,"expected release",True)
            or catalog_id(c) != _exact(expected_catalog_digest,48,"expected catalog digest",True)
            or q.requester_id != _exact(expected_requester,32,"requester",True)
            or q.nonce != _exact(expected_nonce,32,"nonce",True)
            or q.provider_key_id != _exact(expected_provider_key_id,32,"provider",True)
            or q.provider_key_id != public_key_id(provider_public_pem)):
        raise Reject("caller trust/context mismatch")
    if type(raw) is not bytes or not 4+4+4+1+SIGNED_BYTES <= len(raw) <= 4+4+4+MAX_CHUNK_BYTES+1+12*48+SIGNED_BYTES:
        raise Reject("response length")
    if raw[:4] != RESPONSE_MAGIC:
        raise Reject("response type")
    index, size = int.from_bytes(raw[4:8],"big"), int.from_bytes(raw[8:12],"big")
    if index != q.chunk_index or not 0 < size <= MAX_CHUNK_BYTES:
        raise Reject("wrong chunk index/length")
    path_len_at = 12+size
    if path_len_at >= len(raw):
        raise Reject("response framing")
    depth = raw[path_len_at]
    if depth > 12 or len(raw) != path_len_at+1+depth*48+SIGNED_BYTES:
        raise Reject("response proof/trailing")
    chunk = raw[12:path_len_at]
    path = tuple(raw[path_len_at+1+i*48:path_len_at+1+(i+1)*48] for i in range(depth))
    leaf = verify_chunk(c, index, chunk, path)
    frame = raw[-SIGNED_BYTES:]
    verify_reference(frame, payload=_payload(c,q,leaf,path), public_pem=provider_public_pem,
                     expected_network=c.network, expected_context=_context(c,q),
                     expected_purpose=5, expected_generation=q.generation,
                     expected_sequence=q.sequence, now=now)
    return RetrievalObservation(_h(b"challenge\x00",q.encode()), leaf,
                                q.provider_key_id, _h(b"response\x00",raw))


class OfflineOneUseJournal:
    """Single local SQLite anti-double-count observer; not a global chain nullifier."""
    DDL = """CREATE TABLE pq_custody_observation (
            challenge_id BLOB PRIMARY KEY NOT NULL,
            response_digest BLOB NOT NULL,
            provider_key_id BLOB NOT NULL
        ) WITHOUT ROWID"""
    def __init__(self, filename: Path):
        self.db = sqlite3.connect(str(filename), timeout=10, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=10000")
        query = "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        expected = [("table", "pq_custody_observation", self.DDL)]
        pre = self.db.execute(query).fetchall()
        if pre not in ([], expected):
            self.db.close()
            raise Reject("foreign/corrupt SQLite journal schema")
        if self.db.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
            self.db.close()
            raise Reject("WAL unavailable")
        self.db.execute("PRAGMA synchronous=FULL")
        if self.db.execute("PRAGMA synchronous").fetchone() != (2,):
            self.db.close()
            raise Reject("FULL durability unavailable")
        if not pre:
            # Fresh initialization must be owned, not raced by unrelated creators.
            self.db.execute(self.DDL)
        if self.db.execute(query).fetchall() != expected:
            self.db.close()
            raise Reject("SQLite schema changed after initialization")

    def close(self):
        self.db.close()

    def record(self, raw: bytes, **verified_inputs) -> tuple[str, RetrievalObservation]:
        observation = verify_response_research(raw, **verified_inputs)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            found = self.db.execute("SELECT response_digest,provider_key_id FROM pq_custody_observation WHERE challenge_id=?",
                                    (observation.challenge_id,)).fetchone()
            if found is not None:
                if found != (observation.response_digest, observation.provider_key_id):
                    raise Reject("same challenge changed response")
                self.db.execute("COMMIT")
                return "ALREADY_RECORDED", observation
            self.db.execute("INSERT INTO pq_custody_observation VALUES(?,?,?)",
                            (observation.challenge_id, observation.response_digest, observation.provider_key_id))
            self.db.execute("COMMIT")
            return "FIRST_RECORD", observation
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
