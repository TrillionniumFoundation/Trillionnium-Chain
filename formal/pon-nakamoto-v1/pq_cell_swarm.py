"""PCS1: bounded, loopback-only, multi-provider Cell retrieval research.

A genuine PCQ1/PCR1 ML-DSA-65 verifier is called for every accepted shard.
The caller MUST pin an authenticated PCB1 release and PCC1 catalog/content ID;
self-signed provider metadata, a local download and this observation grant NO
custody reward, public release, Hepta Final-use, chainwork, or network authority.

This fixture has no public interface: it intentionally refuses non-loopback hosts.
It models independent local processes, not hostile WAN / persistent storage.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from itertools import islice
import secrets
import socket
import socketserver
import struct
import tempfile
import threading
import time
from typing import Iterable

from pq_envelope import Reject, public_key_id, SIGNED_BYTES
from pq_cell_custody import (
    Catalog, Challenge, MAX_CHUNK_BYTES, CHALLENGE_BYTES, catalog_id,
    chunk_proof, parse_catalog, parse_challenge, sign_response_fixture,
    verify_response_research, _check_challenge,
)

MAX_WIRE_REPLY = 12 + MAX_CHUNK_BYTES + 1 + 12 * 48 + SIGNED_BYTES
MAX_PARALLEL = 4
MAX_PROVIDERS = 8
MAX_ATTEMPTS_PER_CHUNK = 8
MAX_WALL_SECONDS = 300
CONNECT_TIMEOUT = 2.0
REPLY_TIMEOUT = 5.0
CONTENT_DOMAIN = b"TRNM/PoN/PQCellContent/v1\x00"  # exact PCB1 content-id v1


def content_id(data: bytes) -> bytes:
    if type(data) is not bytes or not 0 < len(data) <= 64 * 1024 * 1024:
        raise Reject("content length/type")
    return hashlib.sha384(CONTENT_DOMAIN + len(data).to_bytes(8, "big") + data).digest()


def _u32(v: int) -> bytes:
    if type(v) is not int or not 0 <= v < 2**32:
        raise Reject("wire size")
    return struct.pack(">I", v)


def _read_exact(conn: socket.socket, n: int) -> bytes:
    if type(n) is not int or n < 0 or n > MAX_WIRE_REPLY:
        raise Reject("frame bound")
    data = bytearray()
    while len(data) < n:
        b = conn.recv(min(65536, n-len(data)))
        if not b:
            raise Reject("truncated reply")
        data.extend(b)
    return bytes(data)


def _is_loopback(host: str) -> bool:
    # An explicit literal only: no DNS lookups, localhost aliases or mixed IPv4/IPv6.
    return type(host) is str and host == "127.0.0.1"


@dataclass(frozen=True)
class Peer:
    host: str
    port: int
    public_pem: bytes
    expected_key_id: bytes

    def checked(self) -> bytes:
        if not _is_loopback(self.host) or type(self.port) is not int or not 1 <= self.port <= 65535:
            raise Reject("research peer must be 127.0.0.1 literal")
        if type(self.expected_key_id) is not bytes or len(self.expected_key_id) != 32:
            raise Reject("pinned provider ID")
        if public_key_id(self.public_pem) != self.expected_key_id:
            raise Reject("peer key not in independently pinned roster")
        return self.expected_key_id


@dataclass(frozen=True)
class FetchObservation:
    """No availability proof, independent reward, consensus or final-use field."""
    catalog_digest: bytes
    content_digest: bytes
    object_bytes: int
    chunks_verified: int
    provider_ids: tuple[bytes, ...]
    failed_attempts: int  # includes both Busy/unavailable and invalid, not proof of fraud
    output_file: Path


class _SwarmServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, handler, *, max_inflight=2, **kwargs):
        if not _is_loopback(address[0]) or type(max_inflight) is not int or not 1 <= max_inflight <= 4:
            raise Reject("loopback or max_inflight")
        self._slots = threading.BoundedSemaphore(max_inflight)
        self.catalog = kwargs["catalog"]
        self.chunks = kwargs["chunks"]
        self.public_pem = kwargs["public_pem"]
        self.private_key_path = kwargs["private_key_path"]
        self.failure = kwargs.get("failure")
        self.key_id = public_key_id(self.public_pem)
        self.max_inflight = max_inflight
        self.active = 0
        self.high_watermark = 0
        self._count_lock = threading.Lock()
        super().__init__(address, handler)

    def verify_request(self, request, client_address):
        if client_address[0] != "127.0.0.1" or not self._slots.acquire(blocking=False):
            return False
        with self._count_lock:
            self.active += 1
            self.high_watermark = max(self.high_watermark, self.active)
        return True

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._count_lock:
                self.active -= 1
            self._slots.release()


class _Request(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(REPLY_TIMEOUT)
        try:
            if _read_exact(sock, 4) != _u32(CHALLENGE_BYTES):
                return
            q = parse_challenge(_read_exact(sock, CHALLENGE_BYTES))
            c = self.server.catalog
            _check_challenge(c, q, int(time.time()))
            if q.provider_key_id != self.server.key_id:
                return
            i = q.chunk_index
            if self.server.failure == "close":
                return
            response = sign_response_fixture(
                c, q, chunk=self.server.chunks[i],
                path=chunk_proof(self.server.chunks, i),
                public_pem=self.server.public_pem,
                private_key_path=self.server.private_key_path,
                now=int(time.time()),
            )
            if self.server.failure == "tamper":
                response = response[:-1] + bytes([response[-1] ^ 1])
            elif self.server.failure == "truncate":
                sock.sendall(_u32(len(response)) + response[:9]); return
            if len(response) > MAX_WIRE_REPLY:
                raise Reject("wire reply too large")
            sock.sendall(_u32(len(response)) + response)
        except (Reject, TimeoutError, OSError, ValueError):
            # Invalid inputs never return a signed positive result.
            return


def serve_fixture(chunks: tuple[bytes, ...], catalog_bytes: bytes,
                  private_key_path: Path, public_pem: bytes, port_pipe,
                  *, failure: str | None = None):
    """Runs ONE owned loopback test process; never expose this key-bearing fixture to WAN."""
    try:
        c = parse_catalog(catalog_bytes)
        if type(chunks) is not tuple or not 1 <= len(chunks) == c.chunk_count:
            raise Reject("provider chunk set")
        if any(type(x) is not bytes for x in chunks):
            raise Reject("provider bytes")
        with _SwarmServer(("127.0.0.1", 0), _Request, catalog=c, chunks=chunks,
                          private_key_path=Path(private_key_path), public_pem=public_pem,
                          failure=failure, max_inflight=2) as server:
            port_pipe.send(server.server_address[1]); port_pipe.close()
            server.serve_forever(poll_interval=0.1)
    except BaseException:
        try: port_pipe.send(0)
        except (OSError, EOFError): pass
        port_pipe.close()
        raise


def _request(peer: Peer, q: Challenge) -> bytes:
    q_raw = q.encode()
    with socket.create_connection((peer.host, peer.port), timeout=CONNECT_TIMEOUT) as conn:
        conn.settimeout(REPLY_TIMEOUT)
        conn.sendall(_u32(len(q_raw)) + q_raw)
        n = struct.unpack(">I", _read_exact(conn, 4))[0]
        if not 12 + 1 + SIGNED_BYTES <= n <= MAX_WIRE_REPLY:
            raise Reject("peer wire length")
        return _read_exact(conn, n)


def _read_authenticated_chunk(raw: bytes, c: Catalog, q: Challenge, peer: Peer, now: int,
                              requester_id: bytes) -> bytes:
    verify_response_research(
        raw, catalog_bytes=c.encode(), challenge_bytes=q.encode(),
        provider_public_pem=peer.public_pem, expected_release=c.release_manifest,
        expected_catalog_digest=catalog_id(c), expected_requester=requester_id,
        expected_nonce=q.nonce, expected_provider_key_id=peer.expected_key_id,
        now=now,
    )
    # Only after full Merkle AND genuine PQ signature validation may the bytes escape.
    size = int.from_bytes(raw[8:12], "big")
    return raw[12:12+size]


def _fetch_one(index: int, c: Catalog, peers: tuple[Peer, ...],
               requester_id: bytes, max_attempts: int, deadline: float) -> tuple[bytes, bytes, int]:
    failed = 0
    # A deterministic bounded peer cycle, with distinct fresh challenge for every retry.
    for attempt in range(max_attempts):
        if time.monotonic() >= deadline:
            raise Reject("bounded fetch deadline expired")
        peer = peers[(index + attempt) % len(peers)]
        issued_at = int(time.time())
        nonce = secrets.token_bytes(32)
        if nonce == bytes(32):
            raise Reject("nonce generator returned zero")
        q = Challenge(c.network, catalog_id(c), nonce, requester_id,
                      peer.expected_key_id, c.generation, index * max_attempts + attempt + 1,
                      index, issued_at, issued_at + 60)
        try:
            raw = _request(peer, q)
            data = _read_authenticated_chunk(raw, c, q, peer, int(time.time()), requester_id)
            return data, peer.expected_key_id, failed
        except (Reject, TimeoutError, OSError, ValueError):
            failed += 1
    raise Reject(f"all bounded signed providers failed for chunk {index}")


def fetch_to_immutable_file(*, catalog_bytes: bytes, expected_catalog_digest: bytes,
                            expected_release: bytes, expected_content_id: bytes,
                            requester_id: bytes, peers: Iterable[Peer], destination: Path,
                            max_parallel: int = 4, max_attempts_per_chunk: int = 8,
                            max_wall_seconds: int = 300) -> FetchObservation:
    """Fetch in bounded batches; never publish partial or untrusted bytes.

    Caller-supplied digest pins MUST come from authenticated PCB1/PCA1 and
    independent Hepta authorization. This function cannot establish those facts.
    """
    c = parse_catalog(catalog_bytes)
    if (type(expected_catalog_digest) is not bytes or len(expected_catalog_digest) != 48
            or catalog_id(c) != expected_catalog_digest
            or type(expected_release) is not bytes or len(expected_release) != 48
            or c.release_manifest != expected_release
            or type(expected_content_id) is not bytes or len(expected_content_id) != 48
            or type(requester_id) is not bytes or len(requester_id) != 32 or requester_id == bytes(32)):
        raise Reject("independently pinned content/catalog/release/requester")
    # Do not consume an unbounded adversarial provider iterator.
    try:
        peers = tuple(islice(peers, MAX_PROVIDERS + 1))
    except TypeError as exc:
        raise Reject("peer iterable") from exc
    if not 1 <= len(peers) <= MAX_PROVIDERS or len({(p.host, p.port) for p in peers}) != len(peers):
        raise Reject("peer count/duplicate endpoint")
    for p in peers:
        p.checked()
    if (type(max_parallel) is not int or not 1 <= max_parallel <= MAX_PARALLEL
            or type(max_attempts_per_chunk) is not int
            or not len(peers) <= max_attempts_per_chunk <= MAX_ATTEMPTS_PER_CHUNK
            or type(max_wall_seconds) is not int or not 1 <= max_wall_seconds <= MAX_WALL_SECONDS):
        raise Reject("research worker/attempt budget")
    dest = Path(destination)
    # Do not follow pre-existing symlinks or overwrite existing immutable content.
    if dest.is_symlink() or dest.exists() or not dest.parent.is_dir():
        raise Reject("immutable output already exists or unsupported destination")
    temp_path = None
    rejected = 0
    selected = []
    # Never oversubscribe one signed-provider process with parallel requests.
    # Backpressure is a local capacity observation, not cryptographic invalidity.
    active_parallel = min(max_parallel, len(peers))
    deadline = time.monotonic() + max_wall_seconds
    try:
        fd, p = tempfile.mkstemp(prefix=".pcs1-incomplete-", dir=dest.parent)
        temp_path = Path(p)
        with os.fdopen(fd, "w+b", buffering=0) as out, ThreadPoolExecutor(max_workers=active_parallel) as pool:
            out.truncate(c.total_bytes)
            # Bounded number of live Futures: at most max_parallel, never 4096.
            for start in range(0, c.chunk_count, active_parallel):
                end = min(start + active_parallel, c.chunk_count)
                futures = {i: pool.submit(_fetch_one, i, c, peers, requester_id,
                                           max_attempts_per_chunk, deadline) for i in range(start, end)}
                for i in range(start, end):
                    data, kid, fails = futures[i].result()
                    expected_size = (c.chunk_size if i < c.chunk_count - 1
                                     else c.total_bytes - i * c.chunk_size)
                    if len(data) != expected_size:
                        raise Reject("signed chunk length after readback")
                    out.seek(i * c.chunk_size)
                    out.write(data)
                    rejected += fails
                    selected.append(kid)
            out.flush()
            os.fsync(out.fileno())
            # Hash the complete actual on-disk bytes without rematerializing a 64 MiB model.
            out.seek(0)
            whole = hashlib.sha384()
            whole.update(CONTENT_DOMAIN)
            whole.update(c.total_bytes.to_bytes(8, "big"))
            readback = 0
            while readback < c.total_bytes:
                chunk = out.read(min(65536, c.total_bytes-readback))
                if not chunk:
                    raise Reject("truncated published weight bytes")
                whole.update(chunk)
                readback += len(chunk)
            if readback != c.total_bytes or whole.digest() != expected_content_id:
                raise Reject("whole PCB1 weight identity mismatch")
            # Exclusive hardlink creation: does not replace a concurrent existing file.
            os.link(temp_path, dest, follow_symlinks=False)
            os.fsync(out.fileno())
        os.unlink(temp_path)
        temp_path = None
        if hasattr(os, "O_DIRECTORY"):
            d = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(d)
            finally: os.close(d)
        return FetchObservation(expected_catalog_digest, expected_content_id, c.total_bytes,
                                c.chunk_count, tuple(sorted(set(selected))), rejected, dest)
    except BaseException:
        # If the output was already linked before a rare directory-fsync failure,
        # never silently imply rollback: retain it for explicit caller reconciliation.
        raise
    finally:
        if temp_path is not None:
            try: os.unlink(temp_path)
            except FileNotFoundError: pass
