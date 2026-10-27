"""PAB1: bounded atomic *visibility* of a complete pinned PCB1 Cell bundle.

Research only. The caller MUST independently authenticate PCB1, release/evaluator
signatures, export consent and current chain/Hepta authority. The default fetcher is
PCS1, which verifies real ML-DSA-65 per chunk. This layer verifies every resulting
object again and publishes exactly one no-clobber readiness index. It grants NO
model adoption, storage payment, FinalUse, VerifiedWork or chain authority.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile

MANIFEST_DOMAIN = b"TRNM/PoN/PQCellManifest/v1\0"
CONTENT_DOMAIN = b"TRNM/PoN/PQCellContent/v1\0"
CATALOG_DOMAIN = b"TRNM/PoN/PQCellCustody/v1\0catalog\0"
BASE = bytes(32)
MAX_OBJECT = 64 << 20
MAX_BUNDLE = 256 << 20
MAX_CELLS = 16
ENTRY_BYTES = 96
POINTER_MAGIC = b"PAB1\x01"

class BundleReject(ValueError):
    pass

def _bytes(v, n, label, *, nonzero=False):
    if type(v) is not bytes or len(v) != n or (nonzero and v == bytes(n)):
        raise BundleReject(label)
    return v

def _integer(v, label, *, low=1, high=MAX_OBJECT):
    if type(v) is not int or not low <= v <= high:
        raise BundleReject(label)
    return v

def _sha384(domain: bytes, b: bytes) -> bytes:
    return hashlib.sha384(domain + len(b).to_bytes(4, 'big') + b).digest()

@dataclass(frozen=True)
class Entry:
    selector: bytes
    generation: int
    content_id: bytes
    length: int
    def encoded(self):
        return (_bytes(self.selector, 32, 'selector') +
                _integer(self.generation, 'generation', high=(1 << 64)-1).to_bytes(8, 'big') +
                _bytes(self.content_id, 48, 'content id', nonzero=True) +
                _integer(self.length, 'length').to_bytes(8, 'big'))
    @property
    def filename(self):
        return 'base.bin' if self.selector == BASE else 'cell-' + self.selector.hex() + '.bin'

@dataclass(frozen=True)
class Manifest:
    raw: bytes
    digest: bytes
    network: bytes
    family: bytes
    parent: bytes
    generation: int
    entries: tuple[Entry, ...]

def parse_manifest(raw: bytes) -> Manifest:
    if type(raw) is not bytes or not 262 <= len(raw) <= 166 + MAX_CELLS * ENTRY_BYTES:
        raise BundleReject('PCB1 length')
    if raw[:5] != b'PCB1\x01' or not 1 <= raw[165] <= MAX_CELLS or len(raw) != 166 + raw[165]*ENTRY_BYTES:
        raise BundleReject('PCB1 version/count')
    gen = int.from_bytes(raw[101:109], 'big')
    base = Entry(BASE, gen, raw[109:157], int.from_bytes(raw[157:165], 'big'))
    base.encoded()
    cells = []
    for i in range(raw[165]):
        o = 166 + i*ENTRY_BYTES
        c = Entry(raw[o:o+32], int.from_bytes(raw[o+32:o+40], 'big'),
                  raw[o+40:o+88], int.from_bytes(raw[o+88:o+96], 'big'))
        c.encoded()
        if c.selector == BASE:
            raise BundleReject('reserved Base selector')
        cells.append(c)
    if [c.selector for c in cells] != sorted(set(c.selector for c in cells)):
        raise BundleReject('noncanonical Cell ordering')
    network = _bytes(raw[5:37], 32, 'network', nonzero=True)
    family = _bytes(raw[37:69], 32, 'family', nonzero=True)
    parent = _bytes(raw[69:101], 32, 'parent')
    if sum(e.length for e in (base, *cells)) > MAX_BUNDLE:
        raise BundleReject('bundle byte budget')
    return Manifest(raw, _sha384(MANIFEST_DOMAIN, raw), network, family, parent,
                    gen, (base, *cells))

@dataclass(frozen=True)
class Route:
    selector: bytes
    catalog_bytes: bytes
    expected_catalog_digest: bytes
    peers: tuple

@dataclass(frozen=True)
class BundleObservation:
    """Readback observation only. Not a capability or an authorization token."""
    manifest_digest: bytes
    objects_checked: int
    bytes_checked: int
    index_path: Path

def _catalog_check(raw, expected_digest, m, entry):
    _bytes(expected_digest, 48, 'catalog digest', nonzero=True)
    if type(raw) is not bytes or len(raw) != 157 or raw[:5] != b'PCC1\x01':
        raise BundleReject('PCC1 framing')
    if (raw[5:37] != m.network or raw[37:85] != m.digest or
            int.from_bytes(raw[85:93], 'big') != m.generation or
            int.from_bytes(raw[93:101], 'big') != entry.length):
        raise BundleReject('PCC1 model binding')
    size, count = int.from_bytes(raw[101:105], 'big'), int.from_bytes(raw[105:109], 'big')
    if (not 1 <= size <= (1 << 20) or not 1 <= count <= 4096 or
            not (count - 1)*size < entry.length <= count*size or
            raw[109:157] == bytes(48)):
        raise BundleReject('PCC1 shape')
    if hashlib.sha384(CATALOG_DOMAIN + raw).digest() != expected_digest:
        raise BundleReject('PCC1 digest not pinned')

def _private_dir(path):
    if path.is_symlink() or not path.is_dir():
        raise BundleReject('private directory absent or symlink')
    st = path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise BundleReject('private directory owner/mode')

def _subdir(root, name):
    p = root / name
    try: p.mkdir(mode=0o700)
    except FileExistsError: pass
    _private_dir(p)
    return p

def _content_readback(path: Path, e: Entry):
    if path.is_symlink():
        raise BundleReject('symlink object')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != e.length or before.st_nlink != 1:
            raise BundleReject('object metadata')
        h = hashlib.sha384()
        h.update(CONTENT_DOMAIN)
        h.update(e.length.to_bytes(8, 'big'))
        left = e.length
        while left:
            data = os.read(fd, min(left, 65536))
            if not data: raise BundleReject('truncated object')
            h.update(data); left -= len(data)
        after = os.fstat(fd)
        if (before.st_ino, before.st_dev, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_dev, after.st_mtime_ns, after.st_ctime_ns):
            raise BundleReject('object mutated during readback')
        if h.digest() != e.content_id:
            raise BundleReject('wrong PCB1 whole-object bytes')
    finally:
        os.close(fd)

def _pointer(m: Manifest, token: bytes):
    return (POINTER_MAGIC + m.digest + m.network + m.family + m.parent +
            m.generation.to_bytes(8, 'big') + bytes([len(m.entries)]) +
            _bytes(token, 16, 'stage token', nonzero=True) +
            b''.join(e.encoded() for e in m.entries))

def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try: os.fsync(fd)
    finally: os.close(fd)

def _pins(m, *, expected_manifest_digest, expected_network, expected_family,
          expected_parent, expected_generation):
    if (m.digest != _bytes(expected_manifest_digest, 48, 'manifest digest', nonzero=True)
            or m.network != _bytes(expected_network, 32, 'network', nonzero=True)
            or m.family != _bytes(expected_family, 32, 'family', nonzero=True)
            or m.parent != _bytes(expected_parent, 32, 'parent')
            or type(expected_generation) is not int or m.generation != expected_generation):
        raise BundleReject('caller-pinned PCB1 context')

def publish_bundle(*, manifest_bytes, expected_manifest_digest, expected_network,
                   expected_family, expected_parent, expected_generation,
                   routes, requester_id, root, fetcher=None):
    """Publish one readiness pointer only after all Base+Cell objects pass readback.

    Upstream PCS1 verifies each signed PCR1 on the real fetcher. A custom test
    fetcher does NOT provide PQ authentication and must never be a product plug-in.
    """
    m = parse_manifest(manifest_bytes)
    _pins(m, expected_manifest_digest=expected_manifest_digest,
          expected_network=expected_network, expected_family=expected_family,
          expected_parent=expected_parent, expected_generation=expected_generation)
    _bytes(requester_id, 32, 'requester', nonzero=True)
    if type(routes) is not tuple or len(routes) != len(m.entries):
        raise BundleReject('exact route count required')
    found = {}
    for route in routes:
        if not isinstance(route, Route) or type(route.selector) is not bytes or route.selector in found:
            raise BundleReject('invalid/duplicate route')
        found[route.selector] = route
    if set(found) != {e.selector for e in m.entries}:
        raise BundleReject('missing/extra Cell route')
    for e in m.entries:
        r = found[e.selector]
        if type(r.peers) is not tuple:
            raise BundleReject('bounded tuple of peers required')
        _catalog_check(r.catalog_bytes, r.expected_catalog_digest, m, e)
    root = Path(root)
    _private_dir(root)
    pending = _subdir(root, 'pending')
    published = _subdir(root, 'published')
    pointer = published / (m.digest.hex() + '.pab1')
    if pointer.exists() or pointer.is_symlink():
        raise BundleReject('immutable release already published')
    if fetcher is None:
        from pq_cell_swarm import fetch_to_immutable_file
        fetcher = fetch_to_immutable_file
    token = secrets.token_bytes(16)
    _bytes(token, 16, 'stage token', nonzero=True)
    stage = pending / ('stage-' + token.hex())
    stage.mkdir(mode=0o700)
    linked = False
    try:
        for e in m.entries:
            r = found[e.selector]
            output = stage / e.filename
            fetcher(catalog_bytes=r.catalog_bytes, expected_catalog_digest=r.expected_catalog_digest,
                    expected_release=m.digest, expected_content_id=e.content_id,
                    requester_id=requester_id, peers=r.peers, destination=output)
            _content_readback(output, e)
        meta = stage / 'manifest.pcb1'
        with meta.open('xb') as f:
            f.write(m.raw); f.flush(); os.fsync(f.fileno())
        _fsync_dir(stage)
        idx = stage / 'ready.pab1'
        with idx.open('xb') as f:
            f.write(_pointer(m, token)); f.flush(); os.fsync(f.fileno())
        _fsync_dir(stage)
        # Hardlink is a no-replace, single-file publication linearization point.
        os.link(idx, pointer, follow_symlinks=False)
        linked = True
        _fsync_dir(published)
        _fsync_dir(pending)
        return BundleObservation(m.digest, len(m.entries), sum(e.length for e in m.entries), pointer)
    finally:
        # Failure before publication leaves no visible release. Failure AFTER link
        # is indeterminate: keep the stage and pointer for exact cold reconciliation.
        if not linked:
            shutil.rmtree(stage)

def read_published(*, manifest_bytes, expected_manifest_digest, expected_network,
                   expected_family, expected_parent, expected_generation, root):
    """Cold full-byte readback, no authority inference. Caller supplies trusted pins."""
    m = parse_manifest(manifest_bytes)
    _pins(m, expected_manifest_digest=expected_manifest_digest,
          expected_network=expected_network, expected_family=expected_family,
          expected_parent=expected_parent, expected_generation=expected_generation)
    root = Path(root)
    _private_dir(root)
    pending, published = root / 'pending', root / 'published'
    _private_dir(pending); _private_dir(published)
    pointer = published / (m.digest.hex() + '.pab1')
    # Open no-follow; only a published hardlink to the sealed staged index counts.
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(pointer, flags)
    try:
        pst = os.fstat(fd)
        if not stat.S_ISREG(pst.st_mode) or pst.st_nlink != 2:
            raise BundleReject('published index link ownership')
        raw = os.read(fd, 5+48+32*3+8+1+16+17*ENTRY_BYTES+1)
        if raw != _pointer(m, raw[5+48+32*3+8+1:5+48+32*3+8+1+16]):
            raise BundleReject('altered or truncated readiness pointer')
    finally:
        os.close(fd)
    token = raw[5+48+32*3+8+1:5+48+32*3+8+1+16]
    stage = pending / ('stage-' + token.hex())
    _private_dir(stage)
    idx = stage / 'ready.pab1'
    ist = idx.stat(follow_symlinks=False)
    if (ist.st_ino, ist.st_dev) != (pst.st_ino, pst.st_dev):
        raise BundleReject('index is not staged hardlink')
    meta = stage / 'manifest.pcb1'
    fd = os.open(meta, flags)
    try:
        mst = os.fstat(fd)
        if not stat.S_ISREG(mst.st_mode) or mst.st_size != len(m.raw):
            raise BundleReject('staged manifest metadata')
        if os.read(fd, len(m.raw)+1) != m.raw:
            raise BundleReject('stale manifest in stage')
    finally:
        os.close(fd)
    for e in m.entries:
        _content_readback(stage / e.filename, e)
    return BundleObservation(m.digest, len(m.entries), sum(e.length for e in m.entries), pointer)
