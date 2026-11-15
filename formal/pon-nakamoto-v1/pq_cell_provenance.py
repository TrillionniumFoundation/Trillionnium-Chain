"""PCV1: research-only *complete* PCB1 -> PCA1 -> PCC1 Cell content check.

No authority to publish, reward, Final-use, or assert continuous custody. A caller
MUST independently pin the expected release frame, manifest and catalog hashes,
trusted reviewer roster, generation, plan and current owner head. This verifier
replays actual pure ML-DSA-65 signatures; no signed Boolean or trust-by-digest.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from pq_envelope import Reject, public_key_id, verify_reference
from pq_cell_custody import (
    Catalog, CatalogPinObservation, catalog_from_chunks, catalog_id,
    parse_catalog, release_frame_id, verify_catalog_binding_research,
)

MANIFEST_MAGIC = b"PCB1"
MANIFEST_DOMAIN = b"TRNM/PoN/PQCellManifest/v1\x00"
CONTENT_DOMAIN = b"TRNM/PoN/PQCellContent/v1\x00"
CONTEXT_DOMAIN = b"TRNM/PoN/PQCellContext/v1\x00"
EVAL_DOMAIN = b"TRNM/PoN/PQCellEvaluation/v1\x00"
RELEASE_DOMAIN = b"TRNM/PoN/PQCellRelease/v1\x00"
HEADER_BYTES = 166
CELL_BYTES = 96
MAX_CELLS = 16
MAX_COMPLETE_OBJECT_BYTES = 64 * 1024 * 1024
BASE_SELECTOR = bytes(32)


def _b(value: bytes, size: int, field: str, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != size or (nonzero and value == bytes(size)):
        raise Reject(field)
    return value


def _u64(data: bytes, field: str) -> int:
    v = int.from_bytes(_b(data, 8, field), 'big')
    if v == 0:
        raise Reject(field)
    return v


@dataclass(frozen=True)
class ParsedPCB1:
    network: bytes
    family: bytes
    parent: bytes
    generation: int
    manifest_digest: bytes
    base_id: bytes
    base_size: int
    # (cell_id, generation, content_id, size)
    cells: tuple[tuple[bytes, int, bytes, int], ...]


def parse_pcb1_strict(data: bytes) -> ParsedPCB1:
    """Second explicit wire decoder: strict PCB1 contract, no model loader or grant."""
    if type(data) is not bytes or not HEADER_BYTES + CELL_BYTES <= len(data) <= HEADER_BYTES + MAX_CELLS*CELL_BYTES:
        raise Reject('PCB1 length')
    if data[:5] != MANIFEST_MAGIC + b'\x01':
        raise Reject('PCB1 magic/version')
    count = data[165]
    if not 1 <= count <= MAX_CELLS or len(data) != HEADER_BYTES + count*CELL_BYTES:
        raise Reject('PCB1 count/framing')
    network, family, parent = _b(data[5:37],32,'network',True), _b(data[37:69],32,'family',True), _b(data[69:101],32,'parent')
    generation, base_id, base_size = _u64(data[101:109], 'generation'), _b(data[109:157],48,'base id',True), _u64(data[157:165], 'base size')
    if base_size > MAX_COMPLETE_OBJECT_BYTES:
        raise Reject('oversized base')
    cells=[]
    for i in range(count):
        off = HEADER_BYTES + i*CELL_BYTES
        cell_id = _b(data[off:off+32],32,'cell id',True)
        cgen = _u64(data[off+32:off+40], 'cell generation')
        cid = _b(data[off+40:off+88],48,'cell content id',True)
        csize = _u64(data[off+88:off+96], 'cell size')
        if csize > MAX_COMPLETE_OBJECT_BYTES:
            raise Reject('oversized cell')
        cells.append((cell_id,cgen,cid,csize))
    ids = [v[0] for v in cells]
    if ids != sorted(set(ids)):
        raise Reject('unsorted/duplicate Cell')
    manifest = hashlib.sha384(MANIFEST_DOMAIN + len(data).to_bytes(4,'big') + data).digest()
    return ParsedPCB1(network, family, parent, generation, manifest, base_id, base_size, tuple(cells))


def _purpose_context(m: ParsedPCB1) -> bytes:
    return hashlib.sha256(CONTEXT_DOMAIN + m.network + m.parent).digest()


def _check_full_chunks(chunks: tuple[bytes, ...], size: int, expected_id: bytes,
                       catalog: Catalog) -> None:
    if type(chunks) is not tuple or not chunks or size > MAX_COMPLETE_OBJECT_BYTES:
        raise Reject('complete chunk set required')
    if len(chunks) != catalog.chunk_count or sum(len(c) if type(c) is bytes else 0 for c in chunks) != size:
        raise Reject('complete chunk sizing')
    computed = catalog_from_chunks(catalog.network, catalog.release_manifest, catalog.generation,
                                   chunks, catalog.chunk_size)
    if computed != catalog:
        raise Reject('different Merkle root or partition')
    h = hashlib.sha384(CONTENT_DOMAIN + size.to_bytes(8, 'big'))
    for c in chunks:
        h.update(c)
    if h.digest() != expected_id:
        raise Reject('not the Cell weights committed in PCB1')


@dataclass(frozen=True)
class PQProvenanceObservation:
    """Non-authoritative diagnostics; no deployment, custody or reward decision."""
    manifest_digest: bytes
    catalog_digest: bytes
    object_selector: bytes
    object_content_id: bytes
    object_bytes: int
    checked_chunks: int
    observed_reviewer_ids: tuple[bytes, ...]
    release_key_id: bytes


def verify_cell_provenance_research(
    *, manifest_bytes: bytes, catalog_bytes: bytes, complete_chunks: tuple[bytes, ...],
    object_selector: bytes, release_frame: bytes, catalog_binding_frame: bytes,
    release_public_pem: bytes, reviewer_frames: tuple[tuple[bytes, bytes], ...],
    expected_network: bytes, expected_family: bytes, expected_parent: bytes,
    expected_generation: int, expected_sequence: int, expected_plan_id: bytes,
    expected_manifest_digest: bytes, expected_release_frame_id: bytes,
    expected_catalog_digest: bytes, expected_prior_catalog_head: bytes,
    trusted_release_key_id: bytes, trusted_reviewer_ids: frozenset[bytes], now: int,
) -> PQProvenanceObservation:
    """Verify real PCB1 signatures and the exact content of one anchored PCC1 object.

    The trusted_* and expected_* values are NOT derived from untrusted peer packets.
    They must be checked by a separate authority owner, absent in this research profile.
    """
    m = parse_pcb1_strict(manifest_bytes)
    if (m.network != _b(expected_network,32,'expected network',True)
            or m.family != _b(expected_family,32,'expected family',True)
            or m.parent != _b(expected_parent,32,'expected parent')
            or type(expected_generation) is not int or m.generation != expected_generation
            or m.manifest_digest != _b(expected_manifest_digest,48,'manifest digest',True)):
        raise Reject('pinned PCB1 mismatch')
    if type(expected_sequence) is not int or expected_sequence <= 0:
        raise Reject('sequence')
    if type(now) is not int or not 0 <= now < (1<<64):
        raise Reject('time')
    selector = _b(object_selector,32,'object selector')
    if selector == BASE_SELECTOR:
        content_id, size = m.base_id, m.base_size
    else:
        match = next((v for v in m.cells if v[0] == selector), None)
        if match is None:
            raise Reject('unknown Cell selector')
        _,_,content_id,size=match
    c=parse_catalog(catalog_bytes)
    if (c.network != m.network or c.generation != m.generation
            or c.release_manifest != m.manifest_digest or c.total_bytes != size
            or catalog_id(c) != _b(expected_catalog_digest,48,'catalog digest',True)):
        raise Reject('PCC1 not bound to this exact PCB1 object')
    # Every chunk must reconstruct exactly the PCB1's independently committed object.
    _check_full_chunks(complete_chunks,size,content_id,c)

    # Only independent caller-approved release and reviewer identities are trusted.
    plan = _b(expected_plan_id,48,'plan',True)
    if type(trusted_reviewer_ids) is not frozenset or len(trusted_reviewer_ids) < 3:
        raise Reject('unavailable independently trusted reviewer roster')
    if type(reviewer_frames) is not tuple or not 2 <= len(reviewer_frames) <= 3:
        raise Reject('reviewer quorum')
    release_key = public_key_id(release_public_pem)
    if release_key != _b(trusted_release_key_id,32,'release signer',True):
        raise Reject('release signer mismatch')
    if release_key in trusted_reviewer_ids:
        raise Reject('release signer in trusted reviewer roster')
    reviewers = set()
    eval_payload = EVAL_DOMAIN + m.manifest_digest + plan
    for pub, frame in reviewer_frames:
        key = public_key_id(pub)
        if key not in trusted_reviewer_ids or key in reviewers or key == release_key:
            raise Reject('duplicate/untrusted/self evaluator')
        verify_reference(frame, payload=eval_payload, public_pem=pub,
                         expected_network=m.network, expected_context=_purpose_context(m),
                         expected_purpose=3, expected_generation=m.generation,
                         expected_sequence=expected_sequence, now=now)
        reviewers.add(key)
    chosen = tuple(sorted(reviewers))
    release_payload = (RELEASE_DOMAIN + m.manifest_digest + plan
                       + bytes([len(chosen)]) + b''.join(chosen))
    verify_reference(release_frame, payload=release_payload, public_pem=release_public_pem,
                     expected_network=m.network, expected_context=_purpose_context(m),
                     expected_purpose=4, expected_generation=m.generation,
                     expected_sequence=expected_sequence, now=now)
    if release_frame_id(release_frame) != _b(expected_release_frame_id,48,'release frame ID',True):
        raise Reject('unpinned original release signature')
    # PCA1 must use the SAME genuine release signer and exact verified PCB1 frame.
    pinned: CatalogPinObservation = verify_catalog_binding_research(
        catalog_bytes, release_frame=release_frame, binding_frame=catalog_binding_frame,
        signer_public_pem=release_public_pem,
        expected_release_frame_id=expected_release_frame_id,
        expected_signer_key_id=release_key,
        expected_previous_head=_b(expected_prior_catalog_head,48,'prior catalog head'),
        expected_network=m.network, expected_release_manifest=m.manifest_digest,
        expected_generation=m.generation, expected_sequence=expected_sequence, now=now)
    if pinned.catalog_digest != catalog_id(c):
        raise Reject('catalog binding mismatch')
    return PQProvenanceObservation(m.manifest_digest, pinned.catalog_digest, selector,
                                   content_id, size, len(complete_chunks), chosen, release_key)
