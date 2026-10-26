"""PCB1: signed Cell weight manifest/evaluator/release research boundary.

Requires genuine TPQ1 ML-DSA-65 for each release and evaluator attestation.
A caller-supplied allowlist is NOT independently authenticated; passing this
check never means evaluation validity, durable custody, model adoption,
public export permission, actual P2P availability or Hepta Final-use.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from pq_envelope import (Reject, make_unsigned, public_key_id,
                         sign_reference, verify_reference)

MAGIC = b"PCB1"
VERSION = 1
CELL_BYTES = 96
HEADER_BYTES = 166
MAX_CELLS = 16
MAX_CONTENT_BYTES = 64 * 1024 * 1024
CONTENT_DOMAIN = b"TRNM/PoN/PQCellContent/v1\x00"
MANIFEST_DOMAIN = b"TRNM/PoN/PQCellManifest/v1\x00"
CONTEXT_DOMAIN = b"TRNM/PoN/PQCellContext/v1\x00"
EVAL_DOMAIN = b"TRNM/PoN/PQCellEvaluation/v1\x00"
RELEASE_DOMAIN = b"TRNM/PoN/PQCellRelease/v1\x00"


def _exact(value: bytes, n: int, name: str, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != n or (nonzero and value == bytes(n)):
        raise Reject(name)
    return value


def _u64(value: int, name: str, *, nonzero: bool = False) -> bytes:
    if type(value) is not int or not int(nonzero) <= value < 1 << 64:
        raise Reject(name)
    return value.to_bytes(8, "big")


def content_id(data: bytes) -> bytes:
    if type(data) is not bytes or not 0 < len(data) <= MAX_CONTENT_BYTES:
        raise Reject("content type/size")
    return hashlib.sha384(CONTENT_DOMAIN + len(data).to_bytes(8, "big") + data).digest()


@dataclass(frozen=True)
class CellRef:
    cell_id: bytes
    generation: int
    weight_id: bytes
    weight_size: int

    def encode(self) -> bytes:
        return (_exact(self.cell_id, 32, "cell id", nonzero=True)
                + _u64(self.generation, "cell generation", nonzero=True)
                + _exact(self.weight_id, 48, "weight id", nonzero=True)
                + _u64(self.weight_size, "weight size", nonzero=True))


@dataclass(frozen=True)
class CellBundle:
    network: bytes
    family: bytes
    parent_release: bytes
    generation: int
    base_weight_id: bytes
    base_weight_size: int
    cells: tuple[CellRef, ...]

    def encode(self) -> bytes:
        if type(self.cells) is not tuple or not 1 <= len(self.cells) <= MAX_CELLS:
            raise Reject("cell count")
        encoded = b"".join(c.encode() for c in self.cells)
        ids = [c.cell_id for c in self.cells]
        if ids != sorted(set(ids)):
            raise Reject("cell IDs must be sorted unique")
        return (MAGIC + bytes([VERSION])
                + _exact(self.network, 32, "network", nonzero=True)
                + _exact(self.family, 32, "family", nonzero=True)
                + _exact(self.parent_release, 32, "parent")
                + _u64(self.generation, "generation", nonzero=True)
                + _exact(self.base_weight_id, 48, "base weight", nonzero=True)
                + _u64(self.base_weight_size, "base size", nonzero=True)
                + bytes([len(self.cells)]) + encoded)


def parse_bundle(data: bytes) -> CellBundle:
    if type(data) is not bytes or len(data) < HEADER_BYTES + CELL_BYTES:
        raise Reject("manifest length")
    if data[:4] != MAGIC or data[4] != VERSION:
        raise Reject("manifest version")
    count = data[165]
    if not 1 <= count <= MAX_CELLS or len(data) != HEADER_BYTES + count * CELL_BYTES:
        raise Reject("manifest cell count/trailing data")
    cells = []
    for i in range(count):
        off = HEADER_BYTES + i * CELL_BYTES
        cells.append(CellRef(data[off:off + 32], int.from_bytes(data[off + 32:off + 40], "big"),
                             data[off + 40:off + 88], int.from_bytes(data[off + 88:off + 96], "big")))
    v = CellBundle(data[5:37], data[37:69], data[69:101],
                   int.from_bytes(data[101:109], "big"),
                   data[109:157], int.from_bytes(data[157:165], "big"), tuple(cells))
    if v.encode() != data:
        raise Reject("noncanonical manifest")
    return v


def manifest_id(bundle: CellBundle) -> bytes:
    data = bundle.encode()
    return hashlib.sha384(MANIFEST_DOMAIN + len(data).to_bytes(4, "big") + data).digest()


def _context(bundle: CellBundle) -> bytes:
    return hashlib.sha256(CONTEXT_DOMAIN + bundle.network + bundle.parent_release).digest()


def _evaluation_payload(bundle: CellBundle, plan_id: bytes) -> bytes:
    return EVAL_DOMAIN + manifest_id(bundle) + _exact(plan_id, 48, "evaluation plan", nonzero=True)


def _release_payload(bundle: CellBundle, plan_id: bytes, reviewer_ids: tuple[bytes, ...]) -> bytes:
    if type(reviewer_ids) is not tuple or not 2 <= len(reviewer_ids) <= 3:
        raise Reject("reviewer quorum size")
    if list(reviewer_ids) != sorted(set(reviewer_ids)):
        raise Reject("reviewer quorum identities")
    return (RELEASE_DOMAIN + manifest_id(bundle)
            + _exact(plan_id, 48, "evaluation plan", nonzero=True)
            + bytes([len(reviewer_ids)]) + b"".join(_exact(x, 32, "reviewer key") for x in reviewer_ids))


def sign_review_fixture(bundle: CellBundle, plan_id: bytes, *, public_pem: bytes,
                        private_key_path: Path, expires_at: int, sequence: int) -> bytes:
    """Offline test fixture signer, not an evaluator-owner API."""
    p = _evaluation_payload(bundle, plan_id)
    unsigned = make_unsigned(purpose=3, network=bundle.network, context=_context(bundle),
                             signer_key_id=public_key_id(public_pem),
                             owner_generation=bundle.generation,
                             operation_sequence=sequence, expires_at=expires_at, payload=p)
    return sign_reference(unsigned, private_key_path=private_key_path)


def sign_release_fixture(bundle: CellBundle, plan_id: bytes, reviewer_ids: tuple[bytes, ...],
                         *, public_pem: bytes, private_key_path: Path,
                         expires_at: int, sequence: int) -> bytes:
    """Offline test fixture signer, not a release authority API."""
    payload = _release_payload(bundle, plan_id, reviewer_ids)
    unsigned = make_unsigned(purpose=4, network=bundle.network, context=_context(bundle),
                             signer_key_id=public_key_id(public_pem),
                             owner_generation=bundle.generation,
                             operation_sequence=sequence, expires_at=expires_at, payload=payload)
    return sign_reference(unsigned, private_key_path=private_key_path)


@dataclass(frozen=True)
class ResearchObservation:
    manifest_id: bytes
    approved_signers: tuple[bytes, ...]
    content_objects_checked: int
    adoption_authorized: bool = False


def verify_release_research(
    manifest_bytes: bytes, *, base_weights: bytes, cell_weights: dict[bytes, bytes],
    evaluation_plan_id: bytes, release_public_pem: bytes, release_frame: bytes,
    reviewer_frames: tuple[tuple[bytes, bytes], ...],
    trusted_release_key_id: bytes, trusted_reviewer_ids: frozenset[bytes],
    expected_network: bytes, expected_family: bytes, expected_parent: bytes,
    expected_generation: int, expected_sequence: int, now: int,
) -> ResearchObservation:
    """Offline signature/content observation; never publishes/adopts any release."""
    bundle = parse_bundle(manifest_bytes)
    if (bundle.network != _exact(expected_network, 32, "expected network", nonzero=True)
            or bundle.family != _exact(expected_family, 32, "expected family", nonzero=True)
            or bundle.parent_release != _exact(expected_parent, 32, "expected parent")
            or type(expected_generation) is not int or bundle.generation != expected_generation):
        raise Reject("manifest/context mismatch")
    if len(base_weights) != bundle.base_weight_size or content_id(base_weights) != bundle.base_weight_id:
        raise Reject("base content mismatch")
    if type(cell_weights) is not dict or set(cell_weights) != {c.cell_id for c in bundle.cells}:
        raise Reject("cell content set mismatch")
    for c in bundle.cells:
        data = cell_weights[c.cell_id]
        if len(data) != c.weight_size or content_id(data) != c.weight_id:
            raise Reject("cell content mismatch")
    if type(trusted_reviewer_ids) is not frozenset or len(trusted_reviewer_ids) < 3:
        raise Reject("trusted evaluator roster unavailable")
    if type(reviewer_frames) is not tuple or not 2 <= len(reviewer_frames) <= 3:
        raise Reject("quorum")
    valid = set()
    payload = _evaluation_payload(bundle, evaluation_plan_id)
    for pem, frame in reviewer_frames:
        key_id = public_key_id(pem)
        if key_id not in trusted_reviewer_ids or key_id in valid:
            raise Reject("untrusted or repeated reviewer")
        verify_reference(frame, payload=payload, public_pem=pem,
                         expected_network=bundle.network, expected_context=_context(bundle),
                         expected_purpose=3, expected_generation=bundle.generation,
                         expected_sequence=expected_sequence, now=now)
        valid.add(key_id)
    reviewer_ids = tuple(sorted(valid))
    if public_key_id(release_public_pem) != _exact(trusted_release_key_id, 32, "releaser"):
        raise Reject("release owner not trusted")
    if trusted_release_key_id in valid:
        raise Reject("release owner cannot count as reviewer")
    verify_reference(release_frame, payload=_release_payload(bundle, evaluation_plan_id, reviewer_ids),
                     public_pem=release_public_pem, expected_network=bundle.network,
                     expected_context=_context(bundle), expected_purpose=4,
                     expected_generation=bundle.generation, expected_sequence=expected_sequence,
                     now=now)
    return ResearchObservation(manifest_id(bundle), reviewer_ids, 1 + len(bundle.cells))
