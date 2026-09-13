"""Candidate cross-plane snapshot token and ABA detector.

The five source crates currently expose independent fresh-readback APIs.  This
module freezes the smallest interface an eventual owner must provide: every
plane observation carries the same authenticated transaction token and exact
bytes.  It intentionally does not pretend that a double sample is an atomic
database transaction; the missing upstream seam remains a typed blocker.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Callable, Sequence


MAX_TRANSACTION_ID_BYTES = 32
MAX_VERSION = 2**64 - 1
MAX_EXACT_BYTES = 16 * 1024 * 1024


class AtomicityReject(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _digest(domain: str, payload: bytes) -> bytes:
    encoded = domain.encode("utf-8")
    return hashlib.sha256(struct.pack("<I", len(encoded)) + encoded + payload).digest()


@dataclass(frozen=True)
class PlaneObservation:
    plane: str
    transaction_id: bytes
    version: int
    exact_bytes: bytes
    # An owner-issued mutation generation is optional for the legacy
    # candidate adapter.  When present it is part of the authenticated cut
    # and must be equal for every plane and every fresh sample.  Unlike a
    # local read counter, this value is expected to advance on every durable
    # source mutation; that is what lets the ABA fixture reject A -> B -> A
    # even when the transaction id and bytes have returned to A.
    source_generation: int | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.plane, str)
            or not self.plane
            or self.plane.encode("ascii", "ignore").decode("ascii") != self.plane
            or not isinstance(self.transaction_id, (bytes, bytearray))
            or len(self.transaction_id) != MAX_TRANSACTION_ID_BYTES
            or not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or not 0 <= self.version <= MAX_VERSION
            or not isinstance(self.exact_bytes, (bytes, bytearray))
            or len(self.exact_bytes) > MAX_EXACT_BYTES
            or (
                self.source_generation is not None
                and (
                    not isinstance(self.source_generation, int)
                    or isinstance(self.source_generation, bool)
                    or not 0 <= self.source_generation <= MAX_VERSION
                )
            )
        ):
            raise AtomicityReject("observation_encoding")
        # Freeze mutable bytearray inputs at the boundary.  Otherwise a
        # caller could mutate an observation after its digest was computed.
        object.__setattr__(self, "transaction_id", bytes(self.transaction_id))
        object.__setattr__(self, "exact_bytes", bytes(self.exact_bytes))

    @property
    def bytes_digest(self) -> bytes:
        return _digest("trnm.poco-ai.cross-plane-exact-bytes.v1", self.exact_bytes)


@dataclass(frozen=True)
class AuthenticatedSnapshot:
    transaction_id: bytes
    version: int
    observations: tuple[PlaneObservation, ...]
    snapshot_digest: bytes
    source_generation: int | None = None


REQUIRED_PLANES = ("DA", "Agent", "Verify", "MVCC", "Settlement", "Order")


def authenticate_snapshot(observations: Sequence[PlaneObservation]) -> AuthenticatedSnapshot:
    """Require one common token/version over all required planes.

    ``source_generation`` is an owner-issued durable mutation generation.  It
    is deliberately optional only to preserve compatibility with the earlier
    candidate readback fixture.  New callers should provide it; the strict
    helper below rejects unsequenced samples because same-token ABA cannot be
    detected from bytes alone.
    """

    if len(observations) != len(REQUIRED_PLANES):
        raise AtomicityReject("plane_count")
    if any(not isinstance(item, PlaneObservation) for item in observations):
        raise AtomicityReject("observation_type")
    by_name = {item.plane: item for item in observations}
    if tuple(sorted(by_name)) != tuple(sorted(REQUIRED_PLANES)):
        raise AtomicityReject("plane_set")
    first = observations[0]
    if any(
        item.transaction_id != first.transaction_id or item.version != first.version
        for item in observations
    ):
        raise AtomicityReject("mixed_transaction")
    generations = {item.source_generation for item in observations}
    if len(generations) > 1:
        raise AtomicityReject("mixed_generation")
    source_generation = next(iter(generations))
    preimage = bytearray(first.transaction_id + struct.pack("<Q", first.version))
    if source_generation is not None:
        preimage += b"G" + struct.pack("<Q", source_generation)
    for name in REQUIRED_PLANES:
        item = by_name[name]
        encoded_name = name.encode("ascii")
        preimage += struct.pack("<H", len(encoded_name)) + encoded_name
        preimage += item.bytes_digest
    snapshot_digest = _digest("trnm.poco-ai.cross-plane-authenticated-snapshot.v1", bytes(preimage))
    return AuthenticatedSnapshot(
        first.transaction_id,
        first.version,
        tuple(observations),
        snapshot_digest,
        source_generation,
    )


def double_sample(
    provider: Callable[[], Sequence[PlaneObservation]],
) -> AuthenticatedSnapshot:
    """Detect a changing token, bytes, or supplied mutation generation.

    Without an owner-issued ``source_generation`` an A -> B -> A replay is
    indistinguishable from a stable read and remains an explicit open gap.
    Use :func:`double_sample_strict` for the frozen interface that closes that
    ambiguity.
    """

    first = authenticate_snapshot(provider())
    second = authenticate_snapshot(provider())
    if first.transaction_id != second.transaction_id or first.version != second.version:
        raise AtomicityReject("source_changed")
    if first.source_generation != second.source_generation:
        raise AtomicityReject("source_changed")
    if first.snapshot_digest != second.snapshot_digest:
        raise AtomicityReject("source_changed")
    return second


def double_sample_strict(
    provider: Callable[[], Sequence[PlaneObservation]],
) -> AuthenticatedSnapshot:
    """Require an owner mutation generation and reject generation ABA.

    The provider must return all six planes with a non-``None`` generation.
    The generation must remain exactly equal across both observations.  A
    higher value is not accepted here: it proves that a write occurred between
    reads and therefore cannot be treated as one atomic cut.  The eventual
    Node-owned implementation should replace this double-sample seam with an
    authenticated transaction/snapshot API once A11--A15 publish accepted
    interfaces.
    """

    first = authenticate_snapshot(provider())
    if first.source_generation is None:
        raise AtomicityReject("generation_missing")
    second = authenticate_snapshot(provider())
    if second.source_generation is None:
        raise AtomicityReject("generation_missing")
    if (
        first.transaction_id != second.transaction_id
        or first.version != second.version
        or first.source_generation != second.source_generation
        or first.snapshot_digest != second.snapshot_digest
    ):
        raise AtomicityReject("source_changed")
    return second


def snapshot_to_dict(snapshot: AuthenticatedSnapshot) -> dict[str, object]:
    return {
        "transaction_id": snapshot.transaction_id.hex(),
        "version": snapshot.version,
        "source_generation": snapshot.source_generation,
        "planes": [item.plane for item in snapshot.observations],
        "snapshot_digest": snapshot.snapshot_digest.hex(),
    }


__all__ = [
    "AuthenticatedSnapshot",
    "AtomicityReject",
    "MAX_EXACT_BYTES",
    "MAX_TRANSACTION_ID_BYTES",
    "MAX_VERSION",
    "PlaneObservation",
    "REQUIRED_PLANES",
    "authenticate_snapshot",
    "double_sample",
    "double_sample_strict",
    "snapshot_to_dict",
]
