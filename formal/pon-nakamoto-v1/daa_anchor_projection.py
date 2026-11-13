"""Non-activated PoN ASERT branch-local anchor projection, research only.

This ledger assumes each supplied header was *already* independently validated
by the native PoN owner, including work, full application, legacy target,
network/parameters and historical availability. It performs some additional
syntactic checks but does NOT prove those assumptions. Never import peer-provided
projection rows as consensus authority. Persist/rebuild only with the native
validated branch owner. Every row is derived from its parent; no periodic
floating anchor or arbitrary 4096-header scan is needed for a target projection.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable

from daa_research_oracle import UINT64_MAX, UINT256_MAX, asert_target, mtp11


def _u64(value: object) -> bool:
    return type(value) is int and 0 <= value <= UINT64_MAX


def _hash32(value: object, nonzero: bool = True) -> bool:
    return (type(value) is bytes and len(value) == 32
            and (not nonzero or value != bytes(32)))


@dataclass(frozen=True)
class ProjectedAsertContext:
    network: bytes
    parameters: bytes
    genesis: bytes
    rule_commitment: bytes
    genesis_timestamp: int
    activation_height: int
    target_spacing: int
    half_life: int
    pow_limit: int
    clock: str  # raw or mtp11; different consensus rules, not runtime options

    def validate(self) -> None:
        if not (all(_hash32(x) for x in (
                self.network, self.parameters, self.genesis, self.rule_commitment))
                and _u64(self.genesis_timestamp)
                and _u64(self.activation_height) and 1 <= self.activation_height < UINT64_MAX
                and _u64(self.target_spacing) and self.target_spacing > 0
                and _u64(self.half_life) and self.half_life > 0
                and type(self.pow_limit) is int and 1 <= self.pow_limit <= UINT256_MAX
                and self.clock in ('raw', 'mtp11')):
            raise ValueError('PROJECTION_CONTEXT')

    def identity(self) -> bytes:
        self.validate()
        values = (self.genesis_timestamp, self.activation_height,
                  self.target_spacing, self.half_life)
        return hashlib.sha256(b'TRNM-PON-DAA-PROJECTION-CONTEXT-V1\0'
                              + self.network + self.parameters + self.genesis
                              + self.rule_commitment
                              + b''.join(x.to_bytes(8, 'big') for x in values)
                              + self.pow_limit.to_bytes(32, 'big')
                              + self.clock.encode('ascii')).digest()


@dataclass(frozen=True)
class VerifiedHeaderObservation:
    """Research input only: the name does not create a VerifiedWork capability."""
    claimed_id: bytes
    parent_id: bytes
    network: bytes
    parameters: bytes
    height: int
    timestamp: int
    target: int


@dataclass(frozen=True)
class AnchoredFacts:
    anchor_id: bytes
    predecessor_id: bytes
    anchor_height: int
    anchor_target: int
    predecessor_raw_time: int
    predecessor_mtp11_time: int


@dataclass(frozen=True)
class LocalProjection:
    block_id: bytes
    parent_id: bytes
    height: int
    timestamp: int
    target: int
    parent_commitment: bytes
    times_parent_first: tuple[int, ...]  # at most eleven; O(1) state per block
    anchored: AnchoredFacts | None
    commitment: bytes


def _projection_digest(context_id: bytes, row: LocalProjection) -> bytes:
    h = hashlib.sha256()
    h.update(b'TRNM-PON-DAA-LOCAL-PROJECTION-V1\0')
    h.update(context_id)
    h.update(row.block_id)
    h.update(row.parent_id)
    h.update(row.parent_commitment)
    h.update(row.height.to_bytes(8, 'big'))
    h.update(row.timestamp.to_bytes(8, 'big'))
    h.update(row.target.to_bytes(32, 'big'))
    h.update(len(row.times_parent_first).to_bytes(1, 'big'))
    for stamp in row.times_parent_first:
        h.update(stamp.to_bytes(8, 'big'))
    if row.anchored is None:
        h.update(b'\x00')
    else:
        a = row.anchored
        h.update(b'\x01')
        h.update(a.anchor_id)
        h.update(a.predecessor_id)
        h.update(a.anchor_height.to_bytes(8, 'big'))
        h.update(a.anchor_target.to_bytes(32, 'big'))
        h.update(a.predecessor_raw_time.to_bytes(8, 'big'))
        h.update(a.predecessor_mtp11_time.to_bytes(8, 'big'))
    return h.digest()


class ForkLocalAnchorProjection:
    """In-memory *research* extension of a trusted full-node header owner.

    Commitments detect accidental local inconsistency and allow deterministic
    rebuilding, but hashes alone cannot authenticate peer claims or prove W1.
    No fork is selected; both descendants persist until the caller prunes them.
    """

    def __init__(self, context: ProjectedAsertContext):
        context.validate()
        self.context = context
        self._context_id = context.identity()
        initial = LocalProjection(
            block_id=context.genesis,
            parent_id=bytes(32),
            height=0,
            timestamp=context.genesis_timestamp,
            target=context.pow_limit,
            parent_commitment=bytes(32),
            times_parent_first=(context.genesis_timestamp,),
            anchored=None,
            commitment=bytes(32),
        )
        self._rows: dict[bytes, LocalProjection] = {
            context.genesis: LocalProjection(**{
                **initial.__dict__,
                'commitment': _projection_digest(self._context_id, initial),
            })
        }

    def observe_assumed_validated(self, header: VerifiedHeaderObservation) -> LocalProjection:
        """Append one already-verified block, with zero ancestry reads.

        Any real native caller MUST verify proof, target and state and retain
        the original packet before passing this observation. A projection has
        no production, signing, replay or local-authority status.
        """
        ctx = self.context
        if not (isinstance(header, VerifiedHeaderObservation)
                and all(_hash32(x) for x in (
                    header.claimed_id, header.parent_id, header.network,
                    header.parameters))
                and header.claimed_id != ctx.genesis
                and header.claimed_id != header.parent_id
                and header.network == ctx.network and header.parameters == ctx.parameters
                and _u64(header.height) and header.height > 0
                and _u64(header.timestamp)
                and type(header.target) is int
                and 1 <= header.target <= ctx.pow_limit):
            raise ValueError('PROJECTION_HEADER_CONTEXT')
        parent = self._rows.get(header.parent_id)
        if parent is None:
            raise ValueError('PROJECTION_PARENT_UNAVAILABLE')
        if not self.validate_local_chain(parent.block_id):
            raise ValueError('PROJECTION_INTEGRITY')
        if parent.height == UINT64_MAX or header.height != parent.height + 1:
            raise ValueError('PROJECTION_HEIGHT')
        if header.claimed_id in self._rows:
            old = self._rows[header.claimed_id]
            if (old.parent_id == header.parent_id and old.height == header.height
                    and old.timestamp == header.timestamp and old.target == header.target):
                return old  # identical retransmission, not a second proof
            raise ValueError('PROJECTION_ID_COLLISION')
        if header.height == ctx.activation_height:
            anchor = AnchoredFacts(
                anchor_id=header.claimed_id,
                predecessor_id=parent.block_id,
                anchor_height=header.height,
                anchor_target=header.target,
                predecessor_raw_time=parent.timestamp,
                predecessor_mtp11_time=mtp11(parent.times_parent_first),
            )
        else:
            anchor = parent.anchored
            if header.height > ctx.activation_height and anchor is None:
                raise ValueError('PROJECTION_MISSING_ANCHOR')
            if header.height < ctx.activation_height and anchor is not None:
                raise ValueError('PROJECTION_EARLY_ANCHOR')
        times = (header.timestamp, *parent.times_parent_first[:10])
        row = LocalProjection(
            block_id=header.claimed_id,
            parent_id=header.parent_id,
            height=header.height,
            timestamp=header.timestamp,
            target=header.target,
            parent_commitment=parent.commitment,
            times_parent_first=times,
            anchored=anchor,
            commitment=bytes(32),
        )
        row = LocalProjection(**{
            **row.__dict__, 'commitment': _projection_digest(self._context_id, row),
        })
        self._rows[row.block_id] = row
        return row

    def expected_shadow_target(self, parent_id: bytes) -> int:
        """O(1) ASERT shadow, not a replacement for Node.expected_target."""
        row = self._rows.get(parent_id)
        if row is None:
            raise ValueError('PROJECTION_PARENT_UNAVAILABLE')
        if not self.validate_local_chain(parent_id):
            raise ValueError('PROJECTION_INTEGRITY')
        if row.anchored is None or row.height == UINT64_MAX:
            raise ValueError('PROJECTION_NOT_ACTIVE')
        anchor = row.anchored
        previous = (anchor.predecessor_raw_time if self.context.clock == 'raw'
                    else anchor.predecessor_mtp11_time)
        observed = (row.timestamp if self.context.clock == 'raw'
                    else mtp11(row.times_parent_first))
        return asert_target(
            anchor_target=anchor.anchor_target,
            anchor_parent_time=previous,
            parent_time=observed,
            anchor_height=anchor.anchor_height,
            candidate_height=row.height + 1,
            spacing=self.context.target_spacing,
            half_life=self.context.half_life,
            pow_limit=self.context.pow_limit,
        )

    def read_local(self, block_id: bytes) -> LocalProjection:
        if block_id not in self._rows:
            raise ValueError('PROJECTION_PARENT_UNAVAILABLE')
        return self._rows[block_id]

    def validate_local_chain(self, block_id: bytes) -> bool:
        """Check this projection and its immediate parent, NOT complete W1 history.

        This is a fail-closed local integrity predicate, not a proof of trusted
        network admission or a globally authenticated target/anchor. A complete
        restart audit must replay native verified headers and compare every row.
        """
        row = self.read_local(block_id)
        ctx = self.context
        if row.commitment != _projection_digest(self._context_id, row):
            return False
        if row.height == 0:
            return (row.parent_commitment == bytes(32)
                    and row.block_id == ctx.genesis
                    and row.timestamp == ctx.genesis_timestamp
                    and row.times_parent_first == (ctx.genesis_timestamp,)
                    and row.anchored is None)
        parent = self._rows.get(row.parent_id)
        if (parent is None or parent.commitment != row.parent_commitment
                or parent.commitment != _projection_digest(self._context_id, parent)
                or parent.height == UINT64_MAX or parent.height + 1 != row.height
                or row.times_parent_first != (row.timestamp, *parent.times_parent_first[:10])):
            return False
        if row.height == ctx.activation_height:
            expected = AnchoredFacts(row.block_id, parent.block_id, row.height,
                                     row.target, parent.timestamp,
                                     mtp11(parent.times_parent_first))
            return row.anchored == expected
        if row.height > ctx.activation_height:
            return parent.anchored is not None and row.anchored == parent.anchored
        return row.anchored is None and parent.anchored is None

    def audit_full_local_ancestry(self, tip: bytes, *, max_rows: int) -> int:
        """Cold/recovery self-consistency audit with an EXPLICIT finite read budget.

        Unlike the O(1) hot-path projection, this deliberately visits every
        stored ancestor and checks that it is linked to the prior committed row.
        It does NOT verify native work/proofs or attest the stored bytes. The
        native owner must verify complete Packet ancestry before installing
        a rebuilt/loaded projection as authority. Budget exhaustion is a
        recoverable Unavailable condition, not an invalid-block verdict.
        """
        if type(max_rows) is not int or not 1 <= max_rows <= 1_000_000:
            raise ValueError('PROJECTION_AUDIT_BUDGET')
        seen: set[bytes] = set()
        cursor = tip
        reads = 0
        while True:
            if reads >= max_rows:
                raise ValueError('PROJECTION_AUDIT_BUDGET')
            if cursor in seen:
                raise ValueError('PROJECTION_CYCLE')
            seen.add(cursor)
            row = self.read_local(cursor)
            reads += 1
            if not self.validate_local_chain(cursor):
                raise ValueError('PROJECTION_INTEGRITY')
            if row.height == 0:
                if row.block_id != self.context.genesis:
                    raise ValueError('PROJECTION_GENESIS')
                return reads
            cursor = row.parent_id

    @classmethod
    def rebuild_from_validated_order(cls, context: ProjectedAsertContext,
                                     observed: Iterable[VerifiedHeaderObservation]
                                     ) -> 'ForkLocalAnchorProjection':
        """Rebuild in a new instance; failure never publishes partial state."""
        fresh = cls(context)
        for header in observed:
            fresh.observe_assumed_validated(header)
        return fresh
